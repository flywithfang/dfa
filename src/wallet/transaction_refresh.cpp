#include <numeric>
#include <tuple>
#include <queue>
#include <boost/format.hpp>
#include <boost/optional/optional.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <openssl/evp.h>
#include "include_base_utils.h"
using namespace epee;

#include "cryptonote_config.h"

#include "wallet2.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "net/parse.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/core_rpc_server_error_codes.h"


#include "misc_language.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"

#include "common/boost_serialization_helper.h"
#include "common/command_line.h"
#include "common/threadpool.h"
#include "int-util.h"
#include "profile_tools.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "cryptonote_basic/blobdatatype.h"
#include "mnemonics/electrum-words.h"
#include "common/i18n.h"
#include "common/util.h"
#include "common/apply_permutation.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "common/json_util.h"
#include "memwipe.h"
#include "common/base58.h"
#include "common/combinator.h"
#include "common/dns_utils.h"
#include "common/notify.h"
#include "common/perf_timer.h"
#include "ringct/rctSigs.h"


//#include "device_trezor/device_trezor.hpp"
#include "net/socks_connect.h"

extern "C"
{
#include "crypto/keccak.h"
#include "crypto/crypto-ops.h"
}
using namespace std;
using namespace crypto;
using namespace cryptonote;


namespace tools
{
  template <class T>
string to_json_string(T & tx){
   std::ostringstream ost;
  json_archive<true> a(ost);
  ::serialization::serialize(a,tx);
  auto js= ost.str();
  return js;
}

void drop_from_short_history(std::list<crypto::hash> &short_chain_history, size_t N)
{
  std::list<crypto::hash>::iterator right;
  // drop early N off, skipping the genesis block
  if (short_chain_history.size() > N) {
    right = short_chain_history.end();
    std::advance(right,-1);
    std::list<crypto::hash>::iterator left = right;
    std::advance(left, -N);
    short_chain_history.erase(left, right);
  }
}
 
//----------------------------------------------------------------------------------------------------
void wallet2::refresh( uint64_t start_height)
{
   uint64_t blocks_fetched=0;
  bool received_money = false;
  refresh( start_height, blocks_fetched, received_money);
}
//----------------------------------------------------------------------------------------------------
void wallet2::refresh(uint64_t start_height, uint64_t & blocks_fetched, bool& received_money, bool check_pool)
{
   if (!start_height)
      start_height = m_refresh_from_block_height;

  MDEBUG("refresh "<< start_height<<",check_pool "<<check_pool);
  if (m_offline)
  {
    blocks_fetched = 0;
    received_money = 0;
    return;
  }

  received_money = false;
  blocks_fetched = 0;
  uint64_t added_blocks = 0;
  size_t try_count = 0;
  crypto::hash last_tx_hash_id = m_transfers_in.size() ? m_transfers_in.back().m_txid : null_hash;
  hw::device &hwdev = m_account.get_device();

  // pull the first set of blobs
  std::list<crypto::hash> short_chain_history =get_short_chain_history();
  cout<<"short chain"<<endl;
  for(auto h: short_chain_history){
    std::cout<<h<<std::endl;
  }
  m_run.store(true, std::memory_order_relaxed);

 

  uint64_t blocks_start_height;
 
  if (start_height > m_blockchain.size() ) {
   
    // we can shortcut by only pulling hashes up to the start_height
    fast_refresh(start_height, blocks_start_height, short_chain_history);
    // regenerate the history now that we've got a full set of hashes
    short_chain_history =get_short_chain_history();
    start_height = 0;
    // and then fall through to regular refresh processing
  }

  // If stop() is called during fast refresh we don't need to continue
  if(!m_run.load(std::memory_order_relaxed))
    return;
  // always reset start_height to 0 to force short_chain_ history to be used on
  // subsequent pulls in this refresh.
  start_height = 0;

  auto keys_reencryptor = epee::misc_utils::create_scope_leave_handler([&, this]() {
    if (m_encrypt_keys_after_refresh)
    {
      encrypt_keys(*m_encrypt_keys_after_refresh);
      m_encrypt_keys_after_refresh = boost::none;
    }
  });

  auto scope_exit_handler_hwdev = epee::misc_utils::create_scope_leave_handler([&](){
    hwdev.computing_key_images(false);
  }    );

  // get updated pool state first, but do not process those txes just yet,
  // since that might cause a password prompt, which would introduce a data
  // leak allowing a passive adversary with traffic analysis capability to
  // infer when we get an incoming output
  update_pool_state( true);

  bool first = true, last = false;
  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter(tpool);
   std::vector<cryptonote::block_complete_entry> blobs,next_blobs;
  std::vector<parsed_block> parsed_blocks,next_parsed_blocks;
  while(m_run.load(std::memory_order_relaxed))
  {
    uint64_t next_start_height;

    bool error{};
    std::exception_ptr exception;
    try
    {
      // pull the next set of blobs while we're processing the current one
      error = false;
      exception = NULL;
      added_blocks = 0;
      if (!first && blobs.empty())
      {
        m_node_rpc_proxy.set_height(m_blockchain.size());
        break;
      }
      if (!last)
        tpool.submit(&waiter, [&]{

           drop_from_short_history(short_chain_history, 3);
          // prepend the last 3 blobs, should be enough to guard against a block or two's reorg
          const auto delta= std::min((size_t)3, parsed_blocks.size());
          auto s = std::next(parsed_blocks.rbegin(), delta).base();
          for (; s != parsed_blocks.end(); ++s)
          {
            short_chain_history.push_front(s->hash);
          }
          try{
            std::tie(last,next_start_height,next_blobs,next_parsed_blocks) = pull_and_parse_next_blocks(start_height, short_chain_history);

        }catch(std::exception & ex){
          error =true;
          exception = std::current_exception();
        }
        });

      if (!first)
      {
        try
        {
          process_parsed_blocks(blocks_start_height, blobs, parsed_blocks, added_blocks);
        }
        catch (const tools::error::out_of_hashchain_bounds_error&)
        {
          MINFO("Daemon claims next refresh block is out of hash chain bounds, resetting hash chain");
          uint64_t stop_height = m_blockchain.offset();
          std::vector<crypto::hash> tip(m_blockchain.size() - m_blockchain.offset());
          for (size_t i = m_blockchain.offset(); i < m_blockchain.size(); ++i)
            tip[i - m_blockchain.offset()] = m_blockchain[i];
          cryptonote::block b;
          generate_genesis(b);
          m_blockchain.clear();
          m_blockchain.push_back(get_block_hash(b));
          short_chain_history = get_short_chain_history();
          fast_refresh(stop_height, blocks_start_height, short_chain_history, true);
          throw_wallet_ex_if((m_blockchain.size() == stop_height || (m_blockchain.size() == 1 && stop_height == 0) ? false : true), error::wallet_internal_error, "Unexpected hashchain size");
          throw_wallet_ex_if(m_blockchain.offset() != 0, error::wallet_internal_error, "Unexpected hashchain offset");
          for (const auto &h: tip)
            m_blockchain.push_back(h);

          short_chain_history =get_short_chain_history();
          start_height = stop_height;
          throw std::runtime_error(""); // loop again
        }
        catch (const std::exception &e)
        {
          MERROR("Error parsing blobs: " << e.what());
          error = true;
        }
        blocks_fetched += added_blocks;
      }
      throw_wallet_ex_if(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
      if(!first && blocks_start_height == next_start_height)
      {
        m_node_rpc_proxy.set_height(m_blockchain.size());
        break;
      }

      first = false;

      // handle error from async fetching thread
      if (error)
      {
        if (exception)
          std::rethrow_exception(exception);
        else
          throw std::runtime_error("proxy exception in refresh thread");
      }

      if (!next_blobs.empty())
      {
        const uint64_t expected_start_height = std::max(static_cast<uint64_t>(m_blockchain.size()), uint64_t(1)) - 1;
        const uint64_t reorg_depth = expected_start_height - std::min(expected_start_height, next_start_height);
        throw_wallet_ex_if(reorg_depth > m_max_reorg_depth, error::reorg_depth_error,
          tr("reorg exceeds maximum allowed depth, use 'set max-reorg-depth N' to allow it, reorg depth: ") +
          std::to_string(reorg_depth));
      }

      // switch to the new blobs from the daemon
      blocks_start_height = next_start_height;
      blobs = std::move(next_blobs);
      parsed_blocks = std::move(next_parsed_blocks);
    }
    catch (const error::reorg_depth_error&)
    {
      throw_wallet_ex_if(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
      throw;
    }
    catch (const std::exception&)
    {
      blocks_fetched += added_blocks;
      throw_wallet_ex_if(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
      if(try_count < 3)
      {
        MINFO("Another try pull_blocks (try_count=" << try_count << ")...");
        first = true;
        start_height = 0;
        blobs.clear();
        parsed_blocks.clear();
        short_chain_history =get_short_chain_history();
        ++try_count;
      }
      else
      {
        LOG_ERROR("pull_blocks failed, try_count=" << try_count);
        throw;
      }
    }
  }
  if(last_tx_hash_id != (m_transfers_in.size() ? m_transfers_in.back().m_txid : null_hash))
    received_money = true;



  m_first_refresh_done = true;

  MINFO("Refresh done, blobs received: " << blocks_fetched << ", balance (all accounts): " << print_money(balance(false)) << ", unlocked: " << print_money(unlocked_balance(false)));
}

//----------------------------------------------------------------------------------------------------
std::tuple<bool, uint64_t,std::vector<block_complete_entry> , std::vector<wallet2::parsed_block>  > wallet2::pull_and_parse_next_blocks(const uint64_t start_height, std::list<crypto::hash> &short_chain_history )
{
  bool last = false;
 
  std::exception_ptr ex;

    // pull the new blobs
    COMMAND_RPC_GET_BLOCKS_FAST::response res = pull_blocks(start_height,  short_chain_history);
    const auto o_indices=res.output_indices;
    const uint64_t top_height= res.current_height;
    const auto & blobs = res.blocks;
    std::vector<parsed_block> parsed_blocks(blobs.size());
    const auto next_start_height = res.start_height;

    throw_wallet_ex_if(blobs.size() != o_indices.size(), error::wallet_internal_error, "Mismatched sizes of blobs and o_indices");

    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter(tpool);
    for (size_t i = 0; i < blobs.size(); ++i)
    {
      tpool.submit(&waiter, [&,i]{ 
         auto & pb= parsed_blocks[i];
         auto & blob = blobs[i].block;
         try{
         pb.block = cryptonote::parse_and_validate_block_from_blob(blob);
         pb.hash = cryptonote::get_block_hash(pb.block);
       }catch(std::exception & ){
        ex= std::current_exception();
       }
        }, true);
    }
    throw_wallet_ex_if(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
    if(ex){
      std::rethrow_exception(ex);
    }

    bool error=false;
    for (size_t i = 0; i < blobs.size(); ++i)
    {
      const auto & b = blobs[i];
      auto & pb= parsed_blocks[i];
    
      pb.o_indices = std::move(o_indices[i]);
      const auto h=get_block_height(pb.block);
      const auto hs=string_tools::pod_to_hex(pb.hash).substr(0,6);
      const auto prev_hs=string_tools::pod_to_hex(pb.block.prev_id).substr(0,6);

      MDEBUG("find block "<<h<<"/"<<hs<<"->"<<prev_hs<<","<<b.block.size()<<" w "<<b.block_weight<<",tx "<<b.txs.size());
     MTRACE(to_json_string(pb.block));
    }

    boost::mutex error_lock;
    for (size_t i = 0; i < blobs.size(); ++i)
    {
      auto & b =blobs[i];
      auto & pb = parsed_blocks[i];
      pb.txes.resize(b.txs.size());
      for (size_t j = 0; j < b.txs.size(); ++j)
      {
        tpool.submit(&waiter, [&, j](){
          const auto & tx_blob = b.txs[j].blob;
          auto & tx= pb.txes[j];
          if (!parse_and_validate_tx_base_from_blob(tx_blob,tx))
          {
            boost::unique_lock<boost::mutex> lock(error_lock);
            error = true;
          }
        }, true);
      }
    }

    throw_wallet_ex_if(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");

    if(error){
      throw std::runtime_error("bad transaction");
    }
    last = !blobs.empty() && cryptonote::get_block_height(parsed_blocks.back().block) + 1 == top_height;

    return {last,next_start_height,blobs,parsed_blocks};
}



//----------------------------------------------------------------------------------------------------
COMMAND_RPC_GET_BLOCKS_FAST::response wallet2::pull_blocks(uint64_t start_height, const std::list<crypto::hash> &short_chain_history)
{
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req {};
  COMMAND_RPC_GET_BLOCKS_FAST::response res{};

  MDEBUG("Pulling blobs: start_height " << start_height);
  cout<<"short chain"<<endl;
  for(auto h :short_chain_history){
    std::cout<<h<<endl;
  }
  std::cout<<std::endl;

  req.prune = true;
  req.start_height = start_height;
  req.block_ids = short_chain_history;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    bool r = net_utils::invoke_http_bin("/getblocks.bin", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "getblocks.bin", error::get_blocks_error, get_rpc_status(res.status));
    throw_wallet_ex_if(res.blocks.size() != res.output_indices.size(), error::wallet_internal_error,
        "mismatched blobs (" + boost::lexical_cast<std::string>(res.blocks.size()) + ") and output_indices (" +
        boost::lexical_cast<std::string>(res.output_indices.size()) + ") sizes from daemon");
  }

  MDEBUG("Pulled blobs: blocks_start_height " << res.start_height << ", count " << res.blocks.size()<<"/"<<res.output_indices.size()<< ", node height " << res.current_height);

  return res;
}

//----------------------------------------------------------------------------------------------------
void wallet2::process_parsed_blocks(uint64_t start_height, const std::vector<cryptonote::block_complete_entry> &blobs, const std::vector<parsed_block> &parsed_blocks, uint64_t& blocks_added)
{
  

  const auto h= get_block_height(parsed_blocks[0].block);
  throw_w_ex_if(h!=start_height,"bad height");
  size_t cur_height = h;
  blocks_added = 0;

  throw_wallet_ex_if(blobs.size() != parsed_blocks.size(), error::wallet_internal_error, "size mismatch");
  throw_wallet_ex_if(!m_blockchain.is_in_bounds(cur_height), error::out_of_hashchain_bounds_error);

  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter(tpool);

  std::vector<tx_cache_data> tx_cache_data;
  const size_t num_txes = std::accumulate(parsed_blocks.begin(),parsed_blocks.end(),0,[&](auto&a,auto&b){return a+b.txes.size()+1; });
  tx_cache_data.resize(num_txes);
  size_t txidx = 0;
  for (size_t i = 0; i < blobs.size(); ++i)
  {
    auto & pb = parsed_blocks[i];
    throw_wallet_ex_if(pb.txes.size() != pb.block.tx_hashes.size(),error::wallet_internal_error, "Mismatched parsed_blocks[i].txes.size() and parsed_blocks[i].block.tx_hashes.size()");
    if (should_skip_block(pb.block, start_height + i))
    {
      txidx += 1 + pb.block.tx_hashes.size();
      continue;
    }
    
      tpool.submit(&waiter, [&, txidx](){ 
       tx_cache_data[txidx]= cache_tx_data(pb.block.miner_tx);
        });
    
    ++txidx;
    for (size_t idx = 0; idx <pb.txes.size(); ++idx)
    {
      tpool.submit(&waiter, [&, idx, txidx](){
       tx_cache_data[txidx]= cache_tx_data(pb.txes[idx]);
        });

      ++txidx;
    }
  }
  throw_wallet_ex_if(txidx != num_txes, error::wallet_internal_error, "txidx does not match tx_cache_data size");
  throw_wallet_ex_if(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");

  size_t tx_cache_data_offset = 0;
  for (size_t i = 0; i < blobs.size(); ++i)
  {
    const auto & pb = parsed_blocks[i];
    const crypto::hash &bl_id = pb.hash;


    cur_height =get_block_height(pb.block);
    if(cur_height >= m_blockchain.size())
    {
      process_new_blockchain_entry(blobs[i], pb,tx_cache_data,tx_cache_data_offset);
      ++blocks_added;
    }
    else if(bl_id != m_blockchain[cur_height])
    {
      //split detected here !!!
      throw_wallet_ex_if(cur_height == start_height, error::wallet_internal_error,
        "wrong daemon response: split starts from the first block in response " + string_tools::pod_to_hex(bl_id) +
        " (height " + std::to_string(start_height) + "), local block id at this height: " +
        string_tools::pod_to_hex(m_blockchain[cur_height]));

      detach_blockchain(cur_height);
      process_new_blockchain_entry( blobs[i], pb,tx_cache_data, tx_cache_data_offset);
    }
    else
    {
      MINFO("Block is already in blockchain: " << string_tools::pod_to_hex(bl_id));
    }
  
    tx_cache_data_offset += 1 + pb.txes.size();
  }
}

//----------------------------------------------------------------------------------------------------
bool wallet2::should_skip_block(const cryptonote::block &b, uint64_t height) const
{
  // seeking only for blobs that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
  return !(b.timestamp + 60*60*24 > m_account.get_createtime() && height >= m_refresh_from_block_height);
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_new_blockchain_entry( const cryptonote::block_complete_entry& bche, const parsed_block &pb, const std::vector<tx_cache_data> &tx_cache_data, size_t tx_cache_offset)
{
  const auto& b = pb.block;
  const auto& bl_id = pb.hash;
  const auto height =get_block_height(pb.block);
  throw_wallet_ex_if(bche.txs.size() + 1 != pb.o_indices.indices.size(), error::wallet_internal_error,
      "block transactions=" + std::to_string(bche.txs.size()) +" not match with daemon response size=" + std::to_string(pb.o_indices.indices.size()));

  //handle transactions from new block
    
  //optimization: seeking only for blobs that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
  if (!should_skip_block(b, height))
  {
    TIME_MEASURE_START(miner_tx_handle_time);
    {
      process_new_transaction(b.miner_tx, pb.o_indices.indices[0].indices, height, b.timestamp, true, false, false, tx_cache_data[tx_cache_offset]);
    }
    ++tx_cache_offset;
    TIME_MEASURE_FINISH(miner_tx_handle_time);

    TIME_MEASURE_START(txs_handle_time);
    throw_wallet_ex_if(bche.txs.size() != b.tx_hashes.size(), error::wallet_internal_error, "Wrong amount of transactions for block");
    throw_wallet_ex_if(bche.txs.size() != pb.txes.size(), error::wallet_internal_error, "Wrong amount of transactions for block");
    for (size_t idx = 0; idx < b.tx_hashes.size(); ++idx)
    {
      process_new_transaction(pb.txes[idx], pb.o_indices.indices[idx+1].indices, height,  b.timestamp, false, false, false, tx_cache_data[tx_cache_offset++]);
    }
    TIME_MEASURE_FINISH(txs_handle_time);
    MINFO("Processed block: " << bl_id << ", height " << height << ", " <<  miner_tx_handle_time + txs_handle_time << "(" << miner_tx_handle_time << "/" << txs_handle_time <<")ms");
  }else
  {
    if (!(height % 128))
      MINFO( "Skipped block by timestamp, height: " << height << ", block time " << b.timestamp << ", account time " << m_account.get_createtime());
  }
  m_blockchain.push_back(bl_id);

}





//----------------------------------------------------------------------------------------------------
void wallet2::process_new_transaction(const cryptonote::transaction& tx, const std::vector<uint64_t> &o_indices, uint64_t height, uint64_t ts, bool miner_tx, bool pool, bool double_spend_seen, const tx_cache_data &tc)
{
   if (!pool)
      {
        throw_wallet_ex_if(tx.vout.size() != o_indices.size(), error::wallet_internal_error,
            "transactions outputs size=" + std::to_string(tx.vout.size()) +
            " not match with daemon response size=" + std::to_string(o_indices.size()));
      }
  const crypto::hash &txid = get_transaction_hash(tx);
  PERF_TIMER(process_new_transaction);
  // In this function, tx (probably) only contains the base information
  // (that is, the prunable stuff may or may not be included)
  if (!miner_tx && !pool)
    comfirm_pool_transfer_out(tx, height);

  // per receiving subaddress index
        uint64_t tx_sum=0;
       for (size_t o = 0; o < tx.vout.size(); ++o)
       {
            if(!tc.primary.received[o])
              continue;

        const auto scan= scan_output(tx, miner_tx, tc.primary, o);
        const auto otk=scan.otk_p.pub;
        auto kit = m_otks.find(otk);
        throw_wallet_ex_if(kit != m_otks.end() && kit->second >= m_transfers_in.size(),
            error::wallet_internal_error, std::string("Unexpected transfer index from public key: ")
            + "got " + (kit == m_otks.end() ? "<none>" : boost::lexical_cast<std::string>(kit->second))
            + ", m_transfers_in.size() is " + boost::lexical_cast<std::string>(m_transfers_in.size()));
        if (kit == m_otks.end())
        {
          const uint64_t amount =  scan.money_transfered;
          if (!pool)
          {
            tx_sum+=scan.money_transfered;

            m_transfers_in.push_back(transfer_details{});
            auto & td = m_transfers_in.back();
            td.m_block_height = height;
            td.m_internal_output_index = o;
            td.m_global_output_index = o_indices[o];
            td.m_txid = txid;
            td.m_otk = otk;
            td.m_tx_key=tc.primary.tx_key;
            td.m_key_image = scan.ki;
            td.m_amount = amount;
            td.m_noise = scan.noise;
            td.m_spent = false;
            td.m_spent_height = 0;
            td.m_block_time = ts;

            m_key_images[td.m_key_image] = m_transfers_in.size()-1;

            m_otks[otk] = m_transfers_in.size()-1;

            MINFO("Received money: " << print_money(td.amount()) << ", with height: " << height);
          }
        }
      else 
        {
          auto & td = m_transfers_in[kit->second];
          MINFO("otk " << epee::string_tools::pod_to_hex(otk)<< " from received " << print_money(scan.money_transfered) << " output already exists with "<< print_money(m_transfers_in[kit->second].amount()) << ", replacing with new output");
          // The new larger output replaced a previous smaller one
          throw_wallet_ex_if(td.amount()!=scan.money_transfered || td.m_txid!=txid ,error::wallet_internal_error, "Unexpected values of new and old outputs");
          throw_wallet_ex_if(td.otk() != otk, error::wallet_internal_error, "Inconsistent public keys");
          if (!pool)
          {
            td.m_block_height = height;
            td.m_global_output_index = o_indices[o];
            throw_wallet_ex_if(td.m_spent, error::wallet_internal_error, "Inconsistent spent status");
            MINFO("Received money: " << print_money(td.amount()) << ", with tx: " << txid);
          
          }

        }
      }


  // create payment_details for each incoming transfer to a subaddress index
  if (tx_sum > 0 && pool)
  {
      pool_transfer_in payment;
      payment.m_tx_hash      = txid;
      payment.m_fee          = tx.rct_signatures.txnFee;
      payment.m_amount       = tx_sum;
      payment.m_block_height = height;
      payment.m_unlock_time  = tx.unlock_time;
      payment.m_timestamp    = ts;
      payment.m_coinbase     = miner_tx;
      payment.m_double_spend_seen=double_spend_seen;
      m_pool_transfers_in[txid]=payment;

    
      MINFO("transfer in found in pool" << ": "  << " / " << payment.m_tx_hash << " / " << payment.m_amount);
  }

  uint64_t tx_out_money = 0;
  // The line below is equivalent to "boost::optional<uint32_t> subaddr_account;", but avoids the GCC warning: ‘*((void*)& subaddr_account +4)’ may be used uninitialized in this function
  // It's a GCC bug with boost::optional, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=47679
  // check all outputs for spending (compare key images)
  for(auto& in: tx.vin)
  {
    if(in.type() != typeid(cryptonote::txin_to_key))
      continue;
    const auto &in_to_key = boost::get<cryptonote::txin_to_key>(in);
    auto it = m_key_images.find(in_to_key.k_image);
    if(it != m_key_images.end())
    {
      const auto & td = m_transfers_in[it->second];
      uint64_t amount = td.amount();
      tx_out_money += amount;
      if (!pool)
      {
        MINFO("Spent money: " << print_money(amount) << ", with tx: " << txid);
        set_spent(it->second, height);
      }
    }
  }

  if (tx_out_money > 0 && !pool)
  {
    process_outgoing(tx, height, ts, tx_out_money, tx_sum);
  }


}

//----------------------------------------------------------------------------------------------------
wallet2::tx_scan_info_t wallet2::scan_output(const cryptonote::transaction &tx, bool miner_tx, const is_out_data & tc,size_t i)
{
  tx_scan_info_t scan{};
    bool r = cryptonote::generate_key_image_helper(m_account.get_keys(),  tc.tx_key, i, scan.otk_p, scan.ki, m_account.get_device());
      
      const auto otk= boost::get<cryptonote::txout_to_key>(tx.vout[i].target).key;

    throw_wallet_ex_if(!r, error::wallet_internal_error, "Failed to generate key image");
    throw_wallet_ex_if(scan.otk_p.pub != otk,error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key");

  if (!miner_tx)
  {
    auto [amount, noise]= rct::decodeRctSimple(tx.rct_signatures,tc.kA,i);
    scan.money_transfered = amount;
    scan.noise=noise; 
  }
  else{
    scan.money_transfered = get_outs_money_amount(tx);
  }
  throw_w_ex_if(scan.money_transfered == 0,"Invalid output amount, skipping");

  return scan;
}
//----------------------------------------------------------------------------------------------------
void wallet2::fast_refresh(uint64_t stop_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, bool force)
{
  std::vector<crypto::hash> hashes;

  const uint64_t checkpoint_height = m_checkpoints.get_max_height();
  if ((stop_height > checkpoint_height && m_blockchain.size()-1 < checkpoint_height) && !force)
  {
    // we will drop all these, so don't bother getting them
    uint64_t missing_blocks = m_checkpoints.get_max_height() - m_blockchain.size();
    while (missing_blocks-- > 0)
      m_blockchain.push_back(crypto::null_hash); // maybe a bit suboptimal, but deque won't do huge reallocs like vector
    m_blockchain.push_back(m_checkpoints.get_points().at(checkpoint_height));
    m_blockchain.trim(checkpoint_height);
   short_chain_history =get_short_chain_history();
  }

  size_t current_index = m_blockchain.size();
  while(m_run.load(std::memory_order_relaxed) && current_index < stop_height)
  {
    pull_hashes(0, blocks_start_height, short_chain_history, hashes);
    if (hashes.size() <= 3)
      return;
    if (blocks_start_height < m_blockchain.offset())
    {
      MERROR("Blocks start before blockchain offset: " << blocks_start_height << " " << m_blockchain.offset());
      return;
    }
    current_index = blocks_start_height;
    if (hashes.size() + current_index < stop_height) {
      drop_from_short_history(short_chain_history, 3);
      std::vector<crypto::hash>::iterator right = hashes.end();
      // prepend 3 more
      for (int i = 0; i<3; i++) {
        right--;
        short_chain_history.push_front(*right);
      }
    }
    for(auto& bl_id: hashes)
    {
      if(current_index >= m_blockchain.size())
      {
        if (!(current_index % 1024))
          MINFO( "Skipped block by height: " << current_index);
        m_blockchain.push_back(bl_id);
      }
      else if(bl_id != m_blockchain[current_index])
      {
        //split detected here !!!
        return;
      }
      ++current_index;
      if (current_index >= stop_height)
        return;
    }
  }
}


//----------------------------------------------------------------------------------------------------
void wallet2::pull_hashes(uint64_t start_height, uint64_t &blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<crypto::hash> &hashes)
{
  cryptonote::COMMAND_RPC_GET_HASHES_FAST::request req = AUTO_VAL_INIT(req);
  cryptonote::COMMAND_RPC_GET_HASHES_FAST::response res = AUTO_VAL_INIT(res);
  req.block_ids = short_chain_history;

  req.start_height = start_height;

  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};


    bool r = net_utils::invoke_http_bin("/gethashes.bin", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "gethashes.bin", error::get_hashes_error, get_rpc_status(res.status));
    
  }

  blocks_start_height = res.start_height;
  hashes = std::move(res.m_block_ids);
}


//----------------------------------------------------------------------------------------------------
wallet2::tx_cache_data wallet2::cache_tx_data(const cryptonote::transaction& tx) const
{
  hw::device &hwdev =  m_account.get_device();
  const cryptonote::account_keys &keys = m_account.get_keys();
  const auto a = keys.m_view_secret_key;
  const auto b= keys.m_spend_secret_key;
  tx_cache_data  tc{};
  if(!cryptonote::parse_tx_extra(tx.extra, tc.tx_extra_fields))
  {
    // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
    MERROR("Transaction extra has unsupported format: " << get_transaction_hash(tx));
    if (tc.tx_extra_fields.empty())
      return tc;
  }

    const size_t rec_size = tx.vout.size();
    throw_w_ex_if(rec_size==0,"out size=0");

    // if tx.vout is not empty, we loop through all tx pubkeys
    std::vector<bool> rec(rec_size, false);
    tx_extra_pub_key tx_key{};
    if(!find_tx_extra_field_by_type(tc.tx_extra_fields, tx_key)){
      throw std::runtime_error("not found tx pub key");
    }
    key_derivation kA;
  if (!crypto::generate_key_derivation(tx_key.pub_key, a, kA))
      {
        MWARNING("Failed to generate key derivation from tx pubkey, skipping");
        memcpy(&kA, rct::identity().bytes, sizeof(tc.primary.kA));
      }
    //tx_key,otk,i, a,B
    auto oi=0;
    for (const auto & o : tx.vout)
    {
      if (o.target.type() == typeid(cryptonote::txout_to_key))
      {
        const auto &otk = boost::get<txout_to_key>(o.target).key;
        //otk=H(kA,i)+B
          crypto::public_key B2;
          //B=otk - H(kG,a,oi)*G
          hwdev.derive_subaddress_public_key(otk, kA, oi, B2);
          MDEBUG("B2 "+ string_tools::pod_to_hex(B2));
          MDEBUG("B" +  string_tools::pod_to_hex(m_account.get_spend_public_key()));
          rec[oi] = m_account.get_spend_public_key()==B2;
          ++oi;
      }
    }

    tc.primary={tx_key.pub_key, kA, rec};
  return tc;
}

//----------------------------------------------------------------------------------------------------
void wallet2::process_outgoing( const cryptonote::transaction &tx, uint64_t height, uint64_t ts, uint64_t out, uint64_t change)
{
  const crypto::hash &txid = get_transaction_hash(tx);
  auto entry = m_confirmed_transfer_outs.insert_or_assign(txid, confirmed_transfer_out());
   auto & ctd = entry.first->second;
  // fill with the info we know, some info might already be there
  if (entry.second)
  {
    // this case will happen if the tx is from our outputs, but was sent by another
    // wallet (eg, we're a cold wallet and the hot wallet sent it). For RCT transactions,
    // we only see 0 input amounts, so have to deduce amount out from other parameters.
   
    ctd.m_fee = tx.rct_signatures.txnFee;
    ctd.m_amount = out - change - ctd.m_fee;
    throw_w_ex_if(ctd.m_amount<=0,"bad amount");
  }

  ctd.m_block_height = height;
  ctd.m_unlock_time = tx.unlock_time;

}


//----------------------------------------------------------------------------------------------------
std::list<crypto::hash> wallet2::get_short_chain_history() const
{
  std::list<crypto::hash> ids;
  size_t current_multiplier = 1;
  size_t blockchain_size = std::max(m_blockchain.size() , m_blockchain.offset());
  size_t local_size = blockchain_size - m_blockchain.offset();
  if(!local_size)
  {
    ids.push_back(m_blockchain.genesis());
    return ids;
  }
  size_t back_offset = 1;
  bool base_included = false;
   size_t i = 0;
  while(back_offset < local_size)
  {
    const auto index=local_size-back_offset;
    ids.push_back(m_blockchain[m_blockchain.offset() +index ]);
    if(index == 0)
      base_included = true;
    if(i < 10)
    {
      ++back_offset;
    }else
    {
      back_offset += current_multiplier *= 2;
    }
    ++i;
  }
  if(!base_included)
    ids.push_back(m_blockchain[m_blockchain.offset()]);
  if(m_blockchain.offset())
    ids.push_back(m_blockchain.genesis());
  return ids;
}

}