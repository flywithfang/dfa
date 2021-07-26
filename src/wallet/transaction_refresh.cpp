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
#include "cryptonote_core/tx_sanity_check.h"

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
  //----------------------------------------------------------------------------------------------------

  //----------------------------------------------------------------------------------------------------
void wallet2::refresh(bool trusted_daemon)
{
  uint64_t blocks_fetched = 0;
  refresh(trusted_daemon, 0, blocks_fetched);
}
//----------------------------------------------------------------------------------------------------
void wallet2::refresh(bool trusted_daemon, uint64_t start_height, uint64_t & blocks_fetched)
{
  bool received_money = false;
  refresh(trusted_daemon, start_height, blocks_fetched, received_money);
}
//----------------------------------------------------------------------------------------------------
void wallet2::refresh(bool trusted_daemon, uint64_t start_height, uint64_t & blocks_fetched, bool& received_money, bool check_pool)
{
  MTRACE("refresh "<< start_height<<",check_pool "<<check_pool);
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

  // pull the first set of blocks
  std::list<crypto::hash> short_chain_history =get_short_chain_history();
  for(auto h: short_chain_history){
    std::cout<<h<<std::endl;
  }
  m_run.store(true, std::memory_order_relaxed);

  if (!start_height)
      start_height = m_refresh_from_block_height;

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
   std::vector<cryptonote::block_complete_entry> blocks;
  std::vector<parsed_block> parsed_blocks;
  while(m_run.load(std::memory_order_relaxed))
  {
    uint64_t next_blocks_start_height;
    std::vector<cryptonote::block_complete_entry> next_blocks;
    std::vector<parsed_block> next_parsed_blocks;
    bool error{};
    std::exception_ptr exception;
    try
    {
      // pull the next set of blocks while we're processing the current one
      error = false;
      exception = NULL;
      next_blocks.clear();
      next_parsed_blocks.clear();
      added_blocks = 0;
      if (!first && blocks.empty())
      {
        m_node_rpc_proxy.set_height(m_blockchain.size());
        break;
      }
      if (!last)
        tpool.submit(&waiter, [&]{
          pull_and_parse_next_blocks(start_height, next_blocks_start_height, short_chain_history, blocks, parsed_blocks, next_blocks, next_parsed_blocks, last, error, exception);
        });

      if (!first)
      {
        try
        {
          process_parsed_blocks(blocks_start_height, blocks, parsed_blocks, added_blocks);
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
          THROW_WALLET_EXCEPTION_IF((m_blockchain.size() == stop_height || (m_blockchain.size() == 1 && stop_height == 0) ? false : true), error::wallet_internal_error, "Unexpected hashchain size");
          THROW_WALLET_EXCEPTION_IF(m_blockchain.offset() != 0, error::wallet_internal_error, "Unexpected hashchain offset");
          for (const auto &h: tip)
            m_blockchain.push_back(h);

          short_chain_history =get_short_chain_history();
          start_height = stop_height;
          throw std::runtime_error(""); // loop again
        }
        catch (const std::exception &e)
        {
          MERROR("Error parsing blocks: " << e.what());
          error = true;
        }
        blocks_fetched += added_blocks;
      }
      THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
      if(!first && blocks_start_height == next_blocks_start_height)
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

      if (!next_blocks.empty())
      {
        const uint64_t expected_start_height = std::max(static_cast<uint64_t>(m_blockchain.size()), uint64_t(1)) - 1;
        const uint64_t reorg_depth = expected_start_height - std::min(expected_start_height, next_blocks_start_height);
        THROW_WALLET_EXCEPTION_IF(reorg_depth > m_max_reorg_depth, error::reorg_depth_error,
          tr("reorg exceeds maximum allowed depth, use 'set max-reorg-depth N' to allow it, reorg depth: ") +
          std::to_string(reorg_depth));
      }


      // switch to the new blocks from the daemon
      blocks_start_height = next_blocks_start_height;
      blocks = std::move(next_blocks);
      parsed_blocks = std::move(next_parsed_blocks);
    }
    catch (const tools::error::password_needed&)
    {
      blocks_fetched += added_blocks;
      THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
      throw;
    }
    catch (const error::reorg_depth_error&)
    {
      THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
      throw;
    }
    catch (const std::exception&)
    {
      blocks_fetched += added_blocks;
      THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
      if(try_count < 3)
      {
        MINFO("Another try pull_blocks (try_count=" << try_count << ")...");
        first = true;
        start_height = 0;
        blocks.clear();
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

  MINFO("Refresh done, blocks received: " << blocks_fetched << ", balance (all accounts): " << print_money(balance(false)) << ", unlocked: " << print_money(unlocked_balance(false)));
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
void wallet2::pull_and_parse_next_blocks(uint64_t start_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, const std::vector<cryptonote::block_complete_entry> &prev_blocks, const std::vector<parsed_block> &prev_parsed_blocks, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<parsed_block> &parsed_blocks, bool &last, bool &error, std::exception_ptr &exception)
{
  error = false;
  last = false;
  exception = NULL;

  try
  {
    drop_from_short_history(short_chain_history, 3);

    THROW_WALLET_EXCEPTION_IF(prev_blocks.size() != prev_parsed_blocks.size(), error::wallet_internal_error, "size mismatch");

    // prepend the last 3 blocks, should be enough to guard against a block or two's reorg
    auto s = std::next(prev_parsed_blocks.rbegin(), std::min((size_t)3, prev_parsed_blocks.size())).base();
    for (; s != prev_parsed_blocks.end(); ++s)
    {
      short_chain_history.push_front(s->hash);
    }

    // pull the new blocks
    std::vector<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices> o_indices;
    uint64_t current_height;
    pull_blocks(start_height, blocks_start_height, short_chain_history, blocks, o_indices, current_height);
    THROW_WALLET_EXCEPTION_IF(blocks.size() != o_indices.size(), error::wallet_internal_error, "Mismatched sizes of blocks and o_indices");

    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter(tpool);
    parsed_blocks.resize(blocks.size());
    for (size_t i = 0; i < blocks.size(); ++i)
    {
      tpool.submit(&waiter, [&]{ 
         auto & pb= parsed_blocks[i];
         auto & blob = blocks[i].block;
         pb.error = !cryptonote::parse_and_validate_block_from_blob(blob, pb.block, pb.hash);
        }, true);
    }
    THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
    for (size_t i = 0; i < blocks.size(); ++i)
    {
      auto & b = blocks[i];
      MDEBUG("find block"<<b.block.size()<<"w "<<b.block_weight<<",tx "<<b.txs.size());
      if (parsed_blocks[i].error)
      {
        error = true;
        break;
      }
      parsed_blocks[i].o_indices = std::move(o_indices[i]);
    }

    boost::mutex error_lock;
    for (size_t i = 0; i < blocks.size(); ++i)
    {
      auto & b =blocks[i];
      auto & pb = parsed_blocks[i];
      pb.txes.resize(b.txs.size());
      for (size_t j = 0; j < b.txs.size(); ++j)
      {
        tpool.submit(&waiter, [&, j](){
          if (!parse_and_validate_tx_base_from_blob(b.txs[j].blob, pb.txes[j]))
          {
            boost::unique_lock<boost::mutex> lock(error_lock);
            error = true;
          }
        }, true);
      }
    }
    THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");

    last = !blocks.empty() && cryptonote::get_block_height(parsed_blocks.back().block) + 1 == current_height;
  }
  catch(...)
  {
    error = true;
    exception = std::current_exception();
  }
}


//----------------------------------------------------------------------------------------------------
void wallet2::pull_blocks(uint64_t start_height, uint64_t &blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices> &o_indices, uint64_t &current_height)
{
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req {};
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res{};
  req.block_ids = short_chain_history;

  MDEBUG("Pulling blocks: start_height " << start_height);

  req.prune = true;
  req.start_height = start_height;

  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};


    bool r = net_utils::invoke_http_bin("/getblocks.bin", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "getblocks.bin", error::get_blocks_error, get_rpc_status(res.status));
    THROW_WALLET_EXCEPTION_IF(res.blocks.size() != res.output_indices.size(), error::wallet_internal_error,
        "mismatched blocks (" + boost::lexical_cast<std::string>(res.blocks.size()) + ") and output_indices (" +
        boost::lexical_cast<std::string>(res.output_indices.size()) + ") sizes from daemon");
  }

  blocks_start_height = res.start_height;
  blocks = std::move(res.blocks);
  o_indices = std::move(res.output_indices);
  current_height = res.current_height;

  MDEBUG("Pulled blocks: blocks_start_height " << blocks_start_height << ", count " << blocks.size()
      << ", height " << blocks_start_height + blocks.size() << ", node height " << res.current_height);
}

//----------------------------------------------------------------------------------------------------
void wallet2::process_parsed_blocks(uint64_t start_height, const std::vector<cryptonote::block_complete_entry> &blocks, const std::vector<parsed_block> &parsed_blocks, uint64_t& blocks_added)
{
  size_t current_index = start_height;
  blocks_added = 0;

  THROW_WALLET_EXCEPTION_IF(blocks.size() != parsed_blocks.size(), error::wallet_internal_error, "size mismatch");
  THROW_WALLET_EXCEPTION_IF(!m_blockchain.is_in_bounds(current_index), error::out_of_hashchain_bounds_error);

  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter(tpool);

  size_t num_txes = 0;
  std::vector<tx_cache_data> tx_cache_data;
  for (size_t i = 0; i < blocks.size(); ++i)
    num_txes += 1 + parsed_blocks[i].txes.size();
  tx_cache_data.resize(num_txes);
  size_t txidx = 0;
  for (size_t i = 0; i < blocks.size(); ++i)
  {
    auto & pb = parsed_blocks[i];
    THROW_WALLET_EXCEPTION_IF(pb.txes.size() != pb.block.tx_hashes.size(),
        error::wallet_internal_error, "Mismatched parsed_blocks[i].txes.size() and parsed_blocks[i].block.tx_hashes.size()");
    if (should_skip_block(pb.block, start_height + i))
    {
      txidx += 1 + parsed_blocks[i].block.tx_hashes.size();
      continue;
    }
    {
      tpool.submit(&waiter, [&, txidx](){ 
       tx_cache_data[txidx]= cache_tx_data(pb.block.miner_tx, get_transaction_hash(pb.block.miner_tx));
        });
    }
    ++txidx;
    for (size_t idx = 0; idx <pb.txes.size(); ++idx)
    {
      tpool.submit(&waiter, [&, idx, txidx](){
       tx_cache_data[txidx]= cache_tx_data(pb.txes[idx], pb.block.tx_hashes[idx] );
        });

      ++txidx;
    }
  }
  THROW_WALLET_EXCEPTION_IF(txidx != num_txes, error::wallet_internal_error, "txidx does not match tx_cache_data size");
  THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");

  hw::device &hwdev =  m_account.get_device();
  hw::reset_mode rst(hwdev);
  hwdev.set_mode(hw::device::TRANSACTION_PARSE);

  const cryptonote::account_keys &keys = m_account.get_keys();

 for (size_t i = 0; i < tx_cache_data.size(); ++i)
  {
    if (tx_cache_data[i].empty())
      continue;
    tpool.submit(&waiter, [&hwdev, i,&keys,&tx_cache_data]() {
      auto &slot = tx_cache_data[i];
      auto &primary=slot.primary;
      boost::unique_lock<hw::device> hwdev_lock(hwdev);
      //kG*a=kA
      //H(kA,i)G+B   
      if (!hwdev.generate_key_derivation(primary.pkey, keys.m_view_secret_key, primary.derivation))
      {
        MWARNING("Failed to generate key derivation from tx pubkey, skipping");
        static_assert(sizeof(primary.derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
        memcpy(&primary.derivation, rct::identity().bytes, sizeof(primary.derivation));
      }
    }, true);
  }

  THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");

  auto geniod = [&](const cryptonote::transaction &tx, size_t n_vouts, size_t txidx) {
    for (size_t k = 0; k < n_vouts; ++k)
    {
      const auto &o = tx.vout[k];
      auto & to=tx_cache_data[txidx];
      if (o.target.type() == typeid(cryptonote::txout_to_key))
      {
        const auto &otk = boost::get<txout_to_key>(o.target).key;
        {
          THROW_WALLET_EXCEPTION_IF(to.primary.received.size() != n_vouts,
              error::wallet_internal_error, "Unexpected received array size");
            //otk=H(kA,i)+B
              crypto::public_key B2;
              //B=otk - H(kG,a,oi)*G
              hwdev.derive_subaddress_public_key(otk, to.primary.derivation, k, B2);
              to.primary.received[k] = m_account.get_view_public_key()==B2;
        }
      }
    }
  };

  txidx = 0;
  for (size_t i = 0; i < blocks.size(); ++i)
  {
    auto & pb =parsed_blocks[i];
    if (should_skip_block(pb.block, start_height + i))
    {
      txidx += 1 + pb.block.tx_hashes.size();
      continue;
    }

    {
      THROW_WALLET_EXCEPTION_IF(txidx >= tx_cache_data.size(), error::wallet_internal_error, "txidx out of range");
      const size_t n_vouts = pb.block.miner_tx.vout.size();
      tpool.submit(&waiter, [&, i, n_vouts, txidx](){
       geniod(pb.block.miner_tx, n_vouts, txidx); }, true);
    }
    ++txidx;
    for (size_t j = 0; j < pb.txes.size(); ++j)
    {
      THROW_WALLET_EXCEPTION_IF(txidx >= tx_cache_data.size(), error::wallet_internal_error, "txidx out of range");
      tpool.submit(&waiter, [&, i, j, txidx](){ geniod(pb.txes[j], pb.txes[j].vout.size(), txidx); }, true);
      ++txidx;
    }
  }
  THROW_WALLET_EXCEPTION_IF(txidx != tx_cache_data.size(), error::wallet_internal_error, "txidx did not reach expected value");
  THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
  hwdev.set_mode(hw::device::NONE);

  size_t tx_cache_data_offset = 0;
  for (size_t i = 0; i < blocks.size(); ++i)
  {
    const auto & pb = parsed_blocks[i];
    const crypto::hash &bl_id = pb.hash;
    const cryptonote::block &bl = pb.block;

    if(current_index >= m_blockchain.size())
    {
      process_new_blockchain_entry(bl, blocks[i], pb, bl_id, current_index, tx_cache_data,tx_cache_data_offset);
      ++blocks_added;
    }
    else if(bl_id != m_blockchain[current_index])
    {
      //split detected here !!!
      THROW_WALLET_EXCEPTION_IF(current_index == start_height, error::wallet_internal_error,
        "wrong daemon response: split starts from the first block in response " + string_tools::pod_to_hex(bl_id) +
        " (height " + std::to_string(start_height) + "), local block id at this height: " +
        string_tools::pod_to_hex(m_blockchain[current_index]));

      detach_blockchain(current_index);
      process_new_blockchain_entry(bl, blocks[i], pb, bl_id, current_index, tx_cache_data, tx_cache_data_offset);
    }
    else
    {
      MINFO("Block is already in blockchain: " << string_tools::pod_to_hex(bl_id));
    }
    ++current_index;
    tx_cache_data_offset += 1 + parsed_blocks[i].txes.size();
  }
}

//----------------------------------------------------------------------------------------------------
bool wallet2::should_skip_block(const cryptonote::block &b, uint64_t height) const
{
  // seeking only for blocks that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
  return !(b.timestamp + 60*60*24 > m_account.get_createtime() && height >= m_refresh_from_block_height);
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_new_blockchain_entry(const cryptonote::block& b, const cryptonote::block_complete_entry& bche, const parsed_block &pb, const crypto::hash& bl_id, uint64_t height, const std::vector<tx_cache_data> &tx_cache_data, size_t tx_cache_data_offset)
{
  THROW_WALLET_EXCEPTION_IF(bche.txs.size() + 1 != pb.o_indices.indices.size(), error::wallet_internal_error,
      "block transactions=" + std::to_string(bche.txs.size()) +
      " not match with daemon response size=" + std::to_string(pb.o_indices.indices.size()));

  //handle transactions from new block
    
  //optimization: seeking only for blocks that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
  if (!should_skip_block(b, height))
  {
    TIME_MEASURE_START(miner_tx_handle_time);
    {
      process_new_transaction(get_transaction_hash(b.miner_tx), b.miner_tx, pb.o_indices.indices[0].indices, height, b.major_version, b.timestamp, true, false, false, tx_cache_data[tx_cache_data_offset]);
    }
    ++tx_cache_data_offset;
    TIME_MEASURE_FINISH(miner_tx_handle_time);

    TIME_MEASURE_START(txs_handle_time);
    THROW_WALLET_EXCEPTION_IF(bche.txs.size() != b.tx_hashes.size(), error::wallet_internal_error, "Wrong amount of transactions for block");
    THROW_WALLET_EXCEPTION_IF(bche.txs.size() != pb.txes.size(), error::wallet_internal_error, "Wrong amount of transactions for block");
    for (size_t idx = 0; idx < b.tx_hashes.size(); ++idx)
    {
      process_new_transaction(b.tx_hashes[idx], pb.txes[idx], pb.o_indices.indices[idx+1].indices, height, b.major_version, b.timestamp, false, false, false, tx_cache_data[tx_cache_data_offset++]);
    }
    TIME_MEASURE_FINISH(txs_handle_time);
    MINFO("Processed block: " << bl_id << ", height " << height << ", " <<  miner_tx_handle_time + txs_handle_time << "(" << miner_tx_handle_time << "/" << txs_handle_time <<")ms");
  }else
  {
    if (!(height % 128))
      MINFO( "Skipped block by timestamp, height: " << height << ", block time " << b.timestamp << ", account time " << m_account.get_createtime());
  }
  m_blockchain.push_back(bl_id);

  if (0 != m_callback)
    m_callback->on_new_block(height, b);
}





//----------------------------------------------------------------------------------------------------
void wallet2::process_new_transaction(const crypto::hash &txid, const cryptonote::transaction& tx, const std::vector<uint64_t> &o_indices, uint64_t height, uint8_t block_version, uint64_t ts, bool miner_tx, bool pool, bool double_spend_seen, const tx_cache_data &tx_cache_data)
{
  PERF_TIMER(process_new_transaction);
  // In this function, tx (probably) only contains the base information
  // (that is, the prunable stuff may or may not be included)
  if (!miner_tx && !pool)
    process_unconfirmed(txid, tx, height);

  // per receiving subaddress index
  uint64_t tx_money_got_in_outs=0;

  crypto::public_key tx_pub_key{};


  std::vector<tx_extra_field> local_tx_extra_fields;
  if (tx_cache_data.tx_extra_fields.empty())
  {
    if(!parse_tx_extra(tx.extra, local_tx_extra_fields))
    {
      // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
      MINFO("Transaction extra has unsupported format: " << txid);
    }
  }
  const std::vector<tx_extra_field> &tx_extra_fields = tx_cache_data.tx_extra_fields.empty() ? local_tx_extra_fields : tx_cache_data.tx_extra_fields;

  // Don't try to extract tx public key if tx has no ouputs
  std::vector<tx_scan_info_t> tx_scan_info(tx.vout.size());
  std::deque<bool> output_found(tx.vout.size(), false);
  uint64_t total_received_1 = 0;

    THROW_WALLET_EXCEPTION_IF( tx.vout.empty(),error::wallet_internal_error, "tx.vout.empty()");
  do 
  {
    // if tx.vout is not empty, we loop through all tx pubkeys

    tx_extra_pub_key pub_key_field;
    if(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field))
    {
      MINFO("Public key wasn't found in the transaction extra. Skipping transaction " << txid);
      if(0 != m_callback)
        m_callback->on_skip_transaction(height, txid, tx);
      break;
    }
    if (!tx_cache_data.primary.empty())
    {
      THROW_WALLET_EXCEPTION_IF( pub_key_field.pub_key != tx_cache_data.primary.pkey,error::wallet_internal_error, "tx_cache_data is out of sync");
    }
   
    tx_pub_key = pub_key_field.pub_key;
    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter(tpool);
    const cryptonote::account_keys& keys = m_account.get_keys();
    crypto::key_derivation derivation;

    const wallet2::is_out_data *is_out_data_ptr = NULL;
    if (tx_cache_data.primary.empty())
    {
      hw::device &hwdev = hw::get_device("default");
      
      if (!hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation))
      {
        MWARNING("Failed to generate key derivation from tx pubkey in " << txid << ", skipping");
        static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
        memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
      }
    }
    else
    {
      is_out_data_ptr = &tx_cache_data.primary;
      derivation = tx_cache_data.primary.derivation;
      
    }
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
         tpool.submit(&waiter,[&,i] {
            check_acc_out_precomp_once(tx.vout[i], derivation,  i, is_out_data_ptr, tx_scan_info[i], output_found[i]);
         },true);
       }
      THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
      
      std::vector<size_t> outs;
       int num_vouts_received = 0;
       for (size_t i = 0; i < tx.vout.size(); ++i)
          {
              THROW_WALLET_EXCEPTION_IF(tx_scan_info[i].error, error::acc_outs_lookup_error, tx, tx_pub_key, m_account.get_keys());
              if (tx_scan_info[i].received)
              {
                scan_output(tx, miner_tx, tx_pub_key, i, tx_scan_info[i], num_vouts_received, tx_money_got_in_outs, outs, pool);
               
              }
         
           }
    

    if(!outs.empty() && num_vouts_received > 0)
    {
      //good news - got money! take care about it
      //usually we have only one transfer for user in transaction
      if (!pool)
      {
        THROW_WALLET_EXCEPTION_IF(tx.vout.size() != o_indices.size(), error::wallet_internal_error,
            "transactions outputs size=" + std::to_string(tx.vout.size()) +
            " not match with daemon response size=" + std::to_string(o_indices.size()));
      }

      for(size_t o: outs)
      {
        THROW_WALLET_EXCEPTION_IF(tx.vout.size() <= o, error::wallet_internal_error, "wrong out in transaction: internal index=" + std::to_string(o) + ", total_outs=" + std::to_string(tx.vout.size()));

        const auto otk=tx_scan_info[o].in_ephemeral.pub;
        auto kit = m_otks.find(otk);
        THROW_WALLET_EXCEPTION_IF(kit != m_otks.end() && kit->second >= m_transfers_in.size(),
            error::wallet_internal_error, std::string("Unexpected transfer index from public key: ")
            + "got " + (kit == m_otks.end() ? "<none>" : boost::lexical_cast<std::string>(kit->second))
            + ", m_transfers_in.size() is " + boost::lexical_cast<std::string>(m_transfers_in.size()));
        if (kit == m_otks.end())
        {
          uint64_t amount =  tx_scan_info[o].amount;
          if (!pool)
          {
            m_transfers_in.push_back(transfer_details{});
            transfer_details& td = m_transfers_in.back();
            td.m_block_height = height;
            td.m_internal_output_index = o;
            td.m_global_output_index = o_indices[o];
            td.m_tx = tx;
            td.m_txid = txid;
            td.m_key_image = tx_scan_info[o].ki;
            td.m_amount = amount;
            td.m_noise = tx_scan_info[o].noise;
            td.m_frozen = false;
            set_unspent(m_transfers_in.size()-1);
            m_key_images[td.m_key_image] = m_transfers_in.size()-1;

            m_otks[otk] = m_transfers_in.size()-1;

            MINFO("Received money: " << print_money(td.amount()) << ", with tx: " << txid);
            if (0 != m_callback)
              m_callback->on_money_received(height, txid, tx, td.m_amount, spends_one_of_ours(tx), td.m_tx.unlock_time);
            }

            total_received_1 += amount;
        }
      else 
        {
          auto & td = m_transfers_in[kit->second];
          LOG_ERROR("Public key " << epee::string_tools::pod_to_hex(kit->first)
              << " from received " << print_money(tx_scan_info[o].amount) << " output already exists with "
              << print_money(m_transfers_in[kit->second].amount()) << ", replacing with new output");
          // The new larger output replaced a previous smaller one
          THROW_WALLET_EXCEPTION_IF(tx_money_got_in_outs < tx_scan_info[o].amount,
              error::wallet_internal_error, "Unexpected values of new and old outputs");
          THROW_WALLET_EXCEPTION_IF(m_transfers_in[kit->second].amount() > tx_scan_info[o].amount,
              error::wallet_internal_error, "Unexpected values of new and old outputs");
          tx_money_got_in_outs -= td.amount();

          const auto amount = tx_scan_info[o].amount;
          if (!pool)
          {
            td.m_block_height = height;
            td.m_internal_output_index = o;
            td.m_global_output_index = o_indices[o];
            td.m_tx = (const cryptonote::transaction_prefix&)tx;
            td.m_txid = txid;
            td.m_amount = amount;
            td.m_noise = tx_scan_info[o].noise;

            THROW_WALLET_EXCEPTION_IF(td.otk() != tx_scan_info[o].in_ephemeral.pub, error::wallet_internal_error, "Inconsistent public keys");
            THROW_WALLET_EXCEPTION_IF(td.m_spent, error::wallet_internal_error, "Inconsistent spent status");
            THROW_WALLET_EXCEPTION_IF(amount!=td.amount(), error::wallet_internal_error, "Inconsistent spent status");

            MINFO("Received money: " << print_money(td.amount()) << ", with tx: " << txid);
            if (0 != m_callback)
              m_callback->on_money_received(height, txid, tx, td.m_amount, spends_one_of_ours(tx), td.m_tx.unlock_time);
          }

        }
      }
    }
  }while(0);


  uint64_t tx_money_spent_in_ins = 0;
  // The line below is equivalent to "boost::optional<uint32_t> subaddr_account;", but avoids the GCC warning: ‘*((void*)& subaddr_account +4)’ may be used uninitialized in this function
  // It's a GCC bug with boost::optional, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=47679
  // check all outputs for spending (compare key images)
  for(auto& in: tx.vin)
  {
    if(in.type() != typeid(cryptonote::txin_to_key))
      continue;
    const cryptonote::txin_to_key &in_to_key = boost::get<cryptonote::txin_to_key>(in);
    auto it = m_key_images.find(in_to_key.k_image);
    if(it != m_key_images.end())
    {
      transfer_details& td = m_transfers_in[it->second];
      uint64_t amount = td.amount();
      tx_money_spent_in_ins += amount;
      if (!pool)
      {
        MINFO("Spent money: " << print_money(amount) << ", with tx: " << txid);
        set_spent(it->second, height);
        if (0 != m_callback)
          m_callback->on_money_spent(height, txid, tx, amount, tx);
      }
    }

  }

  const uint64_t fee =  tx.rct_signatures.txnFee;

  if (tx_money_spent_in_ins > 0 && !pool)
  {
    process_outgoing(txid, tx, height, ts, tx_money_spent_in_ins, tx_money_got_in_outs);
    // if sending to yourself at the same subaddress account, set the outgoing payment amount to 0 so that it's less confusing
    if (tx_money_spent_in_ins == tx_money_got_in_outs + fee)
    {
      auto i = m_confirmed_txs.find(txid);
      THROW_WALLET_EXCEPTION_IF(i == m_confirmed_txs.end(), error::wallet_internal_error,
        "confirmed tx wasn't found: " + string_tools::pod_to_hex(txid));
      i->second.m_change = tx_money_got_in_outs;
    }
  }

  // create payment_details for each incoming transfer to a subaddress index
  if (tx_money_got_in_outs > 0)
  {
    {
      pool_transfer_in payment;
      payment.m_tx_hash      = txid;
      payment.m_fee          = tx.rct_signatures.txnFee;
      payment.m_amount       = tx_money_got_in_outs;
      payment.m_block_height = height;
      payment.m_unlock_time  = tx.unlock_time;
      payment.m_timestamp    = ts;
      payment.m_coinbase     = miner_tx;
      payment.m_double_spend_seen=double_spend_seen;
      if (pool) {
        m_pool_transfers_in[txid]=payment;

        if (0 != m_callback)
          m_callback->on_unconfirmed_money_received(height, txid, tx, payment.m_amount);
      }
     

      MINFO("transfer in found in " << (pool ? "pool" : "block") << ": "  << " / " << payment.m_tx_hash << " / " << payment.m_amount);
    }

  }


}

//----------------------------------------------------------------------------------------------------
void wallet2::check_acc_out_precomp(const tx_out &o, const crypto::key_derivation &derivation, size_t i, tx_scan_info_t &tx_scan_info) const
{

  auto otk=boost::get<txout_to_key>(o.target).key;
  hw::device &hwdev = hw::get_device("default");
   crypto::public_key B2;
      //B=otk - H(kG,a,oi)*G
      hwdev.derive_subaddress_public_key(otk, derivation, i, B2);
  tx_scan_info.received =  m_account.get_view_public_key()==B2;

 if(tx_scan_info.received)
  {
    tx_scan_info.money_transfered = o.amount; // may be 0 for ringct outputs
  }
  else
  {
    tx_scan_info.money_transfered = 0;
  }
 
  tx_scan_info.error = false;
}
//----------------------------------------------------------------------------------------------------
void wallet2::check_acc_out_precomp(const tx_out &o, const crypto::key_derivation &derivation,size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info) const
{
  if (!is_out_data || i >= is_out_data->received.size())
    return check_acc_out_precomp(o, derivation,  i, tx_scan_info);

  tx_scan_info.received = is_out_data->received[i];

  tx_scan_info.error = false;
}
//----------------------------------------------------------------------------------------------------
void wallet2::check_acc_out_precomp_once(const tx_out &o, const crypto::key_derivation &derivation,  size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info, bool &already_seen) const
{
  if (already_seen)
    return;
  check_acc_out_precomp(o, derivation,  i, is_out_data, tx_scan_info);
  if (tx_scan_info.received)
    already_seen = true;
}


//----------------------------------------------------------------------------------------------------
void wallet2::scan_output(const cryptonote::transaction &tx, bool miner_tx, const crypto::public_key &tx_pub_key, size_t i, tx_scan_info_t &tx_scan_info, int &num_vouts_received,  uint64_t &tx_money_got_in_outs, std::vector<size_t> &outs, bool pool)
{
  THROW_WALLET_EXCEPTION_IF(i >= tx.vout.size(), error::wallet_internal_error, "Invalid vout index");

  // if keys are encrypted, ask for password
  if (m_ask_password == AskPasswordToDecrypt  )
  {
    static critical_section password_lock;
    CRITICAL_REGION_LOCAL(password_lock);
    if (!m_encrypt_keys_after_refresh)
    {
      boost::optional<epee::wipeable_string> pwd = m_callback->on_get_password(pool ? "output found in pool" : "output received");
      THROW_WALLET_EXCEPTION_IF(!pwd, error::password_needed, tr("Password is needed to compute key image for incoming monero"));
      THROW_WALLET_EXCEPTION_IF(!verify_password(*pwd), error::password_needed, tr("Invalid password: password is needed to compute key image for incoming monero"));
      decrypt_keys(*pwd);
      m_encrypt_keys_after_refresh = *pwd;
    }
  }

    bool r = cryptonote::generate_key_image_helper(m_account.get_keys(),  tx_pub_key, i, tx_scan_info.in_ephemeral, tx_scan_info.ki, m_account.get_device());
      
      const auto otk= boost::get<cryptonote::txout_to_key>(tx.vout[i].target).key;

    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
    THROW_WALLET_EXCEPTION_IF(tx_scan_info.in_ephemeral.pub != otk,error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key");


  THROW_WALLET_EXCEPTION_IF(std::find(outs.begin(), outs.end(), i) != outs.end(), error::wallet_internal_error, "Same output cannot be added twice");
  if (tx_scan_info.money_transfered == 0 && !miner_tx)
  {
     crypto::key_derivation kA;
    crypto::generate_key_derivation(tx_pub_key,m_account.get_keys().m_view_secret_key,kA);

    auto [amount, noise]= rct::decodeRctSimple(tx.rct_signatures,kA,i);
    tx_scan_info.money_transfered = amount;
    tx_scan_info.noise=noise; 
  }
  if (tx_scan_info.money_transfered == 0)
  {
    MERROR("Invalid output amount, skipping");
    tx_scan_info.error = true;
    return;
  }
  outs.push_back(i);

  tx_money_got_in_outs += tx_scan_info.money_transfered;
  tx_scan_info.amount = tx_scan_info.money_transfered;
  ++num_vouts_received;
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

        if (0 != m_callback)
        { // FIXME: this isn't right, but simplewallet just logs that we got a block.
          cryptonote::block dummy;
          m_callback->on_new_block(current_index, dummy);
        }
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
wallet2::tx_cache_data wallet2::cache_tx_data(const cryptonote::transaction& tx, const crypto::hash &txid) const
{
  tx_cache_data  tc{};
  if(!cryptonote::parse_tx_extra(tx.extra, tc.tx_extra_fields))
  {
    // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
    MINFO("Transaction extra has unsupported format: " << txid);
    if (tc.tx_extra_fields.empty())
      return tc;
  }

  // Don't try to extract tx public key if tx has no ouputs
  {
    const size_t rec_size = tx.vout.size();
    if (!tx.vout.empty())
    {
      // if tx.vout is not empty, we loop through all tx pubkeys
      const std::vector<bool> rec(rec_size, false);
      tx_extra_pub_key pub_key_field{};
      if(!find_tx_extra_field_by_type(tc.tx_extra_fields, pub_key_field)){
        MERROR("not found tx pub key");
        return tc;
      }

        tc.primary={pub_key_field.pub_key, {}, rec};
    }
  }
  return tc;
}

//----------------------------------------------------------------------------------------------------
void wallet2::process_outgoing(const crypto::hash &txid, const cryptonote::transaction &tx, uint64_t height, uint64_t ts, uint64_t spent, uint64_t received)
{
  auto entry = m_confirmed_txs.insert_or_assign(txid, confirmed_transfer_out());
   auto & ctd = entry.first->second;
  // fill with the info we know, some info might already be there
  if (entry.second)
  {
    // this case will happen if the tx is from our outputs, but was sent by another
    // wallet (eg, we're a cold wallet and the hot wallet sent it). For RCT transactions,
    // we only see 0 input amounts, so have to deduce amount out from other parameters.
   
    ctd.m_amount_in = spent;
    ctd.m_change = received;
    ctd.m_amount_out = spent - tx.rct_signatures.txnFee-received;
    
  }

  ctd.m_block_height = height;
  ctd.m_timestamp = ts;
  ctd.m_unlock_time = tx.unlock_time;

}
}