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
#include "wallet_rpc_helpers.h"
#include "wallet2.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "net/parse.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/core_rpc_server_error_codes.h"
#include "rpc/rpc_payment_signature.h"
#include "rpc/rpc_payment_costs.h"
#include "misc_language.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "multisig/multisig.h"
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
#include "ringdb.h"
#include "device/device_cold.hpp"
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
static uint64_t decodeRct(const rct::rctSig & rv, const crypto::key_derivation &derivation, unsigned int out_index, rct::key & mask, hw::device &hwdev)
{
  crypto::secret_key scalar1;
  hwdev.derivation_to_scalar(derivation, out_index, scalar1);
  try
  {
    switch (rv.type)
    {
    case rct::RCTTypeSimple:
    case rct::RCTTypeBulletproof:
    case rct::RCTTypeBulletproof2:
    case rct::RCTTypeCLSAG:
      return rct::decodeRctSimple(rv, rct::sk2rct(scalar1), out_index, mask, hwdev);
    case rct::RCTTypeFull:
      return rct::decodeRct(rv, rct::sk2rct(scalar1), out_index, mask, hwdev);
    default:
      LOG_ERROR("Unsupported rct type: " << rv.type);
      return 0;
    }
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Failed to decode input " << out_index);
    return 0;
  }
}
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
  if (m_offline)
  {
    blocks_fetched = 0;
    received_money = 0;
    return;
  }

  if(m_light_wallet) {

    // MyMonero get_address_info needs to be called occasionally to trigger wallet sync.
    // This call is not really needed for other purposes and can be removed if mymonero changes their backend.
    tools::COMMAND_RPC_GET_ADDRESS_INFO::response res;

    // Get basic info
    if(light_wallet_get_address_info(res)) {
      // Last stored block height
      uint64_t prev_height = m_light_wallet_blockchain_height;
      // Update lw heights
      m_light_wallet_scanned_block_height = res.scanned_block_height;
      m_light_wallet_blockchain_height = res.blockchain_height;
      // If new height - call new_block callback
      if(m_light_wallet_blockchain_height != prev_height)
      {
        MDEBUG("new block since last time!");
        m_callback->on_lw_new_block(m_light_wallet_blockchain_height - 1);
      }
      m_light_wallet_connected = true;
      MDEBUG("lw scanned block height: " <<  m_light_wallet_scanned_block_height);
      MDEBUG("lw blockchain height: " <<  m_light_wallet_blockchain_height);
      MDEBUG(m_light_wallet_blockchain_height-m_light_wallet_scanned_block_height << " blocks behind");
      // TODO: add wallet created block info

      light_wallet_get_address_txs();
    } else
      m_light_wallet_connected = false;

    // Lighwallet refresh done
    return;
  }
  received_money = false;
  blocks_fetched = 0;
  uint64_t added_blocks = 0;
  size_t try_count = 0;
  crypto::hash last_tx_hash_id = m_transfers.size() ? m_transfers.back().m_txid : null_hash;
  std::list<crypto::hash> short_chain_history;
  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter(tpool);
  uint64_t blocks_start_height;
  std::vector<cryptonote::block_complete_entry> blocks;
  std::vector<parsed_block> parsed_blocks;
  bool refreshed = false;
  std::shared_ptr<std::map<std::pair<uint64_t, uint64_t>, size_t>> output_tracker_cache;
  hw::device &hwdev = m_account.get_device();

  // pull the first set of blocks
  get_short_chain_history(short_chain_history, (m_first_refresh_done || trusted_daemon) ? 1 : FIRST_REFRESH_GRANULARITY);
  m_run.store(true, std::memory_order_relaxed);
  if (start_height > m_blockchain.size() || m_refresh_from_block_height > m_blockchain.size()) {
    if (!start_height)
      start_height = m_refresh_from_block_height;
    // we can shortcut by only pulling hashes up to the start_height
    fast_refresh(start_height, blocks_start_height, short_chain_history);
    // regenerate the history now that we've got a full set of hashes
    short_chain_history.clear();
    get_short_chain_history(short_chain_history, (m_first_refresh_done || trusted_daemon) ? 1 : FIRST_REFRESH_GRANULARITY);
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

  auto scope_exit_handler_hwdev = epee::misc_utils::create_scope_leave_handler([&](){hwdev.computing_key_images(false);});

  // get updated pool state first, but do not process those txes just yet,
  // since that might cause a password prompt, which would introduce a data
  // leak allowing a passive adversary with traffic analysis capability to
  // infer when we get an incoming output
  std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> process_pool_txs;
  update_pool_state(process_pool_txs, true);

  bool first = true, last = false;
  while(m_run.load(std::memory_order_relaxed))
  {
    uint64_t next_blocks_start_height;
    std::vector<cryptonote::block_complete_entry> next_blocks;
    std::vector<parsed_block> next_parsed_blocks;
    bool error;
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
        refreshed = true;
        break;
      }
      if (!last)
        tpool.submit(&waiter, [&]{pull_and_parse_next_blocks(start_height, next_blocks_start_height, short_chain_history, blocks, parsed_blocks, next_blocks, next_parsed_blocks, last, error, exception);});

      if (!first)
      {
        try
        {
          process_parsed_blocks(blocks_start_height, blocks, parsed_blocks, added_blocks, output_tracker_cache.get());
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
          short_chain_history.clear();
          get_short_chain_history(short_chain_history);
          fast_refresh(stop_height, blocks_start_height, short_chain_history, true);
          THROW_WALLET_EXCEPTION_IF((m_blockchain.size() == stop_height || (m_blockchain.size() == 1 && stop_height == 0) ? false : true), error::wallet_internal_error, "Unexpected hashchain size");
          THROW_WALLET_EXCEPTION_IF(m_blockchain.offset() != 0, error::wallet_internal_error, "Unexpected hashchain offset");
          for (const auto &h: tip)
            m_blockchain.push_back(h);
          short_chain_history.clear();
          get_short_chain_history(short_chain_history);
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
        refreshed = true;
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

      // if we've got at least 10 blocks to refresh, assume we're starting
      // a long refresh, and setup a tracking output cache if we need to
      if (m_track_uses && (!output_tracker_cache || output_tracker_cache->empty()) && next_blocks.size() >= 10)
        output_tracker_cache = create_output_tracker_cache();

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
    catch (const error::payment_required&)
    {
      // no point in trying again, it'd just eat up credits
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
        LOG_PRINT_L1("Another try pull_blocks (try_count=" << try_count << ")...");
        first = true;
        start_height = 0;
        blocks.clear();
        parsed_blocks.clear();
        short_chain_history.clear();
        get_short_chain_history(short_chain_history, 1);
        ++try_count;
      }
      else
      {
        LOG_ERROR("pull_blocks failed, try_count=" << try_count);
        throw;
      }
    }
  }
  if(last_tx_hash_id != (m_transfers.size() ? m_transfers.back().m_txid : null_hash))
    received_money = true;

  try
  {
    // If stop() is called we don't need to check pending transactions
    if (check_pool && m_run.load(std::memory_order_relaxed) && !process_pool_txs.empty())
      process_pool_state(process_pool_txs);
  }
  catch (...)
  {
    LOG_PRINT_L1("Failed to check pending transactions");
  }

  m_first_refresh_done = true;

  LOG_PRINT_L1("Refresh done, blocks received: " << blocks_fetched << ", balance (all accounts): " << print_money(balance_all(false)) << ", unlocked: " << print_money(unlocked_balance_all(false)));
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
      tpool.submit(&waiter, boost::bind(&wallet2::parse_block_round, this, std::cref(blocks[i].block),
        std::ref(parsed_blocks[i].block), std::ref(parsed_blocks[i].hash), std::ref(parsed_blocks[i].error)), true);
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
      parsed_blocks[i].txes.resize(blocks[i].txs.size());
      for (size_t j = 0; j < blocks[i].txs.size(); ++j)
      {
        tpool.submit(&waiter, [&, i, j](){
          if (!parse_and_validate_tx_base_from_blob(blocks[i].txs[j].blob, parsed_blocks[i].txes[j]))
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
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req = AUTO_VAL_INIT(req);
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res = AUTO_VAL_INIT(res);
  req.block_ids = short_chain_history;

  MDEBUG("Pulling blocks: start_height " << start_height);

  req.prune = true;
  req.start_height = start_height;
  req.no_miner_tx = m_refresh_type == RefreshNoCoinbase;

  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    uint64_t pre_call_credits = m_rpc_payment_state.credits;
    req.client = get_client_signature();
    bool r = net_utils::invoke_http_bin("/getblocks.bin", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "getblocks.bin", error::get_blocks_error, get_rpc_status(res.status));
    THROW_WALLET_EXCEPTION_IF(res.blocks.size() != res.output_indices.size(), error::wallet_internal_error,
        "mismatched blocks (" + boost::lexical_cast<std::string>(res.blocks.size()) + ") and output_indices (" +
        boost::lexical_cast<std::string>(res.output_indices.size()) + ") sizes from daemon");
    check_rpc_cost("/getblocks.bin", res.credits, pre_call_credits, 1 + res.blocks.size() * COST_PER_BLOCK);
  }

  blocks_start_height = res.start_height;
  blocks = std::move(res.blocks);
  o_indices = std::move(res.output_indices);
  current_height = res.current_height;

  MDEBUG("Pulled blocks: blocks_start_height " << blocks_start_height << ", count " << blocks.size()
      << ", height " << blocks_start_height + blocks.size() << ", node height " << res.current_height);
}

//----------------------------------------------------------------------------------------------------
void wallet2::process_parsed_blocks(uint64_t start_height, const std::vector<cryptonote::block_complete_entry> &blocks, const std::vector<parsed_block> &parsed_blocks, uint64_t& blocks_added, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache)
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
    THROW_WALLET_EXCEPTION_IF(parsed_blocks[i].txes.size() != parsed_blocks[i].block.tx_hashes.size(),
        error::wallet_internal_error, "Mismatched parsed_blocks[i].txes.size() and parsed_blocks[i].block.tx_hashes.size()");
    if (should_skip_block(parsed_blocks[i].block, start_height + i))
    {
      txidx += 1 + parsed_blocks[i].block.tx_hashes.size();
      continue;
    }
    if (m_refresh_type != RefreshNoCoinbase)
      tpool.submit(&waiter, [&, i, txidx](){ cache_tx_data(parsed_blocks[i].block.miner_tx, get_transaction_hash(parsed_blocks[i].block.miner_tx), tx_cache_data[txidx]); });
    ++txidx;
    for (size_t idx = 0; idx < parsed_blocks[i].txes.size(); ++idx)
    {
      tpool.submit(&waiter, [&, i, idx, txidx](){ cache_tx_data(parsed_blocks[i].txes[idx], parsed_blocks[i].block.tx_hashes[idx], tx_cache_data[txidx]); });
      ++txidx;
    }
  }
  THROW_WALLET_EXCEPTION_IF(txidx != num_txes, error::wallet_internal_error, "txidx does not match tx_cache_data size");
  THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");

  hw::device &hwdev =  m_account.get_device();
  hw::reset_mode rst(hwdev);
  hwdev.set_mode(hw::device::TRANSACTION_PARSE);
  const cryptonote::account_keys &keys = m_account.get_keys();

  auto gender = [&](wallet2::is_out_data &iod) {
    if (!hwdev.generate_key_derivation(iod.pkey, keys.m_view_secret_key, iod.derivation))
    {
      MWARNING("Failed to generate key derivation from tx pubkey, skipping");
      static_assert(sizeof(iod.derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
      memcpy(&iod.derivation, rct::identity().bytes, sizeof(iod.derivation));
    }
  };

  for (size_t i = 0; i < tx_cache_data.size(); ++i)
  {
    if (tx_cache_data[i].empty())
      continue;
    tpool.submit(&waiter, [&hwdev, &gender, &tx_cache_data, i]() {
      auto &slot = tx_cache_data[i];
      boost::unique_lock<hw::device> hwdev_lock(hwdev);
      for (auto &iod: slot.primary)
        gender(iod);
      for (auto &iod: slot.additional)
        gender(iod);
    }, true);
  }
  THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");

  auto geniod = [&](const cryptonote::transaction &tx, size_t n_vouts, size_t txidx) {
    for (size_t k = 0; k < n_vouts; ++k)
    {
      const auto &o = tx.vout[k];
      if (o.target.type() == typeid(cryptonote::txout_to_key))
      {
        std::vector<crypto::key_derivation> additional_derivations;
        additional_derivations.reserve(tx_cache_data[txidx].additional.size());
        for (const auto &iod: tx_cache_data[txidx].additional)
          additional_derivations.push_back(iod.derivation);
        const auto &key = boost::get<txout_to_key>(o.target).key;
        for (size_t l = 0; l < tx_cache_data[txidx].primary.size(); ++l)
        {
          THROW_WALLET_EXCEPTION_IF(tx_cache_data[txidx].primary[l].received.size() != n_vouts,
              error::wallet_internal_error, "Unexpected received array size");
          tx_cache_data[txidx].primary[l].received[k] = is_out_to_acc_precomp(m_subaddresses, key, tx_cache_data[txidx].primary[l].derivation, additional_derivations, k, hwdev);
          additional_derivations.clear();
        }
      }
    }
  };

  txidx = 0;
  for (size_t i = 0; i < blocks.size(); ++i)
  {
    if (should_skip_block(parsed_blocks[i].block, start_height + i))
    {
      txidx += 1 + parsed_blocks[i].block.tx_hashes.size();
      continue;
    }

    if (m_refresh_type != RefreshType::RefreshNoCoinbase)
    {
      THROW_WALLET_EXCEPTION_IF(txidx >= tx_cache_data.size(), error::wallet_internal_error, "txidx out of range");
      const size_t n_vouts = m_refresh_type == RefreshType::RefreshOptimizeCoinbase ? 1 : parsed_blocks[i].block.miner_tx.vout.size();
      tpool.submit(&waiter, [&, i, n_vouts, txidx](){ geniod(parsed_blocks[i].block.miner_tx, n_vouts, txidx); }, true);
    }
    ++txidx;
    for (size_t j = 0; j < parsed_blocks[i].txes.size(); ++j)
    {
      THROW_WALLET_EXCEPTION_IF(txidx >= tx_cache_data.size(), error::wallet_internal_error, "txidx out of range");
      tpool.submit(&waiter, [&, i, j, txidx](){ geniod(parsed_blocks[i].txes[j], parsed_blocks[i].txes[j].vout.size(), txidx); }, true);
      ++txidx;
    }
  }
  THROW_WALLET_EXCEPTION_IF(txidx != tx_cache_data.size(), error::wallet_internal_error, "txidx did not reach expected value");
  THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
  hwdev.set_mode(hw::device::NONE);

  size_t tx_cache_data_offset = 0;
  for (size_t i = 0; i < blocks.size(); ++i)
  {
    const crypto::hash &bl_id = parsed_blocks[i].hash;
    const cryptonote::block &bl = parsed_blocks[i].block;

    if(current_index >= m_blockchain.size())
    {
      process_new_blockchain_entry(bl, blocks[i], parsed_blocks[i], bl_id, current_index, tx_cache_data, tx_cache_data_offset, output_tracker_cache);
      ++blocks_added;
    }
    else if(bl_id != m_blockchain[current_index])
    {
      //split detected here !!!
      THROW_WALLET_EXCEPTION_IF(current_index == start_height, error::wallet_internal_error,
        "wrong daemon response: split starts from the first block in response " + string_tools::pod_to_hex(bl_id) +
        " (height " + std::to_string(start_height) + "), local block id at this height: " +
        string_tools::pod_to_hex(m_blockchain[current_index]));

      detach_blockchain(current_index, output_tracker_cache);
      process_new_blockchain_entry(bl, blocks[i], parsed_blocks[i], bl_id, current_index, tx_cache_data, tx_cache_data_offset, output_tracker_cache);
    }
    else
    {
      LOG_PRINT_L2("Block is already in blockchain: " << string_tools::pod_to_hex(bl_id));
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
void wallet2::process_new_blockchain_entry(const cryptonote::block& b, const cryptonote::block_complete_entry& bche, const parsed_block &parsed_block, const crypto::hash& bl_id, uint64_t height, const std::vector<tx_cache_data> &tx_cache_data, size_t tx_cache_data_offset, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache)
{
  THROW_WALLET_EXCEPTION_IF(bche.txs.size() + 1 != parsed_block.o_indices.indices.size(), error::wallet_internal_error,
      "block transactions=" + std::to_string(bche.txs.size()) +
      " not match with daemon response size=" + std::to_string(parsed_block.o_indices.indices.size()));

  //handle transactions from new block
    
  //optimization: seeking only for blocks that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
  if (!should_skip_block(b, height))
  {
    TIME_MEASURE_START(miner_tx_handle_time);
    if (m_refresh_type != RefreshNoCoinbase)
      process_new_transaction(get_transaction_hash(b.miner_tx), b.miner_tx, parsed_block.o_indices.indices[0].indices, height, b.major_version, b.timestamp, true, false, false, tx_cache_data[tx_cache_data_offset], output_tracker_cache);
    ++tx_cache_data_offset;
    TIME_MEASURE_FINISH(miner_tx_handle_time);

    TIME_MEASURE_START(txs_handle_time);
    THROW_WALLET_EXCEPTION_IF(bche.txs.size() != b.tx_hashes.size(), error::wallet_internal_error, "Wrong amount of transactions for block");
    THROW_WALLET_EXCEPTION_IF(bche.txs.size() != parsed_block.txes.size(), error::wallet_internal_error, "Wrong amount of transactions for block");
    for (size_t idx = 0; idx < b.tx_hashes.size(); ++idx)
    {
      process_new_transaction(b.tx_hashes[idx], parsed_block.txes[idx], parsed_block.o_indices.indices[idx+1].indices, height, b.major_version, b.timestamp, false, false, false, tx_cache_data[tx_cache_data_offset++], output_tracker_cache);
    }
    TIME_MEASURE_FINISH(txs_handle_time);
    m_last_block_reward = cryptonote::get_outs_money_amount(b.miner_tx);
    LOG_PRINT_L2("Processed block: " << bl_id << ", height " << height << ", " <<  miner_tx_handle_time + txs_handle_time << "(" << miner_tx_handle_time << "/" << txs_handle_time <<")ms");
  }else
  {
    if (!(height % 128))
      LOG_PRINT_L2( "Skipped block by timestamp, height: " << height << ", block time " << b.timestamp << ", account time " << m_account.get_createtime());
  }
  m_blockchain.push_back(bl_id);

  if (0 != m_callback)
    m_callback->on_new_block(height, b);
}



static bool emplace_or_replace(std::unordered_multimap<crypto::hash, tools::wallet2::pool_payment_details> &container,
  const crypto::hash &key, const tools::wallet2::pool_payment_details &pd)
{
  auto range = container.equal_range(key);
  for (auto i = range.first; i != range.second; ++i)
  {
    if (i->second.m_pd.m_tx_hash == pd.m_pd.m_tx_hash && i->second.m_pd.m_subaddr_index == pd.m_pd.m_subaddr_index)
    {
      i->second = pd;
      return false;
    }
  }
  container.emplace(key, pd);
  return true;
}


//----------------------------------------------------------------------------------------------------
void wallet2::process_new_transaction(const crypto::hash &txid, const cryptonote::transaction& tx, const std::vector<uint64_t> &o_indices, uint64_t height, uint8_t block_version, uint64_t ts, bool miner_tx, bool pool, bool double_spend_seen, const tx_cache_data &tx_cache_data, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache)
{
  PERF_TIMER(process_new_transaction);
  // In this function, tx (probably) only contains the base information
  // (that is, the prunable stuff may or may not be included)
  if (!miner_tx && !pool)
    process_unconfirmed(txid, tx, height);

  // per receiving subaddress index
  std::unordered_map<cryptonote::subaddress_index, uint64_t> tx_money_got_in_outs;
  std::unordered_map<cryptonote::subaddress_index, amounts_container> tx_amounts_individual_outs;

  crypto::public_key tx_pub_key = null_pkey;
  bool notify = false;

  std::vector<tx_extra_field> local_tx_extra_fields;
  if (tx_cache_data.tx_extra_fields.empty())
  {
    if(!parse_tx_extra(tx.extra, local_tx_extra_fields))
    {
      // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
      LOG_PRINT_L0("Transaction extra has unsupported format: " << txid);
    }
  }
  const std::vector<tx_extra_field> &tx_extra_fields = tx_cache_data.tx_extra_fields.empty() ? local_tx_extra_fields : tx_cache_data.tx_extra_fields;

  // Don't try to extract tx public key if tx has no ouputs
  size_t pk_index = 0;
  std::vector<tx_scan_info_t> tx_scan_info(tx.vout.size());
  std::deque<bool> output_found(tx.vout.size(), false);
  uint64_t total_received_1 = 0;
  while (!tx.vout.empty())
  {
    std::vector<size_t> outs;
    // if tx.vout is not empty, we loop through all tx pubkeys

    tx_extra_pub_key pub_key_field;
    if(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, pk_index++))
    {
      if (pk_index > 1)
        break;
      LOG_PRINT_L0("Public key wasn't found in the transaction extra. Skipping transaction " << txid);
      if(0 != m_callback)
        m_callback->on_skip_transaction(height, txid, tx);
      break;
    }
    if (!tx_cache_data.primary.empty())
    {
      THROW_WALLET_EXCEPTION_IF(tx_cache_data.primary.size() < pk_index || pub_key_field.pub_key != tx_cache_data.primary[pk_index - 1].pkey,
          error::wallet_internal_error, "tx_cache_data is out of sync");
    }

    int num_vouts_received = 0;
    tx_pub_key = pub_key_field.pub_key;
    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter(tpool);
    const cryptonote::account_keys& keys = m_account.get_keys();
    crypto::key_derivation derivation;

    std::vector<crypto::key_derivation> additional_derivations;
    tx_extra_additional_pub_keys additional_tx_pub_keys;
    const wallet2::is_out_data *is_out_data_ptr = NULL;
    if (tx_cache_data.primary.empty())
    {
      hw::device &hwdev = m_account.get_device();
      boost::unique_lock<hw::device> hwdev_lock (hwdev);
      hw::reset_mode rst(hwdev);

      hwdev.set_mode(hw::device::TRANSACTION_PARSE);
      if (!hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation))
      {
        MWARNING("Failed to generate key derivation from tx pubkey in " << txid << ", skipping");
        static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
        memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
      }

      if (pk_index == 1)
      {
        // additional tx pubkeys and derivations for multi-destination transfers involving one or more subaddresses
        if (find_tx_extra_field_by_type(tx_extra_fields, additional_tx_pub_keys))
        {
          for (size_t i = 0; i < additional_tx_pub_keys.data.size(); ++i)
          {
            additional_derivations.push_back({});
            if (!hwdev.generate_key_derivation(additional_tx_pub_keys.data[i], keys.m_view_secret_key, additional_derivations.back()))
            {
              MWARNING("Failed to generate key derivation from additional tx pubkey in " << txid << ", skipping");
              memcpy(&additional_derivations.back(), rct::identity().bytes, sizeof(crypto::key_derivation));
            }
          }
        }
      }
    }
    else
    {
      THROW_WALLET_EXCEPTION_IF(pk_index - 1 >= tx_cache_data.primary.size(),
          error::wallet_internal_error, "pk_index out of range of tx_cache_data");
      is_out_data_ptr = &tx_cache_data.primary[pk_index - 1];
      derivation = tx_cache_data.primary[pk_index - 1].derivation;
      if (pk_index == 1)
      {
        for (size_t n = 0; n < tx_cache_data.additional.size(); ++n)
        {
          additional_tx_pub_keys.data.push_back(tx_cache_data.additional[n].pkey);
          additional_derivations.push_back(tx_cache_data.additional[n].derivation);
        }
      }
    }

    if (miner_tx && m_refresh_type == RefreshNoCoinbase)
    {
      // assume coinbase isn't for us
    }
    else if (miner_tx && m_refresh_type == RefreshOptimizeCoinbase)
    {
      check_acc_out_precomp_once(tx.vout[0], derivation, additional_derivations, 0, is_out_data_ptr, tx_scan_info[0], output_found[0]);
      THROW_WALLET_EXCEPTION_IF(tx_scan_info[0].error, error::acc_outs_lookup_error, tx, tx_pub_key, m_account.get_keys());

      // this assumes that the miner tx pays a single address
      if (tx_scan_info[0].received)
      {
        // process the other outs from that tx
        // the first one was already checked
        for (size_t i = 1; i < tx.vout.size(); ++i)
        {
          tpool.submit(&waiter, boost::bind(&wallet2::check_acc_out_precomp_once, this, std::cref(tx.vout[i]), std::cref(derivation), std::cref(additional_derivations), i,
            std::cref(is_out_data_ptr), std::ref(tx_scan_info[i]), std::ref(output_found[i])), true);
        }
        THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
        // then scan all outputs from 0
        hw::device &hwdev = m_account.get_device();
        boost::unique_lock<hw::device> hwdev_lock (hwdev);
        hwdev.set_mode(hw::device::NONE);
        for (size_t i = 0; i < tx.vout.size(); ++i)
        {
          THROW_WALLET_EXCEPTION_IF(tx_scan_info[i].error, error::acc_outs_lookup_error, tx, tx_pub_key, m_account.get_keys());
          if (tx_scan_info[i].received)
          {
            hwdev.conceal_derivation(tx_scan_info[i].received->derivation, tx_pub_key, additional_tx_pub_keys.data, derivation, additional_derivations);
            scan_output(tx, miner_tx, tx_pub_key, i, tx_scan_info[i], num_vouts_received, tx_money_got_in_outs, outs, pool);
            if (!tx_scan_info[i].error)
            {
              tx_amounts_individual_outs[tx_scan_info[i].received->index].push_back(tx_scan_info[i].money_transfered);
            }
          }
        }
      }
    }
    else if (tx.vout.size() > 1 && tools::threadpool::getInstance().get_max_concurrency() > 1 && !is_out_data_ptr)
    {
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        tpool.submit(&waiter, boost::bind(&wallet2::check_acc_out_precomp_once, this, std::cref(tx.vout[i]), std::cref(derivation), std::cref(additional_derivations), i,
            std::cref(is_out_data_ptr), std::ref(tx_scan_info[i]), std::ref(output_found[i])), true);
      }
      THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");

      hw::device &hwdev = m_account.get_device();
      boost::unique_lock<hw::device> hwdev_lock (hwdev);
      hwdev.set_mode(hw::device::NONE);
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        THROW_WALLET_EXCEPTION_IF(tx_scan_info[i].error, error::acc_outs_lookup_error, tx, tx_pub_key, m_account.get_keys());
        if (tx_scan_info[i].received)
        {
          hwdev.conceal_derivation(tx_scan_info[i].received->derivation, tx_pub_key, additional_tx_pub_keys.data, derivation, additional_derivations);
          scan_output(tx, miner_tx, tx_pub_key, i, tx_scan_info[i], num_vouts_received, tx_money_got_in_outs, outs, pool);
          if (!tx_scan_info[i].error)
          {
            tx_amounts_individual_outs[tx_scan_info[i].received->index].push_back(tx_scan_info[i].money_transfered);
          }
        }
      }
    }
    else
    {
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        check_acc_out_precomp_once(tx.vout[i], derivation, additional_derivations, i, is_out_data_ptr, tx_scan_info[i], output_found[i]);
        THROW_WALLET_EXCEPTION_IF(tx_scan_info[i].error, error::acc_outs_lookup_error, tx, tx_pub_key, m_account.get_keys());
        if (tx_scan_info[i].received)
        {
          hw::device &hwdev = m_account.get_device();
          boost::unique_lock<hw::device> hwdev_lock (hwdev);
          hwdev.set_mode(hw::device::NONE);
          hwdev.conceal_derivation(tx_scan_info[i].received->derivation, tx_pub_key, additional_tx_pub_keys.data, derivation, additional_derivations);
          scan_output(tx, miner_tx, tx_pub_key, i, tx_scan_info[i], num_vouts_received, tx_money_got_in_outs, outs, pool);
          if (!tx_scan_info[i].error)
          {
            tx_amounts_individual_outs[tx_scan_info[i].received->index].push_back(tx_scan_info[i].money_transfered);
          }
        }
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
  THROW_WALLET_EXCEPTION_IF(tx.vout.size() <= o, error::wallet_internal_error, "wrong out in transaction: internal index=" +
          std::to_string(o) + ", total_outs=" + std::to_string(tx.vout.size()));

        auto kit = m_pub_keys.find(tx_scan_info[o].in_ephemeral.pub);
  THROW_WALLET_EXCEPTION_IF(kit != m_pub_keys.end() && kit->second >= m_transfers.size(),
            error::wallet_internal_error, std::string("Unexpected transfer index from public key: ")
            + "got " + (kit == m_pub_keys.end() ? "<none>" : boost::lexical_cast<std::string>(kit->second))
            + ", m_transfers.size() is " + boost::lexical_cast<std::string>(m_transfers.size()));
        if (kit == m_pub_keys.end())
        {
          uint64_t amount = tx.vout[o].amount ? tx.vout[o].amount : tx_scan_info[o].amount;
          if (!pool)
          {
      m_transfers.push_back(transfer_details{});
      transfer_details& td = m_transfers.back();
      td.m_block_height = height;
      td.m_internal_output_index = o;
      td.m_global_output_index = o_indices[o];
      td.m_tx = (const cryptonote::transaction_prefix&)tx;
      td.m_txid = txid;
            td.m_key_image = tx_scan_info[o].ki;
            td.m_key_image_known = !m_watch_only && !m_multisig;
            if (!td.m_key_image_known)
            {
              // we might have cold signed, and have a mapping to key images
              std::unordered_map<crypto::public_key, crypto::key_image>::const_iterator i = m_cold_key_images.find(tx_scan_info[o].in_ephemeral.pub);
              if (i != m_cold_key_images.end())
              {
                td.m_key_image = i->second;
                td.m_key_image_known = true;
              }
            }
            if (m_watch_only)
            {
              // for view wallets, that flag means "we want to request it"
              td.m_key_image_request = true;
            }
            else
            {
              td.m_key_image_request = false;
            }
            td.m_key_image_partial = m_multisig;
            td.m_amount = amount;
            td.m_pk_index = pk_index - 1;
            td.m_subaddr_index = tx_scan_info[o].received->index;
            if (should_expand(tx_scan_info[o].received->index))
              expand_subaddresses(tx_scan_info[o].received->index);
            if (tx.vout[o].amount == 0)
            {
              td.m_mask = tx_scan_info[o].mask;
              td.m_rct = true;
            }
            else if (miner_tx && tx.version == 2)
            {
              td.m_mask = rct::identity();
              td.m_rct = true;
            }
            else
            {
              td.m_mask = rct::identity();
              td.m_rct = false;
            }
            td.m_frozen = false;
      set_unspent(m_transfers.size()-1);
            if (td.m_key_image_known)
        m_key_images[td.m_key_image] = m_transfers.size()-1;
      m_pub_keys[tx_scan_info[o].in_ephemeral.pub] = m_transfers.size()-1;
            if (output_tracker_cache)
              (*output_tracker_cache)[std::make_pair(tx.vout[o].amount, td.m_global_output_index)] = m_transfers.size() - 1;
            if (m_multisig)
            {
              THROW_WALLET_EXCEPTION_IF(!m_multisig_rescan_k && m_multisig_rescan_info,
                  error::wallet_internal_error, "NULL m_multisig_rescan_k");
              if (m_multisig_rescan_info && m_multisig_rescan_info->front().size() >= m_transfers.size())
                update_multisig_rescan_info(*m_multisig_rescan_k, *m_multisig_rescan_info, m_transfers.size() - 1);
            }
      LOG_PRINT_L0("Received money: " << print_money(td.amount()) << ", with tx: " << txid);
      if (0 != m_callback)
        m_callback->on_money_received(height, txid, tx, td.m_amount, td.m_subaddr_index, spends_one_of_ours(tx), td.m_tx.unlock_time);
          }
          total_received_1 += amount;
          notify = true;
        }
  else if (m_transfers[kit->second].m_spent || m_transfers[kit->second].amount() >= tx_scan_info[o].amount)
        {
    LOG_ERROR("Public key " << epee::string_tools::pod_to_hex(kit->first)
              << " from received " << print_money(tx_scan_info[o].amount) << " output already exists with "
              << (m_transfers[kit->second].m_spent ? "spent" : "unspent") << " "
              << print_money(m_transfers[kit->second].amount()) << " in tx " << m_transfers[kit->second].m_txid << ", received output ignored");
          THROW_WALLET_EXCEPTION_IF(tx_money_got_in_outs[tx_scan_info[o].received->index] < tx_scan_info[o].amount,
              error::wallet_internal_error, "Unexpected values of new and old outputs");
          tx_money_got_in_outs[tx_scan_info[o].received->index] -= tx_scan_info[o].amount;

          amounts_container& tx_amounts_this_out = tx_amounts_individual_outs[tx_scan_info[o].received->index]; // Only for readability on the following lines
          auto amount_iterator = std::find(tx_amounts_this_out.begin(), tx_amounts_this_out.end(), tx_scan_info[o].amount);
          THROW_WALLET_EXCEPTION_IF(amount_iterator == tx_amounts_this_out.end(),
              error::wallet_internal_error, "Unexpected values of new and old outputs");
          tx_amounts_this_out.erase(amount_iterator);
        }
        else
        {
    LOG_ERROR("Public key " << epee::string_tools::pod_to_hex(kit->first)
              << " from received " << print_money(tx_scan_info[o].amount) << " output already exists with "
              << print_money(m_transfers[kit->second].amount()) << ", replacing with new output");
          // The new larger output replaced a previous smaller one
          THROW_WALLET_EXCEPTION_IF(tx_money_got_in_outs[tx_scan_info[o].received->index] < tx_scan_info[o].amount,
              error::wallet_internal_error, "Unexpected values of new and old outputs");
          THROW_WALLET_EXCEPTION_IF(m_transfers[kit->second].amount() > tx_scan_info[o].amount,
              error::wallet_internal_error, "Unexpected values of new and old outputs");
          tx_money_got_in_outs[tx_scan_info[o].received->index] -= m_transfers[kit->second].amount();

          uint64_t amount = tx.vout[o].amount ? tx.vout[o].amount : tx_scan_info[o].amount;
          uint64_t extra_amount = amount - m_transfers[kit->second].amount();
          if (!pool)
          {
            transfer_details &td = m_transfers[kit->second];
      td.m_block_height = height;
      td.m_internal_output_index = o;
      td.m_global_output_index = o_indices[o];
      td.m_tx = (const cryptonote::transaction_prefix&)tx;
      td.m_txid = txid;
            td.m_amount = amount;
            td.m_pk_index = pk_index - 1;
            td.m_subaddr_index = tx_scan_info[o].received->index;
            if (should_expand(tx_scan_info[o].received->index))
              expand_subaddresses(tx_scan_info[o].received->index);
            if (tx.vout[o].amount == 0)
            {
              td.m_mask = tx_scan_info[o].mask;
              td.m_rct = true;
            }
            else if (miner_tx && tx.version == 2)
            {
              td.m_mask = rct::identity();
              td.m_rct = true;
            }
            else
            {
              td.m_mask = rct::identity();
              td.m_rct = false;
            }
            if (output_tracker_cache)
              (*output_tracker_cache)[std::make_pair(tx.vout[o].amount, td.m_global_output_index)] = kit->second;
            if (m_multisig)
            {
              THROW_WALLET_EXCEPTION_IF(!m_multisig_rescan_k && m_multisig_rescan_info,
                  error::wallet_internal_error, "NULL m_multisig_rescan_k");
              if (m_multisig_rescan_info && m_multisig_rescan_info->front().size() >= m_transfers.size())
                update_multisig_rescan_info(*m_multisig_rescan_k, *m_multisig_rescan_info, m_transfers.size() - 1);
            }
            THROW_WALLET_EXCEPTION_IF(td.get_public_key() != tx_scan_info[o].in_ephemeral.pub, error::wallet_internal_error, "Inconsistent public keys");
      THROW_WALLET_EXCEPTION_IF(td.m_spent, error::wallet_internal_error, "Inconsistent spent status");

      LOG_PRINT_L0("Received money: " << print_money(td.amount()) << ", with tx: " << txid);
      if (0 != m_callback)
        m_callback->on_money_received(height, txid, tx, td.m_amount, td.m_subaddr_index, spends_one_of_ours(tx), td.m_tx.unlock_time);
          }
          total_received_1 += extra_amount;
          notify = true;
        }
      }
    }
  }

  THROW_WALLET_EXCEPTION_IF(tx_money_got_in_outs.size() != tx_amounts_individual_outs.size(), error::wallet_internal_error, "Inconsistent size of output arrays");

  uint64_t tx_money_spent_in_ins = 0;
  // The line below is equivalent to "boost::optional<uint32_t> subaddr_account;", but avoids the GCC warning: ‘*((void*)& subaddr_account +4)’ may be used uninitialized in this function
  // It's a GCC bug with boost::optional, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=47679
  auto subaddr_account ([]()->boost::optional<uint32_t> {return boost::none;}());
  std::set<uint32_t> subaddr_indices;
  // check all outputs for spending (compare key images)
  for(auto& in: tx.vin)
  {
    if(in.type() != typeid(cryptonote::txin_to_key))
      continue;
    const cryptonote::txin_to_key &in_to_key = boost::get<cryptonote::txin_to_key>(in);
    auto it = m_key_images.find(in_to_key.k_image);
    if(it != m_key_images.end())
    {
      transfer_details& td = m_transfers[it->second];
      uint64_t amount = in_to_key.amount;
      if (amount > 0)
      {
        if(amount != td.amount())
        {
          MERROR("Inconsistent amount in tx input: got " << print_money(amount) <<
            ", expected " << print_money(td.amount()));
          // this means:
          //   1) the same output pub key was used as destination multiple times,
          //   2) the wallet set the highest amount among them to transfer_details::m_amount, and
          //   3) the wallet somehow spent that output with an amount smaller than the above amount, causing inconsistency
          td.m_amount = amount;
        }
      }
      else
      {
        amount = td.amount();
      }
      tx_money_spent_in_ins += amount;
      if (subaddr_account && *subaddr_account != td.m_subaddr_index.major)
        LOG_ERROR("spent funds are from different subaddress accounts; count of incoming/outgoing payments will be incorrect");
      subaddr_account = td.m_subaddr_index.major;
      subaddr_indices.insert(td.m_subaddr_index.minor);
      if (!pool)
      {
        LOG_PRINT_L0("Spent money: " << print_money(amount) << ", with tx: " << txid);
        set_spent(it->second, height);
        if (0 != m_callback)
          m_callback->on_money_spent(height, txid, tx, amount, tx, td.m_subaddr_index);
      }
    }

    if (!pool && m_track_uses)
    {
      PERF_TIMER(track_uses);
      const uint64_t amount = in_to_key.amount;
      std::vector<uint64_t> offsets = cryptonote::relative_output_offsets_to_absolute(in_to_key.key_offsets);
      if (output_tracker_cache)
      {
        for (uint64_t offset: offsets)
        {
          const std::map<std::pair<uint64_t, uint64_t>, size_t>::const_iterator i = output_tracker_cache->find(std::make_pair(amount, offset));
          if (i != output_tracker_cache->end())
          {
            size_t idx = i->second;
            THROW_WALLET_EXCEPTION_IF(idx >= m_transfers.size(), error::wallet_internal_error, "Output tracker cache index out of range");
            m_transfers[idx].m_uses.push_back(std::make_pair(height, txid));
          }
        }
      }
      else for (transfer_details &td: m_transfers)
      {
        if (amount != in_to_key.amount)
          continue;
        for (uint64_t offset: offsets)
          if (offset == td.m_global_output_index)
            td.m_uses.push_back(std::make_pair(height, txid));
      }
    }
  }

  uint64_t fee = miner_tx ? 0 : tx.version == 1 ? tx_money_spent_in_ins - get_outs_money_amount(tx) : tx.rct_signatures.txnFee;

  if (tx_money_spent_in_ins > 0 && !pool)
  {
    uint64_t self_received = std::accumulate<decltype(tx_money_got_in_outs.begin()), uint64_t>(tx_money_got_in_outs.begin(), tx_money_got_in_outs.end(), 0,
      [&subaddr_account] (uint64_t acc, const std::pair<cryptonote::subaddress_index, uint64_t>& p)
      {
        return acc + (p.first.major == *subaddr_account ? p.second : 0);
      });
    process_outgoing(txid, tx, height, ts, tx_money_spent_in_ins, self_received, *subaddr_account, subaddr_indices);
    // if sending to yourself at the same subaddress account, set the outgoing payment amount to 0 so that it's less confusing
    if (tx_money_spent_in_ins == self_received + fee)
    {
      auto i = m_confirmed_txs.find(txid);
      THROW_WALLET_EXCEPTION_IF(i == m_confirmed_txs.end(), error::wallet_internal_error,
        "confirmed tx wasn't found: " + string_tools::pod_to_hex(txid));
      i->second.m_change = self_received;
    }
  }

  // remove change sent to the spending subaddress account from the list of received funds
  uint64_t sub_change = 0;
  for (auto i = tx_money_got_in_outs.begin(); i != tx_money_got_in_outs.end();)
  {
    if (subaddr_account && i->first.major == *subaddr_account)
    {
      sub_change += i->second;
      tx_amounts_individual_outs.erase(i->first);
      i = tx_money_got_in_outs.erase(i);
    }
    else
      ++i;
  }

  // create payment_details for each incoming transfer to a subaddress index
  if (tx_money_got_in_outs.size() > 0)
  {
    tx_extra_nonce extra_nonce;
    crypto::hash payment_id = null_hash;
    if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
    {
      crypto::hash8 payment_id8 = null_hash8;
      if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
      {
        // We got a payment ID to go with this tx
        LOG_PRINT_L2("Found encrypted payment ID: " << payment_id8);
        MINFO("Consider using subaddresses instead of encrypted payment IDs");
        if (tx_pub_key != null_pkey)
        {
          if (!m_account.get_device().decrypt_payment_id(payment_id8, tx_pub_key, m_account.get_keys().m_view_secret_key))
          {
            LOG_PRINT_L0("Failed to decrypt payment ID: " << payment_id8);
          }
          else
          {
            LOG_PRINT_L2("Decrypted payment ID: " << payment_id8);
            // put the 64 bit decrypted payment id in the first 8 bytes
            memcpy(payment_id.data, payment_id8.data, 8);
            // rest is already 0, but guard against code changes above
            memset(payment_id.data + 8, 0, 24);
          }
        }
        else
        {
          LOG_PRINT_L1("No public key found in tx, unable to decrypt payment id");
        }
      }
      else if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
      {
        bool ignore = block_version >= IGNORE_LONG_PAYMENT_ID_FROM_BLOCK_VERSION;
        if (ignore)
        {
          LOG_PRINT_L2("Found unencrypted payment ID in tx " << txid << " (ignored)");
          MWARNING("Found OBSOLETE AND IGNORED unencrypted payment ID: these are bad for privacy, use subaddresses instead");
          payment_id = crypto::null_hash;
        }
        else
        {
          LOG_PRINT_L2("Found unencrypted payment ID: " << payment_id);
          MWARNING("Found unencrypted payment ID: these are bad for privacy, consider using subaddresses instead");
        }
      }
    }

    uint64_t total_received_2 = sub_change;
    for (const auto& i : tx_money_got_in_outs)
      total_received_2 += i.second;
    if (total_received_1 != total_received_2)
    {
      const el::Level level = el::Level::Warning;
      MCLOG_RED(level, "global", "**********************************************************************");
      MCLOG_RED(level, "global", "Consistency failure in amounts received");
      MCLOG_RED(level, "global", "Check transaction " << txid);
      MCLOG_RED(level, "global", "**********************************************************************");
      exit(1);
      return;
    }

    bool all_same = true;
    for (const auto& i : tx_money_got_in_outs)
    {
      payment_details payment;
      payment.m_tx_hash      = txid;
      payment.m_fee          = fee;
      payment.m_amount       = i.second;
      payment.m_amounts      = tx_amounts_individual_outs[i.first];
      payment.m_block_height = height;
      payment.m_unlock_time  = tx.unlock_time;
      payment.m_timestamp    = ts;
      payment.m_coinbase     = miner_tx;
      payment.m_subaddr_index = i.first;
      if (pool) {
        if (emplace_or_replace(m_unconfirmed_payments, payment_id, pool_payment_details{payment, double_spend_seen}))
          all_same = false;
        if (0 != m_callback)
          m_callback->on_unconfirmed_money_received(height, txid, tx, payment.m_amount, payment.m_subaddr_index);
      }
      else
        m_payments.emplace(payment_id, payment);
      LOG_PRINT_L2("Payment found in " << (pool ? "pool" : "block") << ": " << payment_id << " / " << payment.m_tx_hash << " / " << payment.m_amount);
    }

    // if it's a pool tx and we already had it, don't notify again
    if (pool && all_same)
      notify = false;
  }

  if (notify)
  {
    std::shared_ptr<tools::Notify> tx_notify = m_tx_notify;
    if (tx_notify)
      tx_notify->notify("%s", epee::string_tools::pod_to_hex(txid).c_str(), NULL);
  }
}

//----------------------------------------------------------------------------------------------------
void wallet2::check_acc_out_precomp(const tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, tx_scan_info_t &tx_scan_info) const
{
  hw::device &hwdev = m_account.get_device();
  boost::unique_lock<hw::device> hwdev_lock (hwdev);
  hwdev.set_mode(hw::device::TRANSACTION_PARSE);
  if (o.target.type() !=  typeid(txout_to_key))
  {
     tx_scan_info.error = true;
     LOG_ERROR("wrong type id in transaction out");
     return;
  }
  tx_scan_info.received = is_out_to_acc_precomp(m_subaddresses, boost::get<txout_to_key>(o.target).key, derivation, additional_derivations, i, hwdev);
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
void wallet2::check_acc_out_precomp(const tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info) const
{
  if (!is_out_data || i >= is_out_data->received.size())
    return check_acc_out_precomp(o, derivation, additional_derivations, i, tx_scan_info);

  tx_scan_info.received = is_out_data->received[i];
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
void wallet2::check_acc_out_precomp_once(const tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info, bool &already_seen) const
{
  tx_scan_info.received = boost::none;
  if (already_seen)
    return;
  check_acc_out_precomp(o, derivation, additional_derivations, i, is_out_data, tx_scan_info);
  if (tx_scan_info.received)
    already_seen = true;
}


//----------------------------------------------------------------------------------------------------
void wallet2::scan_output(const cryptonote::transaction &tx, bool miner_tx, const crypto::public_key &tx_pub_key, size_t i, tx_scan_info_t &tx_scan_info, int &num_vouts_received, std::unordered_map<cryptonote::subaddress_index, uint64_t> &tx_money_got_in_outs, std::vector<size_t> &outs, bool pool)
{
  THROW_WALLET_EXCEPTION_IF(i >= tx.vout.size(), error::wallet_internal_error, "Invalid vout index");

  // if keys are encrypted, ask for password
  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only && !m_multisig_rescan_k)
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

  
    bool r = cryptonote::generate_key_image_helper_precomp(m_account.get_keys(), boost::get<cryptonote::txout_to_key>(tx.vout[i].target).key, tx_scan_info.received->derivation, i, tx_scan_info.received->index, tx_scan_info.in_ephemeral, tx_scan_info.ki, m_account.get_device());
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
    THROW_WALLET_EXCEPTION_IF(tx_scan_info.in_ephemeral.pub != boost::get<cryptonote::txout_to_key>(tx.vout[i].target).key,
        error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key");


  THROW_WALLET_EXCEPTION_IF(std::find(outs.begin(), outs.end(), i) != outs.end(), error::wallet_internal_error, "Same output cannot be added twice");
  if (tx_scan_info.money_transfered == 0 && !miner_tx)
  {
    tx_scan_info.money_transfered = tools::decodeRct(tx.rct_signatures, tx_scan_info.received->derivation, i, tx_scan_info.mask, m_account.get_device());
  }
  if (tx_scan_info.money_transfered == 0)
  {
    MERROR("Invalid output amount, skipping");
    tx_scan_info.error = true;
    return;
  }
  outs.push_back(i);
  THROW_WALLET_EXCEPTION_IF(tx_money_got_in_outs[tx_scan_info.received->index] >= std::numeric_limits<uint64_t>::max() - tx_scan_info.money_transfered,
      error::wallet_internal_error, "Overflow in received amounts");
  tx_money_got_in_outs[tx_scan_info.received->index] += tx_scan_info.money_transfered;
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
    short_chain_history.clear();
    get_short_chain_history(short_chain_history);
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
          LOG_PRINT_L2( "Skipped block by height: " << current_index);
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
    req.client = get_client_signature();
    uint64_t pre_call_credits = m_rpc_payment_state.credits;
    bool r = net_utils::invoke_http_bin("/gethashes.bin", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "gethashes.bin", error::get_hashes_error, get_rpc_status(res.status));
    check_rpc_cost("/gethashes.bin", res.credits, pre_call_credits, 1 + res.m_block_ids.size() * COST_PER_BLOCK_HASH);
  }

  blocks_start_height = res.start_height;
  hashes = std::move(res.m_block_ids);
}

}