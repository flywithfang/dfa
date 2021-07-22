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
#include "rpc/rpc_payment_signature.h"
#include "rpc/rpc_payment_costs.h"
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
void wallet2::update_pool_state(std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> &process_txs, bool refreshed)
{
  MTRACE("update_pool_state start");

  auto keys_reencryptor = epee::misc_utils::create_scope_leave_handler([&, this]() {
    if (m_encrypt_keys_after_refresh)
    {
      encrypt_keys(*m_encrypt_keys_after_refresh);
      m_encrypt_keys_after_refresh = boost::none;
    }
  });

  // get the pool state
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN::request req;
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN::response res;

  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};


    bool r = epee::net_utils::invoke_http_json("/get_transaction_pool_hashes.bin", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_transaction_pool_hashes.bin", error::get_tx_pool_error);
  }
  MTRACE("update_pool_state got pool");

  // remove any pending tx that's not in the pool
  // TODO: set tx_propagation_timeout to CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE * 3 / 2 after v15 hardfork
  constexpr const std::chrono::seconds tx_propagation_timeout{500};
  const auto now = std::chrono::system_clock::now();
  std::unordered_map<crypto::hash, wallet2::unconfirmed_transfer_details>::iterator it = m_unconfirmed_txs.begin();
  while (it != m_unconfirmed_txs.end())
  {
    const crypto::hash &txid = it->first;
    bool found = false;
    for (const auto &it2: res.tx_hashes)
    {
      if (it2 == txid)
      {
        found = true;
        break;
      }
    }
    auto pit = it++;
    if (!found)
    {
      // we want to avoid a false positive when we ask for the pool just after
      // a tx is removed from the pool due to being found in a new block, but
      // just before the block is visible by refresh. So we keep a boolean, so
      // that the first time we don't see the tx, we set that boolean, and only
      // delete it the second time it is checked (but only when refreshed, so
      // we're sure we've seen the blockchain state first)
      if (pit->second.m_state == wallet2::unconfirmed_transfer_details::pending)
      {
        MINFO("Pending txid " << txid << " not in pool, marking as not in pool");
        pit->second.m_state = wallet2::unconfirmed_transfer_details::pending_not_in_pool;
      }
      else if (pit->second.m_state == wallet2::unconfirmed_transfer_details::pending_not_in_pool && refreshed &&
        now > std::chrono::system_clock::from_time_t(pit->second.m_sent_time) + tx_propagation_timeout)
      {
        MINFO("Pending txid " << txid << " not in pool after " << tx_propagation_timeout.count() <<
          " seconds, marking as failed");
        pit->second.m_state = wallet2::unconfirmed_transfer_details::failed;

        auto & utd = pit->second;
        // the inputs aren't spent anymore, since the tx failed
        for (size_t i = 0; i < utd.m_tx.vin.size(); ++i)
        {
          if (utd.m_tx.vin[i].type() == typeid(txin_to_key))
          {
            txin_to_key &tx_in_to_key = boost::get<txin_to_key>(utd.m_tx.vin[i]);
            for (size_t j = 0; i < m_transfers_in.size(); ++j)
            {
              const transfer_details &td = m_transfers_in[j];
              if (td.m_key_image == tx_in_to_key.k_image)
              {
                 MINFO("Resetting spent status for output " << i << ": " << td.m_key_image);
                 set_unspent(j);
                 break;
              }
            }
          }
        }
      }
    }
  }
  MTRACE("update_pool_state done first loop");

  // remove pool txes to us that aren't in the pool anymore
  // but only if we just refreshed, so that the tx can go in
  // the in transfers list instead (or nowhere if it just
  // disappeared without being mined)
  if (refreshed)
    remove_obsolete_pool_txs(res.tx_hashes);

  MTRACE("update_pool_state done second loop");

  // gather txids of new pool txes to us
  std::vector<std::pair<crypto::hash, bool>> txids;
  for (const auto &txid: res.tx_hashes)
  {
    bool txid_found_in_up = false;
    for (const auto &up: m_pool_transfers_in)
    {
      if (up.second.m_pd.m_tx_hash == txid)
      {
        txid_found_in_up = true;
        break;
      }
    }
    if (m_scanned_pool_txs[0].find(txid) != m_scanned_pool_txs[0].end() || m_scanned_pool_txs[1].find(txid) != m_scanned_pool_txs[1].end())
    {
      // if it's for us, we want to keep track of whether we saw a double spend, so don't bail out
      if (!txid_found_in_up)
      {
        LOG_PRINT_L2("Already seen " << txid << ", and not for us, skipped");
        continue;
      }
    }
    if (!txid_found_in_up)
    {
      MINFO("Found new pool tx: " << txid);
      bool found = false;
      for (const auto &i: m_unconfirmed_txs)
      {
        if (i.first == txid)
        {
          found = true;
          // if this is a payment to yourself at a different subaddress account, don't skip it
          // so that you can see the incoming pool tx with 'show_transfers' on that receiving subaddress account
          const unconfirmed_transfer_details& utd = i.second;
          for (const auto& dst : utd.m_dests)
          {
            auto subaddr_index = m_subaddresses.find(dst.addr.m_spend_public_key);
            if (subaddr_index != m_subaddresses.end() && subaddr_index->second.major != utd.m_subaddr_account)
            {
              found = false;
              break;
            }
          }
          break;
        }
      }
      if (!found)
      {
        // not one of those we sent ourselves
        txids.push_back({txid, false});
      }
      else
      {
        MINFO("We sent that one");
      }
    }
  }

  // get those txes
  if (!txids.empty())
  {
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req;
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res;
    for (const auto &p: txids)
      req.txs_hashes.push_back(epee::string_tools::pod_to_hex(p.first));
    MDEBUG("asking for " << txids.size() << " transactions");
    req.decode_as_json = false;
    req.prune = true;

    bool r;
    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};


      r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client, rpc_timeout);
    }

    MDEBUG("Got " << r << " and " << res.status);
    if (r && res.status == CORE_RPC_STATUS_OK)
    {
      if (res.txs.size() == txids.size())
      {
        for (const auto &tx_entry: res.txs)
        {
          if (tx_entry.in_pool)
          {
            cryptonote::transaction tx;
            cryptonote::blobdata bd;
            crypto::hash tx_hash;

            if (get_pruned_tx(tx_entry, tx, tx_hash))
            {
                const std::vector<std::pair<crypto::hash, bool>>::const_iterator i = std::find_if(txids.begin(), txids.end(),
                    [tx_hash](const std::pair<crypto::hash, bool> &e) { return e.first == tx_hash; });
                if (i != txids.end())
                {
                  process_txs.push_back(std::make_tuple(tx, tx_hash, tx_entry.double_spend_seen));
                }
                else
                {
                  MERROR("Got txid " << tx_hash << " which we did not ask for");
                }
            }
            else
            {
              LOG_PRINT_L0("Failed to parse transaction from daemon");
            }
          }
          else
          {
            MINFO("Transaction from daemon was in pool, but is no more");
          }
        }
      }
      else
      {
        LOG_PRINT_L0("Expected " << txids.size() << " tx(es), got " << res.txs.size());
      }
    }
    else
    {
      LOG_PRINT_L0("Error calling gettransactions daemon RPC: r " << r << ", status " << get_rpc_status(res.status));
    }
  }
  MTRACE("update_pool_state end");
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_pool_state(const std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> &txs)
{
  const time_t now = time(NULL);
  for (const auto &e: txs)
  {
    const cryptonote::transaction &tx = std::get<0>(e);
    const crypto::hash &tx_hash = std::get<1>(e);
    const bool double_spend_seen = std::get<2>(e);
    process_new_transaction(tx_hash, tx, std::vector<uint64_t>(), 0, 0, now, false, true, double_spend_seen, {});
    m_scanned_pool_txs[0].insert(tx_hash);
    if (m_scanned_pool_txs[0].size() > 5000)
    {
      std::swap(m_scanned_pool_txs[0], m_scanned_pool_txs[1]);
      m_scanned_pool_txs[0].clear();
    }
  }
}

void wallet2::remove_obsolete_pool_txs(const std::vector<crypto::hash> &pool_txids)
{
  // remove pool txes to us that aren't in the pool anymore
  std::unordered_multimap<crypto::hash, wallet2::pool_payment_details>::iterator uit = m_pool_transfers_in.begin();
  while (uit != m_pool_transfers_in.end())
  {
  	const auto & utd = uit->second;
    const crypto::hash &txid = utd.m_pd.m_tx_hash;
    bool found = false;
    for (const auto &it2: pool_txids)
    {
      if (it2 == txid)
      {
        found = true;
        break;
      }
    }
    auto pit = uit++;
    if (!found)
    {
      MINFO("Removing " << txid << " from unconfirmed payments, not found in pool");
      m_pool_transfers_in.erase(pit);
      if (0 != m_callback)
        m_callback->on_pool_tx_removed(txid);
    }
  }
}

//----------------------------------------------------------------------------------------------------
void wallet2::get_payments(const crypto::hash& payment_id, std::list<wallet2::payment_details>& payments, uint64_t min_height) const
{
 
}


//----------------------------------------------------------------------------------------------------
void wallet2::get_payments(std::list<std::pair<crypto::hash,wallet2::payment_details>>& payments, uint64_t min_height, uint64_t max_height) const
{
 
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments_out(std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_details>>& confirmed_payments,uint64_t min_height, uint64_t max_height) const
{
  for (auto i = m_confirmed_txs.begin(); i != m_confirmed_txs.end(); ++i) {
    if (i->second.m_block_height <= min_height || i->second.m_block_height > max_height)
      continue;
    confirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_payments_out(std::list<std::pair<crypto::hash,wallet2::unconfirmed_transfer_details>>& unconfirmed_payments) const
{
  for (auto i = m_unconfirmed_txs.begin(); i != m_unconfirmed_txs.end(); ++i) {
   
    unconfirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_payments(std::list<std::pair<crypto::hash,wallet2::pool_payment_details>>& unconfirmed_payments) const
{
  for (auto i = m_pool_transfers_in.begin(); i != m_pool_transfers_in.end(); ++i) {
   
    unconfirmed_payments.push_back(*i);
  }
}

}