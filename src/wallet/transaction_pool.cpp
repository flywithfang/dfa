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
void wallet2::update_pool_state( bool refreshed)
{
  MDEBUG("update_pool_state start");

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
  MDEBUG("update_pool_state got pool");

  // remove any pending tx that's not in the pool
  // TODO: set tx_propagation_timeout to CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE * 3 / 2 after v15 hardfork
  constexpr const std::chrono::seconds tx_propagation_timeout{500};
  const auto now = std::chrono::system_clock::now();
  auto it = m_pool_transfer_outs.begin();
  while (it != m_pool_transfer_outs.end())
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
    auto & utd = pit->second;
    if (!found)
    {
      // we want to avoid a false positive when we ask for the pool just after
      // a tx is removed from the pool due to being found in a new block, but
      // just before the block is visible by refresh. So we keep a boolean, so
      // that the first time we don't see the tx, we set that boolean, and only
      // delete it the second time it is checked (but only when refreshed, so
      // we're sure we've seen the blockchain state first)
      if (utd.m_state == wallet2::unconfirmed_transfer_out::pending)
      {
        MINFO("Pending txid " << txid << " not in pool, marking as not in pool");
        pit->second.m_state = wallet2::unconfirmed_transfer_out::pending_not_in_pool;
      }
      else if (utd.m_state == wallet2::unconfirmed_transfer_out::pending_not_in_pool && refreshed &&
        now > std::chrono::system_clock::from_time_t(utd.m_sent_time) + tx_propagation_timeout)
      {
        MINFO("Pending txid " << txid << " not in pool after " << tx_propagation_timeout.count() <<
          " seconds, marking as failed");
        utd.m_state = wallet2::unconfirmed_transfer_out::failed;
        
        // the inputs aren't spent anymore, since the tx failed
        for (size_t i = 0; i < utd.m_tx.vin.size(); ++i)
        {
          if (utd.m_tx.vin[i].type() == typeid(txin_to_key))
          {
            txin_to_key &tx_in_to_key = boost::get<txin_to_key>(utd.m_tx.vin[i]);
            for (size_t j = 0; j < m_transfers_in.size(); ++j)
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
  MDEBUG("update_pool_state done first loop");

  // remove pool txes to us that aren't in the pool anymore
  // but only if we just refreshed, so that the tx can go in
  // the in transfers list instead (or nowhere if it just
  // disappeared without being mined)
  if (refreshed)
    remove_obsolete_pool_transfer_in(res.tx_hashes);

  MDEBUG("update_pool_state end");
}


void wallet2::remove_obsolete_pool_transfer_in(const std::vector<crypto::hash> &pool_txids)
{
  // remove pool txes to us that aren't in the pool anymore
  std::unordered_multimap<crypto::hash, wallet2::pool_transfer_in>::iterator uit = m_pool_transfers_in.begin();
  while (uit != m_pool_transfers_in.end())
  {
  	const auto & utd = uit->second;
    const crypto::hash &txid = utd.m_tx_hash;
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
void wallet2::get_unconfirmed_transfer_in(std::list<std::pair<crypto::hash,wallet2::pool_transfer_in>>& payments, uint64_t min_height,uint64_t max_height) const
{
 
}

//----------------------------------------------------------------------------------------------------
void wallet2::get_payments_out(std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_out>>& confirmed_payments,uint64_t min_height, uint64_t max_height) const
{
  for (auto i = m_confirmed_transfer_outs.begin(); i != m_confirmed_transfer_outs.end(); ++i) {
    if (i->second.m_block_height <= min_height || i->second.m_block_height > max_height)
      continue;
    confirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_payments_out(std::list<std::pair<crypto::hash,wallet2::unconfirmed_transfer_out>>& unconfirmed_payments) const
{
  for (auto i = m_pool_transfer_outs.begin(); i != m_pool_transfer_outs.end(); ++i) {
   
    unconfirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_transfer_in(std::list<std::pair<crypto::hash,wallet2::pool_transfer_in>>& unconfirmed_payments) const
{
  for (auto i = m_pool_transfers_in.begin(); i != m_pool_transfers_in.end(); ++i) {
   
    unconfirmed_payments.push_back(*i);
  }
}

}