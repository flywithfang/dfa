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

namespace tools{

//----------------------------------------------------------------------------------------------------

void wallet2::check_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations)
{
  crypto::key_derivation derivation;
  //tx_key*A OK= H(kA,oi)G+B  tx_key=kG
  THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(address.m_view_public_key, tx_key, derivation), error::wallet_internal_error,
    "Failed to generate key derivation from supplied parameters");

  std::vector<crypto::key_derivation> additional_derivations;
  additional_derivations.resize(additional_tx_keys.size());
  for (size_t i = 0; i < additional_tx_keys.size(); ++i)
    THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(address.m_view_public_key, additional_tx_keys[i], additional_derivations[i]), error::wallet_internal_error,
      "Failed to generate key derivation from supplied parameters");

  check_tx_key_helper(txid, derivation, additional_derivations, address, received, in_pool, confirmations);
}


void wallet2::check_tx_key_helper(const crypto::hash &txid, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations)
{
  COMMAND_RPC_GET_TRANSACTIONS::request req;
  COMMAND_RPC_GET_TRANSACTIONS::response res;
  req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
  req.decode_as_json = false;
  req.prune = true;

  bool ok;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    uint64_t pre_call_credits = m_rpc_payment_state.credits;
    req.client = get_client_signature();
    ok = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client);
    THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
      error::wallet_internal_error, "Failed to get transaction from daemon");
    check_rpc_cost("/gettransactions", res.credits, pre_call_credits, COST_PER_TX);
  }

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  if (res.txs.size() == 1)
  {
    ok = get_pruned_tx(res.txs.front(), tx, tx_hash);
    THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");
  }
  else
  {
    cryptonote::blobdata tx_data;
    ok = string_tools::parse_hexstr_to_binbuff(res.txs_as_hex.front(), tx_data);
    THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");
    THROW_WALLET_EXCEPTION_IF(!cryptonote::parse_and_validate_tx_from_blob(tx_data, tx),
        error::wallet_internal_error, "Failed to validate transaction from daemon");
    tx_hash = cryptonote::get_transaction_hash(tx);
  }

  THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error,
    "Failed to get the right transaction from daemon");
  THROW_WALLET_EXCEPTION_IF(!additional_derivations.empty() && additional_derivations.size() != tx.vout.size(), error::wallet_internal_error,
    "The size of additional derivations is wrong");

  check_tx_key_helper(tx, derivation, additional_derivations, address, received);

  in_pool = res.txs.front().in_pool;
  confirmations = 0;
  if (!in_pool)
  {
    std::string err;
    uint64_t bc_height = get_daemon_blockchain_height(err);
    if (err.empty())
      confirmations = bc_height - res.txs.front().block_height;
  }
}

void wallet2::check_tx_key_helper(const cryptonote::transaction &tx, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, const cryptonote::account_public_address &address, uint64_t &received) const
{
  received = 0;

  for (size_t n = 0; n < tx.vout.size(); ++n)
  {
    const cryptonote::txout_to_key* const out_key = boost::get<cryptonote::txout_to_key>(std::addressof(tx.vout[n].target));
    if (!out_key)
      continue;

    crypto::public_key derived_out_key;
    //H(kA,oi)G  kG
    bool r = crypto::derive_public_key(derivation, n, address.m_spend_public_key, derived_out_key);
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to derive public key");
    bool found = out_key->key == derived_out_key;
    crypto::key_derivation found_derivation = derivation;
    if (!found && !additional_derivations.empty())
    {
      r = crypto::derive_public_key(additional_derivations[n], n, address.m_spend_public_key, derived_out_key);
      THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to derive public key");
      found = out_key->key == derived_out_key;
      found_derivation = additional_derivations[n];
    }

    if (found)
    {
      uint64_t amount;
      if (tx.version == 1 || tx.rct_signatures.type == rct::RCTTypeNull)
      {
        amount = tx.vout[n].amount;
      }
      else
      {
        crypto::secret_key scalar1;
        crypto::derivation_to_scalar(found_derivation, n, scalar1);
        rct::ecdhTuple ecdh_info = tx.rct_signatures.ecdhInfo[n];
        rct::ecdhDecode(ecdh_info, rct::sk2rct(scalar1), tx.rct_signatures.type == rct::RCTTypeBulletproof2 || tx.rct_signatures.type == rct::RCTTypeCLSAG);
        const rct::key C = tx.rct_signatures.outPk[n].mask;
        rct::key Ctmp;
        THROW_WALLET_EXCEPTION_IF(sc_check(ecdh_info.mask.bytes) != 0, error::wallet_internal_error, "Bad ECDH input mask");
        THROW_WALLET_EXCEPTION_IF(sc_check(ecdh_info.amount.bytes) != 0, error::wallet_internal_error, "Bad ECDH input amount");
        rct::addKeys2(Ctmp, ecdh_info.mask, ecdh_info.amount, rct::H);
        if (rct::equalKeys(C, Ctmp))
          amount = rct::h2d(ecdh_info.amount);
        else
          amount = 0;
      }
      received += amount;
    }
  }
}
}