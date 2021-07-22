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

namespace tools{

//----------------------------------------------------------------------------------------------------

void wallet2::check_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_sec, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations)
{
  crypto::key_derivation derivation;
  //tx_sec*A OK= H(kA,oi)G+B  tx_sec=k
  const auto & A=address.m_view_public_key;
  THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(A, tx_sec, derivation), error::wallet_internal_error,
    "Failed to generate key derivation from supplied parameters");

  check_tx_key_helper(txid, derivation,  address, received, in_pool, confirmations);
}


void wallet2::check_tx_key_helper(const crypto::hash &txid, const crypto::key_derivation &derivation, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations)
{
  COMMAND_RPC_GET_TRANSACTIONS::request req;
  COMMAND_RPC_GET_TRANSACTIONS::response res;
  req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
  req.decode_as_json = false;
  req.prune = true;

  bool ok;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    ok = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client);
    THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
      error::wallet_internal_error, "Failed to get transaction from daemon");
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


  check_tx_key_helper(tx, derivation,  address, received);

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

void wallet2::check_tx_key_helper(const cryptonote::transaction &tx, const crypto::key_derivation &derivation,  const cryptonote::account_public_address &address, uint64_t &received) const
{
  received = 0;
  for (size_t n = 0; n < tx.vout.size(); ++n)
  {
    const cryptonote::txout_to_key* const out_key = boost::get<cryptonote::txout_to_key>(std::addressof(tx.vout[n].target));
    if (!out_key)
      continue;

    crypto::public_key otk;
    //H(kA,oi)G  kG
    bool r = crypto::derive_public_key(derivation, n, address.m_spend_public_key, otk);
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to derive public key");
    bool found = out_key->key == otk;

    if (found)
    {
      uint64_t amount{};
      if (tx.rct_signatures.type == rct::RCTTypeNull)
      {
        amount = tx.vout[n].amount;
      }
      else
      {
        crypto::secret_key ss;
        crypto::derivation_to_scalar(derivation, n, ss);
        rct::key shared_sec=rct::sk2rct(ss);
        const rct::ecdhTuple & ecdh_info = tx.rct_signatures.ecdhInfo[n];
        const auto a= rct::ecdhDecode(ecdh_info.amount, shared_sec);
        const rct::key C = tx.rct_signatures.outPk[n].mask;
        rct::key C2;
        THROW_WALLET_EXCEPTION_IF(sc_check(a.bytes) != 0, error::wallet_internal_error, "Bad ECDH input amount");
        const noise= rct::genCommitmentMask(shared_sec);
        rct::addKeys2(C2, noise, a, rct::H);
        if (rct::equalKeys(C, C2))
          amount = rct::h2d(a);
        else
          amount = 0;
      }
      received += amount;
    }
  }
}

bool wallet2::check_tx_proof(const cryptonote::transaction &tx, const cryptonote::account_public_address &address,  const std::string &message, const std::string &sig_str, uint64_t &received) const
{
  // InProofV1, InProofV2, OutProofV1, OutProofV2
  const bool is_out = sig_str.substr(0, 3) == "Out";
  const std::string header = is_out ? sig_str.substr(0,10) : sig_str.substr(0,9);
  int version = 2; // InProofV2
  else if (is_out) version = 2; // OutProofV2

  const size_t header_len = header.size();
  THROW_WALLET_EXCEPTION_IF(sig_str.size() < header_len || sig_str.substr(0, header_len) != header, error::wallet_internal_error,
    "Signature header check error");

  // decode base58
  crypto::public_key kA{};
  crypto::signature sig{};
  const size_t pk_len = tools::base58::encode(std::string((const char *)&kA, sizeof(crypto::public_key))).size();
  const size_t sig_len = tools::base58::encode(std::string((const char *)&sig, sizeof(crypto::signature))).size();
  THROW_WALLET_EXCEPTION_IF(sig_str.size() != header_len + num_sigs * (pk_len + sig_len), error::wallet_internal_error,
    "Wrong signature size");
  {
    std::string pk_decoded;
    std::string sig_decoded;
    const size_t offset = header_len +  (pk_len + sig_len);
    THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(offset, pk_len), pk_decoded), error::wallet_internal_error,
      "Signature decoding error");
    THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(offset + pk_len, sig_len), sig_decoded), error::wallet_internal_error,
      "Signature decoding error");
    THROW_WALLET_EXCEPTION_IF(sizeof(crypto::public_key) != pk_decoded.size() || sizeof(crypto::signature) != sig_decoded.size(), error::wallet_internal_error,
      "Signature decoding error");
    memcpy(&kA, pk_decoded.data(), sizeof(crypto::public_key));
    memcpy(&sig, sig_decoded.data(), sizeof(crypto::signature));
  }

  crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
  THROW_WALLET_EXCEPTION_IF(tx_pub_key == null_pkey, error::wallet_internal_error, "Tx pubkey was not found");

  THROW_WALLET_EXCEPTION_IF( 1 != num_sigs, error::wallet_internal_error, "Signature size mismatch with additional tx pubkeys");

  const crypto::hash txid = cryptonote::get_transaction_hash(tx);
  std::string prefix_data((const char*)&txid, sizeof(crypto::hash));
  prefix_data += message;
  crypto::hash prefix_hash;
  crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  // check signature
  bool good_signature{};
  if (is_out)
  {
    good_signature=crypto::check_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, boost::none, kA, sig, version);

  }
  else
  {
    good_signature= crypto::check_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, boost::none, kA, sig, version);
  }

  if (good_signature)
  {
    // obtain key derivation by multiplying scalar 1 to the shared secret
    crypto::key_derivation derivation;
      THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(kA, rct::rct2sk(rct::I), derivation), error::wallet_internal_error, "Failed to generate key derivation");

    check_tx_key_helper(tx, derivation,  address, received);
    return true;
  }
  return false;
}

bool wallet2::check_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address,  const std::string &message, const std::string &sig_str, uint64_t &received, bool &in_pool, uint64_t &confirmations)
{
  // fetch tx pubkey from the daemon
  COMMAND_RPC_GET_TRANSACTIONS::request req;
  COMMAND_RPC_GET_TRANSACTIONS::response res;
  req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
  req.decode_as_json = false;
  req.prune = true;

  bool ok;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};

    ok = net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client);
    THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
      error::wallet_internal_error, "Failed to get transaction from daemon");
    
  }

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  {
    ok = get_pruned_tx(res.txs.front(), tx, tx_hash);
    THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");
  }

  THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

  if (!check_tx_proof(tx, address,  message, sig_str, received))
    return false;

  in_pool = res.txs.front().in_pool;
  confirmations = 0;
  if (!in_pool)
  {
    std::string err;
    uint64_t bc_height = get_daemon_blockchain_height(err);
    if (err.empty())
      confirmations = bc_height - res.txs.front().block_height;
  }

  return true;
}

std::string wallet2::get_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address,  const std::string &message)
{
    // fetch tx pubkey from the daemon
    COMMAND_RPC_GET_TRANSACTIONS::request req;
    COMMAND_RPC_GET_TRANSACTIONS::response res;
    req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
    req.decode_as_json = false;
    req.prune = true;

    bool ok;
    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      ok = net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client);
      THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
        error::wallet_internal_error, "Failed to get transaction from daemon");
    }

    cryptonote::transaction tx;
    crypto::hash tx_hash;
    {
      ok = get_pruned_tx(res.txs.front(), tx, tx_hash);
      THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");
    }
 
    THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

    // determine if the address is found in the subaddress hash table (i.e. whether the proof is outbound or inbound)
    crypto::secret_key tx_sec = crypto::null_skey;
    const bool is_out = m_account.get_spend_public_key()!=address.m_spend_public_key;
    if (is_out)
    {
      THROW_WALLET_EXCEPTION_IF(!get_tx_key(txid, tx_sec), error::wallet_internal_error, "Tx secret key wasn't found in the wallet file.");
    }

    return get_tx_proof(tx, tx_sec,  address, message);
}

std::string wallet2::get_tx_proof(const cryptonote::transaction &tx, const crypto::secret_key &tx_sec, const cryptonote::account_public_address &address,  const std::string &message) const
{
  hw::device &hwdev = m_account.get_device();
  
  const auto & A=address.m_view_public_key;
  const auto & B=address.m_spend_public_key;
  // determine if the address is found in the subaddress hash table (i.e. whether the proof is outbound or inbound)
  const bool is_out = m_account.get_spend_public_key()!=B;

  const crypto::hash txid = cryptonote::get_transaction_hash(tx);
  std::string prefix_data((const char*)&txid, sizeof(crypto::hash));
  prefix_data += message;
  crypto::hash prefix_hash;
  crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  crypto::signature sig{};
  std::string sig_str;
  crypto::public_key kA{};
  if (is_out)
  {
     rct::key  aP;
    hwdev.scalarmultKey(aP, rct::pk2rct(A), rct::sk2rct(tx_sec));
    kA = rct::rct2pk(aP);
    crypto::public_key tx_pub_key;

    {
      crypto::secret_key_to_public_key(tx_sec, tx_pub_key);
      crypto::generate_tx_proof(prefix_hash, tx_pub_key, A, boost::none, kA, tx_sec, sig);
    }
   
    sig_str = std::string("OutProofV2");
  }
  else
  {
    rct::key  aP;
    crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
    THROW_WALLET_EXCEPTION_IF(tx_pub_key == null_pkey, error::wallet_internal_error, "Tx pubkey was not found");

    const crypto::secret_key& a = m_account.get_keys().m_view_secret_key;
    hwdev.scalarmultKey(aP, rct::pk2rct(tx_pub_key), rct::sk2rct(a));
    kA =  rct2pk(aP);
 
    {
      hwdev.generate_tx_proof(prefix_hash,A, tx_pub_key, boost::none, kA, a, sig);
    }
   
    sig_str = std::string("InProofV2");
  }
  // check if this address actually received any funds
  crypto::key_derivation derivation;
  THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(kA, rct::rct2sk(rct::I), derivation), error::wallet_internal_error, "Failed to generate key derivation");
  
  uint64_t received;
  check_tx_key_helper(tx, derivation,  address, received);
  THROW_WALLET_EXCEPTION_IF(!received, error::wallet_internal_error, tr("No funds received in this tx."));

  // concatenate all signature strings
    sig_str +=
      tools::base58::encode(std::string((const char *)&kA, sizeof(kA))) +
      tools::base58::encode(std::string((const char *)&sig, sizeof(sig)));
  return sig_str;
}

//----------------------------------------------------------------------------------------------------
std::string wallet2::get_spend_proof(const crypto::hash &txid, const std::string &message)
{
  THROW_WALLET_EXCEPTION_IF(m_watch_only, error::wallet_internal_error,
    "get_spend_proof requires spend secret key and is not available for a watch-only wallet");

  // fetch tx from daemon
  COMMAND_RPC_GET_TRANSACTIONS::request req = AUTO_VAL_INIT(req);
  req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
  req.decode_as_json = false;
  req.prune = true;
  COMMAND_RPC_GET_TRANSACTIONS::response res = AUTO_VAL_INIT(res);
  bool r;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};


    r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "gettransactions");
    THROW_WALLET_EXCEPTION_IF(res.txs.size() != 1, error::wallet_internal_error,
      "daemon returned wrong response for gettransactions, wrong txs count = " +
      std::to_string(res.txs.size()) + ", expected 1");
    
  }

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(res.txs[0], tx, tx_hash), error::wallet_internal_error, "Failed to get tx from daemon");

  std::vector<std::vector<crypto::signature>> signatures;

  // get signature prefix hash
  std::string sig_prefix_data((const char*)&txid, sizeof(crypto::hash));
  sig_prefix_data += message;
  crypto::hash sig_prefix_hash;
  crypto::cn_fast_hash(sig_prefix_data.data(), sig_prefix_data.size(), sig_prefix_hash);

  for(size_t i = 0; i < tx.vin.size(); ++i)
  {
    const txin_to_key* const in_key = boost::get<txin_to_key>(std::addressof(tx.vin[i]));
    if (in_key == nullptr)
      continue;

    // check if the key image belongs to us
    const auto found = m_key_images.find(in_key->k_image);
    if(found == m_key_images.end())
    {
      THROW_WALLET_EXCEPTION_IF(i > 0, error::wallet_internal_error, "subset of key images belong to us, very weird!");
      THROW_WALLET_EXCEPTION_IF(true, error::wallet_internal_error, "This tx wasn't generated by this wallet!");
    }

    // derive the real output keypair
    const transfer_details& in_td = m_transfers_in[found->second];
    const txout_to_key* const in_tx_out_pkey = boost::get<txout_to_key>(std::addressof(in_td.m_tx.vout[in_td.m_internal_output_index].target));
    THROW_WALLET_EXCEPTION_IF(in_tx_out_pkey == nullptr, error::wallet_internal_error, "Output is not txout_to_key");
    const crypto::public_key in_tx_pub_key = get_tx_pub_key_from_extra(in_td.m_tx);
    keypair in_ephemeral;
    crypto::key_image in_img;
    THROW_WALLET_EXCEPTION_IF(!generate_key_image_helper(m_account.get_keys(),in_tx_pub_key,  in_td.m_internal_output_index, in_ephemeral, in_img, m_account.get_device()),
      error::wallet_internal_error, "failed to generate key image");
    THROW_WALLET_EXCEPTION_IF(in_key->k_image != in_img, error::wallet_internal_error, "key image mismatch");

    // get output pubkeys in the ring
    const std::vector<uint64_t> absolute_offsets = cryptonote::relative_output_offsets_to_absolute(in_key->key_offsets);
    const size_t ring_size = in_key->key_offsets.size();
    THROW_WALLET_EXCEPTION_IF(absolute_offsets.size() != ring_size, error::wallet_internal_error, "absolute offsets size is wrong");
    COMMAND_RPC_GET_OUTPUTS_BIN::request req = AUTO_VAL_INIT(req);
    req.outputs.resize(ring_size);
    for (size_t j = 0; j < ring_size; ++j)
    {
      req.outputs[j].amount = in_key->amount;
      req.outputs[j].index = absolute_offsets[j];
    }
    COMMAND_RPC_GET_OUTPUTS_BIN::response res = AUTO_VAL_INIT(res);
    bool r;
    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};


      r = epee::net_utils::invoke_http_bin("/get_outs.bin", req, res, *m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_outs.bin", error::get_outs_error, res.status);
      THROW_WALLET_EXCEPTION_IF(res.outs.size() != ring_size, error::wallet_internal_error,
        "daemon returned wrong response for get_outs.bin, wrong amounts count = " +
        std::to_string(res.outs.size()) + ", expected " +  std::to_string(ring_size));
      
    }

    // copy pubkey pointers
    std::vector<const crypto::public_key *> p_output_keys;
    for (const COMMAND_RPC_GET_OUTPUTS_BIN::outkey &out : res.outs)
      p_output_keys.push_back(&out.key);

    // figure out real output index and secret key
    size_t sec_index = -1;
    for (size_t j = 0; j < ring_size; ++j)
    {
      if (res.outs[j].key == in_ephemeral.pub)
      {
        sec_index = j;
        break;
      }
    }
    THROW_WALLET_EXCEPTION_IF(sec_index >= ring_size, error::wallet_internal_error, "secret index not found");

    // generate ring sig for this input
    signatures.push_back(std::vector<crypto::signature>());
    std::vector<crypto::signature>& sigs = signatures.back();
    sigs.resize(in_key->key_offsets.size());
    crypto::generate_ring_signature(sig_prefix_hash, in_key->k_image, p_output_keys, in_ephemeral.sec, sec_index, sigs.data());
  }

  std::string sig_str = "SpendProofV1";
  for (const std::vector<crypto::signature>& ring_sig : signatures)
    for (const crypto::signature& sig : ring_sig)
       sig_str += tools::base58::encode(std::string((const char *)&sig, sizeof(crypto::signature)));
  return sig_str;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::check_spend_proof(const crypto::hash &txid, const std::string &message, const std::string &sig_str)
{
  const std::string header = "SpendProofV1";
  const size_t header_len = header.size();
  THROW_WALLET_EXCEPTION_IF(sig_str.size() < header_len || sig_str.substr(0, header_len) != header, error::wallet_internal_error,
    "Signature header check error");

  // fetch tx from daemon
  COMMAND_RPC_GET_TRANSACTIONS::request req = AUTO_VAL_INIT(req);
  req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
  req.decode_as_json = false;
  req.prune = true;
  COMMAND_RPC_GET_TRANSACTIONS::response res = AUTO_VAL_INIT(res);
  bool r;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};

    r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "gettransactions");
    THROW_WALLET_EXCEPTION_IF(res.txs.size() != 1, error::wallet_internal_error,
      "daemon returned wrong response for gettransactions, wrong txs count = " +
      std::to_string(res.txs.size()) + ", expected 1");
    
  }

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(res.txs[0], tx, tx_hash), error::wallet_internal_error, "failed to get tx from daemon");

  // check signature size
  size_t num_sigs = 0;
  for(size_t i = 0; i < tx.vin.size(); ++i)
  {
    const txin_to_key* const in_key = boost::get<txin_to_key>(std::addressof(tx.vin[i]));
    if (in_key != nullptr)
      num_sigs += in_key->key_offsets.size();
  }
  std::vector<std::vector<crypto::signature>> signatures = { std::vector<crypto::signature>(1) };
  const size_t sig_len = tools::base58::encode(std::string((const char *)&signatures[0][0], sizeof(crypto::signature))).size();
  if( sig_str.size() != header_len + num_sigs * sig_len ) {
    return false;
  }

  // decode base58
  signatures.clear();
  size_t offset = header_len;
  for(size_t i = 0; i < tx.vin.size(); ++i)
  {
    const txin_to_key* const in_key = boost::get<txin_to_key>(std::addressof(tx.vin[i]));
    if (in_key == nullptr)
      continue;
    signatures.resize(signatures.size() + 1);
    signatures.back().resize(in_key->key_offsets.size());
    for (size_t j = 0; j < in_key->key_offsets.size(); ++j)
    {
      std::string sig_decoded;
      THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(offset, sig_len), sig_decoded), error::wallet_internal_error, "Signature decoding error");
      THROW_WALLET_EXCEPTION_IF(sizeof(crypto::signature) != sig_decoded.size(), error::wallet_internal_error, "Signature decoding error");
      memcpy(&signatures.back()[j], sig_decoded.data(), sizeof(crypto::signature));
      offset += sig_len;
    }
  }

  // get signature prefix hash
  std::string sig_prefix_data((const char*)&txid, sizeof(crypto::hash));
  sig_prefix_data += message;
  crypto::hash sig_prefix_hash;
  crypto::cn_fast_hash(sig_prefix_data.data(), sig_prefix_data.size(), sig_prefix_hash);

  std::vector<std::vector<crypto::signature>>::const_iterator sig_iter = signatures.cbegin();
  for(size_t i = 0; i < tx.vin.size(); ++i)
  {
    const txin_to_key* const in_key = boost::get<txin_to_key>(std::addressof(tx.vin[i]));
    if (in_key == nullptr)
      continue;

    // get output pubkeys in the ring
    COMMAND_RPC_GET_OUTPUTS_BIN::request req = AUTO_VAL_INIT(req);
    const std::vector<uint64_t> absolute_offsets = cryptonote::relative_output_offsets_to_absolute(in_key->key_offsets);
    req.outputs.resize(absolute_offsets.size());
    for (size_t j = 0; j < absolute_offsets.size(); ++j)
    {
      req.outputs[j].amount = in_key->amount;
      req.outputs[j].index = absolute_offsets[j];
    }
    COMMAND_RPC_GET_OUTPUTS_BIN::response res = AUTO_VAL_INIT(res);
    bool r;
    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};


      r = epee::net_utils::invoke_http_bin("/get_outs.bin", req, res, *m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_outs.bin", error::get_outs_error, res.status);
      THROW_WALLET_EXCEPTION_IF(res.outs.size() != req.outputs.size(), error::wallet_internal_error,
        "daemon returned wrong response for get_outs.bin, wrong amounts count = " +
        std::to_string(res.outs.size()) + ", expected " +  std::to_string(req.outputs.size()));
    }

    // copy pointers
    std::vector<const crypto::public_key *> p_output_keys;
    for (const COMMAND_RPC_GET_OUTPUTS_BIN::outkey &out : res.outs)
      p_output_keys.push_back(&out.key);

    // check this ring
    if (!crypto::check_ring_signature(sig_prefix_hash, in_key->k_image, p_output_keys, sig_iter->data()))
      return false;
    ++sig_iter;
  }
  THROW_WALLET_EXCEPTION_IF(sig_iter != signatures.cend(), error::wallet_internal_error, "Signature iterator didn't reach the end");
  return true;
}

std::string wallet2::get_reserve_proof(const boost::optional<std::pair<uint32_t, uint64_t>> &account_minreserve, const std::string &message)
{
  THROW_WALLET_EXCEPTION_IF(m_watch_only, error::wallet_internal_error, "Reserve proof can only be generated by a full wallet");
  THROW_WALLET_EXCEPTION_IF(balance(true) == 0, error::wallet_internal_error, "Zero balance");
  THROW_WALLET_EXCEPTION_IF(account_minreserve && balance(account_minreserve->first, true) < account_minreserve->second, error::wallet_internal_error,
    "Not enough balance in this account for the requested minimum reserve amount");

  // determine which outputs to include in the proof
  std::vector<size_t> selected_transfers;
  for (size_t i = 0; i < m_transfers_in.size(); ++i)
  {
    const transfer_details &td = m_transfers_in[i];
    if (!is_spent(td, true) && !td.m_frozen && (!account_minreserve || account_minreserve->first == td.m_subaddr_index.major))
      selected_transfers.push_back(i);
  }

  if (account_minreserve)
  {
    THROW_WALLET_EXCEPTION_IF(account_minreserve->second == 0, error::wallet_internal_error, "Proved amount must be greater than 0");
    // minimize the number of outputs included in the proof, by only picking the N largest outputs that can cover the requested min reserve amount
    std::sort(selected_transfers.begin(), selected_transfers.end(), [&](const size_t a, const size_t b)
      { return m_transfers_in[a].amount() > m_transfers_in[b].amount(); });
    while (selected_transfers.size() >= 2 && m_transfers_in[selected_transfers[1]].amount() >= account_minreserve->second)
      selected_transfers.erase(selected_transfers.begin());
    size_t sz = 0;
    uint64_t total = 0;
    while (total < account_minreserve->second)
    {
      total += m_transfers_in[selected_transfers[sz]].amount();
      ++sz;
    }
    selected_transfers.resize(sz);
  }

  // compute signature prefix hash
  std::string prefix_data = message;
  prefix_data.append((const char*)&m_account.get_keys().m_account_address, sizeof(cryptonote::account_public_address));
  for (size_t i = 0; i < selected_transfers.size(); ++i)
  {
    prefix_data.append((const char*)&m_transfers_in[selected_transfers[i]].m_key_image, sizeof(crypto::key_image));
  }
  crypto::hash prefix_hash;
  crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  // generate proof entries
  std::vector<reserve_proof_entry> proofs(selected_transfers.size());
  for (size_t i = 0; i < selected_transfers.size(); ++i)
  {
    const transfer_details &td = m_transfers_in[selected_transfers[i]];
    reserve_proof_entry& proof = proofs[i];
    proof.txid = td.m_txid;
    proof.index_in_tx = td.m_internal_output_index;
    proof.key_image = td.m_key_image;

    // get tx pub key 
    const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(td.m_tx);
    THROW_WALLET_EXCEPTION_IF(tx_pub_key == crypto::null_pkey, error::wallet_internal_error, "The tx public key isn't found");

    {
      //Ra=kA
      proof.shared_secret = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(tx_pub_key), rct::sk2rct(m_account.get_keys().m_view_secret_key)));
      crypto::key_derivation derivation;
      THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(proof.shared_secret, rct::rct2sk(rct::I), derivation),        error::wallet_internal_error, "Failed to generate key derivation");
      crypto::public_key B;
      THROW_WALLET_EXCEPTION_IF(!derive_subaddress_public_key(td.otk(), derivation, proof.index_in_tx, B),
        error::wallet_internal_error, "Failed to derive subaddress public key");
    }

    // generate signature for shared secret
    crypto::generate_tx_proof(prefix_hash, m_account.get_keys().m_account_address.m_view_public_key, tx_pub_key, boost::none, proof.shared_secret, m_account.get_keys().m_view_secret_key, proof.shared_secret_sig);

    // derive ephemeral secret key
    crypto::key_image ki;
    cryptonote::keypair ephemeral;
    const bool r = cryptonote::generate_key_image_helper(m_account.get_keys(), tx_pub_key,   td.m_internal_output_index, ephemeral, ki, m_account.get_device());
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
    THROW_WALLET_EXCEPTION_IF(ephemeral.pub != td.otk(), error::wallet_internal_error, "Derived public key doesn't agree with the stored one");

    // generate signature for key image
    crypto::generate_ring_signature(prefix_hash, td.m_key_image, &ephemeral.pub, 1, ephemeral.sec, 0, &proof.key_image_sig);
  }

  // collect all subaddress spend keys that received those outputs and generate their signatures
    crypto::signature  sig;
  {
    crypto::secret_key spend_skey = m_account.get_keys().m_spend_secret_key;

    crypto::public_key spend_pkey = m_account.get_spend_public_key();
    crypto::generate_signature(prefix_hash, spend_pkey, spend_skey, sig);
  }

  // serialize & encode
  std::ostringstream oss;
  binary_archive<true> ar(oss);
  THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, proofs), error::wallet_internal_error, "Failed to serialize proof");
  THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, sig), error::wallet_internal_error, "Failed to serialize proof");
  return "ReserveProofV2" + tools::base58::encode(oss.str());
}

bool wallet2::check_reserve_proof(const cryptonote::account_public_address &address, const std::string &message, const std::string &sig_str, uint64_t &total, uint64_t &spent)
{
  uint32_t rpc_version;
  THROW_WALLET_EXCEPTION_IF(!check_connection(&rpc_version), error::wallet_internal_error, "Failed to connect to daemon: " + get_daemon_address());
  THROW_WALLET_EXCEPTION_IF(rpc_version < MAKE_CORE_RPC_VERSION(1, 0), error::wallet_internal_error, "Daemon RPC version is too old");

  static constexpr char header_v1[] = "ReserveProofV1";
  static constexpr char header_v2[] = "ReserveProofV2"; // assumes same length as header_v1
  THROW_WALLET_EXCEPTION_IF(!boost::string_ref{sig_str}.starts_with(header_v1) && !boost::string_ref{sig_str}.starts_with(header_v2), error::wallet_internal_error,
    "Signature header check error");
  int version = 2; // assume newest version
  if (boost::string_ref{sig_str}.starts_with(header_v1))
      version = 1;
  else if (boost::string_ref{sig_str}.starts_with(header_v2))
      version = 2;

  std::string sig_decoded;
  THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(std::strlen(header_v1)), sig_decoded), error::wallet_internal_error,
    "Signature decoding error");

  bool loaded = false;
  std::vector<reserve_proof_entry> proofs;
  serializable_unordered_map<crypto::public_key, crypto::signature> subaddr_spendkeys;
  try
  {
    std::istringstream iss(sig_decoded);
    binary_archive<false> ar(iss);
    if (::serialization::serialize_noeof(ar, proofs))
      if (::serialization::serialize_noeof(ar, subaddr_spendkeys))
        if (::serialization::check_stream_state(ar))
          loaded = true;
  }
  catch(...) {}
  if (!loaded && m_load_deprecated_formats)
  {
    std::istringstream iss(sig_decoded);
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> proofs >> subaddr_spendkeys.parent();
  }

  THROW_WALLET_EXCEPTION_IF(subaddr_spendkeys.count(address.m_spend_public_key) == 0, error::wallet_internal_error,
    "The given address isn't found in the proof");

  // compute signature prefix hash
  std::string prefix_data = message;
  prefix_data.append((const char*)&address, sizeof(cryptonote::account_public_address));
  for (size_t i = 0; i < proofs.size(); ++i)
  {
    prefix_data.append((const char*)&proofs[i].key_image, sizeof(crypto::key_image));
  }
  crypto::hash prefix_hash;
  crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  // fetch txes from daemon
  COMMAND_RPC_GET_TRANSACTIONS::request gettx_req;
  COMMAND_RPC_GET_TRANSACTIONS::response gettx_res;
  for (size_t i = 0; i < proofs.size(); ++i)
    gettx_req.txs_hashes.push_back(epee::string_tools::pod_to_hex(proofs[i].txid));
  gettx_req.decode_as_json = false;
  gettx_req.prune = true;

  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};


    bool ok = net_utils::invoke_http_json("/gettransactions", gettx_req, gettx_res, *m_http_client);
    THROW_WALLET_EXCEPTION_IF(!ok || gettx_res.txs.size() != proofs.size(),
      error::wallet_internal_error, "Failed to get transaction from daemon");
    
  }

  // check spent status
  COMMAND_RPC_IS_KEY_IMAGE_SPENT::request kispent_req;
  COMMAND_RPC_IS_KEY_IMAGE_SPENT::response kispent_res;
  for (size_t i = 0; i < proofs.size(); ++i)
    kispent_req.key_images.push_back(epee::string_tools::pod_to_hex(proofs[i].key_image));

  bool ok;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};


    ok = epee::net_utils::invoke_http_json("/is_key_image_spent", kispent_req, kispent_res, *m_http_client, rpc_timeout);
    THROW_WALLET_EXCEPTION_IF(!ok || kispent_res.spent_status.size() != proofs.size(),
      error::wallet_internal_error, "Failed to get key image spent status from daemon");
    
  }

  total = spent = 0;
  for (size_t i = 0; i < proofs.size(); ++i)
  {
    const reserve_proof_entry& proof = proofs[i];
    THROW_WALLET_EXCEPTION_IF(gettx_res.txs[i].in_pool, error::wallet_internal_error, "Tx is unconfirmed");

    cryptonote::transaction tx;
    crypto::hash tx_hash;
    ok = get_pruned_tx(gettx_res.txs[i], tx, tx_hash);
    THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");

    THROW_WALLET_EXCEPTION_IF(tx_hash != proof.txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

    THROW_WALLET_EXCEPTION_IF(proof.index_in_tx >= tx.vout.size(), error::wallet_internal_error, "index_in_tx is out of bound");

    const cryptonote::txout_to_key&  out_key = boost::get<cryptonote::txout_to_key>(tx.vout[proof.index_in_tx].target);

    // get tx pub key
    const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
    THROW_WALLET_EXCEPTION_IF(tx_pub_key == crypto::null_pkey, error::wallet_internal_error, "The tx public key isn't found");
   

    // check singature for shared secret
    ok = crypto::check_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, boost::none, proof.shared_secret, proof.shared_secret_sig, version);
  
    if (!ok)
      return false;

    // check signature for key image
    const std::vector<const crypto::public_key*> pubs = { &out_key.key };
    ok = crypto::check_ring_signature(prefix_hash, proof.key_image, &pubs[0], 1, &proof.key_image_sig);
    if (!ok)
      return false;

    // check if the address really received the fund
    crypto::key_derivation derivation;
    THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(proof.shared_secret, rct::rct2sk(rct::I), derivation), error::wallet_internal_error, "Failed to generate key derivation");
    crypto::public_key B;
    crypto::derive_subaddress_public_key(out_key.key, derivation, proof.index_in_tx, B);
    THROW_WALLET_EXCEPTION_IF(m_account.get_spend_public_key()!=B, error::wallet_internal_error,
      "The address doesn't seem to have received the fund");

    // check amount
    {
      // decode rct
      crypto::secret_key shared_secret;
      crypto::derivation_to_scalar(derivation, proof.index_in_tx, shared_secret);
      rct::ecdhTuple ecdh_info = tx.rct_signatures.ecdhInfo[proof.index_in_tx];
      auto [amount,noise]=rct::ecdhDecode(ecdh_info.amount, rct::sk2rct(shared_secret));
    }
    total += amount;
    if (kispent_res.spent_status[i])
      spent += amount;
  }

  // check signatures for all subaddress spend keys
  for (const auto &i : subaddr_spendkeys)
  {
    if (!crypto::check_signature(prefix_hash, i.first, i.second))
      return false;
  }
  return true;
}


// Sign a message with a private key from either the base address or a subaddress
// The signature is also bound to both keys and the signature mode (spend, view) to prevent unintended reuse
std::string wallet2::sign(const std::string &data, message_signature_type_t signature_type) const
{
  const cryptonote::account_keys &keys = m_account.get_keys();
  
  crypto::secret_key skey;
  crypto::public_key pkey;
  crypto::hash hash;
  uint8_t mode;

  // Use the base address
  {
    switch (signature_type)
    {
      case sign_with_spend_key:
        skey = keys.m_spend_secret_key;
        pkey = keys.m_account_address.m_spend_public_key;
        mode = 0;
        break;
      case sign_with_view_key:
        skey = keys.m_view_secret_key;
        pkey = keys.m_account_address.m_view_public_key;
        mode = 1;
        break;
      default: CHECK_AND_ASSERT_THROW_MES(false, "Invalid signature type requested");
    }
    hash = get_message_hash(data,keys.m_account_address.m_spend_public_key,keys.m_account_address.m_view_public_key,mode);
  }

  crypto::signature signature;
  crypto::generate_signature(hash, pkey, skey, signature);
  return std::string("SigV2") + tools::base58::encode(std::string((const char *)&signature, sizeof(signature)));
}

tools::wallet2::message_signature_result_t wallet2::verify(const std::string &data, const cryptonote::account_public_address &address, const std::string &signature) const
{
  static const size_t v2_header_len = strlen("SigV2");
  const bool v2 = signature.size() >= v2_header_len && signature.substr(0, v2_header_len) == "SigV2";
  if ( !v2)
  {
    LOG_PRINT_L0("Signature header check error");
    return {};
  }
  
 
  std::string decoded;
  if (!tools::base58::decode(signature.substr(v2_header_len), decoded)) {
    LOG_PRINT_L0("Signature decoding error");
    return {};
  }
  crypto::signature s;
  if (sizeof(s) != decoded.size()) {
    LOG_PRINT_L0("Signature decoding error");
    return {};
  }
  memcpy(&s, decoded.data(), sizeof(s));
crypto::hash hash;
  // Test each mode and return which mode, if either, succeeded
  hash = get_message_hash(data,address.m_spend_public_key,address.m_view_public_key,(uint8_t) 0);
  if (crypto::check_signature(hash, address.m_spend_public_key, s))
    return {true,  sign_with_spend_key };

  hash = get_message_hash(data,address.m_spend_public_key,address.m_view_public_key,(uint8_t) 1);
  if (crypto::check_signature(hash, address.m_view_public_key, s))
    return {true,   sign_with_view_key };

  // Both modes failed
  return {};
}
}