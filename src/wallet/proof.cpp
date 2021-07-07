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


void wallet2::check_tx_key_helper(const cryptonote::transaction &tx, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, const cryptonote::account_public_address &address, uint64_t &received) const
{
  received = 0;

  for (size_t n = 0; n < tx.vout.size(); ++n)
  {
    const cryptonote::txout_to_key* const out_key = boost::get<cryptonote::txout_to_key>(std::addressof(tx.vout[n].target));
    if (!out_key)
      continue;

    crypto::public_key derived_out_key;
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