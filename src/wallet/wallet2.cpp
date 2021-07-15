// Copyright (c) 2014-2020, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

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

//#undef MONERO_DEFAULT_LOG_CATEGORY


static const std::string MULTISIG_SIGNATURE_MAGIC = "SigMultisigPkV1";
static const std::string MULTISIG_EXTRA_INFO_MAGIC = "MultisigxV1";

static const std::string ASCII_OUTPUT_MAGIC = "MoneroAsciiDataV1";

boost::mutex tools::wallet2::default_daemon_address_lock;
std::string tools::wallet2::default_daemon_address = "";

namespace
{
  std::string get_default_ringdb_path()
  {
    boost::filesystem::path dir = tools::get_default_data_dir();
    // remove .bitmonero, replace with .shared-ringdb
    dir = dir.remove_filename();
    dir /= ".shared-ringdb";
    return dir.string();
  }

  std::string pack_multisignature_keys(const std::string& prefix, const std::vector<crypto::public_key>& keys, const crypto::secret_key& signer_secret_key)
  {
    std::string data;
    crypto::public_key signer;
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(signer_secret_key, signer), "Failed to derive public spend key");
    data += std::string((const char *)&signer, sizeof(crypto::public_key));

    for (const auto &key: keys)
    {
      data += std::string((const char *)&key, sizeof(crypto::public_key));
    }

    data.resize(data.size() + sizeof(crypto::signature));

    crypto::hash hash;
    crypto::cn_fast_hash(data.data(), data.size() - sizeof(crypto::signature), hash);
    crypto::signature &signature = *(crypto::signature*)&data[data.size() - sizeof(crypto::signature)];
    crypto::generate_signature(hash, signer, signer_secret_key, signature);

    return MULTISIG_EXTRA_INFO_MAGIC + tools::base58::encode(data);
  }

  std::vector<crypto::public_key> secret_keys_to_public_keys(const std::vector<crypto::secret_key>& keys)
  {
    std::vector<crypto::public_key> public_keys;
    public_keys.reserve(keys.size());

    std::transform(keys.begin(), keys.end(), std::back_inserter(public_keys), [] (const crypto::secret_key& k) -> crypto::public_key {
      crypto::public_key p;
      CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(k, p), "Failed to derive public spend key");
      return p;
    });

    return public_keys;
  }

  bool keys_intersect(const std::unordered_set<crypto::public_key>& s1, const std::unordered_set<crypto::public_key>& s2)
  {
    if (s1.empty() || s2.empty())
      return false;

    for (const auto& e: s1)
    {
      if (s2.find(e) != s2.end())
        return true;
    }

    return false;
  }


}

namespace
{
// Create on-demand to prevent static initialization order fiasco issues.
struct options {
  const command_line::arg_descriptor<std::string> daemon_address = {"daemon-address", tools::wallet2::tr("Use daemon instance at <host>:<port>"), ""};
  const command_line::arg_descriptor<std::string> daemon_host = {"daemon-host", tools::wallet2::tr("Use daemon instance at host <arg> instead of localhost"), ""};
  const command_line::arg_descriptor<std::string> proxy = {"proxy", tools::wallet2::tr("[<ip>:]<port> socks proxy to use for daemon connections"), {}, true};
  const command_line::arg_descriptor<bool> trusted_daemon = {"trusted-daemon", tools::wallet2::tr("Enable commands which rely on a trusted daemon"), false};
  const command_line::arg_descriptor<bool> untrusted_daemon = {"untrusted-daemon", tools::wallet2::tr("Disable commands which rely on a trusted daemon"), false};
  const command_line::arg_descriptor<std::string> password = {"password", tools::wallet2::tr("Wallet password (escape/quote as needed)"), "", true};
  const command_line::arg_descriptor<std::string> password_file = {"password-file", tools::wallet2::tr("Wallet password file"), "", true};
  const command_line::arg_descriptor<int> daemon_port = {"daemon-port", tools::wallet2::tr("Use daemon instance at port <arg> instead of 18081"), 0};
  const command_line::arg_descriptor<std::string> daemon_login = {"daemon-login", tools::wallet2::tr("Specify username[:password] for daemon RPC client"), "", true};
  const command_line::arg_descriptor<std::string> daemon_ssl = {"daemon-ssl", tools::wallet2::tr("Enable SSL on daemon RPC connections: enabled|disabled|autodetect"), "autodetect"};
  const command_line::arg_descriptor<std::string> daemon_ssl_private_key = {"daemon-ssl-private-key", tools::wallet2::tr("Path to a PEM format private key"), ""};
  const command_line::arg_descriptor<std::string> daemon_ssl_certificate = {"daemon-ssl-certificate", tools::wallet2::tr("Path to a PEM format certificate"), ""};
  const command_line::arg_descriptor<std::string> daemon_ssl_ca_certificates = {"daemon-ssl-ca-certificates", tools::wallet2::tr("Path to file containing concatenated PEM format certificate(s) to replace system CA(s).")};
  const command_line::arg_descriptor<std::vector<std::string>> daemon_ssl_allowed_fingerprints = {"daemon-ssl-allowed-fingerprints", tools::wallet2::tr("List of valid fingerprints of allowed RPC servers")};
  const command_line::arg_descriptor<bool> daemon_ssl_allow_any_cert = {"daemon-ssl-allow-any-cert", tools::wallet2::tr("Allow any SSL certificate from the daemon"), false};
  const command_line::arg_descriptor<bool> daemon_ssl_allow_chained = {"daemon-ssl-allow-chained", tools::wallet2::tr("Allow user (via --daemon-ssl-ca-certificates) chain certificates"), false};
  const command_line::arg_descriptor<bool> testnet = {"testnet", tools::wallet2::tr("For testnet. Daemon must also be launched with --testnet flag"), false};
  const command_line::arg_descriptor<bool> stagenet = {"stagenet", tools::wallet2::tr("For stagenet. Daemon must also be launched with --stagenet flag"), false};
  const command_line::arg_descriptor<std::string, false, true, 2> shared_ringdb_dir = {
    "shared-ringdb-dir", tools::wallet2::tr("Set shared ring database path"),
    get_default_ringdb_path(),
    {{ &testnet, &stagenet }},
    [](std::array<bool, 2> testnet_stagenet, bool defaulted, std::string val)->std::string {
      if (testnet_stagenet[0])
        return (boost::filesystem::path(val) / "testnet").string();
      else if (testnet_stagenet[1])
        return (boost::filesystem::path(val) / "stagenet").string();
      return val;
    }
  };
  const command_line::arg_descriptor<uint64_t> kdf_rounds = {"kdf-rounds", tools::wallet2::tr("Number of rounds for the key derivation function"), 1};
  const command_line::arg_descriptor<std::string> hw_device = {"hw-device", tools::wallet2::tr("HW device to use"), ""};
  const command_line::arg_descriptor<std::string> hw_device_derivation_path = {"hw-device-deriv-path", tools::wallet2::tr("HW device wallet derivation path (e.g., SLIP-10)"), ""};
  const command_line::arg_descriptor<std::string> tx_notify = { "tx-notify" , "Run a program for each new incoming transaction, '%s' will be replaced by the transaction hash" , "" };
  const command_line::arg_descriptor<bool> no_dns = {"no-dns", tools::wallet2::tr("Do not use DNS"), false};
  const command_line::arg_descriptor<bool> offline = {"offline", tools::wallet2::tr("Do not connect to a daemon, nor use DNS"), false};
  const command_line::arg_descriptor<std::string> extra_entropy = {"extra-entropy", tools::wallet2::tr("File containing extra entropy to initialize the PRNG (any data, aim for 256 bits of entropy to be useful, which typically means more than 256 bits of data)")};
};


std::unique_ptr<tools::wallet2> make_basic(const boost::program_options::variables_map& vm, bool unattended, const options& opts, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const bool testnet = command_line::get_arg(vm, opts.testnet);
  const bool stagenet = command_line::get_arg(vm, opts.stagenet);
  const network_type nettype = testnet ? TESTNET : stagenet ? STAGENET : MAINNET;
  const uint64_t kdf_rounds = command_line::get_arg(vm, opts.kdf_rounds);
  THROW_WALLET_EXCEPTION_IF(kdf_rounds == 0, tools::error::wallet_internal_error, "KDF rounds must not be 0");

  const bool use_proxy = command_line::has_arg(vm, opts.proxy);
  auto daemon_address = command_line::get_arg(vm, opts.daemon_address);
  auto daemon_host = command_line::get_arg(vm, opts.daemon_host);
  auto daemon_port = command_line::get_arg(vm, opts.daemon_port);
  auto device_name = command_line::get_arg(vm, opts.hw_device);
  auto device_derivation_path = command_line::get_arg(vm, opts.hw_device_derivation_path);
  auto daemon_ssl_private_key = command_line::get_arg(vm, opts.daemon_ssl_private_key);
  auto daemon_ssl_certificate = command_line::get_arg(vm, opts.daemon_ssl_certificate);
  auto daemon_ssl_ca_file = command_line::get_arg(vm, opts.daemon_ssl_ca_certificates);
  auto daemon_ssl_allowed_fingerprints = command_line::get_arg(vm, opts.daemon_ssl_allowed_fingerprints);
  auto daemon_ssl_allow_any_cert = command_line::get_arg(vm, opts.daemon_ssl_allow_any_cert);
  auto daemon_ssl = command_line::get_arg(vm, opts.daemon_ssl);

  // user specified CA file or fingeprints implies enabled SSL by default
  epee::net_utils::ssl_options_t ssl_options = epee::net_utils::ssl_support_t::e_ssl_support_enabled;
  if (daemon_ssl_allow_any_cert)
    ssl_options.verification = epee::net_utils::ssl_verification_t::none;
  else if (!daemon_ssl_ca_file.empty() || !daemon_ssl_allowed_fingerprints.empty())
  {
    std::vector<std::vector<uint8_t>> ssl_allowed_fingerprints{ daemon_ssl_allowed_fingerprints.size() };
    std::transform(daemon_ssl_allowed_fingerprints.begin(), daemon_ssl_allowed_fingerprints.end(), ssl_allowed_fingerprints.begin(), epee::from_hex_locale::to_vector);
    for (const auto &fpr: ssl_allowed_fingerprints)
    {
      THROW_WALLET_EXCEPTION_IF(fpr.size() != SSL_FINGERPRINT_SIZE, tools::error::wallet_internal_error,
          "SHA-256 fingerprint should be " BOOST_PP_STRINGIZE(SSL_FINGERPRINT_SIZE) " bytes long.");
    }

    ssl_options = epee::net_utils::ssl_options_t{
      std::move(ssl_allowed_fingerprints), std::move(daemon_ssl_ca_file)
    };

    if (command_line::get_arg(vm, opts.daemon_ssl_allow_chained))
      ssl_options.verification = epee::net_utils::ssl_verification_t::user_ca;
  }

  if (ssl_options.verification != epee::net_utils::ssl_verification_t::user_certificates || !command_line::is_arg_defaulted(vm, opts.daemon_ssl))
  {
    THROW_WALLET_EXCEPTION_IF(!epee::net_utils::ssl_support_from_string(ssl_options.support, daemon_ssl), tools::error::wallet_internal_error,
       tools::wallet2::tr("Invalid argument for ") + std::string(opts.daemon_ssl.name));
  }

  ssl_options.auth = epee::net_utils::ssl_authentication_t{
    std::move(daemon_ssl_private_key), std::move(daemon_ssl_certificate)
  };

  THROW_WALLET_EXCEPTION_IF(!daemon_address.empty() && !daemon_host.empty() && 0 != daemon_port,
      tools::error::wallet_internal_error, tools::wallet2::tr("can't specify daemon host or port more than once"));

  boost::optional<epee::net_utils::http::login> login{};
  if (command_line::has_arg(vm, opts.daemon_login))
  {
    auto parsed = tools::login::parse(
      command_line::get_arg(vm, opts.daemon_login), false, [password_prompter](bool verify) {
        if (!password_prompter)
        {
          MERROR("Password needed without prompt function");
          return boost::optional<tools::password_container>();
        }
        return password_prompter("Daemon client password", verify);
      }
    );
    if (!parsed)
      return nullptr;

    login.emplace(std::move(parsed->username), std::move(parsed->password).password());
  }

  if (daemon_host.empty())
    daemon_host = "localhost";

  if (!daemon_port)
  {
    daemon_port = get_config(nettype).RPC_DEFAULT_PORT;
  }

  // if no daemon settings are given and we have a previous one, reuse that one
  if (command_line::is_arg_defaulted(vm, opts.daemon_host) && command_line::is_arg_defaulted(vm, opts.daemon_port) && command_line::is_arg_defaulted(vm, opts.daemon_address))
  {
    // not a bug: taking a const ref to a temporary in this way is actually ok in a recent C++ standard
    const std::string &def = tools::wallet2::get_default_daemon_address();
    if (!def.empty())
      daemon_address = def;
  }

  if (daemon_address.empty())
    daemon_address = std::string("http://") + daemon_host + ":" + std::to_string(daemon_port);

  MDEBUG("daemon_address "<<daemon_address);

  {
    const boost::string_ref real_daemon = boost::string_ref{daemon_address}.substr(0, daemon_address.rfind(':'));

    /* If SSL or proxy is enabled, then a specific cert, CA or fingerprint must
       be specified. This is specific to the wallet. */
    const bool verification_required =
      ssl_options.verification != epee::net_utils::ssl_verification_t::none &&
      (ssl_options.support == epee::net_utils::ssl_support_t::e_ssl_support_enabled || use_proxy);

    THROW_WALLET_EXCEPTION_IF(
      verification_required && !ssl_options.has_strong_verification(real_daemon),
      tools::error::wallet_internal_error,
      tools::wallet2::tr("Enabling --") + std::string{use_proxy ? opts.proxy.name : opts.daemon_ssl.name} + tools::wallet2::tr(" requires --") +
        opts.daemon_ssl_allow_any_cert.name + tools::wallet2::tr(" or --") +
        opts.daemon_ssl_ca_certificates.name + tools::wallet2::tr(" or --") + opts.daemon_ssl_allowed_fingerprints.name + tools::wallet2::tr(" or use of a .onion/.i2p domain")
    );
  }

  std::string proxy;
  if (use_proxy)
  {
    proxy = command_line::get_arg(vm, opts.proxy);
    THROW_WALLET_EXCEPTION_IF(
      !net::get_tcp_endpoint(proxy),
      tools::error::wallet_internal_error,
      std::string{"Invalid address specified for --"} + opts.proxy.name);
  }

  boost::optional<bool> trusted_daemon;
  if (!command_line::is_arg_defaulted(vm, opts.trusted_daemon) || !command_line::is_arg_defaulted(vm, opts.untrusted_daemon))
    trusted_daemon = command_line::get_arg(vm, opts.trusted_daemon) && !command_line::get_arg(vm, opts.untrusted_daemon);
  THROW_WALLET_EXCEPTION_IF(!command_line::is_arg_defaulted(vm, opts.trusted_daemon) && !command_line::is_arg_defaulted(vm, opts.untrusted_daemon),
    tools::error::wallet_internal_error, tools::wallet2::tr("--trusted-daemon and --untrusted-daemon are both seen, assuming untrusted"));

  // set --trusted-daemon if local and not overridden
  if (!trusted_daemon)
  {
    try
    {
      trusted_daemon = false;
      if (tools::is_local_address(daemon_address))
      {
        MINFO(tools::wallet2::tr("Daemon is local, assuming trusted"));
        trusted_daemon = true;
      }
    }
    catch (const std::exception &e) { }
  }
  std::cout<<"daemon_address:"<<daemon_address<<std::endl;

  std::unique_ptr<tools::wallet2> wallet(new tools::wallet2(nettype, kdf_rounds, unattended));

  if (!wallet->init(std::move(daemon_address), std::move(login), std::move(proxy), 0, *trusted_daemon, std::move(ssl_options)))
  {
    THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to initialize the wallet"));
  }
  boost::filesystem::path ringdb_path = command_line::get_arg(vm, opts.shared_ringdb_dir);
  wallet->set_ring_database(ringdb_path.string());
  wallet->get_message_store().set_options(vm);
  MDEBUG("device "<<device_name<<","<<device_derivation_path);
  wallet->device_name(device_name);
  wallet->device_derivation_path(device_derivation_path);

  if (command_line::get_arg(vm, opts.no_dns))
    wallet->enable_dns(false);

  if (command_line::get_arg(vm, opts.offline))
    wallet->set_offline();

  const std::string extra_entropy = command_line::get_arg(vm, opts.extra_entropy);
  if (!extra_entropy.empty())
  {
    std::string data;
    THROW_WALLET_EXCEPTION_IF(!epee::file_io_utils::load_file_to_string(extra_entropy, data),
        tools::error::wallet_internal_error, "Failed to load extra entropy from " + extra_entropy);
    add_extra_entropy_thread_safe(data.data(), data.size());
  }

  try
  {
    if (!command_line::is_arg_defaulted(vm, opts.tx_notify))
      wallet->set_tx_notify(std::shared_ptr<tools::Notify>(new tools::Notify(command_line::get_arg(vm, opts.tx_notify).c_str())));
  }
  catch (const std::exception &e)
  {
    MERROR("Failed to parse tx notify spec: " << e.what());
  }

  return wallet;
}

boost::optional<tools::password_container> get_password(const boost::program_options::variables_map& vm, const options& opts, const std::function<boost::optional<tools::password_container>(const char*, bool)> &password_prompter, const bool verify)
{
  if (command_line::has_arg(vm, opts.password) && command_line::has_arg(vm, opts.password_file))
  {
    THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("can't specify more than one of --password and --password-file"));
  }

  if (command_line::has_arg(vm, opts.password))
  {
    return tools::password_container{command_line::get_arg(vm, opts.password)};
  }

  if (command_line::has_arg(vm, opts.password_file))
  {
    std::string password;
    bool r = epee::file_io_utils::load_file_to_string(command_line::get_arg(vm, opts.password_file),
                                                      password);
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, tools::wallet2::tr("the password file specified could not be read"));

    // Remove line breaks the user might have inserted
    boost::trim_right_if(password, boost::is_any_of("\r\n"));
    return {tools::password_container{std::move(password)}};
  }

  THROW_WALLET_EXCEPTION_IF(!password_prompter, tools::error::wallet_internal_error, tools::wallet2::tr("no password specified; use --prompt-for-password to prompt for a password"));

  return password_prompter(verify ? tools::wallet2::tr("Enter a new password for the wallet") : tools::wallet2::tr("Wallet password"), verify);
}

std::pair<std::unique_ptr<tools::wallet2>, tools::password_container> generate_from_json(const std::string& json_file, const boost::program_options::variables_map& vm, bool unattended, const options& opts, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const bool testnet = command_line::get_arg(vm, opts.testnet);
  const bool stagenet = command_line::get_arg(vm, opts.stagenet);
  const network_type nettype = testnet ? TESTNET : stagenet ? STAGENET : MAINNET;

  /* GET_FIELD_FROM_JSON_RETURN_ON_ERROR Is a generic macro that can return
  false. Gcc will coerce this into unique_ptr(nullptr), but clang correctly
  fails. This large wrapper is for the use of that macro */
  std::unique_ptr<tools::wallet2> wallet;
  epee::wipeable_string password;
  const auto do_generate = [&]() -> bool {
    std::string buf;
    if (!epee::file_io_utils::load_file_to_string(json_file, buf)) {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(tools::wallet2::tr("Failed to load file ")) + json_file);
      return false;
    }

    rapidjson::Document json;
    if (json.Parse(buf.c_str()).HasParseError()) {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Failed to parse JSON"));
      return false;
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, version, unsigned, Uint, true, 0);
    const int current_version = 1;
    THROW_WALLET_EXCEPTION_IF(field_version > current_version, tools::error::wallet_internal_error,
      ((boost::format(tools::wallet2::tr("Version %u too new, we can only grok up to %u")) % field_version % current_version)).str());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, filename, std::string, String, true, std::string());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, scan_from_height, uint64_t, Uint64, false, 0);
    const bool recover = true;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, password, std::string, String, false, std::string());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, viewkey, std::string, String, false, std::string());
    crypto::secret_key viewkey;
    if (field_viewkey_found)
    {
      cryptonote::blobdata viewkey_data;
      if(!epee::string_tools::parse_hexstr_to_binbuff(field_viewkey, viewkey_data) || viewkey_data.size() != sizeof(crypto::secret_key))
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to parse view key secret key"));
      }
      viewkey = *reinterpret_cast<const crypto::secret_key*>(viewkey_data.data());
      crypto::public_key pkey;
      if (viewkey == crypto::null_skey)
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("view secret key may not be all zeroes"));
      if (!crypto::secret_key_to_public_key(viewkey, pkey)) {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify view key secret key"));
      }
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, spendkey, std::string, String, false, std::string());
    crypto::secret_key spendkey;
    if (field_spendkey_found)
    {
      cryptonote::blobdata spendkey_data;
      if(!epee::string_tools::parse_hexstr_to_binbuff(field_spendkey, spendkey_data) || spendkey_data.size() != sizeof(crypto::secret_key))
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to parse spend key secret key"));
      }
      spendkey = *reinterpret_cast<const crypto::secret_key*>(spendkey_data.data());
      crypto::public_key pkey;
      if (spendkey == crypto::null_skey)
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("spend secret key may not be all zeroes"));
      if (!crypto::secret_key_to_public_key(spendkey, pkey)) {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify spend key secret key"));
      }
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed, std::string, String, false, std::string());
    std::string old_language;
    crypto::secret_key recovery_key;
    bool restore_deterministic_wallet = false;
    if (field_seed_found)
    {
      if (!crypto::ElectrumWords::words_to_bytes(field_seed, recovery_key, old_language))
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Electrum-style word list failed verification"));
      }
      restore_deterministic_wallet = true;

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed_passphrase, std::string, String, false, std::string());
      if (field_seed_passphrase_found)
      {
        if (!field_seed_passphrase.empty())
          recovery_key = cryptonote::decrypt_key(recovery_key, field_seed_passphrase);
      }
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, address, std::string, String, false, std::string());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, create_address_file, int, Int, false, false);
    bool create_address_file = field_create_address_file;

    // compatibility checks
    if (!field_seed_found && !field_viewkey_found && !field_spendkey_found)
    {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("At least one of either an Electrum-style word list, private view key, or private spend key must be specified"));
    }
    if (field_seed_found && (field_viewkey_found || field_spendkey_found))
    {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Both Electrum-style word list and private key(s) specified"));
    }

    // if an address was given, we check keys against it, and deduce the spend
    // public key if it was not given
    if (field_address_found)
    {
      cryptonote::address_parse_info info;
      if(!get_account_address_from_str(info, nettype, field_address))
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("invalid address"));
      }
      if (field_viewkey_found)
      {
        crypto::public_key pkey;
        if (!crypto::secret_key_to_public_key(viewkey, pkey)) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify view key secret key"));
        }
        if (info.address.m_view_public_key != pkey) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("view key does not match standard address"));
        }
      }
      if (field_spendkey_found)
      {
        crypto::public_key pkey;
        if (!crypto::secret_key_to_public_key(spendkey, pkey)) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify spend key secret key"));
        }
        if (info.address.m_spend_public_key != pkey) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("spend key does not match standard address"));
        }
      }
    }

    const bool deprecated_wallet = restore_deterministic_wallet && ((old_language == crypto::ElectrumWords::old_language_name) ||
      crypto::ElectrumWords::get_is_old_style_seed(field_seed));
    THROW_WALLET_EXCEPTION_IF(deprecated_wallet, tools::error::wallet_internal_error,
      tools::wallet2::tr("Cannot generate deprecated wallets from JSON"));

    wallet.reset(make_basic(vm, unattended, opts, password_prompter).release());
    wallet->set_refresh_from_block_height(field_scan_from_height);
    wallet->explicit_refresh_from_block_height(field_scan_from_height_found);
    if (!old_language.empty())
      wallet->set_seed_language(old_language);

    try
    {
      if (!field_seed.empty())
      {
        wallet->generate(field_filename, field_password, recovery_key, recover, false, create_address_file);
        password = field_password;
      }
      else if (field_viewkey.empty() && !field_spendkey.empty())
      {
        wallet->generate(field_filename, field_password, spendkey, recover, false, create_address_file);
        password = field_password;
      }
      else
      {
        cryptonote::account_public_address address;
        if (!crypto::secret_key_to_public_key(viewkey, address.m_view_public_key)) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify view key secret key"));
        }

        if (field_spendkey.empty())
        {
          // if we have an address but no spend key, we can deduce the spend public key
          // from the address
          if (field_address_found)
          {
            cryptonote::address_parse_info info;
            if(!get_account_address_from_str(info, nettype, field_address))
            {
              THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(tools::wallet2::tr("failed to parse address: ")) + field_address);
            }
            address.m_spend_public_key = info.address.m_spend_public_key;
          }
          else
          {
            THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Address must be specified in order to create watch-only wallet"));
          }
          wallet->generate(field_filename, field_password, address, viewkey, create_address_file);
          password = field_password;
        }
        else
        {
          if (!crypto::secret_key_to_public_key(spendkey, address.m_spend_public_key)) {
            THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify spend key secret key"));
          }
          wallet->generate(field_filename, field_password, address, spendkey, viewkey, create_address_file);
          password = field_password;
        }
      }
    }
    catch (const std::exception& e)
    {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(tools::wallet2::tr("failed to generate new wallet: ")) + e.what());
    }
    return true;
  };

  if (do_generate())
  {
    return {std::move(wallet), tools::password_container(password)};
  }
  return {nullptr, tools::password_container{}};
}




bool get_short_payment_id(crypto::hash8 &payment_id8, const tools::wallet2::pending_tx &ptx, hw::device &hwdev)
{
  std::vector<tx_extra_field> tx_extra_fields;
  parse_tx_extra(ptx.tx.extra, tx_extra_fields); // ok if partially parsed
  cryptonote::tx_extra_nonce extra_nonce;
  if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
  {
    if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
    {
      if (ptx.dests.empty())
      {
        MWARNING("Encrypted payment id found, but no destinations public key, cannot decrypt");
        return false;
      }
      return hwdev.decrypt_payment_id(payment_id8, ptx.dests[0].addr.m_view_public_key, ptx.tx_key);
    }
  }
  return false;
}

tools::wallet2::tx_construction_data get_construction_data_with_decrypted_short_payment_id(const tools::wallet2::pending_tx &ptx, hw::device &hwdev)
{
  tools::wallet2::tx_construction_data construction_data = ptx.construction_data;
  crypto::hash8 payment_id = null_hash8;
  if (get_short_payment_id(payment_id, ptx, hwdev))
  {
    // Remove encrypted
    remove_field_from_tx_extra(construction_data.extra, typeid(cryptonote::tx_extra_nonce));
    // Add decrypted
    std::string extra_nonce;
    set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
    THROW_WALLET_EXCEPTION_IF(!add_extra_nonce_to_tx_extra(construction_data.extra, extra_nonce),
        tools::error::wallet_internal_error, "Failed to add decrypted payment id to tx extra");
    LOG_PRINT_L1("Decrypted payment ID: " << payment_id);
  }
  return construction_data;
}

uint32_t get_subaddress_clamped_sum(uint32_t idx, uint32_t extra)
{
  static constexpr uint32_t uint32_max = std::numeric_limits<uint32_t>::max();
  if (idx > uint32_max - extra)
    return uint32_max;
  return idx + extra;
}

static void setup_shim(hw::wallet_shim * shim, tools::wallet2 * wallet)
{
  shim->get_tx_pub_key_from_received_outs = std::bind(&tools::wallet2::get_tx_pub_key_from_received_outs, wallet, std::placeholders::_1);
}

  //-----------------------------------------------------------------
} //namespace

namespace tools
{
constexpr const std::chrono::seconds wallet2::rpc_timeout;
const char* wallet2::tr(const char* str) { return i18n_translate(str, "tools::wallet2"); }

gamma_picker::gamma_picker(const std::vector<uint64_t> &rct_offsets, double shape, double scale):
    rct_offsets(rct_offsets)
{
  gamma = std::gamma_distribution<double>(shape, scale);
  THROW_WALLET_EXCEPTION_IF(rct_offsets.size() <= CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, error::wallet_internal_error, "Bad offset calculation");
  const size_t blocks_in_a_year = 86400 * 365 / DIFFICULTY_TARGET_V2;
  const size_t blocks_to_consider = std::min<size_t>(rct_offsets.size(), blocks_in_a_year);
  const size_t outputs_to_consider = rct_offsets.back() - (blocks_to_consider < rct_offsets.size() ? rct_offsets[rct_offsets.size() - blocks_to_consider - 1] : 0);
  begin = rct_offsets.data();
  end = rct_offsets.data() + rct_offsets.size() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
  num_rct_outputs = *(end - 1);
  THROW_WALLET_EXCEPTION_IF(num_rct_outputs == 0, error::wallet_internal_error, "No rct outputs");
  average_output_time = DIFFICULTY_TARGET_V2 * blocks_to_consider / outputs_to_consider; // this assumes constant target over the whole rct range
};

gamma_picker::gamma_picker(const std::vector<uint64_t> &rct_offsets): gamma_picker(rct_offsets, GAMMA_SHAPE, GAMMA_SCALE) {}

uint64_t gamma_picker::pick()
{
  double x = gamma(engine);
  x = exp(x);
  uint64_t output_index = x / average_output_time;
  if (output_index >= num_rct_outputs)
    return std::numeric_limits<uint64_t>::max(); // bad pick
  output_index = num_rct_outputs - 1 - output_index;

  const uint64_t *it = std::lower_bound(begin, end, output_index);
  THROW_WALLET_EXCEPTION_IF(it == end, error::wallet_internal_error, "output_index not found");
  uint64_t index = std::distance(begin, it);

  const uint64_t first_rct = index == 0 ? 0 : rct_offsets[index - 1];
  const uint64_t n_rct = rct_offsets[index] - first_rct;
  if (n_rct == 0)
    return std::numeric_limits<uint64_t>::max(); // bad pick
  MTRACE("Picking 1/" << n_rct << " in block " << index);
  return first_rct + crypto::rand_idx(n_rct);
};

boost::mutex wallet_keys_unlocker::lockers_lock;
unsigned int wallet_keys_unlocker::lockers = 0;
wallet_keys_unlocker::wallet_keys_unlocker(wallet2 &w, const boost::optional<tools::password_container> &password):
  w(w),
  locked(password != boost::none)
{
  boost::lock_guard<boost::mutex> lock(lockers_lock);
  if (lockers++ > 0)
    locked = false;
  if (!locked || w.is_unattended() || w.ask_password() != tools::wallet2::AskPasswordToDecrypt || w.watch_only())
  {
    locked = false;
    return;
  }
  const epee::wipeable_string pass = password->password();
  w.generate_chacha_key_from_password(pass, key);
  w.decrypt_keys(key);
}

wallet_keys_unlocker::wallet_keys_unlocker(wallet2 &w, bool locked, const epee::wipeable_string &password):
  w(w),
  locked(locked)
{
  boost::lock_guard<boost::mutex> lock(lockers_lock);
  if (lockers++ > 0)
    locked = false;
  if (!locked)
    return;
  w.generate_chacha_key_from_password(password, key);
  w.decrypt_keys(key);
}

wallet_keys_unlocker::~wallet_keys_unlocker()
{
  try
  {
    boost::lock_guard<boost::mutex> lock(lockers_lock);
    if (lockers == 0)
    {
      MERROR("There are no lockers in wallet_keys_unlocker dtor");
      return;
    }
    --lockers;
    if (!locked)
      return;
    w.encrypt_keys(key);
  }
  catch (...)
  {
    MERROR("Failed to re-encrypt wallet keys");
    // do not propagate through dtor, we'd crash
  }
}

void wallet_device_callback::on_button_request(uint64_t code)
{
  if (wallet)
    wallet->on_device_button_request(code);
}

void wallet_device_callback::on_button_pressed()
{
  if (wallet)
    wallet->on_device_button_pressed();
}

boost::optional<epee::wipeable_string> wallet_device_callback::on_pin_request()
{
  if (wallet)
    return wallet->on_device_pin_request();
  return boost::none;
}

boost::optional<epee::wipeable_string> wallet_device_callback::on_passphrase_request(bool & on_device)
{
  if (wallet)
    return wallet->on_device_passphrase_request(on_device);
  else
    on_device = true;
  return boost::none;
}

void wallet_device_callback::on_progress(const hw::device_progress& event)
{
  if (wallet)
    wallet->on_device_progress(event);
}

wallet2::wallet2(network_type nettype, uint64_t kdf_rounds, bool unattended, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory):
  m_http_client(http_client_factory->create()),
  m_upper_transaction_weight_limit(0),
  m_run(true),
  m_callback(0),
  m_trusted_daemon(false),
  m_nettype(nettype),
  m_always_confirm_transfers(true),
  m_print_ring_members(false),
  m_store_tx_info(true),
  m_default_mixin(0),
  m_default_priority(0),
  m_refresh_type(RefreshOptimizeCoinbase),
  m_auto_refresh(true),
  m_first_refresh_done(false),
  m_refresh_from_block_height(0),
  m_explicit_refresh_from_block_height(true),
  m_confirm_non_default_ring_size(true),
  m_ask_password(AskPasswordToDecrypt),
  m_max_reorg_depth(ORPHANED_BLOCKS_MAX_COUNT),
  m_min_output_count(0),
  m_min_output_value(0),
  m_merge_destinations(false),
  m_confirm_backlog(true),
  m_confirm_backlog_threshold(0),
  m_confirm_export_overwrite(true),
  m_auto_low_priority(true),
  m_segregate_pre_fork_outputs(true),
  m_key_reuse_mitigation2(true),
  m_segregation_height(0),
  m_ignore_fractional_outputs(true),
  m_ignore_outputs_above(MONEY_SUPPLY),
  m_ignore_outputs_below(0),
  m_track_uses(false),
  m_inactivity_lock_timeout(DEFAULT_INACTIVITY_LOCK_TIMEOUT),
  m_setup_background_mining(BackgroundMiningMaybe),
  m_persistent_rpc_client_id(false),
  m_auto_mine_for_rpc_payment_threshold(-1.0f),
  m_is_initialized(false),
  m_kdf_rounds(kdf_rounds),
  is_old_file_format(false),
  m_watch_only(false),
  m_node_rpc_proxy(*m_http_client, m_rpc_payment_state, m_daemon_rpc_mutex),
  m_account_public_address{crypto::null_pkey, crypto::null_pkey},
  m_subaddress_lookahead_major(SUBADDRESS_LOOKAHEAD_MAJOR),
  m_subaddress_lookahead_minor(SUBADDRESS_LOOKAHEAD_MINOR),
  m_light_wallet(false),
  m_light_wallet_scanned_block_height(0),
  m_light_wallet_blockchain_height(0),
  m_light_wallet_connected(false),
  m_light_wallet_balance(0),
  m_light_wallet_unlocked_balance(0),
  m_original_keys_available(false),
  m_message_store(http_client_factory->create()),
  m_key_device_type(hw::device::device_type::SOFTWARE),
  m_ring_history_saved(false),
  m_ringdb(),
  m_last_block_reward(0),
  m_encrypt_keys_after_refresh(boost::none),
  m_decrypt_keys_lockers(0),
  m_unattended(unattended),
  m_devices_registered(false),
  m_device_last_key_image_sync(0),
  m_use_dns(true),
  m_offline(false),
  m_rpc_version(0),
  m_export_format(ExportFormat::Binary),
  m_load_deprecated_formats(false),
  m_credits_target(0)
{
  set_rpc_client_secret_key(rct::rct2sk(rct::skGen()));
}

wallet2::~wallet2()
{
}

bool wallet2::has_testnet_option(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().testnet);
}

bool wallet2::has_stagenet_option(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().stagenet);
}

std::string wallet2::device_name_option(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().hw_device);
}

std::string wallet2::device_derivation_path_option(const boost::program_options::variables_map &vm)
{
  return command_line::get_arg(vm, options().hw_device_derivation_path);
}

void wallet2::init_options(boost::program_options::options_description& desc_params)
{
  const options opts{};
  command_line::add_arg(desc_params, opts.daemon_address);
  command_line::add_arg(desc_params, opts.daemon_host);
  command_line::add_arg(desc_params, opts.proxy);
  command_line::add_arg(desc_params, opts.trusted_daemon);
  command_line::add_arg(desc_params, opts.untrusted_daemon);
  command_line::add_arg(desc_params, opts.password);
  command_line::add_arg(desc_params, opts.password_file);
  command_line::add_arg(desc_params, opts.daemon_port);
  command_line::add_arg(desc_params, opts.daemon_login);
  command_line::add_arg(desc_params, opts.daemon_ssl);
  command_line::add_arg(desc_params, opts.daemon_ssl_private_key);
  command_line::add_arg(desc_params, opts.daemon_ssl_certificate);
  command_line::add_arg(desc_params, opts.daemon_ssl_ca_certificates);
  command_line::add_arg(desc_params, opts.daemon_ssl_allowed_fingerprints);
  command_line::add_arg(desc_params, opts.daemon_ssl_allow_any_cert);
  command_line::add_arg(desc_params, opts.daemon_ssl_allow_chained);
  command_line::add_arg(desc_params, opts.testnet);
  command_line::add_arg(desc_params, opts.stagenet);
  command_line::add_arg(desc_params, opts.shared_ringdb_dir);
  command_line::add_arg(desc_params, opts.kdf_rounds);
  mms::message_store::init_options(desc_params);
  command_line::add_arg(desc_params, opts.hw_device);
  command_line::add_arg(desc_params, opts.hw_device_derivation_path);
  command_line::add_arg(desc_params, opts.tx_notify);
  command_line::add_arg(desc_params, opts.no_dns);
  command_line::add_arg(desc_params, opts.offline);
  command_line::add_arg(desc_params, opts.extra_entropy);
}

std::pair<std::unique_ptr<wallet2>, tools::password_container> wallet2::make_from_json(const boost::program_options::variables_map& vm, bool unattended, const std::string& json_file, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  return generate_from_json(json_file, vm, unattended, opts, password_prompter);
}

std::pair<std::unique_ptr<wallet2>, password_container> wallet2::make_from_file(
  const boost::program_options::variables_map& vm, bool unattended, const std::string& wallet_file, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  std::cout<<"print vm"<<std::endl;
  for(auto e : vm){
    auto &k = e.first;
    auto &value = e.second.value();
    std::cout<<k<<",";

     if (auto v = boost::any_cast<uint32_t>(&value))
    std::cout << *v;
   else if (auto v = boost::any_cast<int32_t>(&value))
    std::cout << *v;
  else if (auto v = boost::any_cast<std::string>(&value))
    std::cout << *v;
  else
    std::cout << "unknown";
  std::cout<<std::endl;
  }
  std::cout<<"end print vm"<<std::endl;
  std::cout<<"make_from_file"<< wallet_file<<std::endl;
  const options opts{};
  auto pwd = get_password(vm, opts, password_prompter, false);
  if (!pwd)
  {
    return {nullptr, password_container{}};
  }
  std::cout<<"pass "<<pwd->password().data()<<std::endl;
  auto wallet = make_basic(vm, unattended, opts, password_prompter);
  if (wallet && !wallet_file.empty())
  {
    wallet->load(wallet_file, pwd->password());
  }
  return {std::move(wallet), std::move(*pwd)};
}

std::pair<std::unique_ptr<wallet2>, password_container> wallet2::make_new(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  auto pwd = get_password(vm, opts, password_prompter, true);
  if (!pwd)
  {
    return {nullptr, password_container{}};
  }
  return {make_basic(vm, unattended, opts, password_prompter), std::move(*pwd)};
}

std::unique_ptr<wallet2> wallet2::make_dummy(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  return make_basic(vm, unattended, opts, password_prompter);
}

//----------------------------------------------------------------------------------------------------
bool wallet2::set_daemon(std::string daemon_address, boost::optional<epee::net_utils::http::login> daemon_login, bool trusted_daemon, epee::net_utils::ssl_options_t ssl_options)
{
  boost::lock_guard<boost::recursive_mutex> lock(m_daemon_rpc_mutex);

  if(m_http_client->is_connected())
    m_http_client->disconnect();
  const bool changed = m_daemon_address != daemon_address;
  m_daemon_address = std::move(daemon_address);
  m_daemon_login = std::move(daemon_login);
  m_trusted_daemon = trusted_daemon;
  if (changed)
  {
    m_rpc_payment_state.expected_spent = 0;
    m_rpc_payment_state.discrepancy = 0;
    m_node_rpc_proxy.invalidate();
  }

  const std::string address = get_daemon_address();
  MINFO("setting daemon to " << address);
  bool ret =  m_http_client->set_server(address, get_daemon_login(), std::move(ssl_options));
  if (ret)
  {
    CRITICAL_REGION_LOCAL(default_daemon_address_lock);
    default_daemon_address = address;
  }
  return ret;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::set_proxy(const std::string &address)
{
  return m_http_client->set_proxy(address);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::init(std::string daemon_address, boost::optional<epee::net_utils::http::login> daemon_login, const std::string &proxy_address, uint64_t upper_transaction_weight_limit, bool trusted_daemon, epee::net_utils::ssl_options_t ssl_options)
{
  std::cout<<"wallet init "<<daemon_address<<std::endl;
  CHECK_AND_ASSERT_MES(set_proxy(proxy_address), false, "failed to set proxy address");
  m_checkpoints.init_default_checkpoints(m_nettype);
  m_is_initialized = true;
  m_upper_transaction_weight_limit = upper_transaction_weight_limit;
  return set_daemon(daemon_address, daemon_login, trusted_daemon, std::move(ssl_options));
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_deterministic() const
{
  crypto::secret_key second;
  keccak((uint8_t *)&get_account().get_keys().m_spend_secret_key, sizeof(crypto::secret_key), (uint8_t *)&second, sizeof(crypto::secret_key));
  sc_reduce32((uint8_t *)&second);
  return memcmp(second.data,get_account().get_keys().m_view_secret_key.data, sizeof(crypto::secret_key)) == 0;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::get_seed(epee::wipeable_string& electrum_words, const epee::wipeable_string &passphrase) const
{
  bool keys_deterministic = is_deterministic();
  if (!keys_deterministic)
  {
    std::cout << "This is not a deterministic wallet" << std::endl;
    return false;
  }
  if (seed_language.empty())
  {
    std::cout << "seed_language not set" << std::endl;
    return false;
  }

  crypto::secret_key key = get_account().get_keys().m_spend_secret_key;
  if (!passphrase.empty())
    key = cryptonote::encrypt_key(key, passphrase);
  if (!crypto::ElectrumWords::bytes_to_words(key, electrum_words, seed_language))
  {
    std::cout << "Failed to create seed from key for language: " << seed_language << std::endl;
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::reconnect_device()
{
  bool r = true;
  hw::device &hwdev = lookup_device(m_device_name);
  hwdev.set_name(m_device_name);
  hwdev.set_network_type(m_nettype);
  hwdev.set_derivation_path(m_device_derivation_path);
  hwdev.set_callback(get_device_callback());
  r = hwdev.init();
  if (!r){
    MERROR("Could not init device");
    return false;
  }

  r = hwdev.connect();
  if (!r){
    MERROR("Could not connect to the device");
    return false;
  }

  m_account.set_device(hwdev);
  return true;
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Gets the seed language
 */
const std::string &wallet2::get_seed_language() const
{
  return seed_language;
}
/*!
 * \brief Sets the seed language
 * \param language  Seed language to set to
 */
void wallet2::set_seed_language(const std::string &language)
{
  seed_language = language;
}
//----------------------------------------------------------------------------------------------------
cryptonote::account_public_address wallet2::get_subaddress(const cryptonote::subaddress_index& index) const
{
  hw::device &hwdev = m_account.get_device();
  return hwdev.get_subaddress(m_account.get_keys(), index);
}
//----------------------------------------------------------------------------------------------------
boost::optional<cryptonote::subaddress_index> wallet2::get_subaddress_index(const cryptonote::account_public_address& address) const
{
  auto index = m_subaddresses.find(address.m_spend_public_key);
  if (index == m_subaddresses.end())
    return boost::none;
  return index->second;
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_subaddress_spend_public_key(const cryptonote::subaddress_index& index) const
{
  hw::device &hwdev = m_account.get_device();
  return hwdev.get_subaddress_spend_public_key(m_account.get_keys(), index);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_subaddress_as_str(const cryptonote::subaddress_index& index) const
{
  cryptonote::account_public_address address = get_subaddress(index);
  return cryptonote::get_account_address_as_str(m_nettype, !index.is_zero(), address);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_integrated_address_as_str(const crypto::hash8& payment_id) const
{
  return cryptonote::get_account_integrated_address_as_str(m_nettype, get_address(), payment_id);
}
//----------------------------------------------------------------------------------------------------
void wallet2::add_subaddress_account(const std::string& label)
{
  uint32_t index_major = (uint32_t)get_num_subaddress_accounts();
  expand_subaddresses({index_major, 0});
  m_subaddress_labels[index_major][0] = label;
}
//----------------------------------------------------------------------------------------------------
void wallet2::add_subaddress(uint32_t index_major, const std::string& label)
{
  THROW_WALLET_EXCEPTION_IF(index_major >= m_subaddress_labels.size(), error::account_index_outofbound);
  uint32_t index_minor = (uint32_t)get_num_subaddresses(index_major);
  expand_subaddresses({index_major, index_minor});
  m_subaddress_labels[index_major][index_minor] = label;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::should_expand(const cryptonote::subaddress_index &index) const
{
  const uint32_t last_major = m_subaddress_labels.size() - 1 > (std::numeric_limits<uint32_t>::max() - m_subaddress_lookahead_major) ? std::numeric_limits<uint32_t>::max()  : (m_subaddress_labels.size() + m_subaddress_lookahead_major - 1);
  if (index.major > last_major)
    return false;
  const size_t nsub = index.major < m_subaddress_labels.size() ? m_subaddress_labels[index.major].size() : 0;
  const uint32_t last_minor = nsub - 1 > (std::numeric_limits<uint32_t>::max() - m_subaddress_lookahead_minor) ? std::numeric_limits<uint32_t>::max()  : (nsub + m_subaddress_lookahead_minor - 1);
  if (index.minor > last_minor)
    return false;
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::expand_subaddresses(const cryptonote::subaddress_index& index)
{
  hw::device &hwdev = m_account.get_device();
  if (m_subaddress_labels.size() <= index.major)
  {
    // add new accounts
    cryptonote::subaddress_index index2;
    const uint32_t major_end = get_subaddress_clamped_sum(index.major, m_subaddress_lookahead_major);
    for (index2.major = m_subaddress_labels.size(); index2.major < major_end; ++index2.major)
    {
      const uint32_t end = get_subaddress_clamped_sum((index2.major == index.major ? index.minor : 0), m_subaddress_lookahead_minor);
      const std::vector<crypto::public_key> pkeys = hwdev.get_subaddress_spend_public_keys(m_account.get_keys(), index2.major, 0, end);
      for (index2.minor = 0; index2.minor < end; ++index2.minor)
      {
         const crypto::public_key &D = pkeys[index2.minor];
         m_subaddresses[D] = index2;
      }
    }
    m_subaddress_labels.resize(index.major + 1, {"Untitled account"});
    m_subaddress_labels[index.major].resize(index.minor + 1);
    get_account_tags();
  }
  else if (m_subaddress_labels[index.major].size() <= index.minor)
  {
    // add new subaddresses
    const uint32_t end = get_subaddress_clamped_sum(index.minor, m_subaddress_lookahead_minor);
    const uint32_t begin = m_subaddress_labels[index.major].size();
    cryptonote::subaddress_index index2 = {index.major, begin};
    const std::vector<crypto::public_key> pkeys = hwdev.get_subaddress_spend_public_keys(m_account.get_keys(), index2.major, index2.minor, end);
    for (; index2.minor < end; ++index2.minor)
    {
       const crypto::public_key &D = pkeys[index2.minor - begin];
       m_subaddresses[D] = index2;
    }
    m_subaddress_labels[index.major].resize(index.minor + 1);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::create_one_off_subaddress(const cryptonote::subaddress_index& index)
{
  const crypto::public_key pkey = get_subaddress_spend_public_key(index);
  m_subaddresses[pkey] = index;
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_subaddress_label(const cryptonote::subaddress_index& index) const
{
  if (index.major >= m_subaddress_labels.size() || index.minor >= m_subaddress_labels[index.major].size())
  {
    MERROR("Subaddress label doesn't exist");
    return "";
  }
  return m_subaddress_labels[index.major][index.minor];
}
//----------------------------------------------------------------------------------------------------
void wallet2::scan_tx(const std::vector<crypto::hash> &txids)
{
    typedef cryptonote::COMMAND_RPC_GET_TRANSACTIONS::entry E;
  // Get the transactions from daemon in batches and add them to a priority queue ordered in chronological order
  auto cmp_tx_entry = [](const E& l, const E& r)
  { return l.block_height > r.block_height; };


  std::priority_queue<E, std::vector<E>, decltype(cmp_tx_entry)> txq(cmp_tx_entry);
  const size_t SLICE_SIZE =  100; // RESTRICTED_TRANSACTIONS_COUNT as defined in rpc/core_rpc_server.cpp, hardcoded in daemon code
  for(size_t slice = 0; slice < txids.size(); slice += SLICE_SIZE) {
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req{};
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res{};
    req.decode_as_json = false;
    req.prune = true;

    size_t ntxes = slice + SLICE_SIZE > txids.size() ? txids.size() - slice : SLICE_SIZE;
    for (size_t i = slice; i < slice + ntxes; ++i)
     req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txids[i]));

    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      req.client = get_client_signature();
      bool r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client, rpc_timeout);
      THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to get transaction from daemon");
      THROW_WALLET_EXCEPTION_IF(res.txs.size() != req.txs_hashes.size(), error::wallet_internal_error, "Failed to get transaction from daemon");
    }

    for (auto& tx_info : res.txs)
    {
      LOG_PRINT_L2("new trans"<<tx_info.tx_hash<<","<<tx_info.as_json);
       txq.push(tx_info);
    } 
  }

  // Process the transactions in chronologically ascending order
  while(!txq.empty()) {
    auto& tx_info = txq.top();
    cryptonote::transaction tx;
    crypto::hash tx_hash;
    THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(tx_info, tx, tx_hash), error::wallet_internal_error, "Failed to get transaction from daemon (2)");
    process_new_transaction(tx_hash, tx, tx_info.output_indices, tx_info.block_height, 0, tx_info.block_timestamp, false, tx_info.in_pool, tx_info.double_spend_seen, {}, {});
    txq.pop();
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_subaddress_label(const cryptonote::subaddress_index& index, const std::string &label)
{
  THROW_WALLET_EXCEPTION_IF(index.major >= m_subaddress_labels.size(), error::account_index_outofbound);
  THROW_WALLET_EXCEPTION_IF(index.minor >= m_subaddress_labels[index.major].size(), error::address_index_outofbound);
  m_subaddress_labels[index.major][index.minor] = label;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_subaddress_lookahead(size_t major, size_t minor)
{
  THROW_WALLET_EXCEPTION_IF(major == 0, error::wallet_internal_error, "Subaddress major lookahead may not be zero");
  THROW_WALLET_EXCEPTION_IF(major > 0xffffffff, error::wallet_internal_error, "Subaddress major lookahead is too large");
  THROW_WALLET_EXCEPTION_IF(minor == 0, error::wallet_internal_error, "Subaddress minor lookahead may not be zero");
  THROW_WALLET_EXCEPTION_IF(minor > 0xffffffff, error::wallet_internal_error, "Subaddress minor lookahead is too large");
  m_subaddress_lookahead_major = major;
  m_subaddress_lookahead_minor = minor;
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Tells if the wallet file is deprecated.
 */
bool wallet2::is_deprecated() const
{
  return is_old_file_format;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_spent(size_t idx, uint64_t height)
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid index");
  transfer_details &td = m_transfers[idx];
  LOG_PRINT_L2("Setting SPENT at " << height << ": ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
  td.m_spent = true;
  td.m_spent_height = height;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_unspent(size_t idx)
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid index");
  transfer_details &td = m_transfers[idx];
  LOG_PRINT_L2("Setting UNSPENT: ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
  td.m_spent = false;
  td.m_spent_height = 0;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_spent(const transfer_details &td, bool strict) const
{
  if (strict)
  {
    return td.m_spent && td.m_spent_height > 0;
  }
  else
  {
    return td.m_spent;
  }
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_spent(size_t idx, bool strict) const
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid index");
  const transfer_details &td = m_transfers[idx];
  return is_spent(td, strict);
}
//----------------------------------------------------------------------------------------------------
void wallet2::freeze(size_t idx)
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid transfer_details index");
  transfer_details &td = m_transfers[idx];
  td.m_frozen = true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::thaw(size_t idx)
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid transfer_details index");
  transfer_details &td = m_transfers[idx];
  td.m_frozen = false;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::frozen(size_t idx) const
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid transfer_details index");
  const transfer_details &td = m_transfers[idx];
  return td.m_frozen;
}
//----------------------------------------------------------------------------------------------------
void wallet2::freeze(const crypto::key_image &ki)
{
  freeze(get_transfer_details(ki));
}
//----------------------------------------------------------------------------------------------------
void wallet2::thaw(const crypto::key_image &ki)
{
  thaw(get_transfer_details(ki));
}
//----------------------------------------------------------------------------------------------------
bool wallet2::frozen(const crypto::key_image &ki) const
{
  return frozen(get_transfer_details(ki));
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::get_transfer_details(const crypto::key_image &ki) const
{
  for (size_t idx = 0; idx < m_transfers.size(); ++idx)
  {
    const transfer_details &td = m_transfers[idx];
    if (td.m_key_image_known && td.m_key_image == ki)
      return idx;
  }
  CHECK_AND_ASSERT_THROW_MES(false, "Key image not found");
}
//----------------------------------------------------------------------------------------------------
bool wallet2::frozen(const transfer_details &td) const
{
  return td.m_frozen;
}

//----------------------------------------------------------------------------------------------------
void wallet2::cache_tx_data(const cryptonote::transaction& tx, const crypto::hash &txid, tx_cache_data &tx_cache_data) const
{
  if(!parse_tx_extra(tx.extra, tx_cache_data.tx_extra_fields))
  {
    // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
    LOG_PRINT_L0("Transaction extra has unsupported format: " << txid);
    if (tx_cache_data.tx_extra_fields.empty())
      return;
  }

  // Don't try to extract tx public key if tx has no ouputs
  const bool is_miner = tx.vin.size() == 1 && tx.vin[0].type() == typeid(cryptonote::txin_gen);
  if (!is_miner || m_refresh_type != RefreshType::RefreshNoCoinbase)
  {
    const size_t rec_size = is_miner && m_refresh_type == RefreshType::RefreshOptimizeCoinbase ? 1 : tx.vout.size();
    if (!tx.vout.empty())
    {
      // if tx.vout is not empty, we loop through all tx pubkeys
      const std::vector<boost::optional<cryptonote::subaddress_receive_info>> rec(rec_size, boost::none);

      tx_extra_pub_key pub_key_field;
      size_t pk_index = 0;
      while (find_tx_extra_field_by_type(tx_cache_data.tx_extra_fields, pub_key_field, pk_index++))
        tx_cache_data.primary.push_back({pub_key_field.pub_key, {}, rec});

      // additional tx pubkeys and derivations for multi-destination transfers involving one or more subaddresses
      tx_extra_additional_pub_keys additional_tx_pub_keys;
      if (find_tx_extra_field_by_type(tx_cache_data.tx_extra_fields, additional_tx_pub_keys))
      {
        for (size_t i = 0; i < additional_tx_pub_keys.data.size(); ++i)
          tx_cache_data.additional.push_back({additional_tx_pub_keys.data[i], {}, {}});
      }
    }
  }
}
//----------------------------------------------------------------------------------------------------
bool wallet2::spends_one_of_ours(const cryptonote::transaction &tx) const
{
  for (const auto &in: tx.vin)
  {
    if (in.type() != typeid(cryptonote::txin_to_key))
      continue;
    const cryptonote::txin_to_key &in_to_key = boost::get<cryptonote::txin_to_key>(in);
    auto it = m_key_images.find(in_to_key.k_image);
    if (it != m_key_images.end())
      return true;
  }
  return false;
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_unconfirmed(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height)
{
  if (m_unconfirmed_txs.empty())
    return;

  auto unconf_it = m_unconfirmed_txs.find(txid);
  if(unconf_it != m_unconfirmed_txs.end()) {
    if (store_tx_info()) {
      try {
        m_confirmed_txs.insert(std::make_pair(txid, confirmed_transfer_details(unconf_it->second, height)));
      }
      catch (...) {
        // can fail if the tx has unexpected input types
        LOG_PRINT_L0("Failed to add outgoing transaction to confirmed transaction map");
      }
    }
    m_unconfirmed_txs.erase(unconf_it);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_outgoing(const crypto::hash &txid, const cryptonote::transaction &tx, uint64_t height, uint64_t ts, uint64_t spent, uint64_t received, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices)
{
  std::pair<std::unordered_map<crypto::hash, confirmed_transfer_details>::iterator, bool> entry = m_confirmed_txs.insert(std::make_pair(txid, confirmed_transfer_details()));
  // fill with the info we know, some info might already be there
  if (entry.second)
  {
    // this case will happen if the tx is from our outputs, but was sent by another
    // wallet (eg, we're a cold wallet and the hot wallet sent it). For RCT transactions,
    // we only see 0 input amounts, so have to deduce amount out from other parameters.
    entry.first->second.m_amount_in = spent;
    if (tx.version == 1)
      entry.first->second.m_amount_out = get_outs_money_amount(tx);
    else
      entry.first->second.m_amount_out = spent - tx.rct_signatures.txnFee;
    entry.first->second.m_change = received;

    std::vector<tx_extra_field> tx_extra_fields;
    parse_tx_extra(tx.extra, tx_extra_fields); // ok if partially parsed
    tx_extra_nonce extra_nonce;
    if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
    {
      // we do not care about failure here
      get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, entry.first->second.m_payment_id);
    }
    entry.first->second.m_subaddr_account = subaddr_account;
    entry.first->second.m_subaddr_indices = subaddr_indices;
  }

  entry.first->second.m_rings.clear();
  for (const auto &in: tx.vin)
  {
    if (in.type() != typeid(cryptonote::txin_to_key))
      continue;
    const auto &txin = boost::get<cryptonote::txin_to_key>(in);
    entry.first->second.m_rings.push_back(std::make_pair(txin.k_image, txin.key_offsets));
  }
  entry.first->second.m_block_height = height;
  entry.first->second.m_timestamp = ts;
  entry.first->second.m_unlock_time = tx.unlock_time;

  add_rings(tx);
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_short_chain_history(std::list<crypto::hash>& ids, uint64_t granularity) const
{
  size_t i = 0;
  size_t current_multiplier = 1;
  size_t blockchain_size = std::max((size_t)(m_blockchain.size() / granularity * granularity), m_blockchain.offset());
  size_t sz = blockchain_size - m_blockchain.offset();
  if(!sz)
  {
    ids.push_back(m_blockchain.genesis());
    return;
  }
  size_t current_back_offset = 1;
  bool base_included = false;
  while(current_back_offset < sz)
  {
    ids.push_back(m_blockchain[m_blockchain.offset() + sz-current_back_offset]);
    if(sz-current_back_offset == 0)
      base_included = true;
    if(i < 10)
    {
      ++current_back_offset;
    }else
    {
      current_back_offset += current_multiplier *= 2;
    }
    ++i;
  }
  if(!base_included)
    ids.push_back(m_blockchain[m_blockchain.offset()]);
  if(m_blockchain.offset())
    ids.push_back(m_blockchain.genesis());
}
//----------------------------------------------------------------------------------------------------
void wallet2::parse_block_round(const cryptonote::blobdata &blob, cryptonote::block &bl, crypto::hash &bl_id, bool &error) const
{
  error = !cryptonote::parse_and_validate_block_from_blob(blob, bl, bl_id);
}
void wallet2::remove_obsolete_pool_txs(const std::vector<crypto::hash> &tx_hashes)
{
  // remove pool txes to us that aren't in the pool anymore
  std::unordered_multimap<crypto::hash, wallet2::pool_payment_details>::iterator uit = m_unconfirmed_payments.begin();
  while (uit != m_unconfirmed_payments.end())
  {
    const crypto::hash &txid = uit->second.m_pd.m_tx_hash;
    bool found = false;
    for (const auto &it2: tx_hashes)
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
      MDEBUG("Removing " << txid << " from unconfirmed payments, not found in pool");
      m_unconfirmed_payments.erase(pit);
      if (0 != m_callback)
        m_callback->on_pool_tx_removed(txid);
    }
  }
}

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
    uint64_t pre_call_credits = m_rpc_payment_state.credits;
    req.client = get_client_signature();
    bool r = epee::net_utils::invoke_http_json("/get_transaction_pool_hashes.bin", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_transaction_pool_hashes.bin", error::get_tx_pool_error);
    check_rpc_cost("/get_transaction_pool_hashes.bin", res.credits, pre_call_credits, 1 + res.tx_hashes.size() * COST_PER_POOL_HASH);
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
        LOG_PRINT_L1("Pending txid " << txid << " not in pool, marking as not in pool");
        pit->second.m_state = wallet2::unconfirmed_transfer_details::pending_not_in_pool;
      }
      else if (pit->second.m_state == wallet2::unconfirmed_transfer_details::pending_not_in_pool && refreshed &&
        now > std::chrono::system_clock::from_time_t(pit->second.m_sent_time) + tx_propagation_timeout)
      {
        LOG_PRINT_L1("Pending txid " << txid << " not in pool after " << tx_propagation_timeout.count() <<
          " seconds, marking as failed");
        pit->second.m_state = wallet2::unconfirmed_transfer_details::failed;

        // the inputs aren't spent anymore, since the tx failed
        for (size_t vini = 0; vini < pit->second.m_tx.vin.size(); ++vini)
        {
          if (pit->second.m_tx.vin[vini].type() == typeid(txin_to_key))
          {
            txin_to_key &tx_in_to_key = boost::get<txin_to_key>(pit->second.m_tx.vin[vini]);
            for (size_t i = 0; i < m_transfers.size(); ++i)
            {
              const transfer_details &td = m_transfers[i];
              if (td.m_key_image == tx_in_to_key.k_image)
              {
                 LOG_PRINT_L1("Resetting spent status for output " << vini << ": " << td.m_key_image);
                 set_unspent(i);
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
    for (const auto &up: m_unconfirmed_payments)
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
      LOG_PRINT_L1("Found new pool tx: " << txid);
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
        LOG_PRINT_L1("We sent that one");
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
      uint64_t pre_call_credits = m_rpc_payment_state.credits;
      req.client = get_client_signature();
      r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client, rpc_timeout);
      if (r && res.status == CORE_RPC_STATUS_OK)
        check_rpc_cost("/gettransactions", res.credits, pre_call_credits, res.txs.size() * COST_PER_TX);
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
            LOG_PRINT_L1("Transaction from daemon was in pool, but is no more");
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


bool wallet2::add_address_book_row(const cryptonote::account_public_address &address, const crypto::hash8 *payment_id, const std::string &description, bool is_subaddress)
{
  wallet2::address_book_row a;
  a.m_address = address;
  a.m_has_payment_id = !!payment_id;
  a.m_payment_id = payment_id ? *payment_id : crypto::null_hash8;
  a.m_description = description;
  a.m_is_subaddress = is_subaddress;
  
  auto old_size = m_address_book.size();
  m_address_book.push_back(a);
  if(m_address_book.size() == old_size+1)
    return true;
  return false;
}

bool wallet2::set_address_book_row(size_t row_id, const cryptonote::account_public_address &address, const crypto::hash8 *payment_id, const std::string &description, bool is_subaddress)
{
  wallet2::address_book_row a;
  a.m_address = address;
  a.m_has_payment_id = !!payment_id;
  a.m_payment_id = payment_id ? *payment_id : crypto::null_hash8;
  a.m_description = description;
  a.m_is_subaddress = is_subaddress;

  const auto size = m_address_book.size();
  if (row_id >= size)
    return false;
  m_address_book[row_id] = a;
  return true;
}

bool wallet2::delete_address_book_row(std::size_t row_id) {
  if(m_address_book.size() <= row_id)
    return false;
  
  m_address_book.erase(m_address_book.begin()+row_id);

  return true;
}

//----------------------------------------------------------------------------------------------------
std::shared_ptr<std::map<std::pair<uint64_t, uint64_t>, size_t>> wallet2::create_output_tracker_cache() const
{
  std::shared_ptr<std::map<std::pair<uint64_t, uint64_t>, size_t>> cache{new std::map<std::pair<uint64_t, uint64_t>, size_t>()};
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details &td = m_transfers[i];
    (*cache)[std::make_pair(td.is_rct() ? 0 : td.amount(), td.m_global_output_index)] = i;
  }
  return cache;
}

//----------------------------------------------------------------------------------------------------
bool wallet2::refresh(bool trusted_daemon, uint64_t & blocks_fetched, bool& received_money, bool& ok)
{
  try
  {
    refresh(trusted_daemon, 0, blocks_fetched, received_money);
    ok = true;
  }
  catch (...)
  {
    ok = false;
  }
  return ok;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::get_rct_distribution(uint64_t &start_height, std::vector<uint64_t> &distribution)
{
  uint32_t rpc_version;
  boost::optional<std::string> result = m_node_rpc_proxy.get_rpc_version(rpc_version);
  // no error
  if (!!result)
  {
    // empty string -> not connection
    THROW_WALLET_EXCEPTION_IF(result->empty(), tools::error::no_connection_to_daemon, "getversion");
    THROW_WALLET_EXCEPTION_IF(*result == CORE_RPC_STATUS_BUSY, tools::error::daemon_busy, "getversion");
    if (*result != CORE_RPC_STATUS_OK)
    {
      MDEBUG("Cannot determine daemon RPC version, not requesting rct distribution");
      return false;
    }
  }
  else
  {
    if (rpc_version >= MAKE_CORE_RPC_VERSION(1, 19))
    {
      MDEBUG("Daemon is recent enough, requesting rct distribution");
    }
    else
    {
      MDEBUG("Daemon is too old, not requesting rct distribution");
      return false;
    }
  }

  cryptonote::COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request req = AUTO_VAL_INIT(req);
  cryptonote::COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response res = AUTO_VAL_INIT(res);
  req.amounts.push_back(0);
  req.from_height = 0;
  req.cumulative = false;
  req.binary = true;
  req.compress = true;

  bool r;
  try
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    uint64_t pre_call_credits = m_rpc_payment_state.credits;
    req.client = get_client_signature();
    r = net_utils::invoke_http_bin("/get_output_distribution.bin", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "/get_output_distribution.bin");
    check_rpc_cost("/get_output_distribution.bin", res.credits, pre_call_credits, COST_PER_OUTPUT_DISTRIBUTION_0);
  }
  catch(...)
  {
    return false;
  }
  if (res.distributions.size() != 1)
  {
    MWARNING("Failed to request output distribution: not the expected single result");
    return false;
  }
  if (res.distributions[0].amount != 0)
  {
    MWARNING("Failed to request output distribution: results are not for amount 0");
    return false;
  }
  for (size_t i = 1; i < res.distributions[0].data.distribution.size(); ++i)
    res.distributions[0].data.distribution[i] += res.distributions[0].data.distribution[i-1];
  start_height = res.distributions[0].data.start_height;
  distribution = std::move(res.distributions[0].data.distribution);
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::detach_blockchain(uint64_t height, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache)
{
  LOG_PRINT_L0("Detaching blockchain on height " << height);

  // size  1 2 3 4 5 6 7 8 9
  // block 0 1 2 3 4 5 6 7 8
  //               C
  THROW_WALLET_EXCEPTION_IF(height < m_blockchain.offset() && m_blockchain.size() > m_blockchain.offset(),
      error::wallet_internal_error, "Daemon claims reorg below last checkpoint");

  size_t transfers_detached = 0;

  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    wallet2::transfer_details &td = m_transfers[i];
    if (td.m_spent && td.m_spent_height >= height)
    {
      LOG_PRINT_L1("Resetting spent/frozen status for output " << i << ": " << td.m_key_image);
      set_unspent(i);
      thaw(i);
    }
  }

  for (transfer_details &td: m_transfers)
  {
    while (!td.m_uses.empty() && td.m_uses.back().first >= height)
      td.m_uses.pop_back();
  }

  if (output_tracker_cache)
    output_tracker_cache->clear();

  auto it = std::find_if(m_transfers.begin(), m_transfers.end(), [&](const transfer_details& td){return td.m_block_height >= height;});
  size_t i_start = it - m_transfers.begin();

  for(size_t i = i_start; i!= m_transfers.size();i++)
  {
    if (!m_transfers[i].m_key_image_known || m_transfers[i].m_key_image_partial)
      continue;
    auto it_ki = m_key_images.find(m_transfers[i].m_key_image);
    THROW_WALLET_EXCEPTION_IF(it_ki == m_key_images.end(), error::wallet_internal_error, "key image not found: index " + std::to_string(i) + ", ki " + epee::string_tools::pod_to_hex(m_transfers[i].m_key_image) + ", " + std::to_string(m_key_images.size()) + " key images known");
    m_key_images.erase(it_ki);
  }

  for(size_t i = i_start; i!= m_transfers.size();i++)
  {
    auto it_pk = m_pub_keys.find(m_transfers[i].get_public_key());
    THROW_WALLET_EXCEPTION_IF(it_pk == m_pub_keys.end(), error::wallet_internal_error, "public key not found");
    m_pub_keys.erase(it_pk);
  }
  transfers_detached = std::distance(it, m_transfers.end());
  m_transfers.erase(it, m_transfers.end());

  size_t blocks_detached = m_blockchain.size() - height;
  m_blockchain.crop(height);

  for (auto it = m_payments.begin(); it != m_payments.end(); )
  {
    if(height <= it->second.m_block_height)
      it = m_payments.erase(it);
    else
      ++it;
  }

  for (auto it = m_confirmed_txs.begin(); it != m_confirmed_txs.end(); )
  {
    if(height <= it->second.m_block_height)
      it = m_confirmed_txs.erase(it);
    else
      ++it;
  }

  LOG_PRINT_L0("Detached blockchain on height " << height << ", transfers detached " << transfers_detached << ", blocks detached " << blocks_detached);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::deinit()
{
  m_is_initialized=false;
  unlock_keys_file();
  m_account.deinit();
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::clear()
{
  m_blockchain.clear();
  m_transfers.clear();
  m_key_images.clear();
  m_pub_keys.clear();
  m_unconfirmed_txs.clear();
  m_payments.clear();
  m_tx_keys.clear();
  m_additional_tx_keys.clear();
  m_confirmed_txs.clear();
  m_unconfirmed_payments.clear();
  m_scanned_pool_txs[0].clear();
  m_scanned_pool_txs[1].clear();
  m_address_book.clear();
  m_subaddresses.clear();
  m_subaddress_labels.clear();
  m_device_last_key_image_sync = 0;
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::clear_soft(bool keep_key_images)
{
  m_blockchain.clear();
  m_transfers.clear();
  if (!keep_key_images)
    m_key_images.clear();
  m_pub_keys.clear();
  m_unconfirmed_txs.clear();
  m_payments.clear();
  m_confirmed_txs.clear();
  m_unconfirmed_payments.clear();
  m_scanned_pool_txs[0].clear();
  m_scanned_pool_txs[1].clear();

  cryptonote::block b;
  generate_genesis(b);
  m_blockchain.push_back(get_block_hash(b));
  m_last_block_reward = cryptonote::get_outs_money_amount(b.miner_tx);
}

/*!
 * \brief Stores wallet information to wallet file.
 * \param  keys_file_name Name of wallet file
 * \param  password       Password of wallet file
 * \param  watch_only     true to save only view key, false to save both spend and view keys
 * \return                Whether it was successful.
 */
bool wallet2::store_keys(const std::string& keys_file_name, const epee::wipeable_string& password, bool watch_only)
{
  boost::optional<wallet2::keys_file_data> keys_file_data = get_keys_file_data(password, watch_only);
  CHECK_AND_ASSERT_MES(keys_file_data != boost::none, false, "failed to generate wallet keys data");

  std::string tmp_file_name = keys_file_name + ".new";
  std::string buf;
  bool r = ::serialization::dump_binary(keys_file_data.get(), buf);
  r = r && save_to_file(tmp_file_name, buf);
  CHECK_AND_ASSERT_MES(r, false, "failed to generate wallet keys file " << tmp_file_name);

  unlock_keys_file();
  std::cout<<"old "<<tmp_file_name<<",new "<<keys_file_name<<std::endl;
  std::error_code e = tools::replace_file(tmp_file_name, keys_file_name);
  lock_keys_file();

  if (e) {
    boost::filesystem::remove(tmp_file_name);
    LOG_ERROR("failed to update wallet keys file " << keys_file_name);
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
boost::optional<wallet2::keys_file_data> wallet2::get_keys_file_data(const epee::wipeable_string& password, bool watch_only)
{
  epee::byte_slice account_data;
  cryptonote::account_base account = m_account;

  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);

  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
  {
    account.encrypt_viewkey(key);
    account.decrypt_keys(key);
  }

  if (watch_only)
    account.forget_spend_key();

  account.encrypt_keys(key);

  bool r = epee::serialization::store_t_to_binary(account, account_data);
  CHECK_AND_ASSERT_MES(r, boost::none, "failed to serialize wallet keys");
  boost::optional<wallet2::keys_file_data> keys_file_data = (wallet2::keys_file_data) {};

  // Create a JSON object with "key_data" and "seed_language" as keys.
  rapidjson::Document json;
  json.SetObject();
  rapidjson::Value value(rapidjson::kStringType);
  value.SetString(reinterpret_cast<const char*>(account_data.data()), account_data.size());
  json.AddMember("key_data", value, json.GetAllocator());
  if (!seed_language.empty())
  {
    value.SetString(seed_language.c_str(), seed_language.length());
    json.AddMember("seed_language", value, json.GetAllocator());
  }

  rapidjson::Value value2(rapidjson::kNumberType);

  value2.SetInt(m_key_device_type);
  json.AddMember("key_on_device", value2, json.GetAllocator());

  value2.SetInt(watch_only ? 1 :0); // WTF ? JSON has different true and false types, and not boolean ??
  json.AddMember("watch_only", value2, json.GetAllocator());


  
  value2.SetInt(m_always_confirm_transfers ? 1 :0);
  json.AddMember("always_confirm_transfers", value2, json.GetAllocator());

  value2.SetInt(m_print_ring_members ? 1 :0);
  json.AddMember("print_ring_members", value2, json.GetAllocator());

  value2.SetInt(m_store_tx_info ? 1 :0);
  json.AddMember("store_tx_info", value2, json.GetAllocator());

  value2.SetUint(m_default_mixin);
  json.AddMember("default_mixin", value2, json.GetAllocator());

  value2.SetUint(m_default_priority);
  json.AddMember("default_priority", value2, json.GetAllocator());

  value2.SetInt(m_auto_refresh ? 1 :0);
  json.AddMember("auto_refresh", value2, json.GetAllocator());

  value2.SetInt(m_refresh_type);
  json.AddMember("refresh_type", value2, json.GetAllocator());

  value2.SetUint64(m_refresh_from_block_height);
  json.AddMember("refresh_height", value2, json.GetAllocator());

  value2.SetInt(m_confirm_non_default_ring_size ? 1 :0);
  json.AddMember("confirm_non_default_ring_size", value2, json.GetAllocator());

  value2.SetInt(m_ask_password);
  json.AddMember("ask_password", value2, json.GetAllocator());

  value2.SetUint64(m_max_reorg_depth);
  json.AddMember("max_reorg_depth", value2, json.GetAllocator());

  value2.SetUint(m_min_output_count);
  json.AddMember("min_output_count", value2, json.GetAllocator());

  value2.SetUint64(m_min_output_value);
  json.AddMember("min_output_value", value2, json.GetAllocator());

  value2.SetInt(cryptonote::get_default_decimal_point());
  json.AddMember("default_decimal_point", value2, json.GetAllocator());

  value2.SetInt(m_merge_destinations ? 1 :0);
  json.AddMember("merge_destinations", value2, json.GetAllocator());

  value2.SetInt(m_confirm_backlog ? 1 :0);
  json.AddMember("confirm_backlog", value2, json.GetAllocator());

  value2.SetUint(m_confirm_backlog_threshold);
  json.AddMember("confirm_backlog_threshold", value2, json.GetAllocator());

  value2.SetInt(m_confirm_export_overwrite ? 1 :0);
  json.AddMember("confirm_export_overwrite", value2, json.GetAllocator());

  value2.SetInt(m_auto_low_priority ? 1 : 0);
  json.AddMember("auto_low_priority", value2, json.GetAllocator());

  value2.SetUint(m_nettype);
  json.AddMember("nettype", value2, json.GetAllocator());

  value2.SetInt(m_segregate_pre_fork_outputs ? 1 : 0);
  json.AddMember("segregate_pre_fork_outputs", value2, json.GetAllocator());

  value2.SetInt(m_key_reuse_mitigation2 ? 1 : 0);
  json.AddMember("key_reuse_mitigation2", value2, json.GetAllocator());

  value2.SetUint(m_segregation_height);
  json.AddMember("segregation_height", value2, json.GetAllocator());

  value2.SetInt(m_ignore_fractional_outputs ? 1 : 0);
  json.AddMember("ignore_fractional_outputs", value2, json.GetAllocator());

  value2.SetUint64(m_ignore_outputs_above);
  json.AddMember("ignore_outputs_above", value2, json.GetAllocator());

  value2.SetUint64(m_ignore_outputs_below);
  json.AddMember("ignore_outputs_below", value2, json.GetAllocator());

  value2.SetInt(m_track_uses ? 1 : 0);
  json.AddMember("track_uses", value2, json.GetAllocator());

  value2.SetInt(m_inactivity_lock_timeout);
  json.AddMember("inactivity_lock_timeout", value2, json.GetAllocator());

  value2.SetInt(m_setup_background_mining);
  json.AddMember("setup_background_mining", value2, json.GetAllocator());

  value2.SetUint(m_subaddress_lookahead_major);
  json.AddMember("subaddress_lookahead_major", value2, json.GetAllocator());

  value2.SetUint(m_subaddress_lookahead_minor);
  json.AddMember("subaddress_lookahead_minor", value2, json.GetAllocator());

  value2.SetInt(m_original_keys_available ? 1 : 0);
  json.AddMember("original_keys_available", value2, json.GetAllocator());

  value2.SetInt(m_export_format);
  json.AddMember("export_format", value2, json.GetAllocator());

  value2.SetInt(m_load_deprecated_formats);
  json.AddMember("load_deprecated_formats", value2, json.GetAllocator());

  value2.SetUint(1);
  json.AddMember("encrypted_secret_keys", value2, json.GetAllocator());

  value.SetString(m_device_name.c_str(), m_device_name.size());
  json.AddMember("device_name", value, json.GetAllocator());

  value.SetString(m_device_derivation_path.c_str(), m_device_derivation_path.size());
  json.AddMember("device_derivation_path", value, json.GetAllocator());

  std::string original_address;
  std::string original_view_secret_key;
  if (m_original_keys_available)
  {  
    original_address = get_account_address_as_str(m_nettype, false, m_original_address);
    value.SetString(original_address.c_str(), original_address.length());
    json.AddMember("original_address", value, json.GetAllocator());
    original_view_secret_key = epee::string_tools::pod_to_hex(m_original_view_secret_key);
    value.SetString(original_view_secret_key.c_str(), original_view_secret_key.length());
    json.AddMember("original_view_secret_key", value, json.GetAllocator());
  }
  
  value2.SetInt(m_persistent_rpc_client_id ? 1 : 0);
  json.AddMember("persistent_rpc_client_id", value2, json.GetAllocator());

  value2.SetFloat(m_auto_mine_for_rpc_payment_threshold);
  json.AddMember("auto_mine_for_rpc_payment", value2, json.GetAllocator());

  value2.SetUint64(m_credits_target);
  json.AddMember("credits_target", value2, json.GetAllocator());

  // Serialize the JSON object
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  json.Accept(writer);

  // Encrypt the entire JSON object.
  std::string cipher;
  cipher.resize(buffer.GetSize());
  keys_file_data.get().iv = crypto::rand<crypto::chacha_iv>();
  crypto::chacha20(buffer.GetString(), buffer.GetSize(), key, keys_file_data.get().iv, &cipher[0]);
  keys_file_data.get().account_data = cipher;
  return keys_file_data;
}

//----------------------------------------------------------------------------------------------------
void wallet2::change_password(const std::string &filename, const epee::wipeable_string &original_password, const epee::wipeable_string &new_password)
{
  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
    decrypt_keys(original_password);
  setup_keys(new_password);
  rewrite(filename, new_password);
  if (!filename.empty())
    store();
}
/*!
 * \brief verify password for default wallet keys file.
 * \param password       Password to verify
 * \return               true if password is correct
 *
 * for verification only
 * should not mutate state, unlike load_keys()
 * can be used prior to rewriting wallet keys file, to ensure user has entered the correct password
 *
 */
bool wallet2::verify_password(const epee::wipeable_string& password)
{
  // this temporary unlocking is necessary for Windows (otherwise the file couldn't be loaded).
  unlock_keys_file();
  bool r = verify_password(m_keys_file, password, m_account.get_device().device_protocol() == hw::device::PROTOCOL_COLD || m_watch_only , m_account.get_device(), m_kdf_rounds);
  lock_keys_file();
  return r;
}

/*!
 * \brief verify password for specified wallet keys file.
 * \param keys_file_name  Keys file to verify password for
 * \param password        Password to verify
 * \param no_spend_key    If set = only verify view keys, otherwise also spend keys
 * \param hwdev           The hardware device to use
 * \return                true if password is correct
 *
 * for verification only
 * should not mutate state, unlike load_keys()
 * can be used prior to rewriting wallet keys file, to ensure user has entered the correct password
 *
 */
bool wallet2::verify_password(const std::string& keys_file_name, const epee::wipeable_string& password, bool no_spend_key, hw::device &hwdev, uint64_t kdf_rounds)
{
  rapidjson::Document json;
  wallet2::keys_file_data keys_file_data;
  std::string buf;
  bool encrypted_secret_keys = false;
  bool r = load_from_file(keys_file_name, buf);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, keys_file_name);

  // Decrypt the contents
  r = ::serialization::parse_binary(buf, keys_file_data);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize \"" + keys_file_name + '\"');
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
  if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject())
    crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);

  // The contents should be JSON if the wallet follows the new format.
  if (json.Parse(account_data.c_str()).HasParseError())
  {
    // old format before JSON wallet key file format
  }
  else
  {
    account_data = std::string(json["key_data"].GetString(), json["key_data"].GetString() +
      json["key_data"].GetStringLength());
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, encrypted_secret_keys, uint32_t, Uint, false, false);
    encrypted_secret_keys = field_encrypted_secret_keys;
  }

  cryptonote::account_base account_data_check;

  r = epee::serialization::load_t_from_binary(account_data_check, account_data);

  if (encrypted_secret_keys)
    account_data_check.decrypt_keys(key);

  const cryptonote::account_keys& keys = account_data_check.get_keys();
  r = r && hwdev.verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key);
  if(!no_spend_key)
    r = r && hwdev.verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
  return r;
}

void wallet2::encrypt_keys(const crypto::chacha_key &key)
{
  boost::lock_guard<boost::mutex> lock(m_decrypt_keys_lock);
  if (--m_decrypt_keys_lockers) // another lock left ?
    return;
  m_account.encrypt_keys(key);
  m_account.decrypt_viewkey(key);
}

void wallet2::decrypt_keys(const crypto::chacha_key &key)
{
  boost::lock_guard<boost::mutex> lock(m_decrypt_keys_lock);
  if (m_decrypt_keys_lockers++) // already unlocked ?
    return;
  m_account.encrypt_viewkey(key);
  m_account.decrypt_keys(key);
}

void wallet2::encrypt_keys(const epee::wipeable_string &password)
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  encrypt_keys(key);
}

void wallet2::decrypt_keys(const epee::wipeable_string &password)
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  decrypt_keys(key);
}

void wallet2::setup_new_blockchain()
{
  cryptonote::block b;
  generate_genesis(b);
  m_blockchain.push_back(get_block_hash(b));
  m_last_block_reward = cryptonote::get_outs_money_amount(b.miner_tx);
  add_subaddress_account(tr("Primary account"));
}

void wallet2::create_keys_file(const std::string &wallet_, bool watch_only, const epee::wipeable_string &password, bool create_address_file)
{
  if (!wallet_.empty())
  {
    bool r = store_keys(m_keys_file, password, watch_only);
    THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);

    if (create_address_file)
    {
      r = save_to_file(m_wallet_file + ".address.txt", m_account.get_public_address_str(m_nettype), true);
      if(!r) MERROR("String with address text not saved");
    }
  }
}


/*!
 * \brief determine the key storage for the specified wallet file
 * \param device_type     (OUT) wallet backend as enumerated in hw::device::device_type
 * \param keys_file_name  Keys file to verify password for
 * \param password        Password to verify
 * \return                true if password correct, else false
 *
 * for verification only - determines key storage hardware
 *
 */
bool wallet2::query_device(hw::device::device_type& device_type, const std::string& keys_file_name, const epee::wipeable_string& password, uint64_t kdf_rounds)
{
  rapidjson::Document json;
  wallet2::keys_file_data keys_file_data;
  std::string buf;
  bool r = load_from_file(keys_file_name, buf);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, keys_file_name);

  // Decrypt the contents
  r = ::serialization::parse_binary(buf, keys_file_data);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize \"" + keys_file_name + '\"');
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
  if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject())
    crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);

  device_type = hw::device::device_type::SOFTWARE;
  // The contents should be JSON if the wallet follows the new format.
  if (json.Parse(account_data.c_str()).HasParseError())
  {
    // old format before JSON wallet key file format
  }
  else
  {
    account_data = std::string(json["key_data"].GetString(), json["key_data"].GetString() +
      json["key_data"].GetStringLength());

    if (json.HasMember("key_on_device"))
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, key_on_device, int, Int, false, hw::device::device_type::SOFTWARE);
      device_type = static_cast<hw::device::device_type>(field_key_on_device);
    }
  }

  cryptonote::account_base account_data_check;

  r = epee::serialization::load_t_from_binary(account_data_check, account_data);
  if (!r) return false;
  return true;
}

void wallet2::init_type(hw::device::device_type device_type)
{
  m_account_public_address = m_account.get_keys().m_account_address;
  m_watch_only = false;
  m_original_keys_available = false;
  m_key_device_type = device_type;
}

/*!
 * \brief  Generates a wallet or restores one.
 * \param  wallet_                 Name of wallet file
 * \param  password                Password of wallet file
 * \param  recovery_param          If it is a restore, the recovery key
 * \param  recover                 Whether it is a restore
 * \param  two_random              Whether it is a non-deterministic wallet
 * \param  create_address_file     Whether to create an address file
 * \return                         The secret key of the generated wallet
 */
crypto::secret_key wallet2::generate(const std::string& wallet_, const epee::wipeable_string& password,
  const crypto::secret_key& recovery_param, bool recover, bool two_random, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    boost::system::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  crypto::secret_key retval = m_account.generate(recovery_param, recover, two_random);

  init_type(hw::device::device_type::SOFTWARE);
  setup_keys(password);

  // calculate a starting refresh height
  if(m_refresh_from_block_height == 0 && !recover){
    m_refresh_from_block_height = estimate_blockchain_height();
  }

  create_keys_file(wallet_, false, password, m_nettype != MAINNET || create_address_file);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();

  return retval;
}

 uint64_t wallet2::estimate_blockchain_height()
 {
   // -1 month for fluctuations in block time and machine date/time setup.
   // avg seconds per block
   const int seconds_per_block = DIFFICULTY_TARGET_V2;
   // ~num blocks per month
   const uint64_t blocks_per_month = 60*60*24*30/seconds_per_block;

   // try asking the daemon first
   std::string err;
   uint64_t height = 0;

   // we get the max of approximated height and local height.
   // approximated height is the least of daemon target height
   // (the max of what the other daemons are claiming is their
   // height) and the theoretical height based on the local
   // clock. This will be wrong only if both the local clock
   // is bad *and* a peer daemon claims a highest height than
   // the real chain.
   // local height is the height the local daemon is currently
   // synced to, it will be lower than the real chain height if
   // the daemon is currently syncing.
   // If we use the approximate height we subtract one month as
   // a safety margin.
   height = get_approximate_blockchain_height();
   uint64_t target_height = get_daemon_blockchain_target_height(err);
   if (err.empty()) {
     if (target_height < height)
       height = target_height;
   } else {
     // if we couldn't talk to the daemon, check safety margin.
     if (height > blocks_per_month)
       height -= blocks_per_month;
     else
       height = 0;
   }
   uint64_t local_height = get_daemon_blockchain_height(err);
   if (err.empty() && local_height > height)
     height = local_height;
   return height;
 }

/*!
* \brief Creates a watch only wallet from a public address and a view secret key.
* \param  wallet_                 Name of wallet file
* \param  password                Password of wallet file
* \param  account_public_address  The account's public address
* \param  viewkey                 view secret key
* \param  create_address_file     Whether to create an address file
*/
void wallet2::generate(const std::string& wallet_, const epee::wipeable_string& password,
  const cryptonote::account_public_address &account_public_address,
  const crypto::secret_key& viewkey, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    boost::system::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  m_account.create_from_viewkey(account_public_address, viewkey);
  init_type(hw::device::device_type::SOFTWARE);
  m_watch_only = true;
  m_account_public_address = account_public_address;
  setup_keys(password);

  create_keys_file(wallet_, true, password, m_nettype != MAINNET || create_address_file);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();
}

/*!
* \brief Creates a wallet from a public address and a spend/view secret key pair.
* \param  wallet_                 Name of wallet file
* \param  password                Password of wallet file
* \param  account_public_address  The account's public address
* \param  spendkey                spend secret key
* \param  viewkey                 view secret key
* \param  create_address_file     Whether to create an address file
*/
void wallet2::generate(const std::string& wallet_, const epee::wipeable_string& password,
  const cryptonote::account_public_address &account_public_address,
  const crypto::secret_key& spendkey, const crypto::secret_key& viewkey, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    boost::system::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  m_account.create_from_keys(account_public_address, spendkey, viewkey);
  init_type(hw::device::device_type::SOFTWARE);
  m_account_public_address = account_public_address;
  setup_keys(password);

  create_keys_file(wallet_, false, password, create_address_file);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();
}

/*!
* \brief Creates a wallet from a device
* \param  wallet_        Name of wallet file
* \param  password       Password of wallet file
* \param  device_name    device string address
*/
void wallet2::restore(const std::string& wallet_, const epee::wipeable_string& password, const std::string &device_name, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  boost::system::error_code ignored_ec;
  if (!wallet_.empty()) {
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  auto &hwdev = lookup_device(device_name);
  hwdev.set_name(device_name);
  hwdev.set_network_type(m_nettype);
  hwdev.set_derivation_path(m_device_derivation_path);
  hwdev.set_callback(get_device_callback());

  m_account.create_from_device(hwdev);
  init_type(m_account.get_device().get_type());
  setup_keys(password);
  m_device_name = device_name;

  create_keys_file(wallet_, false, password, m_nettype != MAINNET || create_address_file);
  if (m_subaddress_lookahead_major == SUBADDRESS_LOOKAHEAD_MAJOR && m_subaddress_lookahead_minor == SUBADDRESS_LOOKAHEAD_MINOR)
  {
    // the default lookahead setting (50:200) is clearly too much for hardware wallet
    m_subaddress_lookahead_major = 5;
    m_subaddress_lookahead_minor = 20;
  }
  setup_new_blockchain();
  if (!wallet_.empty()) {
    store();
  }
}


bool wallet2::has_unknown_key_images() const
{
  for (const auto &td: m_transfers)
    if (!td.m_key_image_known)
      return true;
  return false;
}

/*!
 * \brief Rewrites to the wallet file for wallet upgrade (doesn't generate key, assumes it's already there)
 * \param wallet_name Name of wallet file (should exist)
 * \param password    Password for wallet file
 */
void wallet2::rewrite(const std::string& wallet_name, const epee::wipeable_string& password)
{
  if (wallet_name.empty())
    return;
  prepare_file_names(wallet_name);
  boost::system::error_code ignored_ec;
  THROW_WALLET_EXCEPTION_IF(!boost::filesystem::exists(m_keys_file, ignored_ec), error::file_not_found, m_keys_file);
  bool r = store_keys(m_keys_file, password, m_watch_only);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);
}
/*!
 * \brief Writes to a file named based on the normal wallet (doesn't generate key, assumes it's already there)
 * \param wallet_name       Base name of wallet file
 * \param password          Password for wallet file
 * \param new_keys_filename [OUT] Name of new keys file
 */
void wallet2::write_watch_only_wallet(const std::string& wallet_name, const epee::wipeable_string& password, std::string &new_keys_filename)
{
  prepare_file_names(wallet_name);
  boost::system::error_code ignored_ec;
  new_keys_filename = m_wallet_file + "-watchonly.keys";
  bool watch_only_keys_file_exists = boost::filesystem::exists(new_keys_filename, ignored_ec);
  THROW_WALLET_EXCEPTION_IF(watch_only_keys_file_exists, error::file_save_error, new_keys_filename);
  bool r = store_keys(new_keys_filename, password, true);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, new_keys_filename);
}
//----------------------------------------------------------------------------------------------------

//----------------------------------------------------------------------------------------------------
bool wallet2::wallet_valid_path_format(const std::string& file_path)
{
  return !file_path.empty();
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_long_payment_id(const std::string& payment_id_str, crypto::hash& payment_id)
{
  cryptonote::blobdata payment_id_data;
  if(!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data))
    return false;

  if(sizeof(crypto::hash) != payment_id_data.size())
    return false;

  payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_data.data());
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_short_payment_id(const std::string& payment_id_str, crypto::hash8& payment_id)
{
  cryptonote::blobdata payment_id_data;
  if(!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data))
    return false;

  if(sizeof(crypto::hash8) != payment_id_data.size())
    return false;

  payment_id = *reinterpret_cast<const crypto::hash8*>(payment_id_data.data());
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_payment_id(const std::string& payment_id_str, crypto::hash& payment_id)
{
  if (parse_long_payment_id(payment_id_str, payment_id))
    return true;
  crypto::hash8 payment_id8;
  if (parse_short_payment_id(payment_id_str, payment_id8))
  {
    memcpy(payment_id.data, payment_id8.data, 8);
    memset(payment_id.data + 8, 0, 24);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------------------------------------
bool wallet2::check_connection(uint32_t *version, bool *ssl, uint32_t timeout)
{
  THROW_WALLET_EXCEPTION_IF(!m_is_initialized, error::wallet_not_initialized);

  if (m_offline)
  {
    m_rpc_version = 0;
    if (version)
      *version = 0;
    if (ssl)
      *ssl = false;
    return false;
  }

  // TODO: Add light wallet version check.
  if(m_light_wallet) {
      m_rpc_version = 0;
      if (version)
        *version = 0;
      if (ssl)
        *ssl = m_light_wallet_connected; // light wallet is always SSL
      return m_light_wallet_connected;
  }

  {
    boost::lock_guard<boost::recursive_mutex> lock(m_daemon_rpc_mutex);
    if(!m_http_client->is_connected(ssl))
    {
      m_rpc_version = 0;
      m_node_rpc_proxy.invalidate();
      if (!m_http_client->connect(std::chrono::milliseconds(timeout)))
        return false;
      if(!m_http_client->is_connected(ssl))
        return false;
    }
  }

  if (!m_rpc_version)
  {
    cryptonote::COMMAND_RPC_GET_VERSION::request req_t = AUTO_VAL_INIT(req_t);
    cryptonote::COMMAND_RPC_GET_VERSION::response resp_t = AUTO_VAL_INIT(resp_t);
    bool r = invoke_http_json_rpc("/json_rpc", "get_version", req_t, resp_t);
    if(!r || resp_t.status != CORE_RPC_STATUS_OK) {
      if(version)
        *version = 0;
      return false;
    }
    m_rpc_version = resp_t.version;
  }
  if (version)
    *version = m_rpc_version;

  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_offline(bool offline)
{
  m_offline = offline;
  m_node_rpc_proxy.set_offline(offline);
  m_http_client->set_auto_connect(!offline);
  if (offline)
  {
    boost::lock_guard<boost::recursive_mutex> lock(m_daemon_rpc_mutex);
    if(m_http_client->is_connected())
      m_http_client->disconnect();
  }
}
//----------------------------------------------------------------------------------------------------
bool wallet2::generate_chacha_key_from_secret_keys(crypto::chacha_key &key) const
{
  hw::device &hwdev =  m_account.get_device();
  return hwdev.generate_chacha_key(m_account.get_keys(), key, m_kdf_rounds);
}
//----------------------------------------------------------------------------------------------------
void wallet2::generate_chacha_key_from_password(const epee::wipeable_string &pass, crypto::chacha_key &key) const
{
  crypto::generate_chacha_key(pass.data(), pass.size(), key, m_kdf_rounds);
}

//----------------------------------------------------------------------------------------------------
void wallet2::trim_hashchain()
{
  uint64_t height = m_checkpoints.get_max_height();

  for (const transfer_details &td: m_transfers)
    if (td.m_block_height < height)
      height = td.m_block_height;

  if (!m_blockchain.empty() && m_blockchain.size() == m_blockchain.offset())
  {
    MINFO("Fixing empty hashchain");
    cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request req = AUTO_VAL_INIT(req);
    cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response res = AUTO_VAL_INIT(res);

    bool r;
    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      req.height = m_blockchain.size() - 1;
      uint64_t pre_call_credits = m_rpc_payment_state.credits;
      req.client = get_client_signature();
      r = net_utils::invoke_http_json_rpc("/json_rpc", "getblockheaderbyheight", req, res, *m_http_client, rpc_timeout);
      if (r && res.status == CORE_RPC_STATUS_OK)
        check_rpc_cost("getblockheaderbyheight", res.credits, pre_call_credits, COST_PER_BLOCK_HEADER);
    }

    if (r && res.status == CORE_RPC_STATUS_OK)
    {
      crypto::hash hash;
      epee::string_tools::hex_to_pod(res.block_header.hash, hash);
      m_blockchain.refill(hash);
    }
    else
    {
      MERROR("Failed to request block header from daemon, hash chain may be unable to sync till the wallet is loaded with a usable daemon");
    }
  }
  if (height > 0 && m_blockchain.size() > height)
  {
    --height;
    MDEBUG("trimming to " << height << ", offset " << m_blockchain.offset());
    m_blockchain.trim(height);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::check_genesis(const crypto::hash& genesis_hash) const {
  std::string what("Genesis block mismatch. You probably use wallet without testnet (or stagenet) flag with blockchain from test (or stage) network or vice versa");

  THROW_WALLET_EXCEPTION_IF(genesis_hash != m_blockchain.genesis(), error::wallet_internal_error, what);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::path() const
{
  return m_wallet_file;
}
//----------------------------------------------------------------------------------------------------
void wallet2::store()
{
  if (!m_wallet_file.empty())
    store_to("", epee::wipeable_string());
}
//----------------------------------------------------------------------------------------------------
void wallet2::store_to(const std::string &path, const epee::wipeable_string &password)
{
  trim_hashchain();

  // if file is the same, we do:
  // 1. save wallet to the *.new file
  // 2. remove old wallet file
  // 3. rename *.new to wallet_name

  // handle if we want just store wallet state to current files (ex store() replacement);
  bool same_file = true;
  if (!path.empty())
  {
    std::string canonical_path = boost::filesystem::canonical(m_wallet_file).string();
    size_t pos = canonical_path.find(path);
    same_file = pos != std::string::npos;
  }


  if (!same_file)
  {
    // check if we want to store to directory which doesn't exists yet
    boost::filesystem::path parent_path = boost::filesystem::path(path).parent_path();

    // if path is not exists, try to create it
    if (!parent_path.empty() &&  !boost::filesystem::exists(parent_path))
    {
      boost::system::error_code ec;
      if (!boost::filesystem::create_directories(parent_path, ec))
      {
        throw std::logic_error(ec.message());
      }
    }
  }

  // get wallet cache data
  boost::optional<wallet2::cache_file_data> cache_file_data = get_cache_file_data(password);
  THROW_WALLET_EXCEPTION_IF(cache_file_data == boost::none, error::wallet_internal_error, "failed to generate wallet cache data");

  const std::string new_file = same_file ? m_wallet_file + ".new" : path;
  const std::string old_file = m_wallet_file;
  const std::string old_keys_file = m_keys_file;
  const std::string old_address_file = m_wallet_file + ".address.txt";
  const std::string old_mms_file = m_mms_file;

  // save keys to the new file
  // if we here, main wallet file is saved and we only need to save keys and address files
  if (!same_file) {
    prepare_file_names(path);
    bool r = store_keys(m_keys_file, password, false);
    THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);
    if (boost::filesystem::exists(old_address_file))
    {
      // save address to the new file
      const std::string address_file = m_wallet_file + ".address.txt";
      r = save_to_file(address_file, m_account.get_public_address_str(m_nettype), true);
      THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_wallet_file);
      // remove old address file
      r = boost::filesystem::remove(old_address_file);
      if (!r) {
        LOG_ERROR("error removing file: " << old_address_file);
      }
    }
    // remove old wallet file
    r = boost::filesystem::remove(old_file);
    if (!r) {
      LOG_ERROR("error removing file: " << old_file);
    }
    // remove old keys file
    r = boost::filesystem::remove(old_keys_file);
    if (!r) {
      LOG_ERROR("error removing file: " << old_keys_file);
    }
    // remove old message store file
    if (boost::filesystem::exists(old_mms_file))
    {
      r = boost::filesystem::remove(old_mms_file);
      if (!r) {
        LOG_ERROR("error removing file: " << old_mms_file);
      }
    }
  } else {
    // save to new file
#ifdef WIN32
    // On Windows avoid using std::ofstream which does not work with UTF-8 filenames
    // The price to pay is temporary higher memory consumption for string stream + binary archive
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    bool success = ::serialization::serialize(oar, cache_file_data.get());
    if (success) {
        success = save_to_file(new_file, oss.str());
    }
    THROW_WALLET_EXCEPTION_IF(!success, error::file_save_error, new_file);
#else
    std::ofstream ostr;
    ostr.open(new_file, std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
    binary_archive<true> oar(ostr);
    bool success = ::serialization::serialize(oar, cache_file_data.get());
    ostr.close();
    THROW_WALLET_EXCEPTION_IF(!success || !ostr.good(), error::file_save_error, new_file);
#endif

    // here we have "*.new" file, we need to rename it to be without ".new"
    std::error_code e = tools::replace_file(new_file, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(e, error::file_save_error, m_wallet_file, e);
  }
  
}
//----------------------------------------------------------------------------------------------------
boost::optional<wallet2::cache_file_data> wallet2::get_cache_file_data(const epee::wipeable_string &passwords)
{
  trim_hashchain();
  try
  {
    std::stringstream oss;
    binary_archive<true> ar(oss);
    if (!::serialization::serialize(ar, *this))
      return boost::none;

    boost::optional<wallet2::cache_file_data> cache_file_data = (wallet2::cache_file_data) {};
    cache_file_data.get().cache_data = oss.str();
    std::string cipher;
    cipher.resize(cache_file_data.get().cache_data.size());
    cache_file_data.get().iv = crypto::rand<crypto::chacha_iv>();
    crypto::chacha20(cache_file_data.get().cache_data.data(), cache_file_data.get().cache_data.size(), m_cache_key, cache_file_data.get().iv, &cipher[0]);
    cache_file_data.get().cache_data = cipher;
    return cache_file_data;
  }
  catch(...)
  {
    return boost::none;
  }
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::balance(uint32_t index_major, bool strict) const
{
  uint64_t amount = 0;
  for (const auto& i : balance_per_subaddress(index_major, strict))
    amount += i.second;
  return amount;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::unlocked_balance(uint32_t index_major, bool strict, uint64_t *blocks_to_unlock, uint64_t *time_to_unlock)
{
  uint64_t amount = 0;
  if (blocks_to_unlock)
    *blocks_to_unlock = 0;
  if (time_to_unlock)
    *time_to_unlock = 0;
  if(m_light_wallet)
    return m_light_wallet_unlocked_balance;
  for (const auto& i : unlocked_balance_per_subaddress(index_major, strict))
  {
    amount += i.second.first;
    if (blocks_to_unlock && i.second.second.first > *blocks_to_unlock)
      *blocks_to_unlock = i.second.second.first;
    if (time_to_unlock && i.second.second.second > *time_to_unlock)
      *time_to_unlock = i.second.second.second;
  }
  return amount;
}
//----------------------------------------------------------------------------------------------------
std::map<uint32_t, uint64_t> wallet2::balance_per_subaddress(uint32_t index_major, bool strict) const
{
  std::map<uint32_t, uint64_t> amount_per_subaddr;
  for (const auto& td: m_transfers)
  {
    if (td.m_subaddr_index.major == index_major && !is_spent(td, strict) && !td.m_frozen)
    {
      auto found = amount_per_subaddr.find(td.m_subaddr_index.minor);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[td.m_subaddr_index.minor] = td.amount();
      else
        found->second += td.amount();
    }
  }
  if (!strict)
  {
   for (const auto& utx: m_unconfirmed_txs)
   {
    if (utx.second.m_subaddr_account == index_major && utx.second.m_state != wallet2::unconfirmed_transfer_details::failed)
    {
      // all changes go to 0-th subaddress (in the current subaddress account)
      auto found = amount_per_subaddr.find(0);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[0] = utx.second.m_change;
      else
        found->second += utx.second.m_change;
    }
   }

   for (const auto& utx: m_unconfirmed_payments)
   {
    if (utx.second.m_pd.m_subaddr_index.major == index_major)
    {
      amount_per_subaddr[utx.second.m_pd.m_subaddr_index.minor] += utx.second.m_pd.m_amount;
    }
   }
  }
  return amount_per_subaddr;
}
//----------------------------------------------------------------------------------------------------
std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> wallet2::unlocked_balance_per_subaddress(uint32_t index_major, bool strict)
{
  std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> amount_per_subaddr;
  const uint64_t blockchain_height = get_blockchain_current_height();
  const uint64_t now = time(NULL);
  for(const transfer_details& td: m_transfers)
  {
    if(td.m_subaddr_index.major == index_major && !is_spent(td, strict) && !td.m_frozen)
    {
      uint64_t amount = 0, blocks_to_unlock = 0, time_to_unlock = 0;
      if (is_transfer_unlocked(td))
      {
        amount = td.amount();
        blocks_to_unlock = 0;
        time_to_unlock = 0;
      }
      else
      {
        uint64_t unlock_height = td.m_block_height + std::max<uint64_t>(CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS);
        if (td.m_tx.unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER && td.m_tx.unlock_time > unlock_height)
          unlock_height = td.m_tx.unlock_time;
        uint64_t unlock_time = td.m_tx.unlock_time >= CRYPTONOTE_MAX_BLOCK_NUMBER ? td.m_tx.unlock_time : 0;
        blocks_to_unlock = unlock_height > blockchain_height ? unlock_height - blockchain_height : 0;
        time_to_unlock = unlock_time > now ? unlock_time - now : 0;
        amount = 0;
      }
      auto found = amount_per_subaddr.find(td.m_subaddr_index.minor);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[td.m_subaddr_index.minor] = std::make_pair(amount, std::make_pair(blocks_to_unlock, time_to_unlock));
      else
      {
        found->second.first += amount;
        found->second.second.first = std::max(found->second.second.first, blocks_to_unlock);
        found->second.second.second = std::max(found->second.second.second, time_to_unlock);
      }
    }
  }
  return amount_per_subaddr;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::balance_all(bool strict) const
{
  uint64_t r = 0;
  for (uint32_t index_major = 0; index_major < get_num_subaddress_accounts(); ++index_major)
    r += balance(index_major, strict);
  return r;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::unlocked_balance_all(bool strict, uint64_t *blocks_to_unlock, uint64_t *time_to_unlock)
{
  uint64_t r = 0;
  if (blocks_to_unlock)
    *blocks_to_unlock = 0;
  if (time_to_unlock)
    *time_to_unlock = 0;
  for (uint32_t index_major = 0; index_major < get_num_subaddress_accounts(); ++index_major)
  {
    uint64_t local_blocks_to_unlock, local_time_to_unlock;
    r += unlocked_balance(index_major, strict, blocks_to_unlock ? &local_blocks_to_unlock : NULL, time_to_unlock ? &local_time_to_unlock : NULL);
    if (blocks_to_unlock)
      *blocks_to_unlock = std::max(*blocks_to_unlock, local_blocks_to_unlock);
    if (time_to_unlock)
      *time_to_unlock = std::max(*time_to_unlock, local_time_to_unlock);
  }
  return r;
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_transfers(wallet2::transfer_container& incoming_transfers) const
{
  incoming_transfers = m_transfers;
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments(const crypto::hash& payment_id, std::list<wallet2::payment_details>& payments, uint64_t min_height, const boost::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  auto range = m_payments.equal_range(payment_id);
  std::for_each(range.first, range.second, [&payments, &min_height, &subaddr_account, &subaddr_indices](const payment_container::value_type& x) {
    if (min_height < x.second.m_block_height &&
      (!subaddr_account || *subaddr_account == x.second.m_subaddr_index.major) &&
      (subaddr_indices.empty() || subaddr_indices.count(x.second.m_subaddr_index.minor) == 1))
    {
      payments.push_back(x.second);
    }
  });
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments(std::list<std::pair<crypto::hash,wallet2::payment_details>>& payments, uint64_t min_height, uint64_t max_height, const boost::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  auto range = std::make_pair(m_payments.begin(), m_payments.end());
  std::for_each(range.first, range.second, [&payments, &min_height, &max_height, &subaddr_account, &subaddr_indices](const payment_container::value_type& x) {
    if (min_height < x.second.m_block_height && max_height >= x.second.m_block_height &&
      (!subaddr_account || *subaddr_account == x.second.m_subaddr_index.major) &&
      (subaddr_indices.empty() || subaddr_indices.count(x.second.m_subaddr_index.minor) == 1))
    {
      payments.push_back(x);
    }
  });
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments_out(std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_details>>& confirmed_payments,
    uint64_t min_height, uint64_t max_height, const boost::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_confirmed_txs.begin(); i != m_confirmed_txs.end(); ++i) {
    if (i->second.m_block_height <= min_height || i->second.m_block_height > max_height)
      continue;
    if (subaddr_account && *subaddr_account != i->second.m_subaddr_account)
      continue;
    if (!subaddr_indices.empty() && std::count_if(i->second.m_subaddr_indices.begin(), i->second.m_subaddr_indices.end(), [&subaddr_indices](uint32_t index) { return subaddr_indices.count(index) == 1; }) == 0)
      continue;
    confirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_payments_out(std::list<std::pair<crypto::hash,wallet2::unconfirmed_transfer_details>>& unconfirmed_payments, const boost::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_unconfirmed_txs.begin(); i != m_unconfirmed_txs.end(); ++i) {
    if (subaddr_account && *subaddr_account != i->second.m_subaddr_account)
      continue;
    if (!subaddr_indices.empty() && std::count_if(i->second.m_subaddr_indices.begin(), i->second.m_subaddr_indices.end(), [&subaddr_indices](uint32_t index) { return subaddr_indices.count(index) == 1; }) == 0)
      continue;
    unconfirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_payments(std::list<std::pair<crypto::hash,wallet2::pool_payment_details>>& unconfirmed_payments, const boost::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_unconfirmed_payments.begin(); i != m_unconfirmed_payments.end(); ++i) {
    if ((!subaddr_account || *subaddr_account == i->second.m_pd.m_subaddr_index.major) &&
      (subaddr_indices.empty() || subaddr_indices.count(i->second.m_pd.m_subaddr_index.minor) == 1))
    unconfirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::rescan_spent()
{
  // This is RPC call that can take a long time if there are many outputs,
  // so we call it several times, in stripes, so we don't time out spuriously
  std::vector<int> spent_status;
  spent_status.reserve(m_transfers.size());
  const size_t chunk_size = 1000;
  for (size_t start_offset = 0; start_offset < m_transfers.size(); start_offset += chunk_size)
  {
    const size_t n_outputs = std::min<size_t>(chunk_size, m_transfers.size() - start_offset);
    MDEBUG("Calling is_key_image_spent on " << start_offset << " - " << (start_offset + n_outputs - 1) << ", out of " << m_transfers.size());
    COMMAND_RPC_IS_KEY_IMAGE_SPENT::request req = AUTO_VAL_INIT(req);
    COMMAND_RPC_IS_KEY_IMAGE_SPENT::response daemon_resp = AUTO_VAL_INIT(daemon_resp);
    for (size_t n = start_offset; n < start_offset + n_outputs; ++n)
      req.key_images.push_back(string_tools::pod_to_hex(m_transfers[n].m_key_image));

    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      uint64_t pre_call_credits = m_rpc_payment_state.credits;
      req.client = get_client_signature();
      bool r = epee::net_utils::invoke_http_json("/is_key_image_spent", req, daemon_resp, *m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR(r, {}, daemon_resp, "is_key_image_spent", error::is_key_image_spent_error, get_rpc_status(daemon_resp.status));
      THROW_WALLET_EXCEPTION_IF(daemon_resp.spent_status.size() != n_outputs, error::wallet_internal_error,
        "daemon returned wrong response for is_key_image_spent, wrong amounts count = " +
        std::to_string(daemon_resp.spent_status.size()) + ", expected " +  std::to_string(n_outputs));
      check_rpc_cost("/is_key_image_spent", daemon_resp.credits, pre_call_credits, n_outputs * COST_PER_KEY_IMAGE);
    }

    std::copy(daemon_resp.spent_status.begin(), daemon_resp.spent_status.end(), std::back_inserter(spent_status));
  }

  // update spent status
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    transfer_details& td = m_transfers[i];
    // a view wallet may not know about key images
    if (!td.m_key_image_known || td.m_key_image_partial)
      continue;
    if (td.m_spent != (spent_status[i] != COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT))
    {
      if (td.m_spent)
      {
        LOG_PRINT_L0("Marking output " << i << "(" << td.m_key_image << ") as unspent, it was marked as spent");
        set_unspent(i);
        td.m_spent_height = 0;
      }
      else
      {
        LOG_PRINT_L0("Marking output " << i << "(" << td.m_key_image << ") as spent, it was marked as unspent");
        set_spent(i, td.m_spent_height);
        // unknown height, if this gets reorged, it might still be missed
      }
    }
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::rescan_blockchain(bool hard, bool refresh, bool keep_key_images)
{
  CHECK_AND_ASSERT_THROW_MES(!hard || !keep_key_images, "Cannot preserve key images on hard rescan");
  const size_t transfers_cnt = m_transfers.size();
  crypto::hash transfers_hash{};

  if(hard)
  {
    clear();
    setup_new_blockchain();
  }
  else
  {
    if (keep_key_images && refresh)
      hash_m_transfers((int64_t) transfers_cnt, transfers_hash);
    clear_soft(keep_key_images);
  }

  if (refresh)
    this->refresh(false);

  if (refresh && keep_key_images)
    finish_rescan_bc_keep_key_images(transfers_cnt, transfers_hash);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_transfer_unlocked(const transfer_details& td)
{
  return is_transfer_unlocked(td.m_tx.unlock_time, td.m_block_height);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_transfer_unlocked(uint64_t unlock_time, uint64_t block_height)
{
  if(!is_tx_spendtime_unlocked(unlock_time, block_height))
    return false;

  if(block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > get_blockchain_current_height())
    return false;

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_tx_spendtime_unlocked(uint64_t unlock_time, uint64_t block_height)
{
  if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
  {
    //interpret as block index
    if(get_blockchain_current_height()-1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
      return true;
    else
      return false;
  }else
  {
    //interpret as time
    uint64_t adjusted_time;
    try { adjusted_time = get_daemon_adjusted_time(); }
    catch(...) { adjusted_time = time(NULL); } // use local time if no daemon to report blockchain time
    // XXX: this needs to be fast, so we'd need to get the starting heights
    // from the daemon to be correct once voting kicks in
    uint64_t v2height = m_nettype == TESTNET ? 624634 : m_nettype == STAGENET ? 32000  : 1009827;
    uint64_t leeway = block_height < v2height ? CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1 : CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2;
    if(adjusted_time + leeway >= unlock_time)
      return true;
    else
      return false;
  }
  return false;
}
//----------------------------------------------------------------------------------------------------
namespace
{
  
}
//----------------------------------------------------------------------------------------------------
// This returns a handwavy estimation of how much two outputs are related
// If they're from the same tx, then they're fully related. From close block
// heights, they're kinda related. The actual values don't matter, just
// their ordering, but it could become more murky if we add scores later.
float wallet2::get_output_relatedness(const transfer_details &td0, const transfer_details &td1) const
{
  int dh;

  // expensive test, and same tx will fall onto the same block height below
  if (td0.m_txid == td1.m_txid)
    return 1.0f;

  // same block height -> possibly tx burst, or same tx (since above is disabled)
  dh = td0.m_block_height > td1.m_block_height ? td0.m_block_height - td1.m_block_height : td1.m_block_height - td0.m_block_height;
  if (dh == 0)
    return 0.9f;

  // adjacent blocks -> possibly tx burst
  if (dh == 1)
    return 0.8f;

  // could extract the payment id, and compare them, but this is a bit expensive too

  // similar block heights
  if (dh < 10)
    return 0.2f;

  // don't think these are particularly related
  return 0.0f;
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::pop_best_value_from(const transfer_container &transfers, std::vector<size_t> &unused_indices, const std::vector<size_t>& selected_transfers, bool smallest) const
{
  std::vector<size_t> candidates;
  float best_relatedness = 1.0f;
  for (size_t n = 0; n < unused_indices.size(); ++n)
  {
    const transfer_details &candidate = transfers[unused_indices[n]];
    float relatedness = 0.0f;
    for (std::vector<size_t>::const_iterator i = selected_transfers.begin(); i != selected_transfers.end(); ++i)
    {
      float r = get_output_relatedness(candidate, transfers[*i]);
      if (r > relatedness)
      {
        relatedness = r;
        if (relatedness == 1.0f)
          break;
      }
    }

    if (relatedness < best_relatedness)
    {
      best_relatedness = relatedness;
      candidates.clear();
    }

    if (relatedness == best_relatedness)
      candidates.push_back(n);
  }

  // we have all the least related outputs in candidates, so we can pick either
  // the smallest, or a random one, depending on request
  size_t idx;
  if (smallest)
  {
    idx = 0;
    for (size_t n = 0; n < candidates.size(); ++n)
    {
      const transfer_details &td = transfers[unused_indices[candidates[n]]];
      if (td.amount() < transfers[unused_indices[candidates[idx]]].amount())
        idx = n;
    }
  }
  else
  {
    idx = crypto::rand_idx(candidates.size());
  }
  return pop_index (unused_indices, candidates[idx]);
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::pop_best_value(std::vector<size_t> &unused_indices, const std::vector<size_t>& selected_transfers, bool smallest) const
{
  return pop_best_value_from(m_transfers, unused_indices, selected_transfers, smallest);
}

//----------------------------------------------------------------------------------------------------
void wallet2::add_unconfirmed_tx(const cryptonote::transaction& tx, uint64_t amount_in, const std::vector<cryptonote::tx_destination_entry> &dests, const crypto::hash &payment_id, uint64_t change_amount, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices)
{
  unconfirmed_transfer_details& utd = m_unconfirmed_txs[cryptonote::get_transaction_hash(tx)];
  utd.m_amount_in = amount_in;
  utd.m_amount_out = 0;
  for (const auto &d: dests)
    utd.m_amount_out += d.amount;
  utd.m_amount_out += change_amount; // dests does not contain change
  utd.m_change = change_amount;
  utd.m_sent_time = time(NULL);
  utd.m_tx = (const cryptonote::transaction_prefix&)tx;
  utd.m_dests = dests;
  utd.m_payment_id = payment_id;
  utd.m_state = wallet2::unconfirmed_transfer_details::pending;
  utd.m_timestamp = time(NULL);
  utd.m_subaddr_account = subaddr_account;
  utd.m_subaddr_indices = subaddr_indices;
  for (const auto &in: tx.vin)
  {
    if (in.type() != typeid(cryptonote::txin_to_key))
      continue;
    const auto &txin = boost::get<cryptonote::txin_to_key>(in);
    utd.m_rings.push_back(std::make_pair(txin.k_image, txin.key_offsets));
  }
}

//----------------------------------------------------------------------------------------------------
crypto::hash wallet2::get_payment_id(const pending_tx &ptx) const
{
  std::vector<tx_extra_field> tx_extra_fields;
  parse_tx_extra(ptx.tx.extra, tx_extra_fields); // ok if partially parsed
  tx_extra_nonce extra_nonce;
  crypto::hash payment_id = null_hash;
  if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
  {
    crypto::hash8 payment_id8 = null_hash8;
    if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
    {
      if (ptx.dests.empty())
      {
        MWARNING("Encrypted payment id found, but no destinations public key, cannot decrypt");
        return crypto::null_hash;
      }
      if (m_account.get_device().decrypt_payment_id(payment_id8, ptx.dests[0].addr.m_view_public_key, ptx.tx_key))
      {
        memcpy(payment_id.data, payment_id8.data, 8);
      }
    }
    else if (!get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
    {
      payment_id = crypto::null_hash;
    }
  }
  return payment_id;
}

//
//----------------------------------------------------------------------------------------------------
bool wallet2::save_tx(const std::vector<pending_tx>& ptx_vector, const std::string &filename) const
{
  LOG_PRINT_L0("saving " << ptx_vector.size() << " transactions");
  std::string ciphertext = dump_tx_to_str(ptx_vector);
  if (ciphertext.empty())
    return false;
  return save_to_file(filename, ciphertext);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::dump_tx_to_str(const std::vector<pending_tx> &ptx_vector) const
{
  LOG_PRINT_L0("saving " << ptx_vector.size() << " transactions");
  unsigned_tx_set txs;
  for (auto &tx: ptx_vector)
  {
    // Short payment id is encrypted with tx_key. 
    // Since sign_tx() generates new tx_keys and encrypts the payment id, we need to save the decrypted payment ID
    // Save tx construction_data to unsigned_tx_set
    txs.txes.push_back(get_construction_data_with_decrypted_short_payment_id(tx, m_account.get_device()));
  }
  
  txs.transfers = export_outputs();
  // save as binary
  std::ostringstream oss;
  binary_archive<true> ar(oss);
  try
  {
    if (!::serialization::serialize(ar, txs))
      return std::string();
  }
  catch (...)
  {
    return std::string();
  }
  LOG_PRINT_L2("Saving unsigned tx data: " << oss.str());
  std::string ciphertext = encrypt_with_view_secret_key(oss.str());
  return std::string(UNSIGNED_TX_PREFIX) + ciphertext;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_unsigned_tx(const std::string &unsigned_filename, unsigned_tx_set &exported_txs) const
{
  std::string s;
  boost::system::error_code errcode;

  if (!boost::filesystem::exists(unsigned_filename, errcode))
  {
    LOG_PRINT_L0("File " << unsigned_filename << " does not exist: " << errcode);
    return false;
  }
  if (!load_from_file(unsigned_filename.c_str(), s))
  {
    LOG_PRINT_L0("Failed to load from " << unsigned_filename);
    return false;
  }

  return parse_unsigned_tx_from_str(s, exported_txs);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_unsigned_tx_from_str(const std::string &unsigned_tx_st, unsigned_tx_set &exported_txs) const
{
  std::string s = unsigned_tx_st;
  const size_t magiclen = strlen(UNSIGNED_TX_PREFIX) - 1;
  if (strncmp(s.c_str(), UNSIGNED_TX_PREFIX, magiclen))
  {
    LOG_PRINT_L0("Bad magic from unsigned tx");
    return false;
  }
  s = s.substr(magiclen);
  const char version = s[0];
  s = s.substr(1);
  if (version == '\003')
  {
    if (!m_load_deprecated_formats)
    {
      LOG_PRINT_L0("Not loading deprecated format");
      return false;
    }
    try
    {
      std::istringstream iss(s);
      boost::archive::portable_binary_iarchive ar(iss);
      ar >> exported_txs;
    }
    catch (...)
    {
      LOG_PRINT_L0("Failed to parse data from unsigned tx");
      return false;
    }
  }
  else if (version == '\004')
  {
    if (!m_load_deprecated_formats)
    {
      LOG_PRINT_L0("Not loading deprecated format");
      return false;
    }
    try
    {
      s = decrypt_with_view_secret_key(s);
      try
      {
        std::istringstream iss(s);
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> exported_txs;
      }
      catch (...)
      {
        LOG_PRINT_L0("Failed to parse data from unsigned tx");
        return false;
      }
    }
    catch (const std::exception &e)
    {
      LOG_PRINT_L0("Failed to decrypt unsigned tx: " << e.what());
      return false;
    }
  }
  else if (version == '\005')
  {
    try { s = decrypt_with_view_secret_key(s); }
    catch(const std::exception &e) { LOG_PRINT_L0("Failed to decrypt unsigned tx: " << e.what()); return false; }
    try
    {
      std::istringstream iss(s);
      binary_archive<false> ar(iss);
      if (!::serialization::serialize(ar, exported_txs))
      {
        LOG_PRINT_L0("Failed to parse data from unsigned tx");
        return false;
      }
    }
    catch (...)
    {
      LOG_PRINT_L0("Failed to parse data from unsigned tx");
      return false;
    }
  }
  else
  {
    LOG_PRINT_L0("Unsupported version in unsigned tx");
    return false;
  }
  LOG_PRINT_L1("Loaded tx unsigned data from binary: " << exported_txs.txes.size() << " transactions");

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::sign_tx(const std::string &unsigned_filename, const std::string &signed_filename, std::vector<wallet2::pending_tx> &txs, std::function<bool(const unsigned_tx_set&)> accept_func, bool export_raw)
{
  unsigned_tx_set exported_txs;
  if(!load_unsigned_tx(unsigned_filename, exported_txs))
    return false;
  
  if (accept_func && !accept_func(exported_txs))
  {
    LOG_PRINT_L1("Transactions rejected by callback");
    return false;
  }
  return sign_tx(exported_txs, signed_filename, txs, export_raw);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::sign_tx(unsigned_tx_set &exported_txs, std::vector<wallet2::pending_tx> &txs, signed_tx_set &signed_txes)
{
  import_outputs(exported_txs.transfers);

  // sign the transactions
  for (size_t n = 0; n < exported_txs.txes.size(); ++n)
  {
    tools::wallet2::tx_construction_data &sd = exported_txs.txes[n];
    THROW_WALLET_EXCEPTION_IF(sd.sources.empty(), error::wallet_internal_error, "Empty sources");
    LOG_PRINT_L1(" " << (n+1) << ": " << sd.sources.size() << " inputs, ring size " << sd.sources[0].outputs.size());
    signed_txes.ptx.push_back(pending_tx());
    tools::wallet2::pending_tx &ptx = signed_txes.ptx.back();
    rct::RCTConfig rct_config = sd.rct_config;
    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    bool r = cryptonote::construct_tx_and_get_tx_key(m_account.get_keys(), m_subaddresses, sd.sources, sd.splitted_dsts, sd.change_dts.addr, sd.extra, ptx.tx, sd.unlock_time, tx_key, additional_tx_keys, sd.use_rct, rct_config,  NULL);
    THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sd.sources, sd.splitted_dsts, sd.unlock_time, m_nettype);
    // we don't test tx size, because we don't know the current limit, due to not having a blockchain,
    // and it's a bit pointless to fail there anyway, since it'd be a (good) guess only. We sign anyway,
    // and if we really go over limit, the daemon will reject when it gets submitted. Chances are it's
    // OK anyway since it was generated in the first place, and rerolling should be within a few bytes.

    // normally, the tx keys are saved in commit_tx, when the tx is actually sent to the daemon.
    // we can't do that here since the tx will be sent from the compromised wallet, which we don't want
    // to see that info, so we save it here
    if (store_tx_info() && tx_key != crypto::null_skey)
    {
      const crypto::hash txid = get_transaction_hash(ptx.tx);
      m_tx_keys[txid] = tx_key;
      m_additional_tx_keys[txid] = additional_tx_keys;
    }

    std::string key_images;
    bool all_are_txin_to_key = std::all_of(ptx.tx.vin.begin(), ptx.tx.vin.end(), [&](const txin_v& s_e) -> bool
    {
      CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
      key_images += boost::to_string(in.k_image) + " ";
      return true;
    });
    THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, ptx.tx);

    ptx.key_images = key_images;
    ptx.fee = 0;
    for (const auto &i: sd.sources) ptx.fee += i.amount;
    for (const auto &i: sd.splitted_dsts) ptx.fee -= i.amount;
    ptx.dust = 0;
    ptx.dust_added_to_fee = false;
    ptx.change_dts = sd.change_dts;
    ptx.selected_transfers = sd.selected_transfers;
    ptx.tx_key = rct::rct2sk(rct::identity()); // don't send it back to the untrusted view wallet
    ptx.dests = sd.dests;
    ptx.construction_data = sd;

    txs.push_back(ptx);

    // add tx keys only to ptx
    txs.back().tx_key = tx_key;
    txs.back().additional_tx_keys = additional_tx_keys;
  }

  // add key image mapping for these txes
  const account_keys &keys = get_account().get_keys();
  hw::device &hwdev = m_account.get_device();
  for (size_t n = 0; n < exported_txs.txes.size(); ++n)
  {
    const cryptonote::transaction &tx = signed_txes.ptx[n].tx;

    crypto::key_derivation derivation;
    std::vector<crypto::key_derivation> additional_derivations;

    // compute public keys from out secret keys
    crypto::public_key tx_pub_key;
    crypto::secret_key_to_public_key(txs[n].tx_key, tx_pub_key);
    std::vector<crypto::public_key> additional_tx_pub_keys;
    for (const crypto::secret_key &skey: txs[n].additional_tx_keys)
    {
      additional_tx_pub_keys.resize(additional_tx_pub_keys.size() + 1);
      crypto::secret_key_to_public_key(skey, additional_tx_pub_keys.back());
    }

    // compute derivations
    hwdev.set_mode(hw::device::TRANSACTION_PARSE);
    if (!hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation))
    {
      MWARNING("Failed to generate key derivation from tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping");
      static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
      memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
    }
    for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
    {
      additional_derivations.push_back({});
      if (!hwdev.generate_key_derivation(additional_tx_pub_keys[i], keys.m_view_secret_key, additional_derivations.back()))
      {
        MWARNING("Failed to generate key derivation from additional tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping");
        memcpy(&additional_derivations.back(), rct::identity().bytes, sizeof(crypto::key_derivation));
      }
    }

    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
      if (tx.vout[i].target.type() != typeid(cryptonote::txout_to_key))
        continue;
      const cryptonote::txout_to_key &out = boost::get<cryptonote::txout_to_key>(tx.vout[i].target);
      // if this output is back to this wallet, we can calculate its key image already
      if (!is_out_to_acc_precomp(m_subaddresses, out.key, derivation, additional_derivations, i, hwdev))
        continue;
      crypto::key_image ki;
      cryptonote::keypair in_ephemeral;
      if (generate_key_image_helper(keys, m_subaddresses, out.key, tx_pub_key, additional_tx_pub_keys, i, in_ephemeral, ki, hwdev))
        signed_txes.tx_key_images[out.key] = ki;
      else
        MERROR("Failed to calculate key image");
    }
  }

  // add key images
  signed_txes.key_images.resize(m_transfers.size());
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    if (!m_transfers[i].m_key_image_known || m_transfers[i].m_key_image_partial)
      LOG_PRINT_L0("WARNING: key image not known in signing wallet at index " << i);
    signed_txes.key_images[i] = m_transfers[i].m_key_image;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::sign_tx(unsigned_tx_set &exported_txs, const std::string &signed_filename, std::vector<wallet2::pending_tx> &txs, bool export_raw)
{
  // sign the transactions
  signed_tx_set signed_txes;
  std::string ciphertext = sign_tx_dump_to_str(exported_txs, txs, signed_txes);
  if (ciphertext.empty())
  {
    LOG_PRINT_L0("Failed to sign unsigned_tx_set");
    return false;
  }

  if (!save_to_file(signed_filename, ciphertext))
  {
    LOG_PRINT_L0("Failed to save file to " << signed_filename);
    return false;
  }
  // export signed raw tx without encryption
  if (export_raw)
  {
    for (size_t i = 0; i < signed_txes.ptx.size(); ++i)
    {
      std::string tx_as_hex = epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(signed_txes.ptx[i].tx));
      std::string raw_filename = signed_filename + "_raw" + (signed_txes.ptx.size() == 1 ? "" : ("_" + std::to_string(i)));
      if (!save_to_file(raw_filename, tx_as_hex))
      {
        LOG_PRINT_L0("Failed to save file to " << raw_filename);
        return false;
      }
    }
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::sign_tx_dump_to_str(unsigned_tx_set &exported_txs, std::vector<wallet2::pending_tx> &ptx, signed_tx_set &signed_txes)
{
  // sign the transactions
  bool r = sign_tx(exported_txs, ptx, signed_txes);
  if (!r)
  {
    LOG_PRINT_L0("Failed to sign unsigned_tx_set");
    return std::string();
  }

  // save as binary
  std::ostringstream oss;
  binary_archive<true> ar(oss);
  try
  {
    if (!::serialization::serialize(ar, signed_txes))
      return std::string();
  }
  catch(...)
  {
    return std::string();
  }
  LOG_PRINT_L3("Saving signed tx data (with encryption): " << oss.str());
  std::string ciphertext = encrypt_with_view_secret_key(oss.str());
  return std::string(SIGNED_TX_PREFIX) + ciphertext;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_tx(const std::string &signed_filename, std::vector<tools::wallet2::pending_tx> &ptx, std::function<bool(const signed_tx_set&)> accept_func)
{
  std::string s;
  boost::system::error_code errcode;
  signed_tx_set signed_txs;

  if (!boost::filesystem::exists(signed_filename, errcode))
  {
    LOG_PRINT_L0("File " << signed_filename << " does not exist: " << errcode);
    return false;
  }

  if (!load_from_file(signed_filename.c_str(), s))
  {
    LOG_PRINT_L0("Failed to load from " << signed_filename);
    return false;
  }

  return parse_tx_from_str(s, ptx, accept_func);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_tx_from_str(const std::string &signed_tx_st, std::vector<tools::wallet2::pending_tx> &ptx, std::function<bool(const signed_tx_set &)> accept_func)
{
  std::string s = signed_tx_st;
  boost::system::error_code errcode;
  signed_tx_set signed_txs;

  const size_t magiclen = strlen(SIGNED_TX_PREFIX) - 1;
  if (strncmp(s.c_str(), SIGNED_TX_PREFIX, magiclen))
  {
    LOG_PRINT_L0("Bad magic from signed transaction");
    return false;
  }
  s = s.substr(magiclen);
  const char version = s[0];
  s = s.substr(1);
  if (version == '\003')
  {
    if (!m_load_deprecated_formats)
    {
      LOG_PRINT_L0("Not loading deprecated format");
      return false;
    }
    try
    {
      std::istringstream iss(s);
      boost::archive::portable_binary_iarchive ar(iss);
      ar >> signed_txs;
    }
    catch (...)
    {
      LOG_PRINT_L0("Failed to parse data from signed transaction");
      return false;
    }
  }
  else if (version == '\004')
  {
    if (!m_load_deprecated_formats)
    {
      LOG_PRINT_L0("Not loading deprecated format");
      return false;
    }
    try
    {
      s = decrypt_with_view_secret_key(s);
      try
      {
        std::istringstream iss(s);
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> signed_txs;
      }
      catch (...)
      {
        LOG_PRINT_L0("Failed to parse decrypted data from signed transaction");
        return false;
      }
    }
    catch (const std::exception &e)
    {
      LOG_PRINT_L0("Failed to decrypt signed transaction: " << e.what());
      return false;
    }
  }
  else if (version == '\005')
  {
    try { s = decrypt_with_view_secret_key(s); }
    catch (const std::exception &e) { LOG_PRINT_L0("Failed to decrypt signed transaction: " << e.what()); return false; }
    try
    {
      std::istringstream iss(s);
      binary_archive<false> ar(iss);
      if (!::serialization::serialize(ar, signed_txs))
      {
        LOG_PRINT_L0("Failed to deserialize signed transaction");
        return false;
      }
    }
    catch (const std::exception &e)
    {
      LOG_PRINT_L0("Failed to decrypt signed transaction: " << e.what());
      return false;
    }
  }
  else
  {
    LOG_PRINT_L0("Unsupported version in signed transaction");
    return false;
  }
  LOG_PRINT_L0("Loaded signed tx data from binary: " << signed_txs.ptx.size() << " transactions");
  for (auto &c_ptx: signed_txs.ptx) LOG_PRINT_L0(cryptonote::obj_to_json_str(c_ptx.tx));

  if (accept_func && !accept_func(signed_txs))
  {
    LOG_PRINT_L1("Transactions rejected by callback");
    return false;
  }

  // import key images
  bool r = import_key_images(signed_txs.key_images);
  if (!r) return false;

  // remember key images for this tx, for when we get those txes from the blockchain
  for (const auto &e: signed_txs.tx_key_images)
    m_cold_key_images.insert(e);

  ptx = signed_txs.ptx;

  return true;
}
//------------------------------------------------------------------------------------------------------------------------------
uint64_t wallet2::get_min_ring_size()
{
  if (use_fork_rules(8, 10))
    return 11;
  if (use_fork_rules(7, 10))
    return 7;
  if (use_fork_rules(6, 10))
    return 5;
  if (use_fork_rules(2, 10))
    return 3;
  return 0;
}
//------------------------------------------------------------------------------------------------------------------------------
uint64_t wallet2::get_max_ring_size()
{
  if (use_fork_rules(8, 10))
    return 11;
  return 0;
}
//------------------------------------------------------------------------------------------------------------------------------
uint64_t wallet2::adjust_mixin(uint64_t mixin)
{
  const uint64_t min_ring_size = get_min_ring_size();
  if (mixin + 1 < min_ring_size)
  {
    MWARNING("Requested ring size " << (mixin + 1) << " too low, using " << min_ring_size);
    mixin = min_ring_size-1;
  }
  const uint64_t max_ring_size = get_max_ring_size();
  if (max_ring_size && mixin + 1 > max_ring_size)
  {
    MWARNING("Requested ring size " << (mixin + 1) << " too high, using " << max_ring_size);
    mixin = max_ring_size-1;
  }
  return mixin;
}
//----------------------------------------------------------------------------------------------------
uint32_t wallet2::adjust_priority(uint32_t priority)
{
  if (priority == 0 && m_default_priority == 0 && auto_low_priority())
  {
    try
    {
      // check if there's a backlog in the tx pool
      const bool use_per_byte_fee = use_fork_rules(HF_VERSION_PER_BYTE_FEE, 0);
      const uint64_t base_fee = get_base_fee();
      const uint64_t fee_multiplier = get_fee_multiplier(1);
      const double fee_level = fee_multiplier * base_fee * (use_per_byte_fee ? 1 : (12/(double)13 / (double)1024));
      const std::vector<std::pair<uint64_t, uint64_t>> blocks = estimate_backlog({std::make_pair(fee_level, fee_level)});
      if (blocks.size() != 1)
      {
        MERROR("Bad estimated backlog array size");
        return priority;
      }
      else if (blocks[0].first > 0)
      {
        MINFO("We don't use the low priority because there's a backlog in the tx pool.");
        return priority;
      }

      // get the current full reward zone
      uint64_t block_weight_limit = 0;
      const auto result = m_node_rpc_proxy.get_block_weight_limit(block_weight_limit);
      if (result)
        return priority;
      const uint64_t full_reward_zone = block_weight_limit / 2;

      // get the last N block headers and sum the block sizes
      const size_t N = 10;
      if (m_blockchain.size() < N)
      {
        MERROR("The blockchain is too short");
        return priority;
      }
      cryptonote::COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request getbh_req = AUTO_VAL_INIT(getbh_req);
      cryptonote::COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response getbh_res = AUTO_VAL_INIT(getbh_res);
      getbh_req.start_height = m_blockchain.size() - N;
      getbh_req.end_height = m_blockchain.size() - 1;

      {
        const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
        uint64_t pre_call_credits = m_rpc_payment_state.credits;
        getbh_req.client = get_client_signature();
        bool r = net_utils::invoke_http_json_rpc("/json_rpc", "getblockheadersrange", getbh_req, getbh_res, *m_http_client, rpc_timeout);
        THROW_ON_RPC_RESPONSE_ERROR(r, {}, getbh_res, "getblockheadersrange", error::get_blocks_error, get_rpc_status(getbh_res.status));
        check_rpc_cost("/getblockheadersrange", getbh_res.credits, pre_call_credits, N * COST_PER_BLOCK_HEADER);
      }

      if (getbh_res.headers.size() != N)
      {
        MERROR("Bad blockheaders size");
        return priority;
      }
      size_t block_weight_sum = 0;
      for (const cryptonote::block_header_response &i : getbh_res.headers)
      {
        block_weight_sum += i.block_weight;
      }

      // estimate how 'full' the last N blocks are
      const size_t P = 100 * block_weight_sum / (N * full_reward_zone);
      MINFO((boost::format("The last %d blocks fill roughly %d%% of the full reward zone.") % N % P).str());
      if (P > 80)
      {
        MINFO("We don't use the low priority because recent blocks are quite full.");
        return priority;
      }
      MINFO("We'll use the low priority because probably it's safe to do so.");
      return 1;
    }
    catch (const std::exception &e)
    {
      MERROR(e.what());
    }
  }
  return priority;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::set_ring_database(const std::string &filename)
{
  m_ring_database = filename;
  MINFO("ringdb path set to " << filename);
  m_ringdb.reset();
  if (!m_ring_database.empty())
  {
    try
    {
      cryptonote::block b;
      generate_genesis(b);
      m_ringdb.reset(new tools::ringdb(m_ring_database, epee::string_tools::pod_to_hex(get_block_hash(b))));
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to initialize ringdb: " << e.what());
      m_ring_database = "";
      return false;
    }
  }
  return true;
}

crypto::chacha_key wallet2::get_ringdb_key()
{
  if (!m_ringdb_key)
  {
    MINFO("caching ringdb key");
    crypto::chacha_key key;
    generate_chacha_key_from_secret_keys(key);
    m_ringdb_key = key;
  }
  return *m_ringdb_key;
}

void wallet2::register_devices(){
//  hw::trezor::register_all();
}

hw::device& wallet2::lookup_device(const std::string & device_descriptor){
  if (!m_devices_registered){
    m_devices_registered = true;
    register_devices();
  }

  return hw::get_device(device_descriptor);
}

bool wallet2::add_rings(const crypto::chacha_key &key, const cryptonote::transaction_prefix &tx)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->add_rings(key, tx); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::add_rings(const cryptonote::transaction_prefix &tx)
{
  try { return add_rings(get_ringdb_key(), tx); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::remove_rings(const cryptonote::transaction_prefix &tx)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->remove_rings(get_ringdb_key(), tx); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::get_ring(const crypto::chacha_key &key, const crypto::key_image &key_image, std::vector<uint64_t> &outs)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->get_ring(key, key_image, outs); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::get_rings(const crypto::hash &txid, std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> &outs)
{
  for (auto i: m_confirmed_txs)
  {
    if (txid == i.first)
    {
      for (const auto &x: i.second.m_rings)
        outs.push_back({x.first, cryptonote::relative_output_offsets_to_absolute(x.second)});
      return true;
    }
  }
  for (auto i: m_unconfirmed_txs)
  {
    if (txid == i.first)
    {
      for (const auto &x: i.second.m_rings)
        outs.push_back({x.first, cryptonote::relative_output_offsets_to_absolute(x.second)});
      return true;
    }
  }
  return false;
}

bool wallet2::get_ring(const crypto::key_image &key_image, std::vector<uint64_t> &outs)
{
  try { return get_ring(get_ringdb_key(), key_image, outs); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::set_ring(const crypto::key_image &key_image, const std::vector<uint64_t> &outs, bool relative)
{
  if (!m_ringdb)
    return false;

  try { return m_ringdb->set_ring(get_ringdb_key(), key_image, outs, relative); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::unset_ring(const std::vector<crypto::key_image> &key_images)
{
  if (!m_ringdb)
    return false;

  try { return m_ringdb->remove_rings(get_ringdb_key(), key_images); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::unset_ring(const crypto::hash &txid)
{
  if (!m_ringdb)
    return false;

  COMMAND_RPC_GET_TRANSACTIONS::request req;
  COMMAND_RPC_GET_TRANSACTIONS::response res;
  req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
  req.decode_as_json = false;
  req.prune = true;
  m_daemon_rpc_mutex.lock();
  bool ok = invoke_http_json("/gettransactions", req, res, rpc_timeout);
  m_daemon_rpc_mutex.unlock();
  THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to get transaction from daemon");
  THROW_WALLET_EXCEPTION_IF(res.txs.size() != 1, error::wallet_internal_error, "Failed to get transaction from daemon");

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  if (!get_pruned_tx(res.txs.front(), tx, tx_hash))
    return false;
  THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

  try { return m_ringdb->remove_rings(get_ringdb_key(), tx); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::find_and_save_rings(bool force)
{
  if (!force && m_ring_history_saved)
    return true;
  if (!m_ringdb)
    return false;

  COMMAND_RPC_GET_TRANSACTIONS::request req = AUTO_VAL_INIT(req);
  COMMAND_RPC_GET_TRANSACTIONS::response res = AUTO_VAL_INIT(res);

  MDEBUG("Finding and saving rings...");

  // get payments we made
  std::vector<crypto::hash> txs_hashes;
  std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_details>> payments;
  get_payments_out(payments, 0, std::numeric_limits<uint64_t>::max(), boost::none, std::set<uint32_t>());
  for (const std::pair<crypto::hash,wallet2::confirmed_transfer_details> &entry: payments)
  {
    const crypto::hash &txid = entry.first;
    txs_hashes.push_back(txid);
  }

  MDEBUG("Found " << std::to_string(txs_hashes.size()) << " transactions");

  // get those transactions from the daemon
  auto it = txs_hashes.begin();
  static const size_t SLICE_SIZE = 200;
  for (size_t slice = 0; slice < txs_hashes.size(); slice += SLICE_SIZE)
  {
    req.decode_as_json = false;
    req.prune = true;
    req.txs_hashes.clear();
    size_t ntxes = slice + SLICE_SIZE > txs_hashes.size() ? txs_hashes.size() - slice : SLICE_SIZE;
    for (size_t s = slice; s < slice + ntxes; ++s)
      req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txs_hashes[s]));

    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      uint64_t pre_call_credits = m_rpc_payment_state.credits;
      req.client = get_client_signature();
      bool r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "/gettransactions");
      THROW_WALLET_EXCEPTION_IF(res.txs.size() != req.txs_hashes.size(), error::wallet_internal_error,
        "daemon returned wrong response for gettransactions, wrong txs count = " +
        std::to_string(res.txs.size()) + ", expected " + std::to_string(req.txs_hashes.size()));
      check_rpc_cost("/gettransactions", res.credits, pre_call_credits, res.txs.size() * COST_PER_TX);
    }

    MDEBUG("Scanning " << res.txs.size() << " transactions");
    THROW_WALLET_EXCEPTION_IF(slice + res.txs.size() > txs_hashes.size(), error::wallet_internal_error, "Unexpected tx array size");
    for (size_t i = 0; i < res.txs.size(); ++i, ++it)
    {
    const auto &tx_info = res.txs[i];
      cryptonote::transaction tx;
      crypto::hash tx_hash;
      THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(tx_info, tx, tx_hash), error::wallet_internal_error,
          "Failed to get transaction from daemon");
      THROW_WALLET_EXCEPTION_IF(!(tx_hash == *it), error::wallet_internal_error, "Wrong txid received");
      THROW_WALLET_EXCEPTION_IF(!add_rings(get_ringdb_key(), tx), error::wallet_internal_error, "Failed to save ring");
    }
  }

  MINFO("Found and saved rings for " << txs_hashes.size() << " transactions");
  m_ring_history_saved = true;
  return true;
}

bool wallet2::blackball_output(const std::pair<uint64_t, uint64_t> &output)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->blackball(output); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::set_blackballed_outputs(const std::vector<std::pair<uint64_t, uint64_t>> &outputs, bool add)
{
  if (!m_ringdb)
    return false;
  try
  {
    bool ret = true;
    if (!add)
      ret &= m_ringdb->clear_blackballs();
    ret &= m_ringdb->blackball(outputs);
    return ret;
  }
  catch (const std::exception &e) { return false; }
}

bool wallet2::unblackball_output(const std::pair<uint64_t, uint64_t> &output)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->unblackball(output); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::is_output_blackballed(const std::pair<uint64_t, uint64_t> &output) const
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->blackballed(output); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::lock_keys_file()
{
  if (m_wallet_file.empty())
    return true;
  if (m_keys_file_locker)
  {
    MDEBUG(m_keys_file << " is already locked.");
    return false;
  }
  m_keys_file_locker.reset(new tools::file_locker(m_keys_file));
  return true;
}

bool wallet2::unlock_keys_file()
{
  if (m_wallet_file.empty())
    return true;
  if (!m_keys_file_locker)
  {
    MDEBUG(m_keys_file << " is already unlocked.");
    return false;
  }
  m_keys_file_locker.reset();
  return true;
}

bool wallet2::is_keys_file_locked() const
{
  if (m_wallet_file.empty())
    return false;
  return m_keys_file_locker->locked();
}

bool wallet2::tx_add_fake_output(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, uint64_t global_index, const crypto::public_key& output_public_key, const rct::key& mask, uint64_t real_index, bool unlocked) const
{
  if (!unlocked) // don't add locked outs
    return false;
  if (global_index == real_index) // don't re-add real one
    return false;
  auto item = std::make_tuple(global_index, output_public_key, mask);
  CHECK_AND_ASSERT_MES(!outs.empty(), false, "internal error: outs is empty");
  if (std::find(outs.back().begin(), outs.back().end(), item) != outs.back().end()) // don't add duplicates
    return false;
  // check the keys are valid
  if (!rct::isInMainSubgroup(rct::pk2rct(output_public_key)))
  {
    MWARNING("Key " << output_public_key << " at index " << global_index << " is not in the main subgroup");
    return false;
  }
  if (!rct::isInMainSubgroup(mask))
  {
    MWARNING("Commitment " << mask << " at index " << global_index << " is not in the main subgroup");
    return false;
  }
//  if (is_output_blackballed(output_public_key)) // don't add blackballed outputs
//    return false;
  outs.back().push_back(item);
  return true;
}



std::vector<size_t> wallet2::pick_preferred_rct_inputs(uint64_t needed_money, uint32_t subaddr_account, const std::set<uint32_t> &subaddr_indices)
{
  std::vector<size_t> picks;
  float current_output_relatdness = 1.0f;

  LOG_PRINT_L2("pick_preferred_rct_inputs: needed_money " << print_money(needed_money));

  // try to find a rct input of enough size
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (!is_spent(td, false) && !td.m_frozen && td.is_rct() && td.amount() >= needed_money && is_transfer_unlocked(td) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
    {
      if (td.amount() > m_ignore_outputs_above || td.amount() < m_ignore_outputs_below)
      {
        MDEBUG("Ignoring output " << i << " of amount " << print_money(td.amount()) << " which is outside prescribed range [" << print_money(m_ignore_outputs_below) << ", " << print_money(m_ignore_outputs_above) << "]");
        continue;
      }
      LOG_PRINT_L2("We can use " << i << " alone: " << print_money(td.amount()));
      picks.push_back(i);
      return picks;
    }
  }

  // then try to find two outputs
  // this could be made better by picking one of the outputs to be a small one, since those
  // are less useful since often below the needed money, so if one can be used in a pair,
  // it gets rid of it for the future
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (!is_spent(td, false) && !td.m_frozen && !td.m_key_image_partial && td.is_rct() && is_transfer_unlocked(td) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
    {
      if (td.amount() > m_ignore_outputs_above || td.amount() < m_ignore_outputs_below)
      {
        MDEBUG("Ignoring output " << i << " of amount " << print_money(td.amount()) << " which is outside prescribed range [" << print_money(m_ignore_outputs_below) << ", " << print_money(m_ignore_outputs_above) << "]");
        continue;
      }
      LOG_PRINT_L2("Considering input " << i << ", " << print_money(td.amount()));
      for (size_t j = i + 1; j < m_transfers.size(); ++j)
      {
        const transfer_details& td2 = m_transfers[j];
        if (td2.amount() > m_ignore_outputs_above || td2.amount() < m_ignore_outputs_below)
        {
          MDEBUG("Ignoring output " << j << " of amount " << print_money(td2.amount()) << " which is outside prescribed range [" << print_money(m_ignore_outputs_below) << ", " << print_money(m_ignore_outputs_above) << "]");
          continue;
        }
        if (!is_spent(td2, false) && !td2.m_frozen && !td2.m_key_image_partial && td2.is_rct() && td.amount() + td2.amount() >= needed_money && is_transfer_unlocked(td2) && td2.m_subaddr_index == td.m_subaddr_index)
        {
          // update our picks if those outputs are less related than any we
          // already found. If the same, don't update, and oldest suitable outputs
          // will be used in preference.
          float relatedness = get_output_relatedness(td, td2);
          LOG_PRINT_L2("  with input " << j << ", " << print_money(td2.amount()) << ", relatedness " << relatedness);
          if (relatedness < current_output_relatdness)
          {
            // reset the current picks with those, and return them directly
            // if they're unrelated. If they are related, we'll end up returning
            // them if we find nothing better
            picks.clear();
            picks.push_back(i);
            picks.push_back(j);
            LOG_PRINT_L0("we could use " << i << " and " << j);
            if (relatedness == 0.0f)
              return picks;
            current_output_relatdness = relatedness;
          }
        }
      }
    }
  }

  return picks;
}

bool wallet2::should_pick_a_second_output(bool use_rct, size_t n_transfers, const std::vector<size_t> &unused_transfers_indices, const std::vector<size_t> &unused_dust_indices) const
{
  if (!use_rct)
    return false;
  if (n_transfers > 1)
    return false;
  if (unused_dust_indices.empty() && unused_transfers_indices.empty())
    return false;
  // we want at least one free rct output to avoid a corner case where
  // we'd choose a non rct output which doesn't have enough "siblings"
  // value-wise on the chain, and thus can't be mixed
  bool found = false;
  for (auto i: unused_dust_indices)
  {
    if (m_transfers[i].is_rct())
    {
      found = true;
      break;
    }
  }
  if (!found) for (auto i: unused_transfers_indices)
  {
    if (m_transfers[i].is_rct())
    {
      found = true;
      break;
    }
  }
  if (!found)
    return false;
  return true;
}

std::vector<size_t> wallet2::get_only_rct(const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices) const
{
  std::vector<size_t> indices;
  for (size_t n: unused_dust_indices)
    if (m_transfers[n].is_rct())
      indices.push_back(n);
  for (size_t n: unused_transfers_indices)
    if (m_transfers[n].is_rct())
      indices.push_back(n);
  return indices;
}



//----------------------------------------------------------------------------------------------------
void wallet2::cold_tx_aux_import(const std::vector<pending_tx> & ptx, const std::vector<std::string> & tx_device_aux)
{
  CHECK_AND_ASSERT_THROW_MES(ptx.size() == tx_device_aux.size(), "TX aux has invalid size");
  for (size_t i = 0; i < ptx.size(); ++i){
    crypto::hash txid;
    txid = get_transaction_hash(ptx[i].tx);
    set_tx_device_aux(txid, tx_device_aux[i]);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::cold_sign_tx(const std::vector<pending_tx>& ptx_vector, signed_tx_set &exported_txs, std::vector<cryptonote::address_parse_info> &dsts_info, std::vector<std::string> & tx_device_aux)
{
  auto & hwdev = get_account().get_device();
  if (!hwdev.has_tx_cold_sign()){
    throw std::invalid_argument("Device does not support cold sign protocol");
  }

  unsigned_tx_set txs;
  for (auto &tx: ptx_vector)
  {
    txs.txes.push_back(get_construction_data_with_decrypted_short_payment_id(tx, m_account.get_device()));
  }
  txs.transfers = std::make_pair(0, m_transfers);

  auto dev_cold = dynamic_cast<::hw::device_cold*>(&hwdev);
  CHECK_AND_ASSERT_THROW_MES(dev_cold, "Device does not implement cold signing interface");

  hw::tx_aux_data aux_data;
  hw::wallet_shim wallet_shim;
  setup_shim(&wallet_shim, this);
  aux_data.tx_recipients = dsts_info;
  aux_data.bp_version = (use_fork_rules(HF_VERSION_CLSAG, -10) ? 3 : use_fork_rules(HF_VERSION_SMALLER_BP, -10) ? 2 : 1);
  aux_data.hard_fork = get_current_hard_fork();
  dev_cold->tx_sign(&wallet_shim, txs, exported_txs, aux_data);
  tx_device_aux = aux_data.tx_device_aux;

  MDEBUG("Signed tx data from hw: " << exported_txs.ptx.size() << " transactions");
  for (auto &c_ptx: exported_txs.ptx) LOG_PRINT_L0(cryptonote::obj_to_json_str(c_ptx.tx));
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::cold_key_image_sync(uint64_t &spent, uint64_t &unspent) {
  auto & hwdev = get_account().get_device();
  CHECK_AND_ASSERT_THROW_MES(hwdev.has_ki_cold_sync(), "Device does not support cold ki sync protocol");

  auto dev_cold = dynamic_cast<::hw::device_cold*>(&hwdev);
  CHECK_AND_ASSERT_THROW_MES(dev_cold, "Device does not implement cold signing interface");

  std::vector<std::pair<crypto::key_image, crypto::signature>> ski;
  hw::wallet_shim wallet_shim;
  setup_shim(&wallet_shim, this);

  dev_cold->ki_sync(&wallet_shim, m_transfers, ski);

  // Call COMMAND_RPC_IS_KEY_IMAGE_SPENT only if daemon is trusted.
  uint64_t import_res = import_key_images(ski, 0, spent, unspent, is_trusted_daemon());
  m_device_last_key_image_sync = time(NULL);

  return import_res;
}
//----------------------------------------------------------------------------------------------------
void wallet2::device_show_address(uint32_t account_index, uint32_t address_index, const boost::optional<crypto::hash8> &payment_id)
{
  if (!key_on_device())
  {
    return;
  }

  auto & hwdev = get_account().get_device();
  hwdev.display_address(subaddress_index{account_index, address_index}, payment_id);
}
//----------------------------------------------------------------------------------------------------
uint8_t wallet2::get_current_hard_fork()
{
  if (m_offline)
    return 0;

  cryptonote::COMMAND_RPC_HARD_FORK_INFO::request req_t = AUTO_VAL_INIT(req_t);
  cryptonote::COMMAND_RPC_HARD_FORK_INFO::response resp_t = AUTO_VAL_INIT(resp_t);

  m_daemon_rpc_mutex.lock();
  req_t.version = 0;
  bool r = net_utils::invoke_http_json_rpc("/json_rpc", "hard_fork_info", req_t, resp_t, *m_http_client, rpc_timeout);
  m_daemon_rpc_mutex.unlock();
  THROW_WALLET_EXCEPTION_IF(!r, tools::error::no_connection_to_daemon, "hard_fork_info");
  THROW_WALLET_EXCEPTION_IF(resp_t.status == CORE_RPC_STATUS_BUSY, tools::error::daemon_busy, "hard_fork_info");
  THROW_WALLET_EXCEPTION_IF(resp_t.status != CORE_RPC_STATUS_OK, tools::error::wallet_generic_rpc_error, "hard_fork_info", m_trusted_daemon ? resp_t.status : "daemon error");
  return resp_t.version;
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_hard_fork_info(uint8_t version, uint64_t &earliest_height)
{
  boost::optional<std::string> result = m_node_rpc_proxy.get_earliest_height(version, earliest_height);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::use_fork_rules(uint8_t version, int64_t early_blocks)
{
  uint64_t height, earliest_height;
  boost::optional<std::string> result = m_node_rpc_proxy.get_height(height);
  THROW_WALLET_EXCEPTION_IF(result, error::wallet_internal_error, "Failed to get height");
  result = m_node_rpc_proxy.get_earliest_height(version, earliest_height);
  THROW_WALLET_EXCEPTION_IF(result, error::wallet_internal_error, "Failed to get earliest fork height");

  bool close_enough = (int64_t)height >= (int64_t)earliest_height - early_blocks && earliest_height != std::numeric_limits<uint64_t>::max(); // start using the rules that many blocks beforehand
  if (close_enough)
    LOG_PRINT_L2("Using v" << (unsigned)version << " rules");
  else
    LOG_PRINT_L2("Not using v" << (unsigned)version << " rules");
  return close_enough;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_upper_transaction_weight_limit()
{
  if (m_upper_transaction_weight_limit > 0)
    return m_upper_transaction_weight_limit;
  uint64_t full_reward_zone = use_fork_rules(5, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 : use_fork_rules(2, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
  if (use_fork_rules(8, 10))
    return full_reward_zone / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
  else
    return full_reward_zone - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_outputs(const std::function<bool(const transfer_details &td)> &f)
{
  std::vector<size_t> outputs;
  size_t n = 0;
  for (transfer_container::const_iterator i = m_transfers.begin(); i != m_transfers.end(); ++i, ++n)
  {
    if (is_spent(*i, false))
      continue;
    if (i->m_frozen)
      continue;
    if (i->m_key_image_partial)
      continue;
    if (!is_transfer_unlocked(*i))
      continue;
    if (f(*i))
      outputs.push_back(n);
  }
  return outputs;
}
//----------------------------------------------------------------------------------------------------
std::vector<uint64_t> wallet2::get_unspent_amounts_vector(bool strict)
{
  std::set<uint64_t> set;
  for (const auto &td: m_transfers)
  {
    if (!is_spent(td, strict) && !td.m_frozen)
      set.insert(td.is_rct() ? 0 : td.amount());
  }
  std::vector<uint64_t> vector;
  vector.reserve(set.size());
  for (const auto &i: set)
  {
    vector.push_back(i);
  }
  return vector;
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_outputs_from_histogram(uint64_t count, bool atleast, bool unlocked, bool allow_rct)
{
  cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request req_t = AUTO_VAL_INIT(req_t);
  cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response resp_t = AUTO_VAL_INIT(resp_t);
  if (is_trusted_daemon())
    req_t.amounts = get_unspent_amounts_vector(false);
  req_t.min_count = count;
  req_t.max_count = 0;
  req_t.unlocked = unlocked;
  req_t.recent_cutoff = 0;

  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    uint64_t pre_call_credits = m_rpc_payment_state.credits;
    req_t.client = get_client_signature();
    bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_output_histogram", req_t, resp_t, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, resp_t, "get_output_histogram", error::get_histogram_error, resp_t.status);
    uint64_t cost = req_t.amounts.empty() ? COST_PER_FULL_OUTPUT_HISTOGRAM : (COST_PER_OUTPUT_HISTOGRAM * req_t.amounts.size());
    check_rpc_cost("get_output_histogram", resp_t.credits, pre_call_credits, cost);
  }

  std::set<uint64_t> mixable;
  for (const auto &i: resp_t.histogram)
  {
    mixable.insert(i.amount);
  }

  return select_available_outputs([mixable, atleast, allow_rct](const transfer_details &td) {
    if (!allow_rct && td.is_rct())
      return false;
    const uint64_t amount = td.is_rct() ? 0 : td.amount();
    if (atleast) {
      if (mixable.find(amount) != mixable.end())
        return true;
    }
    else {
      if (mixable.find(amount) == mixable.end())
        return true;
    }
    return false;
  });
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_num_rct_outputs()
{
  cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request req_t = AUTO_VAL_INIT(req_t);
  cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response resp_t = AUTO_VAL_INIT(resp_t);
  req_t.amounts.push_back(0);
  req_t.min_count = 0;
  req_t.max_count = 0;
  req_t.unlocked = true;
  req_t.recent_cutoff = 0;

  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    uint64_t pre_call_credits = m_rpc_payment_state.credits;
    req_t.client = get_client_signature();
    bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_output_histogram", req_t, resp_t, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, resp_t, "get_output_histogram", error::get_histogram_error, resp_t.status);
    THROW_WALLET_EXCEPTION_IF(resp_t.histogram.size() != 1, error::get_histogram_error, "Expected exactly one response");
    THROW_WALLET_EXCEPTION_IF(resp_t.histogram[0].amount != 0, error::get_histogram_error, "Expected 0 amount");
    check_rpc_cost("get_output_histogram", resp_t.credits, pre_call_credits, COST_PER_OUTPUT_HISTOGRAM);
  }

  return resp_t.histogram[0].total_instances;
}
//----------------------------------------------------------------------------------------------------
const wallet2::transfer_details &wallet2::get_transfer_details(size_t idx) const
{
  THROW_WALLET_EXCEPTION_IF(idx >= m_transfers.size(), error::wallet_internal_error, "Bad transfer index");
  return m_transfers[idx];
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_unmixable_outputs()
{
  // request all outputs with less instances than the min ring size
  return select_available_outputs_from_histogram(get_min_ring_size(), false, true, false);
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_mixable_outputs()
{
  // request all outputs with at least as many instances as the min ring size
  return select_available_outputs_from_histogram(get_min_ring_size(), true, true, true);
}
//----------------------------------------------------------------------------------------------------
void wallet2::discard_unmixable_outputs()
{
  // may throw
  std::vector<size_t> unmixable_outputs = select_available_unmixable_outputs();
  for (size_t idx : unmixable_outputs)
  {
    freeze(idx);
  }
}

bool wallet2::get_tx_key_cached(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const
{
  additional_tx_keys.clear();
  const std::unordered_map<crypto::hash, crypto::secret_key>::const_iterator i = m_tx_keys.find(txid);
  if (i == m_tx_keys.end())
    return false;
  tx_key = i->second;
  if (tx_key == crypto::null_skey)
    return false;
  const auto j = m_additional_tx_keys.find(txid);
  if (j != m_additional_tx_keys.end())
    additional_tx_keys = j->second;
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys)
{
  bool r = get_tx_key_cached(txid, tx_key, additional_tx_keys);
  if (r)
  {
    MDEBUG("tx key cached for txid: " << txid);
    return true;
  }

  auto & hwdev = get_account().get_device();

  // So far only Cold protocol devices are supported.
  if (hwdev.device_protocol() != hw::device::PROTOCOL_COLD)
  {
    return false;
  }

  const auto tx_data_it = m_tx_device.find(txid);
  if (tx_data_it == m_tx_device.end())
  {
    MDEBUG("Aux data not found for txid: " << txid);
    return false;
  }

  auto dev_cold = dynamic_cast<::hw::device_cold*>(&hwdev);
  CHECK_AND_ASSERT_THROW_MES(dev_cold, "Device does not implement cold signing interface");
  if (!dev_cold->is_get_tx_key_supported())
  {
    MDEBUG("get_tx_key not supported by the device");
    return false;
  }

  hw::device_cold::tx_key_data_t tx_key_data;
  dev_cold->load_tx_key_data(tx_key_data, tx_data_it->second);

  // Load missing tx prefix hash
  if (tx_key_data.tx_prefix_hash.empty())
  {
    COMMAND_RPC_GET_TRANSACTIONS::request req;
    COMMAND_RPC_GET_TRANSACTIONS::response res;
    req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
    req.decode_as_json = false;
    req.prune = true;

    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      req.client = get_client_signature();
      uint64_t pre_call_credits = m_rpc_payment_state.credits;
      bool ok = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client);
      THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
                                error::wallet_internal_error, "Failed to get transaction from daemon");
      check_rpc_cost("/gettransactions", res.credits, pre_call_credits, res.txs.size() * COST_PER_TX);
    }

    cryptonote::transaction tx;
    crypto::hash tx_hash{};
    cryptonote::blobdata tx_data;
    crypto::hash tx_prefix_hash{};
    bool ok = string_tools::parse_hexstr_to_binbuff(res.txs_as_hex.front(), tx_data);
    THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");
    THROW_WALLET_EXCEPTION_IF(!cryptonote::parse_and_validate_tx_from_blob(tx_data, tx, tx_hash, tx_prefix_hash),
                              error::wallet_internal_error, "Failed to validate transaction from daemon");
    THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error,
                              "Failed to get the right transaction from daemon");

    tx_key_data.tx_prefix_hash = std::string(tx_prefix_hash.data, 32);
  }

  std::vector<crypto::secret_key> tx_keys;
  dev_cold->get_tx_key(tx_keys, tx_key_data, m_account.get_keys().m_view_secret_key);
  if (tx_keys.empty())
  {
    MDEBUG("Empty tx keys for txid: " << txid);
    return false;
  }

  if (tx_keys[0] == crypto::null_skey)
  {
    return false;
  }

  tx_key = tx_keys[0];
  tx_keys.erase(tx_keys.begin());
  additional_tx_keys = tx_keys;
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const boost::optional<cryptonote::account_public_address> &single_destination_subaddress)
{
  // fetch tx from daemon and check if secret keys agree with corresponding public keys
  COMMAND_RPC_GET_TRANSACTIONS::request req = AUTO_VAL_INIT(req);
  req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
  req.decode_as_json = false;
  req.prune = true;
  COMMAND_RPC_GET_TRANSACTIONS::response res = AUTO_VAL_INIT(res);
  bool r;
  uint64_t pre_call_credits;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    pre_call_credits = m_rpc_payment_state.credits;
    req.client = get_client_signature();
    r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "/gettransactions");
    THROW_WALLET_EXCEPTION_IF(res.txs.size() != 1, error::wallet_internal_error,
      "daemon returned wrong response for gettransactions, wrong txs count = " +
      std::to_string(res.txs.size()) + ", expected 1");
    check_rpc_cost("/gettransactions", res.credits, pre_call_credits, COST_PER_TX);
  }

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(res.txs[0], tx, tx_hash), error::wallet_internal_error,
      "Failed to get transaction from daemon");
  THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "txid mismatch");
  std::vector<tx_extra_field> tx_extra_fields;
  THROW_WALLET_EXCEPTION_IF(!parse_tx_extra(tx.extra, tx_extra_fields), error::wallet_internal_error, "Transaction extra has unsupported format");
  tx_extra_pub_key pub_key_field;
  bool found = false;
  size_t index = 0;
  while (find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, index++))
  {
    crypto::public_key calculated_pub_key;
    crypto::secret_key_to_public_key(tx_key, calculated_pub_key);
    if (calculated_pub_key == pub_key_field.pub_key)
    {
      found = true;
      break;
    }
    // when sent to a single subaddress, the derivation is different
    if (single_destination_subaddress)
    {
      calculated_pub_key = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(single_destination_subaddress->m_spend_public_key), rct::sk2rct(tx_key)));
      if (calculated_pub_key == pub_key_field.pub_key)
      {
        found = true;
        break;
      }
    }
  }
  THROW_WALLET_EXCEPTION_IF(!found, error::wallet_internal_error, "Given tx secret key doesn't agree with the tx public key in the blockchain");
  tx_extra_additional_pub_keys additional_tx_pub_keys;
  find_tx_extra_field_by_type(tx_extra_fields, additional_tx_pub_keys);
  THROW_WALLET_EXCEPTION_IF(additional_tx_keys.size() != additional_tx_pub_keys.data.size(), error::wallet_internal_error, "The number of additional tx secret keys doesn't agree with the number of additional tx public keys in the blockchain" );
  m_tx_keys[txid] = tx_key;
  m_additional_tx_keys[txid] = additional_tx_keys;
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
  uint64_t pre_call_credits;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    pre_call_credits = m_rpc_payment_state.credits;
    req.client = get_client_signature();
    r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "gettransactions");
    THROW_WALLET_EXCEPTION_IF(res.txs.size() != 1, error::wallet_internal_error,
      "daemon returned wrong response for gettransactions, wrong txs count = " +
      std::to_string(res.txs.size()) + ", expected 1");
    check_rpc_cost("/gettransactions", res.credits, pre_call_credits, COST_PER_TX);
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
    const transfer_details& in_td = m_transfers[found->second];
    const txout_to_key* const in_tx_out_pkey = boost::get<txout_to_key>(std::addressof(in_td.m_tx.vout[in_td.m_internal_output_index].target));
    THROW_WALLET_EXCEPTION_IF(in_tx_out_pkey == nullptr, error::wallet_internal_error, "Output is not txout_to_key");
    const crypto::public_key in_tx_pub_key = get_tx_pub_key_from_extra(in_td.m_tx, in_td.m_pk_index);
    const std::vector<crypto::public_key> in_additionakl_tx_pub_keys = get_additional_tx_pub_keys_from_extra(in_td.m_tx);
    keypair in_ephemeral;
    crypto::key_image in_img;
    THROW_WALLET_EXCEPTION_IF(!generate_key_image_helper(m_account.get_keys(), m_subaddresses, in_tx_out_pkey->key, in_tx_pub_key, in_additionakl_tx_pub_keys, in_td.m_internal_output_index, in_ephemeral, in_img, m_account.get_device()),
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
    uint64_t pre_call_credits;
    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      pre_call_credits = m_rpc_payment_state.credits;
      req.client = get_client_signature();
      r = epee::net_utils::invoke_http_bin("/get_outs.bin", req, res, *m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_outs.bin", error::get_outs_error, res.status);
      THROW_WALLET_EXCEPTION_IF(res.outs.size() != ring_size, error::wallet_internal_error,
        "daemon returned wrong response for get_outs.bin, wrong amounts count = " +
        std::to_string(res.outs.size()) + ", expected " +  std::to_string(ring_size));
      check_rpc_cost("/get_outs.bin", res.credits, pre_call_credits, ring_size * COST_PER_OUT);
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
  uint64_t pre_call_credits;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    pre_call_credits = m_rpc_payment_state.credits;
    req.client = get_client_signature();
    r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "gettransactions");
    THROW_WALLET_EXCEPTION_IF(res.txs.size() != 1, error::wallet_internal_error,
      "daemon returned wrong response for gettransactions, wrong txs count = " +
      std::to_string(res.txs.size()) + ", expected 1");
    check_rpc_cost("/gettransactions", res.credits, pre_call_credits, COST_PER_TX);
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
    uint64_t pre_call_credits;
    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      pre_call_credits = m_rpc_payment_state.credits;
      req.client = get_client_signature();
      r = epee::net_utils::invoke_http_bin("/get_outs.bin", req, res, *m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_outs.bin", error::get_outs_error, res.status);
      THROW_WALLET_EXCEPTION_IF(res.outs.size() != req.outputs.size(), error::wallet_internal_error,
        "daemon returned wrong response for get_outs.bin, wrong amounts count = " +
        std::to_string(res.outs.size()) + ", expected " +  std::to_string(req.outputs.size()));
      check_rpc_cost("/get_outs.bin", res.credits, pre_call_credits, req.outputs.size() * COST_PER_OUT);
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

std::string wallet2::get_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message)
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
      uint64_t pre_call_credits = m_rpc_payment_state.credits;
      req.client = get_client_signature();
      ok = net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client);
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

    THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

    // determine if the address is found in the subaddress hash table (i.e. whether the proof is outbound or inbound)
    crypto::secret_key tx_key = crypto::null_skey;
    std::vector<crypto::secret_key> additional_tx_keys;
    const bool is_out = m_subaddresses.count(address.m_spend_public_key) == 0;
    if (is_out)
    {
      THROW_WALLET_EXCEPTION_IF(!get_tx_key(txid, tx_key, additional_tx_keys), error::wallet_internal_error, "Tx secret key wasn't found in the wallet file.");
    }

    return get_tx_proof(tx, tx_key, additional_tx_keys, address, is_subaddress, message);
}

std::string wallet2::get_tx_proof(const cryptonote::transaction &tx, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message) const
{
  hw::device &hwdev = m_account.get_device();
  rct::key  aP;
  // determine if the address is found in the subaddress hash table (i.e. whether the proof is outbound or inbound)
  const bool is_out = m_subaddresses.count(address.m_spend_public_key) == 0;

  const crypto::hash txid = cryptonote::get_transaction_hash(tx);
  std::string prefix_data((const char*)&txid, sizeof(crypto::hash));
  prefix_data += message;
  crypto::hash prefix_hash;
  crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  std::vector<crypto::public_key> shared_secret;
  std::vector<crypto::signature> sig;
  std::string sig_str;
  if (is_out)
  {
    const size_t num_sigs = 1 + additional_tx_keys.size();
    shared_secret.resize(num_sigs);
    sig.resize(num_sigs);

    hwdev.scalarmultKey(aP, rct::pk2rct(address.m_view_public_key), rct::sk2rct(tx_key));
    shared_secret[0] = rct::rct2pk(aP);
    crypto::public_key tx_pub_key;
    if (is_subaddress)
    {
      hwdev.scalarmultKey(aP, rct::pk2rct(address.m_spend_public_key), rct::sk2rct(tx_key));
      tx_pub_key = rct2pk(aP);
      hwdev.generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, address.m_spend_public_key, shared_secret[0], tx_key, sig[0]);
    }
    else
    {
      hwdev.secret_key_to_public_key(tx_key, tx_pub_key);
      hwdev.generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, boost::none, shared_secret[0], tx_key, sig[0]);
    }
    for (size_t i = 1; i < num_sigs; ++i)
    {
      hwdev.scalarmultKey(aP, rct::pk2rct(address.m_view_public_key), rct::sk2rct(additional_tx_keys[i - 1]));
      shared_secret[i] = rct::rct2pk(aP);
      if (is_subaddress)
      {
        hwdev.scalarmultKey(aP, rct::pk2rct(address.m_spend_public_key), rct::sk2rct(additional_tx_keys[i - 1]));
        tx_pub_key = rct2pk(aP);
        hwdev.generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, address.m_spend_public_key, shared_secret[i], additional_tx_keys[i - 1], sig[i]);
      }
      else
      {
        hwdev.secret_key_to_public_key(additional_tx_keys[i - 1], tx_pub_key);
        hwdev.generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, boost::none, shared_secret[i], additional_tx_keys[i - 1], sig[i]);
      }
    }
    sig_str = std::string("OutProofV2");
  }
  else
  {
    crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
    THROW_WALLET_EXCEPTION_IF(tx_pub_key == null_pkey, error::wallet_internal_error, "Tx pubkey was not found");

    std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
    const size_t num_sigs = 1 + additional_tx_pub_keys.size();
    shared_secret.resize(num_sigs);
    sig.resize(num_sigs);

    const crypto::secret_key& a = m_account.get_keys().m_view_secret_key;
    hwdev.scalarmultKey(aP, rct::pk2rct(tx_pub_key), rct::sk2rct(a));
    shared_secret[0] =  rct2pk(aP);
    if (is_subaddress)
    {
      hwdev.generate_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, address.m_spend_public_key, shared_secret[0], a, sig[0]);
    }
    else
    {
      hwdev.generate_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, boost::none, shared_secret[0], a, sig[0]);
    }
    for (size_t i = 1; i < num_sigs; ++i)
    {
      hwdev.scalarmultKey(aP,rct::pk2rct(additional_tx_pub_keys[i - 1]), rct::sk2rct(a));
      shared_secret[i] = rct2pk(aP);
      if (is_subaddress)
      {
        hwdev.generate_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i - 1], address.m_spend_public_key, shared_secret[i], a, sig[i]);
      }
      else
      {
        hwdev.generate_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i - 1], boost::none, shared_secret[i], a, sig[i]);
      }
    }
    sig_str = std::string("InProofV2");
  }
  const size_t num_sigs = shared_secret.size();

  // check if this address actually received any funds
  crypto::key_derivation derivation;
  THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(shared_secret[0], rct::rct2sk(rct::I), derivation), error::wallet_internal_error, "Failed to generate key derivation");
  std::vector<crypto::key_derivation> additional_derivations(num_sigs - 1);
  for (size_t i = 1; i < num_sigs; ++i)
    THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(shared_secret[i], rct::rct2sk(rct::I), additional_derivations[i - 1]), error::wallet_internal_error, "Failed to generate key derivation");
  uint64_t received;
  check_tx_key_helper(tx, derivation, additional_derivations, address, received);
  THROW_WALLET_EXCEPTION_IF(!received, error::wallet_internal_error, tr("No funds received in this tx."));

  // concatenate all signature strings
  for (size_t i = 0; i < num_sigs; ++i)
    sig_str +=
      tools::base58::encode(std::string((const char *)&shared_secret[i], sizeof(crypto::public_key))) +
      tools::base58::encode(std::string((const char *)&sig[i], sizeof(crypto::signature)));
  return sig_str;
}

bool wallet2::check_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message, const std::string &sig_str, uint64_t &received, bool &in_pool, uint64_t &confirmations)
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
    uint64_t pre_call_credits = m_rpc_payment_state.credits;
    req.client = get_client_signature();
    ok = net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client);
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

  THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

  if (!check_tx_proof(tx, address, is_subaddress, message, sig_str, received))
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

bool wallet2::check_tx_proof(const cryptonote::transaction &tx, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message, const std::string &sig_str, uint64_t &received) const
{
  // InProofV1, InProofV2, OutProofV1, OutProofV2
  const bool is_out = sig_str.substr(0, 3) == "Out";
  const std::string header = is_out ? sig_str.substr(0,10) : sig_str.substr(0,9);
  int version = 2; // InProofV2
  if (is_out && sig_str.substr(8,2) == "V1") version = 1; // OutProofV1
  else if (is_out) version = 2; // OutProofV2
  else if (sig_str.substr(7,2) == "V1") version = 1; // InProofV1

  const size_t header_len = header.size();
  THROW_WALLET_EXCEPTION_IF(sig_str.size() < header_len || sig_str.substr(0, header_len) != header, error::wallet_internal_error,
    "Signature header check error");

  // decode base58
  std::vector<crypto::public_key> shared_secret(1);
  std::vector<crypto::signature> sig(1);
  const size_t pk_len = tools::base58::encode(std::string((const char *)&shared_secret[0], sizeof(crypto::public_key))).size();
  const size_t sig_len = tools::base58::encode(std::string((const char *)&sig[0], sizeof(crypto::signature))).size();
  const size_t num_sigs = (sig_str.size() - header_len) / (pk_len + sig_len);
  THROW_WALLET_EXCEPTION_IF(sig_str.size() != header_len + num_sigs * (pk_len + sig_len), error::wallet_internal_error,
    "Wrong signature size");
  shared_secret.resize(num_sigs);
  sig.resize(num_sigs);
  for (size_t i = 0; i < num_sigs; ++i)
  {
    std::string pk_decoded;
    std::string sig_decoded;
    const size_t offset = header_len + i * (pk_len + sig_len);
    THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(offset, pk_len), pk_decoded), error::wallet_internal_error,
      "Signature decoding error");
    THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(offset + pk_len, sig_len), sig_decoded), error::wallet_internal_error,
      "Signature decoding error");
    THROW_WALLET_EXCEPTION_IF(sizeof(crypto::public_key) != pk_decoded.size() || sizeof(crypto::signature) != sig_decoded.size(), error::wallet_internal_error,
      "Signature decoding error");
    memcpy(&shared_secret[i], pk_decoded.data(), sizeof(crypto::public_key));
    memcpy(&sig[i], sig_decoded.data(), sizeof(crypto::signature));
  }

  crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
  THROW_WALLET_EXCEPTION_IF(tx_pub_key == null_pkey, error::wallet_internal_error, "Tx pubkey was not found");

  std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
  THROW_WALLET_EXCEPTION_IF(additional_tx_pub_keys.size() + 1 != num_sigs, error::wallet_internal_error, "Signature size mismatch with additional tx pubkeys");

  const crypto::hash txid = cryptonote::get_transaction_hash(tx);
  std::string prefix_data((const char*)&txid, sizeof(crypto::hash));
  prefix_data += message;
  crypto::hash prefix_hash;
  crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  // check signature
  std::vector<int> good_signature(num_sigs, 0);
  if (is_out)
  {
    good_signature[0] = is_subaddress ?
      crypto::check_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, address.m_spend_public_key, shared_secret[0], sig[0], version) :
      crypto::check_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, boost::none, shared_secret[0], sig[0], version);

    for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
    {
      good_signature[i + 1] = is_subaddress ?
        crypto::check_tx_proof(prefix_hash, additional_tx_pub_keys[i], address.m_view_public_key, address.m_spend_public_key, shared_secret[i + 1], sig[i + 1], version) :
        crypto::check_tx_proof(prefix_hash, additional_tx_pub_keys[i], address.m_view_public_key, boost::none, shared_secret[i + 1], sig[i + 1], version);
    }
  }
  else
  {
    good_signature[0] = is_subaddress ?
      crypto::check_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, address.m_spend_public_key, shared_secret[0], sig[0], version) :
      crypto::check_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, boost::none, shared_secret[0], sig[0], version);

    for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
    {
      good_signature[i + 1] = is_subaddress ?
        crypto::check_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i], address.m_spend_public_key, shared_secret[i + 1], sig[i + 1], version) :
        crypto::check_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i], boost::none, shared_secret[i + 1], sig[i + 1], version);
    }
  }

  if (std::any_of(good_signature.begin(), good_signature.end(), [](int i) { return i > 0; }))
  {
    // obtain key derivation by multiplying scalar 1 to the shared secret
    crypto::key_derivation derivation;
    if (good_signature[0])
      THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(shared_secret[0], rct::rct2sk(rct::I), derivation), error::wallet_internal_error, "Failed to generate key derivation");

    std::vector<crypto::key_derivation> additional_derivations(num_sigs - 1);
    for (size_t i = 1; i < num_sigs; ++i)
      if (good_signature[i])
        THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(shared_secret[i], rct::rct2sk(rct::I), additional_derivations[i - 1]), error::wallet_internal_error, "Failed to generate key derivation");

    check_tx_key_helper(tx, derivation, additional_derivations, address, received);
    return true;
  }
  return false;
}

std::string wallet2::get_reserve_proof(const boost::optional<std::pair<uint32_t, uint64_t>> &account_minreserve, const std::string &message)
{
  THROW_WALLET_EXCEPTION_IF(m_watch_only, error::wallet_internal_error, "Reserve proof can only be generated by a full wallet");
  THROW_WALLET_EXCEPTION_IF(balance_all(true) == 0, error::wallet_internal_error, "Zero balance");
  THROW_WALLET_EXCEPTION_IF(account_minreserve && balance(account_minreserve->first, true) < account_minreserve->second, error::wallet_internal_error,
    "Not enough balance in this account for the requested minimum reserve amount");

  // determine which outputs to include in the proof
  std::vector<size_t> selected_transfers;
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details &td = m_transfers[i];
    if (!is_spent(td, true) && !td.m_frozen && (!account_minreserve || account_minreserve->first == td.m_subaddr_index.major))
      selected_transfers.push_back(i);
  }

  if (account_minreserve)
  {
    THROW_WALLET_EXCEPTION_IF(account_minreserve->second == 0, error::wallet_internal_error, "Proved amount must be greater than 0");
    // minimize the number of outputs included in the proof, by only picking the N largest outputs that can cover the requested min reserve amount
    std::sort(selected_transfers.begin(), selected_transfers.end(), [&](const size_t a, const size_t b)
      { return m_transfers[a].amount() > m_transfers[b].amount(); });
    while (selected_transfers.size() >= 2 && m_transfers[selected_transfers[1]].amount() >= account_minreserve->second)
      selected_transfers.erase(selected_transfers.begin());
    size_t sz = 0;
    uint64_t total = 0;
    while (total < account_minreserve->second)
    {
      total += m_transfers[selected_transfers[sz]].amount();
      ++sz;
    }
    selected_transfers.resize(sz);
  }

  // compute signature prefix hash
  std::string prefix_data = message;
  prefix_data.append((const char*)&m_account.get_keys().m_account_address, sizeof(cryptonote::account_public_address));
  for (size_t i = 0; i < selected_transfers.size(); ++i)
  {
    prefix_data.append((const char*)&m_transfers[selected_transfers[i]].m_key_image, sizeof(crypto::key_image));
  }
  crypto::hash prefix_hash;
  crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  // generate proof entries
  std::vector<reserve_proof_entry> proofs(selected_transfers.size());
  std::unordered_set<cryptonote::subaddress_index> subaddr_indices = { {0,0} };
  for (size_t i = 0; i < selected_transfers.size(); ++i)
  {
    const transfer_details &td = m_transfers[selected_transfers[i]];
    reserve_proof_entry& proof = proofs[i];
    proof.txid = td.m_txid;
    proof.index_in_tx = td.m_internal_output_index;
    proof.key_image = td.m_key_image;
    subaddr_indices.insert(td.m_subaddr_index);

    // get tx pub key 
    const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
    THROW_WALLET_EXCEPTION_IF(tx_pub_key == crypto::null_pkey, error::wallet_internal_error, "The tx public key isn't found");
    const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);

    // determine which tx pub key was used for deriving the output key
    const crypto::public_key *tx_pub_key_used = &tx_pub_key;
    for (int i = 0; i < 2; ++i)
    {
      proof.shared_secret = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(*tx_pub_key_used), rct::sk2rct(m_account.get_keys().m_view_secret_key)));
      crypto::key_derivation derivation;
      THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(proof.shared_secret, rct::rct2sk(rct::I), derivation),
        error::wallet_internal_error, "Failed to generate key derivation");
      crypto::public_key subaddress_spendkey;
      THROW_WALLET_EXCEPTION_IF(!derive_subaddress_public_key(td.get_public_key(), derivation, proof.index_in_tx, subaddress_spendkey),
        error::wallet_internal_error, "Failed to derive subaddress public key");
      if (m_subaddresses.count(subaddress_spendkey) == 1)
        break;
      THROW_WALLET_EXCEPTION_IF(additional_tx_pub_keys.empty(), error::wallet_internal_error,
        "Normal tx pub key doesn't derive the expected output, while the additional tx pub keys are empty");
      THROW_WALLET_EXCEPTION_IF(i == 1, error::wallet_internal_error,
        "Neither normal tx pub key nor additional tx pub key derive the expected output key");
      tx_pub_key_used = &additional_tx_pub_keys[proof.index_in_tx];
    }

    // generate signature for shared secret
    crypto::generate_tx_proof(prefix_hash, m_account.get_keys().m_account_address.m_view_public_key, *tx_pub_key_used, boost::none, proof.shared_secret, m_account.get_keys().m_view_secret_key, proof.shared_secret_sig);

    // derive ephemeral secret key
    crypto::key_image ki;
    cryptonote::keypair ephemeral;
    const bool r = cryptonote::generate_key_image_helper(m_account.get_keys(), m_subaddresses, td.get_public_key(), tx_pub_key,  additional_tx_pub_keys, td.m_internal_output_index, ephemeral, ki, m_account.get_device());
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
    THROW_WALLET_EXCEPTION_IF(ephemeral.pub != td.get_public_key(), error::wallet_internal_error, "Derived public key doesn't agree with the stored one");

    // generate signature for key image
    const std::vector<const crypto::public_key*> pubs = { &ephemeral.pub };
    crypto::generate_ring_signature(prefix_hash, td.m_key_image, &pubs[0], 1, ephemeral.sec, 0, &proof.key_image_sig);
  }

  // collect all subaddress spend keys that received those outputs and generate their signatures
  serializable_unordered_map<crypto::public_key, crypto::signature> subaddr_spendkeys;
  for (const cryptonote::subaddress_index &index : subaddr_indices)
  {
    crypto::secret_key subaddr_spend_skey = m_account.get_keys().m_spend_secret_key;
    if (!index.is_zero())
    {
      crypto::secret_key m = m_account.get_device().get_subaddress_secret_key(m_account.get_keys().m_view_secret_key, index);
      crypto::secret_key tmp = subaddr_spend_skey;
      sc_add((unsigned char*)&subaddr_spend_skey, (unsigned char*)&m, (unsigned char*)&tmp);
    }
    crypto::public_key subaddr_spend_pkey;
    secret_key_to_public_key(subaddr_spend_skey, subaddr_spend_pkey);
    crypto::generate_signature(prefix_hash, subaddr_spend_pkey, subaddr_spend_skey, subaddr_spendkeys[subaddr_spend_pkey]);
  }

  // serialize & encode
  std::ostringstream oss;
  binary_archive<true> ar(oss);
  THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, proofs), error::wallet_internal_error, "Failed to serialize proof");
  THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, subaddr_spendkeys), error::wallet_internal_error, "Failed to serialize proof");
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
    uint64_t pre_call_credits = m_rpc_payment_state.credits;
    gettx_req.client = get_client_signature();
    bool ok = net_utils::invoke_http_json("/gettransactions", gettx_req, gettx_res, *m_http_client);
    THROW_WALLET_EXCEPTION_IF(!ok || gettx_res.txs.size() != proofs.size(),
      error::wallet_internal_error, "Failed to get transaction from daemon");
    check_rpc_cost("/gettransactions", gettx_res.credits, pre_call_credits, gettx_res.txs.size() * COST_PER_TX);
  }

  // check spent status
  COMMAND_RPC_IS_KEY_IMAGE_SPENT::request kispent_req;
  COMMAND_RPC_IS_KEY_IMAGE_SPENT::response kispent_res;
  for (size_t i = 0; i < proofs.size(); ++i)
    kispent_req.key_images.push_back(epee::string_tools::pod_to_hex(proofs[i].key_image));

  bool ok;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    uint64_t pre_call_credits = m_rpc_payment_state.credits;
    kispent_req.client = get_client_signature();
    ok = epee::net_utils::invoke_http_json("/is_key_image_spent", kispent_req, kispent_res, *m_http_client, rpc_timeout);
    THROW_WALLET_EXCEPTION_IF(!ok || kispent_res.spent_status.size() != proofs.size(),
      error::wallet_internal_error, "Failed to get key image spent status from daemon");
    check_rpc_cost("/is_key_image_spent", kispent_res.credits, pre_call_credits, kispent_res.spent_status.size() * COST_PER_KEY_IMAGE);
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

    const cryptonote::txout_to_key* const out_key = boost::get<cryptonote::txout_to_key>(std::addressof(tx.vout[proof.index_in_tx].target));
    THROW_WALLET_EXCEPTION_IF(!out_key, error::wallet_internal_error, "Output key wasn't found")

    // get tx pub key
    const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
    THROW_WALLET_EXCEPTION_IF(tx_pub_key == crypto::null_pkey, error::wallet_internal_error, "The tx public key isn't found");
    const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);

    // check singature for shared secret
    ok = crypto::check_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, boost::none, proof.shared_secret, proof.shared_secret_sig, version);
    if (!ok && additional_tx_pub_keys.size() == tx.vout.size())
      ok = crypto::check_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[proof.index_in_tx], boost::none, proof.shared_secret, proof.shared_secret_sig, version);
    if (!ok)
      return false;

    // check signature for key image
    const std::vector<const crypto::public_key*> pubs = { &out_key->key };
    ok = crypto::check_ring_signature(prefix_hash, proof.key_image, &pubs[0], 1, &proof.key_image_sig);
    if (!ok)
      return false;

    // check if the address really received the fund
    crypto::key_derivation derivation;
    THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(proof.shared_secret, rct::rct2sk(rct::I), derivation), error::wallet_internal_error, "Failed to generate key derivation");
    crypto::public_key subaddr_spendkey;
    crypto::derive_subaddress_public_key(out_key->key, derivation, proof.index_in_tx, subaddr_spendkey);
    THROW_WALLET_EXCEPTION_IF(subaddr_spendkeys.count(subaddr_spendkey) == 0, error::wallet_internal_error,
      "The address doesn't seem to have received the fund");

    // check amount
    uint64_t amount = tx.vout[proof.index_in_tx].amount;
    if (amount == 0)
    {
      // decode rct
      crypto::secret_key shared_secret;
      crypto::derivation_to_scalar(derivation, proof.index_in_tx, shared_secret);
      rct::ecdhTuple ecdh_info = tx.rct_signatures.ecdhInfo[proof.index_in_tx];
      rct::ecdhDecode(ecdh_info, rct::sk2rct(shared_secret), tx.rct_signatures.type == rct::RCTTypeBulletproof2 || tx.rct_signatures.type == rct::RCTTypeCLSAG);
      amount = rct::h2d(ecdh_info.amount);
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

std::string wallet2::get_wallet_file() const
{
  return m_wallet_file;
}

std::string wallet2::get_keys_file() const
{
  return m_keys_file;
}

std::string wallet2::get_daemon_address() const
{
  return m_daemon_address;
}

uint64_t wallet2::get_daemon_blockchain_height(string &err)
{
  uint64_t height;

  boost::optional<std::string> result = m_node_rpc_proxy.get_height(height);
  if (result)
  {
    if (m_trusted_daemon)
      err = *result;
    else
      err = "daemon error";
    return 0;
  }

  err = "";
  return height;
}

uint64_t wallet2::get_daemon_adjusted_time()
{
    uint64_t adjusted_time;

    boost::optional<std::string> result = m_node_rpc_proxy.get_adjusted_time(adjusted_time);
    THROW_WALLET_EXCEPTION_IF(result, error::wallet_internal_error, "Invalid adjusted time from daemon");
    return adjusted_time;
}

uint64_t wallet2::get_daemon_blockchain_target_height(string &err)
{
  err = "";
  uint64_t target_height = 0;
  const auto result = m_node_rpc_proxy.get_target_height(target_height);
  if (result && *result != CORE_RPC_STATUS_OK)
  {
    if (m_trusted_daemon)
      err = *result;
    else
      err = "daemon error";
    return 0;
  }
  return target_height;
}

uint64_t wallet2::get_approximate_blockchain_height() const
{
  // time of v2 fork
  const time_t fork_time = m_nettype == TESTNET ? 1448285909 : m_nettype == STAGENET ? 1520937818 : 1458748658;
  // v2 fork block
  const uint64_t fork_block = m_nettype == TESTNET ? 624634 : m_nettype == STAGENET ? 32000 : 1009827;
  // avg seconds per block
  const int seconds_per_block = DIFFICULTY_TARGET_V2;
  // Calculated blockchain height
  uint64_t approx_blockchain_height = fork_block + (time(NULL) - fork_time)/seconds_per_block;
  // testnet got some huge rollbacks, so the estimation is way off
  static const uint64_t approximate_testnet_rolled_back_blocks = 342100;
  if (m_nettype == TESTNET && approx_blockchain_height > approximate_testnet_rolled_back_blocks)
    approx_blockchain_height -= approximate_testnet_rolled_back_blocks;
  LOG_PRINT_L2("Calculated blockchain height: " << approx_blockchain_height);
  return approx_blockchain_height;
}

void wallet2::set_tx_note(const crypto::hash &txid, const std::string &note)
{
  m_tx_notes[txid] = note;
}

std::string wallet2::get_tx_note(const crypto::hash &txid) const
{
  std::unordered_map<crypto::hash, std::string>::const_iterator i = m_tx_notes.find(txid);
  if (i == m_tx_notes.end())
    return std::string();
  return i->second;
}

void wallet2::set_tx_device_aux(const crypto::hash &txid, const std::string &aux)
{
  m_tx_device[txid] = aux;
}

std::string wallet2::get_tx_device_aux(const crypto::hash &txid) const
{
  std::unordered_map<crypto::hash, std::string>::const_iterator i = m_tx_device.find(txid);
  if (i == m_tx_device.end())
    return std::string();
  return i->second;
}

void wallet2::set_attribute(const std::string &key, const std::string &value)
{
  m_attributes[key] = value;
}

bool wallet2::get_attribute(const std::string &key, std::string &value) const
{
  std::unordered_map<std::string, std::string>::const_iterator i = m_attributes.find(key);
  if (i == m_attributes.end())
    return false;
  value = i->second;
  return true;
}

void wallet2::set_description(const std::string &description)
{
  set_attribute(ATTRIBUTE_DESCRIPTION, description);
}

std::string wallet2::get_description() const
{
  std::string s;
  if (get_attribute(ATTRIBUTE_DESCRIPTION, s))
    return s;
  return "";
}

const std::pair<serializable_map<std::string, std::string>, std::vector<std::string>>& wallet2::get_account_tags()
{
  // ensure consistency
  if (m_account_tags.second.size() != get_num_subaddress_accounts())
    m_account_tags.second.resize(get_num_subaddress_accounts(), "");
  for (const std::string& tag : m_account_tags.second)
  {
    if (!tag.empty() && m_account_tags.first.count(tag) == 0)
      m_account_tags.first.insert({tag, ""});
  }
  for (auto i = m_account_tags.first.begin(); i != m_account_tags.first.end(); )
  {
    if (std::find(m_account_tags.second.begin(), m_account_tags.second.end(), i->first) == m_account_tags.second.end())
      i = m_account_tags.first.erase(i);
    else
      ++i;
  }
  return m_account_tags;
}

void wallet2::set_account_tag(const std::set<uint32_t> &account_indices, const std::string& tag)
{
  for (uint32_t account_index : account_indices)
  {
    THROW_WALLET_EXCEPTION_IF(account_index >= get_num_subaddress_accounts(), error::wallet_internal_error, "Account index out of bound");
    if (m_account_tags.second[account_index] == tag)
      MDEBUG("This tag is already assigned to this account");
    else
      m_account_tags.second[account_index] = tag;
  }
  get_account_tags();
}

void wallet2::set_account_tag_description(const std::string& tag, const std::string& description)
{
  THROW_WALLET_EXCEPTION_IF(tag.empty(), error::wallet_internal_error, "Tag must not be empty");
  THROW_WALLET_EXCEPTION_IF(m_account_tags.first.count(tag) == 0, error::wallet_internal_error, "Tag is unregistered");
  m_account_tags.first[tag] = description;
}

// Set up an address signature message hash
// Hash data: domain separator, spend public key, view public key, mode identifier, payload data
static crypto::hash get_message_hash(const std::string &data, const crypto::public_key &spend_key, const crypto::public_key &view_key, const uint8_t mode)
{
  KECCAK_CTX ctx;
  keccak_init(&ctx);
  keccak_update(&ctx, (const uint8_t*)config::HASH_KEY_MESSAGE_SIGNING, sizeof(config::HASH_KEY_MESSAGE_SIGNING)); // includes NUL
  keccak_update(&ctx, (const uint8_t*)&spend_key, sizeof(crypto::public_key));
  keccak_update(&ctx, (const uint8_t*)&view_key, sizeof(crypto::public_key));
  keccak_update(&ctx, (const uint8_t*)&mode, sizeof(uint8_t));
  char len_buf[(sizeof(size_t) * 8 + 6) / 7];
  char *ptr = len_buf;
  tools::write_varint(ptr, data.size());
  CHECK_AND_ASSERT_THROW_MES(ptr > len_buf && ptr <= len_buf + sizeof(len_buf), "Length overflow");
  keccak_update(&ctx, (const uint8_t*)len_buf, ptr - len_buf);
  keccak_update(&ctx, (const uint8_t*)data.data(), data.size());
  crypto::hash hash;
  keccak_finish(&ctx, (uint8_t*)&hash);
  return hash;
}

// Sign a message with a private key from either the base address or a subaddress
// The signature is also bound to both keys and the signature mode (spend, view) to prevent unintended reuse
std::string wallet2::sign(const std::string &data, message_signature_type_t signature_type, cryptonote::subaddress_index index) const
{
  const cryptonote::account_keys &keys = m_account.get_keys();
  crypto::signature signature;
  crypto::secret_key skey, m;
  crypto::secret_key skey_spend, skey_view;
  crypto::public_key pkey;
  crypto::public_key pkey_spend, pkey_view; // to include both in hash
  crypto::hash hash;
  uint8_t mode;

  // Use the base address
  if (index.is_zero())
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
  // Use a subaddress
  else
  {
    skey_spend = keys.m_spend_secret_key;
    m = m_account.get_device().get_subaddress_secret_key(keys.m_view_secret_key, index);
    sc_add((unsigned char*)&skey_spend, (unsigned char*)&m, (unsigned char*)&skey_spend);
    secret_key_to_public_key(skey_spend,pkey_spend);
    sc_mul((unsigned char*)&skey_view, (unsigned char*)&keys.m_view_secret_key, (unsigned char*)&skey_spend);
    secret_key_to_public_key(skey_view,pkey_view);
    switch (signature_type)
    {
      case sign_with_spend_key:
        skey = skey_spend;
        pkey = pkey_spend;
        mode = 0;
        break;
      case sign_with_view_key:
        skey = skey_view;
        pkey = pkey_view;
        mode = 1;
        break;
      default: CHECK_AND_ASSERT_THROW_MES(false, "Invalid signature type requested");
    }
    secret_key_to_public_key(skey, pkey);
    hash = get_message_hash(data,pkey_spend,pkey_view,mode);
  }
  crypto::generate_signature(hash, pkey, skey, signature);
  return std::string("SigV2") + tools::base58::encode(std::string((const char *)&signature, sizeof(signature)));
}

tools::wallet2::message_signature_result_t wallet2::verify(const std::string &data, const cryptonote::account_public_address &address, const std::string &signature) const
{
  static const size_t v1_header_len = strlen("SigV1");
  static const size_t v2_header_len = strlen("SigV2");
  const bool v1 = signature.size() >= v1_header_len && signature.substr(0, v1_header_len) == "SigV1";
  const bool v2 = signature.size() >= v2_header_len && signature.substr(0, v2_header_len) == "SigV2";
  if (!v1 && !v2)
  {
    LOG_PRINT_L0("Signature header check error");
    return {};
  }
  crypto::hash hash;
  if (v1)
  {
    crypto::cn_fast_hash(data.data(), data.size(), hash);
  }
  std::string decoded;
  if (!tools::base58::decode(signature.substr(v1 ? v1_header_len : v2_header_len), decoded)) {
    LOG_PRINT_L0("Signature decoding error");
    return {};
  }
  crypto::signature s;
  if (sizeof(s) != decoded.size()) {
    LOG_PRINT_L0("Signature decoding error");
    return {};
  }
  memcpy(&s, decoded.data(), sizeof(s));

  // Test each mode and return which mode, if either, succeeded
  if (v2)
      hash = get_message_hash(data,address.m_spend_public_key,address.m_view_public_key,(uint8_t) 0);
  if (crypto::check_signature(hash, address.m_spend_public_key, s))
    return {true, v1 ? 1u : 2u, !v2, sign_with_spend_key };

  if (v2)
      hash = get_message_hash(data,address.m_spend_public_key,address.m_view_public_key,(uint8_t) 1);
  if (crypto::check_signature(hash, address.m_view_public_key, s))
    return {true, v1 ? 1u : 2u, !v2, sign_with_view_key };

  // Both modes failed
  return {};
}


bool wallet2::verify_with_public_key(const std::string &data, const crypto::public_key &public_key, const std::string &signature) const
{
  if (signature.size() < MULTISIG_SIGNATURE_MAGIC.size() || signature.substr(0, MULTISIG_SIGNATURE_MAGIC.size()) != MULTISIG_SIGNATURE_MAGIC) {
    MERROR("Signature header check error");
    return false;
  }
  crypto::hash hash;
  crypto::cn_fast_hash(data.data(), data.size(), hash);
  std::string decoded;
  if (!tools::base58::decode(signature.substr(MULTISIG_SIGNATURE_MAGIC.size()), decoded)) {
    MERROR("Signature decoding error");
    return false;
  }
  crypto::signature s;
  if (sizeof(s) != decoded.size()) {
    MERROR("Signature decoding error");
    return false;
  }
  memcpy(&s, decoded.data(), sizeof(s));
  return crypto::check_signature(hash, public_key, s);
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_tx_pub_key_from_received_outs(const tools::wallet2::transfer_details &td) const
{
  std::vector<tx_extra_field> tx_extra_fields;
  if(!parse_tx_extra(td.m_tx.extra, tx_extra_fields))
  {
    // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
  }

  // Due to a previous bug, there might be more than one tx pubkey in extra, one being
  // the result of a previously discarded signature.
  // For speed, since scanning for outputs is a slow process, we check whether extra
  // contains more than one pubkey. If not, the first one is returned. If yes, they're
  // checked for whether they yield at least one output
  tx_extra_pub_key pub_key_field;
  THROW_WALLET_EXCEPTION_IF(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, 0), error::wallet_internal_error,
      "Public key wasn't found in the transaction extra");
  const crypto::public_key tx_pub_key = pub_key_field.pub_key;
  bool two_found = find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, 1);
  if (!two_found) {
    // easy case, just one found
    return tx_pub_key;
  }

  // more than one, loop and search
  const cryptonote::account_keys& keys = m_account.get_keys();
  size_t pk_index = 0;
  hw::device &hwdev = m_account.get_device();

  while (find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, pk_index++)) {
    const crypto::public_key tx_pub_key = pub_key_field.pub_key;
    crypto::key_derivation derivation;
    bool r = hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation);
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");

    for (size_t i = 0; i < td.m_tx.vout.size(); ++i)
    {
      tx_scan_info_t tx_scan_info;
      check_acc_out_precomp(td.m_tx.vout[i], derivation, {}, i, tx_scan_info);
      if (!tx_scan_info.error && tx_scan_info.received)
        return tx_pub_key;
    }
  }

  // we found no key yielding an output, but it might be in the additional
  // tx pub keys only, which we do not need to check, so return the first one
  return tx_pub_key;
}

bool wallet2::export_key_images(const std::string &filename, bool all) const
{
  PERF_TIMER(export_key_images);
  std::pair<uint64_t, std::vector<std::pair<crypto::key_image, crypto::signature>>> ski = export_key_images(all);
  std::string magic(KEY_IMAGE_EXPORT_FILE_MAGIC, strlen(KEY_IMAGE_EXPORT_FILE_MAGIC));
  const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
  const uint32_t offset = ski.first;

  std::string data;
  data.reserve(4 + ski.second.size() * (sizeof(crypto::key_image) + sizeof(crypto::signature)) + 2 * sizeof(crypto::public_key));
  data.resize(4);
  data[0] = offset & 0xff;
  data[1] = (offset >> 8) & 0xff;
  data[2] = (offset >> 16) & 0xff;
  data[3] = (offset >> 24) & 0xff;
  data += std::string((const char *)&keys.m_spend_public_key, sizeof(crypto::public_key));
  data += std::string((const char *)&keys.m_view_public_key, sizeof(crypto::public_key));
  for (const auto &i: ski.second)
  {
    data += std::string((const char *)&i.first, sizeof(crypto::key_image));
    data += std::string((const char *)&i.second, sizeof(crypto::signature));
  }

  // encrypt data, keep magic plaintext
  PERF_TIMER(export_key_images_encrypt);
  std::string ciphertext = encrypt_with_view_secret_key(data);
  return save_to_file(filename, magic + ciphertext);
}

//----------------------------------------------------------------------------------------------------
std::pair<uint64_t, std::vector<std::pair<crypto::key_image, crypto::signature>>> wallet2::export_key_images(bool all) const
{
  PERF_TIMER(export_key_images_raw);
  std::vector<std::pair<crypto::key_image, crypto::signature>> ski;

  size_t offset = 0;
  if (!all)
  {
    while (offset < m_transfers.size() && !m_transfers[offset].m_key_image_request)
      ++offset;
  }

  ski.reserve(m_transfers.size() - offset);
  for (size_t n = offset; n < m_transfers.size(); ++n)
  {
    const transfer_details &td = m_transfers[n];

    // get ephemeral public key
    const cryptonote::tx_out &out = td.m_tx.vout[td.m_internal_output_index];
    THROW_WALLET_EXCEPTION_IF(out.target.type() != typeid(txout_to_key), error::wallet_internal_error,
        "Output is not txout_to_key");
    const cryptonote::txout_to_key &o = boost::get<const cryptonote::txout_to_key>(out.target);
    const crypto::public_key pkey = o.key;

    // get tx pub key
    std::vector<tx_extra_field> tx_extra_fields;
    if(!parse_tx_extra(td.m_tx.extra, tx_extra_fields))
    {
      // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
    }

    crypto::public_key tx_pub_key = get_tx_pub_key_from_received_outs(td);
    const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);

    // generate ephemeral secret key
    crypto::key_image ki;
    cryptonote::keypair in_ephemeral;
    bool r = cryptonote::generate_key_image_helper(m_account.get_keys(), m_subaddresses, pkey, tx_pub_key, additional_tx_pub_keys, td.m_internal_output_index, in_ephemeral, ki, m_account.get_device());
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");

    THROW_WALLET_EXCEPTION_IF(td.m_key_image_known && !td.m_key_image_partial && ki != td.m_key_image,
        error::wallet_internal_error, "key_image generated not matched with cached key image");
    THROW_WALLET_EXCEPTION_IF(in_ephemeral.pub != pkey,
        error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key");

    // sign the key image with the output secret key
    crypto::signature signature;
    std::vector<const crypto::public_key*> key_ptrs;
    key_ptrs.push_back(&pkey);

    crypto::generate_ring_signature((const crypto::hash&)td.m_key_image, td.m_key_image, key_ptrs, in_ephemeral.sec, 0, &signature);

    ski.push_back(std::make_pair(td.m_key_image, signature));
  }
  return std::make_pair(offset, ski);
}

uint64_t wallet2::import_key_images(const std::string &filename, uint64_t &spent, uint64_t &unspent)
{
  PERF_TIMER(import_key_images_fsu);
  std::string data;
  bool r = load_from_file(filename, data);

  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, std::string(tr("failed to read file ")) + filename);

  const size_t magiclen = strlen(KEY_IMAGE_EXPORT_FILE_MAGIC);
  if (data.size() < magiclen || memcmp(data.data(), KEY_IMAGE_EXPORT_FILE_MAGIC, magiclen))
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Bad key image export file magic in ") + filename);
  }

  try
  {
    PERF_TIMER(import_key_images_decrypt);
    data = decrypt_with_view_secret_key(std::string(data, magiclen));
  }
  catch (const std::exception &e)
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Failed to decrypt ") + filename + ": " + e.what());
  }

  const size_t headerlen = 4 + 2 * sizeof(crypto::public_key);
  THROW_WALLET_EXCEPTION_IF(data.size() < headerlen, error::wallet_internal_error, std::string("Bad data size from file ") + filename);
  const uint32_t offset = (uint8_t)data[0] | (((uint8_t)data[1]) << 8) | (((uint8_t)data[2]) << 16) | (((uint8_t)data[3]) << 24);
  const crypto::public_key &public_spend_key = *(const crypto::public_key*)&data[4];
  const crypto::public_key &public_view_key = *(const crypto::public_key*)&data[4 + sizeof(crypto::public_key)];
  const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
  if (public_spend_key != keys.m_spend_public_key || public_view_key != keys.m_view_public_key)
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string( "Key images from ") + filename + " are for a different account");
  }
  THROW_WALLET_EXCEPTION_IF(offset > m_transfers.size(), error::wallet_internal_error, "Offset larger than known outputs");

  const size_t record_size = sizeof(crypto::key_image) + sizeof(crypto::signature);
  THROW_WALLET_EXCEPTION_IF((data.size() - headerlen) % record_size,
      error::wallet_internal_error, std::string("Bad data size from file ") + filename);
  size_t nki = (data.size() - headerlen) / record_size;

  std::vector<std::pair<crypto::key_image, crypto::signature>> ski;
  ski.reserve(nki);
  for (size_t n = 0; n < nki; ++n)
  {
    crypto::key_image key_image = *reinterpret_cast<const crypto::key_image*>(&data[headerlen + n * record_size]);
    crypto::signature signature = *reinterpret_cast<const crypto::signature*>(&data[headerlen + n * record_size + sizeof(crypto::key_image)]);

    ski.push_back(std::make_pair(key_image, signature));
  }
  
  return import_key_images(ski, offset, spent, unspent);
}

//----------------------------------------------------------------------------------------------------
uint64_t wallet2::import_key_images(const std::vector<std::pair<crypto::key_image, crypto::signature>> &signed_key_images, size_t offset, uint64_t &spent, uint64_t &unspent, bool check_spent)
{
  PERF_TIMER(import_key_images_lots);
  COMMAND_RPC_IS_KEY_IMAGE_SPENT::request req = AUTO_VAL_INIT(req);
  COMMAND_RPC_IS_KEY_IMAGE_SPENT::response daemon_resp = AUTO_VAL_INIT(daemon_resp);

  THROW_WALLET_EXCEPTION_IF(offset > m_transfers.size(), error::wallet_internal_error, "Offset larger than known outputs");
  THROW_WALLET_EXCEPTION_IF(signed_key_images.size() > m_transfers.size() - offset, error::wallet_internal_error,
      "The blockchain is out of date compared to the signed key images");

  if (signed_key_images.empty() && offset == 0)
  {
    spent = 0;
    unspent = 0;
    return 0;
  }

  req.key_images.reserve(signed_key_images.size());

  PERF_TIMER_START(import_key_images_A);
  for (size_t n = 0; n < signed_key_images.size(); ++n)
  {
    const transfer_details &td = m_transfers[n + offset];
    const crypto::key_image &key_image = signed_key_images[n].first;
    const crypto::signature &signature = signed_key_images[n].second;

    // get ephemeral public key
    const cryptonote::tx_out &out = td.m_tx.vout[td.m_internal_output_index];
    THROW_WALLET_EXCEPTION_IF(out.target.type() != typeid(txout_to_key), error::wallet_internal_error,
      "Non txout_to_key output found");
    const cryptonote::txout_to_key &o = boost::get<cryptonote::txout_to_key>(out.target);
    const crypto::public_key pkey = o.key;

    if (!td.m_key_image_known || !(key_image == td.m_key_image))
    {
      std::vector<const crypto::public_key*> pkeys;
      pkeys.push_back(&pkey);
      THROW_WALLET_EXCEPTION_IF(!(rct::scalarmultKey(rct::ki2rct(key_image), rct::curveOrder()) == rct::identity()),
          error::wallet_internal_error, "Key image out of validity domain: input " + boost::lexical_cast<std::string>(n + offset) + "/"
          + boost::lexical_cast<std::string>(signed_key_images.size()) + ", key image " + epee::string_tools::pod_to_hex(key_image));

      THROW_WALLET_EXCEPTION_IF(!crypto::check_ring_signature((const crypto::hash&)key_image, key_image, pkeys, &signature),
          error::signature_check_failed, boost::lexical_cast<std::string>(n + offset) + "/"
          + boost::lexical_cast<std::string>(signed_key_images.size()) + ", key image " + epee::string_tools::pod_to_hex(key_image)
          + ", signature " + epee::string_tools::pod_to_hex(signature) + ", pubkey " + epee::string_tools::pod_to_hex(*pkeys[0]));
    }
    req.key_images.push_back(epee::string_tools::pod_to_hex(key_image));
  }
  PERF_TIMER_STOP(import_key_images_A);

  PERF_TIMER_START(import_key_images_B);
  for (size_t n = 0; n < signed_key_images.size(); ++n)
  {
    m_transfers[n + offset].m_key_image = signed_key_images[n].first;
    m_key_images[m_transfers[n + offset].m_key_image] = n + offset;
    m_transfers[n + offset].m_key_image_known = true;
    m_transfers[n + offset].m_key_image_request = false;
    m_transfers[n + offset].m_key_image_partial = false;
  }
  PERF_TIMER_STOP(import_key_images_B);

  if(check_spent)
  {
    PERF_TIMER(import_key_images_RPC);
    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      uint64_t pre_call_credits = m_rpc_payment_state.credits;
      req.client = get_client_signature();
      bool r = epee::net_utils::invoke_http_json("/is_key_image_spent", req, daemon_resp, *m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {},  daemon_resp, "is_key_image_spent");
      THROW_WALLET_EXCEPTION_IF(daemon_resp.spent_status.size() != signed_key_images.size(), error::wallet_internal_error,
        "daemon returned wrong response for is_key_image_spent, wrong amounts count = " +
        std::to_string(daemon_resp.spent_status.size()) + ", expected " +  std::to_string(signed_key_images.size()));
      check_rpc_cost("/is_key_image_spent", daemon_resp.credits, pre_call_credits, daemon_resp.spent_status.size() * COST_PER_KEY_IMAGE);
    }

    for (size_t n = 0; n < daemon_resp.spent_status.size(); ++n)
    {
      transfer_details &td = m_transfers[n + offset];
      td.m_spent = daemon_resp.spent_status[n] != COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT;
    }
  }
  spent = 0;
  unspent = 0;
  std::unordered_set<crypto::hash> spent_txids;   // For each spent key image, search for a tx in m_transfers that uses it as input.
  std::vector<size_t> swept_transfers;            // If such a spending tx wasn't found in m_transfers, this means the spending tx 
                                                  // was created by sweep_all, so we can't know the spent height and other detailed info.
  std::unordered_map<crypto::key_image, crypto::hash> spent_key_images;

  PERF_TIMER_START(import_key_images_C);
  for (const transfer_details &td: m_transfers)
  {
    for (const cryptonote::txin_v& in : td.m_tx.vin)
    {
      if (in.type() == typeid(cryptonote::txin_to_key))
        spent_key_images.insert(std::make_pair(boost::get<cryptonote::txin_to_key>(in).k_image, td.m_txid));
    }
  }
  PERF_TIMER_STOP(import_key_images_C);

  // accumulate outputs before the updated data
  for(size_t i = 0; i < offset; ++i)
  {
    const transfer_details &td = m_transfers[i];
    if (td.m_frozen)
      continue;
    uint64_t amount = td.amount();
    if (td.m_spent)
      spent += amount;
    else
      unspent += amount;
  }

  PERF_TIMER_START(import_key_images_D);
  for(size_t i = 0; i < signed_key_images.size(); ++i)
  {
    const transfer_details &td = m_transfers[i + offset];
    if (td.m_frozen)
      continue;
    uint64_t amount = td.amount();
    if (td.m_spent)
      spent += amount;
    else
      unspent += amount;
    LOG_PRINT_L2("Transfer " << i << ": " << print_money(amount) << " (" << td.m_global_output_index << "): "
        << (td.m_spent ? "spent" : "unspent") << " (key image " << req.key_images[i] << ")");

    if (i < daemon_resp.spent_status.size() && daemon_resp.spent_status[i] == COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_BLOCKCHAIN)
    {
      const std::unordered_map<crypto::key_image, crypto::hash>::const_iterator skii = spent_key_images.find(td.m_key_image);
      if (skii == spent_key_images.end())
        swept_transfers.push_back(i);
      else
        spent_txids.insert(skii->second);
    }
  }
  PERF_TIMER_STOP(import_key_images_D);

  MDEBUG("Total: " << print_money(spent) << " spent, " << print_money(unspent) << " unspent");

  if (check_spent)
  {
    // query outgoing txes
    COMMAND_RPC_GET_TRANSACTIONS::request gettxs_req;
    COMMAND_RPC_GET_TRANSACTIONS::response gettxs_res;
    gettxs_req.decode_as_json = false;
    gettxs_req.prune = true;
    gettxs_req.txs_hashes.reserve(spent_txids.size());
    for (const crypto::hash& spent_txid : spent_txids)
      gettxs_req.txs_hashes.push_back(epee::string_tools::pod_to_hex(spent_txid));


    PERF_TIMER_START(import_key_images_E);
    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      gettxs_req.client = get_client_signature();
      uint64_t pre_call_credits = m_rpc_payment_state.credits;
      bool r = epee::net_utils::invoke_http_json("/gettransactions", gettxs_req, gettxs_res, *m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, gettxs_res, "gettransactions");
      THROW_WALLET_EXCEPTION_IF(gettxs_res.txs.size() != spent_txids.size(), error::wallet_internal_error,
        "daemon returned wrong response for gettransactions, wrong count = " + std::to_string(gettxs_res.txs.size()) + ", expected " + std::to_string(spent_txids.size()));
      check_rpc_cost("/gettransactions", gettxs_res.credits, pre_call_credits, spent_txids.size() * COST_PER_TX);
    }
    PERF_TIMER_STOP(import_key_images_E);

    // process each outgoing tx
    PERF_TIMER_START(import_key_images_F);
    auto spent_txid = spent_txids.begin();
    hw::device &hwdev =  m_account.get_device();
    auto it = spent_txids.begin();
    for (const COMMAND_RPC_GET_TRANSACTIONS::entry& e : gettxs_res.txs)
    {
      THROW_WALLET_EXCEPTION_IF(e.in_pool, error::wallet_internal_error, "spent tx isn't supposed to be in txpool");

      cryptonote::transaction spent_tx;
      crypto::hash spnet_txid_parsed;
      THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(e, spent_tx, spnet_txid_parsed), error::wallet_internal_error, "Failed to get tx from daemon");
      THROW_WALLET_EXCEPTION_IF(!(spnet_txid_parsed == *it), error::wallet_internal_error, "parsed txid mismatch");
      ++it;

      // get received (change) amount
      uint64_t tx_money_got_in_outs = 0;
      const cryptonote::account_keys& keys = m_account.get_keys();
      const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(spent_tx);
      crypto::key_derivation derivation;
      bool r = hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation);
      THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
      const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(spent_tx);
      std::vector<crypto::key_derivation> additional_derivations;
      for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
      {
        additional_derivations.push_back({});
        r = hwdev.generate_key_derivation(additional_tx_pub_keys[i], keys.m_view_secret_key, additional_derivations.back());
        THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
      }
      size_t output_index = 0;
      bool miner_tx = cryptonote::is_coinbase(spent_tx);
      for (const cryptonote::tx_out& out : spent_tx.vout)
      {
        tx_scan_info_t tx_scan_info;
        check_acc_out_precomp(out, derivation, additional_derivations, output_index, tx_scan_info);
        THROW_WALLET_EXCEPTION_IF(tx_scan_info.error, error::wallet_internal_error, "check_acc_out_precomp failed");
        if (tx_scan_info.received)
        {
          if (tx_scan_info.money_transfered == 0 && !miner_tx)
          {
            rct::key mask;
            tx_scan_info.money_transfered = tools::decodeRct(spent_tx.rct_signatures, tx_scan_info.received->derivation, output_index, mask, hwdev);
          }
          THROW_WALLET_EXCEPTION_IF(tx_money_got_in_outs >= std::numeric_limits<uint64_t>::max() - tx_scan_info.money_transfered,
              error::wallet_internal_error, "Overflow in received amounts");
          tx_money_got_in_outs += tx_scan_info.money_transfered;
        }
        ++output_index;
      }

      // get spent amount
      uint64_t tx_money_spent_in_ins = 0;
      uint32_t subaddr_account = (uint32_t)-1;
      std::set<uint32_t> subaddr_indices;
      for (const cryptonote::txin_v& in : spent_tx.vin)
      {
        if (in.type() != typeid(cryptonote::txin_to_key))
          continue;
        auto it = m_key_images.find(boost::get<cryptonote::txin_to_key>(in).k_image);
        if (it != m_key_images.end())
        {
          THROW_WALLET_EXCEPTION_IF(it->second >= m_transfers.size(), error::wallet_internal_error, std::string("Key images cache contains illegal transfer offset: ") + std::to_string(it->second) + std::string(" m_transfers.size() = ") + std::to_string(m_transfers.size()));
          const transfer_details& td = m_transfers[it->second];
          uint64_t amount = boost::get<cryptonote::txin_to_key>(in).amount;
          if (amount > 0)
          {
            THROW_WALLET_EXCEPTION_IF(amount != td.amount(), error::wallet_internal_error,
                std::string("Inconsistent amount in tx input: got ") + print_money(amount) +
                std::string(", expected ") + print_money(td.amount()));
          }
          amount = td.amount();
          tx_money_spent_in_ins += amount;

          LOG_PRINT_L0("Spent money: " << print_money(amount) << ", with tx: " << *spent_txid);
          set_spent(it->second, e.block_height);
          if (m_callback)
            m_callback->on_money_spent(e.block_height, *spent_txid, spent_tx, amount, spent_tx, td.m_subaddr_index);
          if (subaddr_account != (uint32_t)-1 && subaddr_account != td.m_subaddr_index.major)
            LOG_PRINT_L0("WARNING: This tx spends outputs received by different subaddress accounts, which isn't supposed to happen");
          subaddr_account = td.m_subaddr_index.major;
          subaddr_indices.insert(td.m_subaddr_index.minor);
        }
      }

      // create outgoing payment
      process_outgoing(*spent_txid, spent_tx, e.block_height, e.block_timestamp, tx_money_spent_in_ins, tx_money_got_in_outs, subaddr_account, subaddr_indices);

      // erase corresponding incoming payment
      for (auto j = m_payments.begin(); j != m_payments.end(); ++j)
      {
        if (j->second.m_tx_hash == *spent_txid)
        {
          m_payments.erase(j);
          break;
        }
      }

      ++spent_txid;
    }
    PERF_TIMER_STOP(import_key_images_F);

    PERF_TIMER_START(import_key_images_G);
    for (size_t n : swept_transfers)
    {
      const transfer_details& td = m_transfers[n];
      confirmed_transfer_details pd;
      pd.m_change = (uint64_t)-1;                             // change is unknown
      pd.m_amount_in = pd.m_amount_out = td.amount();         // fee is unknown
      pd.m_block_height = 0;  // spent block height is unknown
      const crypto::hash &spent_txid = crypto::null_hash; // spent txid is unknown
      m_confirmed_txs.insert(std::make_pair(spent_txid, pd));
    }
    PERF_TIMER_STOP(import_key_images_G);
  }

  // this can be 0 if we do not know the height
  return m_transfers[signed_key_images.size() + offset - 1].m_block_height;
}

bool wallet2::import_key_images(std::vector<crypto::key_image> key_images, size_t offset, boost::optional<std::unordered_set<size_t>> selected_transfers)
{
  if (key_images.size() + offset > m_transfers.size())
  {
    LOG_PRINT_L1("More key images returned that we know outputs for");
    return false;
  }
  for (size_t ki_idx = 0; ki_idx < key_images.size(); ++ki_idx)
  {
    const size_t transfer_idx = ki_idx + offset;
    if (selected_transfers && selected_transfers.get().find(transfer_idx) == selected_transfers.get().end())
      continue;

    transfer_details &td = m_transfers[transfer_idx];
    if (td.m_key_image_known && !td.m_key_image_partial && td.m_key_image != key_images[ki_idx])
      LOG_PRINT_L0("WARNING: imported key image differs from previously known key image at index " << ki_idx << ": trusting imported one");
    td.m_key_image = key_images[ki_idx];
    m_key_images[td.m_key_image] = transfer_idx;
    td.m_key_image_known = true;
    td.m_key_image_request = false;
    td.m_key_image_partial = false;
    m_pub_keys[td.get_public_key()] = transfer_idx;
  }

  return true;
}

bool wallet2::import_key_images(signed_tx_set & signed_tx, size_t offset, bool only_selected_transfers)
{
  std::unordered_set<size_t> selected_transfers;
  if (only_selected_transfers)
  {
    for (const pending_tx & ptx : signed_tx.ptx)
    {
      for (const size_t s: ptx.selected_transfers)
        selected_transfers.insert(s);
    }
  }

  return import_key_images(signed_tx.key_images, offset, only_selected_transfers ? boost::make_optional(selected_transfers) : boost::none);
}

wallet2::payment_container wallet2::export_payments() const
{
  payment_container payments;
  for (auto const &p : m_payments)
  {
    payments.emplace(p);
  }
  return payments;
}
void wallet2::import_payments(const payment_container &payments)
{
  m_payments.clear();
  for (auto const &p : payments)
  {
    m_payments.emplace(p);
  }
}
void wallet2::import_payments_out(const std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_details>> &confirmed_payments)
{
  m_confirmed_txs.clear();
  for (auto const &p : confirmed_payments)
  {
    m_confirmed_txs.emplace(p);
  }
}

std::tuple<size_t,crypto::hash,std::vector<crypto::hash>> wallet2::export_blockchain() const
{
  std::tuple<size_t, crypto::hash, std::vector<crypto::hash>> bc;
  std::get<0>(bc) = m_blockchain.offset();
  std::get<1>(bc) = m_blockchain.empty() ? crypto::null_hash: m_blockchain.genesis();
  for (size_t n = m_blockchain.offset(); n < m_blockchain.size(); ++n)
  {
    std::get<2>(bc).push_back(m_blockchain[n]);
  }
  return bc;
}

void wallet2::import_blockchain(const std::tuple<size_t, crypto::hash, std::vector<crypto::hash>> &bc)
{
  m_blockchain.clear();
  if (std::get<0>(bc))
  {
    for (size_t n = std::get<0>(bc); n > 0; --n)
      m_blockchain.push_back(std::get<1>(bc));
    m_blockchain.trim(std::get<0>(bc));
  }
  for (auto const &b : std::get<2>(bc))
  {
    m_blockchain.push_back(b);
  }
  cryptonote::block genesis;
  generate_genesis(genesis);
  crypto::hash genesis_hash = get_block_hash(genesis);
  check_genesis(genesis_hash);
  m_last_block_reward = cryptonote::get_outs_money_amount(genesis.miner_tx);
}
//----------------------------------------------------------------------------------------------------
std::pair<uint64_t, std::vector<tools::wallet2::transfer_details>> wallet2::export_outputs(bool all) const
{
  PERF_TIMER(export_outputs);
  std::vector<tools::wallet2::transfer_details> outs;

  size_t offset = 0;
  if (!all)
    while (offset < m_transfers.size() && (m_transfers[offset].m_key_image_known && !m_transfers[offset].m_key_image_request))
      ++offset;

  outs.reserve(m_transfers.size() - offset);
  for (size_t n = offset; n < m_transfers.size(); ++n)
  {
    const transfer_details &td = m_transfers[n];

    outs.push_back(td);
  }

  return std::make_pair(offset, outs);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::export_outputs_to_str(bool all) const
{
  PERF_TIMER(export_outputs_to_str);

  std::stringstream oss;
  binary_archive<true> ar(oss);
  auto outputs = export_outputs(all);
  THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, outputs), error::wallet_internal_error, "Failed to serialize output data");

  std::string magic(OUTPUT_EXPORT_FILE_MAGIC, strlen(OUTPUT_EXPORT_FILE_MAGIC));
  const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
  std::string header;
  header += std::string((const char *)&keys.m_spend_public_key, sizeof(crypto::public_key));
  header += std::string((const char *)&keys.m_view_public_key, sizeof(crypto::public_key));
  PERF_TIMER(export_outputs_encryption);
  std::string ciphertext = encrypt_with_view_secret_key(header + oss.str());
  return magic + ciphertext;
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::import_outputs(const std::pair<uint64_t, std::vector<tools::wallet2::transfer_details>> &outputs)
{
  PERF_TIMER(import_outputs);

  THROW_WALLET_EXCEPTION_IF(outputs.first > m_transfers.size(), error::wallet_internal_error,
      "Imported outputs omit more outputs that we know of");

  const size_t offset = outputs.first;
  const size_t original_size = m_transfers.size();
  m_transfers.resize(offset + outputs.second.size());
  for (size_t i = 0; i < offset; ++i)
    m_transfers[i].m_key_image_request = false;
  for (size_t i = 0; i < outputs.second.size(); ++i)
  {
    transfer_details td = outputs.second[i];

    // skip those we've already imported, or which have different data
    if (i + offset < original_size)
    {
      // compare the data used to create the key image below
      const transfer_details &org_td = m_transfers[i + offset];
      if (!org_td.m_key_image_known)
        goto process;
#define CMPF(f) if (!(td.f == org_td.f)) goto process
      CMPF(m_txid);
      CMPF(m_key_image);
      CMPF(m_internal_output_index);
#undef CMPF
      if (!(get_transaction_prefix_hash(td.m_tx) == get_transaction_prefix_hash(org_td.m_tx)))
        goto process;

      // copy anyway, since the comparison does not include ancillary fields which may have changed
      m_transfers[i + offset] = std::move(td);
      continue;
    }

process:

    // the hot wallet wouldn't have known about key images (except if we already exported them)
    cryptonote::keypair in_ephemeral;

    THROW_WALLET_EXCEPTION_IF(td.m_tx.vout.empty(), error::wallet_internal_error, "tx with no outputs at index " + boost::lexical_cast<std::string>(i + offset));
    crypto::public_key tx_pub_key = get_tx_pub_key_from_received_outs(td);
    const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);

    THROW_WALLET_EXCEPTION_IF(td.m_internal_output_index >= td.m_tx.vout.size(),
        error::wallet_internal_error, "Internal index is out of range");
    THROW_WALLET_EXCEPTION_IF(td.m_tx.vout[td.m_internal_output_index].target.type() != typeid(cryptonote::txout_to_key),
        error::wallet_internal_error, "Unsupported output type");
    const crypto::public_key& out_key = boost::get<cryptonote::txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key;
    bool r = cryptonote::generate_key_image_helper(m_account.get_keys(), m_subaddresses, out_key, tx_pub_key, additional_tx_pub_keys, td.m_internal_output_index, in_ephemeral, td.m_key_image, m_account.get_device());
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
    if (should_expand(td.m_subaddr_index))
      expand_subaddresses(td.m_subaddr_index);
    td.m_key_image_known = true;
    td.m_key_image_request = true;
    td.m_key_image_partial = false;
    THROW_WALLET_EXCEPTION_IF(in_ephemeral.pub != out_key,
        error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key at index " + boost::lexical_cast<std::string>(i + offset));

    m_key_images[td.m_key_image] = i + offset;
    m_pub_keys[td.get_public_key()] = i + offset;
    m_transfers[i + offset] = std::move(td);
  }

  return m_transfers.size();
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::import_outputs_from_str(const std::string &outputs_st)
{
  PERF_TIMER(import_outputs_from_str);
  std::string data = outputs_st;
  const size_t magiclen = strlen(OUTPUT_EXPORT_FILE_MAGIC);
  if (data.size() < magiclen || memcmp(data.data(), OUTPUT_EXPORT_FILE_MAGIC, magiclen))
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Bad magic from outputs"));
  }

  try
  {
    PERF_TIMER(import_outputs_decrypt);
    data = decrypt_with_view_secret_key(std::string(data, magiclen));
  }
  catch (const std::exception &e)
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Failed to decrypt outputs: ") + e.what());
  }

  const size_t headerlen = 2 * sizeof(crypto::public_key);
  if (data.size() < headerlen)
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Bad data size for outputs"));
  }
  const crypto::public_key &public_spend_key = *(const crypto::public_key*)&data[0];
  const crypto::public_key &public_view_key = *(const crypto::public_key*)&data[sizeof(crypto::public_key)];
  const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
  if (public_spend_key != keys.m_spend_public_key || public_view_key != keys.m_view_public_key)
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Outputs from are for a different account"));
  }

  size_t imported_outputs = 0;
  bool loaded = false;
  try
  {
    std::string body(data, headerlen);
    std::pair<uint64_t, std::vector<tools::wallet2::transfer_details>> outputs;
    try
    {
      std::stringstream iss;
      iss << body;
      binary_archive<false> ar(iss);
      if (::serialization::serialize(ar, outputs))
        if (::serialization::check_stream_state(ar))
          loaded = true;
    }
    catch (...) {}

    if (!loaded && m_load_deprecated_formats)
    {
      try
      {
        std::stringstream iss;
        iss << body;
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> outputs;
        loaded = true;
      }
      catch (...) {}
    }

    if (!loaded)
    {
      outputs.first = 0;
      outputs.second = {};
    }

    imported_outputs = import_outputs(outputs);
  }
  catch (const std::exception &e)
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Failed to import outputs") + e.what());
  }

  return imported_outputs;
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::encrypt(const char *plaintext, size_t len, const crypto::secret_key &skey, bool authenticated) const
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(&skey, sizeof(skey), key, m_kdf_rounds);
  std::string ciphertext;
  crypto::chacha_iv iv = crypto::rand<crypto::chacha_iv>();
  ciphertext.resize(len + sizeof(iv) + (authenticated ? sizeof(crypto::signature) : 0));
  crypto::chacha20(plaintext, len, key, iv, &ciphertext[sizeof(iv)]);
  memcpy(&ciphertext[0], &iv, sizeof(iv));
  if (authenticated)
  {
    crypto::hash hash;
    crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(signature), hash);
    crypto::public_key pkey;
    crypto::secret_key_to_public_key(skey, pkey);
    crypto::signature &signature = *(crypto::signature*)&ciphertext[ciphertext.size() - sizeof(crypto::signature)];
    crypto::generate_signature(hash, pkey, skey, signature);
  }
  return ciphertext;
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::encrypt(const epee::span<char> &plaintext, const crypto::secret_key &skey, bool authenticated) const
{
  return encrypt(plaintext.data(), plaintext.size(), skey, authenticated);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::encrypt(const std::string &plaintext, const crypto::secret_key &skey, bool authenticated) const
{
  return encrypt(plaintext.data(), plaintext.size(), skey, authenticated);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::encrypt(const epee::wipeable_string &plaintext, const crypto::secret_key &skey, bool authenticated) const
{
  return encrypt(plaintext.data(), plaintext.size(), skey, authenticated);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::encrypt_with_view_secret_key(const std::string &plaintext, bool authenticated) const
{
  return encrypt(plaintext, get_account().get_keys().m_view_secret_key, authenticated);
}
//----------------------------------------------------------------------------------------------------
template<typename T>
T wallet2::decrypt(const std::string &ciphertext, const crypto::secret_key &skey, bool authenticated) const
{
  const size_t prefix_size = sizeof(chacha_iv) + (authenticated ? sizeof(crypto::signature) : 0);
  THROW_WALLET_EXCEPTION_IF(ciphertext.size() < prefix_size,
    error::wallet_internal_error, "Unexpected ciphertext size");

  crypto::chacha_key key;
  crypto::generate_chacha_key(&skey, sizeof(skey), key, m_kdf_rounds);
  const crypto::chacha_iv &iv = *(const crypto::chacha_iv*)&ciphertext[0];
  if (authenticated)
  {
    crypto::hash hash;
    crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(signature), hash);
    crypto::public_key pkey;
    crypto::secret_key_to_public_key(skey, pkey);
    const crypto::signature &signature = *(const crypto::signature*)&ciphertext[ciphertext.size() - sizeof(crypto::signature)];
    THROW_WALLET_EXCEPTION_IF(!crypto::check_signature(hash, pkey, signature),
      error::wallet_internal_error, "Failed to authenticate ciphertext");
  }
  std::unique_ptr<char[]> buffer{new char[ciphertext.size() - prefix_size]};
  auto wiper = epee::misc_utils::create_scope_leave_handler([&]() { memwipe(buffer.get(), ciphertext.size() - prefix_size); });
  crypto::chacha20(ciphertext.data() + sizeof(iv), ciphertext.size() - prefix_size, key, iv, buffer.get());
  return T(buffer.get(), ciphertext.size() - prefix_size);
}
//----------------------------------------------------------------------------------------------------
template epee::wipeable_string wallet2::decrypt(const std::string &ciphertext, const crypto::secret_key &skey, bool authenticated) const;
//----------------------------------------------------------------------------------------------------
std::string wallet2::decrypt_with_view_secret_key(const std::string &ciphertext, bool authenticated) const
{
  return decrypt(ciphertext, get_account().get_keys().m_view_secret_key, authenticated);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) const
{
  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, nettype(), address))
  {
    error = std::string("wrong address: ") + address;
    return std::string();
  }

  // we want only one payment id
  if (info.has_payment_id && !payment_id.empty())
  {
    error = "A single payment id is allowed";
    return std::string();
  }

  if (!payment_id.empty())
  {
    crypto::hash pid32;
    if (!wallet2::parse_long_payment_id(payment_id, pid32))
    {
      error = "Invalid payment id";
      return std::string();
    }
  }

  std::string uri = "monero:" + address;
  unsigned int n_fields = 0;

  if (!payment_id.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("tx_payment_id=") + payment_id;
  }

  if (amount > 0)
  {
    // URI encoded amount is in decimal units, not atomic units
    uri += (n_fields++ ? "&" : "?") + std::string("tx_amount=") + cryptonote::print_money(amount);
  }

  if (!recipient_name.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("recipient_name=") + epee::net_utils::conver_to_url_format(recipient_name);
  }

  if (!tx_description.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("tx_description=") + epee::net_utils::conver_to_url_format(tx_description);
  }

  return uri;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_uri(const std::string &uri, std::string &address, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error)
{
  if (uri.substr(0, 7) != "monero:")
  {
    error = std::string("URI has wrong scheme (expected \"monero:\"): ") + uri;
    return false;
  }

  std::string remainder = uri.substr(7);
  const char *ptr = strchr(remainder.c_str(), '?');
  address = ptr ? remainder.substr(0, ptr-remainder.c_str()) : remainder;

  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, nettype(), address))
  {
    error = std::string("URI has wrong address: ") + address;
    return false;
  }
  if (!strchr(remainder.c_str(), '?'))
    return true;

  std::vector<std::string> arguments;
  std::string body = remainder.substr(address.size() + 1);
  if (body.empty())
    return true;
  boost::split(arguments, body, boost::is_any_of("&"));
  std::set<std::string> have_arg;
  for (const auto &arg: arguments)
  {
    std::vector<std::string> kv;
    boost::split(kv, arg, boost::is_any_of("="));
    if (kv.size() != 2)
    {
      error = std::string("URI has wrong parameter: ") + arg;
      return false;
    }
    if (have_arg.find(kv[0]) != have_arg.end())
    {
      error = std::string("URI has more than one instance of " + kv[0]);
      return false;
    }
    have_arg.insert(kv[0]);

    if (kv[0] == "tx_amount")
    {
      amount = 0;
      if (!cryptonote::parse_amount(amount, kv[1]))
      {
        error = std::string("URI has invalid amount: ") + kv[1];
        return false;
      }
    }
    else if (kv[0] == "tx_payment_id")
    {
      if (info.has_payment_id)
      {
        error = "Separate payment id given with an integrated address";
        return false;
      }
      crypto::hash hash;
      if (!wallet2::parse_long_payment_id(kv[1], hash))
      {
        error = "Invalid payment id: " + kv[1];
        return false;
      }
      payment_id = kv[1];
    }
    else if (kv[0] == "recipient_name")
    {
      recipient_name = epee::net_utils::convert_from_url_format(kv[1]);
    }
    else if (kv[0] == "tx_description")
    {
      tx_description = epee::net_utils::convert_from_url_format(kv[1]);
    }
    else
    {
      unknown_parameters.push_back(arg);
    }
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_blockchain_height_by_date(uint16_t year, uint8_t month, uint8_t day)
{
  uint32_t version;
  if (!check_connection(&version))
  {
    throw std::runtime_error("failed to connect to daemon: " + get_daemon_address());
  }
  if (version < MAKE_CORE_RPC_VERSION(1, 6))
  {
    throw std::runtime_error("this function requires RPC version 1.6 or higher");
  }
  std::tm date = { 0, 0, 0, 0, 0, 0, 0, 0 };
  date.tm_year = year - 1900;
  date.tm_mon  = month - 1;
  date.tm_mday = day;
  if (date.tm_mon < 0 || 11 < date.tm_mon || date.tm_mday < 1 || 31 < date.tm_mday)
  {
    throw std::runtime_error("month or day out of range");
  }
  uint64_t timestamp_target = std::mktime(&date);
  std::string err;
  uint64_t height_min = 0;
  uint64_t height_max = get_daemon_blockchain_height(err) - 1;
  if (!err.empty())
  {
    throw std::runtime_error("failed to get blockchain height");
  }
  while (true)
  {
    COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request req;
    COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response res;
    uint64_t height_mid = (height_min + height_max) / 2;
    req.heights =
    {
      height_min,
      height_mid,
      height_max
    };

    bool r;
    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      uint64_t pre_call_credits = m_rpc_payment_state.credits;
      req.client = get_client_signature();
      r = net_utils::invoke_http_bin("/getblocks_by_height.bin", req, res, *m_http_client, rpc_timeout);
      if (r && res.status == CORE_RPC_STATUS_OK)
        check_rpc_cost("/getblocks_by_height.bin", res.credits, pre_call_credits, 3 * COST_PER_BLOCK);
    }

    if (!r || res.status != CORE_RPC_STATUS_OK)
    {
      std::ostringstream oss;
      oss << "failed to get blocks by heights: ";
      for (auto height : req.heights)
        oss << height << ' ';
      oss << endl << "reason: ";
      if (!r)
        oss << "possibly lost connection to daemon";
      else if (res.status == CORE_RPC_STATUS_BUSY)
        oss << "daemon is busy";
      else
        oss << get_rpc_status(res.status);
      throw std::runtime_error(oss.str());
    }
    cryptonote::block blk_min, blk_mid, blk_max;
    if (res.blocks.size() < 3) throw std::runtime_error("Not enough blocks returned from daemon");
    if (!parse_and_validate_block_from_blob(res.blocks[0].block, blk_min)) throw std::runtime_error("failed to parse blob at height " + std::to_string(height_min));
    if (!parse_and_validate_block_from_blob(res.blocks[1].block, blk_mid)) throw std::runtime_error("failed to parse blob at height " + std::to_string(height_mid));
    if (!parse_and_validate_block_from_blob(res.blocks[2].block, blk_max)) throw std::runtime_error("failed to parse blob at height " + std::to_string(height_max));
    uint64_t timestamp_min = blk_min.timestamp;
    uint64_t timestamp_mid = blk_mid.timestamp;
    uint64_t timestamp_max = blk_max.timestamp;
    if (!(timestamp_min <= timestamp_mid && timestamp_mid <= timestamp_max))
    {
      // the timestamps are not in the chronological order. 
      // assuming they're sufficiently close to each other, simply return the smallest height
      return std::min({height_min, height_mid, height_max});
    }
    if (timestamp_target > timestamp_max)
    {
      throw std::runtime_error("specified date is in the future");
    }
    if (timestamp_target <= timestamp_min + 2 * 24 * 60 * 60)   // two days of "buffer" period
    {
      return height_min;
    }
    if (timestamp_target <= timestamp_mid)
      height_max = height_mid;
    else
      height_min = height_mid;
    if (height_max - height_min <= 2 * 24 * 30)        // don't divide the height range finer than two days
    {
      return height_min;
    }
  }
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_synced()
{
  uint64_t height;
  boost::optional<std::string> result = m_node_rpc_proxy.get_height(height);
  if (result && *result != CORE_RPC_STATUS_OK)
    return false;
  return get_blockchain_current_height() >= height;
}
//----------------------------------------------------------------------------------------------------
std::vector<std::pair<uint64_t, uint64_t>> wallet2::estimate_backlog(const std::vector<std::pair<double, double>> &fee_levels)
{
  for (const auto &fee_level: fee_levels)
  {
    THROW_WALLET_EXCEPTION_IF(fee_level.first == 0.0, error::wallet_internal_error, "Invalid 0 fee");
    THROW_WALLET_EXCEPTION_IF(fee_level.second == 0.0, error::wallet_internal_error, "Invalid 0 fee");
  }

  // get txpool backlog
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::request req = AUTO_VAL_INIT(req);
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::response res = AUTO_VAL_INIT(res);

  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    uint64_t pre_call_credits = m_rpc_payment_state.credits;
    req.client = get_client_signature();
    bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_txpool_backlog", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_txpool_backlog", error::get_tx_pool_error);
    check_rpc_cost("get_txpool_backlog", res.credits, pre_call_credits, COST_PER_TX_POOL_STATS * res.backlog.size());
  }

  uint64_t block_weight_limit = 0;
  const auto result = m_node_rpc_proxy.get_block_weight_limit(block_weight_limit);
  THROW_WALLET_EXCEPTION_IF(result, error::wallet_internal_error, "Invalid block weight limit from daemon");
  uint64_t full_reward_zone = block_weight_limit / 2;
  THROW_WALLET_EXCEPTION_IF(full_reward_zone == 0, error::wallet_internal_error, "Invalid block weight limit from daemon");

  std::vector<std::pair<uint64_t, uint64_t>> blocks;
  for (const auto &fee_level: fee_levels)
  {
    const double our_fee_byte_min = fee_level.first;
    const double our_fee_byte_max = fee_level.second;
    uint64_t priority_weight_min = 0, priority_weight_max = 0;
    for (const auto &i: res.backlog)
    {
      if (i.weight == 0)
      {
        MWARNING("Got 0 weight tx from txpool, ignored");
        continue;
      }
      double this_fee_byte = i.fee / (double)i.weight;
      if (this_fee_byte >= our_fee_byte_min)
        priority_weight_min += i.weight;
      if (this_fee_byte >= our_fee_byte_max)
        priority_weight_max += i.weight;
    }

    uint64_t nblocks_min = priority_weight_min / full_reward_zone;
    uint64_t nblocks_max = priority_weight_max / full_reward_zone;
    MDEBUG("estimate_backlog: priority_weight " << priority_weight_min << " - " << priority_weight_max << " for "
        << our_fee_byte_min << " - " << our_fee_byte_max << " piconero byte fee, "
        << nblocks_min << " - " << nblocks_max << " blocks at block weight " << full_reward_zone);
    blocks.push_back(std::make_pair(nblocks_min, nblocks_max));
  }
  return blocks;
}
//----------------------------------------------------------------------------------------------------
std::vector<std::pair<uint64_t, uint64_t>> wallet2::estimate_backlog(uint64_t min_tx_weight, uint64_t max_tx_weight, const std::vector<uint64_t> &fees)
{
  THROW_WALLET_EXCEPTION_IF(min_tx_weight == 0, error::wallet_internal_error, "Invalid 0 fee");
  THROW_WALLET_EXCEPTION_IF(max_tx_weight == 0, error::wallet_internal_error, "Invalid 0 fee");
  for (uint64_t fee: fees)
  {
    THROW_WALLET_EXCEPTION_IF(fee == 0, error::wallet_internal_error, "Invalid 0 fee");
  }
  std::vector<std::pair<double, double>> fee_levels;
  for (uint64_t fee: fees)
  {
    double our_fee_byte_min = fee / (double)min_tx_weight, our_fee_byte_max = fee / (double)max_tx_weight;
    fee_levels.emplace_back(our_fee_byte_min, our_fee_byte_max);
  }
  return estimate_backlog(fee_levels);
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_segregation_fork_height() const
{
  if (m_nettype == TESTNET)
    return TESTNET_SEGREGATION_FORK_HEIGHT;
  if (m_nettype == STAGENET)
    return STAGENET_SEGREGATION_FORK_HEIGHT;
  THROW_WALLET_EXCEPTION_IF(m_nettype != MAINNET, tools::error::wallet_internal_error, "Invalid network type");

  if (m_segregation_height > 0)
    return m_segregation_height;

  if (m_use_dns && !m_offline)
  {
    // All four MoneroPulse domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = {
        "segheights.moneropulse.org",
        "segheights.moneropulse.net",
        "segheights.moneropulse.co",
        "segheights.moneropulse.se"
    };

    const uint64_t current_height = get_blockchain_current_height();
    uint64_t best_diff = std::numeric_limits<uint64_t>::max(), best_height = 0;
    std::vector<std::string> records;
    if (tools::dns_utils::load_txt_records_from_dns(records, dns_urls))
    {
      for (const auto& record : records)
      {
        std::vector<std::string> fields;
        boost::split(fields, record, boost::is_any_of(":"));
        if (fields.size() != 2)
          continue;
        uint64_t height;
        if (!string_tools::get_xtype_from_string(height, fields[1]))
          continue;

        MINFO("Found segregation height via DNS: " << fields[0] << " fork height at " << height);
        uint64_t diff = height > current_height ? height - current_height : current_height - height;
        if (diff < best_diff)
        {
          best_diff = diff;
          best_height = height;
        }
      }
      if (best_height)
        return best_height;
    }
  }
  return SEGREGATION_FORK_HEIGHT;
}
//----------------------------------------------------------------------------------------------------
void wallet2::generate_genesis(cryptonote::block& b) const {
  cryptonote::generate_genesis_block(b, get_config(m_nettype).GENESIS_TX, get_config(m_nettype).GENESIS_NONCE);
}
//----------------------------------------------------------------------------------------------------
wallet_device_callback * wallet2::get_device_callback()
{
  if (!m_device_callback){
    m_device_callback.reset(new wallet_device_callback(this));
  }
  return m_device_callback.get();
}//----------------------------------------------------------------------------------------------------
void wallet2::on_device_button_request(uint64_t code)
{
  if (nullptr != m_callback)
    m_callback->on_device_button_request(code);
}
//----------------------------------------------------------------------------------------------------
void wallet2::on_device_button_pressed()
{
  if (nullptr != m_callback)
    m_callback->on_device_button_pressed();
}
//----------------------------------------------------------------------------------------------------
boost::optional<epee::wipeable_string> wallet2::on_device_pin_request()
{
  if (nullptr != m_callback)
    return m_callback->on_device_pin_request();
  return boost::none;
}
//----------------------------------------------------------------------------------------------------
boost::optional<epee::wipeable_string> wallet2::on_device_passphrase_request(bool & on_device)
{
  if (nullptr != m_callback)
    return m_callback->on_device_passphrase_request(on_device);
  else
    on_device = true;
  return boost::none;
}
//----------------------------------------------------------------------------------------------------
void wallet2::on_device_progress(const hw::device_progress& event)
{
  if (nullptr != m_callback)
    m_callback->on_device_progress(event);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_rpc_status(const std::string &s) const
{
  if (m_trusted_daemon)
    return s;
  if (s == CORE_RPC_STATUS_OK)
    return s;
  if (s == CORE_RPC_STATUS_BUSY || s == CORE_RPC_STATUS_PAYMENT_REQUIRED)
    return s;
  return "<error>";
}
//----------------------------------------------------------------------------------------------------
void wallet2::throw_on_rpc_response_error(bool r, const epee::json_rpc::error &error, const std::string &status, const char *method) const
{
  THROW_WALLET_EXCEPTION_IF(error.code, tools::error::wallet_coded_rpc_error, method, error.code, get_rpc_server_error_message(error.code));
  THROW_WALLET_EXCEPTION_IF(!r, tools::error::no_connection_to_daemon, method);
  // empty string -> not connection
  THROW_WALLET_EXCEPTION_IF(status.empty(), tools::error::no_connection_to_daemon, method);

  THROW_WALLET_EXCEPTION_IF(status == CORE_RPC_STATUS_BUSY, tools::error::daemon_busy, method);
  THROW_WALLET_EXCEPTION_IF(status == CORE_RPC_STATUS_PAYMENT_REQUIRED, tools::error::payment_required, method);
}
//----------------------------------------------------------------------------------------------------

bool wallet2::save_to_file(const std::string& path_to_file, const std::string& raw, bool is_printable) const
{
  if (is_printable || m_export_format == ExportFormat::Binary)
  {
    return epee::file_io_utils::save_string_to_file(path_to_file, raw);
  }

  FILE *fp = fopen(path_to_file.c_str(), "w+");
  if (!fp)
  {
    MERROR("Failed to open wallet file for writing: " << path_to_file << ": " << strerror(errno));
    return false;
  }

  // Save the result b/c we need to close the fp before returning success/failure.
  int write_result = PEM_write(fp, ASCII_OUTPUT_MAGIC.c_str(), "", (const unsigned char *) raw.c_str(), raw.length());
  fclose(fp);

  if (write_result == 0)
  {
    return false;
  }
  else
  {
    return true;
  }
}
//----------------------------------------------------------------------------------------------------

//----------------------------------------------------------------------------------------------------
void wallet2::hash_m_transfer(const transfer_details & transfer, crypto::hash &hash) const
{
  KECCAK_CTX state;
  keccak_init(&state);
  keccak_update(&state, (const uint8_t *) transfer.m_txid.data, sizeof(transfer.m_txid.data));
  keccak_update(&state, (const uint8_t *) &transfer.m_internal_output_index, sizeof(transfer.m_internal_output_index));
  keccak_update(&state, (const uint8_t *) &transfer.m_global_output_index, sizeof(transfer.m_global_output_index));
  keccak_update(&state, (const uint8_t *) &transfer.m_amount, sizeof(transfer.m_amount));
  keccak_finish(&state, (uint8_t *) hash.data);
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::hash_m_transfers(boost::optional<uint64_t> transfer_height, crypto::hash &hash) const
{
  CHECK_AND_ASSERT_THROW_MES(!transfer_height || *transfer_height <= m_transfers.size(), "Hash height is greater than number of transfers");

  KECCAK_CTX state;
  crypto::hash tmp_hash{};
  uint64_t current_height = 0;

  keccak_init(&state);
  for(const transfer_details & transfer : m_transfers){
    if (transfer_height && current_height >= *transfer_height){
      break;
    }

    hash_m_transfer(transfer, tmp_hash);
    keccak_update(&state, (const uint8_t *) &transfer.m_block_height, sizeof(transfer.m_block_height));
    keccak_update(&state, (const uint8_t *) tmp_hash.data, sizeof(tmp_hash.data));
    current_height += 1;
  }

  keccak_finish(&state, (uint8_t *) hash.data);
  return current_height;
}
//----------------------------------------------------------------------------------------------------
void wallet2::finish_rescan_bc_keep_key_images(uint64_t transfer_height, const crypto::hash &hash)
{
  // Compute hash of m_transfers, if differs there had to be BC reorg.
  if (transfer_height <= m_transfers.size()) {
    crypto::hash new_transfers_hash{};
    hash_m_transfers(transfer_height, new_transfers_hash);

    if (new_transfers_hash == hash) {
      // Restore key images in m_transfers from m_key_images
      for(auto it = m_key_images.begin(); it != m_key_images.end(); it++)
      {
        THROW_WALLET_EXCEPTION_IF(it->second >= m_transfers.size(),
                                  error::wallet_internal_error,
                                  "Key images cache contains illegal transfer offset");
        m_transfers[it->second].m_key_image = it->first;
        m_transfers[it->second].m_key_image_known = true;
      }

      return;
    }
  }

  // Soft-Reset to avoid inconsistency in case of BC reorg.
  clear_soft(false);  // keep_key_images works only with soft reset.
  THROW_WALLET_EXCEPTION_IF(true, error::wallet_internal_error, "Transfers changed during rescan, soft or hard rescan is needed");
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_bytes_sent() const
{
  return m_http_client->get_bytes_sent();
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_bytes_received() const
{
  return m_http_client->get_bytes_received();
}
//----------------------------------------------------------------------------------------------------
std::vector<cryptonote::public_node> wallet2::get_public_nodes(bool white_only)
{
  cryptonote::COMMAND_RPC_GET_PUBLIC_NODES::request req = AUTO_VAL_INIT(req);
  cryptonote::COMMAND_RPC_GET_PUBLIC_NODES::response res = AUTO_VAL_INIT(res);

  req.white = true;
  req.gray = !white_only;
  req.include_blocked = false;

  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    bool r = epee::net_utils::invoke_http_json("/get_public_nodes", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "/get_public_nodes");
  }

  std::vector<cryptonote::public_node> nodes;
  nodes = res.white;
  nodes.reserve(nodes.size() + res.gray.size());
  std::copy(res.gray.begin(), res.gray.end(), std::back_inserter(nodes));
  return nodes;
}

//----------------------------------------------------------------------------------------------------
}
