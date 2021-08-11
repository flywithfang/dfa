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
 
  const command_line::arg_descriptor<uint64_t> kdf_rounds = {"kdf-rounds", tools::wallet2::tr("Number of rounds for the key derivation function"), 1};

  const command_line::arg_descriptor<bool> offline = {"offline", tools::wallet2::tr("Do not connect to a daemon, nor use DNS"), false};
  const command_line::arg_descriptor<std::string> extra_entropy = {"extra-entropy", tools::wallet2::tr("File containing extra entropy to initialize the PRNG (any data, aim for 256 bits of entropy to be useful, which typically means more than 256 bits of data)")};
};


std::unique_ptr<tools::wallet2> make_basic(const boost::program_options::variables_map& vm, bool unattended, const options& opts, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const bool testnet = command_line::get_arg(vm, opts.testnet);
  const bool stagenet = command_line::get_arg(vm, opts.stagenet);
  const network_type nettype = testnet ? TESTNET : stagenet ? STAGENET : MAINNET;
  const uint64_t kdf_rounds = command_line::get_arg(vm, opts.kdf_rounds);
  throw_wallet_ex_if(kdf_rounds == 0, tools::error::wallet_internal_error, "KDF rounds must not be 0");

  const bool use_proxy = command_line::has_arg(vm, opts.proxy);
  auto daemon_address = command_line::get_arg(vm, opts.daemon_address);
  auto daemon_host = command_line::get_arg(vm, opts.daemon_host);
  auto daemon_port = command_line::get_arg(vm, opts.daemon_port);
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
      throw_wallet_ex_if(fpr.size() != SSL_FINGERPRINT_SIZE, tools::error::wallet_internal_error,
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
    throw_wallet_ex_if(!epee::net_utils::ssl_support_from_string(ssl_options.support, daemon_ssl), tools::error::wallet_internal_error,
       tools::wallet2::tr("Invalid argument for ") + std::string(opts.daemon_ssl.name));
  }

  ssl_options.auth = epee::net_utils::ssl_authentication_t{
    std::move(daemon_ssl_private_key), std::move(daemon_ssl_certificate)
  };

  throw_wallet_ex_if(!daemon_address.empty() && !daemon_host.empty() && 0 != daemon_port,
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

    throw_wallet_ex_if(
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
    throw_wallet_ex_if(
      !net::get_tcp_endpoint(proxy),
      tools::error::wallet_internal_error,
      std::string{"Invalid address specified for --"} + opts.proxy.name);
  }

 
  std::cout<<"daemon_address:"<<daemon_address<<std::endl;

  std::unique_ptr<tools::wallet2> wallet(new tools::wallet2(nettype, kdf_rounds, unattended));

  if (!wallet->init(std::move(daemon_address), std::move(login), std::move(proxy), 0, true, std::move(ssl_options)))
  {
    THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to initialize the wallet"));
  }

  if (command_line::get_arg(vm, opts.offline))
    wallet->set_offline();

  const std::string extra_entropy = command_line::get_arg(vm, opts.extra_entropy);
  if (!extra_entropy.empty())
  {
    std::string data;
    throw_wallet_ex_if(!epee::file_io_utils::load_file_to_string(extra_entropy, data),
        tools::error::wallet_internal_error, "Failed to load extra entropy from " + extra_entropy);
    add_extra_entropy_thread_safe(data.data(), data.size());
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
    throw_wallet_ex_if(!r, tools::error::wallet_internal_error, tools::wallet2::tr("the password file specified could not be read"));

    // Remove line breaks the user might have inserted
    boost::trim_right_if(password, boost::is_any_of("\r\n"));
    return {tools::password_container{std::move(password)}};
  }

  throw_wallet_ex_if(!password_prompter, tools::error::wallet_internal_error, tools::wallet2::tr("no password specified; use --prompt-for-password to prompt for a password"));

  return password_prompter(verify ? tools::wallet2::tr("Enter a new password for the wallet") : tools::wallet2::tr("Wallet password"), verify);
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
  throw_wallet_ex_if(rct_offsets.size() <= CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, error::wallet_internal_error, "Bad offset calculation");
  const size_t blocks_in_a_year = 86400 * 365 / DIFFICULTY_TARGET_V2;
  const size_t blocks_to_consider = std::min<size_t>(rct_offsets.size(), blocks_in_a_year);
  const size_t outputs_to_consider = rct_offsets.back() - (blocks_to_consider < rct_offsets.size() ? rct_offsets[rct_offsets.size() - blocks_to_consider - 1] : 0);
  begin = rct_offsets.data();
  end = rct_offsets.data() + rct_offsets.size() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
  num_rct_outputs = *(end - 1);
  throw_wallet_ex_if(num_rct_outputs == 0, error::wallet_internal_error, "No rct outputs");
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
  throw_wallet_ex_if(it == end, error::wallet_internal_error, "output_index not found");
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
  if (!locked  )
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


wallet2::wallet2(network_type nettype, uint64_t kdf_rounds, bool unattended, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory):
  m_http_client(http_client_factory->create()),
  m_upper_transaction_weight_limit(0),
  m_run(true),
  m_nettype(nettype),
  m_always_confirm_transfers(true),
  m_auto_refresh(true),
  m_first_refresh_done(false),
  m_refresh_from_block_height(0),
  m_explicit_refresh_from_block_height(true),
  m_max_reorg_depth(ORPHANED_BLOCKS_MAX_COUNT),
  m_inactivity_lock_timeout(DEFAULT_INACTIVITY_LOCK_TIMEOUT),
  m_is_initialized(false),
  m_kdf_rounds(kdf_rounds),
  m_node_rpc_proxy(*m_http_client, m_daemon_rpc_mutex),
  m_account_public_address{crypto::null_pkey, crypto::null_pkey},
  m_encrypt_keys_after_refresh(boost::none),
  m_decrypt_keys_lockers(0),
  m_offline(false),
  m_rpc_version(0)
{
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

void wallet2::init_options(boost::program_options::options_description& desc_params)
{
  const options opts{};
  command_line::add_arg(desc_params, opts.daemon_address);
  command_line::add_arg(desc_params, opts.daemon_host);
  command_line::add_arg(desc_params, opts.proxy);
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
  command_line::add_arg(desc_params, opts.kdf_rounds);
  command_line::add_arg(desc_params, opts.offline);
  command_line::add_arg(desc_params, opts.extra_entropy);
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
  if (changed)
  {
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
std::string wallet2::get_address_as_str() const
{
  cryptonote::account_public_address address = get_address();
  return cryptonote::get_account_address_as_str(m_nettype,  address);
}




//----------------------------------------------------------------------------------------------------
void wallet2::set_spent(size_t idx, uint64_t height)
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers_in.size(), "Invalid index");
  transfer_details &td = m_transfers_in[idx];
  MINFO("Setting SPENT at " << height << ": ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
  td.m_spent = true;
  td.m_spent_height = height;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_unspent(size_t idx)
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers_in.size(), "Invalid index");
  transfer_details &td = m_transfers_in[idx];
  MINFO("Setting UNSPENT: ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
  td.m_spent = false;
  td.m_spent_height = 0;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_spent(const transfer_details &td) const
{
    return td.m_spent;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_spent(size_t idx, bool strict) const
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers_in.size(), "Invalid index");
  const transfer_details &td = m_transfers_in[idx];
  return is_spent(td);
}


//----------------------------------------------------------------------------------------------------
size_t wallet2::get_transfer_details(const crypto::key_image &ki) const
{
  for (size_t idx = 0; idx < m_transfers_in.size(); ++idx)
  {
    const transfer_details &td = m_transfers_in[idx];
    if ( td.m_key_image == ki)
      return idx;
  }
  CHECK_AND_ASSERT_THROW_MES(false, "Key image not found");
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
void wallet2::comfirm_pool_transfer_out(const cryptonote::transaction& tx, uint64_t height)
{
  const crypto::hash &txid=get_transaction_hash(tx);
  auto it = m_pool_transfer_outs.find(txid);
  if(it != m_pool_transfer_outs.end()) {
      m_confirmed_transfer_outs.insert({txid, confirmed_transfer_out(it->second, height)});
    m_pool_transfer_outs.erase(it);
  }
}


//----------------------------------------------------------------------------------------------------
void wallet2::detach_blockchain(uint64_t height)
{
  LOG_PRINT_L0("Detaching blockchain on height " << height);

  // size  1 2 3 4 5 6 7 8 9
  // block 0 1 2 3 4 5 6 7 8
  //               C
  throw_wallet_ex_if(height < m_blockchain.offset() && m_blockchain.size() > m_blockchain.offset(),
      error::wallet_internal_error, "Daemon claims reorg below last checkpoint");

  size_t transfers_detached = 0;

  for (size_t i = 0; i < m_transfers_in.size(); ++i)
  {
    wallet2::transfer_details &td = m_transfers_in[i];
    if (td.m_spent && td.m_spent_height >= height)
    {
      LOG_PRINT_L1("Resetting spent/frozen status for output " << i << ": " << td.m_key_image);
      set_unspent(i);
    }
  }
  auto it = std::find_if(m_transfers_in.begin(), m_transfers_in.end(), [&](const transfer_details& td){return td.m_block_height >= height;});
  size_t i_start = it - m_transfers_in.begin();

  for(size_t i = i_start; i!= m_transfers_in.size();i++)
  {
    auto it_ki = m_key_images.find(m_transfers_in[i].m_key_image);
    throw_wallet_ex_if(it_ki == m_key_images.end(), error::wallet_internal_error, "key image not found: index " + std::to_string(i) + ", ki " + epee::string_tools::pod_to_hex(m_transfers_in[i].m_key_image) + ", " + std::to_string(m_key_images.size()) + " key images known");
    m_key_images.erase(it_ki);
  }

  for(size_t i = i_start; i!= m_transfers_in.size();i++)
  {
    auto it_pk = m_otks.find(m_transfers_in[i].get_public_key());
    throw_wallet_ex_if(it_pk == m_otks.end(), error::wallet_internal_error, "public key not found");
    m_otks.erase(it_pk);
  }
  transfers_detached = std::distance(it, m_transfers_in.end());
  m_transfers_in.erase(it, m_transfers_in.end());

  size_t blocks_detached = m_blockchain.size() - height;
  m_blockchain.crop(height);

 

  for (auto it = m_confirmed_transfer_outs.begin(); it != m_confirmed_transfer_outs.end(); )
  {
    if(height <= it->second.m_block_height)
      it = m_confirmed_transfer_outs.erase(it);
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
  m_transfers_in.clear();
  m_key_images.clear();
  m_otks.clear();
  m_pool_transfer_outs.clear();
  m_tx_secs.clear();
  m_confirmed_transfer_outs.clear();
  m_pool_transfers_in.clear();
  return true;
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

  
  value2.SetInt(m_always_confirm_transfers ? 1 :0);
  json.AddMember("always_confirm_transfers", value2, json.GetAllocator());

  value2.SetInt(m_auto_refresh ? 1 :0);
  json.AddMember("auto_refresh", value2, json.GetAllocator());

  value2.SetUint64(m_refresh_from_block_height);
  json.AddMember("refresh_height", value2, json.GetAllocator());

  value2.SetUint64(m_max_reorg_depth);
  json.AddMember("max_reorg_depth", value2, json.GetAllocator());


  value2.SetUint(m_nettype);
  json.AddMember("nettype", value2, json.GetAllocator());

  value2.SetInt(m_inactivity_lock_timeout);
  json.AddMember("inactivity_lock_timeout", value2, json.GetAllocator());

  value2.SetUint(1);
  json.AddMember("encrypted_secret_keys", value2, json.GetAllocator());


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
  bool r = verify_password(m_keys_file, password, m_account.get_device().device_protocol() == hw::device::PROTOCOL_COLD , m_account.get_device(), m_kdf_rounds);
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
  throw_wallet_ex_if(!r, error::file_read_error, keys_file_name);

  // Decrypt the contents
  r = ::serialization::parse_binary(buf, keys_file_data);
  throw_wallet_ex_if(!r, error::wallet_internal_error, "internal error: failed to deserialize \"" + keys_file_name + '\"');
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
  r = r && cryptonote::verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key);
  if(!no_spend_key)
    r = r && cryptonote::verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
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
}

void wallet2::create_keys_file(const std::string &wallet_, bool watch_only, const epee::wipeable_string &password, bool create_address_file)
{
  if (!wallet_.empty())
  {
    bool r = store_keys(m_keys_file, password, watch_only);
    throw_wallet_ex_if(!r, error::file_save_error, m_keys_file);

    if (create_address_file)
    {
      r = save_to_file(m_wallet_file + ".address.txt", m_account.get_public_address_str(m_nettype), true);
      if(!r) MERROR("String with address text not saved");
    }
  }
}



void wallet2::init_type(hw::device::device_type device_type)
{
  m_account_public_address = m_account.get_keys().m_account_address;
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
  const crypto::secret_key& recovery_param, bool recover, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    boost::system::error_code ignored_ec;
    throw_wallet_ex_if(boost::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    throw_wallet_ex_if(boost::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  crypto::secret_key retval = m_account.generate(recovery_param, recover);

  init_type(hw::device::device_type::SOFTWARE);
  setup_keys(password);

 
  create_keys_file(wallet_, false, password, m_nettype != MAINNET || create_address_file);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();

  return retval;
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
  throw_wallet_ex_if(!boost::filesystem::exists(m_keys_file, ignored_ec), error::file_not_found, m_keys_file);
    bool r = store_keys(m_keys_file, password,false);
  throw_wallet_ex_if(!r, error::file_save_error, m_keys_file);
}

//----------------------------------------------------------------------------------------------------

//----------------------------------------------------------------------------------------------------
bool wallet2::wallet_valid_path_format(const std::string& file_path)
{
  return !file_path.empty();
}


//----------------------------------------------------------------------------------------------------
bool wallet2::check_connection(uint32_t *version, bool *ssl, uint32_t timeout)
{
  throw_wallet_ex_if(!m_is_initialized, error::wallet_not_initialized);

  if (m_offline)
  {
    m_rpc_version = 0;
    if (version)
      *version = 0;
    if (ssl)
      *ssl = false;
    return false;
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
bool  generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key, uint64_t kdf_rounds) {
            const crypto::secret_key &view_key = keys.m_view_secret_key;
            const crypto::secret_key &spend_key = keys.m_spend_secret_key;
            epee::mlocked<tools::scrubbed_arr<char, sizeof(view_key) + sizeof(spend_key) + 1>> data;
            memcpy(data.data(), &view_key, sizeof(view_key));
            memcpy(data.data() + sizeof(view_key), &spend_key, sizeof(spend_key));
            data[sizeof(data) - 1] = config::HASH_KEY_WALLET;
            crypto::generate_chacha_key(data.data(), sizeof(data), key, kdf_rounds);
            return true;
        }
//----------------------------------------------------------------------------------------------------
bool wallet2::generate_chacha_key_from_secret_keys(crypto::chacha_key &key) const
{
  return generate_chacha_key(m_account.get_keys(), key, m_kdf_rounds);
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

  for (const transfer_details &td: m_transfers_in)
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


      r = net_utils::invoke_http_json_rpc("/json_rpc", "getblockheaderbyheight", req, res, *m_http_client, rpc_timeout);
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

  throw_wallet_ex_if(genesis_hash != m_blockchain.genesis(), error::wallet_internal_error, what);
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
  throw_wallet_ex_if(cache_file_data == boost::none, error::wallet_internal_error, "failed to generate wallet cache data");

  const std::string new_file = same_file ? m_wallet_file + ".new" : path;
  const std::string old_file = m_wallet_file;
  const std::string old_keys_file = m_keys_file;
  const std::string old_address_file = m_wallet_file + ".address.txt";

  // save keys to the new file
  // if we here, main wallet file is saved and we only need to save keys and address files
  if (!same_file) {
    prepare_file_names(path);
    bool r = store_keys(m_keys_file, password, false);
    throw_wallet_ex_if(!r, error::file_save_error, m_keys_file);
    if (boost::filesystem::exists(old_address_file))
    {
      // save address to the new file
      const std::string address_file = m_wallet_file + ".address.txt";
      r = save_to_file(address_file, m_account.get_public_address_str(m_nettype), true);
      throw_wallet_ex_if(!r, error::file_save_error, m_wallet_file);
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
    throw_wallet_ex_if(!success, error::file_save_error, new_file);
#else
    std::ofstream ostr;
    ostr.open(new_file, std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
    binary_archive<true> oar(ostr);
    bool success = ::serialization::serialize(oar, cache_file_data.get());
    ostr.close();
    throw_wallet_ex_if(!success || !ostr.good(), error::file_save_error, new_file);
#endif

    // here we have "*.new" file, we need to rename it to be without ".new"
    std::error_code e = tools::replace_file(new_file, m_wallet_file);
    throw_wallet_ex_if(e, error::file_save_error, m_wallet_file, e);
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
uint64_t wallet2::balance(bool strict) const
{
  uint64_t b=0;
  for (const auto& td: m_transfers_in)
  {
    if ( !is_spent(td) )
    {
      b += td.amount();
    }
  }
  
/*
   for (const auto& utx: m_pool_transfers_in)
   {
      b += utx.second.m_amount;
   }
*/  
  return b;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::unlocked_balance( bool strict)
{
  uint64_t b=0;
  for(const transfer_details& td: m_transfers_in)
  {
    if( !is_spent(td) )
    {
      if (is_transfer_unlocked(td))
      {
        b += td.amount();
      }
      
    }
  }
  return b;
}

//----------------------------------------------------------------------------------------------------
void wallet2::get_transfers(wallet2::transfer_container& incoming_transfers) const
{
  incoming_transfers = m_transfers_in;
}


//----------------------------------------------------------------------------------------------------
void wallet2::rescan_spent()
{
  // This is RPC call that can take a long time if there are many outputs,
  // so we call it several times, in stripes, so we don't time out spuriously
  std::vector<int> spent_status;
  spent_status.reserve(m_transfers_in.size());
  const size_t chunk_size = 1000;
  for (size_t start_offset = 0; start_offset < m_transfers_in.size(); start_offset += chunk_size)
  {
    const size_t n_outputs = std::min<size_t>(chunk_size, m_transfers_in.size() - start_offset);
    MDEBUG("Calling is_key_image_spent on " << start_offset << " - " << (start_offset + n_outputs - 1) << ", out of " << m_transfers_in.size());
    COMMAND_RPC_IS_KEY_IMAGE_SPENT::request req = AUTO_VAL_INIT(req);
    COMMAND_RPC_IS_KEY_IMAGE_SPENT::response daemon_resp = AUTO_VAL_INIT(daemon_resp);
    for (size_t n = start_offset; n < start_offset + n_outputs; ++n)
      req.key_images.push_back(string_tools::pod_to_hex(m_transfers_in[n].m_key_image));

    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};


      bool r = epee::net_utils::invoke_http_json("/is_key_image_spent", req, daemon_resp, *m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR(r, {}, daemon_resp, "is_key_image_spent", error::is_key_image_spent_error, get_rpc_status(daemon_resp.status));
      throw_wallet_ex_if(daemon_resp.spent_status.size() != n_outputs, error::wallet_internal_error,
        "daemon returned wrong response for is_key_image_spent, wrong amounts count = " +
        std::to_string(daemon_resp.spent_status.size()) + ", expected " +  std::to_string(n_outputs));
      
    }

    std::copy(daemon_resp.spent_status.begin(), daemon_resp.spent_status.end(), std::back_inserter(spent_status));
  }

  // update spent status
  for (size_t i = 0; i < m_transfers_in.size(); ++i)
  {
    transfer_details& td = m_transfers_in[i];

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
void wallet2::rescan_blockchain(bool refresh)
{
    clear();
    setup_new_blockchain();

  if (refresh)
    this->refresh(0);

}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_transfer_unlocked(const transfer_details& td)
{
  return is_transfer_unlocked(td.m_unlock_time, td.m_block_height);
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
void wallet2::add_pool_transfer_out(const pending_tx & ptx)
{
  unconfirmed_transfer_out& utd = m_pool_transfer_outs[cryptonote::get_transaction_hash(ptx.tx)];
  utd.m_sent_time = time(NULL);
  utd.m_tx = ptx.tx;
  utd.m_amount = ptx.dst.amount;
  utd.m_addr = ptx.dst.addr;
  utd.m_state = wallet2::unconfirmed_transfer_out::pending;

}

//------------------------------------------------------------------------------------------------------------------------------
uint64_t wallet2::get_min_ring_size()
{
 
    return 11;
 
}
//------------------------------------------------------------------------------------------------------------------------------
uint64_t wallet2::get_max_ring_size()
{
 
    return 11;
  
}
//------------------------------------------------------------------------------------------------------------------------------
uint64_t wallet2::adjust_mixin(uint64_t mixin)
{
  return 11;
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



std::vector<size_t> wallet2::get_only_rct(const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices) const
{
  std::vector<size_t> indices;
  for (size_t n: unused_dust_indices)
      indices.push_back(n);
  for (size_t n: unused_transfers_indices)
      indices.push_back(n);
  return indices;
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
  throw_wallet_ex_if(!r, tools::error::no_connection_to_daemon, "hard_fork_info");
  throw_wallet_ex_if(resp_t.status == CORE_RPC_STATUS_BUSY, tools::error::daemon_busy, "hard_fork_info");
  throw_wallet_ex_if(resp_t.status != CORE_RPC_STATUS_OK, tools::error::wallet_generic_rpc_error, "hard_fork_info", resp_t.status);
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
  throw_wallet_ex_if(result, error::wallet_internal_error, "Failed to get height");
  result = m_node_rpc_proxy.get_earliest_height(version, earliest_height);
  throw_wallet_ex_if(result, error::wallet_internal_error, "Failed to get earliest fork height");

  bool close_enough = (int64_t)height >= (int64_t)earliest_height - early_blocks && earliest_height != std::numeric_limits<uint64_t>::max(); // start using the rules that many blocks beforehand
  if (close_enough)
    MINFO("Using v" << (unsigned)version << " rules");
  else
    MINFO("Not using v" << (unsigned)version << " rules");
  return close_enough;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_upper_transaction_weight_limit()
{
 
  return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;

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


    bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_output_histogram", req_t, resp_t, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, resp_t, "get_output_histogram", error::get_histogram_error, resp_t.status);
    throw_wallet_ex_if(resp_t.histogram.size() != 1, error::get_histogram_error, "Expected exactly one response");
    throw_wallet_ex_if(resp_t.histogram[0].amount != 0, error::get_histogram_error, "Expected 0 amount");
    
  }

  return resp_t.histogram[0].total_instances;
}
//----------------------------------------------------------------------------------------------------
const wallet2::transfer_details &wallet2::get_transfer_details(size_t idx) const
{
  throw_wallet_ex_if(idx >= m_transfers_in.size(), error::wallet_internal_error, "Bad transfer index");
  return m_transfers_in[idx];
}

bool wallet2::get_tx_key_cached(const crypto::hash &txid, crypto::secret_key &tx_key) const
{
  const auto i = m_tx_secs.find(txid);
  if (i == m_tx_secs.end())
    return false;
  tx_key = i->second;
  if (tx_key == crypto::null_skey)
    return false;
  
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key)
{
  bool r = get_tx_key_cached(txid, tx_key);
  if (r)
  {
    MDEBUG("tx key cached for txid: " << txid);
    return true;
  }

  return false;

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
      err = *result;
      return 0;
  }

  err = "";
  return height;
}

uint64_t wallet2::get_daemon_adjusted_time()
{
    uint64_t adjusted_time;

    boost::optional<std::string> result = m_node_rpc_proxy.get_adjusted_time(adjusted_time);
    throw_wallet_ex_if(result, error::wallet_internal_error, "Invalid adjusted time from daemon");
    return adjusted_time;
}

uint64_t wallet2::get_daemon_blockchain_target_height(string &err)
{
  err = "";
  uint64_t target_height = 0;
  const auto result = m_node_rpc_proxy.get_target_height(target_height);
  if (result && *result != CORE_RPC_STATUS_OK)
  {
      err = *result;
    return 0;
  }
  return target_height;
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
  throw_wallet_ex_if(ciphertext.size() < prefix_size,
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
    throw_wallet_ex_if(!crypto::check_signature(hash, pkey, signature),
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
      r = net_utils::invoke_http_bin("/getblocks_by_height.bin", req, res, *m_http_client, rpc_timeout);
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
    blk_min = parse_and_validate_block_from_blob(res.blocks[0].block);

   blk_mid = parse_and_validate_block_from_blob(res.blocks[1].block);
    blk_max=parse_and_validate_block_from_blob(res.blocks[2].block);
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
//----------------------------------------------------------------------------------------------------
void wallet2::generate_genesis(cryptonote::block& b) const {
  cryptonote::generate_genesis_block(b, get_config(m_nettype).GENESIS_TX, get_config(m_nettype).GENESIS_NONCE);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_rpc_status(const std::string &s) const
{
    return s;
 
}
//----------------------------------------------------------------------------------------------------
void wallet2::throw_on_rpc_response_error(bool r, const epee::json_rpc::error &error, const std::string &status, const char *method) const
{
  throw_wallet_ex_if(error.code, tools::error::wallet_coded_rpc_error, method, error.code, get_rpc_server_error_message(error.code));
  throw_wallet_ex_if(!r, tools::error::no_connection_to_daemon, method);
  // empty string -> not connection
  throw_wallet_ex_if(status.empty(), tools::error::no_connection_to_daemon, method);

  throw_wallet_ex_if(status == CORE_RPC_STATUS_BUSY, tools::error::daemon_busy, method);
  throw_wallet_ex_if(status == CORE_RPC_STATUS_PAYMENT_REQUIRED, tools::error::payment_required, method);
}
//----------------------------------------------------------------------------------------------------

bool wallet2::save_to_file(const std::string& path_to_file, const std::string& raw, bool is_printable) const
{
    return epee::file_io_utils::save_string_to_file(path_to_file, raw);

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
