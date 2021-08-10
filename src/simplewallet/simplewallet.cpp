// Copyright (c) 2014-2020, The DFA Project
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

/*!
 * \file simplewallet.cpp
 * 
 * \brief Source file that defines simple_wallet class.
 */

// use boost bind placeholders for now
#define BOOST_BIND_GLOBAL_PLACEHOLDERS 1
#include <boost/bind.hpp>

#include <locale.h>
#include <thread>
#include <iostream>
#include <sstream>
#include <fstream>
#include <ctype.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/regex.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/filesystem.hpp>
#include "include_base_utils.h"
#include "console_handler.h"
#include "common/i18n.h"
#include "common/command_line.h"
#include "common/util.h"
#include "common/dns_utils.h"
#include "common/base58.h"
#include "common/scoped_message_writer.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "simplewallet.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "storages/http_abstract_invoke.h"
#include "rpc/core_rpc_server_commands_defs.h"

#include "crypto/crypto.h"  // for crypto::secret_key definition
#include "mnemonics/electrum-words.h"
#include "rapidjson/document.h"
#include "common/json_util.h"
#include "ringct/rctSigs.h"
#include "wallet/wallet_args.h"
#include "version.h"
#include <stdexcept>

#ifdef WIN32
#include <boost/locale.hpp>
#include <boost/filesystem.hpp>
#include <fcntl.h>
#endif

#ifdef HAVE_READLINE
#include "readline_buffer.h"
#endif

using namespace std;
using namespace epee;
using namespace cryptonote;
using boost::lexical_cast;
namespace po = boost::program_options;
typedef cryptonote::simple_wallet sw;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.simplewallet"

#define EXTENDED_LOGS_FILE "wallet_details.log"

#define DEFAULT_MIX 10

#define MIN_RING_SIZE 11 // Used to inform user about min ring size -- does not track actual protocol

#define OLD_AGE_WARN_THRESHOLD (30 * 86400 / DIFFICULTY_TARGET_V2) // 30 days

#define LOCK_IDLE_SCOPE() \
  bool auto_refresh_enabled = m_auto_refresh_enabled.load(std::memory_order_relaxed); \
  m_auto_refresh_enabled.store(false, std::memory_order_relaxed); \
  /* stop any background refresh and other processes, and take over */ \
  m_wallet->stop(); \
  boost::unique_lock<boost::mutex> lock(m_idle_mutex); \
  m_idle_cond.notify_all(); \
  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){ \
    /* m_idle_mutex is still locked here */ \
    m_auto_refresh_enabled.store(auto_refresh_enabled, std::memory_order_relaxed); \
    m_idle_cond.notify_one(); \
  })

#define SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(code) \
  LOCK_IDLE_SCOPE(); \
  boost::optional<tools::password_container> pwd_container = boost::none; \
  if (!(pwd_container = get_and_verify_password())) { code; } 

#define SCOPED_WALLET_UNLOCK() SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(return true;)

#define PRINT_USAGE(usage_help) fail_msg_writer() << boost::format(tr("usage: %s")) % usage_help;

#define LONG_PAYMENT_ID_SUPPORT_CHECK() \
  do { \
    fail_msg_writer() << tr("Error: Long payment IDs are obsolete."); \
    fail_msg_writer() << tr("Long payment IDs were not encrypted on the blockchain and would harm your privacy."); \
    fail_msg_writer() << tr("If the party you're sending to still requires a long payment ID, please notify them."); \
    return true; \
  } while(0)

#define REFRESH_PERIOD 90 // seconds

#define CREDITS_TARGET 50000
#define MAX_PAYMENT_DIFF 10000
#define MIN_PAYMENT_RATE 0.01f // per hash
#define MAX_MNEW_ADDRESSES 1000

enum TransferType {
  Transfer,
  TransferLocked,
};

static std::string get_human_readable_timespan(std::chrono::seconds seconds);
static std::string get_human_readable_timespan(uint64_t seconds);

namespace
{
  const std::array<const char* const, 5> allowed_priority_strings = {{"default", "unimportant", "normal", "elevated", "priority"}};
  const auto arg_wallet_file = wallet_args::arg_wallet_file();
  const command_line::arg_descriptor<std::string> arg_generate_new_wallet = {"generate-new-wallet", sw::tr("Generate new wallet and save it to <arg>"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_device = {"generate-from-device", sw::tr("Generate new wallet from device and save it to <arg>"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_view_key = {"generate-from-view-key", sw::tr("Generate incoming-only wallet from view key"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_spend_key = {"generate-from-spend-key", sw::tr("Generate deterministic wallet from spend key"), ""};
 
  const command_line::arg_descriptor<std::string> arg_mnemonic_language = {"mnemonic-language", sw::tr("Language for mnemonic"), ""};
  const command_line::arg_descriptor<std::string> arg_electrum_seed = {"electrum-seed", sw::tr("Specify Electrum seed for wallet recovery/creation"), ""};
  
  const command_line::arg_descriptor<bool> arg_restore_from_seed = {"restore-from-seed", sw::tr("alias for --restore-deterministic-wallet"), false};

  const command_line::arg_descriptor<bool> arg_allow_mismatched_daemon_version = {"allow-mismatched-daemon-version", sw::tr("Allow communicating with a daemon that uses a different RPC version"), false};
  const command_line::arg_descriptor<uint64_t> arg_restore_height = {"restore-height", sw::tr("Restore from specific blockchain height"), 0};
  const command_line::arg_descriptor<std::string> arg_restore_date = {"restore-date", sw::tr("Restore from estimated blockchain height on specified date"), ""};
  const command_line::arg_descriptor<bool> arg_create_address_file = {"create-address-file", sw::tr("Create an address file for new wallets"), false};
  const command_line::arg_descriptor<bool> arg_use_english_language_names = {"use-english-language-names", sw::tr("Display English language names"), false};

  const command_line::arg_descriptor< std::vector<std::string> > arg_command = {"command", ""};

  const char* USAGE_SET_DAEMON("set_daemon <host>[:<port>] [trusted|untrusted|this-is-probably-a-spy-node]");
  const char* USAGE_SHOW_BALANCE("balance [detail]");
  const char* USAGE_INCOMING_TRANSFERS("receipts");
  const char* USAGE_TRANSFER("transfer [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] (<URI> | <address> <amount>) [<payment_id>]");
  const char* USAGE_SWEEP_ALL("sweep_all [index=<N1>[,<N2>,...] | index=all] [<priority>] [<ring_size>] [outputs=<N>] <address> [<payment_id (obsolete)>]");
  const char* USAGE_SWEEP_BELOW("sweep_below <amount_threshold> [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> [<payment_id (obsolete)>]");
  const char* USAGE_DONATE("donate [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <amount> [<payment_id (obsolete)>]");
  const char* USAGE_SIGN_TRANSFER("sign_transfer [export_raw] [<filename>]");
  const char* USAGE_SET_LOG("set_log <level>|{+,-,}<categories>");
 

  const char* USAGE_SET_VARIABLE("set <option> [<value>]");
  const char* USAGE_GET_TX_KEY("get_tx_key <txid>");
  const char* USAGE_CHECK_TX_KEY("check_tx_key <txid> <txkey> <address>");
  const char* USAGE_GET_TX_PROOF("get_tx_proof <txid> <address> [<message>]");
  const char* USAGE_CHECK_TX_PROOF("check_tx_proof <txid> <address> <signature_file> [<message>]");
  const char* USAGE_GET_SPEND_PROOF("get_spend_proof <txid> [<message>]");
  const char* USAGE_CHECK_SPEND_PROOF("check_spend_proof <txid> <signature_file> [<message>]");
  const char* USAGE_SHOW_TRANSFERS("show_transfers [in|out|all] [<min_height> [<max_height>]]");
  const char* USAGE_RESCAN_BC("rescan_bc [hard|soft|keep_ki] [start_height=0]");
  const char* USAGE_SHOW_TRANSFER("show_transfer <txid>");
  const char* USAGE_LOCK("lock");
  const char* USAGE_NET_STATS("net_stats");
  const char* USAGE_PUBLIC_NODES("public_nodes");
  const char* USAGE_WELCOME("welcome");
  const char* USAGE_VERSION("version");
  const char* USAGE_HELP("help [<command> | all]");
  const char* USAGE_APROPOS("apropos <keyword> [<keyword> ...]");

  std::string input_line(const std::string& prompt, bool yesno = false)
  {
    PAUSE_READLINE();
    std::cout << prompt;
    if (yesno)
      std::cout << "  (Y/Yes/N/No)";
    std::cout << ": " << std::flush;

    std::string buf;
#ifdef _WIN32
    buf = tools::input_line_win();
#else
    std::getline(std::cin, buf);
#endif

    return epee::string_tools::trim(buf);
  }

  epee::wipeable_string input_secure_line(const char *prompt)
  {
    PAUSE_READLINE();
    auto pwd_container = tools::password_container::prompt(false, prompt, false);
    if (!pwd_container)
    {
      MERROR("Failed to read secure line");
      return "";
    }

    epee::wipeable_string buf = pwd_container->password();

    buf.trim();
    return buf;
  }

  boost::optional<tools::password_container> password_prompter(const char *prompt, bool verify)
  {
    PAUSE_READLINE();
    auto pwd_container = tools::password_container::prompt(verify, prompt);
    if (!pwd_container)
    {
      tools::fail_msg_writer() << sw::tr("failed to read wallet password");
    }
    return pwd_container;
  }

  boost::optional<tools::password_container> default_password_prompter(bool verify)
  {
    return password_prompter(verify ? sw::tr("Enter a new password for the wallet") : sw::tr("Wallet password"), verify);
  }

  inline std::string interpret_rpc_response(bool ok, const std::string& status)
  {
    std::string err;
    if (ok)
    {
      if (status == CORE_RPC_STATUS_BUSY)
      {
        err = sw::tr("daemon is busy. Please try again later.");
      }
      else if (status != CORE_RPC_STATUS_OK)
      {
        err = status;
      }
    }
    else
    {
      err = sw::tr("possibly lost connection to daemon");
    }
    return err;
  }

  tools::scoped_message_writer success_msg_writer(bool color = false)
  {
    return tools::scoped_message_writer(color ? console_color_green : console_color_default, false, std::string(), el::Level::Info);
  }

  tools::scoped_message_writer message_writer(epee::console_colors color = epee::console_color_default, bool bright = false)
  {
    return tools::scoped_message_writer(color, bright);
  }

  tools::scoped_message_writer fail_msg_writer()
  {
    return tools::scoped_message_writer(console_color_red, true, sw::tr("Error: "), el::Level::Error);
  }

  bool parse_bool(const std::string& s, bool& result)
  {
    if (s == "1" || command_line::is_yes(s))
    {
      result = true;
      return true;
    }
    if (s == "0" || command_line::is_no(s))
    {
      result = false;
      return true;
    }

    boost::algorithm::is_iequal ignore_case{};
    if (boost::algorithm::equals("true", s, ignore_case) || boost::algorithm::equals(simple_wallet::tr("true"), s, ignore_case))
    {
      result = true;
      return true;
    }
    if (boost::algorithm::equals("false", s, ignore_case) || boost::algorithm::equals(simple_wallet::tr("false"), s, ignore_case))
    {
      result = false;
      return true;
    }

    return false;
  }

  template <typename F>
  bool parse_bool_and_use(const std::string& s, F func)
  {
    bool r;
    if (parse_bool(s, r))
    {
      func(r);
      return true;
    }
    else
    {
      fail_msg_writer() << sw::tr("invalid argument: must be either 0/1, true/false, y/n, yes/no");
      return false;
    }
  }

  std::string get_version_string(uint32_t version)
  {
    return boost::lexical_cast<std::string>(version >> 16) + "." + boost::lexical_cast<std::string>(version & 0xffff);
  }


}

void simple_wallet::handle_transfer_exception(const std::exception_ptr &e, bool trusted_daemon)
{
    bool warn_of_possible_attack = !trusted_daemon;
    try
    {
      std::rethrow_exception(e);
    }
 
    catch (const tools::error::no_connection_to_daemon&)
    {
      fail_msg_writer() << sw::tr("no connection to daemon. Please make sure daemon is running.");
    }
    catch (const tools::error::daemon_busy&)
    {
      fail_msg_writer() << tr("daemon is busy. Please try again later.");
    }
    catch (const tools::error::wallet_rpc_error& e)
    {
      LOG_ERROR("RPC error: " << e.to_string());
      fail_msg_writer() << sw::tr("RPC error: ") << e.what();
    }
    catch (const tools::error::get_outs_error &e)
    {
      fail_msg_writer() << sw::tr("failed to get random outputs to mix: ") << e.what();
    }
    catch (const tools::error::not_enough_unlocked_money& e)
    {
      LOG_PRINT_L0(boost::format("not enough money to transfer, available only %s, sent amount %s") %
        print_money(e.available()) %
        print_money(e.tx_amount()));
      fail_msg_writer() << sw::tr("Not enough money in unlocked balance");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::not_enough_money& e)
    {
      LOG_PRINT_L0(boost::format("not enough money to transfer, available only %s, sent amount %s") %
        print_money(e.available()) %
        print_money(e.tx_amount()));
      fail_msg_writer() << sw::tr("Not enough money in unlocked balance");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::tx_not_possible& e)
    {
      LOG_PRINT_L0(boost::format("not enough money to transfer, available only %s, transaction amount %s = %s + %s (fee)") %
        print_money(e.available()) %
        print_money(e.tx_amount() + e.fee())  %
        print_money(e.tx_amount()) %
        print_money(e.fee()));
      fail_msg_writer() << sw::tr("Failed to find a way to create transactions. This is usually due to dust which is so small it cannot pay for itself in fees, or trying to send more money than the unlocked balance, or not leaving enough for fees");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::not_enough_outs_to_mix& e)
    {
      auto writer = fail_msg_writer();
      writer << sw::tr("not enough outputs for specified ring size") << " = " << (e.mixin_count() + 1) << ":";
      for (std::pair<uint64_t, uint64_t> outs_for_amount : e.scanty_outs())
      {
        writer << "\n" << sw::tr("output amount") << " = " << print_money(outs_for_amount.first) << ", " << sw::tr("found outputs to use") << " = " << outs_for_amount.second;
      }
      writer << sw::tr("Please use sweep_unmixable.");
    }
    catch (const tools::error::tx_not_constructed&)
    {
      fail_msg_writer() << sw::tr("transaction was not constructed");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::tx_rejected& e)
    {
      fail_msg_writer() << (boost::format(sw::tr("transaction %s was rejected by daemon")) % get_transaction_hash(e.tx()));
      std::string reason = e.reason();
      if (!reason.empty())
        fail_msg_writer() << sw::tr("Reason: ") << reason;
    }
    catch (const tools::error::tx_sum_overflow& e)
    {
      fail_msg_writer() << e.what();
      warn_of_possible_attack = false;
    }
    catch (const tools::error::zero_amount&)
    {
      fail_msg_writer() << sw::tr("destination amount is zero");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::zero_destination&)
    {
      fail_msg_writer() << sw::tr("transaction has no destination");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::tx_too_big& e)
    {
      fail_msg_writer() << sw::tr("failed to find a suitable way to split transactions");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::transfer_error& e)
    {
      LOG_ERROR("unknown transfer error: " << e.to_string());
      fail_msg_writer() << sw::tr("unknown transfer error: ") << e.what();
    }
  
    catch (const tools::error::wallet_internal_error& e)
    {
      LOG_ERROR("internal error: " << e.to_string());
      fail_msg_writer() << sw::tr("internal error: ") << e.what();
    }
    catch (const std::exception& e)
    {
      LOG_ERROR("unexpected error: " << e.what());
      fail_msg_writer() << sw::tr("unexpected error: ") << e.what();
    }

    if (warn_of_possible_attack)
      fail_msg_writer() << sw::tr("There was an error, which could mean the node may be trying to get you to retry creating a transaction, and zero in on which outputs you own. Or it could be a bona fide error. It may be prudent to disconnect from this node, and not try to send a transaction immediately. Alternatively, connect to another node so the original node cannot correlate information.");
}

namespace
{
  void print_secret_key(const crypto::secret_key &k)
  {
    static constexpr const char hex[] = u8"0123456789abcdef";
    const uint8_t *ptr = (const uint8_t*)k.data;
    for (size_t i = 0, sz = sizeof(k); i < sz; ++i)
    {
      putchar(hex[*ptr >> 4]);
      putchar(hex[*ptr & 15]);
      ++ptr;
    }
  }
}

std::string simple_wallet::get_commands_str()
{
  std::stringstream ss;
  ss << tr("Commands: ") << ENDL;
  std::string usage = m_cmd_binder.get_usage();
  boost::replace_all(usage, "\n", "\n  ");
  usage.insert(0, "  ");
  ss << usage << ENDL;
  return ss.str();
}

std::string simple_wallet::get_command_usage(const std::vector<std::string> &args)
{
  std::pair<std::string, std::string> documentation = m_cmd_binder.get_documentation(args);
  std::stringstream ss;
  if(documentation.first.empty())
  {
    ss << tr("Unknown command: ") << args.front();
  }
  else
  {
    std::string usage = documentation.second.empty() ? args.front() : documentation.first;
    std::string description = documentation.second.empty() ? documentation.first : documentation.second;
    usage.insert(0, "  ");
    ss << tr("Command usage: ") << ENDL << usage << ENDL << ENDL;
    boost::replace_all(description, "\n", "\n  ");
    description.insert(0, "  ");
    ss << tr("Command description: ") << ENDL << description << ENDL;
  }
  return ss.str();
}

bool simple_wallet::viewkey(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  // don't log
  PAUSE_READLINE();
 {
    SCOPED_WALLET_UNLOCK();
    printf("secret: ");
    print_secret_key(m_wallet->get_account().get_keys().m_view_secret_key);
    putchar('\n');
  }
  std::cout << "public: " << string_tools::pod_to_hex(m_wallet->get_account().get_keys().m_account_address.m_view_public_key) << std::endl;

  return true;
}

bool simple_wallet::spendkey(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
 
  // don't log
  PAUSE_READLINE();
 {
    SCOPED_WALLET_UNLOCK();
    printf("secret: ");
    print_secret_key(m_wallet->get_account().get_keys().m_spend_secret_key);
    putchar('\n');
  }
  std::cout << "public: " << string_tools::pod_to_hex(m_wallet->get_account().get_keys().m_account_address.m_spend_public_key) << std::endl;

  return true;
}

bool simple_wallet::print_seed(bool encrypted)
{
  bool success =  false;
  epee::wipeable_string seed;
  bool ready;

  SCOPED_WALLET_UNLOCK();

  if ( !m_wallet->is_deterministic())
  {
    fail_msg_writer() << tr("wallet is non-deterministic and has no seed");
    return true;
  }

  epee::wipeable_string seed_pass;
  if (encrypted)
  {
    auto pwd_container = password_prompter(tr("Enter optional seed offset passphrase, empty to see raw seed"), true);
    if (std::cin.eof() || !pwd_container)
      return true;
    seed_pass = pwd_container->password();
  }

 if (m_wallet->is_deterministic())
    success = m_wallet->get_seed(seed, seed_pass);

  if (success) 
  {
    print_seed(seed);
  }
  else
  {
    fail_msg_writer() << tr("Failed to retrieve seed");
  }
  return true;
}

bool simple_wallet::seed(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  return print_seed(false);
}

bool simple_wallet::encrypted_seed(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  return print_seed(true);
}

bool simple_wallet::restore_height(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  success_msg_writer() << m_wallet->get_refresh_from_block_height();
  return true;
}

bool simple_wallet::seed_set_language(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{

  epee::wipeable_string password;
  {
    SCOPED_WALLET_UNLOCK();

    if (!m_wallet->is_deterministic())
    {
      fail_msg_writer() << tr("wallet is non-deterministic and has no seed");
      return true;
    }

    // we need the password, even if ask-password is unset
    if (!pwd_container)
    {
      pwd_container = get_and_verify_password();
      if (pwd_container == boost::none)
      {
        fail_msg_writer() << tr("Incorrect password");
        return true;
      }
    }
    password = pwd_container->password();
  }

  std::string mnemonic_language = get_mnemonic_language();
  if (mnemonic_language.empty())
    return true;

  m_wallet->set_seed_language(std::move(mnemonic_language));
  m_wallet->rewrite(m_wallet_file, password);
  return true;
}

bool simple_wallet::change_password(const std::vector<std::string> &args)
{ 
  const auto orig_pwd_container = get_and_verify_password();

  if(orig_pwd_container == boost::none)
  {
    fail_msg_writer() << tr("Your original password was incorrect.");
    return true;
  }

  // prompts for a new password, pass true to verify the password
  const auto pwd_container = default_password_prompter(true);
  if(!pwd_container)
    return true;

  try
  {
    m_wallet->change_password(m_wallet_file, orig_pwd_container->password(), pwd_container->password());
  }
  catch (const tools::error::wallet_logic_error& e)
  {
    fail_msg_writer() << tr("Error with wallet rewrite: ") << e.what();
    return true;
  }

  return true;
}

bool simple_wallet::lock(const std::vector<std::string> &args)
{
  m_locked = true;
  check_for_inactivity_lock(true);
  return true;
}

bool simple_wallet::net_stats(const std::vector<std::string> &args)
{
  message_writer() << std::to_string(m_wallet->get_bytes_sent()) + tr(" bytes sent");
  message_writer() << std::to_string(m_wallet->get_bytes_received()) + tr(" bytes received");
  return true;
}

bool simple_wallet::public_nodes(const std::vector<std::string> &args)
{
  try
  {
    auto nodes = m_wallet->get_public_nodes(false);
    m_claimed_cph.clear();
    if (nodes.empty())
    {
      fail_msg_writer() << tr("No known public nodes");
      return true;
    }
    std::sort(nodes.begin(), nodes.end(), [](const public_node &node0, const public_node &node1) {
      if (node0.rpc_credits_per_hash && node1.rpc_credits_per_hash == 0)
        return true;
      if (node0.rpc_credits_per_hash && node1.rpc_credits_per_hash)
        return node0.rpc_credits_per_hash < node1.rpc_credits_per_hash;
      return false;
    });

    const uint64_t now = time(NULL);
    message_writer() << boost::format("%32s %12s %16s") % tr("address") % tr("credits/hash") % tr("last_seen");
    for (const auto &node: nodes)
    {
      const float cph =0;
      char cphs[9];
      snprintf(cphs, sizeof(cphs), "%.3f", cph);
      const std::string last_seen = node.last_seen == 0 ? tr("never") : get_human_readable_timespan(std::chrono::seconds(now - node.last_seen));
      std::string host = node.host + ":" + std::to_string(node.rpc_port);
      message_writer() << boost::format("%32s %12s %16s") % host % cphs % last_seen;
      m_claimed_cph[host] = node.rpc_credits_per_hash;
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Error retrieving public node list: ") << e.what();
  }
  message_writer(console_color_red, true) << tr("Most of these nodes are probably spies. You should not use them unless connecting via Tor or I2P");
  return true;
}

bool simple_wallet::welcome(const std::vector<std::string> &args)
{
  message_writer() << tr("Welcome to DFA, the private cryptocurrency.");
  message_writer() << "";
  message_writer() << tr("DFA, like Bitcoin, is a cryptocurrency. That is, it is digital money.");
  message_writer() << tr("Unlike Bitcoin, your DFA transactions and balance stay private and are not visible to the world by default.");
  message_writer() << tr("However, you have the option of making those available to select parties if you choose to.");
  message_writer() << "";
  message_writer() << tr("DFA protects your privacy on the blockchain, and while DFA strives to improve all the time,");
  message_writer() << tr("no privacy technology can be 100% perfect, DFA included.");
  message_writer() << tr("DFA cannot protect you from malware, and it may not be as effective as we hope against powerful adversaries.");
  message_writer() << tr("Flaws in DFA may be discovered in the future, and attacks may be developed to peek under some");
  message_writer() << tr("of the layers of privacy DFA provides. Be safe and practice defense in depth.");
  message_writer() << "";
  message_writer() << tr("Welcome to DFA and financial privacy. For more information see https://GetMonero.org");
  return true;
}

bool simple_wallet::version(const std::vector<std::string> &args)
{
  message_writer() << "DFA '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")";
  return true;
}

bool simple_wallet::on_unknown_command(const std::vector<std::string> &args)
{
  if (args[0] == "exit" || args[0] == "q") // backward compat
    return false;
  fail_msg_writer() << boost::format(tr("Unknown command '%s', try 'help'")) % args.front();
  return true;
}

bool simple_wallet::on_empty_command()
{
  return true;
}

bool simple_wallet::on_cancelled_command()
{
  check_for_inactivity_lock(false);
  return true;
}


bool simple_wallet::set_always_confirm_transfers(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->always_confirm_transfers(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}


bool simple_wallet::set_store_tx_info(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{

  return true;
}




bool simple_wallet::set_auto_refresh(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool auto_refresh) {
      m_auto_refresh_enabled.store(false, std::memory_order_relaxed);
      m_wallet->auto_refresh(auto_refresh);
      m_idle_mutex.lock();
      m_auto_refresh_enabled.store(auto_refresh, std::memory_order_relaxed);
      m_idle_cond.notify_one();
      m_idle_mutex.unlock();

      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}


bool simple_wallet::set_unit(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const std::string &unit = args[1];
  unsigned int decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT;

  if (unit == "monero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT;
  else if (unit == "millinero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 3;
  else if (unit == "micronero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 6;
  else if (unit == "nanonero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 9;
  else if (unit == "piconero")
    decimal_point = 0;
  else
  {
    fail_msg_writer() << tr("invalid unit");
    return true;
  }

  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    cryptonote::set_default_decimal_point(decimal_point);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}

bool simple_wallet::set_max_reorg_depth(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  uint64_t depth;
  if (!epee::string_tools::get_xtype_from_string(depth, args[1]))
  {
    fail_msg_writer() << tr("invalid value");
    return true;
  }

  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    m_wallet->max_reorg_depth(depth);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}


bool simple_wallet::set_inactivity_lock_timeout(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
#ifdef _WIN32
  tools::fail_msg_writer() << tr("Inactivity lock timeout disabled on Windows");
  return true;
#endif
 // const auto pwd_container = get_and_verify_password();
 // if (pwd_container)
  {
    uint32_t r;
    if (epee::string_tools::get_xtype_from_string(r, args[1]))
    {
      m_wallet->inactivity_lock_timeout(r);
  //    m_wallet->rewrite(m_wallet_file, pwd_container->password());
       m_wallet->store();
    }
    else
    {
      tools::fail_msg_writer() << tr("Invalid number of seconds");
    }
  }
 // else 
 //  throw std::runtime_error("no pwd");
  return true;
}



bool simple_wallet::help(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  if(args.empty())
  {
    message_writer() << "";
    message_writer() << tr("Important commands:");
    message_writer() << "";
    message_writer() << tr("\"welcome\" - Show welcome message.");
    message_writer() << tr("\"help all\" - Show the list of all available commands.");
    message_writer() << tr("\"help <command>\" - Show a command's documentation.");
    message_writer() << tr("\"apropos <keyword>\" - Show commands related to a keyword.");
    message_writer() << "";
    message_writer() << tr("\"wallet_info\" - Show wallet main address and other info.");
    message_writer() << tr("\"balance\" - Show balance.");
    message_writer() << tr("\"address \" - Show all addresses.");
    message_writer() << tr("\"transfer <address> <amount>\" - Send XMR to an address.");
    message_writer() << tr("\"show_transfers [in|out|pending|failed|pool]\" - Show transactions.");
    message_writer() << tr("\"sweep_all <address>\" - Send whole balance to another wallet.");
    message_writer() << tr("\"seed\" - Show secret 25 words that can be used to recover this wallet.");
    message_writer() << tr("\"refresh\" - Synchronize wallet with the DFA network.");
    message_writer() << tr("\"status\" - Check current status of wallet.");
    message_writer() << tr("\"version\" - Check software version.");
    message_writer() << tr("\"exit\" - Exit wallet.");
    message_writer() << "";
    message_writer() << tr("\"donate <amount>\" - Donate XMR to the development team.");
    message_writer() << "";
  }
  else if ((args.size() == 1) && (args.front() == "all"))
  {
    success_msg_writer() << get_commands_str();
  }
  else if ((args.size() == 2) && (args.front() == "mms"))
  {
    // Little hack to be able to do "help mms <subcommand>"
    std::vector<std::string> mms_args(1, args.front() + " " + args.back());
    success_msg_writer() << get_command_usage(mms_args);
  }
  else
  {
    success_msg_writer() << get_command_usage(args);
  }
  return true;
}

bool simple_wallet::apropos(const std::vector<std::string> &args)
{
  if (args.empty())
  {
    PRINT_USAGE(USAGE_APROPOS);
    return true;
  }
  const std::vector<std::string>& command_list = m_cmd_binder.get_command_list(args);
  if (command_list.empty())
  {
    fail_msg_writer() << tr("No commands found mentioning keyword(s)");
    return true;
  }

  success_msg_writer() << "";
  for(auto const& command:command_list)
  {
    std::vector<std::string> cmd;
    cmd.push_back(command);
    std::pair<std::string, std::string> documentation = m_cmd_binder.get_documentation(cmd);
    success_msg_writer() << "  " << documentation.first;
  }
  success_msg_writer() << "";

  return true;
}


simple_wallet::simple_wallet()
  : m_allow_mismatched_daemon_version(false)
  , m_refresh_progress_reporter(*this)
  , m_idle_run(true)
  , m_auto_refresh_enabled(false)
  , m_auto_refresh_refreshing(false)
  , m_in_manual_refresh(false)
  , m_last_activity_time(time(NULL))
  , m_locked(false)
  , m_in_command(false)
{

  m_cmd_binder.set_handler("set_daemon",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::set_daemon, _1),
                           tr(USAGE_SET_DAEMON),
                           tr("Set another daemon to connect to. If it's not yours, it'll probably spy on you."));

  m_cmd_binder.set_handler("refresh",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::refresh, _1),
                           tr("Synchronize the transactions and balance."));
  m_cmd_binder.set_handler("balance",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::show_balance, _1),
                           tr(USAGE_SHOW_BALANCE),
                           tr("Show the wallet's balance of the currently selected account."));
  m_cmd_binder.set_handler("receipts",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::show_incoming_transfers,_1),
                           tr(USAGE_INCOMING_TRANSFERS),
                           tr("Show the in-transfers  "));

  m_cmd_binder.set_handler("bc_height",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::show_blockchain_height, _1),
                           tr("Show the blockchain height."));
  m_cmd_binder.set_handler("transfer", boost::bind(&simple_wallet::on_command, this, &simple_wallet::transfer, _1),
                           tr(USAGE_TRANSFER),
                           tr("Transfer <amount> to <address>."));


  m_cmd_binder.set_handler("sweep_all", boost::bind(&simple_wallet::on_command, this, &simple_wallet::sweep_all, _1),
                           tr(USAGE_SWEEP_ALL),
                           tr("Send all unlocked balance to an address. "));

  m_cmd_binder.set_handler("sweep_below",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::sweep_below, _1),
                           tr(USAGE_SWEEP_BELOW),
                           tr("Send all unlocked outputs below the threshold to an address."));

  m_cmd_binder.set_handler("donate",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::donate, _1),
                           tr(USAGE_DONATE),
                           tr("Donate <amount> to the development team (donate.getmonero.org)."));


  m_cmd_binder.set_handler("address",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::print_address, _1),
                           tr("If no arguments are specified or <index> is specified, the wallet shows the default or specified address. "));

  m_cmd_binder.set_handler("viewkey",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::viewkey, _1),
                           tr("Display the private view key."));
  m_cmd_binder.set_handler("spendkey",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::spendkey, _1),
                           tr("Display the private spend key."));
  m_cmd_binder.set_handler("seed",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::seed, _1),
                           tr("Display the Electrum-style mnemonic seed"));
  m_cmd_binder.set_handler("restore_height",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::restore_height, _1),
                           tr("Display the restore height"));
  m_cmd_binder.set_handler("set",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::set_variable, _1),
                           tr(USAGE_SET_VARIABLE),
                           tr("Available options:\n "
                                  "seed language\n "
                                  "  Set the wallet's seed language.\n "
                                  "auto-refresh <1|0>\n "
                                  "  Whether to automatically synchronize new blocks from the daemon.\n "
                                  "ask-password <0|1|2   (or never|action|decrypt)>\n "
                                  "  action: ask the password before many actions such as transfer, etc\n "
                                  "  decrypt: same as action, but keeps the spend key encrypted in memory when not needed\n "
                                  "unit <monero|millinero|micronero|nanonero|piconero>\n "
                                  "  Set the default monero (sub-)unit.\n "
                                  "refresh-from-block-height [n]\n "
                                  "  Set the height before which to ignore blocks.\n "
                                  "inactivity-lock-timeout <unsigned int>\n "
                                  "  How many seconds to wait before locking the wallet (0 to disable)."));
  m_cmd_binder.set_handler("encrypted_seed",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::encrypted_seed, _1),
                           tr("Display the encrypted Electrum-style mnemonic seed."));
  m_cmd_binder.set_handler("rescan_spent",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::rescan_spent, _1),
                           tr("Rescan the blockchain for spent outputs."));
  m_cmd_binder.set_handler("get_tx_key",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::get_tx_key, _1),
                           tr(USAGE_GET_TX_KEY),
                           tr("Get the transaction key (r) for a given <txid>."));

  m_cmd_binder.set_handler("check_tx_key",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::check_tx_key, _1),
                           tr(USAGE_CHECK_TX_KEY),
                           tr("Check the amount going to <address> in <txid>."));
  m_cmd_binder.set_handler("get_tx_proof",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::get_tx_proof, _1),
                           tr(USAGE_GET_TX_PROOF),
                           tr("Generate a signature proving funds sent to <address> in <txid>, optionally with a challenge string <message>, using either the transaction secret key (when <address> is not your wallet's address) or the view secret key (otherwise), which does not disclose the secret key."));
  m_cmd_binder.set_handler("check_tx_proof",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::check_tx_proof, _1),
                           tr(USAGE_CHECK_TX_PROOF),
                           tr("Check the proof for funds going to <address> in <txid> with the challenge string <message> if any."));
  m_cmd_binder.set_handler("get_spend_proof",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::get_spend_proof, _1),
                           tr(USAGE_GET_SPEND_PROOF),
                           tr("Generate a signature proving that you generated <txid> using the spend secret key, optionally with a challenge string <message>."));
  m_cmd_binder.set_handler("check_spend_proof",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::check_spend_proof, _1),
                           tr(USAGE_CHECK_SPEND_PROOF),
                           tr("Check a signature proving that the signer generated <txid>, optionally with a challenge string <message>."));
  
  m_cmd_binder.set_handler("show_transfers",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::show_transfers, _1),
                           tr(USAGE_SHOW_TRANSFERS),
                           // Seemingly broken formatting to compensate for the backslash before the quotes.
                           tr("Show the incoming/outgoing transfers within an optional height range.\n\n"
                              "Output format:\n"
                              "In or Coinbase:    Block Number, \"block\"|\"in\",              Time, Amount,  Transaction Hash, Payment ID, Subaddress Index,                     \"-\", Note\n"
                              "Out:               Block Number, \"out\",                     Time, Amount*, Transaction Hash, Payment ID, Fee, Destinations, Input addresses**, \"-\", Note\n"
                              "Pool:                            \"pool\", \"in\",              Time, Amount,  Transaction Hash, Payment Id, Subaddress Index,                     \"-\", Note, Double Spend Note\n"
                              "Pending or Failed:               \"failed\"|\"pending\", \"out\", Time, Amount*, Transaction Hash, Payment ID, Fee, Input addresses**,               \"-\", Note\n\n"
                              "* Excluding change and fee.\n"
                              "** Set of address indices used as inputs in this transfer."));

  m_cmd_binder.set_handler("rescan_bc",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::rescan_blockchain, _1),
                           tr(USAGE_RESCAN_BC),
                           tr("Rescan the blockchain from scratch. If \"hard\" is specified, you will lose any information which can not be recovered from the blockchain itself."));
  m_cmd_binder.set_handler("status",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::status, _1),
                           tr("Show the wallet's status."));
  m_cmd_binder.set_handler("wallet_info",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::wallet_info, _1),
                           tr("Show the wallet's information."));
 
  m_cmd_binder.set_handler("password",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::change_password, _1),
                           tr("Change the wallet's password."));
  m_cmd_binder.set_handler("lock",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::lock, _1),
                           tr(USAGE_LOCK),
                           tr("Lock the wallet console, requiring the wallet password to continue"));
  m_cmd_binder.set_handler("net_stats",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::net_stats, _1),
                           tr(USAGE_NET_STATS),
                           tr("Prints simple network stats"));
  m_cmd_binder.set_handler("public_nodes",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::public_nodes, _1),
                           tr(USAGE_PUBLIC_NODES),
                           tr("Lists known public nodes"));
  m_cmd_binder.set_handler("welcome",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::welcome, _1),
                           tr(USAGE_WELCOME),
                           tr("Prints basic info about DFA for first time users"));
  m_cmd_binder.set_handler("version",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::version, _1),
                           tr(USAGE_VERSION),
                           tr("Returns version information"));
 
  m_cmd_binder.set_handler("help",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::help, _1),
                           tr(USAGE_HELP),
                           tr("Show the help section or the documentation about a <command>."));
 m_cmd_binder.set_handler("apropos",
                           boost::bind(&simple_wallet::on_command, this, &simple_wallet::apropos, _1),
                           tr(USAGE_APROPOS),
                           tr("Search all command descriptions for keyword(s)"));

  m_cmd_binder.set_unknown_command_handler(boost::bind(&simple_wallet::on_command, this, &simple_wallet::on_unknown_command, _1));
  m_cmd_binder.set_empty_command_handler(boost::bind(&simple_wallet::on_empty_command, this));
  m_cmd_binder.set_cancel_handler(boost::bind(&simple_wallet::on_cancelled_command, this));
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::set_variable(const std::vector<std::string> &args)
{
  if (args.empty())
  {
    std::string seed_language = m_wallet->get_seed_language();
    if (m_use_english_language_names)
      seed_language = crypto::ElectrumWords::get_english_name_for(seed_language);
    std::string priority_string = "invalid";
    std::string ask_password_string = "invalid";
  
    success_msg_writer() << "seed = " << seed_language;
    success_msg_writer() << "auto-refresh = " << m_wallet->auto_refresh();
    success_msg_writer() << "unit = " << cryptonote::get_unit(cryptonote::get_default_decimal_point());
    success_msg_writer() << "max-reorg-depth = " << m_wallet->max_reorg_depth();
    success_msg_writer() << "refresh-from-block-height = " << m_wallet->get_refresh_from_block_height();
    success_msg_writer() << "inactivity-lock-timeout = " << m_wallet->inactivity_lock_timeout()
#ifdef _WIN32
        << " (disabled on Windows)"
#endif
        ;
    return true;
  }
  else
  {

#define CHECK_SIMPLE_VARIABLE(name, f, help) do \
  if (args[0] == name) { \
    if (args.size() <= 1) \
    { \
      fail_msg_writer() << "set " << #name << ": " << tr("needs an argument") << " (" << help << ")"; \
      return true; \
    } \
    else \
    { \
      f(args); \
      return true; \
    } \
  } while(0)

    if (args[0] == "seed")
    {
      if (args.size() == 1)
      {
        fail_msg_writer() << tr("set seed: needs an argument. available options: language");
        return true;
      }
      else if (args[1] == "language")
      {
        seed_set_language(args);
        return true;
      }
    }
    CHECK_SIMPLE_VARIABLE("always-confirm-transfers", set_always_confirm_transfers, tr("0 or 1"));
    CHECK_SIMPLE_VARIABLE("auto-refresh", set_auto_refresh, tr("0 or 1"));
    CHECK_SIMPLE_VARIABLE("unit", set_unit, tr("monero, millinero, micronero, nanonero, piconero"));
    CHECK_SIMPLE_VARIABLE("max-reorg-depth", set_max_reorg_depth, tr("unsigned integer"));
    CHECK_SIMPLE_VARIABLE("inactivity-lock-timeout", set_inactivity_lock_timeout, tr("unsigned integer (seconds, 0 to disable)"));
  }
  fail_msg_writer() << tr("set: unrecognized argument(s)");
  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::set_log(const std::vector<std::string> &args)
{
  if(args.size() > 1)
  {
    PRINT_USAGE(USAGE_SET_LOG);
    return true;
  }
  if(!args.empty())
  {
    uint16_t level = 0;
    if(epee::string_tools::get_xtype_from_string(level, args[0]))
    {
      if(4 < level)
      {
        fail_msg_writer() << boost::format(tr("wrong number range, use: %s")) % USAGE_SET_LOG;
        return true;
      }
      mlog_set_log_level(level);
    }
    else
    {
      mlog_set_log(args[0].c_str());
    }
  }
  
  success_msg_writer() << "New log categories: " << mlog_get_categories();
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::ask_wallet_create_if_needed()
{
  LOG_PRINT_L3("simple_wallet::ask_wallet_create_if_needed() started");
  std::string wallet_path;
  std::string confirm_creation;
  bool wallet_name_valid = false;
  bool keys_file_exists;
  bool wallet_file_exists;

  do{
      LOG_PRINT_L3("User asked to specify wallet file name.");
      wallet_path = input_line(
        tr(m_restoring ? "Specify a new wallet file name for your restored wallet (e.g., MyWallet).\n"
        "Wallet file name (or Ctrl-C to quit)" :
        "Specify wallet file name (e.g., MyWallet). If the wallet doesn't exist, it will be created.\n"
        "Wallet file name (or Ctrl-C to quit)")
      );
      if(std::cin.eof())
      {
        LOG_ERROR("Unexpected std::cin.eof() - Exited simple_wallet::ask_wallet_create_if_needed()");
        return false;
      }
      if(!tools::wallet2::wallet_valid_path_format(wallet_path))
      {
        fail_msg_writer() << tr("Wallet name not valid. Please try again or use Ctrl-C to quit.");
        wallet_name_valid = false;
      }
      else
      {
        tools::wallet2::wallet_exists(wallet_path, keys_file_exists, wallet_file_exists);
        LOG_PRINT_L3("wallet_path: " << wallet_path << "");
        LOG_PRINT_L3("keys_file_exists: " << std::boolalpha << keys_file_exists << std::noboolalpha
        << "  wallet_file_exists: " << std::boolalpha << wallet_file_exists << std::noboolalpha);

        if((keys_file_exists || wallet_file_exists) && (!m_generate_new.empty() || m_restoring))
        {
          fail_msg_writer() << tr("Attempting to generate or restore wallet, but specified file(s) exist.  Exiting to not risk overwriting.");
          return false;
        }
        if(wallet_file_exists && keys_file_exists) //Yes wallet, yes keys
        {
          success_msg_writer() << tr("Wallet and key files found, loading...");
          m_wallet_file = wallet_path;
          return true;
        }
        else if(!wallet_file_exists && keys_file_exists) //No wallet, yes keys
        {
          success_msg_writer() << tr("Key file found but not wallet file. Regenerating...");
          m_wallet_file = wallet_path;
          return true;
        }
        else if(wallet_file_exists && !keys_file_exists) //Yes wallet, no keys
        {
          fail_msg_writer() << tr("Key file not found. Failed to open wallet: ") << "\"" << wallet_path << "\". Exiting.";
          return false;
        }
        else if(!wallet_file_exists && !keys_file_exists) //No wallet, no keys
        {
          bool ok = true;
          if (!m_restoring)
          {
            message_writer() << tr("No wallet found with that name. Confirm creation of new wallet named: ") << wallet_path;
            confirm_creation = input_line("", true);
            if(std::cin.eof())
            {
              LOG_ERROR("Unexpected std::cin.eof() - Exited simple_wallet::ask_wallet_create_if_needed()");
              return false;
            }
            ok = command_line::is_yes(confirm_creation);
          }
          if (ok)
          {
            success_msg_writer() << tr("Generating new wallet...");
            m_generate_new = wallet_path;
            return true;
          }
        }
      }
    } while(!wallet_name_valid);

  LOG_ERROR("Failed out of do-while loop in ask_wallet_create_if_needed()");
  return false;
}

/*!
 * \brief Prints the seed with a nice message
 * \param seed seed to print
 */
void simple_wallet::print_seed(const epee::wipeable_string &seed)
{
  success_msg_writer(true) << "\n" << boost::format(tr("NOTE: the following %s can be used to recover access to your wallet. "
    "Write them down and store them somewhere safe and secure. Please do not store them in "
    "your email or on file storage services outside of your immediate control.\n")) %  tr("25 words");
  // don't log
  int space_index = 0;
  size_t len  = seed.size();
  for (const char *ptr = seed.data(); len--; ++ptr)
  {
    if (*ptr == ' ')
    {
      if (space_index == 15 || space_index == 7)
        putchar('\n');
      else
        putchar(*ptr);
      ++space_index;
    }
    else
      putchar(*ptr);
  }
  putchar('\n');
  fflush(stdout);
}
//----------------------------------------------------------------------------------------------------
static bool might_be_partial_seed(const epee::wipeable_string &words)
{
  std::vector<epee::wipeable_string> seed;

  words.split(seed);
  return seed.size() < 24;
}
//----------------------------------------------------------------------------------------------------
static bool datestr_to_int(const std::string &heightstr, uint16_t &year, uint8_t &month, uint8_t &day)
{
  if (heightstr.size() != 10 || heightstr[4] != '-' || heightstr[7] != '-')
  {
    fail_msg_writer() << tr("date format must be YYYY-MM-DD");
    return false;
  }
  try
  {
    year  = boost::lexical_cast<uint16_t>(heightstr.substr(0,4));
    // lexical_cast<uint8_t> won't work because uint8_t is treated as character type
    month = boost::lexical_cast<uint16_t>(heightstr.substr(5,2));
    day   = boost::lexical_cast<uint16_t>(heightstr.substr(8,2));
  }
  catch (const boost::bad_lexical_cast &)
  {
    fail_msg_writer() << tr("bad height parameter: ") << heightstr;
    return false;
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::init(const boost::program_options::variables_map& vm)
{
  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){
    m_electrum_seed.wipe();
  });

  const bool testnet = tools::wallet2::has_testnet_option(vm);
  const bool stagenet = tools::wallet2::has_stagenet_option(vm);
  if (testnet && stagenet)
  {
    fail_msg_writer() << tr("Can't specify more than one of --testnet and --stagenet");
    return false;
  }
  const network_type nettype = testnet ? TESTNET : stagenet ? STAGENET : MAINNET;

  epee::wipeable_string password;

  if (!handle_command_line(vm))
    return false;

  bool welcome = false;

  if((!m_generate_new.empty()) + (!m_wallet_file.empty()) + (!m_restore_from_spend_key.empty())  > 1)
  {
    fail_msg_writer() << tr("can't specify more than one of --generate-new-wallet=\"wallet_name\", --wallet-file=\"wallet_name\", --generate-from-spend-key=\"wallet_name\", ");
    return false;
  }
  else if (m_generate_new.empty() && m_wallet_file.empty()  && m_restore_from_spend_key.empty() )
  {
    if(!ask_wallet_create_if_needed()) 
      return false;
  }

  if (!m_generate_new.empty() || m_restoring)
  {

    std::string old_language;
    // check for recover flag.  if present, require electrum word list (only recovery option for now).
    if (m_restore_from_seed )
    {

      if (!m_wallet_file.empty())
      {
          fail_msg_writer() << tr("--restore-deterministic-wallet uses --generate-new-wallet, not --wallet-file");
        return false;
      }

      if (m_electrum_seed.empty())
      {
          m_electrum_seed = "";
          do
          {
            const char *prompt = m_electrum_seed.empty() ? "Specify Electrum seed" : "Electrum seed continued";
            epee::wipeable_string electrum_seed = input_secure_line(prompt);
            if (std::cin.eof())
              return false;
            if (electrum_seed.empty())
            {
              fail_msg_writer() << tr("specify a recovery parameter with the --electrum-seed=\"words list here\"");
              return false;
            }
            m_electrum_seed += electrum_seed;
            m_electrum_seed += ' ';
          } while (might_be_partial_seed(m_electrum_seed));
        
      }

      {
        if (!crypto::ElectrumWords::words_to_bytes(m_electrum_seed, m_recovery_key, old_language))
        {
          fail_msg_writer() << tr("Electrum-style word list failed verification");
          return false;
        }
      }

      auto pwd_container = password_prompter(tr("Enter seed offset passphrase, empty if none"), false);
      if (std::cin.eof() || !pwd_container)
        return false;
      epee::wipeable_string seed_pass = pwd_container->password();
      if (!seed_pass.empty())
      {
          m_recovery_key = cryptonote::decrypt_key(m_recovery_key, seed_pass);
      }
    }

   if (!m_restore_from_spend_key.empty())
    {
      m_wallet_file = m_restore_from_spend_key;
      // parse spend secret key
      epee::wipeable_string spendkey_string = input_secure_line("Secret spend key");
      if (std::cin.eof())
        return false;
      if (spendkey_string.empty()) {
        fail_msg_writer() << tr("No data supplied, cancelled");
        return false;
      }
      if (!spendkey_string.hex_to_pod(unwrap(unwrap(m_recovery_key))))
      {
        fail_msg_writer() << tr("failed to parse spend key secret key");
        return false;
      }
      auto r = new_wallet(vm, m_recovery_key, true,  "");
      CHECK_AND_ASSERT_MES(r, false, tr("account creation failed"));
      password = *r;
      welcome = true;
    }
    else
    {
      if (m_generate_new.empty()) {
        fail_msg_writer() << tr("specify a wallet path with --generate-new-wallet (not --wallet-file)");
        return false;
      }
      m_wallet_file = m_generate_new;
      boost::optional<epee::wipeable_string> r;
     
        r = new_wallet(vm, m_recovery_key, m_restore_from_seed, old_language);
      CHECK_AND_ASSERT_MES(r, false, tr("account creation failed"));
      password = *r;
      welcome = true;
    }

    if (m_restoring  )
    {
      const auto explicit_restore = !(command_line::is_arg_defaulted(vm, arg_restore_height) &&
        command_line::is_arg_defaulted(vm, arg_restore_date));
      m_wallet->explicit_refresh_from_block_height(explicit_restore);
      if (command_line::is_arg_defaulted(vm, arg_restore_height) && !command_line::is_arg_defaulted(vm, arg_restore_date))
      {
        uint16_t year;
        uint8_t month;
        uint8_t day;
        if (!datestr_to_int(m_restore_date, year, month, day))
          return false;
        try
        {
          m_restore_height = m_wallet->get_blockchain_height_by_date(year, month, day);
          success_msg_writer() << tr("Restore height is: ") << m_restore_height;
        }
        catch (const std::runtime_error& e)
        {
          fail_msg_writer() << e.what();
          return false;
        }
      }
    }
    if (!m_wallet->explicit_refresh_from_block_height() && m_restoring)
    {
      uint32_t version;
      bool connected = try_connect_to_daemon(false, &version);
      while (true)
      {
        std::string heightstr;
        if (!connected || version < MAKE_CORE_RPC_VERSION(1, 6))
          heightstr = input_line("Restore from specific blockchain height (optional, default 0)");
        else
          heightstr = input_line("Restore from specific blockchain height (optional, default 0),\nor alternatively from specific date (YYYY-MM-DD)");
        if (std::cin.eof())
          return false;
        if (heightstr.empty())
        {
          m_restore_height = 0;
          break;
        }
        try
        {
          m_restore_height = boost::lexical_cast<uint64_t>(heightstr);
          break;
        }
        catch (const boost::bad_lexical_cast &)
        {
          if (!connected || version < MAKE_CORE_RPC_VERSION(1, 6))
          {
            fail_msg_writer() << tr("bad m_restore_height parameter: ") << heightstr;
            continue;
          }
          uint16_t year;
          uint8_t month;  // 1, 2, ..., 12
          uint8_t day;    // 1, 2, ..., 31
          try
          {
            if (!datestr_to_int(heightstr, year, month, day))
              return false;
            m_restore_height = m_wallet->get_blockchain_height_by_date(year, month, day);
            success_msg_writer() << tr("Restore height is: ") << m_restore_height;
            std::string confirm = input_line(tr("Is this okay?"), true);
            if (std::cin.eof())
              return false;
            if(command_line::is_yes(confirm))
              break;
          }
          catch (const boost::bad_lexical_cast &)
          {
            fail_msg_writer() << tr("bad m_restore_height parameter: ") << heightstr;
          }
          catch (const std::runtime_error& e)
          {
            fail_msg_writer() << e.what();
          }
        }
      }
    }
    if (m_restoring)
    {
  
      m_wallet->set_refresh_from_block_height(m_restore_height);
    }
    m_wallet->rewrite(m_wallet_file, password);
  }
  else
  {
    assert(!m_wallet_file.empty());
    auto r = open_wallet(vm);
    auto p = r ?  (*r).data():"";
    std::cout<<"open_wallet return "<< p<<std::endl;
    CHECK_AND_ASSERT_MES(r, false, tr("failed to open account"));
    password = *r;
  }
  if (!m_wallet)
  {
    fail_msg_writer() << tr("wallet is null");
    return false;
  }


  if (welcome)
    message_writer(console_color_yellow, true) << tr("If you are new to DFA, type \"welcome\" for a brief overview.");

  m_last_activity_time = time(NULL);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::deinit()
{
  if (!m_wallet.get())
    return true;

  return close_wallet();
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::handle_command_line(const boost::program_options::variables_map& vm)
{
  m_wallet_file                   = command_line::get_arg(vm, arg_wallet_file);
  m_generate_new                  = command_line::get_arg(vm, arg_generate_new_wallet);
  m_restore_from_spend_key       = command_line::get_arg(vm, arg_generate_from_spend_key);
  m_mnemonic_language             = command_line::get_arg(vm, arg_mnemonic_language);
  m_electrum_seed                 = command_line::get_arg(vm, arg_electrum_seed);
  m_restore_from_seed  = command_line::get_arg(vm, arg_restore_from_seed);
  m_allow_mismatched_daemon_version = command_line::get_arg(vm, arg_allow_mismatched_daemon_version);
  m_restore_height                = command_line::get_arg(vm, arg_restore_height);
  m_restore_date                  = command_line::get_arg(vm, arg_restore_date);
  m_use_english_language_names    = command_line::get_arg(vm, arg_use_english_language_names);
  m_restoring                     = !m_restore_from_spend_key.empty() ||
                                    m_restore_from_seed ;

  if (!command_line::is_arg_defaulted(vm, arg_restore_date))
  {
    uint16_t year;
    uint8_t month, day;
    if (!datestr_to_int(m_restore_date, year, month, day))
      return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::try_connect_to_daemon(bool silent, uint32_t* version)
{
  uint32_t version_ = 0;
  if (!version)
    version = &version_;
  if (!m_wallet->check_connection(version))
  {
    if (!silent)
    {
      if (m_wallet->is_offline())
        fail_msg_writer() << tr("wallet failed to connect to daemon, because it is set to offline mode");
      else
        fail_msg_writer() << tr("wallet failed to connect to daemon: ") << m_wallet->get_daemon_address() << ". " <<
          tr("Daemon either is not started or wrong port was passed. "
          "Please make sure daemon is running or change the daemon address using the 'set_daemon' command.");
    }
    return false;
  }
  if (!m_allow_mismatched_daemon_version && ((*version >> 16) != CORE_RPC_VERSION_MAJOR))
  {
    if (!silent)
      fail_msg_writer() << boost::format(tr("Daemon uses a different RPC major version (%u) than the wallet (%u): %s. Either update one of them, or use --allow-mismatched-daemon-version.")) % (*version>>16) % CORE_RPC_VERSION_MAJOR % m_wallet->get_daemon_address();
    return false;
  }
  return true;
}

/*!
 * \brief Gets the word seed language from the user.
 * 
 * User is asked to choose from a list of supported languages.
 * 
 * \return The chosen language.
 */
std::string simple_wallet::get_mnemonic_language()
{
  std::vector<std::string> language_list_self, language_list_english;
  const std::vector<std::string> &language_list = m_use_english_language_names ? language_list_english : language_list_self;
  std::string language_choice;
  int language_number = -1;
  crypto::ElectrumWords::get_language_list(language_list_self, false);
  crypto::ElectrumWords::get_language_list(language_list_english, true);
  std::cout << tr("List of available languages for your wallet's seed:") << std::endl;
  std::cout << tr("If your display freezes, exit blind with ^C, then run again with --use-english-language-names") << std::endl;
  int ii;
  std::vector<std::string>::const_iterator it;
  for (it = language_list.begin(), ii = 0; it != language_list.end(); it++, ii++)
  {
    std::cout << ii << " : " << *it << std::endl;
  }
  while (language_number < 0)
  {
    language_choice = input_line(tr("Enter the number corresponding to the language of your choice"));
    if (std::cin.eof())
      return std::string();
    try
    {
      language_number = std::stoi(language_choice);
      if (!((language_number >= 0) && (static_cast<unsigned int>(language_number) < language_list.size())))
      {
        language_number = -1;
        fail_msg_writer() << tr("invalid language choice entered. Please try again.\n");
      }
    }
    catch (const std::exception &e)
    {
      fail_msg_writer() << tr("invalid language choice entered. Please try again.\n");
    }
  }
  return language_list_self[language_number];
}
//----------------------------------------------------------------------------------------------------
boost::optional<tools::password_container> simple_wallet::get_and_verify_password() const
{
  auto pwd_container = default_password_prompter(m_wallet_file.empty());
  if (!pwd_container)
    return boost::none;

  if (!m_wallet->verify_password(pwd_container->password()))
  {
    fail_msg_writer() << tr("invalid password");
    return boost::none;
  }
  return pwd_container;
}
//----------------------------------------------------------------------------------------------------
boost::optional<epee::wipeable_string> simple_wallet::new_wallet(const boost::program_options::variables_map& vm,const crypto::secret_key& recovery_key, bool recover, const std::string &old_language)
{
  std::pair<std::unique_ptr<tools::wallet2>, tools::password_container> rc;
  try {
   rc = tools::wallet2::make_new(vm, false, password_prompter);
    }
  catch(const std::exception &e) { fail_msg_writer() << tr("Error creating wallet: ") << e.what(); return {}; }
  m_wallet = std::move(rc.first);
  if (!m_wallet)
  {
    return {};
  }
  epee::wipeable_string password = rc.second.password();

  std::string mnemonic_language = old_language;

  std::vector<std::string> language_list;
  crypto::ElectrumWords::get_language_list(language_list);
  if (mnemonic_language.empty() && std::find(language_list.begin(), language_list.end(), m_mnemonic_language) != language_list.end())
  {
    mnemonic_language = m_mnemonic_language;
  }

  // Ask for seed language if:
  // it's a deterministic wallet AND
  // a seed language is not already specified AND
  // (it is not a wallet restore OR if it was a deprecated wallet
  // that was earlier used before this restore)
  if ( mnemonic_language.empty() ||  !m_restore_from_seed )
  {
    mnemonic_language = get_mnemonic_language();
    if (mnemonic_language.empty())
      return {};
  }

  m_wallet->set_seed_language(mnemonic_language);

  bool create_address_file = command_line::get_arg(vm, arg_create_address_file);

  crypto::secret_key recovery_val;
  try
  {
    recovery_val = m_wallet->generate(m_wallet_file, std::move(rc.second).password(), recovery_key, recover,  create_address_file);
    message_writer(console_color_white, true) << tr("Generated new wallet: ")
      << m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    PAUSE_READLINE();
    std::cout << tr("View key: ");
    print_secret_key(m_wallet->get_account().get_keys().m_view_secret_key);
    putchar('\n');
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << tr("failed to generate new wallet: ") << e.what();
    return {};
  }

  // convert rng value to electrum-style word list
  epee::wipeable_string electrum_words;

  crypto::ElectrumWords::bytes_to_words(recovery_val, electrum_words, mnemonic_language);

  success_msg_writer() <<
    "**********************************************************************\n" <<
    tr("Your wallet has been generated!\n"
    "To start synchronizing with the daemon, use the \"refresh\" command.\n"
    "Use the \"help\" command to see a simplified list of available commands.\n"
    "Use \"help all\" command to see the list of all available commands.\n"
    "Use \"help <command>\" to see a command's documentation.\n"
    "Always use the \"exit\" command when closing monero-wallet-cli to save \n"
    "your current session's state. Otherwise, you might need to synchronize \n"
    "your wallet again (your wallet keys are NOT at risk in any case).\n")
  ;

  {
    print_seed(electrum_words);
  }
  success_msg_writer() << "**********************************************************************";

  return password;
}


//----------------------------------------------------------------------------------------------------
boost::optional<epee::wipeable_string> simple_wallet::open_wallet(const boost::program_options::variables_map& vm)
{
  if (!tools::wallet2::wallet_valid_path_format(m_wallet_file))
  {
    fail_msg_writer() << tr("wallet file path not valid: ") << m_wallet_file;
    return {};
  }

  bool keys_file_exists;
  bool wallet_file_exists;

  tools::wallet2::wallet_exists(m_wallet_file, keys_file_exists, wallet_file_exists);
  if(!keys_file_exists)
  {
    fail_msg_writer() << tr("Key file not found. Failed to open wallet");
    return {};
  }
  
  epee::wipeable_string password;
  try
  {
    auto rc = tools::wallet2::make_from_file(vm, false, "", password_prompter);
    m_wallet = std::move(rc.first);
    password = std::move(std::move(rc.second).password());
    if (!m_wallet)
    {
      return {};
    }

    MINFO("open wallet "<<m_wallet_file);
    m_wallet->load(m_wallet_file, password);
    std::string prefix;
    bool ready;
    uint32_t threshold, total;
      prefix = tr("Opened wallet");
    message_writer(console_color_white, true) <<
      prefix << ": " << m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    if (m_wallet->get_account().get_device()) {
       message_writer(console_color_white, true) << "Wallet is on device: " << m_wallet->get_account().get_device().get_name();
    }
   
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << tr("failed to load wallet: ") << e.what();
    if (m_wallet)
    {
      // only suggest removing cache if the password was actually correct
      bool password_is_correct = false;
      try
      {
        password_is_correct = m_wallet->verify_password(password);
        std::cout<<"password_is_correct"<<password_is_correct<<std::endl;
      }
      catch (...) { } // guard against I/O errors
      if (password_is_correct)
        fail_msg_writer() << boost::format(tr("You may want to remove the file \"%s\" and try again")) % m_wallet_file;
    }
    return {};
  }
  success_msg_writer() <<
    "**********************************************************************\n" <<
    tr("Use the \"help\" command to see a simplified list of available commands.\n") <<
    tr("Use \"help all\" to see the list of all available commands.\n") <<
    tr("Use \"help <command>\" to see a command's documentation.\n") <<
    "**********************************************************************";
  return password;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::close_wallet()
{
  if (m_idle_run.load(std::memory_order_relaxed))
  {
    m_idle_run.store(false, std::memory_order_relaxed);
    m_wallet->stop();
    {
      boost::unique_lock<boost::mutex> lock(m_idle_mutex);
      m_idle_cond.notify_one();
    }
    m_idle_thread.join();
  }

  bool r = m_wallet->deinit();
  if (!r)
  {
    fail_msg_writer() << tr("failed to deinitialize wallet");
    return false;
  }

  try
  {
    m_wallet->store();
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << e.what();
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::save(const std::vector<std::string> &args)
{
  try
  {
    LOCK_IDLE_SCOPE();
    m_wallet->store();
    success_msg_writer() << tr("Wallet data saved");
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << e.what();
  }

  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::set_daemon(const std::vector<std::string>& args)
{
  std::string daemon_url;

  if (args.size() < 1)
  {
    PRINT_USAGE(USAGE_SET_DAEMON);
    return true;
  }

  boost::regex rgx("^(.*://)?([A-Za-z0-9\\-\\.]+)(:[0-9]+)?");
  boost::cmatch match;
  // If user input matches URL regex
  if (boost::regex_match(args[0].c_str(), match, rgx))
  {
    if (match.length() < 4)
    {
      fail_msg_writer() << tr("Unexpected array length - Exited simple_wallet::set_daemon()");
      return true;
    }
    // If no port has been provided, use the default from config
    if (!match[3].length())
    {
      uint16_t daemon_port = get_config(m_wallet->nettype()).RPC_DEFAULT_PORT;
      daemon_url = match[1] + match[2] + std::string(":") + std::to_string(daemon_port);
    } else {
      daemon_url = args[0];
    }

    epee::net_utils::http::url_content parsed{};
    const bool r = epee::net_utils::parse_url(daemon_url, parsed);
    if (!r)
    {
      fail_msg_writer() << tr("Failed to parse address");
      return true;
    }

    if (!tools::is_privacy_preserving_network(parsed.host) && !tools::is_local_address(parsed.host))
    {
      if (parsed.schema != "https")
        message_writer(console_color_red) << tr("Warning: connecting to a non-local daemon without SSL, passive adversaries will be able to spy on you.");
    }

    LOCK_IDLE_SCOPE();
    m_wallet->init(daemon_url);

    if (!try_connect_to_daemon())
    {
      fail_msg_writer() << tr("Failed to connect to daemon");
      return true;
    }

    success_msg_writer() << boost::format("Daemon set to %s, %s") % daemon_url <<endl;

  
  } else {
    fail_msg_writer() << tr("This does not seem to be a valid daemon URL.");
  }
  return true;
}

//----------------------------------------------------------------------------------------------------
void simple_wallet::on_new_block(uint64_t height, const cryptonote::block& block)
{
  if (m_locked)
    return;
  if (!m_auto_refresh_refreshing)
    m_refresh_progress_reporter.update(height, false);
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount,  bool is_change, uint64_t unlock_time)
{
  if (m_locked)
    return;
  message_writer(console_color_green, false) << "\r" <<
    tr("Height ") << height << ", " <<
    tr("txid ") << txid << ", " <<
    print_money(amount) ;

  const uint64_t warn_height = m_wallet->nettype() == TESTNET ? 1000000 : m_wallet->nettype() == STAGENET ? 50000 : 1650000;

  if (unlock_time && !cryptonote::is_coinbase(tx))
    message_writer() << tr("NOTE: This transaction is locked, see details with: show_transfer ") + epee::string_tools::pod_to_hex(txid);
  if (m_auto_refresh_refreshing)
    m_cmd_binder.print_prompt();
  else
    m_refresh_progress_reporter.update(height, true);
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount)
{
  if (m_locked)
    return;
  // Not implemented in CLI wallet
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_money_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& in_tx, uint64_t amount, const cryptonote::transaction& spend_tx)
{
  if (m_locked)
    return;
  message_writer(console_color_magenta, false) << "\r" <<
    tr("Height ") << height << ", " <<
    tr("txid ") << txid << ", " <<
    tr("spent ") << print_money(amount) ;
  if (m_auto_refresh_refreshing)
    m_cmd_binder.print_prompt();
  else
    m_refresh_progress_reporter.update(height, true);
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_skip_transaction(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx)
{
  if (m_locked)
    return;
}
//----------------------------------------------------------------------------------------------------
boost::optional<epee::wipeable_string> simple_wallet::on_get_password(const char *reason)
{
  if (m_locked)
    return boost::none;
  // can't ask for password from a background thread
  if (!m_in_manual_refresh.load(std::memory_order_relaxed))
  {
    message_writer(console_color_red, false) << boost::format(tr("Password needed (%s) - use the refresh command")) % reason;
    m_cmd_binder.print_prompt();
    return boost::none;
  }

  PAUSE_READLINE();
  std::string msg = tr("Enter password");
  if (reason && *reason)
    msg += std::string(" (") + reason + ")";
  auto pwd_container = tools::password_container::prompt(false, msg.c_str());
  if (!pwd_container)
  {
    MERROR("Failed to read password");
    return boost::none;
  }

  return pwd_container->password();
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_device_button_request(uint64_t code)
{
  message_writer(console_color_white, false) << tr("Device requires attention");
}
//----------------------------------------------------------------------------------------------------
boost::optional<epee::wipeable_string> simple_wallet::on_device_pin_request()
{
  PAUSE_READLINE();
  std::string msg = tr("Enter device PIN");
  auto pwd_container = tools::password_container::prompt(false, msg.c_str());
  throw_wallet_ex_if(!pwd_container, tools::error::password_entry_failed, tr("Failed to read device PIN"));
  return pwd_container->password();
}
//----------------------------------------------------------------------------------------------------
boost::optional<epee::wipeable_string> simple_wallet::on_device_passphrase_request(bool & on_device)
{
  if (on_device) {
    std::string accepted = input_line(tr(
        "Device asks for passphrase. Do you want to enter the passphrase on device (Y) (or on the host (N))?"));
    if (std::cin.eof() || command_line::is_yes(accepted)) {
      message_writer(console_color_white, true) << tr("Please enter the device passphrase on the device");
      return boost::none;
    }
  }

  PAUSE_READLINE();
  on_device = false;
  std::string msg = tr("Enter device passphrase");
  auto pwd_container = tools::password_container::prompt(false, msg.c_str());
  throw_wallet_ex_if(!pwd_container, tools::error::password_entry_failed, tr("Failed to read device passphrase"));
  return pwd_container->password();
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_refresh_finished(uint64_t start_height, uint64_t fetched_blocks, bool is_init, bool received_money)
{
  const uint64_t rfbh = m_wallet->get_refresh_from_block_height();
  std::string err;
  const uint64_t dh = m_wallet->get_daemon_blockchain_height(err);
  if (err.empty() && rfbh > dh)
  {
    message_writer(console_color_yellow, false) << tr("The wallet's refresh-from-block-height setting is higher than the daemon's height: this may mean your wallet will skip over transactions");
  }

  // Key image sync after the first refresh
  if (!m_wallet->get_account().get_device().has_tx_cold_sign() || m_wallet->get_account().get_device().has_ki_live_refresh()) {
    return;
  }

  if (!received_money ) {
    return;
  }

  // Finished first refresh for HW device and money received -> KI sync
  message_writer() << "\n" << tr("The first refresh has finished for the HW-based wallet with received money. hw_key_images_sync is needed. ");

  std::string accepted = input_line(tr("Do you want to do it now? (Y/Yes/N/No): "));
  if (std::cin.eof() || !command_line::is_yes(accepted)) {
    message_writer(console_color_red, false) << tr("hw_key_images_sync skipped. Run command manually before a transfer.");
    return;
  }

}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::refresh_main(uint64_t start_height, bool is_init)
{
  if (!try_connect_to_daemon(is_init))
    return true;

  LOCK_IDLE_SCOPE();

  crypto::hash transfer_hash_pre{};
  uint64_t height_pre = 0, height_post;

  m_wallet->rescan_blockchain( false);
  PAUSE_READLINE();

  message_writer() << tr("Starting refresh...");

  uint64_t fetched_blocks = 0;
  bool received_money = false;
  bool ok = false;
  std::ostringstream ss;
  try
  {
    m_in_manual_refresh.store(true, std::memory_order_relaxed);
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){m_in_manual_refresh.store(false, std::memory_order_relaxed);});

    m_wallet->refresh( start_height, fetched_blocks, received_money);


    ok = true;
    // Clear line "Height xxx of xxx"
    std::cout << "\r                                                                \r";
    success_msg_writer(true) << tr("Refresh done, blocks received: ") << fetched_blocks;
    show_balance_unlocked();
    on_refresh_finished(start_height, fetched_blocks, is_init, received_money);
  }
  catch (const tools::error::daemon_busy&)
  {
    ss << tr("daemon is busy. Please try again later.");
  }
  catch (const tools::error::no_connection_to_daemon&)
  {
    ss << tr("no connection to daemon. Please make sure daemon is running.");
  }
  
  catch (const tools::error::wallet_rpc_error& e)
  {
    LOG_ERROR("RPC error: " << e.to_string());
    ss << tr("RPC error: ") << e.what();
  }
  catch (const tools::error::refresh_error& e)
  {
    LOG_ERROR("refresh error: " << e.to_string());
    ss << tr("refresh error: ") << e.what();
  }
  catch (const tools::error::wallet_internal_error& e)
  {
    LOG_ERROR("internal error: " << e.to_string());
    ss << tr("internal error: ") << e.what();
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("unexpected error: " << e.what());
    ss << tr("unexpected error: ") << e.what();
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    ss << tr("unknown error");
  }

  if (!ok)
  {
    fail_msg_writer() << tr("refresh failed: ") << ss.str() << ". " << tr("Blocks received: ") << fetched_blocks;
  }

  // prevent it from triggering the idle screen due to waiting for a foreground refresh
  m_last_activity_time = time(NULL);

  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_balance_unlocked(bool detailed)
{
  uint64_t unlocked_balance = m_wallet->unlocked_balance(false);

  success_msg_writer() << tr("Balance: ") << print_money(m_wallet->balance(false)) << ", "
    << tr("unlocked balance: ") << print_money(unlocked_balance) ;

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_balance(const std::vector<std::string>& args/* = std::vector<std::string>()*/)
{
  if (args.size() > 1 || (args.size() == 1 && args[0] != "detail"))
  {
    PRINT_USAGE(USAGE_SHOW_BALANCE);
    return true;
  }
  LOCK_IDLE_SCOPE();
  show_balance_unlocked(args.size() == 1);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_incoming_transfers(const std::vector<std::string>& args)
{
  if (args.size() > 3)
  {
    PRINT_USAGE(USAGE_INCOMING_TRANSFERS);
    return true;
  }
  LOCK_IDLE_SCOPE();

  PAUSE_READLINE();

  tools::wallet2::transfer_container transfers;
  m_wallet->get_transfers(transfers);

  size_t transfers_found = 0;
  for (const auto& td : transfers)
  {
      if (!transfers_found)
      {
        std::string verbose_string;
        message_writer() << boost::format("%21s%8s%12s%16u%68s") % tr("amount") % tr("spent") % tr("unlocked")  % tr("global index") % tr("tx id");
      }
      message_writer(td.m_spent ? console_color_magenta : console_color_green, false) <<
        boost::format("%21s%8s%12s%16u%68s") %
        print_money(td.amount()) %
        (td.m_spent ? tr("T") : tr("F")) %
        ( m_wallet->is_transfer_unlocked(td) ? tr("unlocked") : tr("locked")) %
        td.m_global_output_index %
        td.m_txid ;
      ++transfers_found;
  }

    success_msg_writer() << boost::format("Found %u transfers") % transfers.size();

  return true;
}

//----------------------------------------------------------------------------------------------------
uint64_t simple_wallet::get_daemon_blockchain_height(std::string& err)
{
  if (!m_wallet)
  {
    throw std::runtime_error("simple_wallet null wallet");
  }
  return m_wallet->get_daemon_blockchain_height(err);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_blockchain_height(const std::vector<std::string>& args)
{
  if (!try_connect_to_daemon())
    return true;

  std::string err;
  uint64_t bc_height = get_daemon_blockchain_height(err);
  if (err.empty())
    success_msg_writer() << bc_height;
  else
    fail_msg_writer() << tr("failed to get blockchain height: ") << err;
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::rescan_spent(const std::vector<std::string> &args)
{
 
  if (!try_connect_to_daemon())
    return true;

  try
  {
    LOCK_IDLE_SCOPE();
    m_wallet->rescan_spent();
  }
  catch (const tools::error::daemon_busy&)
  {
    fail_msg_writer() << tr("daemon is busy. Please try again later.");
  }
  catch (const tools::error::no_connection_to_daemon&)
  {
    fail_msg_writer() << tr("no connection to daemon. Please make sure daemon is running.");
  }
 
  catch (const tools::error::is_key_image_spent_error&)
  {
    fail_msg_writer() << tr("failed to get spent status");
  }
  catch (const tools::error::wallet_rpc_error& e)
  {
    LOG_ERROR("RPC error: " << e.to_string());
    fail_msg_writer() << tr("RPC error: ") << e.what();
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("unexpected error: " << e.what());
    fail_msg_writer() << tr("unexpected error: ") << e.what();
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
std::pair<std::string, std::string> simple_wallet::show_outputs_line(const std::vector<uint64_t> &heights, uint64_t blockchain_height, uint64_t highlight_idx) const
{
  std::stringstream ostr;

  for (uint64_t h: heights)
    blockchain_height = std::max(blockchain_height, h);

  for (size_t j = 0; j < heights.size(); ++j)
    ostr << (j == highlight_idx ? " *" : " ") << heights[j];

  // visualize the distribution, using the code by moneroexamples onion-monero-viewer
  const uint64_t resolution = 79;
  std::string ring_str(resolution, '_');
  for (size_t j = 0; j < heights.size(); ++j)
  {
    uint64_t pos = (heights[j] * resolution) / blockchain_height;
    ring_str[pos] = 'o';
  }
  if (highlight_idx < heights.size() && heights[highlight_idx] < blockchain_height)
  {
    uint64_t pos = (heights[highlight_idx] * resolution) / blockchain_height;
    ring_str[pos] = '*';
  }

  return std::make_pair(ostr.str(), ring_str);
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::prompt_if_old(const std::vector<tools::wallet2::pending_tx> &ptx_vector)
{
  // count the number of old outputs
  std::string err;
  uint64_t bc_height = get_daemon_blockchain_height(err);
  if (!err.empty())
    return true;

  int max_n_old = 0;
  for (const auto &ptx: ptx_vector)
  {
    int n_old = 0;
    for (const auto i: ptx.selected_transfers)
    {
      const tools::wallet2::transfer_details &td = m_wallet->get_transfer_details(i);
      uint64_t age = bc_height - td.m_block_height;
      if (age > OLD_AGE_WARN_THRESHOLD)
        ++n_old;
    }
    max_n_old = std::max(max_n_old, n_old);
  }
  if (max_n_old > 1)
  {
    std::stringstream prompt;
    prompt << tr("Transaction spends more than one very old output. Privacy would be better if they were sent separately.");
    prompt << ENDL << tr("Spend them now anyway?");
    std::string accepted = input_line(prompt.str(), true);
    if (std::cin.eof())
      return false;
    if (!command_line::is_yes(accepted))
    {
      return false;
    }
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::check_for_inactivity_lock(bool user)
{
  if (m_locked)
  {
#ifdef HAVE_READLINE
    PAUSE_READLINE();
    rdln::clear_screen();
#endif
    tools::clear_screen();
    m_in_command = true;
    if (!user)
    {
      const std::string speech = tr("I locked your DFA wallet to protect you while you were away\nsee \"help set\" to configure/disable");
      std::vector<std::pair<std::string, size_t>> lines = tools::split_string_by_width(speech, 45);

      size_t max_len = 0;
      for (const auto &i: lines)
        max_len = std::max(max_len, i.second);
      const size_t n_u = max_len + 2;
      tools::msg_writer() << " " << std::string(n_u, '_');
      for (size_t i = 0; i < lines.size(); ++i)
        tools::msg_writer() << (i == 0 ? "/" : i == lines.size() - 1 ? "\\" : "|") << " " << lines[i].first << std::string(max_len - lines[i].second, ' ') << " " << (i == 0 ? "\\" : i == lines.size() - 1 ? "/" : "|");
      tools::msg_writer() << " " << std::string(n_u, '-') << std::endl <<
          "        \\   (__)" << std::endl <<
          "         \\  (oo)\\_______" << std::endl <<
          "            (__)\\       )\\/\\" << std::endl <<
          "                ||----w |" << std::endl <<
          "                ||     ||" << std::endl <<
          "" << std::endl;
    }
    while (1)
    {
      const char *inactivity_msg = user ? "" : tr("Locked due to inactivity.");
      tools::msg_writer() << inactivity_msg << (inactivity_msg[0] ? " " : "") << tr("The wallet password is required to unlock the console.");
      try
      {
        if (get_and_verify_password())
          break;
      }
      catch (...) { /* do nothing, just let the loop loop */ }
    }
    m_last_activity_time = time(NULL);
    m_in_command = false;
    m_locked = false;
  }
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::on_command(bool (simple_wallet::*cmd)(const std::vector<std::string>&), const std::vector<std::string> &args)
{
  m_last_activity_time = time(NULL);

  m_in_command = true;
  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){
    m_last_activity_time = time(NULL);
    m_in_command = false;
  });

  check_for_inactivity_lock(false);
  return (this->*cmd)(args);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::transfer_main( const std::vector<std::string> &args_)
{
//  "transfer [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  if (!try_connect_to_daemon())
    return false;

  std::vector<std::string> local_args = args_;


  size_t fake_outs_count = DEFAULT_MIX;

  std::vector<uint8_t> extra;

  uint64_t locked_blocks = 0;
   size_t i=0;
    cryptonote::address_parse_info  info;
    cryptonote::tx_destination_entry de;
    bool r = true;
    // check for a URI
    uint64_t amount = 0;

    if (1 < local_args.size())
    {
      r = cryptonote::get_account_address_from_str(info, m_wallet->nettype(), local_args[i]);
      bool ok = cryptonote::parse_amount(de.amount, local_args[i + 1]);
      if(!ok || 0 == de.amount)
      {
        fail_msg_writer() << tr("amount is wrong: ") << local_args[i] << ' ' << local_args[i + 1] <<
          ", " << tr("expected number from 0 to ") << print_money(std::numeric_limits<uint64_t>::max());
        return false;
      }
      i += 2;
    }
    else
    {
        fail_msg_writer() << tr("Invalid last argument: ") << local_args.back();
      return false;
    }

    if (!r)
    {
      fail_msg_writer() << tr("failed to parse address");
      return false;
    }
    de.addr = info.address;

  SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(return false;);

  try
  {
    // figure out what tx will be necessary
    uint64_t bc_height, unlock_block = 0;
    std::string err;
   
    bc_height = get_daemon_blockchain_height(err);
    if (!err.empty())
    {
      fail_msg_writer() << tr("failed to get blockchain height: ") << err;
      return false;
    }
    unlock_block = bc_height + locked_blocks;
    auto ptx_vector = m_wallet->transfer(de, fake_outs_count, unlock_block , extra);
     

    if (ptx_vector.empty())
    {
      fail_msg_writer() << tr("No outputs found, or daemon is not ready");
      return false;
    }


    if (!prompt_if_old(ptx_vector))
    {
      fail_msg_writer() << tr("transaction cancelled.");
      return false;
    }

    // if more than one tx necessary, prompt user to confirm
    {
        uint64_t total_sent = 0;
        uint64_t total_fee = 0;
        uint64_t change = 0;
        for (size_t n = 0; n < ptx_vector.size(); ++n)
        {
          total_fee += ptx_vector[n].fee;
          for (auto i: ptx_vector[n].selected_transfers)
            total_sent += m_wallet->get_transfer_details(i).amount();
          total_sent -= ptx_vector[n].change_dts.amount + ptx_vector[n].fee;
          change += ptx_vector[n].change_dts.amount;

        }

        std::stringstream prompt;
       
        prompt << boost::format(tr("Sending %s.  ")) % print_money(total_sent);
        
        prompt << boost::format(tr("The transaction fee is %s")) %print_money(total_fee);
        

        if (locked_blocks>0)
        {
          float days = locked_blocks / 720.0f;
          prompt << boost::format(tr(".\nThis transaction (including %s change) will unlock on block %llu, in approximately %s days (assuming 2 minutes per block)")) % cryptonote::print_money(change) % ((unsigned long long)unlock_block) % days;
        }

        prompt << ENDL << tr("Is this okay?");
        
        std::string accepted = input_line(prompt.str(), true);
        if (std::cin.eof())
          return false;
        if (!command_line::is_yes(accepted))
        {
          fail_msg_writer() << tr("transaction cancelled.");

          return false;
        }
    }
    commit_or_save(ptx_vector);
  }
  catch (const std::exception &e)
  {
    handle_transfer_exception(std::current_exception(), true);
    return false;
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::transfer(const std::vector<std::string> &args_)
{
  transfer_main( args_);
  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::sweep_main(uint64_t below,  const std::vector<std::string> &args_)
{
  auto print_usage = [this, below]()
  {
    if (below)
    {
      PRINT_USAGE(USAGE_SWEEP_BELOW);
    }
    else
    {

    }
  };
  if (args_.size() == 0)
  {
    fail_msg_writer() << tr("No address given");
    print_usage();
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  std::vector<std::string> local_args = args_;
  size_t fake_outs_count = DEFAULT_MIX;

  uint64_t unlock_block = 0;
  
  cryptonote::address_parse_info info;
  if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), local_args[0]))
  {
    fail_msg_writer() << tr("failed to parse address");
    print_usage();
    return true;
  }

  SCOPED_WALLET_UNLOCK();

  try
  {
    // figure out what tx will be necessary
    auto ptx_vector = m_wallet->sweep_transfers(below, info.address, fake_outs_count, unlock_block /* unlock_time */  );

    if (ptx_vector.empty())
    {
      fail_msg_writer() << tr("No outputs found, or daemon is not ready");
      return true;
    }

    if (!prompt_if_old(ptx_vector))
    {
      fail_msg_writer() << tr("transaction cancelled.");
      return false;
    }

    // give user total and fee, and prompt to confirm
    uint64_t total_fee = 0, total_sent = 0;
    for (size_t n = 0; n < ptx_vector.size(); ++n)
    {
      total_fee += ptx_vector[n].fee;
      for (auto i: ptx_vector[n].selected_transfers)
        total_sent += m_wallet->get_transfer_details(i).amount();
    }

    std::ostringstream prompt;

    if (ptx_vector.size() > 1) {
      prompt << boost::format(tr("Sweeping %s in %llu transactions for a total fee of %s.  Is this okay?")) %
        print_money(total_sent) %
        ((unsigned long long)ptx_vector.size()) %
        print_money(total_fee);
    }
    else {
      prompt << boost::format(tr("Sweeping %s for a total fee of %s.  Is this okay?")) %
        print_money(total_sent) %
        print_money(total_fee);
    }
    std::string accepted = input_line(prompt.str(), true);
    if (std::cin.eof())
      return true;
    if (!command_line::is_yes(accepted))
    {
      fail_msg_writer() << tr("transaction cancelled.");

      return true;
    }

    // actually commit the transactions
    {
      commit_or_save(ptx_vector);
    }
  }
  catch (const std::exception& e)
  {
    handle_transfer_exception(std::current_exception(),true);
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
  }

  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::sweep_all(const std::vector<std::string> &args_)
{
  sweep_main( 0,  args_);
  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::sweep_below(const std::vector<std::string> &args_)
{
  uint64_t below = 0;
  if (args_.size() < 1)
  {
    fail_msg_writer() << tr("missing threshold amount");
    return true;
  }
  if (!cryptonote::parse_amount(below, args_[0]))
  {
    fail_msg_writer() << tr("invalid amount threshold");
    return true;
  }
  sweep_main( below, std::vector<std::string>(++args_.begin(), args_.end()));
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::donate(const std::vector<std::string> &args_)
{
  std::vector<std::string> local_args = args_;
  if(local_args.empty() || local_args.size() > 5)
  {
     PRINT_USAGE(USAGE_DONATE);
     return true;
  }
  std::string amount_str;

  // get amount and pop
  uint64_t amount;
  bool ok = cryptonote::parse_amount(amount, local_args.back());
  if (ok && amount != 0)
  {
    amount_str = local_args.back();
    local_args.pop_back();
  }
  else
  { 
    fail_msg_writer() << tr("amount is wrong: ") << local_args.back() << ", " << tr("expected number from 0 to ") << print_money(std::numeric_limits<uint64_t>::max());
    return true;
  }
  // push back address, amount, payment id
  std::string address_str;
  if (m_wallet->nettype() != cryptonote::MAINNET)
  {
    // if not mainnet, convert donation address string to the relevant network type
    address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, cryptonote::MAINNET, MONERO_DONATION_ADDR))
    {
      fail_msg_writer() << tr("Failed to parse donation address: ") << MONERO_DONATION_ADDR;
      return true;
    }
    address_str = cryptonote::get_account_address_as_str(m_wallet->nettype(),  info.address);
  }
  else
  {
    address_str = MONERO_DONATION_ADDR;
  }
  local_args.push_back(address_str);
  local_args.push_back(amount_str);
  if (m_wallet->nettype() == cryptonote::MAINNET)
    message_writer() << (boost::format(tr("Donating %s %s to The DFA Project (donate.getmonero.org or %s).")) % amount_str % cryptonote::get_unit(cryptonote::get_default_decimal_point()) % MONERO_DONATION_ADDR).str();
  else
    message_writer() << (boost::format(tr("Donating %s %s to %s.")) % amount_str % cryptonote::get_unit(cryptonote::get_default_decimal_point()) % address_str).str();
  transfer(local_args);
  return true;
}



//----------------------------------------------------------------------------------------------------
bool simple_wallet::get_tx_key(const std::vector<std::string> &args_)
{
  std::vector<std::string> local_args = args_;

   if(local_args.size() != 1) {
    PRINT_USAGE(USAGE_GET_TX_KEY);
    return true;
  }

  crypto::hash txid;
  if (!epee::string_tools::hex_to_pod(local_args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  SCOPED_WALLET_UNLOCK();

  crypto::secret_key tx_key;

  bool found_tx_key = m_wallet->get_tx_key(txid, tx_key);
  if (found_tx_key)
  {
    ostringstream oss;
    oss << epee::string_tools::pod_to_hex(tx_key);
   
    success_msg_writer() << tr("Tx key: ") << oss.str();
    return true;
  }
  else
  {
    fail_msg_writer() << tr("no tx keys found for this txid");
    return true;
  }
}
//----------------------------------------------------------------------------------------------------

//----------------------------------------------------------------------------------------------------
bool simple_wallet::get_tx_proof(const std::vector<std::string> &args)
{
  if (args.size() != 2 && args.size() != 3)
  {
    PRINT_USAGE(USAGE_GET_TX_PROOF);
    return true;
  }

  crypto::hash txid;
  if(!epee::string_tools::hex_to_pod(args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  cryptonote::address_parse_info info;
  if(!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), args[1]))
  {
    fail_msg_writer() << tr("failed to parse address");
    return true;
  }

  SCOPED_WALLET_UNLOCK();

  try
  {
    std::string sig_str = m_wallet->get_tx_proof(txid, info.address, args.size() == 3 ? args[2] : "");
    const std::string filename = "monero_tx_proof";
    if (m_wallet->save_to_file(filename, sig_str, true))
      success_msg_writer() << tr("signature file saved to: ") << filename;
    else
      fail_msg_writer() << tr("failed to save signature file");
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("error: ") << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_tx_key(const std::vector<std::string> &args_)
{
  std::vector<std::string> local_args = args_;

  if(local_args.size() != 3) {
    PRINT_USAGE(USAGE_CHECK_TX_KEY);
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  if (!m_wallet)
  {
    fail_msg_writer() << tr("wallet is null");
    return true;
  }
  crypto::hash txid;
  if(!epee::string_tools::hex_to_pod(local_args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  crypto::secret_key tx_key;
  if(!epee::string_tools::hex_to_pod(local_args[1].substr(0, 64), tx_key))
  {
    fail_msg_writer() << tr("failed to parse tx key");
    return true;
  }
  local_args[1] = local_args[1].substr(64);


  cryptonote::address_parse_info info;
  if(!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), local_args[2]))
  {
    fail_msg_writer() << tr("failed to parse address");
    return true;
  }

  try
  {
    uint64_t received;
    bool in_pool;
    uint64_t confirmations;
    m_wallet->check_tx_key(txid, tx_key,  info.address, received, in_pool, confirmations);

    if (received > 0)
    {
      success_msg_writer() << get_account_address_as_str(m_wallet->nettype(),  info.address) << " " << tr("received") << " " << print_money(received) << " " << tr("in txid") << " " << txid;
      if (in_pool)
      {
        success_msg_writer() << tr("WARNING: this transaction is not yet included in the blockchain!");
      }
      else
      {
        if (confirmations != (uint64_t)-1)
        {
          success_msg_writer() << boost::format(tr("This transaction has %u confirmations")) % confirmations;
        }
        else
        {
          success_msg_writer() << tr("WARNING: failed to determine number of confirmations!");
        }
      }
    }
    else
    {
      fail_msg_writer() << get_account_address_as_str(m_wallet->nettype(), info.address) << " " << tr("received nothing in txid") << " " << txid;
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("error: ") << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_tx_proof(const std::vector<std::string> &args)
{
  if(args.size() != 3 && args.size() != 4) {
    PRINT_USAGE(USAGE_CHECK_TX_PROOF);
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  // parse txid
  crypto::hash txid;
  if(!epee::string_tools::hex_to_pod(args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  // parse address
  cryptonote::address_parse_info info;
  if(!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), args[1]))
  {
    fail_msg_writer() << tr("failed to parse address");
    return true;
  }

  // read signature file
  std::string sig_str;
  if (!m_wallet->load_from_file(args[2], sig_str))
  {
    fail_msg_writer() << tr("failed to load signature file");
    return true;
  }

  try
  {
    uint64_t received;
    bool in_pool;
    uint64_t confirmations;
    if (m_wallet->check_tx_proof(txid, info.address, args.size() == 4 ? args[3] : "", sig_str, received, in_pool, confirmations))
    {
      success_msg_writer() << tr("Good signature");
      if (received > 0)
      {
        success_msg_writer() << get_account_address_as_str(m_wallet->nettype(), info.address) << " " << tr("received") << " " << print_money(received) << " " << tr("in txid") << " " << txid;
        if (in_pool)
        {
          success_msg_writer() << tr("WARNING: this transaction is not yet included in the blockchain!");
        }
        else
        {
          if (confirmations != (uint64_t)-1)
          {
            success_msg_writer() << boost::format(tr("This transaction has %u confirmations")) % confirmations;
          }
          else
          {
            success_msg_writer() << tr("WARNING: failed to determine number of confirmations!");
          }
        }
      }
      else
      {
        fail_msg_writer() << get_account_address_as_str(m_wallet->nettype(),  info.address) << " " << tr("received nothing in txid") << " " << txid;
      }
    }
    else
    {
      fail_msg_writer() << tr("Bad signature");
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("error: ") << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::get_spend_proof(const std::vector<std::string> &args)
{

  if(args.size() != 1 && args.size() != 2) {
    PRINT_USAGE(USAGE_GET_SPEND_PROOF);
    return true;
  }

  crypto::hash txid;
  if (!epee::string_tools::hex_to_pod(args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  SCOPED_WALLET_UNLOCK();

  try
  {
    const std::string sig_str = m_wallet->get_spend_proof(txid, args.size() == 2 ? args[1] : "");
    const std::string filename = "monero_spend_proof";
    if (m_wallet->save_to_file(filename, sig_str, true))
      success_msg_writer() << tr("signature file saved to: ") << filename;
    else
      fail_msg_writer() << tr("failed to save signature file");
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_spend_proof(const std::vector<std::string> &args)
{
  if(args.size() != 2 && args.size() != 3) {
    PRINT_USAGE(USAGE_CHECK_SPEND_PROOF);
    return true;
  }

  crypto::hash txid;
  if (!epee::string_tools::hex_to_pod(args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  std::string sig_str;
  if (!m_wallet->load_from_file(args[1], sig_str))
  {
    fail_msg_writer() << tr("failed to load signature file");
    return true;
  }

  try
  {
    if (m_wallet->check_spend_proof(txid, args.size() == 3 ? args[2] : "", sig_str))
      success_msg_writer() << tr("Good signature");
    else
      fail_msg_writer() << tr("Bad signature");
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
static std::string get_human_readable_timespan(std::chrono::seconds seconds)
{
  uint64_t ts = seconds.count();
  if (ts < 60)
    return std::to_string(ts) + sw::tr(" seconds");
  if (ts < 3600)
    return std::to_string((uint64_t)(ts / 60)) + sw::tr(" minutes");
  if (ts < 3600 * 24)
    return std::to_string((uint64_t)(ts / 3600)) + sw::tr(" hours");
  if (ts < 3600 * 24 * 30.5)
    return std::to_string((uint64_t)(ts / (3600 * 24))) + sw::tr(" days");
  if (ts < 3600 * 24 * 365.25)
    return std::to_string((uint64_t)(ts / (3600 * 24 * 30.5))) + sw::tr(" months");
  return sw::tr("a long time");
}
//----------------------------------------------------------------------------------------------------
static std::string get_human_readable_timespan(uint64_t seconds)
{
  return get_human_readable_timespan(std::chrono::seconds(seconds));
}
//----------------------------------------------------------------------------------------------------
// mutates local_args as it parses and consumes arguments
bool simple_wallet::get_transfers(std::vector<std::string>& local_args, std::vector<transfer_view>& transfers)
{
  bool in = true;
  bool out = true;
  bool pool = true;
  uint64_t min_height = 0;
  uint64_t max_height = (uint64_t)-1;

  // optional in/out selector
  if (local_args.size() > 0) {
    if (local_args[0] == "in" ) {
      out = false;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "out" ) {
      in = pool = false;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "all" ) {
      local_args.erase(local_args.begin());
    }
  }


  // min height
  if (local_args.size() > 0 && local_args[0].find('=') == std::string::npos) {
    try {
      min_height = boost::lexical_cast<uint64_t>(local_args[0]);
    }
    catch (const boost::bad_lexical_cast &) {
      fail_msg_writer() << tr("bad min_height parameter:") << " " << local_args[0];
      return false;
    }
    local_args.erase(local_args.begin());
  }

  // max height
  if (local_args.size() > 0 && local_args[0].find('=') == std::string::npos) {
    try {
      max_height = boost::lexical_cast<uint64_t>(local_args[0]);
    }
    catch (const boost::bad_lexical_cast &) {
      fail_msg_writer() << tr("bad max_height parameter:") << " " << local_args[0];
      return false;
    }
    local_args.erase(local_args.begin());
  }

  const uint64_t top_height = m_wallet->get_blockchain_current_height();

  if (in) {
    std::vector<tools::wallet2::transfer_details> payments;
    m_wallet->get_confirmed_transfer_in(payments, min_height, max_height);
    for (auto & pd : payments) {

      const std::string type = tr("in");
      const bool unlocked = m_wallet->is_transfer_unlocked(pd);
      std::string locked_msg = "unlocked";
      if (!unlocked)
      {
        locked_msg = "locked";
        if (pd.m_unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
        {
          if (pd.m_unlock_time >= top_height)
            locked_msg = std::to_string(pd.m_unlock_time - top_height) + " blks";
        }
        else
        {
          const uint64_t adjusted_time = m_wallet->get_daemon_adjusted_time();
          uint64_t threshold = adjusted_time + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2 ;
          if (threshold < pd.m_unlock_time)
            locked_msg = get_human_readable_timespan(std::chrono::seconds(pd.m_unlock_time - threshold));
        }
      }
      transfers.push_back({
        type,
        pd.m_block_height,
        pd.m_block_time,
        type,
        true,
        pd.m_amount,
        pd.m_txid,
        0,
        "",
        "",
        locked_msg
      });
    }
  }

  if (out) {
    std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_out>> payments;
    m_wallet->get_payments_out(payments, min_height, max_height);
    for (auto i = payments.begin(); i != payments.end(); ++i) {
      const tools::wallet2::confirmed_transfer_out &pd = i->second;
      uint64_t fee = pd.fee();
      const auto  addr = get_account_address_as_str(m_wallet->nettype(),pd.m_addr);
      transfers.push_back({
        "out",
        pd.m_block_height,
        pd.m_sent_time,
        "out",
        true,
        pd.m_amount,
        i->first,
        fee,
        addr,
        "-"
      });
    }
  }

  if (pool) {
    try
    {
      m_in_manual_refresh.store(true, std::memory_order_relaxed);
      epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){m_in_manual_refresh.store(false, std::memory_order_relaxed);});

      m_wallet->update_pool_state();

      std::list<std::pair<crypto::hash, tools::wallet2::pool_transfer_in>> payments;
      m_wallet->get_unconfirmed_transfer_in(payments);
      for (auto & kv: payments) {

        const auto &pd = kv.second;
        std::string destination = m_wallet->get_address_as_str();
        std::string double_spend_note;
        if (pd.m_double_spend_seen)
          double_spend_note = tr("[Double spend seen on the network: this transaction may or may not end up being mined] ");
        transfers.push_back({
          "pool",
          "pool",
          pd.m_timestamp,
          "in",
          false,
          pd.m_amount,
          pd.m_tx_hash,
          0,
         destination,
          double_spend_note,
          "locked"
        });
      }


      {
    std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_out>> upayments;
    m_wallet->get_unconfirmed_payments_out(upayments);
    for (auto & kv : upayments) {
      const tools::wallet2::unconfirmed_transfer_out &pd = kv.second;
      uint64_t fee = pd.fee();
      const auto  addr = get_account_address_as_str(m_wallet->nettype(),pd.m_addr);
      
      bool is_failed = pd.m_state == tools::wallet2::unconfirmed_transfer_out::failed;
       
        transfers.push_back({
          (is_failed ? "failed" : "pending"),
          (is_failed ? "failed" : "pending"),
          pd.m_sent_time,
          "out",
          false,
         pd.m_amount,
          kv.first,
          fee,
          addr,
          "",
          "-"
        });
    }
  }
    }
    catch (const std::exception& e)
    {
      fail_msg_writer() << "Failed to get pool state:" << e.what();
    }
  }

   
  // sort by block, then by timestamp (unconfirmed last)
  std::sort(transfers.begin(), transfers.end(), [](const transfer_view& a, const transfer_view& b) -> bool {
    if (a.confirmed && !b.confirmed)
      return true;
    if (a.block == b.block)
      return a.timestamp < b.timestamp;
    return a.block < b.block;
  });

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_transfers(const std::vector<std::string> &args_)
{
  std::vector<std::string> local_args = args_;

  if(local_args.size() > 4) {
    fail_msg_writer() << tr("usage: show_transfers [in|out|all|pending|failed|pool|coinbase] [index=<N1>[,<N2>,...]] [<min_height> [<max_height>]]");
    return true;
  }

  LOCK_IDLE_SCOPE();

  std::vector<transfer_view> all_transfers;

  if (!get_transfers(local_args, all_transfers))
    return true;

  PAUSE_READLINE();

  for (const auto& transfer : all_transfers)
  {
    const auto color = transfer.type == "failed" ? console_color_red : transfer.confirmed ? ((transfer.direction == "in" || transfer.direction == "block") ? console_color_green : console_color_magenta) : console_color_default;

    auto formatter = boost::format("%8.8llu %6.6s %8.8s %25.25s %20.20s  %s %14.14s %s - %s");

    message_writer(color, false) << formatter
      % transfer.block
      % transfer.direction
      % transfer.unlocked
      % tools::get_human_readable_timestamp(transfer.timestamp)
      % print_money(transfer.amount)
      % string_tools::pod_to_hex(transfer.hash)
      % print_money(transfer.fee)
      % transfer.addr
      % transfer.note;
  }

  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::refresh(const std::vector<std::string>& args)
{
  uint64_t start_height = 0;
  if(!args.empty()){
    try
    {
        start_height = boost::lexical_cast<uint64_t>( args[0] );
    }
    catch(const boost::bad_lexical_cast &)
    {
        start_height = 0;
    }
  }
  return refresh_main(start_height);
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::rescan_blockchain(const std::vector<std::string> &args_)
{
  uint64_t start_height = 0;

    if (args_.size() > 1)
    {
      try
      {
        start_height = boost::lexical_cast<uint64_t>( args_[0] );
      }
      catch(const boost::bad_lexical_cast &)
      {
        start_height = 0;
      }
    }

  {
    message_writer() << tr("Warning: this will lose any information which can not be recovered from the blockchain.");
    message_writer() << tr("This includes destination addresses, tx secret keys, tx notes, etc");
    std::string confirm = input_line(tr("Rescan anyway?"), true);
    if(!std::cin.eof())
    {
      if (!command_line::is_yes(confirm))
        return true;
    }
  }

  const uint64_t wallet_from_height = m_wallet->get_refresh_from_block_height();
  if (start_height > wallet_from_height)
  {
    message_writer() << tr("Warning: your restore height is higher than wallet restore height: ") << wallet_from_height;
    std::string confirm = input_line(tr("Rescan anyway ? (Y/Yes/N/No): "));
    if(!std::cin.eof())
    {
      if (!command_line::is_yes(confirm))
        return true;
    }
  }

  m_in_manual_refresh.store(true, std::memory_order_relaxed);
  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){m_in_manual_refresh.store(false, std::memory_order_relaxed);});

  return refresh_main(start_height,  true);
}

//----------------------------------------------------------------------------------------------------
void simple_wallet::wallet_idle_thread()
{
  const boost::posix_time::ptime start_time = boost::posix_time::microsec_clock::universal_time();
  while (true)
  {
    boost::unique_lock<boost::mutex> lock(m_idle_mutex);
    if (!m_idle_run.load(std::memory_order_relaxed))
      break;

    // if another thread was busy (ie, a foreground refresh thread), we'll end up here at
    // some random time that's not what we slept for, so we should not call refresh now
    // or we'll be leaking that fact through timing
    const boost::posix_time::ptime now0 = boost::posix_time::microsec_clock::universal_time();
    const uint64_t dt_actual = (now0 - start_time).total_microseconds() % 1000000;
#ifdef _WIN32
    static const uint64_t threshold = 10000;
#else
    static const uint64_t threshold = 2000;
#endif
    if (dt_actual < threshold) // if less than a threshold... would a very slow machine always miss it ?
    {
#ifndef _WIN32
      m_inactivity_checker.do_call(boost::bind(&simple_wallet::check_inactivity, this));
#endif
      m_refresh_checker.do_call(boost::bind(&simple_wallet::check_refresh, this));

      if (!m_idle_run.load(std::memory_order_relaxed))
        break;
    }

    // aim for the next multiple of 1 second
    const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
    const auto dt = (now - start_time).total_microseconds();
    const auto wait = 1000000 - dt % 1000000;
    m_idle_cond.wait_for(lock, boost::chrono::microseconds(wait));
  }
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_inactivity()
{
    // inactivity lock
    if (!m_locked && !m_in_command)
    {
      const uint32_t seconds = m_wallet->inactivity_lock_timeout();
      if (seconds > 0 && time(NULL) - m_last_activity_time > seconds)
      {
        m_locked = true;
        m_cmd_binder.cancel_input();
      }
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_refresh()
{
    // auto refresh
    if (m_auto_refresh_enabled)
    {
      m_auto_refresh_refreshing = true;
      try
      {
        uint64_t fetched_blocks;
        bool received_money;
          m_wallet->refresh(m_wallet->get_refresh_from_block_height(), fetched_blocks, received_money); // don't check the pool in background mode
      }
      catch(...) {}
      m_auto_refresh_refreshing = false;
    }
    return true;
}


//----------------------------------------------------------------------------------------------------
std::string simple_wallet::get_prompt() const
{
  if (m_locked)
    return std::string("[") + tr("locked due to inactivity") + "]";
  std::string addr_start = m_wallet->get_address_as_str().substr(0, 6);
  std::string prompt = std::string("[") + tr("wallet") + " " + addr_start;
  if (!m_wallet->check_connection(NULL))
    prompt += tr(" (no daemon)");
  else if (!m_wallet->is_synced())
    prompt += tr(" (out of sync)");
  prompt += "]: ";
  return prompt;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::run()
{
  std::cout<<"simple_wallet::run()"<<std::endl;
  // check and display warning, but go on anyway
  try_connect_to_daemon();

  refresh_main(0,  true);

  m_auto_refresh_enabled = !m_wallet->is_offline() && m_wallet->auto_refresh();
  m_idle_thread = boost::thread([&]{wallet_idle_thread();});

  message_writer(console_color_green, false) << "Background refresh thread started";
  return m_cmd_binder.run_handling([this](){return get_prompt();}, "");
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::stop()
{
  m_cmd_binder.stop_handling();
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::print_address(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  success_msg_writer() <<  m_wallet->get_account().get_public_address_str(m_wallet->nettype()) ;
   return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::status(const std::vector<std::string> &args)
{
  uint64_t local_height = m_wallet->get_blockchain_current_height();
  uint32_t version = 0;
  bool ssl = false;
  if (!m_wallet->check_connection(&version, &ssl))
  {
    success_msg_writer() << "Refreshed " << local_height << "/?, no daemon connected";
    return true;
  }

  std::string err;
  uint64_t bc_height = get_daemon_blockchain_height(err);
  if (err.empty())
  {
    bool synced = local_height == bc_height;
    success_msg_writer() << "Refreshed " << local_height << "/" << bc_height << ", " << (synced ? "synced" : "syncing")<< ", daemon RPC v" << get_version_string(version) << ", " << (ssl ? "SSL" : "no SSL");
  }
  else
  {
    fail_msg_writer() << "Refreshed " << local_height << "/?, daemon connection error";
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::wallet_info(const std::vector<std::string> &args)
{
  bool ready;
  uint32_t threshold, total;
  message_writer() << tr("Filename: ") << m_wallet->get_wallet_file();
  message_writer() << tr("Address: ") << m_wallet->get_account().get_public_address_str(m_wallet->nettype());
  std::string type;

    type = tr("Normal");
  message_writer() << tr("Type: ") << type;
  message_writer() << tr("Network type: ") << (
    m_wallet->nettype() == cryptonote::TESTNET ? tr("Testnet") :
    m_wallet->nettype() == cryptonote::STAGENET ? tr("Stagenet") : tr("Mainnet"));
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_transfer(const std::vector<std::string> &args)
{
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_SHOW_TRANSFER);
    return true;
  }

  cryptonote::blobdata txid_data;
  if(!epee::string_tools::parse_hexstr_to_binbuff(args.front(), txid_data) || txid_data.size() != sizeof(crypto::hash))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }
  crypto::hash txid = *reinterpret_cast<const crypto::hash*>(txid_data.data());

  const uint64_t top_height = m_wallet->get_blockchain_current_height();

    std::vector<tools::wallet2::transfer_details> payments;
  m_wallet->get_confirmed_transfer_in(payments, 0, (uint64_t)-1);
  for (const auto & pd : payments) {
    if (pd.m_txid == txid) {
      success_msg_writer() << "Incoming transaction found";
      success_msg_writer() << "txid: " << txid;
      success_msg_writer() << "Height: " << pd.m_block_height;
      success_msg_writer() << "Timestamp: " << tools::get_human_readable_timestamp(pd.m_block_time);
      success_msg_writer() << "Amount: " << print_money(pd.m_amount);
      if (pd.m_unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
      {
        uint64_t bh = std::max(pd.m_unlock_time, pd.m_block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
        if (bh >= top_height)
          success_msg_writer() << "Locked: " << (bh - top_height) << " blocks to unlock";
        else
          success_msg_writer() << std::to_string(top_height - bh) << " confirmations";
      }
      else
      {
        const uint64_t adjusted_time = m_wallet->get_daemon_adjusted_time();
        uint64_t threshold = adjusted_time + (m_wallet->use_fork_rules(2, 0) ? CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2 : CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1);
        if (threshold >= pd.m_unlock_time)
          success_msg_writer() << "unlocked for " << get_human_readable_timespan(std::chrono::seconds(threshold - pd.m_unlock_time));
        else
          success_msg_writer() << "locked for " << get_human_readable_timespan(std::chrono::seconds(pd.m_unlock_time - threshold));
      }
      return true;
    }
  }

  std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_out>> payments_out;
  m_wallet->get_payments_out(payments_out, 0, (uint64_t)-1);
  for (std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_out>>::const_iterator i = payments_out.begin(); i != payments_out.end(); ++i) {
    if (i->first == txid)
    {
      const auto &pd = i->second;
      uint64_t fee = pd.fee();
      std::string addr=cryptonote::get_account_address_as_str(m_wallet->nettype(), pd.m_addr);
    
      success_msg_writer() << "Outgoing transaction found";
      success_msg_writer() << "txid: " << txid;
      success_msg_writer() << "Height: " << pd.m_block_height;
      success_msg_writer() << "Send Time: " << tools::get_human_readable_timestamp(pd.m_sent_time);
      success_msg_writer() << "Amount: " << print_money(pd.m_amount);
      success_msg_writer() << "Fee: " << print_money(fee);
      success_msg_writer() << "Destinations: " << addr;
      return true;
    }
  }

  try
  {
    m_wallet->update_pool_state();

    std::list<std::pair<crypto::hash, tools::wallet2::pool_transfer_in>> pool_payments;
    m_wallet->get_unconfirmed_transfer_in(pool_payments);
    for ( auto i = pool_payments.begin(); i != pool_payments.end(); ++i) {
      const auto &pd = i->second;
      if (pd.m_tx_hash == txid)
      {
        success_msg_writer() << "Unconfirmed incoming transaction found in the txpool";
        success_msg_writer() << "txid: " << txid;
        success_msg_writer() << "Timestamp: " << tools::get_human_readable_timestamp(pd.m_timestamp);
        success_msg_writer() << "Amount: " << print_money(pd.m_amount);
        if (pd.m_double_spend_seen)
          success_msg_writer() << tr("Double spend seen on the network: this transaction may or may not end up being mined");
        return true;
      }
    }
  }
  catch (...)
  {
    fail_msg_writer() << "Failed to get pool state";
  }

  std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_out>> upayments;
  m_wallet->get_unconfirmed_payments_out(upayments);
  for (auto i = upayments.begin(); i != upayments.end(); ++i) {
    if (i->first == txid)
    {
      const tools::wallet2::unconfirmed_transfer_out &pd = i->second;
      uint64_t fee = pd.fee();
      bool is_failed = pd.m_state == tools::wallet2::unconfirmed_transfer_out::failed;

      success_msg_writer() << (is_failed ? "Failed" : "Pending") << " outgoing transaction found";
      success_msg_writer() << "txid: " << txid;
      success_msg_writer() << "Send Time: " << tools::get_human_readable_timestamp(pd.m_sent_time);
      success_msg_writer() << "Amount: " << print_money(pd.m_amount);
      success_msg_writer() << "Fee: " << print_money(fee);
      return true;
    }
  }

  fail_msg_writer() << tr("Transaction ID not found");
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::process_command(const std::vector<std::string> &args)
{
  return m_cmd_binder.process_command_vec(args);
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::interrupt()
{
  if (m_in_manual_refresh.load(std::memory_order_relaxed))
  {
    m_wallet->stop();
  }
  else
  {
    stop();
  }
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::commit_or_save(std::vector<tools::wallet2::pending_tx>& ptx_vector)
{
  size_t i = 0;
  while (!ptx_vector.empty())
  {
    auto & ptx = ptx_vector.back();
    const crypto::hash txid = get_transaction_hash(ptx.tx);
    {
      m_wallet->commit_tx(ptx);
      success_msg_writer(true) << tr("Transaction successfully submitted, transaction ") << txid << ENDL
      << tr("You can check its status by using the `show_transfers` command.");
    }
    // if no exception, remove element from vector
    ptx_vector.pop_back();
  }
}
//----------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
  TRY_ENTRY();

#ifdef WIN32
  // Activate UTF-8 support for Boost filesystem classes on Windows
  std::locale::global(boost::locale::generator().generate(""));
  boost::filesystem::path::imbue(std::locale());
#endif
  setlocale(LC_CTYPE, "");

  po::options_description desc_params(wallet_args::tr("Wallet options"));
  tools::wallet2::init_options(desc_params);
  command_line::add_arg(desc_params, arg_wallet_file);
  command_line::add_arg(desc_params, arg_generate_new_wallet);
  command_line::add_arg(desc_params, arg_generate_from_spend_key);
  command_line::add_arg(desc_params, arg_mnemonic_language);
  command_line::add_arg(desc_params, arg_command);

  command_line::add_arg(desc_params, arg_restore_from_seed );
  command_line::add_arg(desc_params, arg_electrum_seed );
  command_line::add_arg(desc_params, arg_allow_mismatched_daemon_version);
  command_line::add_arg(desc_params, arg_restore_height);
  command_line::add_arg(desc_params, arg_restore_date);
  command_line::add_arg(desc_params, arg_create_address_file);
  command_line::add_arg(desc_params, arg_use_english_language_names);

  po::positional_options_description positional_options;
  positional_options.add(arg_command.name, -1);

  boost::optional<po::variables_map> vm;
  bool should_terminate = false;
  std::tie(vm, should_terminate) = wallet_args::main(
   argc, argv,
   "wallet-cli [--wallet-file=<filename>|--generate-new-wallet=<filename>] [<COMMAND>]",
    sw::tr("This is the command line monero wallet. It needs to connect to a monero\ndaemon to work correctly.\nWARNING: Do not reuse your DFA keys on another fork, UNLESS this fork has key reuse mitigations built in. Doing so will harm your privacy."),
    desc_params,
    positional_options,
    [](const std::string &s, bool emphasis){ tools::scoped_message_writer(emphasis ? epee::console_color_white : epee::console_color_default, true) << s; },
    "wallet-cli.log",
    true
  );

  if (!vm)
  {
    return 1;
  }

  if (should_terminate)
  {
    return 0;
  }

  cryptonote::simple_wallet w;
  const bool r = w.init(*vm);
  CHECK_AND_ASSERT_MES(r, 1, sw::tr("Failed to initialize wallet"));

  std::vector<std::string> command = command_line::get_arg(*vm, arg_command);
  if (!command.empty())
  {
    if (!w.process_command(command))
      fail_msg_writer() << sw::tr("Unknown command: ") << command.front();
    w.stop();
    w.deinit();
  }
  else
  {
    tools::signal_handler::install([&w](int type) {
      if (tools::password_container::is_prompting.load())
      {
        // must be prompting for password so return and let the signal stop prompt
        return;
      }
#ifdef WIN32
      if (type == CTRL_C_EVENT)
#else
      if (type == SIGINT)
#endif
      {
        // if we're pressing ^C when refreshing, just stop refreshing
        w.interrupt();
      }
      else
      {
        w.stop();
      }
    });
    w.run();

    w.deinit();
  }
  return 0;
  CATCH_ENTRY_L0("main", 1);
}
