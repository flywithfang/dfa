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

/*!
 * \file simplewallet.h
 * 
 * \brief Header file that declares simple_wallet class.
 */
#pragma once

#include <memory>

#include <boost/optional/optional.hpp>
#include <boost/program_options/variables_map.hpp>

#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "wallet/wallet2.h"
#include "console_handler.h"
#include "math_helper.h"
#include "wipeable_string.h"
#include "common/i18n.h"
#include "common/password.h"
#include "crypto/crypto.h"  // for definition of crypto::secret_key

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.simplewallet"
// Hardcode Monero's donation address (see #1447)
constexpr const char MONERO_DONATION_ADDR[] = "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H";

/*!
 * \namespace cryptonote
 * \brief Holds cryptonote related classes and helpers.
 */
namespace cryptonote
{
  /*!
   * \brief Manages wallet operations. This is the most abstracted wallet class.
   */
  class simple_wallet : public tools::i_wallet2_callback
  {
  public:
    static const char *tr(const char *str) { return i18n_translate(str, "cryptonote::simple_wallet"); }

  public:
    typedef std::vector<std::string> command_type;

    simple_wallet();
    bool init(const boost::program_options::variables_map& vm);
    bool deinit();
    bool run();
    void stop();
    void interrupt();

    //wallet *create_wallet();
    bool process_command(const std::vector<std::string> &args);
    std::string get_commands_str();
    std::string get_command_usage(const std::vector<std::string> &args);
  private:

    bool handle_command_line(const boost::program_options::variables_map& vm);

    bool run_console_handler();

    void wallet_idle_thread();

    //! \return Prompts user for password and verifies against local file. Logs on error and returns `none`
    boost::optional<tools::password_container> get_and_verify_password() const;

    boost::optional<epee::wipeable_string> new_wallet(const boost::program_options::variables_map& vm, const crypto::secret_key& recovery_key,bool recover,  const std::string &old_language);


    boost::optional<epee::wipeable_string> open_wallet(const boost::program_options::variables_map& vm);
    bool close_wallet();

    bool viewkey(const std::vector<std::string> &args = std::vector<std::string>());
    bool spendkey(const std::vector<std::string> &args = std::vector<std::string>());
    bool seed(const std::vector<std::string> &args = std::vector<std::string>());
    bool encrypted_seed(const std::vector<std::string> &args = std::vector<std::string>());
    bool restore_height(const std::vector<std::string> &args = std::vector<std::string>());

    /*!
     * \brief Sets seed language.
     *
     * interactive
     *   - prompts for password so wallet can be rewritten
     *   - calls get_mnemonic_language() which prompts for language
     *
     * \return success status
     */
    bool seed_set_language(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_always_confirm_transfers(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_store_tx_info(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_default_ring_size(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_auto_refresh(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_confirm_missing_payment_id(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_ask_password(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_unit(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_max_reorg_depth(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_refresh_from_block_height(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_auto_low_priority(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_inactivity_lock_timeout(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_device_name(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_export_format(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_load_deprecated_formats(const std::vector<std::string> &args = std::vector<std::string>());
    bool set_persistent_rpc_client_id(const std::vector<std::string> &args = std::vector<std::string>());
    bool help(const std::vector<std::string> &args = std::vector<std::string>());
    bool apropos(const std::vector<std::string> &args);
    bool set_daemon(const std::vector<std::string> &args);
    bool save_bc(const std::vector<std::string> &args);
    bool refresh(const std::vector<std::string> &args);
    bool show_balance_unlocked(bool detailed = false);
    bool show_balance(const std::vector<std::string> &args = std::vector<std::string>());
    bool show_incoming_transfers(const std::vector<std::string> &args);
    bool show_payments(const std::vector<std::string> &args);
    bool show_blockchain_height(const std::vector<std::string> &args);
    bool transfer_main( const std::vector<std::string> &args);
    bool transfer(const std::vector<std::string> &args);
    bool sweep_main( uint64_t below,  const std::vector<std::string> &args);
    bool sweep_all(const std::vector<std::string> &args);
    bool sweep_below(const std::vector<std::string> &args);
    bool donate(const std::vector<std::string> &args);
    bool sign_transfer(const std::vector<std::string> &args);
    bool submit_transfer(const std::vector<std::string> &args);
    std::vector<std::vector<cryptonote::tx_destination_entry>> split_amounts(
        std::vector<cryptonote::tx_destination_entry> dsts, size_t num_splits
    );
    bool print_address(const std::vector<std::string> &args = std::vector<std::string>());
    bool save(const std::vector<std::string> &args);
    bool set_variable(const std::vector<std::string> &args);
    bool rescan_spent(const std::vector<std::string> &args);
    bool set_log(const std::vector<std::string> &args);
    bool get_tx_key(const std::vector<std::string> &args);
    bool check_tx_key(const std::vector<std::string> &args);
    bool get_tx_proof(const std::vector<std::string> &args);
    bool check_tx_proof(const std::vector<std::string> &args);
    bool get_spend_proof(const std::vector<std::string> &args);
    bool check_spend_proof(const std::vector<std::string> &args);
    bool show_transfers(const std::vector<std::string> &args);
    bool rescan_blockchain(const std::vector<std::string> &args);
    bool refresh_main(uint64_t start_height,  bool is_init = false);
    bool status(const std::vector<std::string> &args);
    bool wallet_info(const std::vector<std::string> &args);
    bool show_transfer(const std::vector<std::string> &args);
    bool change_password(const std::vector<std::string>& args);
    bool lock(const std::vector<std::string>& args);
    bool net_stats(const std::vector<std::string>& args);
    bool public_nodes(const std::vector<std::string>& args);
    bool welcome(const std::vector<std::string>& args);
    bool version(const std::vector<std::string>& args);
    bool on_unknown_command(const std::vector<std::string>& args);

    uint64_t get_daemon_blockchain_height(std::string& err);
    bool try_connect_to_daemon(bool silent = false, uint32_t* version = nullptr);
    bool ask_wallet_create_if_needed();
    std::string get_prompt() const;
    bool print_seed(bool encrypted);
    void on_refresh_finished(uint64_t start_height, uint64_t fetched_blocks, bool is_init, bool received_money);
    std::pair<std::string, std::string> show_outputs_line(const std::vector<uint64_t> &heights, uint64_t blockchain_height, uint64_t highlight_idx = std::numeric_limits<uint64_t>::max()) const;
    bool prompt_if_old(const std::vector<tools::wallet2::pending_tx> &ptx_vector);
    bool on_command(bool (simple_wallet::*cmd)(const std::vector<std::string>&), const std::vector<std::string> &args);
    bool on_empty_command();
    bool on_cancelled_command();
    void check_for_inactivity_lock(bool user);

    struct transfer_view
    {
      std::string type;
      boost::variant<uint64_t, std::string> block;
      uint64_t timestamp;
      std::string direction;
      bool confirmed;
      uint64_t amount;
      crypto::hash hash;
      uint64_t fee;
      std::string addr;
      std::string note;
      std::string unlocked;
    };
    bool get_transfers(std::vector<std::string>& args_, std::vector<transfer_view>& transfers);

    /*!
     * \brief Prints the seed with a nice message
     * \param seed seed to print
     */
    void print_seed(const epee::wipeable_string &seed);

    /*!
     * \brief Gets the word seed language from the user.
     * 
     * User is asked to choose from a list of supported languages.
     * 
     * \return The chosen language.
     */
    std::string get_mnemonic_language();

    /*!
     * \brief When --do-not-relay option is specified, save the raw tx hex blob to a file instead of calling m_wallet->commit_tx(ptx).
     * \param ptx_vector Pending tx(es) created by transfer/sweep_all
     */
    void commit_or_save(std::vector<tools::wallet2::pending_tx>& ptx_vector);


    // idle thread workers
    bool check_inactivity();
    bool check_refresh();

    void handle_transfer_exception(const std::exception_ptr &e, bool trusted_daemon);


    //----------------- i_wallet2_callback ---------------------
    virtual void on_new_block(uint64_t height, const cryptonote::block& block);
    virtual void on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, bool is_change, uint64_t unlock_time);
    virtual void on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount);
    virtual void on_money_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& in_tx, uint64_t amount, const cryptonote::transaction& spend_tx);
    virtual void on_skip_transaction(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx);
    virtual boost::optional<epee::wipeable_string> on_get_password(const char *reason);
    virtual void on_device_button_request(uint64_t code);
    virtual boost::optional<epee::wipeable_string> on_device_pin_request();
    virtual boost::optional<epee::wipeable_string> on_device_passphrase_request(bool & on_device);
    //----------------------------------------------------------

    friend class refresh_progress_reporter_t;

    class refresh_progress_reporter_t
    {
    public:
      refresh_progress_reporter_t(cryptonote::simple_wallet& simple_wallet)
        : m_simple_wallet(simple_wallet)
        , m_blockchain_height(0)
        , m_blockchain_height_update_time()
        , m_print_time()
      {
      }

      void update(uint64_t height, bool force = false)
      {
        auto current_time = std::chrono::system_clock::now();
        const auto node_update_threshold = std::chrono::seconds(DIFFICULTY_TARGET_V1 / 2); // use min of V1/V2
        if (node_update_threshold < current_time - m_blockchain_height_update_time || m_blockchain_height <= height)
        {
          update_blockchain_height();
          m_blockchain_height = (std::max)(m_blockchain_height, height);
        }

        if (std::chrono::milliseconds(20) < current_time - m_print_time || force)
        {
          std::cout << QT_TRANSLATE_NOOP("cryptonote::simple_wallet", "Height ") << height << " / " << m_blockchain_height << '\r' << std::flush;
          m_print_time = current_time;
        }
      }

    private:
      void update_blockchain_height()
      {
        std::string err;
        uint64_t blockchain_height = m_simple_wallet.get_daemon_blockchain_height(err);
        if (err.empty())
        {
          m_blockchain_height = blockchain_height;
          m_blockchain_height_update_time = std::chrono::system_clock::now();
        }
        else
        {
          LOG_ERROR("Failed to get current blockchain height: " << err);
        }
      }

    private:
      cryptonote::simple_wallet& m_simple_wallet;
      uint64_t m_blockchain_height;
      std::chrono::system_clock::time_point m_blockchain_height_update_time;
      std::chrono::system_clock::time_point m_print_time;
    };

  private:
    std::string m_wallet_file;
    std::string m_generate_new;
    std::string m_restore_from_spend_key;
    std::string m_mnemonic_language;
    std::string m_import_path;
    std::string m_restore_date;  // optional - converted to m_restore_height

    epee::wipeable_string m_electrum_seed;  // electrum-style seed parameter

    crypto::secret_key m_recovery_key;  // recovery key (used as random for wallet gen)
    bool m_restore_from_seed;  // recover flag
    bool m_allow_mismatched_daemon_version;
    bool m_restoring;           // are we restoring, by whatever method?
    uint64_t m_restore_height;  // optional
    bool m_use_english_language_names;

    epee::console_handlers_binder m_cmd_binder;

    std::unique_ptr<tools::wallet2> m_wallet;
    refresh_progress_reporter_t m_refresh_progress_reporter;

    std::atomic<bool> m_idle_run;
    boost::thread m_idle_thread;
    boost::mutex m_idle_mutex;
    boost::condition_variable m_idle_cond;

    std::atomic<bool> m_auto_refresh_enabled;
    bool m_auto_refresh_refreshing;
    std::atomic<bool> m_in_manual_refresh;

    std::atomic<time_t> m_last_activity_time;
    std::atomic<bool> m_locked;
    std::atomic<bool> m_in_command;

    template<uint64_t mini, uint64_t maxi> struct get_random_interval { public: uint64_t operator()() const { return crypto::rand_range(mini, maxi); } };

    epee::math_helper::once_a_time_seconds<1> m_inactivity_checker;
    epee::math_helper::once_a_time_seconds_range<get_random_interval<80 * 1000000, 100 * 1000000>> m_refresh_checker;
    

    std::unordered_map<std::string, uint32_t> m_claimed_cph;

  };
}
