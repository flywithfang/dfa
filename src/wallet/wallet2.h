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

#pragma once

#include <memory>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#if BOOST_VERSION >= 107400
#include <boost/serialization/library_version_type.hpp>
#endif
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/deque.hpp>
#include <boost/thread/lock_guard.hpp>
#include <atomic>
#include <random>

#include "include_base_utils.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/account_boost_serialization.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "net/http.h"
#include "storages/http_abstract_invoke.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "common/unordered_containers_boost_serialization.h"
#include "common/util.h"
#include "crypto/chacha.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"
#include "ringct/rctOps.h"
#include "checkpoints/checkpoints.h"
#include "serialization/crypto.h"
#include "serialization/string.h"
#include "serialization/pair.h"
#include "serialization/containers.h"
#include "ringct/rctSigs.h"
#include "wallet_errors.h"
#include "common/password.h"
#include "node_rpc_proxy.h"

#include <iostream>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.wallet2"

#define THROW_ON_RPC_RESPONSE_ERROR(r, error, res, method, ...) \
  do { \
    throw_on_rpc_response_error(r, error, res.status, method); \
    throw_wallet_ex_if(res.status != CORE_RPC_STATUS_OK, ## __VA_ARGS__); \
  } while(0)

#define THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, err, res, method) \
  THROW_ON_RPC_RESPONSE_ERROR(r, err, res, method, tools::error::wallet_generic_rpc_error, method, res.status)

class Serialization_portability_wallet_Test;
class wallet_accessor_test;

namespace tools
{
  #define MONERO_DEFAULT_LOG_CATEGORY "wallet.wallet2"

// used to choose when to stop adding outputs to a tx
#define APPROXIMATE_INPUT_BYTES 80

// used to target a given block weight (additional outputs may be added on top to build fee)
#define TX_WEIGHT_TARGET(bytes) (bytes*2/3)

#define UNSIGNED_TX_PREFIX "Monero unsigned tx set\005"
#define SIGNED_TX_PREFIX "Monero signed tx set\005"

#define RECENT_OUTPUT_RATIO (0.5) // 50% of outputs are from the recent zone
#define RECENT_OUTPUT_DAYS (1.8) // last 1.8 day makes up the recent zone (taken from monerolink.pdf, Miller et al)
#define RECENT_OUTPUT_ZONE ((time_t)(RECENT_OUTPUT_DAYS * 86400))
#define RECENT_OUTPUT_BLOCKS (RECENT_OUTPUT_DAYS * 720)

#define FEE_ESTIMATE_GRACE_BLOCKS 10 // estimate fee valid for that many blocks

#define SECOND_OUTPUT_RELATEDNESS_THRESHOLD 0.0f

#define SUBADDRESS_LOOKAHEAD_MAJOR 50
#define SUBADDRESS_LOOKAHEAD_MINOR 200

#define KEY_IMAGE_EXPORT_FILE_MAGIC "Monero key image export\003"


#define OUTPUT_EXPORT_FILE_MAGIC "Monero output export\004"

#define SEGREGATION_FORK_HEIGHT 99999999
#define TESTNET_SEGREGATION_FORK_HEIGHT 99999999
#define STAGENET_SEGREGATION_FORK_HEIGHT 99999999
#define SEGREGATION_FORK_VICINITY 1500 /* blocks */

#define FIRST_REFRESH_GRANULARITY     1024

#define GAMMA_SHAPE 19.28
#define GAMMA_SCALE (1/1.61)

#define DEFAULT_MIN_OUTPUT_COUNT 5
#define DEFAULT_MIN_OUTPUT_VALUE (2*COIN)

#define DEFAULT_INACTIVITY_LOCK_TIMEOUT 90 // a minute and a half

#define IGNORE_LONG_PAYMENT_ID_FROM_BLOCK_VERSION 12

  class ringdb;
  class wallet2;
  class Notify;

  class gamma_picker
  {
  public:
    uint64_t pick();
    gamma_picker(const std::vector<uint64_t> &rct_offsets);
    gamma_picker(const std::vector<uint64_t> &rct_offsets, double shape, double scale);

  private:
    struct gamma_engine
    {
      typedef uint64_t result_type;
      static constexpr result_type min() { return 0; }
      static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }
      result_type operator()() { return crypto::rand<result_type>(); }
    } engine;

private:
    std::gamma_distribution<double> gamma;
    const std::vector<uint64_t> &rct_offsets;
    const uint64_t *begin, *end;
    uint64_t num_rct_outputs;
    double average_output_time;
  };

  class wallet_keys_unlocker
  {
  public:
    wallet_keys_unlocker(wallet2 &w, const boost::optional<tools::password_container> &password);
    wallet_keys_unlocker(wallet2 &w, bool locked, const epee::wipeable_string &password);
    ~wallet_keys_unlocker();
  private:
    wallet2 &w;
    bool locked;
    crypto::chacha_key key;
    static boost::mutex lockers_lock;
    static unsigned int lockers;
  };

  class i_wallet2_callback
  {
  public:
    // Full wallet callbacks
    virtual void on_new_block(uint64_t height, const cryptonote::block& block) {}
    virtual void on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, bool is_change, uint64_t unlock_time) {}
    virtual void on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount) {}
    virtual void on_money_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& in_tx, uint64_t amount, const cryptonote::transaction& spend_tx) {}
    virtual void on_skip_transaction(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx) {}
    virtual boost::optional<epee::wipeable_string> on_get_password(const char *reason) { return boost::none; }

    // Common callbacks
    virtual void on_pool_tx_removed(const crypto::hash &txid) {}
    virtual ~i_wallet2_callback() {}
  };

  class hashchain
  {
  public:
    hashchain(): m_genesis(crypto::null_hash), m_offset(0) {}

    size_t size() const { 
      return m_blockchain.size() + m_offset;
       }
    size_t offset() const { return m_offset; }
    const crypto::hash &genesis() const { return m_genesis; }
    void push_back(const crypto::hash &hash) {
     if (m_offset == 0 && m_blockchain.empty()) 
        m_genesis = hash; 
     m_blockchain.push_back(hash); 
   }
    bool is_in_bounds(size_t idx) const { return idx >= m_offset && idx < size(); }
    const crypto::hash &operator[](size_t idx) const { return m_blockchain[idx - m_offset]; }
    crypto::hash &operator[](size_t idx) {
      if(!is_in_bounds(idx)) 
        throw std::runtime_error("bad block index "+std::to_string(idx));
     return m_blockchain[idx - m_offset]; 
   }
    void crop(size_t height) { m_blockchain.resize(height - m_offset); }
    void clear() { m_offset = 0; m_blockchain.clear(); }
    bool empty() const { return m_blockchain.empty() && m_offset == 0; }
    void trim(size_t height) { 
      while (height > m_offset && m_blockchain.size() > 1)
       { m_blockchain.pop_front(); ++m_offset; } 
     m_blockchain.shrink_to_fit(); 
   }
    void refill(const crypto::hash &hash) { 
      m_blockchain.push_back(hash);
       --m_offset; 
     }

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int ver)
    {
      a & m_offset;
      a & m_genesis;
      a & m_blockchain;
    }

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(0)
      VARINT_FIELD(m_offset)
      FIELD(m_genesis)
  //    FIELD(m_blockchain)
        do {              
          ar.tag("m_blockchain");           
          bool r = ::do_serialize(ar, m_blockchain);     
          if (!r || !ar.stream().good()) return false;  
        } while(0);
    END_SERIALIZE()

  private:
    size_t m_offset;
    crypto::hash m_genesis;
    std::deque<crypto::hash> m_blockchain;
  };

  class wallet_keys_unlocker;
  class wallet2
  {
    friend class ::Serialization_portability_wallet_Test;
    friend class ::wallet_accessor_test;
    friend class wallet_keys_unlocker;
  public:
    static constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);


    static const char* tr(const char* str);

    static bool has_testnet_option(const boost::program_options::variables_map& vm);
    static bool has_stagenet_option(const boost::program_options::variables_map& vm);
    static void init_options(boost::program_options::options_description& desc_params);

    //! Uses stdin and stdout. Returns a wallet2 and password for `wallet_file` if no errors.
    static std::pair<std::unique_ptr<wallet2>, password_container>
      make_from_file(const boost::program_options::variables_map& vm, bool unattended, const std::string& wallet_file, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter);

    //! Uses stdin and stdout. Returns a wallet2 and password for wallet with no file if no errors.
    static std::pair<std::unique_ptr<wallet2>, password_container> make_new(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter);

    //! Just parses variables.
    static std::unique_ptr<wallet2> make_dummy(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter);

    static bool verify_password(const std::string& keys_file_name, const epee::wipeable_string& password,  uint64_t kdf_rounds);

    wallet2(cryptonote::network_type nettype = cryptonote::MAINNET, uint64_t kdf_rounds = 1, bool unattended = false, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = std::unique_ptr<epee::net_utils::http::http_client_factory>(new net::http::client_factory()));
    ~wallet2();



    struct tx_scan_info_t
    {
      cryptonote::keypair otk_p;
      crypto::key_image ki;
      rct::key noise;
      uint64_t money_transfered;

      tx_scan_info_t():  money_transfered(0) {}
    };

    struct transfer_details
    {
      uint64_t m_block_height;
      //cryptonote::transaction_prefix m_tx;
      crypto::public_key m_otk;
      crypto::public_key m_tx_key;
      crypto::hash m_txid;
      uint64_t m_unlock_time;
      uint64_t m_internal_output_index;
      uint64_t m_global_output_index;
      bool     m_spent;
      uint64_t m_spent_height;
      crypto::key_image m_key_image; //TODO: key_image stored twice :(
      rct::key m_noise;
      uint64_t m_amount;
      uint64_t m_block_time;

      uint64_t amount() const { return m_amount; }
      const crypto::public_key& otk()const{
          return m_otk;
      }
      const crypto::public_key &get_public_key() const {
        return otk();
         }

 //     BEGIN_SERIALIZE_OBJECT()
  template <bool W, template <bool> class Archive>      
  bool do_serialize(Archive<W> &ar) {         
    ar.begin_object();              
    bool r = do_serialize_object(ar);         
    ar.end_object();              
    return r;               
  }                 
  template <bool W, template <bool> class Archive>      
  bool do_serialize_object(Archive<W> &ar){
        FIELD(m_block_height)
        FIELD(m_otk)
        FIELD(m_tx_key)
        FIELD(m_txid)
        VARINT_FIELD(m_unlock_time)
        VARINT_FIELD(m_internal_output_index)
        VARINT_FIELD(m_global_output_index)
        FIELD(m_spent)
        VARINT_FIELD(m_spent_height)
        FIELD(m_key_image)
        FIELD(m_noise)
        VARINT_FIELD(m_amount)
        VARINT_FIELD(m_block_time)

        return ar.stream().good();      
  }
    };

     struct pool_transfer_in
    {
      crypto::hash m_tx_hash;
      uint64_t m_amount;
      uint64_t m_fee;
      uint64_t m_block_height;
      uint64_t m_unlock_time;
      uint64_t m_timestamp;
      bool m_coinbase;
      bool m_double_spend_seen;

    BEGIN_SERIALIZE_OBJECT()
        VERSION_FIELD(0)
        FIELD(m_tx_hash)
        VARINT_FIELD(m_amount)
        VARINT_FIELD(m_fee)
        VARINT_FIELD(m_block_height)
        VARINT_FIELD(m_unlock_time)
        VARINT_FIELD(m_timestamp)
        FIELD(m_coinbase)
         FIELD(m_double_spend_seen)
      END_SERIALIZE()
     
    };

    struct unconfirmed_transfer_out
    {
      cryptonote::transaction_prefix m_tx;
      time_t m_sent_time;
      uint64_t m_fee;
      uint64_t m_amount;                    //money
      cryptonote::account_public_address m_addr;        //destination address

      enum { pending, pending_not_in_pool, failed } m_state;

      BEGIN_SERIALIZE_OBJECT()
        VERSION_FIELD(1)
        FIELD(m_tx)
        VARINT_FIELD(m_sent_time)
        VARINT_FIELD(m_fee)
        VARINT_FIELD(m_amount)
        FIELD(m_addr)
        VARINT_FIELD(m_state)
      END_SERIALIZE()

      uint64_t fee()const { return m_fee;}
    };

    struct confirmed_transfer_out
    {
      uint64_t m_block_height;
      uint64_t m_fee;
      uint64_t m_amount;                    //money
      cryptonote::account_public_address m_addr;        //destination address
      uint64_t m_sent_time;
      uint64_t m_unlock_time;

      confirmed_transfer_out() {}
      confirmed_transfer_out(const unconfirmed_transfer_out &utd, uint64_t height):
       m_block_height(height), m_addr(utd.m_addr),m_amount(utd.m_amount),m_fee(utd.m_fee), m_sent_time(utd.m_sent_time), m_unlock_time(utd.m_tx.unlock_time) {}

      BEGIN_SERIALIZE_OBJECT()
        VERSION_FIELD(0)
        VARINT_FIELD(m_block_height)
        VARINT_FIELD(m_fee)
        VARINT_FIELD(m_amount);
         FIELD(m_addr)
        VARINT_FIELD(m_sent_time)
        VARINT_FIELD(m_unlock_time)
      END_SERIALIZE()

      uint64_t fee()const {return m_fee;}
    };

    typedef std::vector<transfer_details> transfer_container;


    // The convention for destinations is:
    // dests does not include change
    // splitted_dsts (in construction_data) does
    struct pending_tx
    {
      cryptonote::transaction tx;
      uint64_t  fee;
      cryptonote::tx_destination_entry change_dts;
      std::vector<size_t> selected_transfers;
      std::string key_images;
      crypto::secret_key tx_sec;
      cryptonote::tx_destination_entry dst;


      BEGIN_SERIALIZE_OBJECT()
        FIELD(tx)
        FIELD(fee)
        FIELD(change_dts)
        FIELD(selected_transfers)
        FIELD(key_images)
        FIELD(tx_sec)
        FIELD(dst)
      END_SERIALIZE()
    };

   

    struct signed_tx_set
    {
      std::vector<pending_tx> ptx;
      std::vector<crypto::key_image> key_images;
      serializable_unordered_map<crypto::public_key, crypto::key_image> tx_key_images;

      BEGIN_SERIALIZE_OBJECT()
        VERSION_FIELD(0)
        FIELD(ptx)
        FIELD(key_images)
        FIELD(tx_key_images)
      END_SERIALIZE()
    };

   

    struct keys_file_data
    {
      crypto::chacha_iv iv;
      std::string account_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(account_data)
      END_SERIALIZE()
    };

    struct cache_file_data
    {
      crypto::chacha_iv iv;
      std::string cache_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(cache_data)
      END_SERIALIZE()
    };

   
    struct reserve_proof_entry
    {
      crypto::hash txid;
      uint64_t o_index;
      crypto::public_key shared_secret;
      crypto::key_image key_image;
      crypto::signature shared_secret_sig;
      crypto::signature key_image_sig;

      BEGIN_SERIALIZE_OBJECT()
        VERSION_FIELD(0)
        FIELD(txid)
        VARINT_FIELD(o_index)
        FIELD(shared_secret)
        FIELD(key_image)
        FIELD(shared_secret_sig)
        FIELD(key_image_sig)
      END_SERIALIZE()
    };

    typedef std::tuple<uint64_t, crypto::public_key, rct::key> get_outs_entry;

    struct parsed_block
    {
      crypto::hash hash;
      cryptonote::block block;
      std::vector<cryptonote::transaction> txes;
      cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices o_indices;
      bool error;
    };

    struct is_out_data
    {
      crypto::public_key tx_key;
      crypto::key_derivation kA;//kA=kG.a
      std::vector<bool> received;
      bool empty()const{
        return tx_key==crypto::null_pkey;
      }
    };

    struct tx_cache_data
    {
      std::vector<cryptonote::tx_extra_field> tx_extra_fields;
      is_out_data primary;

      bool empty() const { return tx_extra_fields.empty() && primary.empty() ; }
    };


    /*!
     * \brief Generates a wallet or restores one.
     * \param  wallet_              Name of wallet file
     * \param  password             Password of wallet file
     * \param  recovery_param       If it is a restore, the recovery key
     * \param  recover              Whether it is a restore
     * \param  two_random           Whether it is a non-deterministic wallet
     * \param  create_address_file  Whether to create an address file
     * \return                      The secret key of the generated wallet
     */
    crypto::secret_key generate(const std::string& wallet, const epee::wipeable_string& password,
      const crypto::secret_key& recovery_param = crypto::secret_key(), bool recover = false,
      bool create_address_file = false);
   
    /*!
     * \brief Rewrites to the wallet file for wallet upgrade (doesn't generate key, assumes it's already there)
     * \param wallet_name Name of wallet file (should exist)
     * \param password    Password for wallet file
     */
    void rewrite(const std::string& wallet_name, const epee::wipeable_string& password);
    void load(const std::string& wallet, const epee::wipeable_string& password, const std::string& keys_buf = "", const std::string& cache_buf = "");
    void store();
    /*!
     * \brief store_to  Stores wallet to another file(s), deleting old ones
     * \param path      Path to the wallet file (keys and address filenames will be generated based on this filename)
     * \param password  Password to protect new wallet (TODO: probably better save the password in the wallet object?)
     */
    void store_to(const std::string &path, const epee::wipeable_string &password);
    /*!
     * \brief get_keys_file_data  Get wallet keys data which can be stored to a wallet file.
     * \param password            Password of the encrypted wallet buffer (TODO: probably better save the password in the wallet object?)
     * \param watch_only          true to include only view key, false to include both spend and view keys
     * \return                    Encrypted wallet keys data which can be stored to a wallet file
     */
    boost::optional<wallet2::keys_file_data> get_keys_file_data(const epee::wipeable_string& password, bool watch_only);
    /*!
     * \brief get_cache_file_data   Get wallet cache data which can be stored to a wallet file.
     * \param password              Password to protect the wallet cache data (TODO: probably better save the password in the wallet object?)
     * \return                      Encrypted wallet cache data which can be stored to a wallet file
     */
    boost::optional<wallet2::cache_file_data> get_cache_file_data(const epee::wipeable_string& password);

    std::string path() const;

    /*!
     * \brief verifies given password is correct for default wallet keys file
     */
    bool verify_password(const epee::wipeable_string& password);
    cryptonote::account_base& get_account(){return m_account;}
    const cryptonote::account_base& get_account()const{return m_account;}

    void encrypt_keys(const crypto::chacha_key &key);
    void encrypt_keys(const epee::wipeable_string &password);
    void decrypt_keys(const crypto::chacha_key &key);
    void decrypt_keys(const epee::wipeable_string &password);

    void set_refresh_from_block_height(uint64_t height) {m_refresh_from_block_height = height;}
    uint64_t get_refresh_from_block_height() const {return m_refresh_from_block_height;}

    void explicit_refresh_from_block_height(bool expl) {m_explicit_refresh_from_block_height = expl;}
    bool explicit_refresh_from_block_height() const {return m_explicit_refresh_from_block_height;}

    void max_reorg_depth(uint64_t depth) {m_max_reorg_depth = depth;}
    uint64_t max_reorg_depth() const {return m_max_reorg_depth;}


    bool deinit();
    bool init(std::string daemon_address = "http://localhost:8080",
      boost::optional<epee::net_utils::http::login> daemon_login = boost::none,
      const std::string &proxy = "",
      uint64_t upper_transaction_weight_limit = 0,
      bool trusted_daemon = true,
      epee::net_utils::ssl_options_t ssl_options = epee::net_utils::ssl_support_t::e_ssl_support_autodetect);
    bool set_daemon(std::string daemon_address = "http://localhost:8080",
      boost::optional<epee::net_utils::http::login> daemon_login = boost::none, bool trusted_daemon = true,
      epee::net_utils::ssl_options_t ssl_options = epee::net_utils::ssl_support_t::e_ssl_support_autodetect);
    bool set_proxy(const std::string &address);

    void stop() { m_run.store(false, std::memory_order_relaxed);  }

    /*!
     * \brief Checks if deterministic wallet
     */
    bool is_deterministic() const;
    bool get_seed(epee::wipeable_string& electrum_words, const epee::wipeable_string &passphrase = epee::wipeable_string()) const;

    /*!
     * \brief Gets the seed language
     */
    const std::string &get_seed_language() const;
    /*!
     * \brief Sets the seed language
     */
    void set_seed_language(const std::string &language);

    // Subaddress scheme
    cryptonote::account_public_address get_address() const { return m_account.get_keys().m_account_address; }
    std::string get_address_as_str() const;
  
    /*!
     * \brief Tells if the wallet file is deprecated.
     */
    void refresh( uint64_t start_height);
    void refresh( const uint64_t start_height, uint64_t & blocks_fetched, bool check_pool = true);

    cryptonote::network_type nettype() const { return m_nettype; }

    uint64_t unlocked_balance( bool strict=true);
    // locked & unlocked balance per subaddress of given or current subaddress account
    uint64_t balance(bool strict=true) const;
  

    wallet2::pending_tx transfer_selected_rct(const cryptonote::tx_destination_entry & dt, const std::vector<size_t>& selected_transfers, size_t fake_outputs_count,std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs,uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra);

    void commit_tx(pending_tx& ptx_vector);
    void commit_tx(std::vector<pending_tx>& ptx_vector);

    std::vector<wallet2::pending_tx> transfer(cryptonote::tx_destination_entry dst, const size_t fake_outs_count, const uint64_t unlock_time, const std::vector<uint8_t>& extra={});    
    std::vector<wallet2::pending_tx> sweep_transfers(uint64_t below, const cryptonote::account_public_address &address,   const size_t fake_outs_count=10, const uint64_t unlock_time=0, const std::vector<uint8_t>& extra={});
   
    bool sanity_check(const std::vector<wallet2::pending_tx> &ptx_vector, std::vector<cryptonote::tx_destination_entry> dsts) const;
    bool check_connection(uint32_t *version = NULL, bool *ssl = NULL, uint32_t timeout = 200000);
    void get_transfers(wallet2::transfer_container& incoming_transfers) const;
    void get_confirmed_transfer_in(std::vector<transfer_details>& payments, uint64_t min_height, uint64_t max_height = (uint64_t)-1) const;
    void get_payments_out(std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_out>>& confirmed_payments,uint64_t min_height, uint64_t max_height = (uint64_t)-1) const;
    void get_unconfirmed_payments_out(std::list<std::pair<crypto::hash,wallet2::unconfirmed_transfer_out>>& unconfirmed_payments) const;
    void get_unconfirmed_transfer_in(std::list<std::pair<crypto::hash,wallet2::pool_transfer_in>>& unconfirmed_payments) const;

    uint64_t get_blockchain_current_height() const { return  m_blockchain.size(); }
    void rescan_spent();
    void rescan_blockchain( bool refresh = true);
    bool is_transfer_unlocked(const transfer_details& td);
    bool is_transfer_unlocked(uint64_t unlock_time, uint64_t block_height);

    std::vector<cryptonote::public_node> get_public_nodes(bool white_only = true);

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int ver)
    {
      a & m_account_public_address;
      a & m_blockchain;
      
      a & m_transfers_in;
      a & m_pool_transfers_in.parent();

    
      a & m_key_images.parent();
      a & m_pool_transfer_outs;
      a & m_tx_secs.parent();
      a & m_confirmed_transfer_outs.parent();

      a & m_otks.parent();

    
    
    }

    BEGIN_SERIALIZE_OBJECT()
    MDEBUG("serialize wallet2");
       std::string magic = "monero wallet cache";     
      do {            
        ar.tag("magic");        
        ar.serialize_blob((void*)magic.data(), magic.size()); 
        if (!ar.stream().good()) return false;  
        if (magic != "monero wallet cache") return false;   
      } while(0);

       uint32_t version = 0;        
      do {            
        ar.tag("version");        
        ar.serialize_varint(version);   
        if (!ar.stream().good()) return false;  
      } while(0);

    
      FIELD(m_account_public_address)
      FIELD(m_transfers_in)
      FIELD(m_blockchain)
      FIELD(m_key_images)
      FIELD(m_pool_transfer_outs)
      FIELD(m_tx_secs)
      FIELD(m_confirmed_transfer_outs)
      FIELD(m_pool_transfers_in)
      FIELD(m_otks)
    END_SERIALIZE()

    /*!
     * \brief  Check if wallet keys and bin files exist
     * \param  file_path           Wallet file path
     * \param  keys_file_exists    Whether keys file exists
     * \param  wallet_file_exists  Whether bin file exists
     */
    static void wallet_exists(const std::string& file_path, bool& keys_file_exists, bool& wallet_file_exists);
    /*!
     * \brief  Check if wallet file path is valid format
     * \param  file_path      Wallet file path
     * \return                Whether path is valid format
     */
    static bool wallet_valid_path_format(const std::string& file_path);

    bool always_confirm_transfers() const { return m_always_confirm_transfers; }
    void always_confirm_transfers(bool always) { m_always_confirm_transfers = always; }
    bool store_tx_info() const { return true; }
    void store_tx_info(bool store) {  }
    uint32_t default_mixin() const { return m_default_mixin; }
    void default_mixin(uint32_t m) { m_default_mixin = m; }
    bool auto_refresh() const { return m_auto_refresh; }
    void auto_refresh(bool r) { m_auto_refresh = r; }

    uint32_t inactivity_lock_timeout()const { return m_inactivity_lock_timeout; }
    void inactivity_lock_timeout(uint32_t seconds) { m_inactivity_lock_timeout = seconds; }

    bool get_tx_key_cached(const crypto::hash &txid, crypto::secret_key &tx_key) const;
    void set_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key, const boost::optional<cryptonote::account_public_address> &single_destination_subaddress = boost::none);
    bool get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key);
    void check_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key,  const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations);
    void check_tx_key_helper(const crypto::hash &txid, const crypto::key_derivation &derivation,  const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations);
    void check_tx_key_helper(const cryptonote::transaction &tx, const crypto::key_derivation &derivation,  const cryptonote::account_public_address &address, uint64_t &received) const;
    std::string get_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address,  const std::string &message);
    std::string get_tx_proof(const cryptonote::transaction &tx, const crypto::secret_key &tx_key, const cryptonote::account_public_address &address,  const std::string &message) const;
    bool check_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address,  const std::string &message, const std::string &sig_str, uint64_t &received, bool &in_pool, uint64_t &confirmations);
    bool check_tx_proof(const cryptonote::transaction &tx, const cryptonote::account_public_address &address,  const std::string &message, const std::string &sig_str, uint64_t &received) const;

    std::string get_spend_proof(const crypto::hash &txid, const std::string &message);
    bool check_spend_proof(const crypto::hash &txid, const std::string &message, const std::string &sig_str);

   /*!
    * \brief GUI Address book get/store
    */
        
    uint64_t get_num_rct_outputs();
    size_t get_num_transfer_details() const { return m_transfers_in.size(); }
    const transfer_details &get_transfer_details(size_t idx) const;

    uint8_t get_current_hard_fork();
    void get_hard_fork_info(uint8_t version, uint64_t &earliest_height);
    bool use_fork_rules(uint8_t version, int64_t early_blocks = 0);
    int get_fee_algorithm();

    std::string get_wallet_file() const;
    std::string get_keys_file() const;
    std::string get_daemon_address() const;
    const boost::optional<epee::net_utils::http::login>& get_daemon_login() const { return m_daemon_login; }
    uint64_t get_daemon_blockchain_height(std::string& err);
    uint64_t get_daemon_blockchain_target_height(std::string& err);
    uint64_t get_daemon_adjusted_time();

 

    /*!
     * \brief  Get the list of registered account tags. 
     * \return first.Key=(tag's name), first.Value=(tag's label), second[i]=(i-th account's tag)
     */
    const std::pair<serializable_map<std::string, std::string>, std::vector<std::string>>& get_account_tags();
   
    enum message_signature_type_t { sign_with_spend_key, sign_with_view_key };
    std::string sign(const std::string &data, message_signature_type_t signature_type) const;
    struct message_signature_result_t { bool valid; message_signature_type_t type; };
    message_signature_result_t verify(const std::string &data, const cryptonote::account_public_address &address, const std::string &signature) const;

   
    /*!
     * \brief verify_with_public_key verifies message was signed with given public key
     * \param data                   message
     * \param public_key             public key to check signature
     * \param signature              signature of the message
     * \return                       true if the signature is correct
     */
    bool verify_with_public_key(const std::string &data, const crypto::public_key &public_key, const std::string &signature) const;

   


    std::string encrypt(const char *plaintext, size_t len, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt(const epee::span<char> &span, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt(const std::string &plaintext, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt(const epee::wipeable_string &plaintext, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt_with_view_secret_key(const std::string &plaintext, bool authenticated = true) const;
    template<typename T=std::string> T decrypt(const std::string &ciphertext, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string decrypt_with_view_secret_key(const std::string &ciphertext, bool authenticated = true) const;


    uint64_t get_blockchain_height_by_date(uint16_t year, uint8_t month, uint8_t day);    // 1<=month<=12, 1<=day<=31

    bool is_synced();

    uint64_t get_base_fee();
  

    /*
     * "attributes" are a mechanism to store an arbitrary number of string values
     * on the level of the wallet as a whole, identified by keys. Their introduction,
     * technically the unordered map m_attributes stored as part of a wallet file,
     * led to a new wallet file version, but now new singular pieces of info may be added
     * without the need for a new version.
     *
     * The first and so far only value stored as such an attribute is the description.
     * It's stored under the standard key ATTRIBUTE_DESCRIPTION (see method set_description).
     *
     * The mechanism is open to all clients and allows them to use it for storing basically any
     * single string values in a wallet. To avoid the problem that different clients possibly
     * overwrite or misunderstand each other's attributes, a two-part key scheme is
     * proposed: <client name>.<value name>
     */
    const char* const ATTRIBUTE_DESCRIPTION = "wallet2.description";

    template<class t_request, class t_response>
    inline bool invoke_http_json(const boost::string_ref uri, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const boost::string_ref http_method = "POST")
    {
      if (m_offline) return false;
      boost::lock_guard<boost::recursive_mutex> lock(m_daemon_rpc_mutex);
      return epee::net_utils::invoke_http_json(uri, req, res, *m_http_client, timeout, http_method);
    }
    template<class t_request, class t_response>
    inline bool invoke_http_bin(const boost::string_ref uri, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const boost::string_ref http_method = "POST")
    {
      if (m_offline) return false;
      boost::lock_guard<boost::recursive_mutex> lock(m_daemon_rpc_mutex);
      return epee::net_utils::invoke_http_bin(uri, req, res, *m_http_client, timeout, http_method);
    }
    template<class t_request, class t_response>
    inline bool invoke_http_json_rpc(const boost::string_ref uri, const std::string& method_name, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const boost::string_ref http_method = "POST", const std::string& req_id = "0")
    {
      if (m_offline) return false;
      boost::lock_guard<boost::recursive_mutex> lock(m_daemon_rpc_mutex);
      return epee::net_utils::invoke_http_json_rpc(uri, method_name, req, res, *m_http_client, timeout, http_method, req_id);
    }
   
    bool save_to_file(const std::string& path_to_file, const std::string& binary, bool is_printable = false) const;
    static bool load_from_file(const std::string& path_to_file, std::string& target_str, size_t max_size = 1000000000);

    uint64_t get_bytes_sent() const;
    uint64_t get_bytes_received() const;


    void change_password(const std::string &filename, const epee::wipeable_string &original_password, const epee::wipeable_string &new_password);

    bool is_tx_spendtime_unlocked(uint64_t unlock_time, uint64_t block_height);
    void set_offline(bool offline = true);
    bool is_offline() const { return m_offline; }

    static std::string get_default_daemon_address() { CRITICAL_REGION_LOCAL(default_daemon_address_lock); return default_daemon_address; }

    void update_pool_state(bool refreshed = false);
  private:

  std::vector<wallet2::pending_tx> __sweep(const cryptonote::account_public_address &addr,std::vector<size_t> selected, const uint64_t unlock_time=0, const std::vector<uint8_t>& extra={},const size_t fake_outs_count=10);

    void remove_obsolete_pool_transfer_in(const std::vector<crypto::hash> &tx_hashes);

    /*!
     * \brief  Stores wallet information to wallet file.
     * \param  keys_file_name Name of wallet file
     * \param  password       Password of wallet file
     * \param  watch_only     true to save only view key, false to save both spend and view keys
     * \return                Whether it was successful.
     */
    bool store_keys(const std::string& keys_file_name, const epee::wipeable_string& password, bool watch_only = false);
    /*!
     * \brief Load wallet keys information from wallet file.
     * \param keys_file_name Name of wallet file
     * \param password       Password of wallet file
     */
    bool load_keys(const std::string& keys_file_name, const epee::wipeable_string& password);
    /*!
     * \brief Load wallet keys information from a string buffer.
     * \param keys_buf       Keys buffer to load
     * \param password       Password of keys buffer
     */
    bool load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password);
    bool load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password, boost::optional<crypto::chacha_key>& keys_to_encrypt);
    void process_new_transaction( const cryptonote::transaction& tx, const std::vector<uint64_t> &o_indices, uint64_t height,  uint64_t ts, bool miner_tx, bool pool, bool double_spend_seen, const tx_cache_data &tx_cache_data);
    bool should_skip_block(const cryptonote::block &b, uint64_t height) const;
    void process_new_blockchain_entry( const cryptonote::block_complete_entry& bche, const parsed_block &pb, const std::vector<tx_cache_data> &tx_cache_data, size_t offset);
    void detach_blockchain(uint64_t height);
    std::list<crypto::hash>  get_short_chain_history() const;
    bool clear();
    void clear_soft(bool keep_key_images=false);
   cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response pull_blocks(uint64_t start_height, const std::list<crypto::hash> &short_chain_history);
    void pull_hashes(uint64_t start_height, uint64_t& blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<crypto::hash> &hashes);
    void fast_refresh(uint64_t stop_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, bool force = false);
std::tuple<bool, uint64_t,std::vector<cryptonote::block_complete_entry> , std::vector<wallet2::parsed_block>  > pull_and_parse_next_blocks(const uint64_t start_height, std::list<crypto::hash> &short_chain_history );
    void process_parsed_blocks(uint64_t start_height, const std::vector<cryptonote::block_complete_entry> &blocks, const std::vector<parsed_block> &parsed_blocks, uint64_t& blocks_added);

    bool prepare_file_names(const std::string& file_path);
    void comfirm_pool_transfer_out( const cryptonote::transaction& tx, uint64_t height);
    void process_outgoing( const cryptonote::transaction& tx, uint64_t height, uint64_t ts, uint64_t spent, uint64_t received);
    void add_pool_transfer_out(const pending_tx & ptx);
    void generate_genesis(cryptonote::block& b) const;
    void check_genesis(const crypto::hash& genesis_hash) const; //throws
    bool generate_chacha_key_from_secret_keys(crypto::chacha_key &key) const;
    void generate_chacha_key_from_password(const epee::wipeable_string &pass, crypto::chacha_key &key) const;
    uint64_t get_upper_transaction_weight_limit();
    float get_output_relatedness(const transfer_details &td0, const transfer_details &td1) const;
    void set_spent(size_t idx, uint64_t height);
    void set_unspent(size_t idx);
    bool is_spent(const transfer_details &td) const;
    bool is_spent(size_t idx, bool strict = true) const;
    void get_outs(std::vector<std::vector<get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count);
    std::vector<std::vector<tools::wallet2::get_outs_entry>>  get_outs(const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, std::vector<uint64_t> &rct_offsets);
    bool tx_add_fake_output(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, uint64_t global_index, const crypto::public_key& tx_public_key, const rct::key& mask, uint64_t real_index, bool unlocked) const;
    std::vector<size_t> get_only_rct(const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices) const;
    tx_scan_info_t scan_output(const cryptonote::transaction &tx, bool miner_tx, const is_out_data & tc,size_t i);
    void trim_hashchain();
    void setup_keys(const epee::wipeable_string &password);
    size_t get_transfer_details(const crypto::key_image &ki) const;

    bool get_rct_distribution(uint64_t &start_height, std::vector<uint64_t> &distribution);

    tx_cache_data cache_tx_data(const cryptonote::transaction& tx ) const;

    void init_type();
    void setup_new_blockchain();
    void create_keys_file(const std::string &wallet_, bool watch_only, const epee::wipeable_string &password, bool create_address_file);


    std::string get_rpc_status(const std::string &s) const;
    void throw_on_rpc_response_error(bool r, const epee::json_rpc::error &error, const std::string &status, const char *method) const;

    bool spends_one_of_ours(const cryptonote::transaction &tx) const;

    cryptonote::account_base m_account;
    boost::optional<epee::net_utils::http::login> m_daemon_login;
    std::string m_daemon_address;
    std::string m_wallet_file;
    std::string m_keys_file;
    const std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_client;
    cryptonote::account_public_address m_account_public_address;
     cryptonote::checkpoints m_checkpoints;

    hashchain m_blockchain;
    serializable_unordered_map<crypto::hash, unconfirmed_transfer_out> m_pool_transfer_outs;
     serializable_unordered_map<crypto::hash, pool_transfer_in> m_pool_transfers_in;

    std::vector<transfer_details> m_transfers_in;
    serializable_unordered_map<crypto::key_image, size_t> m_key_images;
    serializable_unordered_map<crypto::public_key, size_t> m_otks;
    serializable_unordered_map<crypto::hash, confirmed_transfer_out> m_confirmed_transfer_outs;

    serializable_unordered_map<crypto::hash, crypto::secret_key> m_tx_secs;
   
    std::atomic<bool> m_run;

    boost::recursive_mutex m_daemon_rpc_mutex;

    cryptonote::network_type m_nettype;
    uint64_t m_kdf_rounds;
    std::string seed_language; /*!< Language of the mnemonics (seed). */
    bool m_always_confirm_transfers;
    uint32_t m_default_mixin;
    bool m_auto_refresh;
    bool m_first_refresh_done;
    uint64_t m_refresh_from_block_height;
    // If m_refresh_from_block_height is explicitly set to zero we need this to differentiate it from the case that
    // m_refresh_from_block_height was defaulted to zero.*/
    bool m_explicit_refresh_from_block_height;
    uint64_t m_max_reorg_depth;
    uint32_t m_inactivity_lock_timeout;
    bool m_is_initialized;
    NodeRPCProxy m_node_rpc_proxy;
    bool m_offline;
    uint32_t m_rpc_version;

    std::unique_ptr<tools::file_locker> m_keys_file_locker;
    
    crypto::chacha_key m_cache_key;
    boost::optional<epee::wipeable_string> m_encrypt_keys_after_refresh;
    boost::mutex m_decrypt_keys_lock;
    unsigned int m_decrypt_keys_lockers;


    static boost::mutex default_daemon_address_lock;
    static std::string default_daemon_address;
  };
}
BOOST_CLASS_VERSION(tools::wallet2, 29)
BOOST_CLASS_VERSION(tools::wallet2::transfer_details, 12)
BOOST_CLASS_VERSION(tools::wallet2::pool_transfer_in, 1)
BOOST_CLASS_VERSION(tools::wallet2::unconfirmed_transfer_out, 8)
BOOST_CLASS_VERSION(tools::wallet2::confirmed_transfer_out, 6)
BOOST_CLASS_VERSION(tools::wallet2::reserve_proof_entry, 0)
BOOST_CLASS_VERSION(tools::wallet2::signed_tx_set, 1)
BOOST_CLASS_VERSION(tools::wallet2::pending_tx, 3)

namespace boost
{
  namespace serialization
  {
     /*
    template <class Archive>
    inline typename std::enable_if<!Archive::is_loading::value, void>::type initialize_transfer_details(Archive &a, tools::wallet2::transfer_details &x, const boost::serialization::version_type ver)
    {
    }
    template <class Archive>
    inline typename std::enable_if<Archive::is_loading::value, void>::type initialize_transfer_details(Archive &a, tools::wallet2::transfer_details &x, const boost::serialization::version_type ver)
    {
       
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet2::transfer_details &x, const boost::serialization::version_type ver)
    {
      a & x.m_block_height;
      a & x.m_global_output_index;
      a & x.m_internal_output_index;
      a & x.m_tx;
     
      a & x.m_key_image;
      
      a & x.m_noise;
      a & x.m_amount;
     
      a & x.m_spent_height;
      a & x.m_spent;
      a & x.m_txid;
    }

  
    template <class Archive>
    inline void serialize(Archive &a, tools::wallet2::unconfirmed_transfer_out &x, const boost::serialization::version_type ver)
    {
      a & x.m_sent_time;
     
      a & x.m_tx;
    
      a & x.m_dst;
      a & x.m_state;
      a & x.m_timestamp;
    }


    template <class Archive>
    inline void serialize(Archive &a, tools::wallet2::confirmed_transfer_out &x, const boost::serialization::version_type ver)
    {
      a & x.m_block_height;
       a & x.m_fee;
      a & x.m_amount;
      a & x.m_addr;
      a & x.m_sent_time;
      a & x.m_unlock_time;
    }

    template <class Archive>
    inline void serialize(Archive& a, tools::wallet2::pool_transfer_in& x, const boost::serialization::version_type ver)
    {
      a & x.m_tx_hash;
      a & x.m_amount;
      a & x.m_block_height;
      a & x.m_unlock_time;
      a & x.m_timestamp;

      a & x.m_fee;
      a & x.m_coinbase;
      a & x.m_double_spend_seen;
    }

   

    template <class Archive>
    inline void serialize(Archive& a, tools::wallet2::reserve_proof_entry& x, const boost::serialization::version_type ver)
    {
      a & x.txid;
      a & x.o_index;
      a & x.shared_secret;
      a & x.key_image;
      a & x.shared_secret_sig;
      a & x.key_image_sig;
    }

   

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet2::signed_tx_set &x, const boost::serialization::version_type ver)
    {
      a & x.ptx;
      a & x.key_images;
      if (ver < 1)
        return;
      a & x.tx_key_images.parent();
    }


    template <class Archive>
    inline void serialize(Archive &a, tools::wallet2::pending_tx &x, const boost::serialization::version_type ver)
    {
      a & x.tx;
      a & x.fee;
      a & x.change_dts;
      a & x.key_images;
      a & x.tx_sec;
      a & x.dst;
      a & x.selected_transfers;
    }
        */
  }
}

namespace tools
{

  namespace detail
  {

   
    //----------------------------------------------------------------------------------------------------
    inline void print_source_entry(const cryptonote::tx_source_entry& src)
    {
      std::string indexes;
      std::for_each(src.decoys.begin(), src.decoys.end(), [&](const cryptonote::tx_source_entry::output_entry& s_e) { indexes += boost::to_string(s_e.first) + " "; });

      LOG_PRINT_L0("amount=" << cryptonote::print_money(src.amount) << ", real_output=" <<src.real_output << ", real_output_in_tx_index=" << src.real_output_in_tx_index << ", indexes: " << indexes);
    }
    //----------------------------------------------------------------------------------------------------
  }

  inline std::string strjoin(const std::vector<size_t> &V, const char *sep)
{
  std::stringstream ss;
  bool first = true;
  for (const auto &v: V)
  {
    if (!first)
      ss << sep;
    ss << std::to_string(v);
    first = false;
  }
  return ss.str();
}
inline std::ostream & operator<<(std::ostream & os, const std::vector<uint8_t> & v){
  for(auto e:v){
    os<<e<<",";
  }
  os<<std::endl;
  return os;
}

template<typename T>
  inline T pop_index(std::vector<T>& vec, size_t idx)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
    CHECK_AND_ASSERT_MES(idx < vec.size(), T(), "idx out of bounds");

    T res = vec[idx];
    if (idx + 1 != vec.size())
    {
      vec[idx] = vec.back();
    }
    vec.resize(vec.size() - 1);

    return res;
  }

  template<typename T>
  inline T pop_random_value(std::vector<T>& vec)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");

    size_t idx = crypto::rand_idx(vec.size());
    return pop_index (vec, idx);
  }

  template<typename T>
 inline T pop_back(std::vector<T>& vec)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");

    T res = vec.back();
    vec.pop_back();
    return res;
  }

  template<typename T>
  inline void pop_if_present(std::vector<T>& vec, T e)
  {
    for (size_t i = 0; i < vec.size(); ++i)
    {
      if (e == vec[i])
      {
        pop_index (vec, i);
        return;
      }
    }
  }


inline bool get_pruned_tx(const cryptonote::COMMAND_RPC_GET_TRANSACTIONS::entry &entry, cryptonote::transaction &tx, crypto::hash &tx_hash)
{
  cryptonote::blobdata bd;

  // easy case if we have the whole tx
  if (!entry.as_hex.empty() || (!entry.prunable_as_hex.empty() && !entry.pruned_as_hex.empty()))
  {
    CHECK_AND_ASSERT_MES(epee::string_tools::parse_hexstr_to_binbuff(entry.as_hex.empty() ? entry.pruned_as_hex + entry.prunable_as_hex : entry.as_hex, bd), false, "Failed to parse tx data");
    CHECK_AND_ASSERT_MES(cryptonote::parse_and_validate_tx_from_blob(bd, tx), false, "Invalid tx data");
    tx_hash = cryptonote::get_transaction_hash(tx);
    // if the hash was given, check it matches
    CHECK_AND_ASSERT_MES(entry.tx_hash.empty() || epee::string_tools::pod_to_hex(tx_hash) == entry.tx_hash, false,
        "Response claims a different hash than the data yields");
    return true;
  }
  // case of a pruned tx with its prunable data hash
  if (!entry.pruned_as_hex.empty() && !entry.prunable_hash.empty())
  {

    CHECK_AND_ASSERT_MES(epee::string_tools::parse_hexstr_to_binbuff(entry.pruned_as_hex, bd), false, "Failed to parse pruned data");
    CHECK_AND_ASSERT_MES(parse_and_validate_tx_base_from_blob(bd, tx), false, "Invalid base tx data");

    crypto::hash ph;
    CHECK_AND_ASSERT_MES(epee::string_tools::hex_to_pod(entry.prunable_hash, ph), false, "Failed to parse prunable hash");

    // only v2 txes can calculate their txid after pruned
    if (bd[0] > 1)
    {
      tx_hash = cryptonote::get_pruned_transaction_hash(tx, ph);
    }
    else
    {
      // for v1, we trust the dameon
      CHECK_AND_ASSERT_MES(epee::string_tools::hex_to_pod(entry.tx_hash, tx_hash), false, "Failed to parse tx hash");
    }
    return true;
  }
  return false;
}
  //----------------------------------------------------------------------------------------------------
}
