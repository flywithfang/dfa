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

#include <ctime>

#include <boost/function.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>

#include "cryptonote_basic/fwd.h"
#include "cryptonote_protocol/cryptonote_protocol.h"
#include "cryptonote_protocol/enums.h"
#include "storages/portable_storage_template_helper.h"
#include "common/download.h"
#include "common/command_line.h"
#include "tx_pool.h"
#include "blockchain.h"
#include "cryptonote_basic/miner.h"
#include "cryptonote_basic/cryptonote_peer_context.h"
#include "warnings.h"
#include "crypto/hash.h"
#include "span.h"
#include "rpc/fwd.h"

PUSH_WARNINGS
DISABLE_VS_WARNINGS(4355)

enum { HAVE_BLOCK_MAIN_CHAIN, HAVE_BLOCK_ALT_CHAIN, HAVE_BLOCK_INVALID };

namespace cryptonote
{
   struct test_options {
     const std::pair<uint8_t, uint64_t> *hard_forks;
     const size_t long_term_block_weight_window;
   };

  extern const command_line::arg_descriptor<std::string, false, true, 2> arg_data_dir;
  extern const command_line::arg_descriptor<bool, false> arg_testnet_on;
  extern const command_line::arg_descriptor<bool, false> arg_stagenet_on;
  extern const command_line::arg_descriptor<bool, false> arg_regtest_on;
  extern const command_line::arg_descriptor<difficulty_type> arg_fixed_difficulty;
  extern const command_line::arg_descriptor<bool> arg_offline;
  extern const command_line::arg_descriptor<size_t> arg_block_download_max_size;
  extern const command_line::arg_descriptor<bool> arg_sync_pruned_blocks;

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/

   /**
    * @brief handles core cryptonote functionality
    *
    * This class coordinates cryptonote functionality including, but not
    * limited to, communication among the Blockchain, the transaction pool,
    * any miners, and the network.
    */
   class core final//: public i_miner_handler
   {
   public:

      /**
       * @brief constructor
       *
       * sets member variables into a usable state
       *
       * @param pprotocol pre-constructed protocol object to store and use
       */
     core();

     /**
      * @brief calls various idle routines
      *
      * @note see miner::on_idle and tx_memory_pool::on_idle
      *
      * @return true
      */
     bool on_idle();

     /**
      * @brief handles an incoming transaction
      *
      * Parses an incoming transaction and, if nothing is obviously wrong,
      * passes it along to the transaction pool
      *
      * @param tx_blob the tx to handle
      * @param tvc metadata about the transaction's validity
      * @param tx_relay how the transaction was received
      * @param relayed whether or not the transaction was relayed to us
      *
      * @return true if the transaction was accepted, false otherwise
      */
     tx_verification_context handle_incoming_tx(const tx_blob_entry& tx_blob, relay_method tx_relay, bool relayed);

     /**
      * @brief handles a list of incoming transactions
      *
      * Parses incoming transactions and, if nothing is obviously wrong,
      * passes them along to the transaction pool
      *
      * @pre `tx_blobs.size() == tvc.size()`
      *
      * @param tx_blobs the txs to handle
      * @param tvc metadata about the transactions' validity
      * @param tx_relay how the transaction was received.
      * @param relayed whether or not the transactions were relayed to us
      *
      * @return true if the transactions were accepted, false otherwise
      */
     bool handle_incoming_txs(epee::span<const tx_blob_entry> tx_blobs, epee::span<tx_verification_context> tvc, relay_method tx_relay, bool relayed);

     /**
      * @brief handles a list of incoming transactions
      *
      * Parses incoming transactions and, if nothing is obviously wrong,
      * passes them along to the transaction pool
      *
      * @param tx_blobs the txs to handle
      * @param tvc metadata about the transactions' validity
      * @param tx_relay how the transaction was received.
      * @param relayed whether or not the transactions were relayed to us
      *
      * @return true if the transactions were accepted, false otherwise
      */
     bool handle_incoming_txs(const std::vector<tx_blob_entry>& tx_blobs, std::vector<tx_verification_context>& tvc, relay_method tx_relay, bool relayed)
     {
       tvc.resize(tx_blobs.size());
       return handle_incoming_txs(epee::to_span(tx_blobs), epee::to_mut_span(tvc), tx_relay, relayed);
     }


     /**
      * @brief called when a transaction is relayed.
      * @note Should only be invoked from `levin_notify`.
      */
     virtual void on_transactions_relayed(epee::span<const cryptonote::blobdata> tx_blobs, relay_method tx_relay) final;

     /**
      * @brief adds command line options to the given options set
      *
      * As of now, there are no command line options specific to core,
      * so this function simply returns.
      *
      * @param desc return-by-reference the command line options set to add to
      */
     static void init_options(boost::program_options::options_description& desc);

     /**
      * @brief initializes the core as needed
      *
      * This function initializes the transaction pool, the Blockchain, and
      * a miner instance with parameters given on the command line (or defaults)
      *
      * @param vm command line parameters
      * @param test_options configuration options for testing
      * @param get_checkpoints if set, will be called to get checkpoints data, must return checkpoints data pointer and size or nullptr if there ain't any checkpoints for specific network type
      *
      * @return false if one of the init steps fails, otherwise true
      */
     bool init(const boost::program_options::variables_map& vm, const test_options *test_options = NULL, const GetCheckpointsCallback& get_checkpoints = nullptr);

    
     /**
      * @brief performs safe shutdown steps for core and core components
      *
      * Uninitializes the miner instance, transaction pool, and Blockchain
      *
      * @return true
      */
     bool deinit();

     /**
      * @brief sets to drop blocks downloaded (for testing)
      */
     void test_drop_download();

     /**
      * @brief sets to drop blocks downloaded below a certain height
      *
      * @param height height below which to drop blocks
      */
     void test_drop_download_height(uint64_t height);

     /**
      * @brief gets whether or not to drop blocks (for testing)
      *
      * @return whether or not to drop blocks
      */
     bool get_test_drop_download() const;

     /**
      * @brief gets whether or not to drop blocks
      *
      * If the current blockchain height <= our block drop threshold
      * and test drop blocks is set, return true
      *
      * @return see above
      */
     bool get_test_drop_download_height() const;

     /**
      * @copydoc Blockchain::get_chain_height
      *
      * @note see Blockchain::get_chain_height()
      */
     uint64_t get_chain_height() const ;

     /**
      * @brief get the hash and height of the most recent block
      *
      * @param height return-by-reference height of the block
      * @param top_id return-by-reference hash of the block
      */
     void get_blockchain_top(uint64_t& height, crypto::hash& top_id) const;
     std::tuple<uint64_t, crypto::hash>  get_blockchain_top() const;

  

     /**
      * @copydoc Blockchain::get_block_hash_by_height
      *
      * @note see Blockchain::get_block_hash_by_height
      */
     crypto::hash get_block_hash_by_height(uint64_t height) const;

/**
     * @brief creates a new block to mine against
     *
     * @param b return-by-reference block to be filled in
     * @param from_block optional block hash to start mining from (main chain tip if NULL)
     * @param miner_address address new coins for the block will go to
     * @param di return-by-reference tells the miner what the difficulty target is
     * @param height return-by-reference tells the miner what height it's mining against
     * @param expected_reward return-by-reference the total reward awarded to the miner finding this block, including transaction fees
     * @param ex_nonce extra data to be added to the miner transaction's extra
     *
     * @return true if block template filled in successfully, else false
     */

    cryptonote::BlockTemplate create_block_template( const account_public_address& miner_address, const blobdata& ex_nonc);

    
    /**
     * @brief adds a block to the blockchain
     *
     * Adds a new block to the blockchain.  If the block's parent is not the
     * current top of the blockchain, the block may be added to an alternate
     * chain.  If the block does not belong, is already in the blockchain
     * or an alternate chain, or is invalid, return false.
     *
     * @param bl_ the block to be added
     * @param bvc metadata about the block addition's success/failure
     *
     * @return true on successful addition to the blockchain, else false
     */
    bool add_new_block(const block& bl_, block_verification_context& bvc);

    block_verification_context add_sync_block(const block& bl_, std::vector<std::pair<transaction, blobdata>> &txs );


     /**
      * @copydoc Blockchain::get_block_by_hash
      *
      * @note see Blockchain::get_block_by_hash
      */
     bool get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan = NULL) const;

     /**
      * @copydoc Blockchain::get_alternative_blocks
      *
      * @note see Blockchain::get_alternative_blocks(std::vector<block>&) const
      */
     bool get_alternative_blocks(std::vector<block>& blocks) const;

     /**
      * @copydoc Blockchain::get_alternative_blocks_count
      *
      * @note see Blockchain::get_alternative_blocks_count() const
      */
     size_t get_alternative_blocks_count() const;

     /**
      * @brief set the file path to read from when loading checkpoints
      *
      * @param path the path to set ours as
      */
     void set_checkpoints_file_path(const std::string& path);

     /**
      * @brief set whether or not to enable or disable DNS checkpoints
      *
      * @param disble whether to disable DNS checkpoints
      */
     void disable_dns_checkpoints(bool disable = true) { m_disable_dns_checkpoints = disable; }

     /**
      * @copydoc tx_memory_pool::have_tx
      *
      * @note see tx_memory_pool::have_tx
      */
     bool pool_has_tx(const crypto::hash &txid) const;

     bool pool_has_key_image(const crypto::key_image & ki)const;

     /**
      * @copydoc tx_memory_pool::get_transactions
      * @param include_sensitive_txes include private transactions
      *
      * @note see tx_memory_pool::get_transactions
      */
     bool get_pool_transactions(std::vector<transaction>& txs, bool include_sensitive_txes = false) const;

     std::vector<std::tuple<crypto::hash, cryptonote::blobdata, relay_method>> get_relayable_transactions();
   
     
     /**
      * @copydoc tx_memory_pool::get_transactions
      * @param include_sensitive_txes include private transactions
      *
      * @note see tx_memory_pool::get_transactions
      */
     bool get_pool_transaction_hashes(std::vector<crypto::hash>& txs, bool include_sensitive_txes = false) const;

     /**
      * @copydoc tx_memory_pool::get_transactions
      * @param include_sensitive_txes include private transactions
      *
      * @note see tx_memory_pool::get_transactions
      */
     bool get_pool_transaction_stats(struct txpool_stats& stats, bool include_sensitive_txes = false) const;



     /**
      * @copydoc tx_memory_pool::get_pool_transactions
      * @param include_sensitive_txes include private transactions
      *
      * @note see tx_memory_pool::get_pool_transactions
      */
     bool get_pool_transactions(std::vector<tx_info>& tx_infos, bool include_sensitive_txes = false) const;

     /**
      * @copydoc tx_memory_pool::get_transactions_count
      * @param include_sensitive_txes include private transactions
      *
      * @note see tx_memory_pool::get_transactions_count
      */
     size_t get_pool_transactions_count(bool include_sensitive_txes = false) const;

     /**
      * @copydoc Blockchain::get_total_transactions
      *
      * @note see Blockchain::get_total_transactions
      */
     size_t get_blockchain_total_transactions() const;

     /**
      * @copydoc Blockchain::have_block
      *
      * @note see Blockchain::have_block
      */
     bool have_block_unlocked(const crypto::hash& id, int *where = NULL) const;
     bool have_block(const crypto::hash& id, int *where = NULL) const;

 
     /**
      * @copydoc Blockchain::get_top_hash
      *
      * @note see Blockchain::get_top_hash
      */
     crypto::hash get_top_hash() const;

   

     /**
      * @copydoc Blockchain::get_block_cumulative_difficulty
      *
      * @note see Blockchain::get_block_cumulative_difficulty
      */
     difficulty_type get_block_cumulative_difficulty(uint64_t height) const;


     /**
      * @brief gets the Blockchain instance
      *
      * @return a reference to the Blockchain instance
      */
     Blockchain& get_blockchain(){return m_blockchain;}

   /**
     * @brief returns a set of known alternate chains
     *
     * @return a vector of chains
     */
    std::vector<std::pair<block_extended_info,std::vector<crypto::hash>>> get_alternative_chains() const;

     /**
      * @brief gets the Blockchain instance (const)
      *
      * @return a const reference to the Blockchain instance
      */
     const Blockchain& get_blockchain()const{return m_blockchain;}

     const tx_memory_pool& get_tx_pool()const{return m_tx_pool;}


     /**
      * @brief sets the target blockchain height
      *
      * @param target_blockchain_height the height to set
      */
     void set_target_blockchain_height(uint64_t target_blockchain_height);

     /**
      * @brief gets the target blockchain height
      *
      * @param target_blockchain_height the target height
      */
     uint64_t get_target_blockchain_height() const;

     /**
      * @brief returns the newest hardfork version known to the blockchain
      *
      * @return the version
      */
     uint8_t get_ideal_hard_fork_version() const;

     /**
      * @brief return the ideal hard fork version for a given block height
      *
      * @return what it says above
      */
     uint8_t get_ideal_hard_fork_version(uint64_t height) const;

     /**
      * @brief return the hard fork version for a given block height
      *
      * @return what it says above
      */
     uint8_t get_hard_fork_version(uint64_t height) const;

     /**
      * @brief return the earliest block a given version may activate
      *
      * @return what it says above
      */
     uint64_t get_earliest_ideal_height_for_version(uint8_t version) const;

     /**
      * @brief gets start_time
      *
      */
     std::time_t get_start_time() const;

     /**
      * @brief tells the Blockchain to update its checkpoints
      *
      * This function will check if enough time has passed since the last
      * time checkpoints were updated and tell the Blockchain to update
      * its checkpoints if it is time.  If updating checkpoints fails,
      * the daemon is told to shut down.
      *
      * @note see Blockchain::update_checkpoints()
      */
     bool update_checkpoints(const bool skip_dns = false);

     /**
      * @brief tells the daemon to wind down operations and stop running
      *
      * Currently this function raises SIGTERM, allowing the installed signal
      * handlers to do the actual stopping.
      */
     void graceful_exit();

     /**
      * @brief stops the daemon running
      *
      * @note see graceful_exit()
      */
     void stop();

     /**
      * @copydoc Blockchain::have_tx_keyimg_as_spent
      *
      * @note see Blockchain::have_tx_keyimg_as_spent
      */
     bool is_key_image_spent(const crypto::key_image& key_im) const;

     /**
      * @brief check if multiple key images are spent
      *
      * plural version of is_key_image_spent()
      *
      * @param key_im list of key images to check
      * @param spent return-by-reference result for each image checked
      *
      * @return true
      */
     bool are_key_images_spent(const std::vector<crypto::key_image>& key_im, std::vector<bool> &spent) const;


     /**
      * @brief get the number of blocks to sync in one go
      *
      * @return the number of blocks to sync in one go
      */
     size_t get_block_sync_batch_size() const;

     /**
      * @brief get the sum of coinbase tx amounts between blocks
      *
      * @return the number of blocks to sync in one go
      */
     std::pair<boost::multiprecision::uint128_t, boost::multiprecision::uint128_t> get_coinbase_tx_sum(const uint64_t start_offset, const size_t count);
     
     /**
      * @brief get the network type we're on
      *
      * @return which network are we on?
      */     
     network_type get_nettype() const { return m_nettype; };

     /**
      * @brief check whether an update is known to be available or not
      *
      * This does not actually trigger a check, but returns the result
      * of the last check
      *
      * @return whether an update is known to be available or not
      */
     bool is_update_available() const { return m_update_available; }

  
     /**
      * @brief get free disk space on the blockchain partition
      *
      * @return free space in bytes
      */
     uint64_t get_free_space() const;

     /**
      * @brief get whether the core is running offline
      *
      * @return whether the core is running offline
      */
     bool offline() const { return m_offline; }

     /**
      * @brief get the blockchain pruning seed
      *
      * @return the blockchain pruning seed
      */
     uint32_t get_blockchain_pruning_seed() const;

     /**
      * @brief prune the blockchain
      *
      * @param pruning_seed the seed to use to prune the chain (0 for default, highly recommended)
      *
      * @return true iff success
      */
     bool prune_blockchain(uint32_t pruning_seed = 0);

     /**
      * @brief incrementally prunes blockchain
      *
      * @return true on success, false otherwise
      */
     bool update_blockchain_pruning();

     /**
      * @brief checks the blockchain pruning if enabled
      *
      * @return true on success, false otherwise
      */
     bool check_blockchain_pruning();


   private:

  

     /**
      * @brief load any core state stored on disk
      *
      * currently does nothing, but may have state to load in the future.
      *
      * @return true
      */
     bool load_state_data();

     /**
      * @copydoc parse_tx_from_blob(transaction&, crypto::hash&, crypto::hash&, const blobdata&) const
      *
      * @note see parse_tx_from_blob(transaction&, crypto::hash&, crypto::hash&, const blobdata&) const
      */
     bool parse_tx_from_blob(transaction& tx, crypto::hash& tx_hash, const blobdata& blob) const;

     /**
      * @brief act on a set of command line options given
      *
      * @param vm the command line options
      *
      * @return true
      */
     bool handle_command_line(const boost::program_options::variables_map& vm);

     /**
      * @brief checks DNS versions
      *
      * @return true on success, false otherwise
      */
     bool check_updates();

     /**
      * @brief checks free disk space
      *
      * @return true on success, false otherwise
      */
     bool check_disk_space();

  /**
     * @brief reverts the blockchain to its previous state following a failed switch
     *
     * If Blockchain fails to switch to an alternate chain when it means
     * to do so, this function reverts the blockchain to how it was before
     * the attempted switch.
     *
     * @param original_chain the chain to switch back to
     * @param rollback_height the height to revert to before appending the original chain
     *
     * @return false if something goes wrong with reverting (very bad), otherwise true
     */
    void rollback_blockchain_switching(ChainSection & sect, uint64_t rollback_height);

    /**
     * @brief performs a blockchain reorganization according to the longest chain rule
     *
     * This function aggregates all the actions necessary to switch to a
     * newly-longer chain.  If any step in the reorganization process fails,
     * the blockchain is reverted to its previous state.
     *
     * @param alt_chain the chain to switch to
     * @param discard_disconnected_chain whether or not to keep the old chain as an alternate
     *
     * @return false if the reorganization fails, otherwise true
     */
    bool switch_to_alternative_blockchain(AltChain & altChain);

 /**
     * @brief validate and add a new block to the end of the blockchain
     *
     * This function is merely a convenience wrapper around the other
     * of the same name.  This one passes the block's hash to the other
     * as well as the block and verification context.
     *
     * @param bl the block to be added
     * @param bvc metadata concerning the block's validity
     * @param notify if set to true, sends new block notification on success
     *
     * @return true if the block was added successfully, otherwise false
     */
    bool handle_block_to_main_chain(const block& bl, block_verification_context& bvc, bool notify = true);
  
    /**
     * @brief sets a block notify object to call for every new block
     *
     * @param notify the notify object to call at every new block
     */
    void add_block_notify(boost::function<void(std::uint64_t, epee::span<const block>)> &&notify);

    /**
     * @brief sets a reorg notify object to call for every reorg
     *
     * @param notify the notify object to call at every reorg
     */
    void set_reorg_notify(const std::shared_ptr<tools::Notify> &notify) { m_reorg_notify = notify; }
    void return_tx_to_pool(std::vector<std::pair<transaction, blobdata>> &txs);

     bool m_test_drop_download = true; //!< whether or not to drop incoming blocks (for testing)

     uint64_t m_test_drop_download_height = 0; //!< height under which to drop incoming blocks, if doing so

     tx_memory_pool m_tx_pool; //!< transaction pool instance
     Blockchain m_blockchain; //!< Blockchain instance
     std::unique_ptr<BlockchainDB> m_db;

     epee::critical_section m_incoming_tx_lock; //!< incoming transaction lock

     std::string m_config_folder; //!< folder to look in for configs and other files


     epee::math_helper::once_a_time_seconds<60*60*2, true> m_fork_moaner; //!< interval for checking HardFork status
     epee::math_helper::once_a_time_seconds<60*60*12, true> m_check_updates_interval; //!< interval for checking for new versions
     epee::math_helper::once_a_time_seconds<60*10, true> m_check_disk_space_interval; //!< interval for checking for disk space
 
     epee::math_helper::once_a_time_seconds<60*60*5, true> m_blockchain_pruning_interval; //!< interval for incremental blockchain pruning

     std::atomic<bool> m_starter_message_showed; //!< has the "daemon will sync now" message been shown?

     uint64_t m_target_blockchain_height; //!< blockchain height target

     network_type m_nettype; //!< which network are we on?

     std::atomic<bool> m_update_available;

     std::string m_checkpoints_path; //!< path to json checkpoints file
     time_t m_last_dns_checkpoints_update; //!< time when dns checkpoints were last updated
     time_t m_last_json_checkpoints_update; //!< time when json checkpoints were last updated

     std::atomic_flag m_checkpoints_updating; //!< set if checkpoints are currently updating to avoid multiple threads attempting to update at once
     bool m_disable_dns_checkpoints;

     size_t m_block_sync_size;

     time_t start_time;


    /* `boost::function` is used because the implementation never allocates if
       the callable object has a single `std::shared_ptr` or `std::weap_ptr`
       internally. Whereas, the libstdc++ `std::function` will allocate. */

    std::vector<boost::function<void(std::uint64_t, epee::span<const block>)>> m_block_notifiers;
    std::shared_ptr<tools::Notify> m_reorg_notify;

     enum {
       UPDATES_DISABLED,
       UPDATES_NOTIFY,
       UPDATES_DOWNLOAD,
       UPDATES_UPDATE,
     } check_updates_level;

     tools::download_async_handle m_update_download;
     size_t m_last_update_length;
     boost::mutex m_update_mutex;

     bool m_offline;

   };
}

POP_WARNINGS
