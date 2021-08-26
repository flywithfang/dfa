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
#include <boost/asio/io_service.hpp>
#include <boost/function/function_fwd.hpp>
#if BOOST_VERSION >= 107400
#include <boost/serialization/library_version_type.hpp>
#endif
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/version.hpp>
#include <boost/serialization/list.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/global_fun.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <atomic>
#include <functional>
#include <unordered_map>
#include <unordered_set>

#include "span.h"
#include "syncobj.h"
#include "string_tools.h"
#include "rolling_median.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "common/powerof.h"
#include "common/util.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_basic/verification_context.h"
#include "crypto/hash.h"
#include "checkpoints/checkpoints.h"
#include "cryptonote_basic/hardfork.h"
#include "blockchain_db/blockchain_db.h"

namespace tools { class Notify; }

namespace cryptonote
{
  class tx_memory_pool;
  struct test_options;


  
  /** 
   * @brief Callback routine that returns checkpoints data for specific network type
   * 
   * @param network network type
   * 
   * @return checkpoints data, empty span if there ain't any checkpoints for specific network type
   */
  typedef std::function<const epee::span<const unsigned char>(cryptonote::network_type network)> GetCheckpointsCallback;

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class Blockchain
  {
  public:
    /**
     * @brief container for passing a block and metadata about it on the blockchain
     */
    struct block_extended_info
    {
      block   bl; //!< the block
      uint64_t height; //!< the height of the block in the blockchain
      uint64_t block_cumulative_weight; //!< the weight of the block
      difficulty_type cum_diff; //!< the accumulated difficulty after that block
      uint64_t already_generated_coins; //!< the total coins minted after that block
    };

    /**
     * @brief Blockchain constructor
     *
     * @param tx_pool a reference to the transaction pool to be kept by the Blockchain
     */
    Blockchain(tx_memory_pool& tx_pool);

    /**
     * @brief Blockchain destructor
     */
    ~Blockchain();

    /**
     * @brief Initialize the Blockchain state
     *
     * @param db a pointer to the backing store to use for the blockchain
     * @param nettype network type
     * @param offline true if running offline, else false
     * @param test_options test parameters
     * @param fixed_difficulty fixed difficulty for testing purposes; 0 means disabled
     * @param get_checkpoints if set, will be called to get checkpoints data
     *
     * @return true on success, false if any initialization steps fail
     */
    bool init(BlockchainDB* db, const network_type nettype = MAINNET, bool offline = false, const cryptonote::test_options *test_options = NULL,  const GetCheckpointsCallback& get_checkpoints = nullptr);

    /**
     * @brief Initialize the Blockchain state
     *
     * @param db a pointer to the backing store to use for the blockchain
     * @param hf a structure containing hardfork information
     * @param nettype network type
     * @param offline true if running offline, else false
     *
     * @return true on success, false if any initialization steps fail
     */
    bool init(BlockchainDB* db, HardFork*& hf, const network_type nettype = MAINNET, bool offline = false);

    /**
     * @brief Uninitializes the blockchain state
     *
     * Saves to disk any state that needs to be maintained
     *
     * @return true on success, false if any uninitialization steps fail
     */
    bool deinit();

   
    /**
     * @brief get blocks from blocks based on start height and count
     *
     * @param start_offset the height on the blockchain to start at
     * @param count the number of blocks to get, if there are as many after start_offset
     * @param blocks return-by-reference container to put result blocks in
     *
     * @return false if start_offset > blockchain height, else true
     */
    bool get_blocks(uint64_t start_offset, size_t count, std::vector<BlobBlock>& blocks) const;


    /**
     * @brief gets a block's hash given a height
     *
     * @param height the height of the block
     *
     * @return the hash of the block at the requested height, or a zeroed hash if there is no such block
     */
    crypto::hash get_block_hash_by_height(uint64_t height) const;

    /**
     * @brief gets the block with a given hash
     *
     * @param h the hash to look for
     * @param blk return-by-reference variable to put result block in
     * @param orphan if non-NULL, will be set to true if not in the main chain, false otherwise
     *
     * @return true if the block was found, else false
     */
    bool get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan = NULL) const;


    /**
     * @brief search the blockchain for a transaction by hash
     *
     * @param id the hash to search for
     *
     * @return true if the tx exists, else false
     */
    bool have_tx(const crypto::hash &id) const;

    /**
     * @brief check if any key image in a transaction has already been spent
     *
     * @param tx the transaction to check
     *
     * @return true if any key image is already spent in the blockchain, else false
     */
    bool have_tx_keyimges_as_spent(const transaction &tx) const;

    /**
     * @brief check if a key image is already spent on the blockchain
     *
     * Whenever a transaction output is used as an input for another transaction
     * (a true input, not just one of a mixing set), a key image is generated
     * and stored in the transaction in order to prevent double spending.  If
     * this key image is seen again, the transaction using it is rejected.
     *
     * @param key_im the key image to search for
     *
     * @return true if the key image is already spent in the blockchain, else false
     */
    bool have_tx_keyimg_as_spent(const crypto::key_image &key_im) const;

    /**
     * @brief get the current height of the blockchain
     *
     * @return the height
     */
    uint64_t get_chain_height() const;

    /**
     * @brief get the hash of the most recent block on the blockchain
     *
     * @return the hash
     */
    crypto::hash get_top_hash() const;

    /**
     * @brief get the height and hash of the most recent block on the blockchain
     *
     * @param height return-by-reference variable to store the height in
     *
     * @return the hash
     */
    crypto::hash get_top_hash(uint64_t& height) const;
    
    std::tuple<crypto::hash,uint64_t> get_top_block_hash()const;


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
     * @brief checks if a block is known about with a given hash
     *
     * This function checks the main chain, alternate chains, and invalid blocks
     * for a block with the given hash
     *
     * @param id the hash to search for
     * @param where the type of block, if non NULL
     *
     * @return true if the block is known, else false
     */
    bool have_block_unlocked(const crypto::hash& id, int *where = NULL) const;
    bool have_block(const crypto::hash& id, int *where = NULL) const;

    /**
     * @brief gets the total number of transactions on the main chain
     *
     * @return the number of transactions on the main chain
     */
    size_t get_total_transactions() const;

    /**
     * @brief gets the hashes for a subset of the blockchain
     *
     * puts into list <ids> a list of hashes representing certain blocks
     * from the blockchain in reverse chronological order
     *
     * the blocks chosen, at the time of this writing, are:
     *   the most recent 11
     *   powers of 2 less recent from there, so 13, 17, 25, etc...
     *
     * @param ids return-by-reference list to put the resulting hashes in
     *
     * @return true
     */
    std::list<crypto::hash> get_short_chain_history() const;

    /**
     * @brief get recent block hashes for a foreign chain
     *
     * Find the split point between us and foreign blockchain and return
     * (by reference) the most recent common block hash along with up to
     * BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT additional (more recent) hashes.
     *
     * @param qblock_ids the foreign chain's "short history" (see get_short_chain_history)
     * @param hashes the hashes to be returned, return-by-reference
     * @param weights the block weights to be returned, return-by-reference
     * @param start_height the start height, return-by-reference
     * @param current_height the current blockchain height, return-by-reference
     * @param clip_pruned whether to constrain results to unpruned data
     *
     * @return true if a block found in common, else false
     */
  ChainSyncInfo find_blockchain_sync_info(const std::list<crypto::hash>& remote) const

  
    /**
     * @brief find the most recent common point between ours and a foreign chain
     *
     * This function takes a list of block hashes from another node
     * on the network to find where the split point is between us and them.
     * This is used to see what to send another node that needs to sync.
     *
     * @param qblock_ids the foreign chain's "short history" (see get_short_chain_history)
     * @param starter_offset return-by-reference the most recent common block's height
     *
     * @return true if a block found in common, else false
     */
    uint64_t find_blockchain_split_height(const std::list<crypto::hash>& qblock_ids) const;



    /**
     * @brief gets specific outputs to mix with
     *
     * This function takes an RPC request for outputs to mix with
     * and creates an RPC response with the resultant output indices.
     *
     * Outputs to mix with are specified in the request.
     *
     * @param req the outputs to return
     * @param res return-by-reference the resultant output indices and keys
     *
     * @return true
     */
    bool get_outs(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res) const;




    /**
     * @brief gets the difficulty of the block with a given height
     *
     * @param i the height
     *
     * @return the difficulty
     */
    difficulty_type block_difficulty(uint64_t i) const;

   
    /**
     * @brief gets transactions based on a list of transaction hashes
     *
     * @tparam t_ids_container a standard-iterable container
     * @tparam t_tx_container a standard-iterable container
     * @tparam t_missed_container a standard-iterable container
     * @param txs_ids a container of hashes for which to get the corresponding transactions
     * @param txs return-by-reference a container to store result transactions in
     * @param missed_txs return-by-reference a container to store missed transactions in
     * @param pruned whether to return full or pruned blobs
     *
     * @return false if an unexpected exception occurs, else true
     */
    std::vector<tx_blob_pruned_entry> get_pruned_transactions_blobs(const std::vector<crypto::hash>& txs_ids) const;
     std::vector<tx_blob_entry> get_transactions_blobs(const std::vector<crypto::hash>& txs_ids) const;

    //debug functions

  
    /**
     * @brief configure whether or not to enforce DNS-based checkpoints
     *
     * @param enforce the new enforcement setting
     */
    void set_enforce_dns_checkpoints(bool enforce);


    // user options, must be called before calling init()


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

 
    /**
     * @brief set whether or not to show/print time statistics
     *
     * @param stats the new time stats setting
     */
    void set_show_time_stats(bool stats) { m_show_time_stats = stats; }

    /**
     * @brief gets the hardfork voting state object
     *
     * @return the HardFork object
     */
    HardFork::State get_hard_fork_state() const;

    /**
     * @brief gets the current hardfork version in use/voted for
     *
     * @return the version
     */
    uint8_t get_current_hard_fork_version() const { return m_hardfork->get_current_version(); }

    /**
     * @brief returns the newest hardfork version known to the blockchain
     *
     * @return the version
     */
    uint8_t get_ideal_hard_fork_version() const { return m_hardfork->get_ideal_version(); }

    /**
     * @brief returns the next hardfork version
     *
     * @return the version
     */
    uint8_t get_next_hard_fork_version() const { return m_hardfork->get_next_version(); }

    /**
     * @brief returns the newest hardfork version voted to be enabled
     * as of a certain height
     *
     * @param height the height for which to check version info
     *
     * @return the version
     */
    uint8_t get_ideal_hard_fork_version(uint64_t height) const { return m_hardfork->get_ideal_version(height); }

    /**
     * @brief returns the actual hardfork version for a given block height
     *
     * @param height the height for which to check version info
     *
     * @return the version
     */
    uint8_t get_hard_fork_version(uint64_t height) const { return m_hardfork->get(height); }

    /**
     * @brief returns the earliest block a given version may activate
     *
     * @return the height
     */
    uint64_t get_earliest_ideal_height_for_version(uint8_t version) const { return m_hardfork->get_earliest_ideal_height_for_version(version); }

    /**
     * @brief get information about hardfork voting for a version
     *
     * @param version the version in question
     * @param window the size of the voting window
     * @param votes the number of votes to enable <version>
     * @param threshold the number of votes required to enable <version>
     * @param earliest_height the earliest height at which <version> is allowed
     * @param voting which version this node is voting for/using
     *
     * @return whether the version queried is enabled 
     */
    bool get_hard_fork_voting_info(uint8_t version, uint32_t &window, uint32_t &votes, uint32_t &threshold, uint64_t &earliest_height, uint8_t &voting) const;



    /**
     * @brief perform a check on all key images in the blockchain
     *
     * @param std::function the check to perform, pass/fail
     *
     * @return false if any key image fails the check, otherwise true
     */
    bool for_all_key_images(std::function<bool(const crypto::key_image&)>) const;

    /**
     * @brief perform a check on all blocks in the blockchain in the given range
     *
     * @param h1 the start height
     * @param h2 the end height
     * @param std::function the check to perform, pass/fail
     *
     * @return false if any block fails the check, otherwise true
     */
    bool for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const crypto::hash&, const block&)>) const;

    /**
     * @brief perform a check on all transactions in the blockchain
     *
     * @param std::function the check to perform, pass/fail
     * @param bool pruned whether to return pruned txes only
     *
     * @return false if any transaction fails the check, otherwise true
     */
    bool for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)>) const;


    /**
     * @brief perform a check on all outputs of a given amount in the blockchain
     *
     * @param amount the amount to iterate through
     * @param std::function the check to perform, pass/fail
     *
     * @return false if any output fails the check, otherwise true
     */
    bool for_all_outputs(  const uint64_t start_height,std::function<bool(uint64_t,const output_data_t&)> f) const;

    /**
     * @brief get a reference to the BlockchainDB in use by Blockchain
     *
     * @return a reference to the BlockchainDB instance
     */
    const BlockchainDB& get_db() const
    {
      return *m_db;
    }

    /**
     * @brief get a reference to the BlockchainDB in use by Blockchain
     *
     * @return a reference to the BlockchainDB instance
     */
    BlockchainDB& get_db()
    {
      return *m_db;
    }

   
 

    bool txpool_tx_matches_category(const crypto::hash& tx_hash, relay_category category);

   
    uint32_t get_blockchain_pruning_seed() const { return m_db->get_blockchain_pruning_seed(); }
    bool prune_blockchain(uint32_t pruning_seed = 0);
    bool update_blockchain_pruning();
    bool check_blockchain_pruning();

    void lock();
    void unlock();

    uint64_t get_block_timestamp(const uint64_t& height) const;
    uint64_t get_block_already_generated_coins(uint64_t height) const;
   

    difficulty_type get_block_cumulative_difficulty(uint64_t height) const;
  


 /**
     * @brief validate a transaction's inputs and their keys
     *
     * This function validates transaction inputs and their keys.  Previously
     * it also performed double spend checking, but that has been moved to its
     * own function.
     * The transaction's rct signatures, if any, are expanded.
     *
     * If pmax_related_block_height is not NULL, its value is set to the height
     * of the most recent block which contains an output used in any input set
     *
     * Currently this function calls ring signature validation for each
     * transaction.
     *
     * @param tx the transaction to validate
     * @param tvc returned information about tx verification
     * @param pmax_related_block_height return-by-pointer the height of the most recent block in the input set
     *
     * @return false if any validation step fails, otherwise true
     */
    bool check_tx_inputs(transaction& tx, tx_verification_context &tvc) const;
#ifndef IN_UNIT_TESTS
  private:
#endif
       // TODO: evaluate whether or not each of these typedefs are left over from blockchain_storage
    typedef std::unordered_set<crypto::key_image> key_images_container;

    typedef std::unordered_map<crypto::hash, block_extended_info> blocks_ext_by_hash;


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
    bool switch_to_alternative_blockchain(std::list<block_extended_info>& alt_chain, bool discard_disconnected_chain);

    /**
     * @brief removes the most recent block from the blockchain
     *
     * @return the block removed
     */
    block pop_block_from_blockchain();

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

    block_verification_context validate_block(const block &b);
    
    /**
     * @brief validate and add a new block to an alternate blockchain
     *
     * If a block to be added does not belong to the main chain, but there
     * is an alternate chain to which it should be added, that is handled
     * here.
     *
     * @param b the block to be added
     * @param id the hash of the block
     * @param bvc metadata concerning the block's validity
     *
     * @return true if the block was added successfully, otherwise false
     */
    bool handle_alternative_block(const block& b, block_verification_context& bvc);

    /**
     * @brief builds a list of blocks connecting a block to the main chain
     *
     * @param prev_id the block hash of the tip of the alt chain
     * @param alt_chain the chain to be added to
     * @param timestamps returns the timestamps of previous blocks
     * @param bvc the block verification context for error return
     *
     * @return true on success, false otherwise
     */
    bool build_alt_chain(const crypto::hash &prev_id, std::list<block_extended_info>& alt_chain, std::vector<uint64_t> &timestamps, block_verification_context& bvc) const;

    /**
     * @brief gets the difficulty requirement for a new block on an alternate chain
     *
     * @param alt_chain the chain to be added to
     * @param bei the block being added (and metadata, see ::block_extended_info)
     *
     * @return the difficulty requirement
     */
    difficulty_type get_next_difficulty_for_alternative_chain(const std::list<block_extended_info>& alt_chain, block_extended_info& bei) const;

    /**
     * @brief validates a miner (coinbase) transaction
     *
     * This function makes sure that the miner calculated his reward correctly
     * and that his miner transaction totals reward + fee.
     *
     * @param b the block containing the miner transaction to be validated
     * @param cumulative_block_weight the block's weight
     * @param fee the total fees collected in the block
     * @param base_reward return-by-reference the new block's generated coins
     * @param already_generated_coins the amount of currency generated prior to this block
     * @param partial_block_reward return-by-reference true if miner accepted only partial reward
     * @param version hard fork version for that transaction
     *
     * @return false if anything is found wrong with the miner transaction, otherwise true
     */
    bool validate_miner_transaction(const block& b,  uint64_t fee, uint64_t& base_reward, uint8_t version);

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
    bool rollback_blockchain_switching(std::list<block>& original_chain, uint64_t rollback_height);


    /**
     * @brief gets block long term weight median
     *
     * get the block long term weight median of <count> blocks starting at <start_height>
     *
     * @param start_height the block height of the first block to query
     * @param count the number of blocks to get weights for
     *
     * @return the long term median block weight
     */
    uint64_t get_long_term_block_weight_median(uint64_t start_height, size_t count) const;

    /**
     * @brief checks if a transaction is unlocked (its outputs spendable)
     *
     * This function checks to see if a transaction is unlocked.
     * unlock_time is either a block index or a unix time.
     *
     * @param unlock_time the unlock parameter (height or time)
     * @param hf_version the consensus rules version to use
     *
     * @return true if spendable, otherwise false
     */
    bool is_tx_spendtime_unlocked(uint64_t unlock_time, uint8_t hf_version) const;


    void return_tx_to_pool(std::vector<std::pair<transaction, blobdata>> &txs);


    /**
     * @brief loads block hashes from compiled-in data set
     *
     * A (possibly empty) set of block hashes can be compiled into the
     * monero daemon binary.  This function loads those hashes into
     * a useful state.
     * 
     * @param get_checkpoints if set, will be called to get checkpoints data
     */
    void load_compiled_in_block_hashes(const GetCheckpointsCallback& get_checkpoints);


    /**
     * @brief stores a new cached block template
     *
     * At some point, may be used to push an update to miners
     */
    void cache_block_template(const block &b, const cryptonote::account_public_address &address, const blobdata &nonce, const difficulty_type &diff, uint64_t height, uint64_t expected_reward, uint64_t seed_height, const crypto::hash &seed_hash, uint64_t pool_cookie);


#ifndef IN_UNIT_TESTS
  private:
#endif

    BlockchainDB* m_db;

    tx_memory_pool& m_tx_pool;

    mutable epee::critical_section m_blockchain_lock; // TODO: add here reader/writer lock

    HardFork *m_hardfork;

    network_type m_nettype;
    bool m_offline;

    /* `boost::function` is used because the implementation never allocates if
       the callable object has a single `std::shared_ptr` or `std::weap_ptr`
       internally. Whereas, the libstdc++ `std::function` will allocate. */

    std::vector<boost::function<void(std::uint64_t, epee::span<const block>)>> m_block_notifiers;
    std::shared_ptr<tools::Notify> m_reorg_notify;

  };
}  // namespace cryptonote
