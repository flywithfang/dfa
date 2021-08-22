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
     * @brief assign a set of blockchain checkpoint hashes
     *
     * @param chk_pts the set of checkpoints to assign
     */
    void set_checkpoints(checkpoints&& chk_pts) { m_checkpoints = chk_pts; }


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
     * @brief compiles a list of all blocks stored as alternative chains
     *
     * @param blocks return-by-reference container to put result blocks in
     *
     * @return true
     */
    bool get_alternative_blocks(std::vector<block>& blocks) const;

    /**
     * @brief returns the number of alternative blocks stored
     *
     * @return the number of alternative blocks stored
     */
    size_t get_alternative_blocks_count() const;

    /**
     * @brief gets a block's hash given a height
     *
     * @param height the height of the block
     *
     * @return the hash of the block at the requested height, or a zeroed hash if there is no such block
     */
    crypto::hash get_block_hash_by_height(uint64_t height) const;

    /**
     * @brief gets a block's hash given a height
     *
     * Used only by prepare_handle_incoming_blocks. Will look in the list of incoming blocks
     * if the height is contained there.
     *
     * @param height the height of the block
     *
     * @return the hash of the block at the requested height, or a zeroed hash if there is no such block
     */
    crypto::hash get_pending_block_id_by_height(uint64_t height) const;

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
    uint64_t get_current_blockchain_height() const;

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
     * @brief returns the difficulty target the next block to be added must meet
     *
     * @return the target
     */
    difficulty_type get_blockchain_diff();

    /**
     * @brief check currently stored difficulties against difficulty checkpoints
     *
     * @return {flag, height} flag: true if all difficulty checkpoints pass, height: the last checkpoint height before the difficulty drift bug starts
     */
    std::pair<bool, uint64_t> check_difficulty_checkpoints() const;

 
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

    cryptonote::BlockTemplate create_block_template(const crypto::hash *from_block, const account_public_address& miner_address, const blobdata& ex_nonc);

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
     * @brief retrieves a set of blocks and their transactions, and possibly other transactions
     *
     * the request object encapsulates a list of block hashes and a (possibly empty) list of
     * transaction hashes.  for each block hash, the block is fetched along with all of that
     * block's transactions.  Any transactions requested separately are fetched afterwards.
     *
     * @param arg the request
     * @param rsp return-by-reference the response to fill in
     *
     * @return true unless any blocks or transactions are missing
     */
    bool handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp);

   


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
     * @brief gets per block distribution of outputs of a given amount
     *
     * @param amount the amount to get a ditribution for
     * @param from_height the height before which we do not care about the data
     * @param to_height the height after which we do not care about the data
     * @param return-by-reference start_height the height of the first rct output
     * @param return-by-reference distribution the start offset of the first rct output in this block (same as previous if none)
     * @param return-by-reference base how many outputs of that amount are before the stated distribution
     */
    bool get_output_distribution(uint64_t from_height, uint64_t to_height, uint64_t &start_height, std::vector<uint64_t> &distribution) const;

    /**
     * @brief gets the global indices for outputs from a given transaction
     *
     * This function gets the global indices for all outputs belonging
     * to a specific transaction.
     *
     * @param tx_id the hash of the transaction to fetch indices for
     * @param indexs return-by-reference the global indices for the transaction's outputs
     * @param n_txes how many txes in a row to get results for
     *
     * @return false if the transaction does not exist, or if no indices are found, otherwise true
     */
    bool get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs) const;
    bool get_tx_outputs_gindexs(const crypto::hash& tx_id, size_t n_txes, std::vector<std::vector<uint64_t>>& indexs) const;

    /**
     * @brief stores the blockchain
     *
     * If Blockchain is handling storing of the blockchain (rather than BlockchainDB),
     * this initiates a blockchain save.
     *
     * @return true unless saving the blockchain fails
     */
    bool store_blockchain();


   
    /**
     * @brief validate a transaction's fee
     *
     * This function validates the fee is enough for the transaction.
     * This is based on the weight of the transaction, and, after a
     * height threshold, on the average weight of transaction in a past window
     *
     * @param tx_weight the transaction weight
     * @param fee the fee
     *
     * @return true if the fee is enough, false otherwise
     */
    bool check_fee(size_t tx_weight, uint64_t fee) const;

    /**
     * @brief check that a transaction's outputs conform to current standards
     *
     * This function checks, for example at the time of this writing, that
     * each output is of the form a * 10^b (phrased differently, that if
     * written out would have only one non-zero digit in base 10).
     *
     * @param tx the transaction to check the outputs of
     * @param tvc returned info about tx verification
     *
     * @return false if any outputs do not conform, otherwise true
     */
    bool check_tx_outputs(const transaction& tx, tx_verification_context &tvc) const;


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
    bool get_transactions_blobs(const std::vector<crypto::hash>& txs_ids, std::vector<cryptonote::blobdata>& txs, std::vector<crypto::hash>& missed_txs, bool pruned = false) const;
    bool get_transactions_blobs(const std::vector<crypto::hash>& txs_ids, std::vector<tx_blob_entry>& txs, std::vector<crypto::hash>& missed_txs, bool pruned = false) const;
    template<class t_ids_container, class t_tx_container, class t_missed_container>
    bool get_split_transactions_blobs(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs) const;
  

    //debug functions

    /**
     * @brief check the blockchain against a set of checkpoints
     *
     * If a block fails a checkpoint and enforce is enabled, the blockchain
     * will be rolled back to two blocks prior to that block.  If enforce
     * is disabled, as is currently the default case with DNS-based checkpoints,
     * an error will be printed to the user but no other action will be taken.
     *
     * @param points the checkpoints to check against
     * @param enforce whether or not to take action on failure
     */
    void check_against_checkpoints(const checkpoints& points, bool enforce);

    /**
     * @brief configure whether or not to enforce DNS-based checkpoints
     *
     * @param enforce the new enforcement setting
     */
    void set_enforce_dns_checkpoints(bool enforce);

    /**
     * @brief loads new checkpoints from a file and optionally from DNS
     *
     * @param file_path the path of the file to look for and load checkpoints from
     * @param check_dns whether or not to check for new DNS-based checkpoints
     *
     * @return false if any enforced checkpoint type fails to load, otherwise true
     */
    bool update_checkpoints(const std::string& file_path, bool check_dns);


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
     * @brief get difficulty target based on chain and hardfork version
     *
     * @return difficulty target
     */
    uint64_t get_difficulty_target() const;



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

   
    /**
     * @brief returns a set of known alternate chains
     *
     * @return a vector of chains
     */
    std::vector<std::pair<block_extended_info,std::vector<crypto::hash>>> get_alternative_chains() const;

    void add_txpool_tx(const crypto::hash &txid, const cryptonote::blobdata &blob, const txpool_tx_meta_t &meta);
    void update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t &meta);
    void remove_txpool_tx(const crypto::hash &txid);
    uint64_t get_txpool_tx_count(bool include_sensitive = false) const;
    bool get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const;
    bool get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata &bd, relay_category tx_category) const;
    cryptonote::blobdata get_txpool_tx_blob(const crypto::hash& txid, relay_category tx_category) const;
    bool for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::blobdata_ref*)>, bool include_blob = false, relay_category tx_category = relay_category::broadcasted) const;
    bool txpool_tx_matches_category(const crypto::hash& tx_hash, relay_category category);

   
    uint64_t prevalidate_block_hashes(uint64_t height, const std::vector<crypto::hash> &hashes, const std::vector<uint64_t> &weights);
    uint32_t get_blockchain_pruning_seed() const { return m_db->get_blockchain_pruning_seed(); }
    bool prune_blockchain(uint32_t pruning_seed = 0);
    bool update_blockchain_pruning();
    bool check_blockchain_pruning();

    void lock();
    void unlock();


    /**
     * @brief returns the timestamps of the last N blocks
     */
    std::vector<time_t> get_last_block_timestamps(unsigned int blocks) const;

  

    /**
     * @brief checks whether we have known weights for the given block heights
     *
     * @param height the start height to check for
     * @param nblocks how many blocks to check from that height
     */
    bool has_block_weights(uint64_t height, uint64_t nblocks) const;

    /**
     * @brief flush the invalid blocks set
     */
    void flush_invalid_blocks();

    /**
     * @brief get the "adjusted time"
     *
     * Computes the median timestamp of the previous 60 blocks, projects it
     * onto the current block to get an 'adjusted median time' which approximates
     * what the current block's timestamp should be. Also projects the previous
     * block's timestamp to estimate the current block's timestamp.
     * 
     * Returns the minimum of the two projections, or the current local time on
     * the machine if less than 60 blocks are available.
     *
     * @return current time approximated from chain data
     */
    uint64_t get_adjusted_time(uint64_t height) const;

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

    typedef std::vector<block_extended_info> blocks_container;

    typedef std::unordered_map<crypto::hash, block_extended_info> blocks_ext_by_hash;

    /**
     * @brief collects the keys for all outputs being "spent" as an input
     *
     * This function makes sure that each "input" in an input (mixins) exists
     * and collects the public key for each from the transaction it was included in
     * via the visitor passed to it.
     *
     * If pmax_related_block_height is not NULL, its value is set to the height
     * of the most recent block which contains an output used in the input set
     *
     * @tparam visitor_t a class encapsulating tx is unlocked and collect tx key
     * @param tx_in_to_key a transaction input instance
     * @param vis an instance of the visitor to use
     * @param tx_prefix_hash the hash of the associated transaction_prefix
     * @param pmax_related_block_height return-by-pointer the height of the most recent block in the input set
     * @param tx_version version of the tx, if > 1 we also get commitments
     *
     * @return false if any keys are not found or any inputs are not unlocked, otherwise true
     */
    template<class visitor_t>
    inline bool scan_outputkeys_for_indexes(size_t tx_version, const txin_to_key& tx_in_to_key, visitor_t &vis, const crypto::hash &tx_prefix_hash) const;

    /**
     * @brief collect output public keys of a transaction input set
     *
     * This function locates all outputs associated with a given input set (mixins)
     * and validates that they exist and are usable
     * (unlocked, unspent is checked elsewhere).
     *
     * If pmax_related_block_height is not NULL, its value is set to the height
     * of the most recent block which contains an output used in the input set
     *
     * @param tx_version the transaction version
     * @param txin the transaction input
     * @param tx_prefix_hash the transaction prefix hash, for caching organization
     * @param sig the input signature
     * @param output_keys return-by-reference the public keys of the outputs in the input set
     * @param rct_signatures the ringCT signatures, which are only valid if tx version > 1
     * @param pmax_related_block_height return-by-pointer the height of the most recent block in the input set
     * @param hf_version the consensus rules version to use
     *
     * @return false if any output is not yet unlocked, or is missing, otherwise true
     */
    bool check_tx_input(size_t tx_version,const txin_to_key& txin, const crypto::hash& tx_prefix_hash, const rct::rctSig &rct_signatures, std::vector<rct::ctkey> &decoys,  uint8_t hf_version) const;

   

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
     * @brief sanity checks a miner transaction before validating an entire block
     *
     * This function merely checks basic things like the structure of the miner
     * transaction, the unlock time, and that the amount doesn't overflow.
     *
     * @param b the block containing the miner transaction
     * @param height the height at which the block will be added
     * @param hf_version the consensus rules to apply
     *
     * @return false if anything is found wrong with the miner transaction, otherwise true
     */
    bool prevalidate_miner_transaction(const block& b, uint64_t height, uint8_t hf_version);

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

    /**
     * @brief stores an invalid block in a separate container
     *
     * Storing invalid blocks allows quick dismissal of the same block
     * if it is seen again.
     *
     * @param bl the invalid block
     * @param h the block's hash
     *
     * @return false if the block cannot be stored for some reason, otherwise true
     */
    bool add_block_as_invalid(const block& bl, const crypto::hash& h);

    /**
     * @brief stores an invalid block in a separate container
     *
     * Storing invalid blocks allows quick dismissal of the same block
     * if it is seen again.
     *
     * @param bei the invalid block (see ::block_extended_info)
     * @param h the block's hash
     *
     * @return false if the block cannot be stored for some reason, otherwise true
     */
    bool add_block_as_invalid(const block_extended_info& bei, const crypto::hash& h);

    /**
     * @brief checks a block's timestamp
     *
     * This function grabs the timestamps from the most recent <n> blocks,
     * where n = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.  If there are not those many
     * blocks in the blockchain, the timestap is assumed to be valid.  If there
     * are, this function returns:
     *   true if the block's timestamp is not less than the timestamp of the
     *       median of the selected blocks
     *   false otherwise
     *
     * @param b the block to be checked
     * @param median_ts return-by-reference the median of timestamps
     *
     * @return true if the block's timestamp is valid, otherwise false
     */
    bool check_block_timestamp(const block& b, uint64_t& median_ts) const;
    bool check_block_timestamp(const block& b) const {
     uint64_t median_ts; return check_block_timestamp(b, median_ts); }

    /**
     * @brief checks a block's timestamp
     *
     * If the block is not more recent than the median of the recent
     * timestamps passed here, it is considered invalid.
     *
     * @param timestamps a list of the most recent timestamps to check against
     * @param b the block to be checked
     *
     * @return true if the block's timestamp is valid, otherwise false
     */
    bool check_block_timestamp(std::vector<uint64_t>& timestamps, const block& b, uint64_t& median_ts) const;
    bool check_block_timestamp(std::vector<uint64_t>& timestamps, const block& b) const { uint64_t median_ts; return check_block_timestamp(timestamps, b, median_ts); }

    /**
     * @brief finish an alternate chain's timestamp window from the main chain
     *
     * for an alternate chain, get the timestamps from the main chain to complete
     * the needed number of timestamps for the BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.
     *
     * @param start_height the alternate chain's attachment height to the main chain
     * @param timestamps return-by-value the timestamps set to be populated
     *
     * @return true unless start_height is greater than the current blockchain height
     */
    bool complete_timestamps_vector(uint64_t start_height, std::vector<uint64_t>& timestamps) const;

    void return_tx_to_pool(std::vector<std::pair<transaction, blobdata>> &txs);

    /**
     * @brief make sure a transaction isn't attempting a double-spend
     *
     * @param tx the transaction to check
     * @param keys_this_block a cumulative list of spent keys for the current block
     *
     * @return false if a double spend was detected, otherwise true
     */
    bool check_for_double_spend(const transaction& tx, key_images_container& keys_this_block) const;

    /**
     * @brief validates a transaction input's ring signature
     *
     * @param tx_prefix_hash the transaction prefix' hash
     * @param key_image the key image generated from the true input
     * @param pubkeys the public keys for each input in the ring signature
     * @param sig the signature generated for each input in the ring signature
     * @param result false if the ring signature is invalid, otherwise true
     */
    void check_ring_signature(const crypto::hash &tx_prefix_hash, const crypto::key_image &key_image,
        const std::vector<rct::ctkey> &pubkeys, const std::vector<crypto::signature> &sig, uint64_t &result) const;

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
     * @brief expands v2 transaction data from blockchain
     *
     * RingCT transactions do not transmit some of their data if it
     * can be reconstituted by the receiver. This function expands
     * that implicit data.
     */
    bool expand_transaction_2(transaction &tx, const crypto::hash &tx_prefix_hash, const std::vector<std::vector<rct::ctkey>> &pubkeys) const;

 
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

    // Keccak hashes for each block and for fast pow checking
    std::vector<std::pair<crypto::hash, crypto::hash>> m_blocks_hash_of_hashes;
    std::vector<std::pair<crypto::hash, uint64_t>> m_blocks_hash_check;

    // some invalid blocks
    blocks_ext_by_hash m_invalid_blocks;     // crypto::hash -> block_extended_info


    checkpoints m_checkpoints;

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
