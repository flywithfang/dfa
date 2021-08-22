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

#include <algorithm>
#include <cstdio>
#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/format.hpp>

#include "include_base_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "tx_pool.h"
#include "blockchain.h"
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/miner.h"
#include "hardforks/hardforks.h"
#include "misc_language.h"
#include "profile_tools.h"
#include "file_io_utils.h"
#include "int-util.h"
#include "common/threadpool.h"
#include "common/boost_serialization_helper.h"
#include "warnings.h"
#include "crypto/hash.h"
#include "cryptonote_core.h"
#include "ringct/rctSigs.h"
#include "common/perf_timer.h"
#include "common/notify.h"
#include "common/varint.h"
#include "common/pruning.h"
#include "time_helper.h"
#include "string_tools.h"
#include "crypto/rx-hash.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain"

#define FIND_BLOCKCHAIN_SUPPLEMENT_MAX_SIZE (100*1024*1024) // 100 MB

using namespace crypto;
using namespace epee;

//#include "serialization/json_archive.h"

/* TODO:
 *  Clean up code:
 *    Possibly change how outputs are referred to/indexed in blockchain and wallets
 *
 */

using namespace cryptonote;
using epee::string_tools::pod_to_hex;

DISABLE_VS_WARNINGS(4267)

#define MERROR_VER(x) MCERROR("verify", x)

// used to overestimate the block reward when estimating a per kB to use
#define BLOCK_REWARD_OVERESTIMATE (10 * 1000000000000)

//------------------------------------------------------------------
Blockchain::Blockchain(tx_memory_pool& tx_pool) :
  m_db(), m_tx_pool(tx_pool), m_hardfork(NULL), 
{
  MTRACE("Blockchain::" << __func__);
}
//------------------------------------------------------------------
Blockchain::~Blockchain()
{
  try { deinit(); }
  catch (const std::exception &e) { /* ignore */ }
}
//------------------------------------------------------------------
bool Blockchain::have_tx(const crypto::hash &id) const
{
  MTRACE("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->tx_exists(id);
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimg_as_spent(const crypto::key_image &key_im) const
{
  MTRACE("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return  m_db->has_key_image(key_im);
}
//------------------------------------------------------------------
// This function makes sure that each "input" in an input (mixins) exists
// and collects the public key for each from the transaction it was included in
// via the visitor passed to it.
template <class visitor_t>
bool Blockchain::scan_outputkeys_for_indexes(size_t tx_version, const txin_to_key& tx_in_to_key, visitor_t &vis, const crypto::hash &tx_prefix_hash) const
{
  MTRACE("Blockchain::" << __func__);

  // ND: Disable locking and make method private.
  //CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // verify that the input has key offsets (that it exists properly, really)
  if(!tx_in_to_key.key_offsets.size())
    return false;

  // cryptonote_format_utils uses relative offsets for indexing to the global
  // outputs list.  that is to say that absolute offset #2 is absolute offset
  // #1 plus relative offset #2.
  // TODO: Investigate if this is necessary / why this is done.
  const std::vector<uint64_t> absolute_offsets = relative_output_offsets_to_absolute(tx_in_to_key.key_offsets);
  std::vector<output_data_t> outputs;

    try
    {
      m_db->get_output_key(absolute_offsets, outputs);
    }
    catch (...)
    {
      MERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
      return false;
    }

  size_t k = 0;
  for (const uint64_t& i : absolute_offsets)
  {
    try
    {
      const output_data_t out = outputs.at(k);

        // call to the passed boost visitor to grab the public key for the output
        if (!vis.handle_output(out.unlock_time, out.otk, out.commitment))
        {
          MERROR_VER("Failed to handle_output for output no = " << k << ", with absolute offset " << i);
          return false;
        }
    }
    catch (const OUTPUT_DNE& e)
    {
      MERROR_VER("Output does not exist: " << e.what());
      return false;
    }
    catch (const TX_DNE& e)
    {
      MERROR_VER("Transaction does not exist: " << e.what());
      return false;
    }

  }

  return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_blockchain_height() const
{
  MTRACE("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->height();
}
//------------------------------------------------------------------
//FIXME: possibly move this into the constructor, to avoid accidentally
//       dereferencing a null BlockchainDB pointer
bool Blockchain::init(BlockchainDB* db, const network_type nettype, bool offline, const cryptonote::test_options *test_options, const GetCheckpointsCallback& get_checkpoints/* = nullptr*/)
{
  MTRACE("Blockchain::" << __func__);

  CHECK_AND_ASSERT_MES(nettype != FAKECHAIN || test_options, false, "fake chain network type used without options");

  CRITICAL_REGION_LOCAL(m_tx_pool);
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);

  if (db == nullptr)
  {
    LOG_ERROR("Attempted to init Blockchain with null DB");
    return false;
  }
  if (!db->is_open())
  {
    LOG_ERROR("Attempted to init Blockchain with unopened DB");
    delete db;
    return false;
  }

  m_db = db;

  m_nettype = test_options != NULL ? FAKECHAIN : nettype;
  m_offline = offline;
  if (m_hardfork == nullptr)
  {
    if (m_nettype ==  FAKECHAIN || m_nettype == STAGENET)
      m_hardfork = new HardFork(*db, 1, 0);
    else if (m_nettype == TESTNET)
      m_hardfork = new HardFork(*db, 1, testnet_hard_fork_version_1_till);
    else
      m_hardfork = new HardFork(*db, 1, mainnet_hard_fork_version_1_till);
  }
  if (m_nettype == FAKECHAIN)
  {
    for (size_t n = 0; test_options->hard_forks[n].first; ++n)
      m_hardfork->add_fork(test_options->hard_forks[n].first, test_options->hard_forks[n].second, 0, n + 1);
  }
  else if (m_nettype == TESTNET)
  {
    for (size_t n = 0; n < num_testnet_hard_forks; ++n)
      m_hardfork->add_fork(testnet_hard_forks[n].version, testnet_hard_forks[n].height, testnet_hard_forks[n].threshold, testnet_hard_forks[n].time);
  }
  else if (m_nettype == STAGENET)
  {
    for (size_t n = 0; n < num_stagenet_hard_forks; ++n)
      m_hardfork->add_fork(stagenet_hard_forks[n].version, stagenet_hard_forks[n].height, stagenet_hard_forks[n].threshold, stagenet_hard_forks[n].time);
  }
  else
  {
    for (size_t n = 0; n < num_mainnet_hard_forks; ++n)
      m_hardfork->add_fork(mainnet_hard_forks[n].version, mainnet_hard_forks[n].height, mainnet_hard_forks[n].threshold, mainnet_hard_forks[n].time);
  }
  m_hardfork->init();

  m_db->set_hard_fork(m_hardfork);

  // if the blockchain is new, add the genesis block
  // this feels kinda kludgy to do it this way, but can be looked at later.
  // TODO: add function to create and store genesis block,
  //       taking testnet into account
  if(0==m_db->height())
  {
    MINFO("Blockchain not loaded, generating genesis block.");
    block_verification_context bvc = {};
   const auto bl= make_genesis_block(get_config(m_nettype).GENESIS_TX, get_config(m_nettype).GENESIS_NONCE);
    db_wtxn_guard wtxn_guard(m_db);
    add_new_block(bl, bvc);
    CHECK_AND_ASSERT_MES(!bvc.m_verifivation_failed, false, "Failed to add genesis block to blockchain");
  }
  // TODO: if blockchain load successful, verify blockchain against both
  //       hard-coded and runtime-loaded (and enforced) checkpoints.
  else
  {
  }

 
  db_rtxn_guard rtxn_guard(m_db);

  // check how far behind we are
  uint64_t top_block_timestamp = m_db->get_top_block_timestamp();
  uint64_t timestamp_diff = time(NULL) - top_block_timestamp;

  // genesis block has no timestamp, could probably change it to have timestamp of 1397818133...
  if(!top_block_timestamp)
    timestamp_diff = time(NULL) - 1397818133;

#if defined(PER_BLOCK_CHECKPOINT)
  if (m_nettype != FAKECHAIN)
    load_compiled_in_block_hashes(get_checkpoints);
#endif

  MINFO("Blockchain initialized. last block: " << m_db->height() - 1 << ", " << epee::misc_utils::get_time_interval_string(timestamp_diff) << " time ago, current difficulty: " << get_blockchain_diff());

  rtxn_guard.stop();

  uint64_t num_popped_blocks = 0;
  while (!m_db->is_read_only())
  {
    uint64_t top_height;
    const crypto::hash top_id = m_db->top_block_hash(&top_height);
    const block top_block = m_db->get_top_block();
    const uint8_t ideal_hf_version = get_ideal_hard_fork_version(top_height);
    if (ideal_hf_version <= 1 || ideal_hf_version == top_block.major_version)
    {
      if (num_popped_blocks > 0)
        MGINFO("Initial popping done, top block: " << top_id << ", top height: " << top_height << ", block version: " << (uint64_t)top_block.major_version);
      break;
    }
    else
    {
      if (num_popped_blocks == 0)
        MGINFO("Current top block " << top_id << " at height " << top_height << " has version " << (uint64_t)top_block.major_version << " which disagrees with the ideal version " << (uint64_t)ideal_hf_version);
      if (num_popped_blocks % 100 == 0)
        MGINFO("Popping blocks... " << top_height);
      ++num_popped_blocks;
      block popped_block;
      std::vector<transaction> popped_txs;
      try
      {
        m_db->pop_block(popped_block, popped_txs);
      }
      // anything that could cause this to throw is likely catastrophic,
      // so we re-throw
      catch (const std::exception& e)
      {
        MERROR("Error popping block from blockchain: " << e.what());
        throw;
      }
      catch (...)
      {
        MERROR("Error popping block from blockchain, throwing!");
        throw;
      }
    }
  }
  if (num_popped_blocks > 0)
  {
    m_hardfork->reorganize_from_chain_height(get_current_blockchain_height());
  }

  {
    db_txn_guard txn_guard(m_db, m_db->is_read_only());
  
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::init(BlockchainDB* db, HardFork*& hf, const network_type nettype, bool offline)
{
  if (hf != nullptr)
    m_hardfork = hf;
  bool res = init(db, nettype, offline, NULL);
  if (hf == nullptr)
    hf = m_hardfork;
  return res;
}
//------------------------------------------------------------------
bool Blockchain::store_blockchain()
{
  MTRACE("Blockchain::" << __func__);
  // lock because the rpc_thread command handler also calls this
  CRITICAL_REGION_LOCAL(m_db->m_synchronization_lock);

  TIME_MEASURE_START(save);
  // TODO: make sure sync(if this throws that it is not simply ignored higher
  // up the call stack
  try
  {
    m_db->sync();
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Error syncing blockchain db: ") + e.what() + "-- shutting down now to prevent issues!");
    throw;
  }
  catch (...)
  {
    MERROR("There was an issue storing the blockchain, shutting down now to prevent issues!");
    throw;
  }

  TIME_MEASURE_FINISH(save);
  if(m_show_time_stats)
    MINFO("Blockchain stored OK, took: " << save << " ms");
  return true;
}
//------------------------------------------------------------------
bool Blockchain::deinit()
{
  MTRACE("Blockchain::" << __func__);

  MTRACE("Stopping blockchain read/write activity");


  // as this should be called if handling a SIGSEGV, need to check
  // if m_db is a NULL pointer (and thus may have caused the illegal
  // memory operation), otherwise we may cause a loop.
  try
  {
    if (m_db)
    {
      m_db->close();
      MTRACE("Local blockchain read/write activity stopped successfully");
    }
  }
  catch (const std::exception& e)
  {
    LOG_ERROR(std::string("Error closing blockchain db: ") + e.what());
  }
  catch (...)
  {
    LOG_ERROR("There was an issue closing/storing the blockchain, shutting down now to prevent issues!");
  }

  delete m_hardfork;
  m_hardfork = NULL;
  delete m_db;
  m_db = NULL;
  return true;
}
//------------------------------------------------------------------
// This function tells BlockchainDB to remove the top block from the
// blockchain and then returns all transactions (except the miner tx, of course)
// from it to the tx_pool
block Blockchain::pop_block_from_blockchain()
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  block popped_block;
  std::vector<transaction> popped_txs;

  CHECK_AND_ASSERT_THROW_MES(m_db->height() > 1, "Cannot pop the genesis block");

  try
  {
    m_db->pop_block(popped_block, popped_txs);
  }
  // anything that could cause this to throw is likely catastrophic,
  // so we re-throw
  catch (const std::exception& e)
  {
    LOG_ERROR("Error popping block from blockchain: " << e.what());
    throw;
  }
  catch (...)
  {
    LOG_ERROR("Error popping block from blockchain, throwing!");
    throw;
  }

  // make sure the hard fork object updates its current version
  m_hardfork->on_block_popped(1);

  // return transactions from popped block to the tx_pool
  size_t pruned = 0;
  for (transaction& tx : popped_txs)
  {
    if (tx.pruned)
    {
      ++pruned;
      continue;
    }
    if (!is_coinbase(tx))
    {
      cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);

      // FIXME: HardFork
      // Besides the below, popping a block should also remove the last entry
      // in hf_versions.
      uint8_t version = get_ideal_hard_fork_version(m_db->height());

      // We assume that if they were in a block, the transactions are already
      // known to the network as a whole. However, if we had mined that block,
      // that might not be always true. Unlikely though, and always relaying
      // these again might cause a spike of traffic as many nodes re-relay
      // all the transactions in a popped block when a reorg happens.
      bool r = m_tx_pool.add_tx(tx, tvc, relay_method::block, true, version);
      if (!r)
      {
        LOG_ERROR("Error returning transaction to tx_pool");
      }
    }
  }
  if (pruned)
    MWARNING(pruned << " pruned txes could not be added back to the txpool");

  return popped_block;
}

//------------------------------------------------------------------
crypto::hash Blockchain::get_top_hash(uint64_t& height) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->top_block_hash(&height);
}
 std::tuple<crypto::hash,uint64_t> Blockchain::get_top_block_hash()const
 {
   MTRACE("Blockchain::" << __func__);
      CRITICAL_REGION_LOCAL(m_blockchain_lock);
      uint64_t height;
      auto hash =  m_db->top_block_hash(&height);
      return {hash,height};
 }
//------------------------------------------------------------------
crypto::hash Blockchain::get_top_hash() const
{
  MTRACE("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->top_block_hash();
}
//------------------------------------------------------------------
/*TODO: this function was...poorly written.  As such, I'm not entirely
 *      certain on what it was supposed to be doing.  Need to look into this,
 *      but it doesn't seem terribly important just yet.
 *
 * puts into list <ids> a list of hashes representing certain blocks
 * from the blockchain in reverse chronological order
 *
 * the blocks chosen, at the time of this writing, are:
 *   the most recent 11
 *   powers of 2 less recent from there, so 13, 17, 25, etc...
 *
 */
std::list<crypto::hash> Blockchain::get_short_chain_history() const
{
  std::list<crypto::hash> ids;

  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t i = 0;
  uint64_t current_multiplier = 1;
  uint64_t sz = m_db->height();

  if(!sz)
    throw_and_log(__func__<<"height is 0");

  db_rtxn_guard rtxn_guard(m_db);
  bool genesis_included = false;
  uint64_t current_back_offset = 1;
  while(current_back_offset < sz)
  {
    ids.push_back(m_db->get_block_hash_from_height(sz - current_back_offset));

    if(sz-current_back_offset == 0)
    {
      genesis_included = true;
    }
    if(i < 10)
    {
      ++current_back_offset;
    }
    else
    {
      current_multiplier *= 2;
      current_back_offset += current_multiplier;
    }
    ++i;
  }

  if (!genesis_included)
  {
    ids.push_back(m_db->get_block_hash_from_height(0));
  }

  return ids;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_block_hash_by_height(uint64_t height) const
{
  MTRACE("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  try
  {
    return m_db->get_block_hash_from_height(height);
  }
  catch (const BLOCK_DNE& e)
  {
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Something went wrong fetching block hash by height: ") + e.what());
    throw;
  }
  catch (...)
  {
    MERROR(std::string("Something went wrong fetching block hash by height"));
    throw;
  }
  return null_hash;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_pending_block_id_by_height(uint64_t height) const
{
  return get_block_hash_by_height(height);
}
//------------------------------------------------------------------
bool Blockchain::get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // try to find block in main chain
  try
  {
    blk = m_db->get_block(h);
    if (orphan)
      *orphan = false;
    return true;
  }
  // try to find block in alternative chain
  catch (const BLOCK_DNE& e)
  {
    alt_block_data_t data;
    cryptonote::blobdata blob;
    if (m_db->get_alt_block(h, &data, &blob))
    {
      blk = cryptonote::parse_block_from_blob(blob);
      
      if (orphan)
        *orphan = true;
      return true;
    }
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Something went wrong fetching block by hash: ") + e.what());
    throw;
  }
  catch (...)
  {
    MERROR(std::string("Something went wrong fetching block hash by hash"));
    throw;
  }

  return false;
}
//------------------------------------------------------------------
// This function aggregates the cumulative difficulties and timestamps of the
// last DIFFICULTY_WINDOW blocks and passes them to next_difficulty,
// returning the result of that call.  Ignores the genesis block, and can use
// less blocks than desired if there aren't enough.
difficulty_type Blockchain::get_blockchain_diff()
{
  MTRACE("Blockchain::" << __func__);

   CRITICAL_REGION_LOCAL(m_blockchain_lock);

  const auto [ _,cur_height]= get_top_block_hash(); // get it again now that we have the lock
  const uint64_t  height= cur_height+1;;

    const auto  W = DIFFICULTY_WINDOW;

    const int64_t end_h = height-W-height%W;
    const int64_t start_h=end_h-W;
    if(start_h<0)
      return 1;

    std::vector<uint64_t> timestamps;
    std::vector<difficulty_type> difficulties;
   
    for (auto h = start_h;h<end_h;++h)
    {
      timestamps.push_back(m_db->get_block_timestamp(h));
      difficulties.push_back(m_db->get_block_cumulative_difficulty(h));
    }


  const difficulty_type diff = next_difficulty(timestamps, difficulties, DIFFICULTY_TARGET);

  return diff;
}
//------------------------------------------------------------------
std::pair<bool, uint64_t> Blockchain::check_difficulty_checkpoints() const
{
  uint64_t res = 0;
  for (const std::pair<const uint64_t, difficulty_type>& i : m_checkpoints.get_difficulty_points())
  {
    if (i.first >= m_db->height())
      break;
    if (m_db->get_block_cumulative_difficulty(i.first) != i.second)
      return {false, res};
    res = i.first;
  }
  return {true, res};
}

//------------------------------------------------------------------
std::vector<time_t> Blockchain::get_last_block_timestamps(unsigned int blocks) const
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t height = m_db->height();
  if (blocks > height)
    blocks = height;
  std::vector<time_t> timestamps(blocks);
  while (blocks--)
    timestamps[blocks] = m_db->get_block_timestamp(height - blocks - 1);
  return timestamps;
}
//------------------------------------------------------------------
// This function removes blocks from the blockchain until it gets to the
// position where the blockchain switch started and then re-adds the blocks
// that had been removed.
bool Blockchain::rollback_blockchain_switching(std::list<block>& original_chain, uint64_t rollback_height)
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // fail if rollback_height passed is too high
  if (rollback_height > m_db->height())
  {
    return true;
  }

  // remove blocks from blockchain until we get back to where we should be.
  while (m_db->height() != rollback_height)
  {
    pop_block_from_blockchain();
  }

  // make sure the hard fork object updates its current version
  m_hardfork->reorganize_from_chain_height(rollback_height);

  //return back original chain
  for (auto& bl : original_chain)
  {
    block_verification_context bvc = {};
    bool r = handle_block_to_main_chain(bl, bvc, false);
    CHECK_AND_ASSERT_MES(r && bvc.m_added_to_main_chain, false, "PANIC! failed to add (again) block while chain switching during the rollback!");
  }

  m_hardfork->reorganize_from_chain_height(rollback_height);

  MINFO("Rollback to height " << rollback_height << " was successful.");
  if (!original_chain.empty())
  {
    MINFO("Restoration to previous blockchain successful as well.");
  }
  return true;
}
//------------------------------------------------------------------
// This function attempts to switch to an alternate chain, returning
// boolean based on success therein.
bool Blockchain::switch_to_alternative_blockchain(std::list<block_extended_info>& alt_chain, bool discard_disconnected_chain)
{
  MWARNING("switch_to_alternative_blockchain" );

  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // if empty alt chain passed (not sure how that could happen), return false
  CHECK_AND_ASSERT_MES(alt_chain.size(), false, "switch_to_alternative_blockchain: empty chain passed");

  // verify that main chain has front of alt chain's parent block
  if (!m_db->block_exists(alt_chain.front().bl.prev_id))
  {
    LOG_ERROR("Attempting to move to an alternate chain, but it doesn't appear to connect to the main chain!");
    return false;
  }

  // pop blocks from the blockchain until the top block is the parent
  // of the front block of the alt chain.
  std::list<block> disconnected_chain;
  while (m_db->top_block_hash() != alt_chain.front().bl.prev_id)
  {
    block b = pop_block_from_blockchain();
    disconnected_chain.push_front(b);
  }

  auto split_height = m_db->height();

  //connecting new alternative chain
  for(auto alt_ch_iter = alt_chain.begin(); alt_ch_iter != alt_chain.end(); alt_ch_iter++)
  {
    const auto &bei = *alt_ch_iter;
    block_verification_context bvc = {};

    // add block to main chain
    bool r = handle_block_to_main_chain(bei.bl, bvc, false);

    // if adding block to main chain failed, rollback to previous state and
    // return false
    if(!r || !bvc.m_added_to_main_chain)
    {
      MERROR("Failed to switch to alternative blockchain");

      // rollback_blockchain_switching should be moved to two different
      // functions: rollback and apply_chain, but for now we pretend it is
      // just the latter (because the rollback was done above).
      rollback_blockchain_switching(disconnected_chain, split_height);

      // FIXME: Why do we keep invalid blocks around?  Possibly in case we hear
      // about them again so we can immediately dismiss them, but needs some
      // looking into.
      const crypto::hash blkid = cryptonote::get_block_hash(bei.bl);
      add_block_as_invalid(bei, blkid);
      MERROR("The block was inserted as invalid while connecting new alternative chain, block_id: " << blkid);
      m_db->remove_alt_block(blkid);
      alt_ch_iter++;

      for(auto it = alt_ch_iter; it != alt_chain.end(); )
      {
        const auto &bei = *it++;
        const crypto::hash blkid = cryptonote::get_block_hash(bei.bl);
        add_block_as_invalid(bei, blkid);
        m_db->remove_alt_block(blkid);
      }
      return false;
    }
  }

  // if we're to keep the disconnected blocks, add them as alternates
  const size_t discarded_blocks = disconnected_chain.size();
  if(!discard_disconnected_chain)
  {
    //pushing old chain as alternative chain
    for (auto& old_ch_ent : disconnected_chain)
    {
      block_verification_context bvc = {};
      bool r = handle_alternative_block(old_ch_ent, bvc);
      if(!r)
      {
        MERROR("Failed to push ex-main chain blocks to alternative chain ");
        // previously this would fail the blockchain switching, but I don't
        // think this is bad enough to warrant that.
      }
    }
  }

  //removing alt_chain entries from alternative chains container
  for (const auto &bei: alt_chain)
  {
    m_db->remove_alt_block(cryptonote::get_block_hash(bei.bl));
  }

  m_hardfork->reorganize_from_chain_height(split_height);
  get_block_longhash_reorg(split_height);

  std::shared_ptr<tools::Notify> reorg_notify = m_reorg_notify;
  if (reorg_notify)
    reorg_notify->notify("%s", std::to_string(split_height).c_str(), "%h", std::to_string(m_db->height()).c_str(),
        "%n", std::to_string(m_db->height() - split_height).c_str(), "%d", std::to_string(discarded_blocks).c_str(), NULL);

  for (const auto& notifier : m_block_notifiers)
  {
    std::size_t notify_height = split_height;
    for (const auto& bei: alt_chain)
    {
      notifier(notify_height, {std::addressof(bei.bl), 1});
      ++notify_height;
    }
  }

  MGINFO_GREEN("REORGANIZE SUCCESS! on height: " << split_height << ", new blockchain size: " << m_db->height());
  return true;
}
//------------------------------------------------------------------
// This function calculates the difficulty target for the block being added to
// an alternate chain.
difficulty_type Blockchain::get_next_difficulty_for_alternative_chain(const std::list<block_extended_info>& alt_chain, block_extended_info& bei) const
{
 
  MTRACE("Blockchain::" << __func__);
  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> cumulative_difficulties;

  // if the alt chain isn't long enough to calculate the difficulty target
  // based on its blocks alone, need to get more blocks from the main chain
  if(alt_chain.size()< DIFFICULTY_WINDOW)
  {
    CRITICAL_REGION_LOCAL(m_blockchain_lock);

    // Figure out start and stop offsets for main chain blocks
    size_t main_chain_stop_offset = alt_chain.size() ? alt_chain.front().height : bei.height;
    size_t main_chain_count = DIFFICULTY_WINDOW - std::min(static_cast<size_t>(DIFFICULTY_WINDOW), alt_chain.size());
    main_chain_count = std::min(main_chain_count, main_chain_stop_offset);
    size_t main_chain_start_offset = main_chain_stop_offset - main_chain_count;

    if(!main_chain_start_offset)
      ++main_chain_start_offset; //skip genesis block

    // get difficulties and timestamps from relevant main chain blocks
    for(; main_chain_start_offset < main_chain_stop_offset; ++main_chain_start_offset)
    {
      timestamps.push_back(m_db->get_block_timestamp(main_chain_start_offset));
      cumulative_difficulties.push_back(m_db->get_block_cumulative_difficulty(main_chain_start_offset));
    }

    // make sure we haven't accidentally grabbed too many blocks...maybe don't need this check?
    CHECK_AND_ASSERT_MES((alt_chain.size() + timestamps.size()) <= DIFFICULTY_WINDOW, false, "Internal error, alt_chain.size()[" << alt_chain.size() << "] + vtimestampsec.size()[" << timestamps.size() << "] NOT <= DIFFICULTY_WINDOW[]" << DIFFICULTY_WINDOW);

    for (const auto &bei : alt_chain)
    {
      timestamps.push_back(bei.bl.timestamp);
      cumulative_difficulties.push_back(bei.cum_diff);
    }
  }
  // if the alt chain is long enough for the difficulty calc, grab difficulties
  // and timestamps from it alone
  else
  {
    timestamps.resize(static_cast<size_t>(DIFFICULTY_WINDOW));
    cumulative_difficulties.resize(static_cast<size_t>(DIFFICULTY_WINDOW));
    size_t count = 0;
    size_t max_i = timestamps.size()-1;
    // get difficulties and timestamps from most recent blocks in alt chain
    for (const auto &bei: boost::adaptors::reverse(alt_chain))
    {
      timestamps[max_i - count] = bei.bl.timestamp;
      cumulative_difficulties[max_i - count] = bei.cum_diff;
      count++;
      if(count >= DIFFICULTY_WINDOW)
        break;
    }
  }


  // calculate the difficulty target for the block and return it
  return next_difficulty(timestamps, cumulative_difficulties, DIFFICULTY_TARGET);
}
//------------------------------------------------------------------
// This function does a sanity check on basic things that all miner
// transactions have in common, such as:
//   one input, of type txin_gen, with height set to the block's height
//   correct miner tx unlock time
//   a non-overflowing tx amount (dubious necessity on this check)
bool Blockchain::prevalidate_miner_transaction(const block& b, uint64_t height, uint8_t hf_version)
{
  MTRACE("Blockchain::" << __func__);
  CHECK_AND_ASSERT_MES(b.miner_tx.vin.size() == 1, false, "coinbase transaction in the block has no inputs");
  CHECK_AND_ASSERT_MES(b.miner_tx.vin[0].type() == typeid(txin_gen), false, "coinbase transaction in the block has the wrong type");

  // for v2 txes (ringct), we only accept empty rct signatures for miner transactions,
  {
    CHECK_AND_ASSERT_MES(b.miner_tx.rct_signatures.type == rct::RCTTypeNull, false, "RingCT signatures not allowed in coinbase transactions");
  }

  if(boost::get<txin_gen>(b.miner_tx.vin[0]).height != height)
  {
    MWARNING("The miner transaction in block has invalid height: " << boost::get<txin_gen>(b.miner_tx.vin[0]).height << ", expected: " << height);
    return false;
  }
  MDEBUG("Miner tx hash: " << get_transaction_hash(b.miner_tx));
  CHECK_AND_ASSERT_MES(b.miner_tx.unlock_time == height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, false, "coinbase transaction transaction has the wrong unlock time=" << b.miner_tx.unlock_time << ", expected " << height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);

  //check outs overflow
  //NOTE: not entirely sure this is necessary, given that this function is
  //      designed simply to make sure the total amount for a transaction
  //      does not overflow a uint64_t, and this transaction *is* a uint64_t...
  if(!check_outs_overflow(b.miner_tx))
  {
    MERROR("miner transaction has money overflow in block " << get_block_hash(b));
    return false;
  }

  return true;
}
//------------------------------------------------------------------
// This function validates the miner transaction reward
bool Blockchain::validate_miner_transaction(const block& b,  uint64_t fee, uint64_t& base_reward,  uint8_t version)
{
  MTRACE("Blockchain::" << __func__);
  //validate reward
  uint64_t money_in_use = 0;
  for (auto& o: b.miner_tx.vout)
    money_in_use += o.amount;
  base_reward=get_block_reward();
    if(base_reward + fee != money_in_use)
    {
      MDEBUG("coinbase transaction doesn't use full amount of block reward:  spent: " << money_in_use << ",  block reward " << base_reward + fee << "(" << base_reward << "+" << fee << ")");
      return false;
    }
 
  return true;
}

//------------------------------------------------------------------
// for an alternate chain, get the timestamps from the main chain to complete
// the needed number of timestamps for the BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.
bool Blockchain::complete_timestamps_vector(uint64_t start_top_height, std::vector<uint64_t>& timestamps) const
{
  MTRACE("Blockchain::" << __func__);

  if(timestamps.size() >= BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW)
    return true;

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  const size_t need_elements = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - timestamps.size();
  CHECK_AND_ASSERT_MES(start_top_height < m_db->height(), false, "internal error: passed start_height not < " << " m_db->height() -- " << start_top_height << " >= " << m_db->height());
  const size_t stop_height = start_top_height > need_elements ? start_top_height - need_elements : 0;
  timestamps.reserve(timestamps.size() + start_top_height - stop_height);

  auto h = start_top_height;
  while (h >= stop_height)
  {
    timestamps.push_back(m_db->get_block_timestamp(h));
    --h;
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::build_alt_chain(const crypto::hash &prev_id, std::list<block_extended_info>& alt_chain, std::vector<uint64_t> &timestamps, block_verification_context& bvc) const
{
    //build alternative subchain, front -> mainchain, back -> alternative head
    cryptonote::alt_block_data_t alt_block;
    cryptonote::blobdata blob;
    bool found = m_db->get_alt_block(prev_id, &alt_block, &blob);
    timestamps.clear();
    while(found)
    {
      block_extended_info bei;
      bei.bl = cryptonote::parse_block_from_blob(blob);
      bei.height = alt_block.height;
      bei.block_cumulative_weight = alt_block.cumulative_weight;
      bei.cum_diff = alt_block.cumulative_difficulty_high;
      bei.cum_diff = (bei.cum_diff << 64) + alt_block.cumulative_difficulty_low;
      bei.already_generated_coins = alt_block.already_generated_coins;
      timestamps.push_back(bei.bl.timestamp);
      alt_chain.push_front(std::move(bei));//push_front
      found = m_db->get_alt_block(bei.bl.prev_id, &alt_block, &blob);
    }

    // if block to be added connects to known blocks that aren't part of the
    // main chain -- that is, if we're adding on to an alternate chain
    if(!alt_chain.empty())
    {
      // make sure alt chain doesn't somehow start past the end of the main chain
      CHECK_AND_ASSERT_MES(m_db->height() > alt_chain.front().height, false, "main blockchain wrong height");

      // make sure that the blockchain contains the block that should connect
      // this alternate chain with it.
      if (!m_db->block_exists(alt_chain.front().bl.prev_id))
      {
        MERROR("alternate chain does not appear to connect to main chain...");
        return false;
      }

      // make sure block connects correctly to the main chain
      auto h = m_db->get_block_hash_from_height(alt_chain.front().height - 1);
      CHECK_AND_ASSERT_MES(h == alt_chain.front().bl.prev_id, false, "alternative chain has wrong connection to main chain");
      complete_timestamps_vector(m_db->get_block_height(alt_chain.front().bl.prev_id), timestamps);
    }
    // if block not associated with known alternate chain
    else
    {
      // if block parent is not part of main chain or an alternate chain,
      // we ignore it
      bool parent_in_main = m_db->block_exists(prev_id);
      CHECK_AND_ASSERT_MES(parent_in_main, false, "internal error: broken imperative condition: parent_in_main");

      complete_timestamps_vector(m_db->get_block_height(prev_id), timestamps);
    }

    return true;
}
//------------------------------------------------------------------
// If a block is to be added and its parent block is not the current
// main chain top block, then we need to see if we know about its parent block.
// If its parent block is part of a known forked chain, then we need to see
// if that chain is long enough to become the main chain and re-org accordingly
// if so.  If not, we need to hang on to the block in case it becomes part of
// a long forked chain eventually.
bool Blockchain::handle_alternative_block(const block& b, block_verification_context& bvc)
{
  MTRACE("Blockchain::" << __func__);

  const crypto::hash& id = get_block_hash(b);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t block_height = get_block_height(b);
  if(0 == block_height)
  {
    MERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative), but miner tx says height is 0.");
    bvc.m_verifivation_failed = true;
    return false;
  }
  // this is a cheap test
  const uint8_t hf_version = 0;

try{
  //block is not related with head of main chain
  //first of all - look in alternative chains container
  alt_block_data_t prev_data;
  bool parent_in_alt = m_db->get_alt_block(b.prev_id, &prev_data, NULL);
  bool parent_in_main = m_db->block_exists(b.prev_id);
  if (parent_in_alt || parent_in_main)
  {
    //we have new block in alternative chain
    std::list<block_extended_info> alt_chain;
    std::vector<uint64_t> timestamps;
    if (!build_alt_chain(b.prev_id, alt_chain, timestamps, bvc))
      return false;

    // FIXME: consider moving away from block_extended_info at some point
    block_extended_info bei = {};
    bei.bl = b;
    const uint64_t prev_height = alt_chain.size() ? prev_data.height : m_db->get_block_height(b.prev_id);
    bei.height = prev_height + 1;
    const uint64_t block_reward = get_outs_money_amount(b.miner_tx);
    const uint64_t prev_generated_coins = alt_chain.size() ? prev_data.already_generated_coins : m_db->get_block_already_generated_coins(prev_height);
    bei.already_generated_coins =  prev_generated_coins + block_reward ;

    // verify that the block's timestamp is within the acceptable range
    // (not earlier than the median of the last X blocks)
    if(!check_block_timestamp(timestamps, b))
    {
      MERROR_VER("Block with id: " << id << std::endl << " for alternative chain, has invalid timestamp: " << b.timestamp);
      bvc.m_verifivation_failed = true;
      return false;
    }

  
    // Check the block's hash against the difficulty target for its alt chain
    difficulty_type current_diff = get_next_difficulty_for_alternative_chain(alt_chain, bei);
    CHECK_AND_ASSERT_MES(current_diff, false, "!!!!!!! DIFFICULTY OVERHEAD !!!!!!!");
    crypto::hash pow;
    memset(pow.data, 0xff, sizeof(pow.data));
    {
      crypto::hash seedhash = null_hash;
      uint64_t seedheight = rx_seedheight(bei.height);
      // seedblock is on the alt chain somewhere
      if (alt_chain.size() && alt_chain.front().height <= seedheight)
      {
        for (auto it=alt_chain.begin(); it != alt_chain.end(); it++)
        {
          if (it->height == seedheight+1)
          {
            seedhash = it->bl.prev_id;
            break;
          }
        }
      } else
      {
        seedhash = get_block_hash_by_height(seedheight);
      }
      get_altblock_longhash(bei.bl, pow, get_current_blockchain_height(), bei.height, seedheight, seedhash);
    } 

    
    if(!check_hash(pow, current_diff))
    {
      MERROR_VER("Block with id: " << id << std::endl << " for alternative chain, does not have enough proof of work: " << pow << std::endl << " expected difficulty: " << current_diff);
      bvc.m_verifivation_failed = true;
      bvc.m_bad_pow = true;
      return false;
    }

    if(!prevalidate_miner_transaction(b, bei.height, hf_version))
    {
      MERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative) has incorrect miner transaction.");
      bvc.m_verifivation_failed = true;
      return false;
    }

    // FIXME:
    // this brings up an interesting point: consider allowing to get block
    // difficulty both by height OR by hash, not just height.
    difficulty_type main_chain_cumulative_difficulty = m_db->get_block_cumulative_difficulty(m_db->height() - 1);
    if (alt_chain.size())
    {
      bei.cum_diff = prev_data.cumulative_difficulty_high;
      bei.cum_diff = (bei.cum_diff << 64) + prev_data.cumulative_difficulty_low;
    }
    else
    {
      // passed-in block's previous block's cumulative difficulty, found on the main chain
      bei.cum_diff = m_db->get_block_cumulative_difficulty(m_db->get_block_height(b.prev_id));
    }
    bei.cum_diff += current_diff;

    bei.block_cumulative_weight =0;
    for (const crypto::hash &txid: b.tx_hashes)
    {
      cryptonote::tx_memory_pool::tx_details td;
      cryptonote::blobdata blob;
      if (m_tx_pool.have_tx(txid, relay_category::legacy))
      {
        if (m_tx_pool.get_transaction_info(txid, td))
        {
          bei.block_cumulative_weight += td.weight;
        }
        else
        {
          MERROR_VER("Transaction is in the txpool, but metadata not found");
          bvc.m_verifivation_failed = true;
          return false;
        }
      }
      else if (m_db->get_pruned_tx_blob(txid, blob))
      {
        cryptonote::transaction tx=cryptonote::parse_tx_base_from_blob(blob);
       
        bei.block_cumulative_weight += cryptonote::get_transaction_weight(tx);
      }
      else
      {
        // we can't determine the block weight, set it to 0 and break out of the loop
        bei.block_cumulative_weight = 0;
        break;
      }
    }

    // add block to alternate blocks storage,
    // as well as the current "alt chain" container
    CHECK_AND_ASSERT_MES(!m_db->get_alt_block(id, NULL, NULL), false, "insertion of new alternative block returned as it already exists");
    cryptonote::alt_block_data_t data;
    data.height = bei.height;
    data.cumulative_weight = bei.block_cumulative_weight;
    data.cumulative_difficulty_low = (bei.cum_diff & 0xffffffffffffffff).convert_to<uint64_t>();
    data.cumulative_difficulty_high = ((bei.cum_diff >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
    data.already_generated_coins = bei.already_generated_coins;
    m_db->add_alt_block(id, data, cryptonote::block_to_blob(bei.bl));
    alt_chain.push_back(bei);

    if(main_chain_cumulative_difficulty < bei.cum_diff) //check if difficulty bigger then in main chain
    {
      //do reorganize!
      MGINFO_GREEN("###### REORGANIZE on height: " << alt_chain.front().height << " of " << m_db->height() - 1 << " with cum_difficulty " << m_db->get_block_cumulative_difficulty(m_db->height() - 1) << std::endl << " alternative blockchain size: " << alt_chain.size() << " with cum_difficulty " << bei.cum_diff);

      bool r = switch_to_alternative_blockchain(alt_chain, false);
      if (r)
        bvc.m_added_to_main_chain = true;
      else
        bvc.m_verifivation_failed = true;
      return r;
    }
    else
    {
      MGINFO_BLUE("----- BLOCK ADDED AS ALTERNATIVE ON HEIGHT " << bei.height << std::endl << "id:\t" << id << std::endl << "PoW:\t" << pow << std::endl << "difficulty:\t" << current_diff);
      return true;
    }
  }
  else
  {
    //block orphaned
    bvc.m_marked_as_orphaned = true;
    MERROR_VER("orphaned and rejected, id = " << id << ", height " << block_height
        << ", parent in alt " << parent_in_alt << ", parent in main " << parent_in_main
        << " (prev_id " << b.prev_id << ", top hash" << get_top_hash() << ", chain height " << get_current_blockchain_height() << ")");
  }
  }catch(std::exception & ex){
      bvc.m_verifivation_failed = true;
      return false;
   
  }
 return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::vector<BlobBlock>& blocks) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  const uint64_t height = m_db->height();
  if(start_offset >= height)
    return false;
  const auto end_h =  start_offset + count> height ? height: start_offset+count;

  blocks.reserve(blocks.size() + height - start_offset);
  for(size_t i = start_offset; i < start_offset + count && i < height;i++)
  {
    const auto blob = m_db->get_block_blob_from_height(i);
    const auto b = parse_block_from_blob(blob);
    blocks.push_back({std::moved(blob),std::move(b)});
  }
  return true;
}
//------------------------------------------------------------------
//TODO: This function *looks* like it won't need to be rewritten
//      to use BlockchainDB, as it calls other functions that were,
//      but it warrants some looking into later.
//
//FIXME: This function appears to want to return false if any transactions
//       that belong with blocks are missing, but not if blocks themselves
//       are missing.
bool Blockchain::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& req, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp)
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  db_rtxn_guard rtxn_guard (m_db);
  rsp.current_blockchain_height = get_current_blockchain_height();
  std::vector<BlobBlock> blocks;
  get_blocks(req.blocks, blocks, rsp.missed_ids);

  for (auto & [bblob, b] : blocks)
  {
    std::vector<crypto::hash> missed_tx_ids;

    block_complete_entry e{};

    get_transactions_blobs(b.tx_hashes, e.tbs, missed_tx_ids );
    if (missed_tx_ids.size() != 0)
    {
      // do not display an error if the peer asked for an unpruned block which we are not meant to have
      {
        throw_and_log("Error retrieving blocks, missed " << missed_tx_ids.size()
            << " transactions for block with hash: " << get_block_hash(b));
      }
    }

    //pack block
    e.block = std::move(bblob);
    rsp.bces.push_back(std::move(e));
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_alternative_blocks(std::vector<block>& blocks) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  blocks.reserve(m_db->get_alt_block_count());
  m_db->for_all_alt_blocks([&blocks](const crypto::hash &blkid, const cryptonote::alt_block_data_t &data, const cryptonote::blobdata_ref *blob) {
    if (!blob)
    {
      MERROR("No blob, but blobs were requested");
      return false;
    }
    cryptonote::block bl= cryptonote::parse_block_from_blob(*blob);
    blocks.push_back(std::move(bl));
   
    return true;
  }, true);
  return true;
}
//------------------------------------------------------------------
size_t Blockchain::get_alternative_blocks_count() const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->get_alt_block_count();
}


//------------------------------------------------------------------
bool Blockchain::get_outs(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  res.outs.clear();
  res.outs.reserve(req.outputs.size());

  
  try
  {
    std::vector<uint64_t>  offsets;
    offsets.reserve(req.outputs.size());
    for (const auto &[index]: req.outputs)
    {
      offsets.push_back(index);
    }
    std::vector<cryptonote::output_data_t> data;
    m_db->get_output_key( offsets, data);
    if (data.size() != req.outputs.size())
    {
      MERROR("Unexpected output data size: expected " << req.outputs.size() << ", got " << data.size());
      return false;
    }
    const uint8_t hf_version = m_hardfork->get_current_version();
    for (const auto &out: data)
    {
      res.outs.push_back({out.otk, out.commitment, is_tx_spendtime_unlocked(out.unlock_time, hf_version), out.height, out.tx_hash});
    }

    
  }
  catch (const std::exception &e)
  {
    return false;
  }
  return true;
}

//------------------------------------------------------------------
bool Blockchain::get_output_distribution( uint64_t from_height, uint64_t to_height, uint64_t &start_height, std::vector<uint64_t> &distribution) const
{
 
  start_height = 0;

  if (to_height > 0 && to_height < from_height)
    return false;

  if (from_height > start_height)
    start_height = from_height;

  uint64_t db_height = m_db->height();
  if (db_height == 0)
    return false;
  if (start_height >= db_height || to_height >= db_height)
    return false;
  
  {
    std::vector<uint64_t> heights;
    heights.reserve(to_height + 1 - start_height);
    const uint64_t real_start_height = start_height > 0 ? start_height-1 : start_height;
    for (uint64_t h = real_start_height; h <= to_height; ++h)
      heights.push_back(h);

    distribution = m_db->get_block_cumulative_rct_outputs(heights);
  
    return true;
  }

}

//------------------------------------------------------------------
difficulty_type Blockchain::block_difficulty(uint64_t i) const
{
  MTRACE("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  try
  {
    return m_db->get_block_difficulty(i);
  }
  catch (const BLOCK_DNE& e)
  {
    MERROR("Attempted to get block difficulty for height above blockchain height");
  }
  return 0;
}

//------------------------------------------------------------------
static bool fill(BlockchainDB *db, const crypto::hash &tx_hash, cryptonote::blobdata &tx, bool pruned)
{
  if (pruned)
  {
    if (!db->get_pruned_tx_blob(tx_hash, tx))
    {
      MDEBUG("Pruned transaction blob not found for " << tx_hash);
      return false;
    }
  }
  else
  {
    if (!db->get_tx_blob(tx_hash, tx))
    {
      MDEBUG("Transaction blob not found for " << tx_hash);
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
static  bool fill_tx_blob_entry(BlockchainDB *db, const crypto::hash &tx_hash, tx_blob_entry & tbe)
{
  blobdata t1,t2;
  if (!db->get_pruned_tx_blob(tx_hash, t1))
    {
      MDEBUG("Pruned transaction blob not found for " << tx_hash);
      return false;
    }

     if (db->get_prunable_tx_blob(tx_hash, t2))
    {
      tbe.blob = t1+t2;
    }
   else if (db->get_prunable_tx_hash(tx_hash, tx.prunable_hash))
    {
      tbe.blob =t1;
    }
    else{
      MDEBUG("Prunable transaction data hash not found for " << tx_hash);
      return false;
    }
  
  return true;
}
//------------------------------------------------------------------
//TODO: return type should be void, throw on exception
//       alternatively, return true only if no transactions missed
bool Blockchain::get_transactions_blobs(const std::vector<crypto::hash>& tx_hashes, std::vector<cryptonote::blobdata>& txs, std::vector<crypto::hash>& missed_txs, bool pruned) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  txs.reserve(tx_hashes.size());
  for (const auto& tx_hash : tx_hashes)
  {
    try
    {
      cryptonote::blobdata tx;
      if (fill(m_db, tx_hash, tx))
        txs.push_back(std::move(tx));
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_transactions_blobs(const std::vector<crypto::hash>& tx_hashes, std::vector<tx_blob_entry>& txs, std::vector<crypto::hash>& missed_txs) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  txs.reserve(tx_hashes.size());
  for (const auto& tx_hash : tx_hashes)
  {
    try
    {
      tx_blob_entry tx;
      if (fill_tx_blob_entry(m_db, tx_hash, tx))
        txs.push_back(std::move(tx));
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
size_t get_transaction_version(const cryptonote::blobdata &bd)
{
  size_t version;
  const char* begin = static_cast<const char*>(bd.data());
  const char* end = begin + bd.size();
  int read = tools::read_varint(begin, end, version);
  if (read <= 0)
    throw std::runtime_error("Internal error getting transaction version");
  return version;
}
//------------------------------------------------------------------
template<class t_ids_container, class t_tx_container, class t_missed_container>
bool Blockchain::get_split_transactions_blobs(const t_ids_container& tx_hashes, t_tx_container& txs, t_missed_container& missed_txs) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  reserve_container(txs, tx_hashes.size());
  for (const auto& tx_hash : tx_hashes)
  {
    try
    {
      cryptonote::blobdata tx_blob;
      if (m_db->get_pruned_tx_blob(tx_hash, tx_blob))
      {
        txs.push_back(std::make_tuple(tx_hash, std::move(tx_blob), crypto::null_hash, cryptonote::blobdata()));
        if ( !m_db->get_prunable_tx_hash(tx_hash, std::get<2>(txs.back())))
        {
          MERROR("Prunable data hash not found for " << tx_hash);
          return false;
        }
        if (!m_db->get_prunable_tx_blob(tx_hash, std::get<3>(txs.back())))
          std::get<3>(txs.back()).clear();
      }
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
// This function takes a list of block hashes from another node
// on the network to find where the split point is between us and them.
// This is used to see what to send another node that needs to sync.
//a,b,c,d
//a,b,x,y,z
uint64_t Blockchain::find_blockchain_split_height(const std::list<crypto::hash>& remote) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // make sure the request includes at least the genesis block, otherwise
  // how can we expect to sync from the client that the block list came from?
  if(remote.empty())
  {
    throw_and_log("Client sent wrong NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << remote.size() << ", dropping connection");
  }

  db_rtxn_guard rtxn_guard(m_db);
  // make sure that the last block in the request's block list matches
  // the genesis block
  auto gen_hash = m_db->get_block_hash_from_height(0);
  if(remote.back() != gen_hash)
  {
    throw_and_log("Client sent wrong NOTIFY_REQUEST_CHAIN: genesis block mismatch: " << std::endl << "id: " << remote.back() << ", " << std::endl << "expected: " << gen_hash << "," << std::endl << " dropping connection");
  }

  // Find the first block the foreign chain has that we also have.
  // Assume remote is in reverse-chronological order.
  uint64_t split_height = 0;
  for(auto& b_hash : remote)
  {
    try
    {
      if (m_db->block_exists(b_hash, &split_height))
        break;
    }
    catch (const std::exception& e)
    {
      throw_and_log("Non-critical error trying to find block by hash in BlockchainDB, hash: " << *bl_it);
    }
  }

  //we start to put block ids INCLUDING last known id, just to make other side be sure
   return split_height;
}
//------------------------------------------------------------------
// Find the split point between us and foreign blockchain and return
// (by reference) the most recent common block hash along with up to
// BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT additional (more recent) hashes.
ChainSyncInfo Blockchain::find_blockchain_sync_info(const std::list<crypto::hash>& remote) const
{
  ChainSyncInfo sync{};
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // if we can't find the split point, return false
  sync.split_height = find_blockchain_split_height(remote);
  
  db_rtxn_guard rtxn_guard(m_db);
  sync.top_height = get_current_blockchain_height();
  uint64_t stop_height = std::min(sync.top_height,sync.split_height+BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT);

  size_t count = 0;
  for(size_t i = split_height; i < stop_height ; i++)
  {
    sync.hashes.push_back(m_db->get_block_hash_from_height(i));
  }

  return sync;
}


//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block& bl, const crypto::hash& h)
{
  MTRACE("Blockchain::" << __func__);
  block_extended_info bei = AUTO_VAL_INIT(bei);
  bei.bl = bl;
  return add_block_as_invalid(bei, h);
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block_extended_info& bei, const crypto::hash& h)
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto i_res = m_invalid_blocks.insert(std::map<crypto::hash, block_extended_info>::value_type(h, bei));
  CHECK_AND_ASSERT_MES(i_res.second, false, "at insertion invalid by tx returned status existed");
  MINFO("BLOCK ADDED AS INVALID: " << h << std::endl << ", prev_id=" << bei.bl.prev_id << ", m_invalid_blocks count=" << m_invalid_blocks.size());
  return true;
}
//------------------------------------------------------------------
void Blockchain::flush_invalid_blocks()
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  m_invalid_blocks.clear();
}
//------------------------------------------------------------------
bool Blockchain::have_block_unlocked(const crypto::hash& b_hash, int *where) const
{
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  MTRACE("Blockchain::" << __func__);

  if(m_db->block_exists(b_hash))
  {
    LOG_PRINT_L2("block " << b_hash << " found in main chain");
    if (where) 
      *where = HAVE_BLOCK_MAIN_CHAIN;
    return true;
  }

  if(m_db->get_alt_block(b_hash, NULL, NULL))
  {
    LOG_PRINT_L2("block " << b_hash << " found in alternative chains");
    if (where)
     *where = HAVE_BLOCK_ALT_CHAIN;
    return true;
  }

  if(m_invalid_blocks.count(b_hash))
  {
    LOG_PRINT_L2("block " << b_hash << " found in m_invalid_blocks");
    if (where) *where = HAVE_BLOCK_INVALID;
    return true;
  }

  return false;
}
//------------------------------------------------------------------
bool Blockchain::have_block(const crypto::hash& id, int *where) const
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return have_block_unlocked(id, where);
}

//------------------------------------------------------------------
size_t Blockchain::get_total_transactions() const
{
  MTRACE("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->get_tx_count();
}
//------------------------------------------------------------------
// This function checks each input in the transaction <tx> to make sure it
// has not been used already, and adds its key to the container <keys_this_block>.
//
// This container should be managed by the code that validates blocks so we don't
// have to store the used keys in a given block in the permanent storage only to
// remove them later if the block fails validation.
bool Blockchain::check_for_double_spend(const transaction& tx, key_images_container& keys_this_block) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  struct add_transaction_input_visitor: public boost::static_visitor<bool>
  {
    key_images_container& m_spent_keys;
    BlockchainDB* m_db;
    add_transaction_input_visitor(key_images_container& spent_keys, BlockchainDB* db) :
      m_spent_keys(spent_keys), m_db(db)
    {
    }
    bool operator()(const txin_to_key& in) const
    {
      const crypto::key_image& ki = in.k_image;

      // attempt to insert the newly-spent key into the container of
      // keys spent this block.  If this fails, the key was spent already
      // in this block, return false to flag that a double spend was detected.
      //
      // if the insert into the block-wide spent keys container succeeds,
      // check the blockchain-wide spent keys container and make sure the
      // key wasn't used in another block already.
      auto r = m_spent_keys.insert(ki);
      if(!r.second || m_db->has_key_image(ki))
      {
        //double spend detected
        return false;
      }

      // if no double-spend detected, return true
      return true;
    }

    bool operator()(const txin_gen& tx) const
    {
      return true;
    }
   
  };

  for (const txin_v& in : tx.vin)
  {
    if(!boost::apply_visitor(add_transaction_input_visitor(keys_this_block, m_db), in))
    {
      LOG_ERROR("Double spend detected!");
      return false;
    }
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(const crypto::hash& tx_hash, size_t n_txes, std::vector<std::vector<uint64_t>>& indexs) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t tx_id;
  if (!m_db->tx_exists(tx_hash, tx_id))
  {
    MERROR_VER("get_tx_outputs_gindexs failed to find transaction with id = " << tx_hash);
    return false;
  }
  indexs = m_db->get_tx_output_indices(tx_id, n_txes);
  CHECK_AND_ASSERT_MES(n_txes == indexs.size(), false, "Wrong indexs size");

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(const crypto::hash& tx_hash, std::vector<uint64_t>& indexs) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t tx_id;
  if (!m_db->tx_exists(tx_hash, tx_id))
  {
    MERROR_VER("get_tx_outputs_gindexs failed to find transaction with id = " << tx_id);
    return false;
  }
  std::vector<std::vector<uint64_t>> indices = m_db->get_tx_output_indices(tx_id, 1);
  CHECK_AND_ASSERT_MES(indices.size() == 1, false, "Wrong indices size");
  indexs = indices.front();
  return true;
}

//------------------------------------------------------------------
bool Blockchain::check_tx_outputs(const transaction& tx, tx_verification_context &tvc) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  const uint8_t hf_version = m_hardfork->get_current_version();

  // in a v2 tx, all outputs must have 0 amount
      for (auto &o: tx.vout) {
        if (o.amount != 0) {
          tvc.m_invalid_output = true;
          return false;
        }
      }


  // from v4, forbid invalid pubkeys
  if (hf_version >= 4) {
    for (const auto &o: tx.vout) {
      if (o.target.type() == typeid(txout_to_key)) {
        const txout_to_key& out_to_key = boost::get<txout_to_key>(o.target);
        if (!crypto::check_key(out_to_key.key)) {
          tvc.m_invalid_output = true;
          return false;
        }
      }
    }
  }



  

  // from v14, allow only CLSAGs
      if (tx.rct_signatures.type <= rct::RCTTypeBulletproof2)
      {
    
        {
          MERROR_VER("Ringct type " << (unsigned)tx.rct_signatures.type << " is not allowed from v" << (HF_VERSION_CLSAG + 1));
          tvc.m_invalid_output = true;
          return false;
        }
      }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimges_as_spent(const transaction &tx) const
{
  MTRACE("Blockchain::" << __func__);
  for (const txin_v& in: tx.vin)
  {
    CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, in_to_key, true);
    if(have_tx_keyimg_as_spent(in_to_key.k_image))
      return true;
  }
  return false;
}
bool Blockchain::expand_transaction_2(transaction &tx, const crypto::hash &tx_prefix_hash, const std::vector<std::vector<rct::ctkey>> &pubkeys) const
{
  PERF_TIMER(expand_transaction_2);
  CHECK_AND_ASSERT_MES(tx.version == 2, false, "Transaction version is not 2");

  rct::rctSig &rv = tx.rct_signatures;

  // message - hash of the transaction prefix
  rv.message = rct::hash2rct(tx_prefix_hash);

   if (rv.type == rct::RCTTypeSimple || rv.type == rct::RCTTypeBulletproof || rv.type == rct::RCTTypeBulletproof2 || rv.type == rct::RCTTypeCLSAG)
  {
    CHECK_AND_ASSERT_MES(!pubkeys.empty() && !pubkeys[0].empty(), false, "empty pubkeys");
   // rv.mixRing.resize(pubkeys.size());
    rv.mixRing=pubkeys;
   /* for (size_t n = 0; n < pubkeys.size(); ++n)
    {
      rv.mixRing[n]= pubkeys[n];
      rv.mixRing[n].clear();
      for (size_t m = 0; m < pubkeys[n].size(); ++m)
      {
        rv.mixRing[n].push_back(pubkeys[n][m]);
      }
    }*/
  }
  else
  {
    CHECK_AND_ASSERT_MES(false, false, "Unsupported rct tx type: " + boost::lexical_cast<std::string>(rv.type));
  }

  // II
 if (rv.type == rct::RCTTypeCLSAG)
  {
    if (!tx.pruned)
    {
      CHECK_AND_ASSERT_MES(rv.p.CLSAGs.size() == tx.vin.size(), false, "Bad CLSAGs size");
      for (size_t n = 0; n < tx.vin.size(); ++n)
      {
        rv.p.CLSAGs[n].I = rct::ki2rct(boost::get<txin_to_key>(tx.vin[n]).k_image);
      }
    }
  }
  else
  {
    CHECK_AND_ASSERT_MES(false, false, "Unsupported rct tx type: " + boost::lexical_cast<std::string>(rv.type));
  }

  // outCommitments was already done by handle_incoming_tx

  return true;
}
//------------------------------------------------------------------
// This function validates transaction inputs and their keys.
// FIXME: consider moving functionality specific to one input into
//        check_tx_input() rather than here, and use this function simply
//        to iterate the inputs as necessary (splitting the task
//        using threads, etc.)
bool Blockchain::check_tx_inputs(transaction& tx, tx_verification_context &tvc) const
{
  PERF_TIMER(check_tx_inputs);
  MTRACE("Blockchain::" << __func__);
  size_t sig_index = 0;
  

  // pruned txes are skipped, as they're only allowed in sync-pruned-blocks mode, which is within the builtin hashes
  if (tx.pruned)
    return true;

  crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);

  const uint8_t hf_version = m_hardfork->get_current_version();


  // from hard fork 2, we require mixin at least 2 unless one output cannot mix with 2 others
  // if one output cannot mix with 2 others, we accept at most 1 output that can mix
    for (const auto& txin : tx.vin)
    {
      // non txin_to_key inputs will be rejected below
      if (txin.type() == typeid(txin_to_key))
      {
        const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);
        {
          // always consider rct inputs mixable. Even if there's not enough rct
          // inputs on the chain to mix with, this is going to be the case for
          // just a few blocks right after the fork at most
          ++n_mixable;
        }
   
        size_t ring_mixin = in_to_key.key_offsets.size() - 1;
        if (ring_mixin <2 || ring_mixin>10)
          return false;
      }
    }
  
  // from v7, sorted ins
  {
    const crypto::key_image *last_key_image = NULL;
    for (size_t n = 0; n < tx.vin.size(); ++n)
    {
      const txin_v &txin = tx.vin[n];
      if (txin.type() == typeid(txin_to_key))
      {
        const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);
        if (last_key_image && memcmp(&in_to_key.k_image, last_key_image, sizeof(*last_key_image)) >= 0)
        {
          MERROR_VER("transaction has unsorted inputs");
          tvc.m_verifivation_failed = true;
          return false;
        }
        last_key_image = &in_to_key.k_image;
      }
    }
  }

  std::vector<std::vector<rct::ctkey>> pubkeys(tx.vin.size());
  std::vector < uint64_t > results;
  results.resize(tx.vin.size(), 0);

  for (const auto& txin : tx.vin)
  {
    // make sure output being spent is of type txin_to_key, rather than
    // e.g. txin_gen, which is only used for miner transactions
    CHECK_AND_ASSERT_MES(txin.type() == typeid(txin_to_key), false, "wrong type id in tx input at Blockchain::check_tx_inputs");
    const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);

    // make sure tx output has key offset(s) (is signed to be used)
    CHECK_AND_ASSERT_MES(in_to_key.key_offsets.size(), false, "empty in_to_key.key_offsets in transaction with id " << get_transaction_hash(tx));

    if(have_tx_keyimg_as_spent(in_to_key.k_image))
    {
      MERROR_VER("Key image already spent in blockchain: " << epee::string_tools::pod_to_hex(in_to_key.k_image));
      tvc.m_double_spend = true;
      return false;
    }

    // make sure that output being spent matches up correctly with the
    // signature spending it.
    auto & decoys = pubkeys[sig_index];
    if (!check_tx_input(tx.version, in_to_key, tx_prefix_hash, tx.rct_signatures, decoys,  hf_version))
    {
      MERROR_VER("Failed to check ring signature for tx " << get_transaction_hash(tx) << "  vin key with k_image: " << in_to_key.k_image << "  sig_index: " << sig_index);
     
      return false;
    }

    sig_index++;
  }
 

  {
    if (!expand_transaction_2(tx, tx_prefix_hash, pubkeys))
    {
      MERROR_VER("Failed to expand rct signatures!");
      return false;
    }

    // from version 2, check ringct signatures
    // obviously, the original and simple rct APIs use a mixRing that's indexes
    // in opposite orders, because it'd be too simple otherwise...
    const rct::rctSig &rv = tx.rct_signatures;
    switch (rv.type)
    {
    case rct::RCTTypeNull: {
      // we only accept no signatures for coinbase txes
      MERROR_VER("Null rct signature on non-coinbase tx");
      return false;
    }
    case rct::RCTTypeSimple:
    case rct::RCTTypeBulletproof:
    case rct::RCTTypeBulletproof2:
    case rct::RCTTypeCLSAG:
    {
      // check all this, either reconstructed (so should really pass), or not
      {
        if (pubkeys.size() != rv.mixRing.size())
        {
          MERROR_VER("Failed to check ringct signatures: mismatched pubkeys/mixRing size");
          return false;
        }
        for (size_t i = 0; i < pubkeys.size(); ++i)
        {
          if (pubkeys[i].size() != rv.mixRing[i].size())
          {
            MERROR_VER("Failed to check ringct signatures: mismatched pubkeys/mixRing size");
            return false;
          }
        }

        for (size_t n = 0; n < pubkeys.size(); ++n)
        {
          for (size_t m = 0; m < pubkeys[n].size(); ++m)
          {
            if (pubkeys[n][m].otk != rct::rct2pk(rv.mixRing[n][m].otk))
            {
              MERROR_VER("Failed to check ringct signatures: mismatched pubkey at vin " << n << ", index " << m);
              return false;
            }
            if (pubkeys[n][m].commitment != rct::rct2pk(rv.mixRing[n][m].commitment))
            {
              MERROR_VER("Failed to check ringct signatures: mismatched commitment at vin " << n << ", index " << m);
              return false;
            }
          }
        }
      }

      const size_t n_sigs =  rv.p.CLSAGs.size();
      if (n_sigs != tx.vin.size())
      {
        MERROR_VER("Failed to check ringct signatures: mismatched MGs/vin sizes");
        return false;
      }
      for (size_t n = 0; n < tx.vin.size(); ++n)
      {
        bool error = memcmp(&boost::get<txin_to_key>(tx.vin[n]).k_image, &rv.p.CLSAGs[n].I, 32);
    
        if (error)
        {
          MERROR_VER("Failed to check ringct signatures: mismatched key image");
          return false;
        }
      }

      if (!rct::verRctNonSemanticsSimple(rv))
      {
        MERROR_VER("Failed to check ringct signatures!");
        return false;
      }
      break;
    }
   
    default:
      MERROR_VER("Unsupported rct type: " << rv.type);
      return false;
    }

  
  }
  return true;
}

//------------------------------------------------------------------
void Blockchain::check_ring_signature(const crypto::hash &tx_prefix_hash, const crypto::key_image &key_image, const std::vector<rct::ctkey> &pubkeys, const std::vector<crypto::signature>& sig, uint64_t &result) const
{
  std::vector<const crypto::public_key *> p_output_keys;
  p_output_keys.reserve(pubkeys.size());
  for (auto &key : pubkeys)
  {
    // rct::key and crypto::public_key have the same structure, avoid object ctor/memcpy
    p_output_keys.push_back(&(const crypto::public_key&)key.otk);
  }

  result = crypto::check_ring_signature(tx_prefix_hash, key_image, p_output_keys, sig.data()) ? 1 : 0;
}


//------------------------------------------------------------------
bool Blockchain::check_fee(size_t tx_weight, uint64_t fee) const
{

   const uint64_t needed_fee= BASE_FEE;
  if (fee < BASE_FEE) {
    MERROR_VER("transaction fee is not enough: " << print_money(fee) << ", minimum fee: " << print_money(needed_fee));
    return false;
  }
  return true;
}
//------------------------------------------------------------------
// This function checks to see if a tx is unlocked.  unlock_time is either
// a block index or a unix time.
bool Blockchain::is_tx_spendtime_unlocked(uint64_t unlock_time, uint8_t _) const
{
  MTRACE("Blockchain::" << __func__);
  if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
  {
    // ND: Instead of calling get_current_blockchain_height(), call m_db->height()
    //    directly as get_current_blockchain_height() locks the recursive mutex.
    if(m_db->height()-1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
      return true;
    else
      return false;
  }
  else
  {
    //interpret as time
    const uint64_t current_time =  static_cast<uint64_t>(time(NULL));
    if(current_time +  CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS >= unlock_time)
      return true;
    else
      return false;
  }
  return false;
}
//------------------------------------------------------------------
// This function locates all outputs associated with a given input (mixins)
// and validates that they exist and are usable.  It also checks the ring
// signature for each input.
bool Blockchain::check_tx_input(size_t tx_version, const txin_to_key& txin, const crypto::hash& tx_prefix_hash,const rct::rctSig &rct_signatures, std::vector<rct::ctkey> &decoys, uint8_t hf_version) const
{
  MTRACE("Blockchain::" << __func__);

  // ND:
  // 1. Disable locking and make method private.
  //CRITICAL_REGION_LOCAL(m_blockchain_lock);

  struct outputs_visitor
  {
    std::vector<rct::ctkey >& m_output_keys;
    const Blockchain& m_bch;
    const uint8_t hf_version;
    outputs_visitor(std::vector<rct::ctkey>& decoys, const Blockchain& bch, uint8_t hf_version) :
      m_output_keys(decoys), m_bch(bch), hf_version(hf_version)
    {
    }
    bool handle_output(uint64_t unlock_time, const crypto::public_key &otk, const rct::key &commitment)
    {
      //check tx unlock time
      if (!m_bch.is_tx_spendtime_unlocked(unlock_time, hf_version))
      {
        MERROR_VER("One of outputs for one of inputs has wrong tx.unlock_time = " << unlock_time);
        return false;
      }

      // The original code includes a check for the output corresponding to this input
      // to be a txout_to_key. This is removed, as the database does not store this info,
      // but only txout_to_key outputs are stored in the DB in the first place, done in
      // Blockchain*::add_output

      m_output_keys.push_back(rct::ctkey({rct::pk2rct(otk), commitment}));
      return true;
    }
  };

  decoys.clear();

  // collect output keys
  outputs_visitor vi(decoys, *this, hf_version);
  if (!scan_outputkeys_for_indexes(tx_version, txin, vi, tx_prefix_hash))
  {
    MERROR_VER("Failed to get output keys for tx with amount = " << print_money(txin.amount) << " and count indexes " << txin.key_offsets.size());
    return false;
  }

  if(txin.key_offsets.size() != decoys.size())
  {
    MERROR_VER("Output keys for tx with amount = " << txin.amount << " and count indexes " << txin.key_offsets.size() << " returned wrong keys count " << decoys.size());
    return false;
  }

  // rct_signatures will be expanded after this
  return true;
}
//------------------------------------------------------------------
// only works on the main chain
uint64_t Blockchain::get_adjusted_time(uint64_t height) const
{
  MTRACE("Blockchain::" << __func__);

  // if not enough blocks, no proper median yet, return current time
  if(height < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW)
  {
      return static_cast<uint64_t>(time(NULL));
  }
  std::vector<uint64_t> timestamps;

  // need most recent 60 blocks, get index of first of those
  size_t offset = height - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
  timestamps.reserve(height - offset);
  for(;offset < height; ++offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
  }
  uint64_t median_ts = epee::misc_utils::median(timestamps);

  // project the median to match approximately when the block being validated will appear
  // the median is calculated from a chunk of past blocks, so we use +1 to offset onto the current block
  median_ts += (BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 1) * DIFFICULTY_TARGET / 2;

  // project the current block's time based on the previous block's time
  // we don't use the current block's time directly to mitigate timestamp manipulation
  uint64_t adjusted_current_block_ts = timestamps.back() + DIFFICULTY_TARGET;

  // return minimum of ~current block time and adjusted median time
  // we do this since it's better to report a time in the past than a time in the future
  return (adjusted_current_block_ts < median_ts ? adjusted_current_block_ts : median_ts);
}
//------------------------------------------------------------------
//TODO: revisit, has changed a bit on upstream
bool Blockchain::check_block_timestamp(std::vector<uint64_t>& timestamps, const block& b, uint64_t& median_ts) const
{
  MTRACE("Blockchain::" << __func__);
  median_ts = epee::misc_utils::median(timestamps);

  if(b.timestamp < median_ts)
  {
    MERROR_VER("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", less than median of last " << BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW << " blocks, " << median_ts);
    return false;
  }

  return true;
}
//------------------------------------------------------------------
// This function grabs the timestamps from the most recent <n> blocks,
// where n = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.  If there are not those many
// blocks in the blockchain, the timestap is assumed to be valid.  If there
// are, this function returns:
//   true if the block's timestamp is not less than the timestamp of the
//       median of the selected blocks
//   false otherwise
bool Blockchain::check_block_timestamp(const block& b, uint64_t& median_ts) const
{
  MTRACE("Blockchain::" << __func__);
  if(b.timestamp > (uint64_t)time(NULL) + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT)
  {
    MERROR_VER("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", bigger than local time + 2 hours");
    return false;
  }

  const auto h = m_db->height();

  // if not enough blocks, no proper median yet, return true
  if(h < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW)
  {
    return true;
  }

  std::vector<uint64_t> timestamps;

  // need most recent 60 blocks, get index of first of those
  size_t offset = h - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
  timestamps.reserve(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW/*h - offset*/);
  for(;offset < h; ++offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
  }

  return check_block_timestamp(timestamps, b, median_ts);
}
//------------------------------------------------------------------
void Blockchain::return_tx_to_pool(std::vector<std::pair<transaction, blobdata>> &txs)
{
  uint8_t version = get_current_hard_fork_version();
  for (auto& tx : txs)
  {
    cryptonote::tx_verification_context tvc{};
    // We assume that if they were in a block, the transactions are already
    // known to the network as a whole. However, if we had mined that block,
    // that might not be always true. Unlikely though, and always relaying
    // these again might cause a spike of traffic as many nodes re-relay
    // all the transactions in a popped block when a reorg happens.
    const size_t weight = get_transaction_weight(tx.first);
    const crypto::hash tx_hash = get_transaction_hash(tx.first);
    if (!m_tx_pool.add_tx(tx.first, tx_hash, tx.second, weight, tvc, relay_method::block, true, version))
    {
      MERROR("Failed to return taken transaction with hash: " << get_transaction_hash(tx.first) << " to tx_pool");
    }
  }
}

block_verification_context Blockchain::validate_sync_block(const BlobBlock& bb, std::vector<BlobTx> &tx_ps){

  block_verification_context bvc{};

  db_rtxn_guard rtxn_guard(m_db);

  const auto chain_height= m_db.height();
  const auto top_hash = chain_height==0 ? null_hash : get_top_hash();
  const auto new_b_height=chain_height;
  const auto & bl = bb.b;
  if(bl.prev_id != top_hash)
  {
    MERROR_VER("Block with id: " << id << std::endl << "has wrong prev_id: " << bl.prev_id << std::endl << "expected: " << top_hash);
    bvc.m_verifivation_failed = true;

    return bvc;
  }

  // make sure block timestamp is not less than the median timestamp
  // of a set number of the most recent blocks.
  if(!check_block_timestamp(bl))
  {
    MERROR_VER("Block with id: " << id << std::endl << "has invalid timestamp: " << bl.timestamp);
    bvc.m_verifivation_failed = true;
    return bvc;
  }

  // get the target difficulty for the block.
  // the calculation can overflow, among other failure cases,
  // so we need to check the return type.
  // FIXME: get_blockchain_diff can also assert, look into
  // changing this to throwing exceptions instead so we can clean up.
  const difficulty_type block_diff = get_blockchain_diff();

  const auto pow = get_block_pow(this, bl, new_b_height);
  if(!check_hash(pow, block_diff))
  {
    MERROR_VER("Block with id: " << id << std::endl << "does not have enough proof of work: " << pow << " at height " << new_b_height << ", unexpected difficulty: " << block_diff);
    bvc.m_verifivation_failed = true;
    bvc.m_bad_pow = true;
    return bvc;
  }

  // sanity check basic miner tx properties;
  if(!prevalidate_miner_transaction(bl, new_b_height, hf_version))
  {
    MERROR_VER("Block with id: " << id << " failed to pass prevalidation");
    bvc.m_verifivation_failed = true;
    return bvc;
  }

  if(bl.tx_hashes.size()!=tx_ps.size()){
     bvc.m_verifivation_failed = true;
    return bvc;
  }

  uint64_t fee=0;
 for (const auto& tx_hash : bl.tx_hashes)
  {
    transaction tx_tmp;
    blobdata txblob;
  // XXX old code does not check whether tx exists
    if (m_db->tx_exists(tx_hash))
    {
      MERROR("Block with id: " << id << " attempting to add transaction already in blockchain with id: " << tx_hash);
      bvc.m_verifivation_failed = true;
      return bvc;
    }

    // get transaction with hash <tx_hash> from tx_pool
    if(!m_tx_pool.have_tx(tx_hash, relay_category::all))
    {
      MERROR_VER("Block with id: " << id  << " has at least one unknown transaction with id: " << tx_hash);
      bvc.m_verifivation_failed = true;
      return bvc;
    }

    fee += tx.fee();
  }

  uint64_t base_reward = 0;

  if(!validate_miner_transaction(bl,  fee, base_reward,  m_hardfork->get_current_version()))
  {
    MERROR_VER("Block with id: " << id << " has incorrect miner transaction");
    bvc.m_verifivation_failed = true;
    return bvc;
  }

  for(auto & e : tx_ps){
    const auto & h2= get_transaction_hash(e.tx);
    if(std::find(bl.tx_hashes.begin(),bl.tx_hashes.end(),h2)==b.tx_hashes.end()){
      MERROR("cannot find tx hash in block"<<h2);
       bvc.m_verifivation_failed = true;
        return bvc;
    }
  }
  return bvc;

}
block_verification_context Blockchain::validate_block(const block &bl){
  block_verification_context bvc{};

  db_rtxn_guard rtxn_guard(m_db);

  const auto chain_height= m_db.height();
  const auto top_hash = chain_height==0 ? null_hash : get_top_hash();
  const auto new_b_height=chain_height;
  if(bl.prev_id != top_hash)
  {
    MERROR_VER("Block with id: " << id << std::endl << "has wrong prev_id: " << bl.prev_id << std::endl << "expected: " << top_hash);
    bvc.m_verifivation_failed = true;

    return bvc;
  }

  // make sure block timestamp is not less than the median timestamp
  // of a set number of the most recent blocks.
  if(!check_block_timestamp(bl))
  {
    MERROR_VER("Block with id: " << id << std::endl << "has invalid timestamp: " << bl.timestamp);
    bvc.m_verifivation_failed = true;
    return bvc;
  }

  // get the target difficulty for the block.
  // the calculation can overflow, among other failure cases,
  // so we need to check the return type.
  // FIXME: get_blockchain_diff can also assert, look into
  // changing this to throwing exceptions instead so we can clean up.
  const difficulty_type block_diff = get_blockchain_diff();

  const auto pow = get_block_pow(this, bl, new_b_height);
  if(!check_hash(pow, block_diff))
  {
    MERROR_VER("Block with id: " << id << std::endl << "does not have enough proof of work: " << pow << " at height " << new_b_height << ", unexpected difficulty: " << block_diff);
    bvc.m_verifivation_failed = true;
    bvc.m_bad_pow = true;
    return bvc;
  }

  // sanity check basic miner tx properties;
  if(!prevalidate_miner_transaction(bl, new_b_height, hf_version))
  {
    MERROR_VER("Block with id: " << id << " failed to pass prevalidation");
    bvc.m_verifivation_failed = true;
    return bvc;
  }
  uint64_t fee=0;
 for (const auto& tx_hash : bl.tx_hashes)
  {
    transaction tx_tmp;
    blobdata txblob;
  // XXX old code does not check whether tx exists
    if (m_db->tx_exists(tx_hash))
    {
      MERROR("Block with id: " << id << " attempting to add transaction already in blockchain with id: " << tx_hash);
      bvc.m_verifivation_failed = true;
      return bvc;
    }

    // get transaction with hash <tx_hash> from tx_pool
    if(!m_tx_pool.have_tx(tx_hash, relay_category::all))
    {
      MERROR_VER("Block with id: " << id  << " has at least one unknown transaction with id: " << tx_hash);
      bvc.m_verifivation_failed = true;
      return bvc;
    }

    fee += tx.fee();
  }

  uint64_t base_reward = 0;

  if(!validate_miner_transaction(bl,  fee, base_reward,  m_hardfork->get_current_version()))
  {
    MERROR_VER("Block with id: " << id << " has incorrect miner transaction");
    bvc.m_verifivation_failed = true;
    return bvc;
  }
  return bvc;
}

//------------------------------------------------------------------
bool Blockchain::handle_block_to_main_chain(const block& bl, block_verification_context& bvc, bool notify/* = true*/)
{
  MTRACE("Blockchain::" << __func__);
  const crypto::hash id = get_block_hash(bl);

  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  const auto chain_height= m_db.height();
  const auto top_hash = chain_height==0 ? null_hash : get_top_hash();
  const auto new_b_height=chain_height;
 
  bvc = validate_block(bl);
  std::vector<std::pair<transaction, blobdata>> txs;

  // Iterate over the block's transaction hashes, grabbing each
  // from the tx_pool and validating them.  Each is then added
  // to txs.  Keys spent in each are added to <keys> by the double spend check.
  txs.reserve(bl.tx_hashes.size());
  for (const auto& tx_hash : bl.tx_hashes)
  {
    transaction tx_tmp;
    blobdata txblob;
    // get transaction with hash <tx_hash> from tx_pool
    if(!m_tx_pool.pop_tx(tx_hash, tx_tmp, txblob))
    {
      MERROR_VER("Block with id: " << id  << " has at least one unknown transaction with id: " << tx_hash);
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      goto leave;
    }

    // add the transaction to the temp list of transactions, so we can either
    // store the list of transactions all at once or return the ones we've
    // taken from the tx_pool back to it if the block fails verification.
    txs.push_back(std::make_pair(std::move(tx_tmp), std::move(txblob)));
    transaction &tx = txs.back().first;
  }

   // populate various metadata about the block to be stored alongside it.
    try
    {
      cryptonote::blobdata bd = cryptonote::block_to_blob(bl);
      MDEBUG("add_block hex "<<string_tools::buff_to_hex_nodelimer(bd));
      const difficulty_type block_diff = get_blockchain_diff();
     m_db->add_block(std::make_pair(std::move(bl), std::move(bd)),  block_diff, txs);

    }
    catch (const std::exception& e)
    {
      //TODO: figure out the best way to deal with this failure
      LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      return false;
    }

  MINFO("add block" << std::endl << "id: " << id << std::endl << "PoW: " << pow << std::endl << "HEIGHT " << new_b_height << ", block_diff: " << block_diff <<std::endl << "block reward: " << print_money(get_outs_money_amount(bl))  << ", block weight: " << block_weight) ;


  bvc.m_added_to_main_chain = true;

  for (const auto& notifier: m_block_notifiers)
    notifier(new_b_height, {std::addressof(bl), 1});

  return true;
}
//------------------------------------------------------------------
bool Blockchain::prune_blockchain(uint32_t pruning_seed)
{
  m_tx_pool.lock();
  epee::misc_utils::auto_scope_leave_caller unlocker = epee::misc_utils::create_scope_leave_handler([&](){m_tx_pool.unlock();});
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  return m_db->prune_blockchain(pruning_seed);
}
//------------------------------------------------------------------
bool Blockchain::update_blockchain_pruning()
{
  m_tx_pool.lock();
  epee::misc_utils::auto_scope_leave_caller unlocker = epee::misc_utils::create_scope_leave_handler([&](){m_tx_pool.unlock();});
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  return m_db->update_pruning();
}
//------------------------------------------------------------------
bool Blockchain::check_blockchain_pruning()
{
  m_tx_pool.lock();
  epee::misc_utils::auto_scope_leave_caller unlocker = epee::misc_utils::create_scope_leave_handler([&](){m_tx_pool.unlock();});
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  return m_db->check_pruning();
}
//------------------------------------------------------------------

//------------------------------------------------------------------
bool Blockchain::add_new_block(const block& bl, block_verification_context& bvc)
{
  try
  {

  MTRACE("Blockchain::" << __func__);
  crypto::hash id = get_block_hash(bl);
  CRITICAL_REGION_LOCAL(m_tx_pool);//to avoid deadlock lets lock tx_pool for whole add/reorganize process
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);
  db_rtxn_guard rtxn_guard(m_db);
  if(have_block(id))
  {
    MTRACE("block with id = " << id << " already exists");
    bvc.m_already_exists = true;
    return false;
  }

  //check that block refers to chain tail
  if(bl.prev_id != get_top_hash())
  {
    //chain switching or wrong block
    bvc.m_added_to_main_chain = false;
    rtxn_guard.stop();
    bool r = handle_alternative_block(bl, bvc);
    return r;
    //never relay alternative blocks
  }

  rtxn_guard.stop();
  return handle_block_to_main_chain(bl,  bvc);

  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Exception at [add_new_block], what=" << e.what());
    bvc.m_verifivation_failed = true;
    return false;
  }
}
block_verification_context  Blockchain::add_sync_block(const std::pair<block,blobdata>& b_p, std::vector<std::pair<transaction, blobdata>> &txs )
{
  block_verification_context bvc;
  try
  {

  CRITICAL_REGION_LOCAL(m_blockchain_lock);

    bvc = validate_block(bl);
    if(bvc.m_verifivation_failed)
      return bvc;
 
      const difficulty_type block_diff = get_blockchain_diff();
     m_db->add_block(b_p, block_diff, txs);

    MINFO("add sync block" << "HEIGHT " << new_b_height << ", block_diff: " << block_diff <<std::endl );
    bvc.m_added_to_main_chain = true;
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Exception at [add_new_block], what=" << e.what());
    bvc.m_verifivation_failed = true;
    return false;
  }

}
//------------------------------------------------------------------
//TODO: Refactor, consider returning a failure height and letting
//      caller decide course of action.
void Blockchain::check_against_checkpoints(const checkpoints& points, bool enforce)
{
  const auto& pts = points.get_points();
  bool stop_batch;

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  stop_batch = m_db->batch_start();
  const uint64_t blockchain_height = m_db->height();
  for (const auto& pt : pts)
  {
    // if the checkpoint is for a block we don't have yet, move on
    if (pt.first >= blockchain_height)
    {
      continue;
    }

    if (!points.check_block(pt.first, m_db->get_block_hash_from_height(pt.first)))
    {
      // if asked to enforce checkpoints, roll back to a couple of blocks before the checkpoint
      if (enforce)
      {
        LOG_ERROR("Local blockchain failed to pass a checkpoint, rolling back!");
        std::list<block> empty;
        rollback_blockchain_switching(empty, pt.first - 2);
      }
      else
      {
        LOG_ERROR("WARNING: local blockchain failed to pass a MoneroPulse checkpoint, and you could be on a fork. You should either sync up from scratch, OR download a fresh blockchain bootstrap, OR enable checkpoint enforcing with the --enforce-dns-checkpointing command-line option");
      }
    }
  }
  if (stop_batch)
    m_db->batch_stop();
}
//------------------------------------------------------------------
// returns false if any of the checkpoints loading returns false.
// That should happen only if a checkpoint is added that conflicts
// with an existing checkpoint.
bool Blockchain::update_checkpoints(const std::string& file_path, bool check_dns)
{
  if (!m_checkpoints.load_checkpoints_from_json(file_path))
  {
      return false;
  }


  check_against_checkpoints(m_checkpoints, true);

  return true;
}


uint64_t Blockchain::prevalidate_block_hashes(uint64_t height, const std::vector<crypto::hash> &hashes)
{
  // new: . . . . . X X X X X . . . . . .
  // pre: A A A A B B B B C C C C D D D D


  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // easy case: height >= hashes
  if (height >= m_blocks_hash_of_hashes.size() * HASH_OF_HASHES_STEP)
    return hashes.size();

  // if we're getting old blocks, we might have jettisoned the hashes already
  if (m_blocks_hash_check.empty())
    return hashes.size();

  // find hashes encompassing those block
  size_t first_index = height / HASH_OF_HASHES_STEP;
  size_t last_index = (height + hashes.size() - 1) / HASH_OF_HASHES_STEP;
  MDEBUG("Blocks " << height << " - " << (height + hashes.size() - 1) << " start at " << first_index << " and end at " << last_index);

  // case of not enough to calculate even a single hash
  if (first_index == last_index && hashes.size() < HASH_OF_HASHES_STEP && (height + hashes.size()) % HASH_OF_HASHES_STEP)
    return hashes.size();

  // build hashes vector to hash hashes together
  std::vector<crypto::hash> data_hashes;
  data_hashes.reserve(hashes.size() + HASH_OF_HASHES_STEP - 1); // may be a bit too much

  // we expect height to be either equal or a bit below db height
  bool disconnected = (height > m_db->height());
  size_t pop;
  if (disconnected && height % HASH_OF_HASHES_STEP)
  {
    ++first_index;
    pop = HASH_OF_HASHES_STEP - height % HASH_OF_HASHES_STEP;
  }
  else
  {
    // we might need some already in the chain for the first part of the first hash
    for (uint64_t h = first_index * HASH_OF_HASHES_STEP; h < height; ++h)
    {
      data_hashes.push_back(m_db->get_block_hash_from_height(h));
    }
    pop = 0;
  }

  // push the data to check
  for (size_t i = 0; i < hashes.size(); ++i)
  {
    if (pop)
      --pop;
    else
    {
      data_hashes.push_back(hashes[i]);
    }
  }

  // hash and check
  uint64_t usable = first_index * HASH_OF_HASHES_STEP - height; // may start negative, but unsigned under/overflow is not UB
  for (size_t n = first_index; n <= last_index; ++n)
  {
    if (n < m_blocks_hash_of_hashes.size())
    {
      // if the last index isn't fully filled, we can't tell if valid
      if (data_hashes.size() < (n - first_index) * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP)
        break;

      crypto::hash hash;
      cn_fast_hash(data_hashes.data() + (n - first_index) * HASH_OF_HASHES_STEP, HASH_OF_HASHES_STEP * sizeof(crypto::hash), hash);
      bool valid = hash == m_blocks_hash_of_hashes[n].first;
      if (valid && !weights.empty())
      {
        cn_fast_hash(data_weights.data() + (n - first_index) * HASH_OF_HASHES_STEP, HASH_OF_HASHES_STEP * sizeof(uint64_t), hash);
        valid &= hash == m_blocks_hash_of_hashes[n].second;
      }

      // add to the known hashes array
      if (!valid)
      {
        MDEBUG("invalid hash for blocks " << n * HASH_OF_HASHES_STEP << " - " << (n * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP - 1));
        break;
      }

      size_t end = n * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP;
      for (size_t i = n * HASH_OF_HASHES_STEP; i < end; ++i)
      {
        CHECK_AND_ASSERT_MES(m_blocks_hash_check[i].first == crypto::null_hash || m_blocks_hash_check[i].first == data_hashes[i - first_index * HASH_OF_HASHES_STEP],
            0, "Consistency failure in m_blocks_hash_check construction");
        m_blocks_hash_check[i].first = data_hashes[i - first_index * HASH_OF_HASHES_STEP];
        if (!weights.empty())
        {
          CHECK_AND_ASSERT_MES(m_blocks_hash_check[i].second == 0 || m_blocks_hash_check[i].second == data_weights[i - first_index * HASH_OF_HASHES_STEP],
              0, "Consistency failure in m_blocks_hash_check construction");
          m_blocks_hash_check[i].second = data_weights[i - first_index * HASH_OF_HASHES_STEP];
        }
      }
      usable += HASH_OF_HASHES_STEP;
    }
    else
    {
      // if after the end of the precomputed blocks, accept anything
      usable += HASH_OF_HASHES_STEP;
      if (usable > hashes.size())
        usable = hashes.size();
    }
  }
  MDEBUG("usable: " << usable << " / " << hashes.size());
  CHECK_AND_ASSERT_MES(usable < std::numeric_limits<uint64_t>::max() / 2, 0, "usable is negative");
  return usable;
}

bool Blockchain::has_block_weights(uint64_t height, uint64_t nblocks) const
{
  CHECK_AND_ASSERT_MES(nblocks > 0, false, "nblocks is 0");
  uint64_t last_block_height = height + nblocks - 1;
  if (last_block_height >= m_blocks_hash_check.size())
    return false;
  for (uint64_t h = height; h <= last_block_height; ++h)
    if (m_blocks_hash_check[h].second == 0)
      return false;
  return true;
}

void Blockchain::add_txpool_tx(const crypto::hash &txid, const cryptonote::blobdata &blob, const txpool_tx_meta_t &meta)
{
  m_db->add_txpool_tx(txid, blob, meta);
}

void Blockchain::update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t &meta)
{
  m_db->update_txpool_tx(txid, meta);
}

void Blockchain::remove_txpool_tx(const crypto::hash &txid)
{
  m_db->remove_txpool_tx(txid);
}

uint64_t Blockchain::get_txpool_tx_count(bool include_sensitive) const
{
  return m_db->get_txpool_tx_count(include_sensitive ? relay_category::all : relay_category::broadcasted);
}

bool Blockchain::get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const
{
  return m_db->get_txpool_tx_meta(txid, meta);
}

bool Blockchain::get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata &bd, relay_category tx_category) const
{
  return m_db->get_txpool_tx_blob(txid, bd, tx_category);
}

cryptonote::blobdata Blockchain::get_txpool_tx_blob(const crypto::hash& txid, relay_category tx_category) const
{
  return m_db->get_txpool_tx_blob(txid, tx_category);
}

bool Blockchain::for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::blobdata_ref*)> f, bool include_blob, relay_category tx_category) const
{
  return m_db->for_all_txpool_txes(f, include_blob, tx_category);
}

bool Blockchain::txpool_tx_matches_category(const crypto::hash& tx_hash, relay_category category)
{
  return m_db->txpool_tx_matches_category(tx_hash, category);
}


void Blockchain::add_block_notify(boost::function<void(std::uint64_t, epee::span<const block>)>&& notify)
{
  if (notify)
  {
    CRITICAL_REGION_LOCAL(m_blockchain_lock);
    m_block_notifiers.push_back(std::move(notify));
  }
}



HardFork::State Blockchain::get_hard_fork_state() const
{
  return m_hardfork->get_state();
}

bool Blockchain::get_hard_fork_voting_info(uint8_t version, uint32_t &window, uint32_t &votes, uint32_t &threshold, uint64_t &earliest_height, uint8_t &voting) const
{
  return m_hardfork->get_voting_info(version, window, votes, threshold, earliest_height, voting);
}

uint64_t Blockchain::get_difficulty_target() const
{
  return DIFFICULTY_TARGET;
}


std::vector<std::pair<Blockchain::block_extended_info,std::vector<crypto::hash>>> Blockchain::get_alternative_chains() const
{
  std::vector<std::pair<Blockchain::block_extended_info,std::vector<crypto::hash>>> chains;

  blocks_ext_by_hash alt_blocks;
  alt_blocks.reserve(m_db->get_alt_block_count());
  m_db->for_all_alt_blocks([&alt_blocks](const crypto::hash &blkid, const cryptonote::alt_block_data_t &data, const cryptonote::blobdata_ref *blob) {
    if (!blob)
    {
      MERROR("No blob, but blobs were requested");
      return false;
    }
    cryptonote::block bl;
    block_extended_info bei;
    bei.bl=cryptonote::parse_block_from_blob(*blob);
    {
      bei.height = data.height;
      bei.block_cumulative_weight = data.cumulative_weight;
      bei.cum_diff = data.cumulative_difficulty_high;
      bei.cum_diff = (bei.cum_diff << 64) + data.cumulative_difficulty_low;
      bei.already_generated_coins = data.already_generated_coins;
      alt_blocks.insert(std::make_pair(cryptonote::get_block_hash(bei.bl), std::move(bei)));
    }

    return true;
  }, true);

  for (const auto &i: alt_blocks)
  {
    const crypto::hash top = cryptonote::get_block_hash(i.second.bl);
    bool found = false;
    for (const auto &j: alt_blocks)
    {
      if (j.second.bl.prev_id == top)
      {
        found = true;
        break;
      }
    }
    if (!found)
    {
      std::vector<crypto::hash> chain;
      auto h = i.second.bl.prev_id;
      chain.push_back(top);
      blocks_ext_by_hash::const_iterator prev;
      while ((prev = alt_blocks.find(h)) != alt_blocks.end())
      {
        chain.push_back(h);
        h = prev->second.bl.prev_id;
      }
      chains.push_back(std::make_pair(i.second, chain));
    }
  }
  return chains;
}



void Blockchain::lock()
{
  m_blockchain_lock.lock();
}

void Blockchain::unlock()
{
  m_blockchain_lock.unlock();
}

bool Blockchain::for_all_key_images(std::function<bool(const crypto::key_image&)> f) const
{
  return m_db->for_all_key_images(f);
}

bool Blockchain::for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const crypto::hash&, const block&)> f) const
{
  return m_db->for_blocks_range(h1, h2, f);
}

bool Blockchain::for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)> f) const
{
  return m_db->for_all_transactions(f);
}

bool Blockchain::for_all_outputs(  const uint64_t start_height,std::function<bool(uint64_t,const output_data_t&)> f) const
{
  return m_db->for_all_outputs(start_height, f);
}


#include "blockchain_block_template.inl"

namespace cryptonote {
template bool Blockchain::get_transactions(const std::vector<crypto::hash>&, std::vector<transaction>&, std::vector<crypto::hash>&) const;
template bool Blockchain::get_split_transactions_blobs(const std::vector<crypto::hash>&, std::vector<std::tuple<crypto::hash, cryptonote::blobdata, crypto::hash, cryptonote::blobdata>>&, std::vector<crypto::hash>&) const;
}

