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
#include "chain_util.h"
#include "alt_chain.h"

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
uint64_t Blockchain::get_chain_height() const
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
 
  db_rtxn_guard rtxn_guard(m_db);

  // check how far behind we are
  uint64_t top_block_timestamp = m_db->get_top_block_timestamp();
  uint64_t timestamp_diff = time(NULL) - top_block_timestamp;

  // genesis block has no timestamp, could probably change it to have timestamp of 1397818133...
  if(!top_block_timestamp)
    timestamp_diff = time(NULL) - 1397818133;

  MINFO("Blockchain initialized. last block: " << m_db->height() - 1 << ", " << epee::misc_utils::get_time_interval_string(timestamp_diff) << " time ago, current difficulty: " << get_blockchain_diff());

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
bool Blockchain::deinit()
{
  MTRACE("Blockchain::" << __func__);

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
      cryptonote::tx_verification_context tvc{};

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
  uint64_t chain_height = m_db->height();

  if(chain_height==0)
    throw_and_log(__func__<<"height is 0");

  db_rtxn_guard rtxn_guard(m_db);
  bool genesis_included = false;
  uint64_t current_back_offset = 1;
  while(current_back_offset < chain_height)
  {
    ids.push_back(m_db->get_block_hash_from_height(chain_height - current_back_offset));

    if(chain_height-current_back_offset == 0)
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
bool Blockchain::switch_to_alternative_blockchain(AltChain& alt_chain, bool discard_disconnected_chain)
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
  std::list<block> popped_blocks;
  while (m_db->top_block_hash() != alt_chain.front().bl.prev_id)
  {
    block b = pop_block_from_blockchain();
    popped_blocks.push_front(b);
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
      rollback_blockchain_switching(popped_blocks, split_height);

      // FIXME: Why do we keep invalid blocks around?  Possibly in case we hear
      // about them again so we can immediately dismiss them, but needs some
      // looking into.
      const crypto::hash blkid = cryptonote::get_block_hash(bei.bl);

      MERROR("The block was inserted as invalid while connecting new alternative chain, block_id: " << blkid);
      m_db->remove_alt_block(blkid);
      alt_ch_iter++;

      for(auto it = alt_ch_iter; it != alt_chain.end(); )
      {
        const auto &bei = *it++;
        const crypto::hash blkid = cryptonote::get_block_hash(bei.bl);
        m_db->remove_alt_block(blkid);
      }
      return false;
    }
  }

  // if we're to keep the disconnected blocks, add them as alternates
  
    //pushing old chain as alternative chain
    for (auto& b : popped_blocks)
    {
      block_verification_context bvc = {};
      bool r = handle_alternative_block(b, bvc);
      m_db->getbl
      const alt_block_data_t alt_info={

      };
      m_db->add_alt_block(get_block_hash(b),alt_info,block_to_blob(b));
      if(!r)
      {
        MERROR("Failed to push ex-main chain blocks to alternative chain ");
        // previously this would fail the blockchain switching, but I don't
        // think this is bad enough to warrant that.
      }
    }
  

  //removing alt_chain entries from alternative chains container
  for (const auto &bei: alt_chain)
  {
    m_db->remove_alt_block(cryptonote::get_block_hash(bei.bl));
  }

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
std::vector<BlobBlock> Blockchain::get_blocks(uint64_t start_height, size_t count) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  std::vector<BlobBlock> blocks;
  const uint64_t height = m_db->height();
  if(start_height >= height)
    throw_and_log(__func__<<"bad start height"<<start_height);

  const auto end_h =  start_height + count;
  if(end_h)

  for(size_t i = start_height; i < end_h;i++)
  {
    const auto blob = m_db->get_block_blob_from_height(i);
    const auto b = parse_block_from_blob(blob);
    blocks.push_back({std::moved(blob),std::move(b)});
  }
  return blocks;
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
    for (const auto &[index]: req.outputs)
    {
      offsets.push_back(index);
    }
    std::vector<cryptonote::output_data_t> data= m_db->get_output_keys( offsets);
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
//TODO: return type should be void, throw on exception
//       alternatively, return true only if no transactions missed
std::vector<tx_blob_pruned_entry> Blockchain::get_pruned_transactions_blobs(const std::vector<crypto::hash>& tx_hashes) const
{
  std::vector<tx_blob_pruned_entry> txs;
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  txs.reserve(tx_hashes.size());
  for (const auto& tx_hash : tx_hashes)
  {
      cryptonote::blobdata tx_blob;
      if (!db->get_pruned_tx_blob(tx_hash, tx_blob))
      {
        throw_and_log("Pruned transaction blob not found for " << tx_hash);
        return false;
      }
      crypto::hash prunable_hash;
       if ( !m_db->get_prunable_tx_hash(tx_hash, prunable_hash))
        {
          throw_and_log("Prunable hash not found for " << tx_hash);
        }
      txs.push_back({std::move(tx_blob),prunable_hash});
  }
  return txs;
}
//------------------------------------------------------------------
 std::vector<tx_blob_entry> Blockchain::get_transactions_blobs(const std::vector<crypto::hash>& tx_hashes) const
{
  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

   std::vector<tx_blob_entry> txs;
  for (const auto& tx_hash : tx_hashes)
  {
      tx_blob_entry tbe{};
     blobdata t1,t2;
    if (!db->get_pruned_tx_blob(tx_hash, t1))
    {
      throw_and_log("Pruned transaction blob not found for " << tx_hash);
    }

     if (db->get_prunable_tx_blob(tx_hash, t2))
    {
      tbe.blob = t1+t2;
    }
    else if (db->get_prunable_tx_hash(tx_hash, tbe.prunable_hash))
    {
      tbe.blob =t1;
    }
    else{
      throw_and_log("Prunable transaction data hash not found for " << tx_hash);
    }
    txs.push_back(std::move(tbe));
  }
  return txs;
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
  sync.chain_height = get_chain_height();
  uint64_t stop_height = std::min(sync.chain_height,sync.split_height+BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT);

  size_t count = 0;
  for(size_t i = split_height; i < stop_height ; i++)
  {
    sync.hashes.push_back(m_db->get_block_hash_from_height(i));
  }

  return sync;
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


//------------------------------------------------------------------
// This function checks to see if a tx is unlocked.  unlock_time is either
// a block index or a unix time.
bool Blockchain::is_tx_spendtime_unlocked(uint64_t unlock_time, uint8_t _) const
{
  MTRACE("Blockchain::" << __func__);
  if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
  {
    // ND: Instead of calling get_chain_height(), call m_db->height()
    //    directly as get_chain_height() locks the recursive mutex.
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

 uint64_t Blockchain::get_block_timestamp(const uint64_t& height) const
 {
    return m_db->get_block_timestamp(height);
 }
 difficulty_type Blockchain::get_block_cumulative_difficulty(uint64_t height) const
 {
  return m_db->get_block_cumulative_difficulty(height);
 }
 uint64_t Blockchain::get_block_already_generated_coins(uint64_t height) const
 {
  return m_db->get_block_already_generated_coins(height);
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
    const crypto::hash tx_hash = get_transaction_hash(tx.first);
    if (!m_tx_pool.add_tx(tx.first, tx_hash, tx.second,  tvc, relay_method::block, true, version))
    {
      MERROR("Failed to return taken transaction with hash: " << get_transaction_hash(tx.first) << " to tx_pool");
    }
  }
}

//------------------------------------------------------------------
bool Blockchain::handle_block_to_main_chain(const block& bl, block_verification_context& bvc, bool notify/* = true*/)
{
  MTRACE("Blockchain::" << __func__);
  const crypto::hash bh = get_block_hash(bl);

  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  const auto chain_height= m_db.height();
  const auto top_hash = chain_height==0 ? null_hash : get_top_hash();
  const auto new_b_height=chain_height;
 
  bvc = cryptonote::validate_new_block(*this,m_tx_pool,bl);
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
      MERROR_VER("Block with bh: " << bh  << " has at least one unknown transaction with bh: " << tx_hash);
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      goto leave;
    }

    // add the transaction to the temp list of transactions, so we can either
    // store the list of transactions all at once or return the ones we've
    // taken from the tx_pool back to it if the block fails verification.
    txs.push_back(std::make_pair(std::move(tx_tmp), std::move(txblob)));
  }

   // populate various metadata about the block to be stored alongside it.
    try
    {
      cryptonote::blobdata bd = cryptonote::block_to_blob(bl);
      MDEBUG("add_block hex "<<string_tools::buff_to_hex_nodelimer(bd));
      const difficulty_type block_diff = get_blockchain_diff(*this);
     m_db->add_block(std::make_pair(std::move(bl), std::move(bd)),  block_diff, txs);

    }
    catch (const std::exception& e)
    {
      //TODO: figure out the best way to deal with this failure
      LOG_ERROR("Error adding block with hash: " << bh << " to blockchain, what = " << e.what());
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      return false;
    }

  MINFO("add block" << std::endl << "bh: " << bh << std::endl << "PoW: " << pow << std::endl << "HEIGHT " << new_b_height << ", block_diff: " << block_diff <<std::endl << "block reward: " << print_money(get_outs_money_amount(bl))  ) ;


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

block_verification_context  Blockchain::add_sync_block(const std::pair<block,blobdata>& b_p, std::vector<std::pair<transaction, blobdata>> &txs )
{
  block_verification_context bvc;
  try
  {

  CRITICAL_REGION_LOCAL(m_blockchain_lock);

    bvc = validate_sync_block(bl);
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



