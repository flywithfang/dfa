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

#include <boost/algorithm/string.hpp>
#include <boost/uuid/nil_generator.hpp>

#include "string_tools.h"
using namespace epee;

#include <unordered_set>
#include "cryptonote_core.h"
#include "common/util.h"
#include "common/updates.h"
#include "common/download.h"
#include "common/threadpool.h"
#include "common/command_line.h"
#include "cryptonote_basic/events.h"
#include "warnings.h"
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "misc_language.h"
#include "file_io_utils.h"
#include <csignal>
#include "checkpoints/checkpoints.h"
#include "ringct/rctTypes.h"
#include "blockchain_db/blockchain_db.h"
#include "ringct/rctSigs.h"
#include "common/notify.h"
#include "hardforks/hardforks.h"
#include "version.h"

#include <boost/filesystem.hpp>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

DISABLE_VS_WARNINGS(4355)

#define MERROR_VER(x) MCERROR("verify", x)

#define BAD_SEMANTICS_TXES_MAX_SIZE 100

// basically at least how many bytes the block itself serializes to without the miner tx
#define BLOCK_SIZE_SANITY_LEEWAY 100

namespace cryptonote
{
  const command_line::arg_descriptor<bool, false> arg_testnet_on  = {
    "testnet"
  , "Run on testnet. The wallet must be launched with --testnet flag."
  , false
  };
  const command_line::arg_descriptor<bool, false> arg_stagenet_on  = {
    "stagenet"
  , "Run on stagenet. The wallet must be launched with --stagenet flag."
  , false
  };
  const command_line::arg_descriptor<bool> arg_regtest_on  = {
    "regtest"
  , "Run in a regression testing mode."
  , false
  };
  const command_line::arg_descriptor<bool> arg_keep_fakechain = {
    "keep-fakechain"
  , "Don't delete any existing database when in fakechain mode."
  , false
  };
  const command_line::arg_descriptor<difficulty_type> arg_fixed_difficulty  = {
    "fixed-difficulty"
  , "Fixed difficulty used for testing."
  , 0
  };
  const command_line::arg_descriptor<std::string, false, true, 2> arg_data_dir = {
    "data-dir"
  , "Specify data directory"
  , tools::get_default_data_dir()
  , {{ &arg_testnet_on, &arg_stagenet_on }}
  , [](std::array<bool, 2> testnet_stagenet, bool defaulted, std::string val)->std::string {
      if (testnet_stagenet[0])
        return (boost::filesystem::path(val) / "testnet").string();
      else if (testnet_stagenet[1])
        return (boost::filesystem::path(val) / "stagenet").string();
      return val;
    }
  };
  const command_line::arg_descriptor<bool> arg_offline = {
    "offline"
  , "Do not listen for peers, nor connect to any"
  };
  const command_line::arg_descriptor<bool> arg_disable_dns_checkpoints = {
    "disable-dns-checkpoints"
  , "Do not retrieve checkpoints from DNS"
  };
  const command_line::arg_descriptor<size_t> arg_block_download_max_size  = {
    "block-download-max-size"
  , "Set maximum size of block download queue in bytes (0 for default)"
  , 0
  };
  const command_line::arg_descriptor<bool> arg_sync_pruned_blocks  = {
    "sync-pruned-blocks"
  , "Allow syncing from nodes with only pruned blocks"
  };

  static const command_line::arg_descriptor<bool> arg_test_drop_download = {
    "test-drop-download"
  , "For net tests: in download, discard ALL blocks instead checking/saving them (very fast)"
  };
  static const command_line::arg_descriptor<uint64_t> arg_test_drop_download_height = {
    "test-drop-download-height"
  , "Like test-drop-download but discards only after around certain height"
  , 0
  };
  static const command_line::arg_descriptor<int> arg_test_dbg_lock_sleep = {
    "test-dbg-lock-sleep"
  , "Sleep time in ms, defaults to 0 (off), used to debug before/after locking mutex. Values 100 to 1000 are good for tests."
  , 0
  };
  static const command_line::arg_descriptor<bool> arg_dns_checkpoints  = {
    "enforce-dns-checkpointing"
  , "checkpoints from DNS server will be enforced"
  , false
  };
  static const command_line::arg_descriptor<uint64_t> arg_fast_block_sync = {
    "fast-block-sync"
  , "Sync up most of the way by using embedded, known block hashes."
  , 1
  };
  static const command_line::arg_descriptor<uint64_t> arg_prep_blocks_threads = {
    "prep-blocks-threads"
  , "Max number of threads to use when preparing block hashes in groups."
  , 4
  };
  static const command_line::arg_descriptor<uint64_t> arg_show_time_stats  = {
    "show-time-stats"
  , "Show time-stats when processing blocks/txs and disk synchronization."
  , 0
  };
  static const command_line::arg_descriptor<size_t> arg_block_sync_size  = {
    "block-sync-size"
  , "How many blocks to sync at once during chain synchronization (0 = adaptive)."
  , 0
  };
  static const command_line::arg_descriptor<std::string> arg_check_updates = {
    "check-updates"
  , "Check for new versions of monero: [disabled|notify|download|update]"
  , "notify"
  };
 
  static const command_line::arg_descriptor<bool> arg_no_fluffy_blocks  = {
    "no-fluffy-blocks"
  , "Relay blocks as normal blocks"
  , false
  };
  static const command_line::arg_descriptor<size_t> arg_max_txpool_weight  = {
    "max-txpool-weight"
  , "Set maximum txpool weight in bytes."
  , DEFAULT_TXPOOL_MAX_WEIGHT
  };
  static const command_line::arg_descriptor<std::string> arg_block_notify = {
    "block-notify"
  , "Run a program for each new block, '%s' will be replaced by the block hash"
  , ""
  };
  static const command_line::arg_descriptor<bool> arg_prune_blockchain  = {
    "prune-blockchain"
  , "Prune blockchain"
  , true
  };
  static const command_line::arg_descriptor<std::string> arg_reorg_notify = {
    "reorg-notify"
  , "Run a program for each reorg, '%s' will be replaced by the split height, "
    "'%h' will be replaced by the new blockchain height, '%n' will be "
    "replaced by the number of new blocks in the new chain, and '%d' will be "
    "replaced by the number of blocks discarded from the old chain"
  , ""
  };
  static const command_line::arg_descriptor<std::string> arg_block_rate_notify = {
    "block-rate-notify"
  , "Run a program when the block rate undergoes large fluctuations. This might "
    "be a sign of large amounts of hash rate going on and off the Monero network, "
    "and thus be of potential interest in predicting attacks. %t will be replaced "
    "by the number of minutes for the observation window, %b by the number of "
    "blocks observed within that window, and %e by the number of blocks that was "
    "expected in that window. It is suggested that this notification is used to "
    "automatically increase the number of confirmations required before a payment "
    "is acted upon."
  , ""
  };
  static const command_line::arg_descriptor<bool> arg_keep_alt_blocks  = {
    "keep-alt-blocks"
  , "Keep alternative blocks on restart"
  , false
  };

  //-----------------------------------------------------------------------------------------------
  core::core():
              m_mempool(m_blockchain),
              m_blockchain(m_mempool),
              m_starter_message_showed(false),
              m_target_blockchain_height(0),
              m_checkpoints_path(""),
              m_last_dns_checkpoints_update(0),
              m_last_json_checkpoints_update(0),
              m_disable_dns_checkpoints(false),
              m_update_download(0),
              m_nettype(UNDEFINED),
              m_update_available(false)
  {
    m_checkpoints_updating.clear();
  }

  //-----------------------------------------------------------------------------------
  void core::set_checkpoints_file_path(const std::string& path)
  {
    m_checkpoints_path = path;
  }
  //-----------------------------------------------------------------------------------
  void core::set_enforce_dns_checkpoints(bool enforce_dns)
  {
    m_blockchain.set_enforce_dns_checkpoints(enforce_dns);
  }
  //-----------------------------------------------------------------------------------
  void core::set_txpool_listener(boost::function<void(std::vector<txpool_event>)> zmq_pub)
  {
    CRITICAL_REGION_LOCAL(m_incoming_tx_lock);
    m_zmq_pub = std::move(zmq_pub);
  }

  //-----------------------------------------------------------------------------------------------
  bool core::update_checkpoints(const bool skip_dns /* = false */)
  {
    if (m_nettype != MAINNET || m_disable_dns_checkpoints) return true;

    if (m_checkpoints_updating.test_and_set()) return true;

    bool res = true;
    if (!skip_dns && time(NULL) - m_last_dns_checkpoints_update >= 3600)
    {
      res = m_blockchain.update_checkpoints(m_checkpoints_path, true);
      m_last_dns_checkpoints_update = time(NULL);
      m_last_json_checkpoints_update = time(NULL);
    }
    else if (time(NULL) - m_last_json_checkpoints_update >= 600)
    {
      res = m_blockchain.update_checkpoints(m_checkpoints_path, false);
      m_last_json_checkpoints_update = time(NULL);
    }

    m_checkpoints_updating.clear();

    // if anything fishy happened getting new checkpoints, bring down the house
    if (!res)
    {
      graceful_exit();
    }
    return res;
  }
  //-----------------------------------------------------------------------------------
  void core::stop()
  {
    m_blockchain.cancel();

    tools::download_async_handle handle;
    {
      boost::lock_guard<boost::mutex> lock(m_update_mutex);
      handle = m_update_download;
      m_update_download = 0;
    }
    if (handle)
      tools::download_cancel(handle);
  }
  //-----------------------------------------------------------------------------------
  void core::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_data_dir);

    command_line::add_arg(desc, arg_test_drop_download);
    command_line::add_arg(desc, arg_test_drop_download_height);

    command_line::add_arg(desc, arg_testnet_on);
    command_line::add_arg(desc, arg_stagenet_on);
    command_line::add_arg(desc, arg_regtest_on);
    command_line::add_arg(desc, arg_keep_fakechain);
    command_line::add_arg(desc, arg_fixed_difficulty);
    command_line::add_arg(desc, arg_dns_checkpoints);
    command_line::add_arg(desc, arg_prep_blocks_threads);
    command_line::add_arg(desc, arg_fast_block_sync);
    command_line::add_arg(desc, arg_show_time_stats);
    command_line::add_arg(desc, arg_block_sync_size);
    command_line::add_arg(desc, arg_check_updates);
    command_line::add_arg(desc, arg_no_fluffy_blocks);
    command_line::add_arg(desc, arg_test_dbg_lock_sleep);
    command_line::add_arg(desc, arg_offline);
    command_line::add_arg(desc, arg_disable_dns_checkpoints);
    command_line::add_arg(desc, arg_block_download_max_size);
    command_line::add_arg(desc, arg_sync_pruned_blocks);
    command_line::add_arg(desc, arg_max_txpool_weight);
    command_line::add_arg(desc, arg_block_notify);
    command_line::add_arg(desc, arg_prune_blockchain);
    command_line::add_arg(desc, arg_reorg_notify);
    command_line::add_arg(desc, arg_block_rate_notify);
    command_line::add_arg(desc, arg_keep_alt_blocks);

    miner::init_options(desc);
    BlockchainDB::init_options(desc);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_command_line(const boost::program_options::variables_map& vm)
  {
    if (m_nettype != FAKECHAIN)
    {
      const bool testnet = command_line::get_arg(vm, arg_testnet_on);
      const bool stagenet = command_line::get_arg(vm, arg_stagenet_on);
      m_nettype = testnet ? TESTNET : stagenet ? STAGENET : MAINNET;
    }

    m_config_folder = command_line::get_arg(vm, arg_data_dir);

    auto data_dir = boost::filesystem::path(m_config_folder);

    m_offline = get_arg(vm, arg_offline);

    epee::debug::g_test_dbg_lock_sleep() = command_line::get_arg(vm, arg_test_dbg_lock_sleep);

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_current_blockchain_height() const
  {
    return m_blockchain.get_current_blockchain_height();
  }
  //-----------------------------------------------------------------------------------------------
  void core::get_blockchain_top(uint64_t& height, crypto::hash& top_id) const
  {
    top_id = m_blockchain.get_top_hash(height);
  }
   std::tuple<uint64_t, crypto::hash>  core::get_blockchain_top() const
  {
    uint64_t height;
    crypto::hash top_id;
    top_id = m_blockchain.get_top_hash(height);
    return {height,top_id};
  }
  
  //-----------------------------------------------------------------------------------------------
  bool core::get_split_transactions_blobs(const std::vector<crypto::hash>& txs_ids, std::vector<std::tuple<crypto::hash, cryptonote::blobdata, crypto::hash, cryptonote::blobdata>>& txs, std::vector<crypto::hash>& missed_txs) const
  {
    return m_blockchain.get_split_transactions_blobs(txs_ids, txs, missed_txs);
  }

  //-----------------------------------------------------------------------------------------------
  bool core::get_alternative_blocks(std::vector<block>& blocks) const
  {
    return m_blockchain.get_alternative_blocks(blocks);
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_alternative_blocks_count() const
  {
    return m_blockchain.get_alternative_blocks_count();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::init(const boost::program_options::variables_map& vm, const cryptonote::test_options *test_options, const GetCheckpointsCallback& get_checkpoints/* = nullptr */)
  {
    start_time = std::time(nullptr);

    const bool regtest = command_line::get_arg(vm, arg_regtest_on);
    if (test_options != NULL || regtest)
    {
      m_nettype = FAKECHAIN;
    }
    bool r = handle_command_line(vm);
    CHECK_AND_ASSERT_MES(r, false, "Failed to handle command line");

    std::string db_sync_mode = command_line::get_arg(vm, cryptonote::arg_db_sync_mode);
    bool db_salvage = command_line::get_arg(vm, cryptonote::arg_db_salvage) != 0;
    bool fast_sync = command_line::get_arg(vm, arg_fast_block_sync) != 0;
    uint64_t blocks_threads = command_line::get_arg(vm, arg_prep_blocks_threads);
    std::string check_updates_string = command_line::get_arg(vm, arg_check_updates);
    size_t max_txpool_weight = command_line::get_arg(vm, arg_max_txpool_weight);
    bool prune_blockchain = command_line::get_arg(vm, arg_prune_blockchain);
    bool keep_alt_blocks = command_line::get_arg(vm, arg_keep_alt_blocks);
    bool keep_fakechain = command_line::get_arg(vm, arg_keep_fakechain);

    boost::filesystem::path folder(m_config_folder);
    if (m_nettype == FAKECHAIN)
      folder /= "fake";

    // make sure the data directory exists, and try to lock it
    CHECK_AND_ASSERT_MES (boost::filesystem::exists(folder) || boost::filesystem::create_directories(folder), false,
      std::string("Failed to create directory ").append(folder.string()).c_str());

    // check for blockchain.bin
    try
    {
      const boost::filesystem::path old_files = folder;
      if (boost::filesystem::exists(old_files / "blockchain.bin"))
      {
        MWARNING("Found old-style blockchain.bin in " << old_files.string());
        MWARNING("Monero now uses a new format. You can either remove blockchain.bin to start syncing");
        MWARNING("the blockchain anew, or use monero-blockchain-export and monero-blockchain-import to");
        MWARNING("convert your existing blockchain.bin to the new format. See README.md for instructions.");
        return false;
      }
    }
    // folder might not be a directory, etc, etc
    catch (...) { }

    std::unique_ptr<BlockchainDB> db(new_db());
    if (db == NULL)
    {
      LOG_ERROR("Failed to initialize a database");
      return false;
    }

    folder /= db->get_db_name();
    MGINFO("Loading blockchain from folder " << folder.string() << " ...");

    const std::string filename = folder.string();
    // default to fast:async:1 if overridden

    if (m_nettype == FAKECHAIN && !keep_fakechain)
    {
      // reset the db by removing the database file before opening it
      if (!db->remove_data_file(filename))
      {
        MERROR("Failed to remove data file in " << filename);
        return false;
      }
    }

    try
    {

      db->open(filename, DBF_FAST);
      if(!db->m_open)
        return false;
    }
    catch (const DB_ERROR& e)
    {
      LOG_ERROR("Error opening database: " << e.what());
      return false;
    }


    try
    {
      if (!command_line::is_arg_defaulted(vm, arg_block_notify))
      {
        struct hash_notify
        {
          tools::Notify cmdline;

          void operator()(std::uint64_t, epee::span<const block> blocks) const
          {
            for (const block& bl : blocks)
              cmdline.notify("%s", epee::string_tools::pod_to_hex(get_block_hash(bl)).c_str(), NULL);
          }
        };

        m_blockchain.add_block_notify(hash_notify{{command_line::get_arg(vm, arg_block_notify).c_str()}});
      }
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to parse block notify spec: " << e.what());
    }

    try
    {
      if (!command_line::is_arg_defaulted(vm, arg_reorg_notify))
        m_blockchain.set_reorg_notify(std::shared_ptr<tools::Notify>(new tools::Notify(command_line::get_arg(vm, arg_reorg_notify).c_str())));
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to parse reorg notify spec: " << e.what());
    }

    try
    {
      if (!command_line::is_arg_defaulted(vm, arg_block_rate_notify))
        m_block_rate_notify.reset(new tools::Notify(command_line::get_arg(vm, arg_block_rate_notify).c_str()));
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to parse block rate notify spec: " << e.what());
    }

    const std::pair<uint8_t, uint64_t> regtest_hard_forks[3] = {std::make_pair(1, 0), std::make_pair(mainnet_hard_forks[num_mainnet_hard_forks-1].version, 1), std::make_pair(0, 0)};
    const cryptonote::test_options regtest_test_options = {
      regtest_hard_forks,
      0
    };
    const difficulty_type fixed_difficulty = command_line::get_arg(vm, arg_fixed_difficulty);
    r = m_blockchain.init(db.release(), m_nettype, m_offline, regtest ? &regtest_test_options : test_options, fixed_difficulty, get_checkpoints);
    CHECK_AND_ASSERT_MES(r, false, "Failed to initialize blockchain storage");

    r = m_mempool.init(max_txpool_weight, m_nettype == FAKECHAIN);
    CHECK_AND_ASSERT_MES(r, false, "Failed to initialize memory pool");

    // now that we have a valid m_blockchain, we can clean out any
    // transactions in the pool that do not conform to the current fork
    m_mempool.validate(m_blockchain.get_current_hard_fork_version());

    bool show_time_stats = command_line::get_arg(vm, arg_show_time_stats) != 0;
    m_blockchain.set_show_time_stats(show_time_stats);
    CHECK_AND_ASSERT_MES(r, false, "Failed to initialize blockchain storage");

    m_block_sync_size = command_line::get_arg(vm, arg_block_sync_size);
    if (m_block_sync_size > BLOCKS_SYNCHRONIZING_MAX_COUNT)
      MERROR("Error --block-sync-size cannot be greater than " << BLOCKS_SYNCHRONIZING_MAX_COUNT);

  

   // DNS versions checking
    if (check_updates_string == "disabled")
      check_updates_level = UPDATES_DISABLED;
    else if (check_updates_string == "notify")
      check_updates_level = UPDATES_NOTIFY;
    else if (check_updates_string == "download")
      check_updates_level = UPDATES_DOWNLOAD;
    else if (check_updates_string == "update")
      check_updates_level = UPDATES_UPDATE;
    else {
      MERROR("Invalid argument to --dns-versions-check: " << check_updates_string);
      return false;
    }


    if (!keep_alt_blocks && !m_blockchain.get_db().is_read_only())
      m_blockchain.get_db().drop_alt_blocks();

    if (prune_blockchain)
    {
      // display a message if the blockchain is not pruned yet
      if (!m_blockchain.get_blockchain_pruning_seed())
      {
        MGINFO("Pruning blockchain...");
        CHECK_AND_ASSERT_MES(m_blockchain.prune_blockchain(), false, "Failed to prune blockchain");
      }
      else
      {
        CHECK_AND_ASSERT_MES(m_blockchain.update_blockchain_pruning(), false, "Failed to update blockchain pruning");
      }
    }

    return load_state_data();
  }

  //-----------------------------------------------------------------------------------------------
  bool core::load_state_data()
  {
    // may be some code later
    return true;
  }
  //-----------------------------------------------------------------------------------------------
    bool core::deinit()
  {
    m_mempool.deinit();
    m_blockchain.deinit();
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  void core::test_drop_download()
  {
    m_test_drop_download = false;
  }
  //-----------------------------------------------------------------------------------------------
  void core::test_drop_download_height(uint64_t height)
  {
    m_test_drop_download_height = height;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_test_drop_download() const
  {
    return m_test_drop_download;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_test_drop_download_height() const
  {
    if (m_test_drop_download_height == 0)
      return true;

    if (get_blockchain().get_current_blockchain_height() <= m_test_drop_download_height)
      return true;

    return false;
  }
 
  //-----------------------------------------------------------------------------------------------
  static bool is_canonical_bulletproof_layout(const std::vector<rct::Bulletproof> &proofs)
  {
    if (proofs.size() != 1)
      return false;
    const size_t sz = proofs[0].V.size();
    if (sz == 0 || sz > BULLETPROOF_MAX_OUTPUTS)
      return false;
    return true;
  }
 
   //-----------------------------------------------------------------------------------------------
  tx_verification_context core::handle_incoming_tx(const tx_blob_entry& tx_blob, relay_method tx_relay, bool relayed)
  {
    tx_verification_context  tvc{};

    CRITICAL_REGION_LOCAL(m_incoming_tx_lock);

        try
        {
          const auto tx = parse_tx_from_blob(tx_blob.blob);
        const auto tx_hash = get_transaction_hash(tx);
      if(m_mempool.have_tx(tx_hash, relay_category::legacy))
      {
        MWARNING("tx " << tx_hash << "already have transaction in tx_pool");
       tvc.m_verifivation_failed = true;
       return tvc;
      }
      else if(m_blockchain.have_tx(tx_hash))
      {
        MWARNING("tx " << tx_hash << " already have transaction in blockchain");
        tvc.m_verifivation_failed = true;
       return tvc;
      }

      if(!check_tx_semantic(tx_info, tx_relay == relay_method::block)){
          tvc.m_verifivation_failed = true;
          return tvc;
      }

      if(!m_mempool.add_tx(tx, tx_hash, blob, tx_weight, tvc, tx_relay, relayed, 0)){
          tvc.m_verifivation_failed = true;
          return tvc;
      }
      if(tvc.m_added_to_pool)
      {
        MDEBUG("tx added: " << results[i].hash);
      }
      return tvc;
  }
 catch (const std::exception &e)
        {
          MERROR_VER("Exception in handle_incoming_tx_pre: " << e.what());
          tvc.m_verifivation_failed = true;
          return tvc;
        }
  }
 
  //-----------------------------------------------------------------------------------------------
  bool core::is_key_image_spent(const crypto::key_image &key_image) const
  {
    return m_blockchain.have_tx_keyimg_as_spent(key_image);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::are_key_images_spent(const std::vector<crypto::key_image>& key_im, std::vector<bool> &spent) const
  {
    spent.clear();
    for(auto& ki: key_im)
    {
      spent.push_back(m_blockchain.have_tx_keyimg_as_spent(ki));
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_block_sync_batch_size() const
  {
    size_t res = 0;
    if (m_block_sync_size > 0)
      res = m_block_sync_size;
    else
      res = BLOCKS_SYNCHRONIZING_DEFAULT_COUNT;
   
    const size_t max_block_size = skip_unneeded_hashes(peer_cxt, true) ;
    if (res > max_block_size)
    {
      res = max_block_size;
    }
    return res;
  }
 
  //-----------------------------------------------------------------------------------------------
  size_t core::get_blockchain_total_transactions() const
  {
    return m_blockchain.get_total_transactions();
  }
  //-----------------------------------------------------------------------------------------------
 

  //-----------------------------------------------------------------------------------------------
  void core::on_transactions_relayed(const epee::span<const cryptonote::blobdata> tx_blobs, const relay_method tx_relay)
  {
    std::vector<crypto::hash> tx_hashes{};
    tx_hashes.resize(tx_blobs.size());

    for (std::size_t i = 0; i < tx_blobs.size(); ++i)
    {
      cryptonote::transaction tx{};
      if (!parse_tx_from_blob(tx_blobs[i], tx, tx_hashes[i]))
      {
        LOG_ERROR("Failed to parse relayed transaction");
        return;
      }
    }
    m_mempool.set_relayed(epee::to_span(tx_hashes), tx_relay);
  }


  //-----------------------------------------------------------------------------------------------
  bool core::get_outs(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res) const
  {
    return m_blockchain.get_outs(req, res);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_output_distribution( uint64_t from_height, uint64_t to_height, uint64_t &start_height, std::vector<uint64_t> &distribution) const
  {
    return m_blockchain.get_output_distribution( from_height, to_height, start_height, distribution);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs) const
  {
    return m_blockchain.get_tx_outputs_gindexs(tx_id, indexs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_tx_outputs_gindexs(const crypto::hash& tx_id, size_t n_txes, std::vector<std::vector<uint64_t>>& indexs) const
  {
    return m_blockchain.get_tx_outputs_gindexs(tx_id, n_txes, indexs);
  }
 
 
  //-----------------------------------------------------------------------------------------------
  bool core::handle_block_found(const block& b, block_verification_context &bvc)
  {
    bvc = {};
    try
    {
     m_blockchain.add_new_block(b, bvc);

    CHECK_AND_ASSERT_MES(!bvc.m_verifivation_failed, false, "mined block failed verification");
    }
     catch (const std::exception &e)
    {
      return false;
    }
    return true;
  }
 
   //-----------------------------------------------------------------------------------------------
  crypto::hash core::get_top_hash() const
  {
    return m_blockchain.get_top_hash();
  }
  //-----------------------------------------------------------------------------------------------
  difficulty_type core::get_block_cumulative_difficulty(uint64_t height) const
  {
    return m_blockchain.get_db().get_block_cumulative_difficulty(height);
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_pool_transactions_count(bool include_sensitive_txes) const
  {
    return m_mempool.get_transactions_count(include_sensitive_txes);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::have_block_unlocked(const crypto::hash& id, int *where) const
  {
    return m_blockchain.have_block_unlocked(id, where);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::have_block(const crypto::hash& id, int *where) const
  {
    return m_blockchain.have_block(id, where);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::parse_tx_from_blob(transaction& tx, crypto::hash& tx_hash, const blobdata& blob) const
  {
    return parse_tx_from_blob(blob, tx, tx_hash);
  }

  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transactions(std::vector<transaction>& txs, bool include_sensitive_data) const
  {
    m_mempool.get_transactions(txs, include_sensitive_data);
    return true;
  }
   std::vector<std::tuple<crypto::hash, cryptonote::blobdata, relay_method>> core::get_relayable_transactions()
   {
      std::vector<std::tuple<crypto::hash, cryptonote::blobdata, relay_method>> v;
      m_mempool.get_relayable_transactions(v);
      return v;
   }

  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transaction_hashes(std::vector<crypto::hash>& txs, bool include_sensitive_data) const
  {
    m_mempool.get_transaction_hashes(txs, include_sensitive_data);
    return true;
  }
 
  //-----------------------------------------------------------------------------------------------
  bool core::pool_has_tx(const crypto::hash &id) const
  {
    return m_mempool.have_tx(id, relay_category::legacy);
  }

   bool core::pool_has_key_image(const crypto::key_image & ki)const
   {
    return m_mempool.spent_in_pool(ki);
   }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transactions(std::vector<tx_info>& tx_infos,  bool include_sensitive_data) const
  {
    return m_mempool.get_transactions_info(tx_infos,  include_sensitive_data);
  }
 
  
  //-----------------------------------------------------------------------------------------------
  bool core::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp, cryptonote_peer_context& context)
  {
    return m_blockchain.handle_get_objects(arg, rsp);
  }
  //-----------------------------------------------------------------------------------------------
  crypto::hash core::get_block_hash_by_height(uint64_t height) const
  {
    return m_blockchain.get_block_hash_by_height(height);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan) const
  {
    return m_blockchain.get_block_by_hash(h, blk, orphan);
  }
 
  #include "cryptonote_core_idle.inl"
  //-----------------------------------------------------------------------------------------------
  uint8_t core::get_ideal_hard_fork_version() const
  {
    return get_blockchain().get_ideal_hard_fork_version();
  }
  //-----------------------------------------------------------------------------------------------
  uint8_t core::get_ideal_hard_fork_version(uint64_t height) const
  {
    return get_blockchain().get_ideal_hard_fork_version(height);
  }
  //-----------------------------------------------------------------------------------------------
  uint8_t core::get_hard_fork_version(uint64_t height) const
  {
    return get_blockchain().get_hard_fork_version(height);
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_earliest_ideal_height_for_version(uint8_t version) const
  {
    return get_blockchain().get_earliest_ideal_height_for_version(version);
  }

  //-----------------------------------------------------------------------------------------------
  bool core::check_blockchain_pruning()
  {
    return m_blockchain.check_blockchain_pruning();
  }
  //-----------------------------------------------------------------------------------------------
  void core::set_target_blockchain_height(uint64_t target_blockchain_height)
  {
    m_target_blockchain_height = target_blockchain_height;
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_target_blockchain_height() const
  {
    return m_target_blockchain_height;
  }
 
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_free_space() const
  {
    boost::filesystem::path path(m_config_folder);
    boost::filesystem::space_info si = boost::filesystem::space(path);
    return si.available;
  }
  //-----------------------------------------------------------------------------------------------
  uint32_t core::get_blockchain_pruning_seed() const
  {
    return get_blockchain().get_blockchain_pruning_seed();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::prune_blockchain(uint32_t pruning_seed)
  {
    return get_blockchain().prune_blockchain(pruning_seed);
  }
 
  //-----------------------------------------------------------------------------------------------
  std::time_t core::get_start_time() const
  {
    return start_time;
  }
  //-----------------------------------------------------------------------------------------------
  void core::graceful_exit()
  {
    raise(SIGTERM);
  }

cryptonote::BlockTemplate core::get_block_template(const crypto::hash *prev_block, const account_public_address& adr, const blobdata& ex_nonce)
{
  return m_blockchain.create_block_template(prev_block,adr,ex_nonce);
}
}
