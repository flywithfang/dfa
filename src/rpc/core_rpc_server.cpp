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

#include <boost/preprocessor/stringize.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <boost/filesystem.hpp>
#include "include_base_utils.h"
#include "string_tools.h"
using namespace epee;

#include "core_rpc_server.h"
#include "common/command_line.h"
#include "common/updates.h"
#include "common/download.h"
#include "common/util.h"
#include "common/perf_timer.h"
#include "int-util.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "misc_language.h"
#include "net/parse.h"
#include "storages/http_abstract_invoke.h"
#include "crypto/hash.h"
#include "crypto/rx-hash.h"
#include "rpc/rpc_args.h"


#include "core_rpc_server_error_codes.h"
#include "p2p/net_node.h"
#include "version.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon.rpc"

#define MAX_RESTRICTED_FAKE_OUTS_COUNT 40
#define MAX_RESTRICTED_GLOBAL_FAKE_OUTS_COUNT 5000

#define OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION (3 * 86400) // 3 days max, the wallet requests 1.8 days

#define DEFAULT_PAYMENT_DIFFICULTY 1000
#define DEFAULT_PAYMENT_CREDITS_PER_HASH 100

#define RESTRICTED_BLOCK_HEADER_RANGE 1000
#define RESTRICTED_TRANSACTIONS_COUNT 100
#define RESTRICTED_SPENT_KEY_IMAGES_COUNT 5000
#define RESTRICTED_BLOCK_COUNT 1000

#define RPC_TRACKER(rpc) \
  PERF_TIMER(rpc); \
  RPCTracker tracker(#rpc, PERF_TIMER_NAME(rpc))

namespace
{
  class RPCTracker
  {
  public:
    struct entry_t
    {
      uint64_t count;
      uint64_t time;
      uint64_t credits;
    };

    RPCTracker(const char *rpc, tools::LoggingPerformanceTimer &timer): rpc(rpc), timer(timer) {
    }
    ~RPCTracker() {
      try
      {
        boost::unique_lock<boost::mutex> lock(mutex);
        auto &e = tracker[rpc];
        ++e.count;
        e.time += timer.value();
      }
      catch (...) { /* ignore */ }
    }
    void pay(uint64_t amount) {
      boost::unique_lock<boost::mutex> lock(mutex);
      auto &e = tracker[rpc];
      e.credits += amount;
    }
    const std::string &rpc_name() const { return rpc; }
    static void clear() { boost::unique_lock<boost::mutex> lock(mutex); tracker.clear(); }
    static std::unordered_map<std::string, entry_t> data() { boost::unique_lock<boost::mutex> lock(mutex); return tracker; }
  private:
    std::string rpc;
    tools::LoggingPerformanceTimer &timer;
    static boost::mutex mutex;
    static std::unordered_map<std::string, entry_t> tracker;
  };
  boost::mutex RPCTracker::mutex;
  std::unordered_map<std::string, RPCTracker::entry_t> RPCTracker::tracker;

  void add_reason(std::string &reasons, const char *reason)
  {
    if (!reasons.empty())
      reasons += ", ";
    reasons += reason;
  }

  uint64_t round_up(uint64_t value, uint64_t quantum)
  {
    return (value + quantum - 1) / quantum * quantum;
  }

  void store_128(boost::multiprecision::uint128_t value, uint64_t &slow64, std::string &swide, uint64_t &stop64)
  {
    slow64 = (value & 0xffffffffffffffff).convert_to<uint64_t>();
    swide = cryptonote::hex(value);
    stop64 = ((value >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
  }

  void store_difficulty(cryptonote::difficulty_type difficulty, uint64_t &sdiff, std::string &swdiff, uint64_t &stop64)
  {
    store_128(difficulty, sdiff, swdiff, stop64);
  }
}

namespace cryptonote
{

  //-----------------------------------------------------------------------------------
  void core_rpc_server::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_rpc_bind_port);
    command_line::add_arg(desc, arg_restricted_rpc);

    cryptonote::rpc_args::init_options(desc, true);

  }
  //------------------------------------------------------------------------------------------------------------------------------
  core_rpc_server::core_rpc_server(
      core& cr
    , nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p
    )
    : m_core(cr)
    , m_p2p(p2p)
    , disable_rpc_ban(false)
  {}
  //------------------------------------------------------------------------------------------------------------------------------

  //------------------------------------------------------------------------------------------------------------------------------
  std::map<std::string, bool> core_rpc_server::get_public_nodes(uint32_t credits_per_hash_threshold/* = 0*/)
  {
    COMMAND_RPC_GET_PUBLIC_NODES::request request;
    COMMAND_RPC_GET_PUBLIC_NODES::response response;

    request.gray = true;
    request.white = true;
    request.include_blocked = false;
    if (!on_get_public_nodes(request, response) || response.status != CORE_RPC_STATUS_OK)
    {
      return {};
    }

    std::map<std::string, bool> result;

    const auto append = [&result, &credits_per_hash_threshold](const std::vector<public_node> &nodes, bool white) {
      for (const auto &node : nodes)
      {
          result.insert(std::make_pair(node.host + ":" + std::to_string(node.rpc_port), white));
      }
    };

    append(response.white, true);
    append(response.gray, false);

    return result;
  }

  core_rpc_server::~core_rpc_server()
  {
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::init(const boost::program_options::variables_map& vm, const bool restricted
      , const std::string& port)
  {
    m_restricted = restricted;
    m_net_server.set_threads_prefix("RPC");
    m_net_server.set_connection_filter(&m_p2p);

    auto rpc_config = cryptonote::rpc_args::process(vm, true);
    if (!rpc_config)
      return false;

    std::string bind_ip_str = rpc_config->bind_ip;
    std::string bind_ipv6_str = rpc_config->bind_ipv6_address;
   
    disable_rpc_ban = rpc_config->disable_rpc_ban;
    const std::string data_dir{command_line::get_arg(vm, cryptonote::arg_data_dir)};

    boost::optional<epee::net_utils::http::login> http_login{};

    if (rpc_config->login)
      http_login.emplace(std::move(rpc_config->login->username), std::move(rpc_config->login->password).password());


    bool store_ssl_key = !restricted && rpc_config->ssl_options && rpc_config->ssl_options.auth.certificate_path.empty();
    const auto ssl_base_path = (boost::filesystem::path{data_dir} / "rpc_ssl").string();
    if (store_ssl_key && boost::filesystem::exists(ssl_base_path + ".crt"))
    {
      // load key from previous run, password prompted by OpenSSL
      store_ssl_key = false;
      rpc_config->ssl_options.auth =
        epee::net_utils::ssl_authentication_t{ssl_base_path + ".key", ssl_base_path + ".crt"};
    }

    auto rng = [](size_t len, uint8_t *ptr){ return crypto::rand(len, ptr); };
    const bool inited = super_type::init(
      rng, std::move(port), std::move(bind_ip_str),
      std::move(bind_ipv6_str), std::move(rpc_config->use_ipv6), std::move(rpc_config->require_ipv4),
      std::move(rpc_config->access_control_origins), std::move(http_login), std::move(rpc_config->ssl_options)
    );

    if (store_ssl_key && inited)
    {
      // new keys were generated, store for next run
      const auto error = epee::net_utils::store_ssl_keys(m_net_server.get_ssl_context(), ssl_base_path);
      if (error)
        MFATAL("Failed to store HTTP SSL cert/key for " << (restricted ? "restricted " : "") << "RPC server: " << error.message());
      return !bool(error);
    }
    return inited;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::check_core_ready()
  {
    if(!m_p2p.get_crypto_protocol().is_synchronized())
    {
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::add_host_fail(const connection_context *ctx, unsigned int score)
  {
    if(!ctx || !ctx->m_remote_address.is_blockable() || disable_rpc_ban)
      return false;

    CRITICAL_REGION_LOCAL(m_host_fails_score_lock);
    uint64_t fails = m_host_fails_score[ctx->m_remote_address.host_str()] += score;
    MDEBUG("Host " << ctx->m_remote_address.host_str() << " fail score=" << fails);
    if(fails > RPC_IP_FAILS_BEFORE_BLOCK)
    {
      auto it = m_host_fails_score.find(ctx->m_remote_address.host_str());
      CHECK_AND_ASSERT_MES(it != m_host_fails_score.end(), false, "internal error");
      it->second = RPC_IP_FAILS_BEFORE_BLOCK/2;
      m_p2p.block_host(ctx->m_remote_address);
    }
    return true;
  }
#define CHECK_CORE_READY() do { if(!check_core_ready()){res.status =  CORE_RPC_STATUS_BUSY;return true;} } while(0)

  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_height);
 

    crypto::hash hash;
    m_core.get_blockchain_top(res.height, hash);
    ++res.height; // block height to chain height
    res.hash = string_tools::pod_to_hex(hash);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_info);

    const bool restricted = m_restricted && ctx;

    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    ++res.height; // turn top block height into blockchain height
    res.top_block_hash = string_tools::pod_to_hex(top_hash);
    res.target_height = m_p2p.get_crypto_protocol().is_synchronized() ? 0 : m_core.get_target_blockchain_height();
    store_difficulty(m_core.get_blockchain_storage().get_difficulty_for_next_block(), res.difficulty, res.wide_difficulty, res.difficulty_top64);
    res.target = m_core.get_blockchain_storage().get_difficulty_target();
    res.tx_count = m_core.get_blockchain_storage().get_total_transactions() - res.height; //without coinbase
    res.tx_pool_size = m_core.get_pool_transactions_count(!restricted);
    res.alt_blocks_count = restricted ? 0 : m_core.get_blockchain_storage().get_alternative_blocks_count();
    uint64_t total_conn = restricted ? 0 : m_p2p.get_public_connections_count();
    res.outgoing_connections_count = restricted ? 0 : m_p2p.get_outgoing_connections_count();
    res.incoming_connections_count = restricted ? 0 : (total_conn - res.outgoing_connections_count);
    res.rpc_connections_count = restricted ? 0 : get_connections_count();
    res.white_peerlist_size = restricted ? 0 : m_p2p.get_public_white_peers_count();
    res.grey_peerlist_size = restricted ? 0 : m_p2p.get_public_gray_peers_count();

    cryptonote::network_type net_type = nettype();
    res.mainnet = net_type == MAINNET;
    res.testnet = net_type == TESTNET;
    res.stagenet = net_type == STAGENET;
    res.nettype = net_type == MAINNET ? "mainnet" : net_type == TESTNET ? "testnet" : net_type == STAGENET ? "stagenet" : "fakechain";
    store_difficulty(m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(res.height - 1),
        res.cum_diff, res.wide_cumulative_difficulty, res.cumulative_difficulty_top64);
    res.block_size_limit =0 ;
    res.block_size_median = res.block_weight_median = 0;
    res.adjusted_time = m_core.get_blockchain_storage().get_adjusted_time(res.height);

    res.start_time = restricted ? 0 : (uint64_t)m_core.get_start_time();
    res.free_space = restricted ? std::numeric_limits<uint64_t>::max() : m_core.get_free_space();
    res.offline = m_core.offline();
  
    res.database_size = m_core.get_blockchain_storage().get_db().get_database_size();
    if (restricted)
      res.database_size = round_up(res.database_size, 5ull* 1024 * 1024 * 1024);
    res.update_available = restricted ? false : m_core.is_update_available();
    res.version = restricted ? "" : MONERO_VERSION_FULL;
    res.synchronized = check_core_ready();
    res.busy_syncing = m_p2p.get_crypto_protocol().is_busy_syncing();

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_net_stats(const COMMAND_RPC_GET_NET_STATS::request& req, COMMAND_RPC_GET_NET_STATS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_net_stats);
    // No bootstrap daemon check: Only ever get stats about local server
    res.start_time = (uint64_t)m_core.get_start_time();
    {
      CRITICAL_REGION_LOCAL(epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_in);
      epee::net_utils::network_throttle_manager::get_global_throttle_in().get_stats(res.total_packets_in, res.total_bytes_in);
    }
    {
      CRITICAL_REGION_LOCAL(epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_out);
      epee::net_utils::network_throttle_manager::get_global_throttle_out().get_stats(res.total_packets_out, res.total_bytes_out);
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  class pruned_transaction {
    transaction& tx;
  public:
    pruned_transaction(transaction& tx) : tx(tx) {}
    BEGIN_SERIALIZE_OBJECT()
      bool r = tx.serialize_base(ar);
      if (!r) return false;
    END_SERIALIZE()
  };
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_blocks);

    // quick check for noop
    if (!req.block_ids.empty())
    {
      const auto [height,top_hash]=m_core.get_blockchain_top();
      if (top_hash == req.block_ids.front())
      {
        res.start_height = 0;
        res.current_height = height;
        res.status = CORE_RPC_STATUS_OK;
        return true;
      }
    }

    size_t max_blocks = COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT;


    std::vector<BlockchainDB::BlockData > bs;
    if(!m_core.find_blockchain_supplement(req.start_height, req.block_ids, bs, res.current_height, res.start_height, req.prune, true, max_blocks, COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT))
    {
      res.status = "Failed";
      add_host_fail(ctx);
      return true;
    }


    size_t size = 0, ntxes = 0;
    res.blocks.reserve(bs.size());
    res.output_indices.reserve(bs.size());
    for(auto& bd: bs)
    {
      res.blocks.resize(res.blocks.size()+1);
      auto & bb = res.blocks.back();
      bb.pruned = req.prune;
      bb.block = bd.b_blob;
      size += bd.b_blob.size();
      res.output_indices.push_back(COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices());
      ntxes += bd.txes.size();
      auto & b_oi = res.output_indices.back().indices;
      b_oi.reserve(1 + bd.txes.size());
      
      bb.txs.reserve(bd.txes.size());
      for (auto &[t_hash,t_blob]:bd.txes)
      {
        bb.txs.push_back({std::move(t_blob), crypto::null_hash});
        size += bb.txs.back().blob.size();
      }

      const size_t n_txes_to_lookup = bd.txes.size() + 1;
     // if (n_txes_to_lookup > 0)
      {
        std::vector<std::vector<uint64_t>> indices;
        bool r = m_core.get_tx_outputs_gindexs(bd.miner_tx_hash, n_txes_to_lookup, indices);
        if (!r)
        {
          res.status = "Failed";
          return true;
        }
        if (indices.size() != n_txes_to_lookup || res.output_indices.back().indices.size() != 0)
        {
          res.status = "Failed";
          return true;
        }
        for (auto & e : indices)
          b_oi.push_back({std::move(e)});
      }
    }

    MDEBUG("on_get_blocks: " << bs.size() << " blocks, " << ntxes << " txes, size " << size);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

bool core_rpc_server::on_get_alt_blocks_hashes(const COMMAND_RPC_GET_ALT_BLOCKS_HASHES::request& req, COMMAND_RPC_GET_ALT_BLOCKS_HASHES::response& res, const connection_context *ctx)
    {
      RPC_TRACKER(get_alt_blocks_hashes);
   

      std::vector<block> blks;

      if(!m_core.get_alternative_blocks(blks))
      {
          res.status = "Failed";
          return true;
      }

      res.blks_hashes.reserve(blks.size());

      for (auto const& blk: blks)
      {
          res.blks_hashes.push_back(epee::string_tools::pod_to_hex(get_block_hash(blk)));
      }

      MDEBUG("on_get_alt_blocks_hashes: " << blks.size() << " blocks " );
      res.status = CORE_RPC_STATUS_OK;
      return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_blocks_by_height(const COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_blocks_by_height);
  

    const bool restricted = m_restricted && ctx;
    if (restricted && req.heights.size() > RESTRICTED_BLOCK_COUNT)
    {
      res.status = "Too many blocks requested in restricted mode";
      return true;
    }

    res.status = "Failed";
    res.blocks.clear();
    res.blocks.reserve(req.heights.size());
    
    for (uint64_t height : req.heights)
    {
      block blk;
      try
      {
        blk = m_core.get_blockchain_storage().get_db().get_block_from_height(height);
      }
      catch (...)
      {
        res.status = "Error retrieving block at height " + std::to_string(height);
        return true;
      }
      std::vector<transaction> txs;
      std::vector<crypto::hash> missed_txs;
      m_core.get_transactions(blk.tx_hashes, txs, missed_txs);
      res.blocks.resize(res.blocks.size() + 1);
      res.blocks.back().block = block_to_blob(blk);
      for (auto& tx : txs)
        res.blocks.back().txs.push_back({tx_to_blob(tx), crypto::null_hash});
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_hashes(const COMMAND_RPC_GET_HASHES_FAST::request& req, COMMAND_RPC_GET_HASHES_FAST::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_hashes);

    res.start_height = req.start_height;
    if(!m_core.get_blockchain_storage().find_blockchain_supplement(req.block_ids, res.m_block_ids, NULL, res.start_height, res.current_height, false))
    {
      res.status = "Failed";
      add_host_fail(ctx);
      return true;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_outs_bin(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_outs_bin);


    res.status = "Failed";

    const bool restricted = m_restricted && ctx;
    if (restricted)
    {
      if (req.outputs.size() > MAX_RESTRICTED_GLOBAL_FAKE_OUTS_COUNT)
      {
        res.status = "Too many outs requested";
        return true;
      }
    }

    if(!m_core.get_outs(req, res))
    {
      return true;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_outs(const COMMAND_RPC_GET_OUTPUTS::request& req, COMMAND_RPC_GET_OUTPUTS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_outs);

    res.status = "Failed";

    const bool restricted = m_restricted && ctx;
    if (restricted)
    {
      if (req.outputs.size() > MAX_RESTRICTED_GLOBAL_FAKE_OUTS_COUNT)
      {
        res.status = "Too many outs requested";
        return true;
      }
    }

    cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::request req_bin;
    req_bin.outputs = req.outputs;
    cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::response res_bin;
    if(!m_core.get_outs(req_bin, res_bin))
    {
      return true;
    }

    // convert to text
    for (const auto &i: res_bin.outs)
    {
      res.outs.push_back(cryptonote::COMMAND_RPC_GET_OUTPUTS::outkey());
      auto &outkey = res.outs.back();
      outkey.key = epee::string_tools::pod_to_hex(i.key);
      outkey.commitment = epee::string_tools::pod_to_hex(i.commitment);
      outkey.unlocked = i.unlocked;
      outkey.height = i.height;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_indexes);


    

    bool r = m_core.get_tx_outputs_gindexs(req.txid, res.o_indexes);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    MINFO("COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES: [" << res.o_indexes.size() << "]");
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transactions);
  
    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;

    if (restricted && req.txs_hashes.size() > RESTRICTED_TRANSACTIONS_COUNT)
    {
      res.status = "Too many transactions requested in restricted mode";
      return true;
    }


    std::vector<crypto::hash> vh;
    for(const auto& tx_hex_str: req.txs_hashes)
    {
      blobdata b;
      if(!string_tools::parse_hexstr_to_binbuff(tx_hex_str, b))
      {
        res.status = "Failed to parse hex representation of transaction hash";
        return true;
      }
      if(b.size() != sizeof(crypto::hash))
      {
        res.status = "Failed, size of data mismatch";
        return true;
      }
      vh.push_back(*reinterpret_cast<const crypto::hash*>(b.data()));
    }
    std::vector<crypto::hash> missed_txs;
    std::vector<std::tuple<crypto::hash, cryptonote::blobdata, crypto::hash, cryptonote::blobdata>> txs;
    bool r = m_core.get_split_transactions_blobs(vh, txs, missed_txs);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    MINFO("Found " << txs.size() << "/" << vh.size() << " transactions on the blockchain");

    // try the pool for any missing txes
    size_t found_in_pool = 0;
    std::unordered_set<crypto::hash> pool_tx_hashes;
    std::unordered_map<crypto::hash, tx_info> per_tx_pool_tx_info;
    if (!missed_txs.empty())
    {
      std::vector<tx_info> pool_tx_info;
      bool r = m_core.get_pool_transactions_and_spent_keys_info(pool_tx_info,  !request_has_rpc_origin || !restricted);
      if(r)
      {
        // sort to match original request
        std::vector<std::tuple<crypto::hash, cryptonote::blobdata, crypto::hash, cryptonote::blobdata>> sorted_txs;
        std::vector<tx_info>::const_iterator i;
        unsigned txs_processed = 0;
        for (const crypto::hash &h: vh)
        {
          if (std::find(missed_txs.begin(), missed_txs.end(), h) == missed_txs.end())
          {
            if (txs.size() == txs_processed)
            {
              res.status = "Failed: internal error - txs is empty";
              return true;
            }
            // core returns the ones it finds in the right order
            if (std::get<0>(txs[txs_processed]) != h)
            {
              res.status = "Failed: tx hash mismatch";
              return true;
            }
            sorted_txs.push_back(std::move(txs[txs_processed]));
            ++txs_processed;
          }
          else if ((i = std::find_if(pool_tx_info.begin(), pool_tx_info.end(), [h](const tx_info &txi) { return epee::string_tools::pod_to_hex(h) == txi.id_hash; })) != pool_tx_info.end())
          {
            cryptonote::transaction tx;
            if (!cryptonote::parse_and_validate_tx_from_blob(i->tx_blob, tx))
            {
              res.status = "Failed to parse and validate tx from blob";
              return true;
            }
            std::stringstream ss;
            binary_archive<true> ba(ss);
            bool r = const_cast<cryptonote::transaction&>(tx).serialize_base(ba);
            if (!r)
            {
              res.status = "Failed to serialize transaction base";
              return true;
            }
            const cryptonote::blobdata pruned = ss.str();
            const crypto::hash prunable_hash =  get_transaction_prunable_hash(tx);
            sorted_txs.push_back(std::make_tuple(h, pruned, prunable_hash, std::string(i->tx_blob, pruned.size())));
            missed_txs.erase(std::find(missed_txs.begin(), missed_txs.end(), h));
            pool_tx_hashes.insert(h);
            const std::string hash_string = epee::string_tools::pod_to_hex(h);
            for (const auto &ti: pool_tx_info)
            {
              if (ti.id_hash == hash_string)
              {
                per_tx_pool_tx_info.insert(std::make_pair(h, ti));
                break;
              }
            }
            ++found_in_pool;
          }
        }
        txs = sorted_txs;
      }
      MINFO("Found " << found_in_pool << "/" << vh.size() << " transactions in the pool");
    }

    std::vector<std::string>::const_iterator txhi = req.txs_hashes.begin();
    std::vector<crypto::hash>::const_iterator vhi = vh.begin();
    for(auto& tx: txs)
    {
      res.txs.push_back(COMMAND_RPC_GET_TRANSACTIONS::entry());
      COMMAND_RPC_GET_TRANSACTIONS::entry &e = res.txs.back();

      crypto::hash tx_hash = *vhi++;
      e.tx_hash = *txhi++;
      e.prunable_hash = epee::string_tools::pod_to_hex(std::get<2>(tx));
      if (req.split || req.prune || std::get<3>(tx).empty())
      {
        // use splitted form with pruned and prunable (filled only when prune=false and the daemon has it), leaving as_hex as empty
        e.pruned_as_hex = string_tools::buff_to_hex_nodelimer(std::get<1>(tx));
        if (!req.prune)
          e.prunable_as_hex = string_tools::buff_to_hex_nodelimer(std::get<3>(tx));
        if (req.decode_as_json)
        {
          cryptonote::blobdata tx_data;
          cryptonote::transaction t;
          if (req.prune || std::get<3>(tx).empty())
          {
            // decode pruned tx to JSON
            tx_data = std::get<1>(tx);
            if (cryptonote::parse_and_validate_tx_base_from_blob(tx_data, t))
            {
              pruned_transaction pruned_tx{t};
              e.as_json = obj_to_json_str(pruned_tx);
            }
            else
            {
              res.status = "Failed to parse and validate pruned tx from blob";
              return true;
            }
          }
          else
          {
            // decode full tx to JSON
            tx_data = std::get<1>(tx) + std::get<3>(tx);
            if (cryptonote::parse_and_validate_tx_from_blob(tx_data, t))
            {
              e.as_json = obj_to_json_str(t);
            }
            else
            {
              res.status = "Failed to parse and validate tx from blob";
              return true;
            }
          }
        }
      }
      else
      {
        // use non-splitted form, leaving pruned_as_hex and prunable_as_hex as empty
        cryptonote::blobdata tx_data = std::get<1>(tx) + std::get<3>(tx);
        e.as_hex = string_tools::buff_to_hex_nodelimer(tx_data);
        if (req.decode_as_json)
        {
          cryptonote::transaction t;
          if (cryptonote::parse_and_validate_tx_from_blob(tx_data, t))
          {
            e.as_json = obj_to_json_str(t);
          }
          else
          {
            res.status = "Failed to parse and validate tx from blob";
            return true;
          }
        }
      }
      e.in_pool = pool_tx_hashes.find(tx_hash) != pool_tx_hashes.end();
      if (e.in_pool)
      {
        e.block_height = e.block_timestamp = std::numeric_limits<uint64_t>::max();
        auto it = per_tx_pool_tx_info.find(tx_hash);
        if (it != per_tx_pool_tx_info.end())
        {
          e.relayed = it->second.relayed;
          e.received_timestamp = it->second.receive_time;
        }
        else
        {
          MERROR("Failed to determine pool info for " << tx_hash);
          e.relayed = false;
          e.received_timestamp = 0;
        }
      }
      else
      {
        e.block_height = m_core.get_blockchain_storage().get_db().get_tx_block_height(tx_hash);
        e.block_timestamp = m_core.get_blockchain_storage().get_db().get_block_timestamp(e.block_height);
        e.received_timestamp = 0;
        e.relayed = false;
      }

      // fill up old style responses too, in case an old wallet asks
      res.txs_as_hex.push_back(e.as_hex);
      if (req.decode_as_json)
        res.txs_as_json.push_back(e.as_json);

      // output indices too if not in pool
      if (pool_tx_hashes.find(tx_hash) == pool_tx_hashes.end())
      {
        bool r = m_core.get_tx_outputs_gindexs(tx_hash, e.output_indices);
        if (!r)
        {
          res.status = "Failed";
          return true;
        }
      }
    }

    for(const auto& miss_tx: missed_txs)
    {
      res.missed_tx.push_back(string_tools::pod_to_hex(miss_tx));
    }

    MINFO(res.txs.size() << " transactions found, " << res.missed_tx.size() << " not found");
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_is_key_image_spent(const COMMAND_RPC_IS_KEY_IMAGE_SPENT::request& req, COMMAND_RPC_IS_KEY_IMAGE_SPENT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(is_key_image_spent);

    const bool restricted = m_restricted && ctx;

    if (restricted && req.key_images.size() > RESTRICTED_SPENT_KEY_IMAGES_COUNT)
    {
      res.status = "Too many key images queried in restricted mode";
      return true;
    }

    
    using R=COMMAND_RPC_IS_KEY_IMAGE_SPENT;
    const Blockchain & bc = m_core.get_blockchain_storage();
    for(const auto& ki_hex_str: req.key_images)
    {
      blobdata b;
      if(!string_tools::parse_hexstr_to_binbuff(ki_hex_str, b))
      {
        res.status = "Failed to parse hex representation of key image";
        return true;
      }
      if(b.size() != sizeof(crypto::key_image))
      {
        res.status = "Failed, size of data mismatch";
      }
      const auto ki = (*reinterpret_cast<const crypto::key_image*>(b.data()));
      const R::STATUS s= bc.have_tx_keyimg_as_spent(ki)?R::SPENT_IN_BLOCKCHAIN : m_core.pool_has_key_image(ki)? R::SPENT_IN_POOL : R::UNSPENT;
      res.spent_status.push_back(s);
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

   //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
      try{
      PERF_TIMER(submitblock);
      RPCTracker tracker("submitblock", PERF_TIMER_NAME(submitblock));

      CHECK_CORE_READY();
      if(req.size()!=1)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Wrong param";
        return false;
      }
      blobdata blockblob;
      if(!string_tools::parse_hexstr_to_binbuff(req[0], blockblob))
      {
        
      }
      
      // Fixing of high orphan issue for most pools
      // Thanks Boolberry!
      const block b =parse_and_validate_block_from_blob(blockblob);

      // Fix from Boolberry neglects to check block
      // size, do that with the function below
      if(!m_core.check_incoming_block_size(blockblob))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE;
        error_resp.message = "Block bloc size is too big, rejecting block";
        return false;
      }

      block_verification_context bvc;
      if(!m_core.handle_block_found(b, bvc))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED;
        error_resp.message = "Block not accepted";
        return false;
      }

      if(bvc.m_added_to_main_chain)
      {
        cryptonote_peer_context exclude_context = {};
        NOTIFY_NEW_BLOCK::request arg {};
        arg.current_blockchain_height = m_core.get_current_blockchain_height();
        std::vector<crypto::hash> missed_txs;
        std::vector<cryptonote::blobdata> txs;
        m_core.get_transactions(b.tx_hashes, txs, missed_txs);
        if(missed_txs.size() &&  m_core.get_block_hash_by_height(cryptonote::get_block_height(b)) != get_block_hash(b))
        {
          MWARNING("Block found but, seems that reorganize just happened after that, do not relay this block");
          return true;
        }
        CHECK_AND_ASSERT_MES(txs.size() == b.tx_hashes.size() && !missed_txs.size(), false, "can't find some transactions in found block:" << get_block_hash(b) << " txs.size()=" << txs.size()<< ", b.tx_hashes.size()=" << b.tx_hashes.size() << ", missed_txs.size()" << missed_txs.size());

        cryptonote::block_to_blob(b, arg.b.block);
        //pack transactions
        for(auto& tx:  txs)
          arg.b.txs.push_back({tx, crypto::null_hash});

        m_p2p.get_crypto_protocol().relay_block(arg, exclude_context);
      }

      res.status = CORE_RPC_STATUS_OK;
      return true;
    }
    catch(std::exception & ex){
       error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
        error_resp.message = "Wrong block blob";
        return false;
    }

  }
 
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_submit_tx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(send_raw_tx);

    {
      CHECK_CORE_READY();
    }


    std::string tx_blob;
    if(!string_tools::parse_hexstr_to_binbuff(req.tx_as_hex, tx_blob))
    {
      LOG_PRINT_L0("[on_submit_tx]: Failed to parse tx from hexbuff: " << req.tx_as_hex);
      res.status = "Failed";
      return true;
    }

    res.sanity_check_failed = false;

   // if (!skip_validation)
    {
      tx_verification_context tvc{};
      if(!m_core.handle_incoming_tx({tx_blob, crypto::null_hash}, tvc, relay_method::local, false) || tvc.m_verifivation_failed)
      {
        res.status = "Failed";
        std::string reason = "";
        if ((res.low_mixin = tvc.m_low_mixin))
          add_reason(reason, "bad ring size");
        if ((res.double_spend = tvc.m_double_spend))
          add_reason(reason, "double spend");
        if ((res.invalid_input = tvc.m_invalid_input))
          add_reason(reason, "invalid input");
        if ((res.invalid_output = tvc.m_invalid_output))
          add_reason(reason, "invalid output");
        if ((res.too_big = tvc.m_too_big))
          add_reason(reason, "too big");
        if ((res.overspend = tvc.m_overspend))
          add_reason(reason, "overspend");
        if ((res.fee_too_low = tvc.m_fee_too_low))
          add_reason(reason, "fee too low");
        if ((res.too_few_outputs = tvc.m_too_few_outputs))
          add_reason(reason, "too few outputs");
        const std::string punctuation = reason.empty() ? "" : ": ";
        if (tvc.m_verifivation_failed)
        {
          LOG_PRINT_L0("[on_submit_tx]: tx verification failed" << punctuation << reason);
        }
        else
        {
          LOG_PRINT_L0("[on_submit_tx]: Failed to process tx" << punctuation << reason);
        }
        return true;
      }

      if(tvc.m_relay == relay_method::none)
      {
        LOG_PRINT_L0("[on_submit_tx]: tx accepted, but not relayed");
        res.reason = "Not relayed";
        res.not_relayed = true;
        res.status = CORE_RPC_STATUS_OK;
        return true;
      }
    }

    NOTIFY_NEW_TRANSACTIONS::request r;
    r.txs.push_back(std::move(tx_blob));
    m_p2p.get_crypto_protocol().relay_transactions(r, boost::uuids::nil_uuid(), epee::net_utils::zone::invalid, relay_method::local);
    //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

 
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_save_bc(const COMMAND_RPC_SAVE_BC::request& req, COMMAND_RPC_SAVE_BC::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(save_bc);
    if( !m_core.get_blockchain_storage().store_blockchain() )
    {
      res.status = "Error while storing blockchain";
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_peer_list);
    std::vector<nodetool::peerlist_entry> white_list;
    std::vector<nodetool::peerlist_entry> gray_list;

  
      m_p2p.get_peerlist(gray_list, white_list);
    
    for (auto & entry : white_list)
    {
      if (!req.include_blocked && m_p2p.is_host_blocked(entry.adr, NULL))
        continue;
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
        res.white_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
      else if (entry.adr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
        res.white_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv6_network_address>().host_str(),
            entry.adr.as<epee::net_utils::ipv6_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
      else
        res.white_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
    }

    for (auto & entry : gray_list)
    {
      if (!req.include_blocked && m_p2p.is_host_blocked(entry.adr, NULL))
        continue;
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
        res.gray_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
      else if (entry.adr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
        res.gray_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv6_network_address>().host_str(),
            entry.adr.as<epee::net_utils::ipv6_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
      else
        res.gray_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_public_nodes(const COMMAND_RPC_GET_PUBLIC_NODES::request& req, COMMAND_RPC_GET_PUBLIC_NODES::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_public_nodes);

    COMMAND_RPC_GET_PEER_LIST::request peer_list_req;
    COMMAND_RPC_GET_PEER_LIST::response peer_list_res;
    peer_list_req.include_blocked = req.include_blocked;
    const bool success = on_get_peer_list(peer_list_req, peer_list_res, ctx);
    res.status = peer_list_res.status;
    if (!success)
    {      
      res.status = "Failed to get peer list";
      return true;
    }
    if (res.status != CORE_RPC_STATUS_OK)
    {
      return true;
    }

    const auto collect = [](const std::vector<peer> &peer_list, std::vector<public_node> &public_nodes)
    {
      for (const auto &entry : peer_list)
      {
        if (entry.rpc_port != 0)
        {
          public_nodes.emplace_back(entry);
        }
      }
    };

    if (req.white)
    {
      collect(peer_list_res.white_list, res.white);
    }
    if (req.gray)
    {
      collect(peer_list_res.gray_list, res.gray);
    }

    return true;
  }
 
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_level(const COMMAND_RPC_SET_LOG_LEVEL::request& req, COMMAND_RPC_SET_LOG_LEVEL::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(set_log_level);
    if (req.level < 0 || req.level > 4)
    {
      res.status = "Error: log level not valid";
      return true;
    }
    mlog_set_log_level(req.level);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_categories(const COMMAND_RPC_SET_LOG_CATEGORIES::request& req, COMMAND_RPC_SET_LOG_CATEGORIES::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(set_log_categories);
    mlog_set_log(req.categories.c_str());
    res.categories = mlog_get_categories();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool(const COMMAND_RPC_GET_TRANSACTION_POOL::request& req, COMMAND_RPC_GET_TRANSACTION_POOL::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool);

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;
    const bool allow_sensitive = !request_has_rpc_origin || !restricted;

    size_t n_txes = m_core.get_pool_transactions_count(allow_sensitive);
    if (n_txes > 0)
    {
      m_core.get_pool_transactions_and_spent_keys_info(res.transactions, allow_sensitive);
      for (tx_info& txi : res.transactions)
        txi.tx_blob = epee::string_tools::buff_to_hex_nodelimer(txi.tx_blob);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_hashes_bin(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool_hashes);
    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;
    const bool allow_sensitive = !request_has_rpc_origin || !restricted;

    size_t n_txes = m_core.get_pool_transactions_count(allow_sensitive);
    if (n_txes > 0)
    {
      m_core.get_pool_transaction_hashes(res.tx_hashes, allow_sensitive);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_hashes(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool_hashes);
   


    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;
    const bool allow_sensitive = !request_has_rpc_origin || !restricted;

    size_t n_txes = m_core.get_pool_transactions_count(allow_sensitive);
    if (n_txes > 0)
    {
      std::vector<crypto::hash> tx_hashes;
      m_core.get_pool_transaction_hashes(tx_hashes, allow_sensitive);
      res.tx_hashes.reserve(tx_hashes.size());
      for (const crypto::hash &tx_hash: tx_hashes)
        res.tx_hashes.push_back(epee::string_tools::pod_to_hex(tx_hash));
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_stats(const COMMAND_RPC_GET_TRANSACTION_POOL_STATS::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_STATS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool_stats);
 

    

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;
    m_core.get_pool_transaction_stats(res.pool_stats, !request_has_rpc_origin || !restricted);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  
  
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(getblockcount);
   
    res.count = m_core.get_current_blockchain_height();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(getblockhash);
   
    if(req.size() != 1)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Wrong parameters, expected height";
      return false;
    }
    uint64_t h = req[0];
    if(m_core.get_current_blockchain_height() <= h)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = std::string("Requested block height: ") + std::to_string(h) + " greater than current top block height: " +  std::to_string(m_core.get_current_blockchain_height() - 1);
    }
    res = string_tools::pod_to_hex(m_core.get_block_hash_by_height(h));
    return true;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(getblocktemplate);

     try{

    if(!check_core_ready())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_CORE_BUSY;
      error_resp.message = "Core is busy";
      return false;
    }

    if(req.reserve_size > 255)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE;
      error_resp.message = "Too big reserved size, maximum 255";
      return false;
    }

    if(req.reserve_size && !req.extra_nonce.empty())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Cannot specify both a reserve_size and an extra_nonce";
      return false;
    }

    if(req.extra_nonce.size() > 510)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE;
      error_resp.message = "Too big extra_nonce size, maximum 510 hex chars";
      return false;
    }

    const auto &miner_addr = cryptonote::get_account_address_from_str( nettype(), req.wallet_address);

    const auto blob_reserve= !req.extra_nonce.empty() ?string_tools::parse_hexstr_to_binbuff(req.extra_nonce): blobdata(req.reserve_size, 0);
   

    cryptonote::difficulty_type wdiff;
    crypto::hash prev_block=crypto::null_hash;
    if (!req.prev_block.empty())
    {
      if (!epee::string_tools::hex_to_pod(req.prev_block, prev_block))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Invalid prev_block";
        return false;
      }
    }
    const auto bt= m_core.get_block_template(prev_block==crypto::null_hash ? nullptr:&prev_block, miner_addr,blob_reserve);
  
    res.seed_hash = string_tools::pod_to_hex(bt.seed_hash);
    res.next_seed_hash = string_tools::pod_to_hex(bt.n_seed_hash);

    res.reserved_offset = bt.reserved_offset;
    store_difficulty(bt.diff, res.difficulty, res.wide_difficulty, res.difficulty_top64);
    blobdata block_blob = t_serializable_object_to_blob(bt.b);
    blobdata hashing_blob = get_block_hashing_blob(bt.b);
    res.prev_hash = string_tools::pod_to_hex(bt.b.prev_id);
    res.blocktemplate_blob = string_tools::buff_to_hex_nodelimer(block_blob);
    res.blockhashing_blob =  string_tools::buff_to_hex_nodelimer(hashing_blob);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  catch(std::exception & e){
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to create block template");
    return false;
  }
  }
 
 
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::fill_block_header_response(const block& blk, bool orphan_status, uint64_t height, const crypto::hash& hash, block_header_response& response, bool fill_pow_hash)
  {
    PERF_TIMER(fill_block_header_response);
    response.major_version = blk.major_version;
    response.minor_version = blk.minor_version;
    response.timestamp = blk.timestamp;
    response.prev_hash = string_tools::pod_to_hex(blk.prev_id);
    response.nonce = blk.nonce;
    response.orphan_status = orphan_status;
    response.height = height;
    response.depth = m_core.get_current_blockchain_height() - height - 1;
    response.hash = string_tools::pod_to_hex(hash);
    store_difficulty(m_core.get_blockchain_storage().block_difficulty(height),
        response.difficulty, response.wide_difficulty, response.difficulty_top64);
    store_difficulty(m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(height),
        response.cum_diff, response.wide_cumulative_difficulty, response.cumulative_difficulty_top64);
    response.reward = get_outs_money_amount(blk.miner_tx);
    response.block_size = response.block_weight = m_core.get_blockchain_storage().get_db().get_block_weight(height);
    response.num_txes = blk.tx_hashes.size();
    response.pow_hash = fill_pow_hash ? string_tools::pod_to_hex(get_block_pow(&(m_core.get_blockchain_storage()), blk, height)) : "";
    response.long_term_weight = 0;
    response.miner_tx_hash = string_tools::pod_to_hex(cryptonote::get_transaction_hash(blk.miner_tx));
    return true;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_last_block_header);
   
    CHECK_CORE_READY();
    uint64_t last_block_height;
    crypto::hash last_block_hash;
    m_core.get_blockchain_top(last_block_height, last_block_hash);
    block last_block;
    bool have_last_block = m_core.get_block_by_hash(last_block_hash, last_block);
    if (!have_last_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get last block.";
      return false;
    }
    const bool restricted = m_restricted && ctx;
    bool response_filled = fill_block_header_response(last_block, false, last_block_height, last_block_hash, res.block_header, req.fill_pow_hash && !restricted);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_block_header_by_hash);
  

    

    const bool restricted = m_restricted && ctx;
    if (restricted && req.hashes.size() > RESTRICTED_BLOCK_COUNT)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_RESTRICTED;
      error_resp.message = "Too many block headers requested in restricted mode";
      return false;
    }

    auto get = [this](const std::string &hash, bool fill_pow_hash, block_header_response &block_header, bool restricted, epee::json_rpc::error& error_resp) -> bool {
      crypto::hash block_hash;
      bool hash_parsed = parse_hash256(hash, block_hash);
      if(!hash_parsed)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Failed to parse hex representation of block hash. Hex = " + hash + '.';
        return false;
      }
      block blk;
      bool orphan = false;
      bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);
      if (!have_block)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't get block by hash. Hash = " + hash + '.';
        return false;
      }
      if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
        return false;
      }
      uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
      bool response_filled = fill_block_header_response(blk, orphan, block_height, block_hash, block_header, fill_pow_hash && !restricted);
      if (!response_filled)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't produce valid response.";
        return false;
      }
      return true;
    };

    if (!req.hash.empty())
    {
      if (!get(req.hash, req.fill_pow_hash, res.block_header, restricted, error_resp))
        return false;
    }
    res.block_headers.reserve(req.hashes.size());
    for (const std::string &hash: req.hashes)
    {
      res.block_headers.push_back({});
      if (!get(hash, req.fill_pow_hash, res.block_headers.back(), restricted, error_resp))
        return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_headers_range(const COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request& req, COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_block_headers_range);
   

    const uint64_t bc_height = m_core.get_current_blockchain_height();
    if (req.start_height >= bc_height || req.end_height >= bc_height || req.start_height > req.end_height)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = "Invalid start/end heights.";
      return false;
    }
    const bool restricted = m_restricted && ctx;
    if (restricted && req.end_height - req.start_height > RESTRICTED_BLOCK_HEADER_RANGE)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_RESTRICTED;
      error_resp.message = "Too many block headers requested.";
      return false;
    }

    
    for (uint64_t h = req.start_height; h <= req.end_height; ++h)
    {
      crypto::hash block_hash = m_core.get_block_hash_by_height(h);
      block blk;
      bool have_block = m_core.get_block_by_hash(block_hash, blk);
      if (!have_block)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't get block by height. Height = " + boost::lexical_cast<std::string>(h) + ". Hash = " + epee::string_tools::pod_to_hex(block_hash) + '.';
        return false;
      }
      if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
        return false;
      }
      uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
      if (block_height != h)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong height";
        return false;
      }
      res.headers.push_back(block_header_response());
      bool response_filled = fill_block_header_response(blk, false, block_height, block_hash, res.headers.back(), req.fill_pow_hash && !restricted);
      if (!response_filled)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't produce valid response.";
        return false;
      }
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_block_header_by_height);
  

    if(m_core.get_current_blockchain_height() <= req.height)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = std::string("Requested block height: ") + std::to_string(req.height) + " greater than current top block height: " +  std::to_string(m_core.get_current_blockchain_height() - 1);
      return false;
    }
    
    crypto::hash block_hash = m_core.get_block_hash_by_height(req.height);
    block blk;
    bool have_block = m_core.get_block_by_hash(block_hash, blk);
    if (!have_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get block by height. Height = " + std::to_string(req.height) + '.';
      return false;
    }
    const bool restricted = m_restricted && ctx;
    bool response_filled = fill_block_header_response(blk, false, req.height, block_hash, res.block_header, req.fill_pow_hash && !restricted);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block(const COMMAND_RPC_GET_BLOCK::request& req, COMMAND_RPC_GET_BLOCK::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_block);
   


    crypto::hash block_hash;
    if (!req.hash.empty())
    {
      bool hash_parsed = parse_hash256(req.hash, block_hash);
      if(!hash_parsed)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Failed to parse hex representation of block hash. Hex = " + req.hash + '.';
        return false;
      }
    }
    else
    {
      if(m_core.get_current_blockchain_height() <= req.height)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
        error_resp.message = std::string("Requested block height: ") + std::to_string(req.height) + " greater than current top block height: " +  std::to_string(m_core.get_current_blockchain_height() - 1);
        return false;
      }
      block_hash = m_core.get_block_hash_by_height(req.height);
    }
    block blk;
    bool orphan = false;
    bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);
    if (!have_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get block by hash. Hash = " + req.hash + '.';
      return false;
    }
    if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
      return false;
    }
    uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
    const bool restricted = m_restricted && ctx;
    bool response_filled = fill_block_header_response(blk, orphan, block_height, block_hash, res.block_header, req.fill_pow_hash && !restricted);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.miner_tx_hash = res.block_header.miner_tx_hash;
    for (size_t n = 0; n < blk.tx_hashes.size(); ++n)
    {
      res.tx_hashes.push_back(epee::string_tools::pod_to_hex(blk.tx_hashes[n]));
    }
    res.blob = string_tools::buff_to_hex_nodelimer(t_serializable_object_to_blob(blk));
    res.json = obj_to_json_str(blk);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_connections);

    res.connections = m_p2p.get_crypto_protocol().get_connections();

    res.status = CORE_RPC_STATUS_OK;

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_info_json(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    if (!on_get_info(req, res, ctx) || res.status != CORE_RPC_STATUS_OK)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = res.status;
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_hard_fork_info(const COMMAND_RPC_HARD_FORK_INFO::request& req, COMMAND_RPC_HARD_FORK_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(hard_fork_info);
    

    const Blockchain &blockchain = m_core.get_blockchain_storage();
    uint8_t version = req.version > 0 ? req.version : blockchain.get_next_hard_fork_version();
    res.version = blockchain.get_current_hard_fork_version();
    res.enabled = blockchain.get_hard_fork_voting_info(version, res.window, res.votes, res.threshold, res.earliest_height, res.voting);
    res.state = blockchain.get_hard_fork_state();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_bans(const COMMAND_RPC_GETBANS::request& req, COMMAND_RPC_GETBANS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_bans);

    auto now = time(nullptr);
    std::map<std::string, time_t> blocked_hosts = m_p2p.get_blocked_hosts();
    for (std::map<std::string, time_t>::const_iterator i = blocked_hosts.begin(); i != blocked_hosts.end(); ++i)
    {
      if (i->second > now) {
        COMMAND_RPC_GETBANS::ban b;
        b.host = i->first;
        b.ip = 0;
        uint32_t ip;
        if (epee::string_tools::get_ip_int32_from_string(ip, b.host))
          b.ip = ip;
        b.seconds = i->second - now;
        res.bans.push_back(b);
      }
    }
    std::map<epee::net_utils::ipv4_network_subnet, time_t> blocked_subnets = m_p2p.get_blocked_subnets();
    for (std::map<epee::net_utils::ipv4_network_subnet, time_t>::const_iterator i = blocked_subnets.begin(); i != blocked_subnets.end(); ++i)
    {
      if (i->second > now) {
        COMMAND_RPC_GETBANS::ban b;
        b.host = i->first.host_str();
        b.ip = 0;
        b.seconds = i->second - now;
        res.bans.push_back(b);
      }
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_banned(const COMMAND_RPC_BANNED::request& req, COMMAND_RPC_BANNED::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    PERF_TIMER(on_banned);

    auto na_parsed = net::get_network_address(req.address, 0);
    if (!na_parsed)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Unsupported host type";
      return false;
    }
    epee::net_utils::network_address na = std::move(*na_parsed);

    time_t seconds;
    if (m_p2p.is_host_blocked(na, &seconds))
    {
      res.banned = true;
      res.seconds = seconds;
    }
    else
    {
      res.banned = false;
      res.seconds = 0;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
 

  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_version(const COMMAND_RPC_GET_VERSION::request& req, COMMAND_RPC_GET_VERSION::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_version);

    res.version = CORE_RPC_VERSION;
    res.release = MONERO_VERSION_IS_RELEASE;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_coinbase_tx_sum(const COMMAND_RPC_GET_COINBASE_TX_SUM::request& req, COMMAND_RPC_GET_COINBASE_TX_SUM::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_coinbase_tx_sum);
    const uint64_t bc_height = m_core.get_current_blockchain_height();
    if (req.height >= bc_height || req.count > bc_height)
    {
      res.status = "height or count is too large";
      return true;
    }
    std::pair<boost::multiprecision::uint128_t, boost::multiprecision::uint128_t> amounts = m_core.get_coinbase_tx_sum(req.height, req.count);
    store_128(amounts.first, res.emission_amount, res.wide_emission_amount, res.emission_amount_top64);
    store_128(amounts.second, res.fee_amount, res.wide_fee_amount, res.fee_amount_top64);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_base_fee_estimate(const COMMAND_RPC_GET_BASE_FEE_ESTIMATE::request& req, COMMAND_RPC_GET_BASE_FEE_ESTIMATE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_base_fee_estimate);

    res.fee = 0;
    res.quantization_mask =0;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_alternate_chains(const COMMAND_RPC_GET_ALTERNATE_CHAINS::request& req, COMMAND_RPC_GET_ALTERNATE_CHAINS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_alternate_chains);
    try
    {
      std::vector<std::pair<Blockchain::block_extended_info, std::vector<crypto::hash>>> chains = m_core.get_blockchain_storage().get_alternative_chains();
      for (const auto &i: chains)
      {
        difficulty_type wdiff = i.first.cum_diff;
        res.chains.push_back(COMMAND_RPC_GET_ALTERNATE_CHAINS::chain_info{epee::string_tools::pod_to_hex(get_block_hash(i.first.bl)), i.first.height, i.second.size(), 0, "", 0, {}, std::string()});
        store_difficulty(wdiff, res.chains.back().difficulty, res.chains.back().wide_difficulty, res.chains.back().difficulty_top64);
        res.chains.back().block_hashes.reserve(i.second.size());
        for (const crypto::hash &block_id: i.second)
          res.chains.back().block_hashes.push_back(epee::string_tools::pod_to_hex(block_id));
        if (i.first.height < i.second.size())
        {
          res.status = "Error finding alternate chain attachment point";
          return true;
        }
        cryptonote::block main_chain_parent_block;
        try { main_chain_parent_block = m_core.get_blockchain_storage().get_db().get_block_from_height(i.first.height - i.second.size()); }
        catch (const std::exception &e) { res.status = "Error finding alternate chain attachment point"; return true; }
        res.chains.back().main_chain_parent_block = epee::string_tools::pod_to_hex(get_block_hash(main_chain_parent_block));
      }
      res.status = CORE_RPC_STATUS_OK;
    }
    catch (...)
    {
      res.status = "Error retrieving alternate chains";
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_limit(const COMMAND_RPC_GET_LIMIT::request& req, COMMAND_RPC_GET_LIMIT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_limit);


    res.limit_down = epee::net_utils::connection_basic::get_rate_down_limit();
    res.limit_up = epee::net_utils::connection_basic::get_rate_up_limit();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_limit(const COMMAND_RPC_SET_LIMIT::request& req, COMMAND_RPC_SET_LIMIT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(set_limit);
    // -1 = reset to default
    //  0 = do not modify

    if (req.limit_down > 0)
    {
      epee::net_utils::connection_basic::set_rate_down_limit(req.limit_down);
    }
    else if (req.limit_down < 0)
    {
      if (req.limit_down != -1)
      {
        res.status = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        return true;
      }
      epee::net_utils::connection_basic::set_rate_down_limit(nodetool::default_limit_down);
    }

    if (req.limit_up > 0)
    {
      epee::net_utils::connection_basic::set_rate_up_limit(req.limit_up);
    }
    else if (req.limit_up < 0)
    {
      if (req.limit_up != -1)
      {
        res.status = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        return true;
      }
      epee::net_utils::connection_basic::set_rate_up_limit(nodetool::default_limit_up);
    }

    res.limit_down = epee::net_utils::connection_basic::get_rate_down_limit();
    res.limit_up = epee::net_utils::connection_basic::get_rate_up_limit();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_out_peers(const COMMAND_RPC_OUT_PEERS::request& req, COMMAND_RPC_OUT_PEERS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(out_peers);
    if (req.set)
      m_p2p.change_max_out_public_peers(req.out_peers);
    res.out_peers = m_p2p.get_max_out_public_peers();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_in_peers(const COMMAND_RPC_IN_PEERS::request& req, COMMAND_RPC_IN_PEERS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(in_peers);
    if (req.set)
      m_p2p.change_max_in_public_peers(req.in_peers);
    res.in_peers = m_p2p.get_max_in_public_peers();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_update(const COMMAND_RPC_UPDATE::request& req, COMMAND_RPC_UPDATE::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(update);

    res.update = false;
    if (m_core.offline())
    {
      res.status = "Daemon is running offline";
      return true;
    }

    static const char software[] = "dfa";
#ifdef BUILD_TAG
    static const char buildtag[] = BOOST_PP_STRINGIZE(BUILD_TAG);
    static const char subdir[] = "cli";
#else
    static const char buildtag[] = "source";
    static const char subdir[] = "source";
#endif

    if (req.command != "check" && req.command != "download" && req.command != "update")
    {
      res.status = std::string("unknown command: '") + req.command + "'";
      return true;
    }

    std::string version, hash;
    if (!tools::check_updates(software, buildtag, version, hash))
    {
      res.status = "Error checking for updates";
      return true;
    }
    if (tools::vercmp(version.c_str(), MONERO_VERSION) <= 0)
    {
      res.update = false;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }
    res.update = true;
    res.version = version;
    res.user_uri = tools::get_update_url(software, subdir, buildtag, version, true);
    res.auto_uri = tools::get_update_url(software, subdir, buildtag, version, false);
    res.hash = hash;
    if (req.command == "check")
    {
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    boost::filesystem::path path;
    if (req.path.empty())
    {
      std::string filename;
      const char *slash = strrchr(res.auto_uri.c_str(), '/');
      if (slash)
        filename = slash + 1;
      else
        filename = std::string(software) + "-update-" + version;
      path = epee::string_tools::get_current_module_folder();
      path /= filename;
    }
    else
    {
      path = req.path;
    }

    crypto::hash file_hash;
    if (!tools::sha256sum(path.string(), file_hash) || (hash != epee::string_tools::pod_to_hex(file_hash)))
    {
      MDEBUG("We don't have that file already, downloading");
      if (!tools::download(path.string(), res.auto_uri))
      {
        MERROR("Failed to download " << res.auto_uri);
        return true;
      }
      if (!tools::sha256sum(path.string(), file_hash))
      {
        MERROR("Failed to hash " << path);
        return true;
      }
      if (hash != epee::string_tools::pod_to_hex(file_hash))
      {
        MERROR("Download from " << res.auto_uri << " does not match the expected hash");
        return true;
      }
      MINFO("New version downloaded to " << path);
    }
    else
    {
      MDEBUG("We already have " << path << " with expected hash");
    }
    res.path = path.string();

    if (req.command == "download")
    {
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    res.status = "'update' not implemented yet";
    return true;
  }

 
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_sync_info(const COMMAND_RPC_SYNC_INFO::request& req, COMMAND_RPC_SYNC_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(sync_info);


    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    ++res.height; // turn top block height into blockchain height
    res.target_height = m_p2p.get_crypto_protocol().is_synchronized() ? 0 : m_core.get_target_blockchain_height();
    res.next_needed_pruning_seed = m_p2p.get_crypto_protocol().get_next_needed_pruning_stripe().second;

    for (const auto &c: m_p2p.get_crypto_protocol().get_connections())
      res.peers.push_back({c});
    const cryptonote::block_queue &block_queue = m_p2p.get_crypto_protocol().get_block_queue();
    block_queue.foreach([&](const cryptonote::block_queue::span &span) {
      const std::string span_connection_id = epee::string_tools::pod_to_hex(span.connection_id);
      uint32_t speed = (uint32_t)(100.0f * block_queue.get_speed(span.connection_id) + 0.5f);
      res.spans.push_back({span.start_block_height, span.nblocks, span_connection_id, (uint32_t)(span.rate + 0.5f), speed, span.size, span.origin.str()});
      return true;
    });
    res.overview = block_queue.get_overview(res.height);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_txpool_backlog(const COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_txpool_backlog);
  

    if (!m_core.get_txpool_backlog(res.backlog))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to get txpool backlog";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
   //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_output_distribution_bin(const COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request& req, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_output_distribution_bin);

    res.status = "Failed";

    if (!req.binary)
    {
      res.status = "Binary only call";
      return true;
    }
    try
    {
     // 0 is placeholder for the whole chain
      const uint64_t to = req.to_height ? req.to_height : (m_core.get_current_blockchain_height() - 1);
        uint64_t start_height{};
        std::vector<uint64_t> dist;
        auto r =  m_core.get_output_distribution( req.from_height, to, start_height, dist); 
        if (!r)
        {
          res.status = "Failed to get output distribution";
          return false;
        }

        res.dist={ {std::move(dist), start_height}, req.binary};
    }
    catch (const std::exception &e)
    {
      res.status = "Failed to get output distribution";
      return true;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_output_distribution(const COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request& req, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_output_distribution);

    try
    {
      // 0 is placeholder for the whole chain
      const uint64_t to = req.to_height ? req.to_height : (m_core.get_current_blockchain_height() - 1);
        uint64_t start_height{};
        std::vector<uint64_t> dist;
        auto r =  m_core.get_output_distribution( req.from_height, to, start_height, dist); 
        if (!r)
        {
          error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
          error_resp.message = "Failed to get output distribution";
          return false;
        }

        res.dist={ {std::move(dist), start_height}, req.binary};
    }
    catch (const std::exception &e)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to get output distribution";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
 
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_prune_blockchain(const COMMAND_RPC_PRUNE_BLOCKCHAIN::request& req, COMMAND_RPC_PRUNE_BLOCKCHAIN::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(prune_blockchain);

    try
    {
      if (!(req.check ? m_core.check_blockchain_pruning() : m_core.prune_blockchain()))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = req.check ? "Failed to check blockchain pruning" : "Failed to prune blockchain";
        return false;
      }
      res.pruning_seed = m_core.get_blockchain_pruning_seed();
      res.pruned = res.pruning_seed != 0;
    }
    catch (const std::exception &e)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to prune blockchain";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
 
  bool core_rpc_server::on_sync_balance(const COMMAND_RPC_SYNC_BALANCE::request& req, COMMAND_RPC_SYNC_BALANCE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(prune_blockchain);

    try
    {
        const crypto::secret_key & a=*reinterpret_cast<const crypto::secret_key*>(&req.a);
        const crypto::public_key & B=req.B;
        const auto start_height = req.start_height;
        std::vector<transaction_out> v;
          Blockchain & bc = m_core.get_blockchain_storage();
         //B+H(kA,i)G=otk
         bc.for_all_outputs(start_height,[&](auto oid, auto & ot){
          const auto & tx_pub_key= ot.tx_pub_key;
           crypto::key_derivation kA;
            bool r = crypto::generate_key_derivation(tx_pub_key, a, kA);
            if(!r)
             throw_and_log( "Failed to generate key derivation");
            crypto::public_key otk2;
            r = crypto::derive_public_key(kA, ot.local_index, B, otk2);
            if (ot.otk==otk2){
              MDEBUG("found own trans "<<ot.tx_hash);
              transaction_out td;
              td.tx_hash = ot.tx_hash;
              td.tx_key=ot.tx_pub_key;
              td.unlock_time=ot.unlock_time;
              td.otk = ot.otk;
              td.block_height = ot.height;
              td.local_oi=ot.local_index;
              td.global_oi = oid;
              td.commitment = ot.commitment;
              td.amount = ot.amount;
              v.emplace_back(td);
            }
            return true;
         });
         res.v = std::move(v);
    }
    catch (const std::exception &e)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = e.what();
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_flush_cache(const COMMAND_RPC_FLUSH_CACHE::request& req, COMMAND_RPC_FLUSH_CACHE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(flush_cache);
    if (req.bad_txs)
      m_core.flush_bad_txs_cache();
    if (req.bad_blocks)
      m_core.flush_invalid_blocks();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
 
 
  //------------------------------------------------------------------------------------------------------------------------------
  const command_line::arg_descriptor<std::string, false, true, 2> core_rpc_server::arg_rpc_bind_port = {
      "rpc-bind-port"
    , "Port for RPC server"
    , std::to_string(config::RPC_DEFAULT_PORT)
    , {{ &cryptonote::arg_testnet_on, &cryptonote::arg_stagenet_on }}
    , [](std::array<bool, 2> testnet_stagenet, bool defaulted, std::string val)->std::string {
        if (testnet_stagenet[0] && defaulted)
          return std::to_string(config::testnet::RPC_DEFAULT_PORT);
        else if (testnet_stagenet[1] && defaulted)
          return std::to_string(config::stagenet::RPC_DEFAULT_PORT);
        return val;
      }
    };


  const command_line::arg_descriptor<bool> core_rpc_server::arg_restricted_rpc = {
      "restricted-rpc"
    , "Restrict RPC to view only commands and do not return privacy sensitive data in RPC calls"
    , false
    };


}  // namespace cryptonote
