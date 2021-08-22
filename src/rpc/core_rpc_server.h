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

#pragma  once 

#include <memory>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>

#include "net/http_server_impl_base.h"
#include "net/http_client.h"
#include "core_rpc_server_commands_defs.h"
#include "cryptonote_core/cryptonote_core.h"
#include "p2p/net_node.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon.rpc"

// yes, epee doesn't properly use its full namespace when calling its
// functions from macros.  *sigh*
using namespace epee;

namespace cryptonote
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class core_rpc_server: public epee::http_server_impl_base<core_rpc_server>
  {

  public:

    static const command_line::arg_descriptor<bool> arg_public_node;
    static const command_line::arg_descriptor<std::string, false, true, 2> arg_rpc_bind_port;
    static const command_line::arg_descriptor<bool> arg_restricted_rpc;
    static const command_line::arg_descriptor<std::string> arg_rpc_ssl;
    static const command_line::arg_descriptor<std::string> arg_rpc_ssl_private_key;
    static const command_line::arg_descriptor<std::string> arg_rpc_ssl_certificate;
    static const command_line::arg_descriptor<std::string> arg_rpc_ssl_ca_certificates;
    static const command_line::arg_descriptor<std::vector<std::string>> arg_rpc_ssl_allowed_fingerprints;
    static const command_line::arg_descriptor<bool> arg_rpc_ssl_allow_any_cert;


    typedef epee::net_utils::connection_context_base connection_context;
    typedef  epee::http_server_impl_base<core_rpc_server> super_type;
    core_rpc_server(core& cr, nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p);
    ~core_rpc_server();

    static void init_options(boost::program_options::options_description& desc);
    bool init(
        const boost::program_options::variables_map& vm,
        const bool restricted,
        const std::string& port
      );
    network_type nettype() const { return m_core.get_nettype(); }

    //CHAIN_HTTP_TO_MAP2(connection_context); //forward http requests to uri map
    bool handle_http_request(const epee::net_utils::http::http_request_info& query_info, 
              epee::net_utils::http::http_response_info& response, connection_context& m_conn_context) 
      {
        MINFO("HTTP [" << m_conn_context.m_remote_address.host_str() << "] " << query_info.m_http_method_str << " " << query_info.m_URI); 
        response.m_response_code = 200; 
        response.m_response_comment = "Ok"; 
        try 
        { 
          if(!handle_http_request_map(query_info, response, m_conn_context)) 
          {response.m_response_code = 404;response.m_response_comment = "Not found";} 
        } 
        catch (const std::exception &e) 
        { 
          MERROR(m_conn_context << "Exception in handle_http_request_map: " << e.what()); 
          response.m_response_code = 500; 
          response.m_response_comment = "Internal Server Error"; 
        } 
        return true; 
      }

  //  BEGIN_URI_MAP2()
     template<class t_context> bool handle_http_request_map(const epee::net_utils::http::http_request_info& query_info,   epee::net_utils::http::http_response_info& response_info, t_context& m_conn_context) { 
      bool handled = false; 
      const auto  s_pattern= "/getheight";
       auto callback_f=&core_rpc_server::on_get_height;
      using command_type=COMMAND_RPC_GET_HEIGHT;
      if(false) return true; //just a stub to have "else if"

 else if((query_info.m_URI == s_pattern) && (true)) 
    { 
      handled = true; 
      uint64_t ticks = misc_utils::get_tick_count(); 
      boost::value_initialized<command_type::request> req; 
      bool parse_res = epee::serialization::load_t_from_json(static_cast<command_type::request&>(req), query_info.m_body); 
      if (!parse_res) 
      { 
         MERROR("Failed to parse json: \r\n" << query_info.m_body); 
         response_info.m_response_code = 400; 
         response_info.m_response_comment = "Bad request"; 
         return true; 
      } 
      uint64_t ticks1 = epee::misc_utils::get_tick_count(); 
      boost::value_initialized<command_type::response> resp;
      MINFO(m_conn_context << "calling " << s_pattern); 
      bool res = false; 
      try { res = (this->*callback_f)(static_cast<command_type::request&>(req), static_cast<command_type::response&>(resp), &m_conn_context); } 
      catch (const std::exception &e) { MERROR(m_conn_context << "Failed to " << s_pattern << "(): " << e.what()); } 
      if (!res) 
      { 
        response_info.m_response_code = 500; 
        response_info.m_response_comment = "Internal Server Error"; 
        return true; 
      } 
      uint64_t ticks2 = epee::misc_utils::get_tick_count(); 
      epee::serialization::store_t_to_json(static_cast<command_type::response&>(resp), response_info.m_body); 
      uint64_t ticks3 = epee::misc_utils::get_tick_count(); 
      response_info.m_mime_tipe = "application/json"; 
      response_info.m_header_info.m_content_type = " application/json"; 
      MDEBUG( s_pattern << " processed with " << ticks1-ticks << "/"<< ticks2-ticks1 << "/" << ticks3-ticks2 << "ms"); 
    }
    //  MAP_URI_AUTO_JON2("/get_height", on_get_height, COMMAND_RPC_GET_HEIGHT)
    //  MAP_URI_AUTO_JON2("/getheight", on_get_height, COMMAND_RPC_GET_HEIGHT)
      MAP_URI_AUTO_BIN2("/get_blocks_by_height.bin", on_get_blocks_by_height, COMMAND_RPC_GET_BLOCKS_BY_HEIGHT)
      MAP_URI_AUTO_BIN2("/getblocks_by_height.bin", on_get_blocks_by_height, COMMAND_RPC_GET_BLOCKS_BY_HEIGHT)
      MAP_URI_AUTO_BIN2("/get_o_indexes.bin", on_get_indexes, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES)      
      MAP_URI_AUTO_BIN2("/get_outs.bin", on_get_outs_bin, COMMAND_RPC_GET_OUTPUTS_BIN)
      MAP_URI_AUTO_JON2("/get_transactions", on_get_transactions, COMMAND_RPC_GET_TRANSACTIONS)
      MAP_URI_AUTO_JON2("/gettransactions", on_get_transactions, COMMAND_RPC_GET_TRANSACTIONS)
      MAP_URI_AUTO_JON2("/get_alt_blocks_hashes", on_get_alt_blocks_hashes, COMMAND_RPC_GET_ALT_BLOCKS_HASHES)
      MAP_URI_AUTO_JON2("/is_key_image_spent", on_is_key_image_spent, COMMAND_RPC_IS_KEY_IMAGE_SPENT)
      MAP_URI_AUTO_JON2("/send_raw_transaction", on_submit_tx, COMMAND_RPC_SEND_RAW_TX)
      MAP_URI_AUTO_JON2("/sendrawtransaction", on_submit_tx, COMMAND_RPC_SEND_RAW_TX)
      MAP_URI_AUTO_JON2_IF("/get_peer_list", on_get_peer_list, COMMAND_RPC_GET_PEER_LIST, !m_restricted)
      MAP_URI_AUTO_JON2("/get_public_nodes", on_get_public_nodes, COMMAND_RPC_GET_PUBLIC_NODES)
      MAP_URI_AUTO_JON2_IF("/set_log_level", on_set_log_level, COMMAND_RPC_SET_LOG_LEVEL, !m_restricted)
      MAP_URI_AUTO_JON2_IF("/set_log_categories", on_set_log_categories, COMMAND_RPC_SET_LOG_CATEGORIES, !m_restricted)
      MAP_URI_AUTO_JON2("/get_transaction_pool", on_get_transaction_pool, COMMAND_RPC_GET_TRANSACTION_POOL)
      MAP_URI_AUTO_JON2("/get_transaction_pool_hashes.bin", on_get_transaction_pool_hashes_bin, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN)
      MAP_URI_AUTO_JON2("/get_transaction_pool_hashes", on_get_transaction_pool_hashes, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES)
      MAP_URI_AUTO_JON2("/get_transaction_pool_stats", on_get_transaction_pool_stats, COMMAND_RPC_GET_TRANSACTION_POOL_STATS)

      MAP_URI_AUTO_JON2("/get_info", on_get_info, COMMAND_RPC_GET_INFO)
      MAP_URI_AUTO_JON2("/getinfo", on_get_info, COMMAND_RPC_GET_INFO)
      MAP_URI_AUTO_JON2_IF("/get_net_stats", on_get_net_stats, COMMAND_RPC_GET_NET_STATS, !m_restricted)
      MAP_URI_AUTO_JON2("/get_limit", on_get_limit, COMMAND_RPC_GET_LIMIT)
      MAP_URI_AUTO_JON2_IF("/set_limit", on_set_limit, COMMAND_RPC_SET_LIMIT, !m_restricted)
      MAP_URI_AUTO_JON2_IF("/out_peers", on_out_peers, COMMAND_RPC_OUT_PEERS, !m_restricted)
      MAP_URI_AUTO_JON2_IF("/in_peers", on_in_peers, COMMAND_RPC_IN_PEERS, !m_restricted)
      MAP_URI_AUTO_JON2("/get_outs", on_get_outs, COMMAND_RPC_GET_OUTPUTS)      
      MAP_URI_AUTO_JON2_IF("/update", on_update, COMMAND_RPC_UPDATE, !m_restricted)
      MAP_URI_AUTO_BIN2("/get_output_distribution.bin", on_get_output_distribution_bin, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION)
      BEGIN_JSON_RPC_MAP("/json_rpc")
        MAP_JON_RPC("get_block_count",           on_getblockcount,              COMMAND_RPC_GETBLOCKCOUNT)
        MAP_JON_RPC("getblockcount",             on_getblockcount,              COMMAND_RPC_GETBLOCKCOUNT)
        MAP_JON_RPC_WE("on_get_block_hash",      on_getblockhash,               COMMAND_RPC_GETBLOCKHASH)
        MAP_JON_RPC_WE("on_getblockhash",        on_getblockhash,               COMMAND_RPC_GETBLOCKHASH)
        MAP_JON_RPC_WE("get_block_template",     on_getblocktemplate,           COMMAND_RPC_GETBLOCKTEMPLATE)
        MAP_JON_RPC_WE("getblocktemplate",       on_getblocktemplate,           COMMAND_RPC_GETBLOCKTEMPLATE)
        MAP_JON_RPC_WE("submit_block",           on_submitblock,                COMMAND_RPC_SUBMITBLOCK)
        MAP_JON_RPC_WE("submitblock",            on_submitblock,                COMMAND_RPC_SUBMITBLOCK)
        MAP_JON_RPC_WE("get_last_block_header",  on_get_last_block_header,      COMMAND_RPC_GET_LAST_BLOCK_HEADER)
        MAP_JON_RPC_WE("getlastblockheader",     on_get_last_block_header,      COMMAND_RPC_GET_LAST_BLOCK_HEADER)
        MAP_JON_RPC_WE("get_block_header_by_hash", on_get_block_header_by_hash,   COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH)
        MAP_JON_RPC_WE("getblockheaderbyhash",   on_get_block_header_by_hash,   COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH)
        MAP_JON_RPC_WE("get_block_header_by_height", on_get_block_header_by_height, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT)
        MAP_JON_RPC_WE("getblockheaderbyheight", on_get_block_header_by_height, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT)
        MAP_JON_RPC_WE("get_block_headers_range", on_get_block_headers_range,    COMMAND_RPC_GET_BLOCK_HEADERS_RANGE)
        MAP_JON_RPC_WE("getblockheadersrange",   on_get_block_headers_range,    COMMAND_RPC_GET_BLOCK_HEADERS_RANGE)
        MAP_JON_RPC_WE("get_block",              on_get_block,                 COMMAND_RPC_GET_BLOCK)
        MAP_JON_RPC_WE("getblock",                on_get_block,                 COMMAND_RPC_GET_BLOCK)
        MAP_JON_RPC_WE_IF("get_connections",     on_get_connections,            COMMAND_RPC_GET_CONNECTIONS, !m_restricted)
        MAP_JON_RPC_WE("get_info",               on_get_info_json,              COMMAND_RPC_GET_INFO)
        MAP_JON_RPC_WE("hard_fork_info",         on_hard_fork_info,             COMMAND_RPC_HARD_FORK_INFO)
        MAP_JON_RPC_WE_IF("get_bans",            on_get_bans,                   COMMAND_RPC_GETBANS, !m_restricted)
        MAP_JON_RPC_WE_IF("banned",              on_banned,                     COMMAND_RPC_BANNED, !m_restricted)
        MAP_JON_RPC_WE("get_version",            on_get_version,                COMMAND_RPC_GET_VERSION)
        MAP_JON_RPC_WE("get_fee_estimate",       on_get_base_fee_estimate,      COMMAND_RPC_GET_BASE_FEE_ESTIMATE)
        MAP_JON_RPC_WE_IF("get_alternate_chains",on_get_alternate_chains,       COMMAND_RPC_GET_ALTERNATE_CHAINS, !m_restricted)
        MAP_JON_RPC_WE_IF("sync_info",           on_sync_info,                  COMMAND_RPC_SYNC_INFO, !m_restricted)
        MAP_JON_RPC_WE("get_txpool_backlog",     on_get_txpool_backlog,         COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG)
        MAP_JON_RPC_WE("get_output_distribution", on_get_output_distribution, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION)
        MAP_JON_RPC_WE_IF("prune_blockchain",    on_prune_blockchain,           COMMAND_RPC_PRUNE_BLOCKCHAIN, !m_restricted)
        MAP_JON_RPC_WE_IF("flush_cache",         on_flush_cache,                COMMAND_RPC_FLUSH_CACHE, !m_restricted)
       MAP_JON_RPC_WE_IF("sync_balance",         on_sync_balance,                COMMAND_RPC_SYNC_BALANCE, !m_restricted)
      END_JSON_RPC_MAP()
   // END_URI_MAP2()
      return handled;
    }

    bool on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res, const connection_context *ctx = NULL);
    bool on_get_alt_blocks_hashes(const COMMAND_RPC_GET_ALT_BLOCKS_HASHES::request& req, COMMAND_RPC_GET_ALT_BLOCKS_HASHES::response& res, const connection_context *ctx = NULL);
    bool on_get_blocks_by_height(const COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response& res, const connection_context *ctx = NULL);
    bool on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res, const connection_context *ctx = NULL);
    bool on_is_key_image_spent(const COMMAND_RPC_IS_KEY_IMAGE_SPENT::request& req, COMMAND_RPC_IS_KEY_IMAGE_SPENT::response& res, const connection_context *ctx = NULL);
    bool on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res, const connection_context *ctx = NULL);
    bool on_submit_tx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res, const connection_context *ctx = NULL);
    bool on_get_outs_bin(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res, const connection_context *ctx = NULL);
    bool on_get_outs(const COMMAND_RPC_GET_OUTPUTS::request& req, COMMAND_RPC_GET_OUTPUTS::response& res, const connection_context *ctx = NULL);
    bool on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, const connection_context *ctx = NULL);
    bool on_get_net_stats(const COMMAND_RPC_GET_NET_STATS::request& req, COMMAND_RPC_GET_NET_STATS::response& res, const connection_context *ctx = NULL);
    bool on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res, const connection_context *ctx = NULL);
    bool on_get_public_nodes(const COMMAND_RPC_GET_PUBLIC_NODES::request& req, COMMAND_RPC_GET_PUBLIC_NODES::response& res, const connection_context *ctx = NULL);
    bool on_set_log_level(const COMMAND_RPC_SET_LOG_LEVEL::request& req, COMMAND_RPC_SET_LOG_LEVEL::response& res, const connection_context *ctx = NULL);
    bool on_set_log_categories(const COMMAND_RPC_SET_LOG_CATEGORIES::request& req, COMMAND_RPC_SET_LOG_CATEGORIES::response& res, const connection_context *ctx = NULL);
    bool on_get_transaction_pool(const COMMAND_RPC_GET_TRANSACTION_POOL::request& req, COMMAND_RPC_GET_TRANSACTION_POOL::response& res, const connection_context *ctx = NULL);
    bool on_get_transaction_pool_hashes_bin(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN::response& res, const connection_context *ctx = NULL);
    bool on_get_transaction_pool_hashes(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::response& res, const connection_context *ctx = NULL);
    bool on_get_transaction_pool_stats(const COMMAND_RPC_GET_TRANSACTION_POOL_STATS::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_STATS::response& res, const connection_context *ctx = NULL);
    bool on_get_limit(const COMMAND_RPC_GET_LIMIT::request& req, COMMAND_RPC_GET_LIMIT::response& res, const connection_context *ctx = NULL);
    bool on_set_limit(const COMMAND_RPC_SET_LIMIT::request& req, COMMAND_RPC_SET_LIMIT::response& res, const connection_context *ctx = NULL);
    bool on_out_peers(const COMMAND_RPC_OUT_PEERS::request& req, COMMAND_RPC_OUT_PEERS::response& res, const connection_context *ctx = NULL);
    bool on_in_peers(const COMMAND_RPC_IN_PEERS::request& req, COMMAND_RPC_IN_PEERS::response& res, const connection_context *ctx = NULL);
    bool on_update(const COMMAND_RPC_UPDATE::request& req, COMMAND_RPC_UPDATE::response& res, const connection_context *ctx = NULL);
    bool on_get_output_distribution_bin(const COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request& req, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response& res, const connection_context *ctx = NULL);
  
    
    //json_rpc
    bool on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res, const connection_context *ctx = NULL);
    bool on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_block_headers_range(const COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request& req, COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_block(const COMMAND_RPC_GET_BLOCK::request& req, COMMAND_RPC_GET_BLOCK::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_info_json(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_hard_fork_info(const COMMAND_RPC_HARD_FORK_INFO::request& req, COMMAND_RPC_HARD_FORK_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_bans(const COMMAND_RPC_GETBANS::request& req, COMMAND_RPC_GETBANS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_banned(const COMMAND_RPC_BANNED::request& req, COMMAND_RPC_BANNED::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_version(const COMMAND_RPC_GET_VERSION::request& req, COMMAND_RPC_GET_VERSION::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_coinbase_tx_sum(const COMMAND_RPC_GET_COINBASE_TX_SUM::request& req, COMMAND_RPC_GET_COINBASE_TX_SUM::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_base_fee_estimate(const COMMAND_RPC_GET_BASE_FEE_ESTIMATE::request& req, COMMAND_RPC_GET_BASE_FEE_ESTIMATE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_alternate_chains(const COMMAND_RPC_GET_ALTERNATE_CHAINS::request& req, COMMAND_RPC_GET_ALTERNATE_CHAINS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_sync_info(const COMMAND_RPC_SYNC_INFO::request& req, COMMAND_RPC_SYNC_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_txpool_backlog(const COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_get_output_distribution(const COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request& req, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_prune_blockchain(const COMMAND_RPC_PRUNE_BLOCKCHAIN::request& req, COMMAND_RPC_PRUNE_BLOCKCHAIN::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_flush_cache(const COMMAND_RPC_FLUSH_CACHE::request& req, COMMAND_RPC_FLUSH_CACHE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx = NULL);
    bool on_sync_balance(const COMMAND_RPC_SYNC_BALANCE::request& req, COMMAND_RPC_SYNC_BALANCE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx);
   
    //-----------------------

private:
    bool check_core_busy();
    bool check_core_ready();
    bool add_host_fail(const connection_context *ctx, unsigned int score = 1);
    
    //utils
    bool fill_block_header_response(const block& blk, bool orphan_status, uint64_t height, const crypto::hash& hash, block_header_response& response, bool fill_pow_hash);
    std::map<std::string, bool> get_public_nodes(uint32_t credits_per_hash_threshold = 0);
   
    enum invoke_http_mode { JON, BIN, JON_RPC };

    core& m_core;
    nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& m_p2p;
    bool m_restricted;
    epee::critical_section m_host_fails_score_lock;
    std::map<std::string, uint64_t> m_host_fails_score;
    bool disable_rpc_ban;
    bool m_rpc_payment_allow_free_loopback;
  };
}

BOOST_CLASS_VERSION(nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >, 1);
