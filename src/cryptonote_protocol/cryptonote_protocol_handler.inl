/// @file
/// @author rfree (current maintainer/user in monero.cc project - most of code is from CryptoNote)
/// @brief This is the original cryptonote protocol network-events handler, modified by us

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

// (may contain code and/or modifications by other developers)
// developer rfree: this code is caller of our new network code, and is modded; e.g. for rate limiting

#include <boost/interprocess/detail/atomic.hpp>
#include <list>
#include <ctime>

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "profile_tools.h"
#include "net/network_throttle-detail.hpp"
#include "common/pruning.h"
#include "common/util.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.cn"

#define MLOG_P2P_MESSAGE(x) MCINFO("net.p2p.msg", peer_cxt << x)
#define MLOGIF_P2P_MESSAGE(init, test, x) \
  do { \
    const auto level = el::Level::Info; \
    const char *cat = "net.p2p.msg"; \
    if (ELPP->vRegistry()->allowed(level, cat)) { \
      init; \
      if (test) \
        el::base::Writer(level, el::Color::Default, __FILE__, __LINE__, ELPP_FUNC, el::base::DispatchAction::NormalLog).construct(cat) << x; \
    } \
  } while(0)

#define MLOG_PEER_STATE(x) \
  MCINFO(MONERO_DEFAULT_LOG_CATEGORY, peer_cxt << "[" << epee::string_tools::to_string_hex(peer_cxt.m_pruning_seed) << "] state: " << x << " in state " << cryptonote::get_protocol_state_string(peer_cxt.m_state))

#define BLOCK_QUEUE_NSPANS_THRESHOLD 10 // chunks of N blocks
#define BLOCK_QUEUE_SIZE_THRESHOLD (100*1024*1024) // MB
#define BLOCK_QUEUE_FORCE_DOWNLOAD_NEAR_BLOCKS 1000
#define REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY (5 * 1000000) // microseconds
#define REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD (30 * 1000000) // microseconds
#define IDLE_PEER_KICK_TIME (240 * 1000000) // microseconds
#define NON_RESPONSIVE_PEER_KICK_TIME (20 * 1000000) // microseconds
#define PASSIVE_PEER_KICK_TIME (60 * 1000000) // microseconds
#define DROP_ON_SYNC_WEDGE_THRESHOLD (30 * 1000000000ull) // nanoseconds
#define LAST_ACTIVITY_STALL_THRESHOLD (2.0f) // seconds
#define DROP_PEERS_ON_SCORE -2

namespace cryptonote
{



  //-----------------------------------------------------------------------------------------------------------------------
  template<class t_core>
    t_cryptonote_protocol_handler<t_core>::t_cryptonote_protocol_handler(t_core& rcore, nodetool::i_p2p_endpoint<cryptonote_peer_context>* p2p, bool offline):m_core(rcore),m_p2p(p2p),m_syncronized_connections_count(0),m_synchronized(offline),m_ask_for_txpool_complement(true),m_stopping(false),m_no_sync(false)

  {
    if(!m_p2p)
      m_p2p = &m_p2p_stub;
  }
  //-----------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::init(const boost::program_options::variables_map& vm)
  {
    m_sync_timer.pause();
    m_sync_timer.reset();
    m_add_timer.pause();
    m_add_timer.reset();
    m_last_add_end_time = 0;
    m_sync_spans_downloaded = 0;
    m_sync_old_spans_downloaded = 0;
    m_sync_bad_spans_downloaded = 0;
    m_sync_download_objects_size = 0;

    m_block_download_max_size = command_line::get_arg(vm, cryptonote::arg_block_download_max_size);

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::deinit()
  {
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::set_p2p_endpoint(nodetool::i_p2p_endpoint<cryptonote_peer_context>* p2p)
  {
    if(p2p)
      m_p2p = p2p;
    else
      m_p2p = &m_p2p_stub;
  }
  
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::log_connections()
  {
    std::stringstream ss;
    ss.precision(1);

    double down_sum = 0.0;
    double down_curr_sum = 0.0;
    double up_sum = 0.0;
    double up_curr_sum = 0.0;

    ss << std::setw(30) << std::left << "Remote Host"
      << std::setw(20) << "Peer id"
      << std::setw(20) << "Support Flags"      
      << std::setw(30) << "Recv/Sent (inactive,sec)"
      << std::setw(25) << "State"
      << std::setw(20) << "Livetime(sec)"
      << std::setw(12) << "Down (kB/s)"
      << std::setw(14) << "Down(now)"
      << std::setw(10) << "Up (kB/s)"
      << std::setw(13) << "Up(now)"
      << ENDL;

    m_p2p->for_each_connection([&](const cryptonote_peer_context& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags)
    {
      bool local_ip = peer_cxt.m_remote_address.is_local();
      auto connection_time = time(NULL) - peer_cxt.m_started;
      ss << std::setw(30) << std::left << std::string(peer_cxt.m_is_income ? " [INC]":"[OUT]") +
        peer_cxt.m_remote_address.str()
        << std::setw(20) << nodetool::peerid_to_string(peer_id)
        << std::setw(20) << std::hex << support_flags
        << std::setw(30) << std::to_string(peer_cxt.m_recv_cnt)+ "(" + std::to_string(time(NULL) - peer_cxt.m_last_recv) + ")" + "/" + std::to_string(peer_cxt.m_send_cnt) + "(" + std::to_string(time(NULL) - peer_cxt.m_last_send) + ")"
        << std::setw(25) << get_protocol_state_string(peer_cxt.m_state)
        << std::setw(20) << std::to_string(time(NULL) - peer_cxt.m_started)
        << std::setw(12) << std::fixed << (connection_time == 0 ? 0.0 : peer_cxt.m_recv_cnt / connection_time / 1024)
        << std::setw(14) << std::fixed << peer_cxt.m_current_speed_down / 1024
        << std::setw(10) << std::fixed << (connection_time == 0 ? 0.0 : peer_cxt.m_send_cnt / connection_time / 1024)
        << std::setw(13) << std::fixed << peer_cxt.m_current_speed_up / 1024
        << (local_ip ? "[LAN]" : "")
        << std::left << (peer_cxt.m_remote_address.is_loopback() ? "[LOCALHOST]" : "") // 127.0.0.1
        << ENDL;

      if (connection_time > 1)
      {
        down_sum += (peer_cxt.m_recv_cnt / connection_time / 1024);
        up_sum += (peer_cxt.m_send_cnt / connection_time / 1024);
      }

      down_curr_sum += (peer_cxt.m_current_speed_down / 1024);
      up_curr_sum += (peer_cxt.m_current_speed_up / 1024);

      return true;
    });
    ss << ENDL
      << std::setw(125) << " "
      << std::setw(12) << down_sum
      << std::setw(14) << down_curr_sum
      << std::setw(10) << up_sum
      << std::setw(13) << up_curr_sum
      << ENDL;
    LOG_PRINT_L0("Connections: " << ENDL << ss.str());
  }
  //------------------------------------------------------------------------------------------------------------------------
  // Returns a list of connection_info objects describing each open p2p connection
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  std::list<connection_info> t_cryptonote_protocol_handler<t_core>::get_connections()
  {
    std::list<connection_info> connections;

    m_p2p->for_each_connection([&](const cryptonote_peer_context& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags)
    {
      connection_info cnx;
      auto timestamp = time(NULL);

      cnx.incoming = peer_cxt.m_is_income ? true : false;

      cnx.address = peer_cxt.m_remote_address.str();
      cnx.host = peer_cxt.m_remote_address.host_str();
      cnx.ip = "";
      cnx.port = "";
      if (peer_cxt.m_remote_address.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
      {
        cnx.ip = cnx.host;
        cnx.port = std::to_string(peer_cxt.m_remote_address.as<epee::net_utils::ipv4_network_address>().port());
      }
      cnx.rpc_port = peer_cxt.m_rpc_port;
      cnx.rpc_credits_per_hash = peer_cxt.m_rpc_credits_per_hash;

      cnx.peer_id = nodetool::peerid_to_string(peer_id);
      
      cnx.support_flags = support_flags;

      cnx.recv_count = peer_cxt.m_recv_cnt;
      cnx.recv_idle_time = timestamp - std::max(peer_cxt.m_started, peer_cxt.m_last_recv);

      cnx.send_count = peer_cxt.m_send_cnt;
      cnx.send_idle_time = timestamp - std::max(peer_cxt.m_started, peer_cxt.m_last_send);

      cnx.state = get_protocol_state_string(peer_cxt.m_state);

      cnx.live_time = timestamp - peer_cxt.m_started;

      cnx.localhost = peer_cxt.m_remote_address.is_loopback();
      cnx.local_ip = peer_cxt.m_remote_address.is_local();

      auto connection_time = time(NULL) - peer_cxt.m_started;
      if (connection_time == 0)
      {
        cnx.avg_download = 0;
        cnx.avg_upload = 0;
      }

      else
      {
        cnx.avg_download = peer_cxt.m_recv_cnt / connection_time / 1024;
        cnx.avg_upload = peer_cxt.m_send_cnt / connection_time / 1024;
      }

      cnx.current_download = peer_cxt.m_current_speed_down / 1024;
      cnx.current_upload = peer_cxt.m_current_speed_up / 1024;

      cnx.connection_id = epee::string_tools::pod_to_hex(peer_cxt.m_connection_id);
      cnx.ssl = peer_cxt.m_ssl;

      cnx.height = peer_cxt.m_remote_chain_height;
      cnx.pruning_seed = peer_cxt.m_pruning_seed;
      cnx.address_type = (uint8_t)peer_cxt.m_remote_address.get_type_id();

      connections.push_back(cnx);

      return true;
    });

    return connections;
  }
 
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::get_payload_sync_data(CORE_SYNC_DATA& hshd)
  {
    m_core.get_blockchain_top(hshd.current_height, hshd.top_id);
    hshd.top_version = m_core.get_ideal_hard_fork_version(hshd.current_height);
    difficulty_type wide_cumulative_difficulty = m_core.get_block_cumulative_difficulty(hshd.current_height);
    hshd.cum_diff = (wide_cumulative_difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
    hshd.cumulative_difficulty_top64 = ((wide_cumulative_difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
    hshd.current_height +=1;
    hshd.pruning_seed = m_core.get_blockchain_pruning_seed();
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
    template<class t_core>
    bool t_cryptonote_protocol_handler<t_core>::get_payload_sync_data(epee::byte_slice& data)
  {
    CORE_SYNC_DATA hsd = {};
    get_payload_sync_data(hsd);
    epee::serialization::store_t_to_binary(hsd, data);
    return true;
  }
  
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_notify_new_fluffy_block(int command, NOTIFY_NEW_FLUFFY_BLOCK::request& req, cryptonote_peer_context& peer_cxt)
  {

    if(peer_cxt.m_state != cryptonote_peer_context::state_normal)
      return 1;
    if(!is_synchronized()) // can happen if a peer connection goes to normal but another thread still hasn't finished adding queued blocks
    {
      MDEBUG(peer_cxt, "Received new block while syncing, ignored");
      return 1;
    }
    
    try{
    const auto & new_block =parse_block_from_blob(req.b.block);
    
      // This is a second notification, we must have asked for some missing tx
      if(!peer_cxt.m_requested_objects.empty())
      {
        // What we asked for != to what we received ..
        if(peer_cxt.m_requested_objects.size() != req.b.txs.size())
        {
          MERROR(peer_cxt<<"NOTIFY_NEW_FLUFFY_BLOCK -> request/response mismatch, " 
            << "block = " << epee::string_tools::pod_to_hex(get_blob_hash(req.b.block))
            << ", requested = " << peer_cxt.m_requested_objects.size() 
            << ", received = " << new_block.tx_hashes.size()<< ", dropping connection"
          );
          
          drop_connection(peer_cxt, false, false);
          return 1;
        }
      }      

     
      for(auto& tb: req.bce.tbs)
      {
          const  auto tx = parse_tx_from_blob(tb.blob);
          tx_hash =get_transaction_hash(tx);
         
          // we might already have the tx that the peer
          // sent in our pool, so don't verify again..
          if(!m_core.pool_has_tx(tx_hash))
          {
            MDEBUG("Incoming tx " << tx_hash << " not in pool, adding");
            const auto  tvc = m_core.handle_incoming_tx(tx_blob,  relay_method::block, true);                  
            if(tvc.m_verifivation_failed)
            {
              LOG_PRINT_CCONTEXT_L1("Block verification failed: transaction verification failed, dropping connection");
              drop_connection(peer_cxt, false, false);
              return 1;
            }
            // future todo: 
            // tx should only not be added to pool if verification failed, but
            // maybe in the future could not be added for other reasons 
            // according to monero-moo so keep track of these separately ..
            //
          }
      }
      
      std::vector<crypto::hash> missing_tx_hashes;
      for(auto& tx_hash: new_block.tx_hashes)
      {
          if (!m_core.pool_has_tx(tx_hash) )
          {
            missing_tx_hashes.push_back(tx_hash);
          }
      }
        
      if(!missing_tx_hashes.empty()) // drats, we don't have everything..
      {
        // request non-mempool txs
        
        NOTIFY_REQUEST_FLUFFY_MISSING_TX::request missing_tx_req;
        missing_tx_req.block_hash = get_block_hash(new_block);
        missing_tx_req.cur_chain_height = req.cur_chain_height;
        missing_tx_req.missing_tx_hashes = std::move(missing_tx_hashes);
        
        MLOG_P2P_MESSAGE("-->>NOTIFY_REQUEST_FLUFFY_MISSING_TX: missing_tx_hashes.size()=" << missing_tx_req.missing_tx_indices.size() );
        post_notify<NOTIFY_REQUEST_FLUFFY_MISSING_TX>(missing_tx_req, peer_cxt);
      }
      else // whoo-hoo we've got em all ..
      {
        MDEBUG("We have all needed txes for this fluffy block");
        const auto & b = parse_block_from_blob(req.bce.blob);
        block_verification_context bvc = m_core.get_blockchain().add_new_block(b); 
        
        if( bvc.m_verifivation_failed )
        {
          MERROR("Block verification failed, dropping connection");
          drop_connection_with_score(peer_cxt, bvc.m_bad_pow ? P2P_IP_FAILS_BEFORE_BLOCK : 1, false);
          return 1;
        }
        if( bvc.m_added_to_main_chain )
        {
          //TODO: Add here announce protocol usage
          relay_block(req.b.block,req.cur_chain_height, peer_cxt);
        }
        else if( bvc.m_marked_as_orphaned )
        {
          peer_cxt.m_needed_blocks.clear();
          peer_cxt.m_state = cryptonote_peer_context::state_synchronizing;
          NOTIFY_REQUEST_CHAIN::request r {m_core.get_blockchain().get_short_chain_history()};
          peer_cxt.m_sync_start_height = m_core.get_current_blockchain_height();
          peer_cxt.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
          peer_cxt.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
          MLOG_P2P_MESSAGE("-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << r.block_ids.size() );

          post_notify<NOTIFY_REQUEST_CHAIN>(r, peer_cxt);
          MLOG_PEER_STATE("requesting chain");
        }            
      }
    } 
    catch(const std::exception &ex)
    {
      MERROR(ex.what());
        
      drop_connection(peer_cxt, false, false);
        
      return 1;     
    }
        
    return 1;
  }  
  //------------------------------------------------------------------------------------------------------------------------  
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_request_fluffy_missing_tx(int command, NOTIFY_REQUEST_FLUFFY_MISSING_TX::request& arg, cryptonote_peer_context& peer_cxt)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_REQUEST_FLUFFY_MISSING_TX (" << arg.missing_tx_hashes.size() << " txes), block hash " << arg.block_hash);
    if (peer_cxt.m_state == cryptonote_peer_context::state_before_handshake)
    {
      MERROR(peer_cxt<<"Requested fluffy tx before handshake, dropping connection");
      drop_connection(peer_cxt, false, false);
      return 1;
    }
    try{
    
    block b;
    if (!m_core.get_block_by_hash(arg.block_hash, b))
    {
      MERROR(peer_cxt<<"failed to find block: " << arg.block_hash << ", dropping connection");
      drop_connection(peer_cxt, false, false);
      return 1;
    }

    NOTIFY_NEW_FLUFFY_BLOCK::request fluffy_response;
    fluffy_response.bce.blob = t_serializable_object_to_blob(b);
    fluffy_response.cur_chain_height = arg.cur_chain_height;

    const auto blobs=m_core.get_tx_pool().get_transaction_blobs(arg.missing_tx_hashes);
  
    for(auto& tx_blob: blobs)
    {
      fluffy_response.bce.tbs.push_back({tx_blob, crypto::null_hash});
    }

    MLOG_P2P_MESSAGE
    (
        "-->>NOTIFY_RESPONSE_FLUFFY_MISSING_TX: " 
        << ", txs.size()=" << fluffy_response.bce.tbs.size()
        << ", rsp.cur_chain_height=" << fluffy_response.cur_chain_height
    );
           
    post_notify<NOTIFY_NEW_FLUFFY_BLOCK>(fluffy_response, peer_cxt);    
    return 1;        
  }catch(std::exception & ex){
     MERROR(peer_cxt<<"Requested fluffy tx missing, dropping connection");
      drop_connection(peer_cxt, false, false);
      return 1;
  }
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_notify_get_txpool_complement(int command, NOTIFY_GET_TXPOOL_COMPLEMENT::request& arg, cryptonote_peer_context& peer_cxt)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_GET_TXPOOL_COMPLEMENT (" << arg.hashes.size() << " txes)");
    if(peer_cxt.m_state != cryptonote_peer_context::state_normal)
      return 1;

try{

    const auto &txes=m_core.get_tx_pool().get_transaction_blobs_ex(arg.hashes);
 
    NOTIFY_NEW_TRANSACTIONS::request new_txes;
    new_txes.txs = std::move(txes);

    MLOG_P2P_MESSAGE
    (
        "-->>NOTIFY_NEW_TRANSACTIONS: "
        << ", txs.size()=" << new_txes.txs.size()
    );

    post_notify<NOTIFY_NEW_TRANSACTIONS>(new_txes, peer_cxt);
    return 1;
  }catch(std::exception & ex){
    MERROR(peer_cxt<<"failed to get txpool blobs"<<ex.what());
     return 1;
  }
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_notify_new_transactions(int command, NOTIFY_NEW_TRANSACTIONS::request& arg, cryptonote_peer_context& peer_cxt)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_NEW_TRANSACTIONS (" << arg.txs.size() << " txes)");
    for (const auto &blob: arg.txs)
      MLOGIF_P2P_MESSAGE(cryptonote::transaction tx; crypto::hash hash; bool ret = cryptonote::parse_tx_from_blob(blob, tx, hash);, ret, "Including transaction " << hash);

    if(peer_cxt.m_state != cryptonote_peer_context::state_normal)
      return 1;

    // while syncing, core will lock for a long time, so we ignore
    // those txes as they aren't really needed anyway, and avoid a
    // long block before replying
    if(!is_synchronized())
    {
      MDEBUG(peer_cxt, "Received new tx while syncing, ignored");
      return 1;
    }

    /* If the txes were received over i2p/tor, the default is to "forward"
       with a randomized delay to further enhance the "white noise" behavior,
       potentially making it harder for ISP-level spies to determine which
       inbound link sent the tx. If the sender disabled "white noise" over
       i2p/tor, then the sender is "fluffing" (to only outbound) i2p/tor
       connections with the `dandelionpp_fluff` flag set. The receiver (hidden
       service) will immediately fluff in that scenario (i.e. this assumes that a
       sybil spy will be unable to link an IP to an i2p/tor connection). */

    relay_method tx_relay = relay_method::stem ;

    std::vector<blobdata> stem_txs{};
    std::vector<blobdata> fluff_txs{};
    if (arg.dandelionpp_fluff)
    {
      tx_relay = relay_method::fluff;
      fluff_txs.reserve(arg.txs.size());
    }
    else
      stem_txs.reserve(arg.txs.size());

    for (auto& tx : arg.txs)
    {
      tx_verification_context tvc=m_core.handle_incoming_tx({tx, crypto::null_hash}, tx_relay, true);
      if (tvc.m_verifivation_failed)
      {
        LOG_PRINT_CCONTEXT_L1("Tx verification failed, dropping connection");
        drop_connection(peer_cxt, false, false);
        return 1;
      }

      switch (tvc.m_relay)
      {
        case relay_method::local:
        case relay_method::stem:
          stem_txs.push_back(std::move(tx));
          break;
        case relay_method::block:
        case relay_method::fluff:
          fluff_txs.push_back(std::move(tx));
          break;
        default:
        case relay_method::forward: // not supposed to happen here
        case relay_method::none:
          break;
      }
    }

    if (!stem_txs.empty())
    {
      //TODO: add announce usage here
      arg.dandelionpp_fluff = false;
      arg.txs = std::move(stem_txs);
      relay_transactions(arg, peer_cxt.m_connection_id, peer_cxt.m_remote_address.get_zone(), relay_method::stem);
    }
    if (!fluff_txs.empty())
    {
      //TODO: add announce usage here
      arg.dandelionpp_fluff = true;
      arg.txs = std::move(fluff_txs);
      relay_transactions(arg, peer_cxt.m_connection_id, peer_cxt.m_remote_address.get_zone(), relay_method::fluff);
    }
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_request_get_objects(int command, NOTIFY_REQUEST_GET_OBJECTS::request& arg, cryptonote_peer_context& peer_cxt)
  {
    if (peer_cxt.m_state == cryptonote_peer_context::state_before_handshake)
    {
      MERROR(peer_cxt<<"Requested objects before handshake, dropping connection");
      drop_connection(peer_cxt, false, false);
      return 1;
    }
    try{
    MLOG_P2P_MESSAGE("Received NOTIFY_REQUEST_GET_OBJECTS " << arg.span_start_height<<","<<arg.span_len);
   
    NOTIFY_RESPONSE_GET_OBJECTS::request rsp;
    if(!m_core.handle_get_objects(arg, rsp, peer_cxt))
    {
      MERROR(peer_cxt<<"failed to handle request NOTIFY_REQUEST_GET_OBJECTS, dropping connection");
      drop_connection(peer_cxt, false, false);
      return 1;
    }
    peer_cxt.m_last_request_time = boost::posix_time::microsec_clock::universal_time();

    post_notify<NOTIFY_RESPONSE_GET_OBJECTS>(rsp, peer_cxt);
    //handler_response_blocks_now(sizeof(rsp)); // XXX
    //handler_response_blocks_now(200);
    return 1;
  }catch(std::exception& ex){
      drop_connection(peer_cxt, false, false);
        return 1;
  }
  }
  //------------------------------------------------------------------------------------------------------------------------


  template<class t_core>
  double t_cryptonote_protocol_handler<t_core>::get_avg_block_size()
  {
    CRITICAL_REGION_LOCAL(m_buffer_mutex);
    if (m_avg_buffer.empty()) {
      MWARNING("m_avg_buffer.size() == 0");
      return 500;
    }
    double avg = 0;
    for (const auto &element : m_avg_buffer) avg += element;
    return avg / m_avg_buffer.size();
  }

  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_response_get_objects(int command, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp, cryptonote_peer_context& peer_cxt)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_RESPONSE_GET_OBJECTS (" << rsp.bces.size() << " blocks)");
    MLOG_PEER_STATE("received objects");

 if (peer_cxt.m_expect_response != NOTIFY_RESPONSE_GET_OBJECTS::ID)
    {
      MERROR(peer_cxt<<"Got NOTIFY_RESPONSE_GET_OBJECTS out of the blue, dropping connection");
      drop_connection(peer_cxt, true, false);
      return 1;
    }

    if(rsp.bces.empty())
    {
      MERROR(peer_cxt<<"sent wrong NOTIFY_HAVE_OBJECTS: no blocks");
      drop_connection(peer_cxt, true, false);
      ++m_sync_bad_spans_downloaded;
      return 1;
    }

    const auto request_time = peer_cxt.m_last_request_time;
    peer_cxt.m_last_request_time = boost::date_time::not_a_date_time;
    peer_cxt.m_expect_response = 0;

    // calculate size of request
    size_t size = 0;
    size_t blocks_size = 0;
    for (const auto &element : rsp.bces) {
      blocks_size += element.blob.size();
      for (const auto &tx : element.txs)
        blocks_size += tx.blob.size();
    }
    size += blocks_size;

    {
      CRITICAL_REGION_LOCAL(m_buffer_mutex);
      m_avg_buffer.push_back(size);
    }
    ++m_sync_spans_downloaded;
    m_sync_download_objects_size += size;
    MDEBUG(peer_cxt << " downloaded " << size << " bytes worth of blocks");

    const auto local_height =m_core.get_current_blockchain_height() ;
    if( rsp.chain_height <=local_height)
    {
      MERROR(peer_cxt<<"why sync with shorter chains?" << rsp.chain_height<<"/"<< local_height << ", dropping connection");
      drop_connection(peer_cxt, false, false);
      ++m_sync_bad_spans_downloaded;
      return 1;
    }


    peer_cxt.m_remote_chain_height = rsp.chain_height;
    if (peer_cxt.m_remote_chain_height > m_core.get_target_blockchain_height())
      m_core.set_target_blockchain_height(peer_cxt.m_remote_chain_height);

    uint64_t start_height = rsp.span_start_height;
    peer_cxt.m_requested_objects.clear();

    const auto now = boost::posix_time::microsec_clock::universal_time();
    {
      MLOG_YELLOW(el::Level::Debug, peer_cxt << " Got NEW BLOCKS inside of " << __FUNCTION__ << ": size: " << rsp.blocks.size()<< ", blocks: " << start_height << " - " << (start_height + rsp.bces.size() - 1));

      // add that new span to the block queue
      const boost::posix_time::time_duration dt = now - request_time;
      const float rate = size * 1e6 / (dt.total_microseconds() + 1);
      MDEBUG(peer_cxt << " adding span: " << rsp.bces.size() << " at height " << start_height << ", " << dt.total_microseconds()/1e6 << " seconds, " << (rate/1024) << " kB/s, size now " << (m_block_queue.get_data_size() + blocks_size) / 1048576.f << " MB");

    }

      m_block_queue.finish_span(start_height, rsp.bces, peer_cxt);
    //  peer_cxt.m_last_known_hash = cryptonote::get_block_hash(b);
  
   if (!download_next_span(peer_cxt, true))
    {
      MERROR(peer_cxt<<"Failed to request missing objects, dropping connection");
      drop_connection(peer_cxt, false, false);
      return 1;
    }
      try_add_next_span(peer_cxt);
    return 1;
  }

  // Get an estimate for the remaining sync time from given current to target blockchain height, in seconds
  template<class t_core>
  uint64_t t_cryptonote_protocol_handler<t_core>::get_estimated_remaining_sync_seconds(uint64_t cur_chain_height, uint64_t target_blockchain_height)
  {
    // The average sync speed varies so much, even averaged over quite long time periods like 10 minutes,
    // that using some sliding window would be difficult to implement without often leading to bad estimates.
    // The simplest strategy - always average sync speed over the maximum available interval i.e. since sync
    // started at all (from "m_sync_start_time" and "m_sync_start_height") - gives already useful results
    // and seems to be quite robust. Some quite special cases like "Internet connection suddenly becoming
    // much faster after syncing already a long time, and staying fast" are not well supported however.

    if (target_blockchain_height <= cur_chain_height)
    {
      // Syncing stuck, or other special circumstance: Avoid errors, simply give back 0
      return 0;
    }

    const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
    const boost::posix_time::time_duration sync_time = now - m_sync_start_time;
    cryptonote::network_type nettype = m_core.get_nettype();

    // Don't simply use remaining number of blocks for the estimate but "sync weight" as provided by
    // "cumulative_block_sync_weight" which knows about strongly varying Monero mainnet block sizes
    uint64_t synced_weight = tools::cumulative_block_sync_weight(nettype, m_sync_start_height, cur_chain_height - m_sync_start_height);
    float us_per_weight = (float)sync_time.total_microseconds() / (float)synced_weight;
    uint64_t remaining_weight = tools::cumulative_block_sync_weight(nettype, cur_chain_height, target_blockchain_height - cur_chain_height);
    float remaining_us = us_per_weight * (float)remaining_weight;
    return (uint64_t)(remaining_us / 1e6);
  }

  // Return a textual remaining sync time estimate, or the empty string if waiting period not yet over
  template<class t_core>
  std::string t_cryptonote_protocol_handler<t_core>::get_periodic_sync_estimate(uint64_t cur_chain_height, uint64_t target_blockchain_height)
  {
    std::string text = "";
    const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
    boost::posix_time::time_duration period_sync_time = now - m_period_start_time;
    if (period_sync_time > boost::posix_time::minutes(2))
    {
      // Period is over, time to report another estimate
      uint64_t remaining_seconds = get_estimated_remaining_sync_seconds(cur_chain_height, target_blockchain_height);
      text = tools::get_human_readable_timespan(remaining_seconds);

      // Start the new period
      m_period_start_time = now;
    }
    return text;
  }

  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::try_add_next_span(cryptonote_peer_context& peer_cxt)
  {

      // We try to lock the sync lock. If we can, it means no other thread is
      // currently adding blocks, so we do that for as long as we can from the
      // block queue. Then, we go back to download.
      const boost::unique_lock<boost::mutex> sync{m_sync_lock, boost::try_to_lock};
      if (!sync.owns_lock())
      {
        MINFO( "Failed to lock m_sync_lock, going back to download");
        goto skip;
      }
      MDEBUG(" lock m_sync_lock, adding blocks to chain...");
      MLOG_PEER_STATE("adding blocks");

        m_add_timer.resume();
        bool starting = true;
        epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([this, &starting]() {
          m_add_timer.pause();
          if (!starting)
            m_last_add_end_time = tools::get_tick_count();
        });
        m_sync_start_time = boost::posix_time::microsec_clock::universal_time();
        m_sync_start_height = m_core.get_current_blockchain_height();
        m_period_start_time = m_sync_start_time;

        while (1)
        {
          const uint64_t local_height = m_core.get_current_blockchain_height();
          uint64_t start_height;
         
          boost::uuids::uuid span_con_id;
          epee::net_utils::network_address span_origin;
          const auto & o_span = m_block_queue.get_next_span(start_height, v_sync_b_data, span_con_id, span_origin);
          if (!o_span)
          {
            MDEBUG(" no next span found, going back to download");
            break;
          }
          const auto & span = o_span.value();
          auto & v_sync_b_data  = span.bces;
          MDEBUG(" next span in the queue has v_sync_b_data " << start_height << "-" << (start_height + v_sync_b_data.size() - 1)<< ", we need " << local_height);

          const boost::posix_time::ptime start = boost::posix_time::microsec_clock::universal_time();

          if (starting)
          {
            starting = false;
            if (m_last_add_end_time)
            {
              const uint64_t tnow = tools::get_tick_count();
              const uint64_t ns = tools::ticks_to_ns(tnow - m_last_add_end_time);
              MINFO("Restarting adding block after idle for " << ns/1e9 << " seconds");
            }
          }
          
          uint64_t block_process_time_full = 0, transactions_process_time_full = 0;
          size_t num_txs = 0, blockidx = 0;
          for(const auto& sync_b_data: v_sync_b_data)
          {
            if (m_stopping)
            {
                m_core.cleanup_handle_incoming_blocks();
                return 1;
            }

            const auto block = parse_block_from_blob(sync_b_data.block);
            std::vector<BlobTx> tx_ps;
            txes.reserve(sync_b_data.txs.size());
            for(auto &  tb: sync_b_data.txs){
              const auto & tx = parse_tx_from_blob_entry(tb);
              tx_ps.push_back({std::move(tx),std::move(tb.tx_blob)});
            }
            // process transactions
            num_txs += tx_ps.size();
            // process block

            TIME_MEASURE_START(block_process_time);
            block_verification_context bvc = m_core.get_blockchain().add_sync_block(block,tx_ps); // <--- process block

            if(bvc.m_verifivation_failed)
            {
              drop_connections(span_origin);
              // in case the peer had dropped beforehand, remove the span anyway so other threads can wake up and get it
              m_block_queue.remove_spans(span_con_id, start_height);
              return 1;
            }
            if(bvc.m_marked_as_orphaned)
            {
              drop_connections(span_origin);

              // in case the peer had dropped beforehand, remove the span anyway so other threads can wake up and get it
              m_block_queue.remove_spans(span_con_id, start_height);
              return 1;
            }

            TIME_MEASURE_FINISH(block_process_time);
            block_process_time_full += block_process_time;
            ++blockidx;

          } // each download block

          MDEBUG(peer_cxt << "Block process time (" << v_sync_b_data.size() << " v_sync_b_data, " << num_txs << " txs): " << block_process_time_full + transactions_process_time_full << " (" << transactions_process_time_full << "/" << block_process_time_full << ") ms");

          m_block_queue.remove_spans(span_con_id, start_height);

          const uint64_t cur_chain_height = m_core.get_current_blockchain_height();
          if (cur_chain_height > local_height)
          {
            const uint64_t target_blockchain_height = m_core.get_target_blockchain_height();
            const boost::posix_time::time_duration dt = boost::posix_time::microsec_clock::universal_time() - start;
            std::string progress_message = "";
            if (cur_chain_height < target_blockchain_height)
            {
              uint64_t completion_percent = (cur_chain_height * 100 / target_blockchain_height);
              if (completion_percent == 100) // never show 100% if not actually up to date
                completion_percent = 99;
              progress_message = " (" + std::to_string(completion_percent) + "%, "+ std::to_string(target_blockchain_height - cur_chain_height) + " left";
              std::string time_message = get_periodic_sync_estimate(cur_chain_height, target_blockchain_height);
              if (!time_message.empty())
              {
                uint64_t total_blocks_to_sync = target_blockchain_height - m_sync_start_height;
                uint64_t total_blocks_synced = cur_chain_height - m_sync_start_height;
                progress_message += ", " + std::to_string(total_blocks_synced * 100 / total_blocks_to_sync) + "% of total synced";
                progress_message += ", estimated " + time_message + " left";
              }
              progress_message += ")";
            }
            const uint32_t previous_stripe = tools::get_pruning_stripe(local_height, target_blockchain_height, CRYPTONOTE_PRUNING_LOG_STRIPES);
            const uint32_t current_stripe = tools::get_pruning_stripe(cur_chain_height, target_blockchain_height, CRYPTONOTE_PRUNING_LOG_STRIPES);
            std::string timing_message = "";
              timing_message = std::string(" (") + std::to_string(dt.total_microseconds()/1e6) + " sec, "+ std::to_string((cur_chain_height - local_height) * 1e6 / dt.total_microseconds())+ " v_sync_b_data/sec), " + std::to_string(m_block_queue.get_data_size() / 1048576.f) + " MB queued in "+ std::to_string(m_block_queue.get_num_filled_spans()) + " spans, stripe  -> " + std::to_string(current_stripe);
              timing_message += std::string(": ") + m_block_queue.get_overview(cur_chain_height);
            MGINFO_YELLOW("Synced " << cur_chain_height << "/" << target_blockchain_height<< progress_message << timing_message);
          }
        }
    
skip:
  
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::notify_new_stripe(cryptonote_peer_context& peer_cxt, uint32_t stripe)
  {
    m_p2p->for_each_connection([&](cryptonote_peer_context& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags)->bool
    {
      if (peer_cxt.m_connection_id == peer_cxt.m_connection_id)
        return true;
      if (peer_cxt.m_state == cryptonote_peer_context::state_normal)
      {
        const uint32_t peer_stripe = tools::get_pruning_stripe(peer_cxt.m_pruning_seed);
        if (stripe && peer_stripe && peer_stripe != stripe)
          return true;
        peer_cxt.m_new_stripe_notification = true;
        LOG_PRINT_CCONTEXT_L2("requesting callback");
        ++peer_cxt.m_callback_request_count;
        m_p2p->request_callback(peer_cxt);
        MLOG_PEER_STATE("requesting callback");
      }
      return true;
    });
  }

  #include "cryptonote_protocol_handler_idle.inl"
  
 
 
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_request_chain(int command, NOTIFY_REQUEST_CHAIN::request& arg, cryptonote_peer_context& peer_cxt)
  {
    try{
    MLOG_P2P_MESSAGE("Received NOTIFY_REQUEST_CHAIN (" << arg.block_ids.size() << " blocks");
    if (peer_cxt.m_state == cryptonote_peer_context::state_before_handshake)
    {
      MERROR(peer_cxt<<"Requested chain before handshake, dropping connection");
      drop_connection(peer_cxt, false, false);
      return 1;
    }
    NOTIFY_RESPONSE_CHAIN_ENTRY::request r;
     auto sync = find_blockchain_sync_info(remote, resp.m_block_ids,  resp.start_height, resp.total_height);
    r.split_height=sync.split_height;
    r.chain_height = sync.top_height;
    r.m_block_ids=sync.hashes;

  
    if (r.m_block_ids.size() >= 2)
    {
      cryptonote::block b;
      if (!m_core.get_block_by_hash(r.m_block_ids[1], b))
      {
        MERROR(peer_cxt<<"Failed to handle NOTIFY_REQUEST_CHAIN: first block not found");
        return 1;
      }
      r.first_block = cryptonote::block_to_blob(b);
    }
    MLOG_P2P_MESSAGE("-->>NOTIFY_RESPONSE_CHAIN_ENTRY: m_start_height=" << r.start_height << ", m_total_height=" << r.total_height << ", m_block_ids.size()=" << r.m_block_ids.size());
    post_notify<NOTIFY_RESPONSE_CHAIN_ENTRY>(r, peer_cxt);
    return 1;
  }
  catch(std::exception &ex){

     MERROR(peer_cxt<<"Failed to handle NOTIFY_REQUEST_CHAIN.");
      return 1;

  }
  }

    //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  int t_cryptonote_protocol_handler<t_core>::handle_response_chain_entry(int command, NOTIFY_RESPONSE_CHAIN_ENTRY::request& arg, cryptonote_peer_peer_cxt& peer_cxt)
  {
    MLOG_P2P_MESSAGE("Received NOTIFY_RESPONSE_CHAIN_ENTRY: m_block_ids.size()=" << arg.m_block_ids.size()
      << ", m_start_height=" << arg.start_height << ", m_total_height=" << arg.top_height);
    MLOG_PEER_STATE("received chain");

    if (peer_cxt.m_expect_response != NOTIFY_RESPONSE_CHAIN_ENTRY::ID)
    {
      MERROR(peer_cxt<<"Got NOTIFY_RESPONSE_CHAIN_ENTRY out of the blue, dropping connection");
      drop_connection(peer_cxt, true, false);
      return 1;
    }
   
    if (arg.split_height + 1 > peer_cxt.m_sync_start_height) // we expect an overlapping block
    {
      MERROR(peer_cxt<<"Got NOTIFY_RESPONSE_CHAIN_ENTRY past expected height, dropping connection");
      drop_connection(peer_cxt, true, false);
      return 1;
    }
    if(!arg.m_block_ids.size())
    {
      MERROR(peer_cxt<<"sent empty m_block_ids, dropping connection");
      drop_connection(peer_cxt, true, false);
      return 1;
    }
    if (arg.top_height < arg.m_block_ids.size() || arg.start_height > arg.top_height - arg.m_block_ids.size())
    {
      MERROR(peer_cxt<<"sent invalid start/nblocks/height, dropping connection");
      drop_connection(peer_cxt, true, false);
      return 1;
    }
    if (arg.top_height >= CRYPTONOTE_MAX_BLOCK_NUMBER || arg.m_block_ids.size() > BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT)
    {
      MERROR(peer_cxt<<"sent wrong NOTIFY_RESPONSE_CHAIN_ENTRY, with top_height=" << arg.top_height << " and block_ids=" << arg.m_block_ids.size());
      drop_connection(peer_cxt, false, false);
      return 1;
    }

    peer_cxt.m_expect_response = 0;
    peer_cxt.m_last_request_time = boost::date_time::not_a_date_time;
    peer_cxt.m_remote_chain_height = arg.top_height;
    peer_cxt.m_last_response_height = arg.start_height + arg.m_block_ids.size()-1;
    peer_cxt.m_needed_blocks.clear();
    peer_cxt.m_needed_blocks.reserve(arg.m_block_ids.size());
    std::unordered_set<crypto::hash> blocks_found;
    bool first = true;
    bool expect_unknown = false;
    for (auto &bh : arg.m_block_ids)
    {
      if (!blocks_found.insert(bh).second)
      {
        MERROR(peer_cxt<<"Duplicate blocks in chain entry response, dropping connection");
        drop_connection_with_score(peer_cxt, 5, false);
        return 1;
      }
      int where;
      const bool have_block = m_core.have_block_unlocked(bh, &where);
      if (first)
      {
        if (!have_block && !m_block_queue.requested(bh) && !m_block_queue.have_downloaded(bh))
        {
          MERROR(peer_cxt<<"First block hash is unknown, dropping connection");
          drop_connection_with_score(peer_cxt, 5, false);
          return 1;
        }
        if (!have_block)
          expect_unknown = true;
      }
      else
      {
        // after the first, blocks may be known or unknown, but if they are known,
        // they should be at the same height if on the main chain
        if (have_block)
        {
          switch (where)
          {
            default:
            case HAVE_BLOCK_INVALID:
              MERROR(peer_cxt<<"Block is invalid or known without known type, dropping connection");
              drop_connection(peer_cxt, true, false);
              return 1;
            case HAVE_BLOCK_MAIN_CHAIN:
              if (expect_unknown)
              {
                MERROR(peer_cxt<<"Block is on the main chain, but we did not expect a known block, dropping connection");
                drop_connection_with_score(peer_cxt, 5, false);
                return 1;
              }
              if (m_core.get_block_hash_by_height(arg.start_height + i) != bh)
              {
                MERROR(peer_cxt<<"Block is on the main chain, but not at the expected height, dropping connection");
                drop_connection_with_score(peer_cxt, 5, false);
                return 1;
              }
              break;
            case HAVE_BLOCK_ALT_CHAIN:
              if (expect_unknown)
              {
                MERROR(peer_cxt<<"Block is on the alt chain, but we did not expect a known block, dropping connection");
                drop_connection_with_score(peer_cxt, 5, false);
                return 1;
              }
              break;
          }
        }
        else
          expect_unknown = true;
      }
      peer_cxt.m_needed_blocks.push_back(bh);
      first = false;
    }

    if (!download_next_span(peer_cxt, false))
    {
      MERROR(peer_cxt<<"Failed to request missing objects, dropping connection");
      drop_connection(peer_cxt, false, false);
      return 1;
    }

    if (arg.top_height > m_core.get_target_blockchain_height())
      m_core.set_target_blockchain_height(arg.top_height);

    peer_cxt.m_num_requested = 0;
    return 1;
  }

  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  size_t t_cryptonote_protocol_handler<t_core>::skip_unneeded_hashes(cryptonote_peer_context& peer_cxt, bool check_block_queue) const
  {
    if(peer_cxt.m_needed_blocks.size()==0)
      return 0;
    // take out blocks we already have
    size_t i = 0;
    for(i=0;i<peer_cxt.m_needed_blocks.size();++i){
        const auto & bh = peer_cxt.m_needed_blocks[i];
       if ( !(m_core.have_block(bh) || (check_block_queue && m_block_queue.have_downloaded(bh))))
        {
          break;
        }
    }

    // if we're popping the last hash, record it so we can ask again from that hash,
      // this prevents never being able to progress on peers we get old hash lists from
      if (i == peer_cxt.m_needed_blocks.size())
        peer_cxt.m_last_known_hash = peer_cxt.m_needed_blocks[i-1];

    if (i > 0)
    {
      MDEBUG(peer_cxt << "skipping " << i << "/" << peer_cxt.m_needed_blocks.size() << " blocks");
      peer_cxt.m_needed_blocks = std::vector<crypto::hash>(peer_cxt.m_needed_blocks.begin() + i, peer_cxt.m_needed_blocks.end());
    }
    return i;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::should_ask_for_pruned_data(cryptonote_peer_context& peer_cxt, uint64_t first_block_height, uint64_t nblocks, bool check_block_weights) const
  {
  
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::download_next_span(cryptonote_peer_context& peer_cxt, bool check_having_blocks)
  {
    // flush stale spans
    std::set<boost::uuids::uuid> live_connections;
    m_p2p->for_each_connection([&](cryptonote_peer_context& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags)->bool{
      live_connections.insert(peer_cxt.m_connection_id);
      return true;
    });
    m_block_queue.flush_stale_spans(live_connections);

    // if we don't need to get next span, and the block queue is full enough, wait a bit
      do
      {
        size_t nspans = m_block_queue.get_num_filled_spans();
        size_t size = m_block_queue.get_data_size();
        const uint64_t cur_chain_height = m_core.get_current_blockchain_height();
      
        const size_t block_queue_size_threshold = m_block_download_max_size ? m_block_download_max_size : BLOCK_QUEUE_SIZE_THRESHOLD;
        bool queue_proceed = nspans < BLOCK_QUEUE_NSPANS_THRESHOLD || size < block_queue_size_threshold;
        // get rid of blocks we already requested, or already have
        skip_unneeded_hashes(peer_cxt, true);
        if (peer_cxt.m_needed_blocks.empty() && peer_cxt.m_num_requested == 0)
        {
          if (peer_cxt.m_remote_chain_height > m_block_queue.get_next_needed_height(cur_chain_height))
          {
            MERROR(peer_cxt << "Nothing we can request from this peer, and we did not request anything previously");
            return false;
          }
          MDEBUG(peer_cxt << "Nothing to get from this peer, and it's not ahead of us, all done");
          peer_cxt.m_state = cryptonote_peer_context::state_normal;
          return true;
        }

        uint64_t next_block_height;
        if (peer_cxt.m_needed_blocks.empty())
          next_block_height = m_block_queue.get_next_needed_height(cur_chain_height);
        else
          next_block_height = peer_cxt.m_last_response_height - peer_cxt.m_needed_blocks.size() + 1;
    
       
        if (proceed)
        {
          if (peer_cxt.m_state != cryptonote_peer_context::state_standby)
          {
            MDEBUG(peer_cxt, "Block queue is " << nspans << " and " << size << ", resuming");
            MLOG_PEER_STATE("resuming");
          }
          break;
        }

        // this one triggers if all threads are in standby, which should not happen,
        // but happened at least once, so we unblock at least one thread if so
        boost::unique_lock<boost::mutex> sync{m_sync_lock, boost::try_to_lock};
        if (sync.owns_lock())
        {
          bool filled = false;
          boost::posix_time::ptime time;
          boost::uuids::uuid connection_id;
          if (m_block_queue.has_next_span(m_core.get_current_blockchain_height(), filled, time, connection_id) && filled)
          {
            MDEBUG(peer_cxt, "No other thread is adding blocks, and next span needed is ready, resuming");
            MLOG_PEER_STATE("resuming");
            peer_cxt.m_state = cryptonote_peer_context::state_standby;
            ++peer_cxt.m_callback_request_count;
            m_p2p->request_callback(peer_cxt);
            return true;
          }
          else
          {
            sync.unlock();

            // if this has gone on for too long, drop incoming connection to guard against some wedge state
            if (!peer_cxt.m_is_income)
            {
              const uint64_t now = tools::get_tick_count();
              const uint64_t dt = now - m_last_add_end_time;
              if (m_last_add_end_time && tools::ticks_to_ns(dt) >= DROP_ON_SYNC_WEDGE_THRESHOLD)
              {
                MDEBUG(peer_cxt << "ns " << tools::ticks_to_ns(dt) << " from " << m_last_add_end_time << " and " << now);
                MDEBUG(peer_cxt << "Block addition seems to have wedged, dropping connection");
                return false;
              }
            }
          }
        }

        if (peer_cxt.m_state != cryptonote_peer_context::state_standby)
        {
          if (!queue_proceed)
            MDEBUG(peer_cxt, "Block queue is " << nspans << " and " << size << ", pausing");
          else if (!stripe_proceed_main && !stripe_proceed_secondary)
            MDEBUG(peer_cxt, "We do not have the stripe required to download another block, pausing");
          peer_cxt.m_state = cryptonote_peer_context::state_standby;
          MLOG_PEER_STATE("pausing");
        }

        return true;
      } while(0);

      peer_cxt.m_state = cryptonote_peer_context::state_synchronizing;

    MDEBUG(peer_cxt << " download_next_span: check " << check_having_blocks  << ", m_needed_blocks " << peer_cxt.m_needed_blocks.size() << " lrh " << peer_cxt.m_last_response_height << ", chain "<< m_core.get_current_blockchain_height() );
    if(peer_cxt.m_needed_blocks.size())
    {
      //we know objects that we need, request this objects
      NOTIFY_REQUEST_GET_OBJECTS::request req;
      bool is_next = false;
      size_t count = 0;
   
      
        MDEBUG(peer_cxt << " span size is 0");
        if (peer_cxt.m_last_response_height + 1 < peer_cxt.m_needed_blocks.size())
        {
          MERROR(peer_cxt << " ERROR: inconsistent peer_cxt: lrh " << peer_cxt.m_last_response_height << ", nos " << peer_cxt.m_needed_blocks.size());
          peer_cxt.m_needed_blocks.clear();
          peer_cxt.m_last_response_height = 0;
          goto skip;
        }
        skip_unneeded_hashes(peer_cxt, false);
        if (peer_cxt.m_needed_blocks.empty() && peer_cxt.m_num_requested == 0)
        {
          if (peer_cxt.m_remote_chain_height > m_block_queue.get_next_needed_height(m_core.get_current_blockchain_height()))
          {
            MERROR(peer_cxt << "Nothing we can request from this peer, and we did not request anything previously");
            return false;
          }
          MDEBUG(peer_cxt << "Nothing to get from this peer, and it's not ahead of us, all done");
          peer_cxt.m_state = cryptonote_peer_context::state_normal;
          return true;
        }

        const uint64_t first_block_height = peer_cxt.m_last_response_height - peer_cxt.m_needed_blocks.size() + 1;
         const size_t batch_size = m_core.get_block_sync_batch_size();

        const auto span = m_block_queue.start_span(first_block_height, peer_cxt.m_last_response_height, batch_size, peer_cxt.m_connection_id, peer_cxt.m_remote_address,  peer_cxt.m_remote_chain_height, peer_cxt.m_needed_blocks);

        MDEBUG(peer_cxt << " span from " << first_block_height << ": " << span.first << "/" << span.second);
    

      MDEBUG(peer_cxt << " span: " << span.first << "/" << span.second << " (" << span.first << " - " << (span.first + span.second - 1) << ")");
      if (span.second > 0)
      {
        if (!is_next)
        {
          const uint64_t first_context_block_height = peer_cxt.m_last_response_height - peer_cxt.m_needed_blocks.size() + 1;
          uint64_t skip = span.first - first_context_block_height;
          if (skip > peer_cxt.m_needed_blocks.size())
          {
            MERROR("ERROR: skip " << skip << ", m_needed_blocks " << peer_cxt.m_needed_blocks.size() << ", first_context_block_height" << first_context_block_height);
            return false;
          }
          if (skip > 0)
            peer_cxt.m_needed_blocks = std::vector<crypto::hash>(peer_cxt.m_needed_blocks.begin() + skip, peer_cxt.m_needed_blocks.end());
          if (peer_cxt.m_needed_blocks.size() < span.second)
          {
            MERROR("ERROR: span " << span.first << "/" << span.second << ", m_needed_blocks " << peer_cxt.m_needed_blocks.size());
            return false;
          }

          req.blocks.reserve(req.blocks.size() + span.second);
          for (size_t n = 0; n < span.second; ++n)
          {
            const auto & bh = peer_cxt.m_needed_blocks[n];
            req.blocks.push_back(bh);
            ++count;
            peer_cxt.m_requested_objects.insert(bh);
          }
          peer_cxt.m_needed_blocks = std::vector<crypto::hash>(peer_cxt.m_needed_blocks.begin() + span.second, peer_cxt.m_needed_blocks.end());
        }

        // if we need to ask for full data and that peer does not have the right stripe, we can't ask it
       
        peer_cxt.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
        peer_cxt.m_sync_start_height = span.first;
        peer_cxt.m_expect_response = NOTIFY_RESPONSE_GET_OBJECTS::ID;
        MLOG_P2P_MESSAGE("-->>NOTIFY_REQUEST_GET_OBJECTS: blocks.size()=" << req.blocks.size()
            << "requested blocks count=" << count ,< " from " << span.first << ", first hash " << req.blocks.front());
     
        peer_cxt.m_num_requested += req.blocks.size();
        post_notify<NOTIFY_REQUEST_GET_OBJECTS>(req, peer_cxt);
        MLOG_PEER_STATE("requesting objects");
        return true;
      }

      // we can do nothing, so drop this peer to make room for others unless we think we've downloaded all we need
      const uint64_t blockchain_height = m_core.get_current_blockchain_height();
      if (std::max(blockchain_height, m_block_queue.get_next_needed_height(blockchain_height)) >= m_core.get_target_blockchain_height())
      {
        peer_cxt.m_state = cryptonote_peer_context::state_normal;
        MLOG_PEER_STATE("Nothing to do for now, switching to normal state");
        return true;
      }
      MLOG_PEER_STATE("We can download nothing from this peer, dropping");
      return false;
    }

skip:
    peer_cxt.m_needed_blocks.clear();

    // we might have been called from the "received chain entry" handler, and end up
    // here because we can't use any of those blocks (maybe because all of them are
    // actually already requested). In this case, if we can add blocks instead, do so
    if (m_core.get_current_blockchain_height() < m_core.get_target_blockchain_height())
    {
      const boost::unique_lock<boost::mutex> sync{m_sync_lock, boost::try_to_lock};
      if (sync.owns_lock())
      {
        uint64_t start_height;
        std::vector<cryptonote::block_complete_entry> blocks;
        boost::uuids::uuid span_con_id;
        epee::net_utils::network_address span_origin;
        if (m_block_queue.get_next_span(start_height, blocks, span_con_id, span_origin, true))
        {
          MDEBUG(peer_cxt, "No other thread is adding blocks, resuming");
          MLOG_PEER_STATE("will try to add blocks next");
          peer_cxt.m_state = cryptonote_peer_context::state_standby;
          ++peer_cxt.m_callback_request_count;
          m_p2p->request_callback(peer_cxt);
          return true;
        }
      }
    }

    if(peer_cxt.m_last_response_height < peer_cxt.m_remote_chain_height-1)
    {//we have to fetch more objects ids, request blockchain entry

      NOTIFY_REQUEST_CHAIN::request r {m_core.get_blockchain().get_short_chain_history()};
      peer_cxt.m_sync_start_height = m_core.get_current_blockchain_height();
      {
        // we'll want to start off from where we are on that peer, which may not be added yet
        if (peer_cxt.m_last_known_hash != crypto::null_hash && r.block_ids.front() != peer_cxt.m_last_known_hash)
        {
          peer_cxt.m_sync_start_height = std::numeric_limits<uint64_t>::max();
          r.block_ids.push_front(peer_cxt.m_last_known_hash);
        }
      }

      peer_cxt.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
      peer_cxt.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
      MLOG_P2P_MESSAGE("-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << r.block_ids.size() << ", start_from_current_chain " << start_from_current_chain);
      post_notify<NOTIFY_REQUEST_CHAIN>(r, peer_cxt);
      MLOG_PEER_STATE("requesting chain");
    }else
    {
      CHECK_AND_ASSERT_MES(peer_cxt.m_last_response_height == peer_cxt.m_remote_chain_height-1
                           && !peer_cxt.m_needed_blocks.size()&& !peer_cxt.m_requested_objects.size(), false, "request_missing_blocks final condition failed!"
                           << "\r\nm_last_response_height=" << peer_cxt.m_last_response_height
                           << "\r\nm_remote_blockchain_height=" << peer_cxt.m_remote_chain_height
                           << "\r\nm_needed_objects.size()=" << peer_cxt.m_needed_blocks.size()
                           << "\r\nm_requested_objects.size()=" << peer_cxt.m_requested_objects.size()
                           << "\r\non connection [" << epee::net_utils::print_connection_context_short(peer_cxt)<< "]");

      peer_cxt.m_state = cryptonote_peer_context::state_normal;
      if (peer_cxt.m_remote_chain_height >= m_core.get_target_blockchain_height())
      {
        if (m_core.get_current_blockchain_height() >= m_core.get_target_blockchain_height())
        {
          MGINFO_GREEN("SYNCHRONIZED OK");
          on_connection_synchronized();
        }
      }
      else
      {
        MINFO(peer_cxt << " we've reached this peer's blockchain height (theirs " << peer_cxt.m_remote_chain_height << ", our target " << m_core.get_target_blockchain_height());
      }
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::on_connection_synchronized()
  {
    bool val_expected = false;
    uint64_t cur_chain_height = m_core.get_current_blockchain_height();
    if( m_synchronized.compare_exchange_strong(val_expected, true))
    {
      if ((cur_chain_height > m_sync_start_height) && (m_sync_spans_downloaded > 0))
      {
        uint64_t synced_blocks = cur_chain_height - m_sync_start_height;
        // Report only after syncing an "interesting" number of blocks:
        if (synced_blocks > 20)
        {
          const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
          uint64_t synced_seconds = (now - m_sync_start_time).total_seconds();
          if (synced_seconds == 0)
          {
            synced_seconds = 1;
          }
          float blocks_per_second = (1000 * synced_blocks / synced_seconds) / 1000.0f;
          MGINFO_YELLOW("Synced " << synced_blocks << " blocks in "
            << tools::get_human_readable_timespan(synced_seconds) << " (" << blocks_per_second << " blocks per second)");
        }
      }
      MGINFO_YELLOW(ENDL << "**********************************************************************" << ENDL
        << "You are now synchronized with the network." << ENDL);
      m_sync_timer.pause();
      {
        const uint64_t sync_time = m_sync_timer.value();
        const uint64_t add_time = m_add_timer.value();
        if (sync_time && add_time)
        {
          MCLOG_YELLOW(el::Level::Info, "sync-info", "Sync time: " << sync_time/1e9/60 << " min, idle time " <<
              (100.f * (1.0f - add_time / (float)sync_time)) << "%" << ", " <<
              (10 * m_sync_download_objects_size / 1024 / 1024) / 10.f  << " MB downloaded, " <<
              100.0f * m_sync_old_spans_downloaded / m_sync_spans_downloaded << "% old spans, " <<
              100.0f * m_sync_bad_spans_downloaded / m_sync_spans_downloaded << "% bad spans");
        }
      }
    }
    m_p2p->clear_used_stripe_peers();

    // ask for txpool complement from any suitable node if we did not yet
    val_expected = true;
    if (m_ask_for_txpool_complement.compare_exchange_strong(val_expected, false))
    {
      m_p2p->for_each_connection([&](cryptonote_peer_context& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags)->bool
      {
        if(peer_cxt.m_state < cryptonote_peer_context::state_synchronizing)
        {
          MDEBUG(peer_cxt << "not ready, ignoring");
          return true;
        }
        if (!request_txpool_complement(peer_cxt))
        {
          MERROR(peer_cxt << "Failed to request txpool complement");
          return true;
        }
        return false;
      });
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  size_t t_cryptonote_protocol_handler<t_core>::get_synchronizing_connections_count()
  {
    size_t count = 0;
    m_p2p->for_each_connection([&](cryptonote_peer_context& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags)->bool{
      if(peer_cxt.m_state == cryptonote_peer_context::state_synchronizing)
        ++count;
      return true;
    });
    return count;
  }

  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::relay_block(const blobdata& blob, const uint64_t b_height, cryptonote_peer_context& exclude_context)
  {
    NOTIFY_NEW_FLUFFY_BLOCK::request fluffy_arg{};
    fluffy_arg.cur_chain_height = b_height;   
    fluffy_arg.b = blob;

    // sort peers between fluffy ones and others
    std::vector< boost::uuids::uuid>  fluffyConnections;
    m_p2p->for_each_connection([this, &exclude_context, &fullConnections, &fluffyConnections](cryptonote_peer_context& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags)
    {
      // peer_id also filters out connections before handshake
      if (peer_id && exclude_context.m_connection_id != peer_cxt.m_connection_id )
      {
          fluffyConnections.push_back( peer_cxt.m_connection_id);
      }
      return true;
    });

    // send fluffy ones first, we want to encourage people to run that
    if (!fluffyConnections.empty())
    {
      epee::levin::message_writer fluffyBlob{32 * 1024};
      epee::serialization::store_t_to_binary(fluffy_arg, fluffyBlob.buffer);
      m_p2p->relay_notify_to_list(NOTIFY_NEW_FLUFFY_BLOCK::ID, std::move(fluffyBlob), std::move(fluffyConnections));
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::relay_transactions(NOTIFY_NEW_TRANSACTIONS::request& arg, const boost::uuids::uuid& source, epee::net_utils::zone zone, relay_method tx_relay)
  {
    /* Push all outgoing transactions to this function. The behavior needs to
       identify how the transaction is going to be relayed, and then update the
       local mempool before doing the relay. The code was already updating the
       DB twice on received transactions - it is difficult to workaround this
       due to the internal design. */
    return m_p2p->send_txs(std::move(arg.txs),  source, tx_relay) ;
  }
  template<class t_core>
  uint64_t t_cryptonote_protocol_handler<t_core>::get_current_blockchain_height()const
  {
    return m_core.get_current_blockchain_height();
  }
  template<class t_core>
   void t_cryptonote_protocol_handler<t_core>::on_transactions_relayed(epee::span<const cryptonote::blobdata> tx_blobs, relay_method tx_relay) 
   {
      m_core.on_transactions_relayed(tx_blobs,tx_relay);
   }

  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::request_txpool_complement(cryptonote_peer_context &peer_cxt)
  {
    NOTIFY_GET_TXPOOL_COMPLEMENT::request r = {};
    if (!m_core.get_pool_transaction_hashes(r.hashes, false))
    {
      MERROR("Failed to get txpool hashes");
      return false;
    }
    MLOG_P2P_MESSAGE("-->>NOTIFY_GET_TXPOOL_COMPLEMENT: hashes.size()=" << r.hashes.size() );
    post_notify<NOTIFY_GET_TXPOOL_COMPLEMENT>(r, peer_cxt);
    MLOG_PEER_STATE("requesting txpool complement");
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::hit_score(cryptonote_peer_context &peer_cxt, int32_t score)
  {
    if (score <= 0)
    {
      MERROR("Negative score hit");
      return;
    }
    peer_cxt.m_score -= score;
    if (peer_cxt.m_score <= DROP_PEERS_ON_SCORE)
      drop_connection_with_score(peer_cxt, 5, false);
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  std::string t_cryptonote_protocol_handler<t_core>::get_peers_overview() const
  {
    std::stringstream ss;
    const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
    m_p2p->for_each_connection([&](const cryptonote_peer_context &ctx, nodetool::peerid_type peer_id, uint32_t support_flags) {
      const uint32_t stripe = tools::get_pruning_stripe(ctx.m_pruning_seed);
      char state_char = cryptonote::get_protocol_state_char(ctx.m_state);
      ss << stripe + state_char;
      if (ctx.m_last_request_time != boost::date_time::not_a_date_time)
        ss << (((now - ctx.m_last_request_time).total_microseconds() > IDLE_PEER_KICK_TIME) ? "!" : "?");
      ss <<  + " ";
      return true;
    });
    return ss.str();
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  std::pair<uint32_t, uint32_t> t_cryptonote_protocol_handler<t_core>::get_next_needed_pruning_stripe() const
  {
    const uint64_t cur_chain_height = m_core.get_current_blockchain_height();
    const uint64_t want_height_from_block_queue = m_block_queue.get_next_needed_height(cur_chain_height);
    const uint64_t want_height = std::max(cur_chain_height, want_height_from_block_queue);
    uint64_t blockchain_height = m_core.get_target_blockchain_height();
    // if we don't know the remote chain size yet, assume infinitely large so we get the right stripe if we're not near the tip
    if (blockchain_height == 0)
      blockchain_height = CRYPTONOTE_MAX_BLOCK_NUMBER;
    const uint32_t next_pruning_stripe = tools::get_pruning_stripe(want_height, blockchain_height, CRYPTONOTE_PRUNING_LOG_STRIPES);
    if (next_pruning_stripe == 0)
      return std::make_pair(0, 0);
    // if we already have a few peers on this stripe, but none on next one, try next one
    unsigned int n_next = 0, n_subsequent = 0, n_others = 0;
    const uint32_t subsequent_pruning_stripe = 1 + next_pruning_stripe % (1<<CRYPTONOTE_PRUNING_LOG_STRIPES);
    m_p2p->for_each_connection([&](const cryptonote_peer_context &peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags) {
      if (peer_cxt.m_state >= cryptonote_peer_context::state_synchronizing)
      {
        if (peer_cxt.m_pruning_seed == 0 || tools::get_pruning_stripe(peer_cxt.m_pruning_seed) == next_pruning_stripe)
          ++n_next;
        else if (tools::get_pruning_stripe(peer_cxt.m_pruning_seed) == subsequent_pruning_stripe)
          ++n_subsequent;
        else
          ++n_others;
      }
      return true;
    });
    const bool use_next = (n_next > m_max_out_peers / 2 && n_subsequent <= 1) || (n_next > 2 && n_subsequent == 0);
    const uint32_t ret_stripe = use_next ? subsequent_pruning_stripe: next_pruning_stripe;
      MIDEBUG(const std::string po = get_peers_overview(), "get_next_needed_pruning_stripe: want height " << want_height << " (" <<
        cur_chain_height << " from blockchain, " << want_height_from_block_queue << " from block queue), stripe " <<
        next_pruning_stripe << " (" << n_next << "/" << m_max_out_peers << " on it and " << n_subsequent << " on " <<
        subsequent_pruning_stripe << ", " << n_others << " others) -> " << ret_stripe << " (+" <<
        (ret_stripe - next_pruning_stripe + (1 << CRYPTONOTE_PRUNING_LOG_STRIPES)) % (1 << CRYPTONOTE_PRUNING_LOG_STRIPES) <<
        "), current peers " << po);
    return std::make_pair(next_pruning_stripe, ret_stripe);
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::needs_new_sync_connections() const
  {
    const uint64_t target = m_core.get_target_blockchain_height();
    const uint64_t height = m_core.get_current_blockchain_height();
    if (target && target <= height)
      return false;
    size_t n_out_peers = 0;
    m_p2p->for_each_connection([&](cryptonote_peer_context& ctx, nodetool::peerid_type peer_id, uint32_t support_flags)->bool{
      if (!ctx.m_is_income)
        ++n_out_peers;
      return true;
    });
    if (n_out_peers >= m_max_out_peers)
      return false;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::is_busy_syncing()
  {
    const boost::unique_lock<boost::mutex> sync{m_sync_lock, boost::try_to_lock};
    return !sync.owns_lock();
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::drop_connection_with_score(cryptonote_peer_context &peer_cxt, unsigned score, bool flush_all_spans)
  {
    MDEBUG(peer_cxt<<"dropping connection id " << peer_cxt.m_connection_id << " (pruning seed " <<
        epee::string_tools::to_string_hex(peer_cxt.m_pruning_seed) <<
        "), score " << score << ", flush_all_spans " << flush_all_spans);

    if (score > 0)
      m_p2p->add_host_fail(peer_cxt.m_remote_address, score);

    m_block_queue.flush_spans(peer_cxt.m_connection_id, flush_all_spans);

    m_p2p->drop_connection(peer_cxt);
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::drop_connection(cryptonote_peer_context &peer_cxt, bool add_fail, bool flush_all_spans)
  {
    return drop_connection_with_score(peer_cxt, add_fail ? 1 : 0, flush_all_spans);
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::drop_connections(const epee::net_utils::network_address address)
  {
    MWARNING("dropping connections to " << address.str());

    m_p2p->add_host_fail(address, 5);

    std::vector<boost::uuids::uuid> drop;
    m_p2p->for_each_connection([&](const auto& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags) {
      if (address.is_same_host(peer_cxt.m_remote_address))
        drop.push_back(peer_cxt.m_connection_id);
      return true;
    });
    for (const auto &id: drop)
    {
      m_block_queue.flush_spans(id, true);
      m_p2p->for_connection(id, [&](auto& peer_cxt, nodetool::peerid_type peer_id, uint32_t f)->bool{
        drop_connection(peer_cxt, true, false);
        return true;
      });
    }
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::on_connection_close(cryptonote_peer_context &peer_cxt)
  {
    uint64_t target = 0;
    m_p2p->for_each_connection([&](const cryptonote_peer_context& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags) {
      if (peer_cxt.m_state >= cryptonote_peer_context::state_synchronizing && peer_cxt.m_connection_id != peer_cxt.m_connection_id)
        target = std::max(target, peer_cxt.m_remote_chain_height);
      return true;
    });
    const uint64_t previous_target = m_core.get_target_blockchain_height();
    if (target < previous_target)
    {
      MINFO("Target height decreasing from " << previous_target << " to " << target);
      m_core.set_target_blockchain_height(target);
      if (target == 0 && peer_cxt.m_state > cryptonote_peer_context::state_before_handshake && !m_stopping)
      {
        MCWARNING("global", "monerod is now disconnected from the network");
        m_ask_for_txpool_complement = true;
      }
    }

    m_block_queue.flush_spans(peer_cxt.m_connection_id, false);
    MLOG_PEER_STATE("closed");
  }

  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  void t_cryptonote_protocol_handler<t_core>::stop()
  {
    m_stopping = true;
    m_core.stop();
  }
} // namespace

