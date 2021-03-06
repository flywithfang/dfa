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

#pragma once

#include <boost/program_options/variables_map.hpp>
#include <string>

#include "byte_slice.h"
#include "math_helper.h"
#include "storages/levin_abstract_invoke2.h"
#include "warnings.h"
#include "cryptonote_protocol_defs.h"
#include "cryptonote_protocol.h"
#include "block_queue.h"
#include "common/perf_timer.h"
#include "cryptonote_basic/cryptonote_peer_context.h"
#include "net/levin_base.h"
#include "p2p/net_node_common.h"
#include <boost/circular_buffer.hpp>

PUSH_WARNINGS
DISABLE_VS_WARNINGS(4355)

#define LOCALHOST_INT 2130706433
#define CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT 100

namespace cryptonote
{

  template<class t_core>
  class t_cryptonote_protocol_handler:  public i_cryptonote_protocol
  { 
  public:
    typedef cryptonote_peer_context peer_context;
    typedef t_cryptonote_protocol_handler<t_core> cryptonote_protocol_handler;
    typedef CORE_SYNC_DATA payload_type;

    t_cryptonote_protocol_handler(t_core& rcore, nodetool::i_p2p_endpoint<cryptonote_peer_context>* p2p, bool offline = false);


      template <class t_context>
      int handle_invoke_map(bool is_notify, int command, const epee::span<const uint8_t> in_buff, epee::byte_stream& buff_out, t_context& context, bool& handled) 
  { 
        try { 
            typedef cryptonote_protocol_handler internal_owner_type_name;
          
              if(is_notify && NOTIFY_NEW_TRANSACTIONS::ID == command) 
            {
              handled=true;
              const auto func = &cryptonote_protocol_handler::handle_notify_new_transactions;
              return epee::net_utils::buff_to_t_adapter<internal_owner_type_name, typename NOTIFY_NEW_TRANSACTIONS::request>(this, command, in_buff, std::bind(func, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), context);
            }
          HANDLE_NOTIFY_T2(NOTIFY_NEW_FLUFFY_BLOCK, &cryptonote_protocol_handler::handle_notify_new_fluffy_block)      
            HANDLE_NOTIFY_T2(NOTIFY_REQUEST_FLUFFY_MISSING_TX, &cryptonote_protocol_handler::handle_request_fluffy_missing_tx)            


            HANDLE_NOTIFY_T2(NOTIFY_REQUEST_GET_BLOCKS, &cryptonote_protocol_handler::handle_request_get_blocks)
            HANDLE_NOTIFY_T2(NOTIFY_RESPONSE_GET_BLOCKS, &cryptonote_protocol_handler::handle_response_get_objects)
            HANDLE_NOTIFY_T2(NOTIFY_REQUEST_CHAIN, &cryptonote_protocol_handler::handle_request_chain)
            HANDLE_NOTIFY_T2(NOTIFY_RESPONSE_CHAIN_ENTRY, &cryptonote_protocol_handler::handle_response_chain_entry)
         
            HANDLE_NOTIFY_T2(NOTIFY_GET_TXPOOL_COMPLEMENT, &cryptonote_protocol_handler::handle_notify_get_txpool_complement)

              LOG_ERROR("Unknown command:" << command); 
              on_levin_traffic(context, false, false, true, in_buff.size(), "invalid-command"); 
              return LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED; 
            } 
            catch (const std::exception &e) { 
              MERROR("Error in handle_invoke_map: " << e.what()); 
              return LEVIN_ERROR_CONNECTION_TIMEDOUT; /* seems kinda appropriate */ 
            } 
      }

    bool on_idle();
    bool init(const boost::program_options::variables_map& vm);
    bool deinit();

    void set_p2p_endpoint(nodetool::i_p2p_endpoint<cryptonote_peer_context>* p2p);
    
    //bool process_handshake_data(const blobdata& data, cryptonote_peer_context& context);
    bool process_payload_sync_data(const CORE_SYNC_DATA& hshd, cryptonote_peer_context& context, bool is_inital);
    bool get_payload_sync_data(epee::byte_slice& data);
    bool get_payload_sync_data(CORE_SYNC_DATA& hshd);
    bool on_callback(cryptonote_peer_context& context);
    t_core& get_core(){return m_core;}
   

    void log_connections();
    std::list<connection_info> get_connections();
    const block_queue &get_block_queue() const { return m_block_queue; }
    void stop();
    void on_connection_close(cryptonote_peer_context &context);
    void set_max_out_peers(unsigned int max) { m_max_out_peers = max; }
    bool no_sync() const { return m_no_sync; }
    void set_no_sync(bool value) { m_no_sync = value; }
    std::string get_peers_overview() const;
    std::pair<uint32_t, uint32_t> get_next_needed_pruning_stripe() const;
    bool needs_new_sync_connections() const;
    bool is_busy_syncing();

  
    public:
    //----------------- i_bc_protocol_layout ---------------------------------------
    virtual bool relay_block(const blobdata& blob, const uint64_t b_height, cryptonote_peer_context& exclude_context);
    virtual bool relay_transactions(NOTIFY_NEW_TRANSACTIONS::request& arg, const boost::uuids::uuid& source, epee::net_utils::zone zone, relay_method tx_relay);
    virtual uint64_t get_chain_height()const;
    virtual void on_transactions_relayed(epee::span<const cryptonote::blobdata> tx_blobs, relay_method tx_relay) ;
     virtual bool is_synchronized() const {
     return !no_sync() && m_synchronized;
     }
   
  private:
    //----------------- commands handlers ----------------------------------------------
    int handle_notify_new_transactions(int command, NOTIFY_NEW_TRANSACTIONS::request& arg, cryptonote_peer_context& context);
    int handle_request_get_blocks(int command, NOTIFY_REQUEST_GET_BLOCKS::request& arg, cryptonote_peer_context& context);
    int handle_response_get_objects(int command, NOTIFY_RESPONSE_GET_BLOCKS::request& arg, cryptonote_peer_context& context);
    int handle_request_chain(int command, NOTIFY_REQUEST_CHAIN::request& arg, cryptonote_peer_context& context);
    int handle_response_chain_entry(int command, NOTIFY_RESPONSE_CHAIN_ENTRY::request& arg, cryptonote_peer_context& context);
    int handle_notify_new_fluffy_block(int command, NOTIFY_NEW_FLUFFY_BLOCK::request& arg, cryptonote_peer_context& context);
    int handle_request_fluffy_missing_tx(int command, NOTIFY_REQUEST_FLUFFY_MISSING_TX::request& arg, cryptonote_peer_context& context);
    int handle_notify_get_txpool_complement(int command, NOTIFY_GET_TXPOOL_COMPLEMENT::request& arg, cryptonote_peer_context& context);

    //----------------------------------------------------------------------------------
    //bool get_payload_sync_data(HANDSHAKE_DATA::request& hshd, cryptonote_peer_context& context);
    bool download_next_span(cryptonote_peer_context& context, bool check_having_blocks);
    size_t get_synchronizing_connections_count();
    bool on_connection_synchronized();
    bool should_ask_for_pruned_data(cryptonote_peer_context& context, uint64_t first_block_height, uint64_t nblocks, bool check_block_weights) const;
    void drop_connection(cryptonote_peer_context &context, bool add_fail, bool flush_all_spans);
    void drop_connection_with_score(cryptonote_peer_context &context, unsigned int score, bool flush_all_spans);
    void drop_connections(const epee::net_utils::network_address address);
    bool kick_idle_peers();
    bool check_standby_peers();
    bool update_sync_search();
    int try_add_next_span(cryptonote_peer_context &context);
    void notify_new_stripe(cryptonote_peer_context &context, uint32_t stripe);
    size_t skip_unneeded_hashes(cryptonote_peer_context& context, bool check_block_queue) const;
    bool request_txpool_complement(cryptonote_peer_context &context);
    void hit_score(cryptonote_peer_context &context, int32_t score);

     /**
      * @brief attempts to relay any transactions in the mempool which need it
      *
      * @return true
      */
     bool relay_txpool_transactions();

    template<class MSG>
      bool post_notify(typename MSG::request& arg, cryptonote_peer_context& context)
      {
        MDEBUG("[" << epee::net_utils::print_connection_context_short(context) << "] post " << typeid(MSG).name() << " -->");

        epee::levin::message_writer out{256 * 1024}; // optimize for block responses
        epee::serialization::store_t_to_binary(arg, out.buffer);
        //handler_response_blocks_now(blob.size()); // XXX
        return m_p2p->invoke_notify_to_peer(MSG::ID, std::move(out), context);
      }

private:

    t_core& m_core;

    nodetool::p2p_endpoint_stub<cryptonote_peer_context> m_p2p_stub;

    nodetool::i_p2p_endpoint<cryptonote_peer_context>* m_p2p;

    block_queue m_block_queue;
    
    std::atomic<uint32_t> m_syncronized_connections_count;
    std::atomic<bool> m_synchronized;
    std::atomic<bool> m_stopping;
    std::atomic<bool> m_no_sync;
    std::atomic<bool> m_ask_for_txpool_complement;
    boost::mutex m_sync_lock;


    epee::math_helper::once_a_time_seconds<8> m_idle_peer_kicker;
    epee::math_helper::once_a_time_milliseconds<100> m_standby_checker;
    epee::math_helper::once_a_time_seconds<101> m_sync_search_checker;
    epee::math_helper::once_a_time_seconds<43> m_bad_peer_checker;
    std::atomic<unsigned int> m_max_out_peers;
    tools::PerformanceTimer m_sync_timer, m_add_timer;
    uint64_t m_last_add_end_time;
    uint64_t m_sync_spans_downloaded, m_sync_old_spans_downloaded, m_sync_bad_spans_downloaded;
    uint64_t m_sync_download_chain_size, m_sync_download_objects_size;
    size_t m_block_download_max_size;

    // Values for sync time estimates
    boost::posix_time::ptime m_sync_start_time;
    boost::posix_time::ptime m_period_start_time;
    uint64_t m_sync_start_height;
    uint64_t m_period_start_height;
    uint64_t get_estimated_remaining_sync_seconds(uint64_t current_blockchain_height, uint64_t target_blockchain_height);
    std::string get_periodic_sync_estimate(uint64_t current_blockchain_height, uint64_t target_blockchain_height);

    boost::mutex m_buffer_mutex;
    double get_avg_block_size();
    boost::circular_buffer<size_t> m_avg_buffer = boost::circular_buffer<size_t>(10);

    boost::mutex m_bad_peer_check_lock;


  };

} // namespace

POP_WARNINGS
