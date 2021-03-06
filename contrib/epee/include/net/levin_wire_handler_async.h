// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 

#pragma once
#include <boost/asio/deadline_timer.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/unordered_map.hpp>
#include <boost/interprocess/detail/atomic.hpp>
#include <boost/smart_ptr/make_shared.hpp>

#include <atomic>
#include <deque>

#include "levin_base.h"
#include "buffer.h"
#include "misc_language.h"
#include "syncobj.h"
#include "misc_os_dependent.h"
#include "int-util.h"

#include <random>
#include <chrono>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net"

#ifndef MIN_BYTES_WANTED
#define MIN_BYTES_WANTED	512
#endif

template<typename context_t>
void on_levin_traffic(const context_t &context, bool initiator, bool sent, bool error, size_t bytes, const char* category)
{
  MCINFO("net.p2p.traffic", context << bytes << " bytes " << (sent ? "sent" : "received") << (error ? "/corrupt" : "")
      << " for category " << category << " initiated by " << (initiator ? "us" : "peer"));
}

template<typename context_t>
void on_levin_traffic(const context_t &context, bool initiator, bool sent, bool error, size_t bytes, int command)
{
  char buf[32];
  snprintf(buf, sizeof(buf),  "command-%u", command);
  on_levin_traffic(context, initiator, sent, error, bytes, buf);
}

namespace epee
{
namespace levin
{

/************************************************************************/
/*                                                                      */
/************************************************************************/
template<class t_connection_context>
class async_wire_handler;

#include "levin_wire_async_shared_state.inl"

/************************************************************************/
/*                                                                      */
/************************************************************************/
template<class t_connection_context = net_utils::connection_context_base>
class async_wire_handler
{
public:
  typedef t_connection_context connection_context;
  typedef async_wire_shared_state<t_connection_context> shared_state;
private:
  std::string m_fragment_buffer;

  bool send_message(byte_slice message)
  {
    if (message.size() < sizeof(message_writer::header))
      return false;

    message_writer::header head;
    std::memcpy(std::addressof(head), message.data(), sizeof(head));
    if(!m_pservice_endpoint->do_send(std::move(message)))
      return false;

    on_levin_traffic(m_connection_context, true, true, false, head.m_cb, head.m_command);
    MDEBUG(m_connection_context << "LEVIN_PACKET_SENT. [len=" << head.m_cb
        << ", flags" << head.m_flags
        << ", r?=" << head.m_have_to_return_data
        <<", cmd = " << head.m_command
        << ", ver=" << head.m_protocol_version);
    return true;
  }



#include "anvoke_wrapper.inl"
  
public:
  enum stream_state
  {
    stream_state_head,
    stream_state_body
  };

  std::atomic<bool> m_protocol_released;
  volatile uint32_t m_invoke_buf_ready;

  volatile int m_invoke_result_code;

  critical_section m_local_inv_buff_lock;
  std::string m_local_inv_buff;

  critical_section m_call_lock;

  volatile uint32_t m_wait_count;
  volatile uint32_t m_close_called;
  bucket_head2 m_current_head;
  net_utils::i_service_endpoint* m_pservice_endpoint; 

  shared_state& m_shared_state;

  t_connection_context& m_connection_context;

  std::atomic<uint64_t> m_max_packet_size;

  net_utils::buffer m_cache_in_buffer;
  stream_state m_state;

  int32_t m_oponent_protocol_ver;
  bool m_connection_initialized;

  critical_section m_invoke_response_handlers_lock;
  std::list<boost::shared_ptr<invoke_response_handler_base> > m_invoke_response_handlers;
  
  template<class callback_t>
  bool add_invoke_response_handler(const callback_t &cb, uint64_t timeout,  async_wire_handler& con, int command)
  {
    CRITICAL_REGION_LOCAL(m_invoke_response_handlers_lock);
    if (m_protocol_released)
    {
      MERROR("Adding response handler to a released object");
      return false;
    }
    boost::shared_ptr<invoke_response_handler_base> handler(boost::make_shared<anvoke_handler<callback_t>>(cb, timeout, con, command));
    m_invoke_response_handlers.push_back(handler);
    return handler->is_timer_started();
  }
  template<class callback_t> friend struct anvoke_handler;
public:
  async_wire_handler(net_utils::i_service_endpoint* psnd_hndlr, shared_state& config, t_connection_context& conn_context):m_current_head(bucket_head2()),
            m_pservice_endpoint(psnd_hndlr), 
            m_shared_state(config), 
            m_connection_context(conn_context),
            m_max_packet_size(config.m_initial_max_packet_size),
            m_cache_in_buffer(4 * 1024),
            m_state(stream_state_head)
  {
    m_close_called = 0;
    m_protocol_released = false;
    m_wait_count = 0;
    m_oponent_protocol_ver = 0;
    m_connection_initialized = false;
    m_invoke_buf_ready = 0;
    m_invoke_result_code = LEVIN_ERROR_CONNECTION;
  }
  virtual ~async_wire_handler()
  {
    try
    {

    if(m_connection_initialized)
    {
      m_shared_state.del_connection(this);
    }

    for (size_t i = 0; i < 60 * 1000 / 100 && 0 != boost::interprocess::ipcdetail::atomic_read32(&m_wait_count); ++i)
    {
      misc_utils::sleep_no_w(100);
    }
    CHECK_AND_ASSERT_MES_NO_RET(0 == boost::interprocess::ipcdetail::atomic_read32(&m_wait_count), "Failed to wait for operation completion. m_wait_count = " << m_wait_count);

    MTRACE(m_connection_context << "~async_wire_handler()");

    }
    catch (...) { /* ignore */ }
  }

  bool start_outer_call()
  {
    MTRACE(m_connection_context << "[levin_protocol] -->> start_outer_call");
    if(!m_pservice_endpoint->add_ref())
    {
      MERROR(m_connection_context << "[levin_protocol] -->> start_outer_call failed");
      return false;
    }
    boost::interprocess::ipcdetail::atomic_inc32(&m_wait_count);
    return true;
  }
  bool finish_outer_call()
  {
    MTRACE(m_connection_context << "[levin_protocol] <<-- finish_outer_call");
    boost::interprocess::ipcdetail::atomic_dec32(&m_wait_count);
    m_pservice_endpoint->release();
    return true;
  }

  bool release_protocol()
  {
    decltype(m_invoke_response_handlers) local_invoke_response_handlers;
    CRITICAL_REGION_BEGIN(m_invoke_response_handlers_lock);
    local_invoke_response_handlers.swap(m_invoke_response_handlers);
    m_protocol_released = true;
    CRITICAL_REGION_END();

    // Never call callback inside critical section, that can cause deadlock. Callback can be called when
    // invoke_response_handler_base is cancelled
    std::for_each(local_invoke_response_handlers.begin(), local_invoke_response_handlers.end(), [](const boost::shared_ptr<invoke_response_handler_base>& pinv_resp_hndlr) {
      pinv_resp_hndlr->cancel();
    });

    return true;
  }
  
  bool close()
  {    
    boost::interprocess::ipcdetail::atomic_inc32(&m_close_called);

    m_pservice_endpoint->close();
    return true;
  }

  void update_connection_context(const connection_context& contxt)
  {
    m_connection_context = contxt;
  }

  void request_callback()
  {
    misc_utils::auto_scope_leave_caller scope_exit_handler = misc_utils::create_scope_leave_handler(
      boost::bind(&async_wire_handler::finish_outer_call, this));

    m_pservice_endpoint->request_callback();
  }

  void handle_qued_callback()   
  {
    m_shared_state.m_pcommands_handler->callback(m_connection_context);
  }

  virtual bool handle_recv(const void* ptr, size_t cb)
  {
    if(boost::interprocess::ipcdetail::atomic_read32(&m_close_called))
      return false; //closing connections

    if(!m_shared_state.m_pcommands_handler)
    {
      MERROR(m_connection_context << "Commands handler not set!");
      return false;
    }

    // these should never fail, but do runtime check for safety
    const uint64_t max_packet_size = m_max_packet_size;
    CHECK_AND_ASSERT_MES(max_packet_size >= m_cache_in_buffer.size(), false, "Bad m_cache_in_buffer.size()");
    CHECK_AND_ASSERT_MES(max_packet_size - m_cache_in_buffer.size() >= m_fragment_buffer.size(), false, "Bad m_cache_in_buffer.size() + m_fragment_buffer.size()");

    // flipped to subtraction; prevent overflow since m_max_packet_size is variable and public
    if(cb > max_packet_size - m_cache_in_buffer.size() - m_fragment_buffer.size())
    {
      MWARNING(m_connection_context << "Maximum packet size exceed!, m_max_packet_size = " << max_packet_size
                          << ", packet received " << m_cache_in_buffer.size() +  cb 
                          << ", connection will be closed.");
      return false;
    }

    m_cache_in_buffer.append((const char*)ptr, cb);

    bool is_continue = true;
    while(is_continue)
    {
      switch(m_state)
      {
      case stream_state_body:
        if(m_cache_in_buffer.size() < m_current_head.m_cb)
        {
          is_continue = false;
          if(cb >= MIN_BYTES_WANTED)
          {
            CRITICAL_REGION_LOCAL(m_invoke_response_handlers_lock);
            if (!m_invoke_response_handlers.empty())
            {
              //async call scenario
              boost::shared_ptr<invoke_response_handler_base> response_handler = m_invoke_response_handlers.front();
              response_handler->reset_timer();
              MDEBUG(m_connection_context << "LEVIN_PACKET partial msg received. len=" << cb << ", current total " << m_cache_in_buffer.size() << "/" << m_current_head.m_cb << " (" << (100.0f * m_cache_in_buffer.size() / (m_current_head.m_cb ? m_current_head.m_cb : 1)) << "%)");
            }
          }
          break;
        }

        {
          std::string temp{};
          epee::span<const uint8_t> buff_to_invoke = m_cache_in_buffer.carve((std::string::size_type)m_current_head.m_cb);
          m_state = stream_state_head;

          // abstract_tcp_server2.h manages max bandwidth for a p2p link
          if (!(m_current_head.m_flags & (LEVIN_PACKET_REQUEST | LEVIN_PACKET_RESPONSE)))
          {
            // special noise/fragment command
            static constexpr const uint32_t both_flags = (LEVIN_PACKET_BEGIN | LEVIN_PACKET_END);
            if ((m_current_head.m_flags & both_flags) == both_flags)
              break; // noise message, skip to next message

            if (m_current_head.m_flags & LEVIN_PACKET_BEGIN)
              m_fragment_buffer.clear();

            m_fragment_buffer.append(reinterpret_cast<const char*>(buff_to_invoke.data()), buff_to_invoke.size());
            if (!(m_current_head.m_flags & LEVIN_PACKET_END))
              break; // skip to next message

            if (m_fragment_buffer.size() < sizeof(bucket_head2))
            {
              MERROR(m_connection_context << "Fragmented data too small for levin header");
              return false;
            }

            temp = std::move(m_fragment_buffer);
            m_fragment_buffer.clear();
            std::memcpy(std::addressof(m_current_head), std::addressof(temp[0]), sizeof(bucket_head2));
            const size_t max_bytes = m_connection_context.get_max_bytes(m_current_head.m_command);
            if(m_current_head.m_cb > std::min<size_t>(max_packet_size, max_bytes))
            {
              MERROR(m_connection_context << "Maximum packet size exceed!, m_max_packet_size = " << std::min<size_t>(max_packet_size, max_bytes)
                << ", packet header received " << m_current_head.m_cb << ", command " << m_current_head.m_command
                << ", connection will be closed.");
              return false;
            }
            buff_to_invoke = {reinterpret_cast<const uint8_t*>(temp.data()) + sizeof(bucket_head2), temp.size() - sizeof(bucket_head2)};
          }

          bool is_response = (m_oponent_protocol_ver == LEVIN_PROTOCOL_VER_1 && m_current_head.m_flags&LEVIN_PACKET_RESPONSE);

          MDEBUG(m_connection_context << "LEVIN_PACKET_RECEIVED. [len=" << m_current_head.m_cb<< ", flags" << m_current_head.m_flags << ", r?=" << m_current_head.m_have_to_return_data <<", cmd = " << m_current_head.m_command << ", v=" << m_current_head.m_protocol_version);

          if(is_response)
          {//response to some invoke 

            epee::critical_region_t<decltype(m_invoke_response_handlers_lock)> invoke_response_handlers_guard(m_invoke_response_handlers_lock);
            if(!m_invoke_response_handlers.empty())
            {//async call scenario
              auto response_handler = m_invoke_response_handlers.front();
              bool timer_cancelled = response_handler->cancel_timer();
               // Don't pop handler, to avoid destroying it
              if(timer_cancelled)
                m_invoke_response_handlers.pop_front();
              invoke_response_handlers_guard.unlock();

              if(timer_cancelled)
                response_handler->handle(m_current_head.m_return_code, buff_to_invoke, m_connection_context);
            }
            else
            {
              invoke_response_handlers_guard.unlock();
              //use sync call scenario
              if(!boost::interprocess::ipcdetail::atomic_read32(&m_wait_count) && !boost::interprocess::ipcdetail::atomic_read32(&m_close_called))
              {
                MERROR(m_connection_context << "no active invoke when response came, wtf?");
                return false;
              }else
              {
                CRITICAL_REGION_BEGIN(m_local_inv_buff_lock);
                m_local_inv_buff = std::string((const char*)buff_to_invoke.data(), buff_to_invoke.size());
                buff_to_invoke = epee::span<const uint8_t>((const uint8_t*)NULL, 0);
                m_invoke_result_code = m_current_head.m_return_code;
                CRITICAL_REGION_END();
                boost::interprocess::ipcdetail::atomic_write32(&m_invoke_buf_ready, 1);
              }
            }
          }else
          {
            if(m_current_head.m_have_to_return_data)
            {
              levin::message_writer return_message{32 * 1024};
              const uint32_t return_code = m_shared_state.m_pcommands_handler->invoke(m_current_head.m_command, buff_to_invoke, return_message.buffer, m_connection_context
              );

              // peer_id remains unset if dropped
              if (m_current_head.m_command == m_connection_context.handshake_command() && m_connection_context.handshake_complete())
                m_max_packet_size = m_shared_state.m_max_packet_size;

              if(!send_message(return_message.finalize_response(m_current_head.m_command, return_code)))
                return false;
            }
            else
              m_shared_state.m_pcommands_handler->notify(m_current_head.m_command, buff_to_invoke, m_connection_context);
          }
          // reuse small buffer
          if (!temp.empty() && temp.capacity() <= 64 * 1024)
          {
            temp.clear();
            m_fragment_buffer = std::move(temp);
          }
        }
        break;
      case stream_state_head:
        {
          if(m_cache_in_buffer.size() < sizeof(bucket_head2))
          {
            if(m_cache_in_buffer.size() >= sizeof(uint64_t) && *((uint64_t*)m_cache_in_buffer.span(8).data()) != SWAP64LE(LEVIN_SIGNATURE))
            {
              MWARNING(m_connection_context << "Signature mismatch, connection will be closed");
              return false;
            }
            is_continue = false;
            break;
          }

#if BYTE_ORDER == LITTLE_ENDIAN
          bucket_head2& phead = *(bucket_head2*)m_cache_in_buffer.span(sizeof(bucket_head2)).data();
#else
          bucket_head2 phead = *(bucket_head2*)m_cache_in_buffer.span(sizeof(bucket_head2)).data();
          phead.m_signature = SWAP64LE(phead.m_signature);
          phead.m_cb = SWAP64LE(phead.m_cb);
          phead.m_command = SWAP32LE(phead.m_command);
          phead.m_return_code = SWAP32LE(phead.m_return_code);
          phead.m_flags = SWAP32LE(phead.m_flags);
          phead.m_protocol_version = SWAP32LE(phead.m_protocol_version);
#endif
          if(LEVIN_SIGNATURE != phead.m_signature)
          {
            LOG_ERROR_CC(m_connection_context, "Signature mismatch, connection will be closed");
            return false;
          }
          m_current_head = phead;

          m_cache_in_buffer.erase(sizeof(bucket_head2));
          m_state = stream_state_body;
          m_oponent_protocol_ver = m_current_head.m_protocol_version;
          const size_t max_bytes = m_connection_context.get_max_bytes(m_current_head.m_command);
          if(m_current_head.m_cb > std::min<size_t>(max_packet_size, max_bytes))
          {
            LOG_ERROR_CC(m_connection_context, "Maximum packet size exceed!, m_max_packet_size = " << std::min<size_t>(max_packet_size, max_bytes)
              << ", packet header received " << m_current_head.m_cb << ", command " << m_current_head.m_command
              << ", connection will be closed.");
            return false;
          }
        }
        break;
      default:
        LOG_ERROR_CC(m_connection_context, "Undefined state in levin_server_impl::connection_handler, m_state=" << m_state);
        return false;
      }
    }

    return true;
  }

  bool after_init_connection()
  {
    if (!m_connection_initialized)
    {
      m_connection_initialized = true;
      m_shared_state.add_connection(this);
    }
    return true;
  }

  template<class callback_t>
  bool async_invoke(int command, message_writer in_msg, const callback_t &cb, size_t timeout = LEVIN_DEFAULT_TIMEOUT_PRECONFIGURED)
  {
    misc_utils::auto_scope_leave_caller scope_exit_handler = misc_utils::create_scope_leave_handler(
      boost::bind(&async_wire_handler::finish_outer_call, this));

    if(timeout == LEVIN_DEFAULT_TIMEOUT_PRECONFIGURED)
      timeout = m_shared_state.m_invoke_timeout;

    int err_code = LEVIN_OK;
    do
    {
      CRITICAL_REGION_LOCAL(m_call_lock);

      boost::interprocess::ipcdetail::atomic_write32(&m_invoke_buf_ready, 0);
      CRITICAL_REGION_BEGIN(m_invoke_response_handlers_lock);

      if (command == m_connection_context.handshake_command())
        m_max_packet_size = m_shared_state.m_max_packet_size;

      if(!send_message(in_msg.finalize_invoke(command)))
      {
        LOG_ERROR_CC(m_connection_context, "Failed to do_send");
        err_code = LEVIN_ERROR_CONNECTION;
        break;
      }

      if(!add_invoke_response_handler(cb, timeout, *this, command))
      {
        err_code = LEVIN_ERROR_CONNECTION_DESTROYED;
        break;
      }
      CRITICAL_REGION_END();
    } while (false);

    if (LEVIN_OK != err_code)
    {
      epee::span<const uint8_t> stub_buff = nullptr;
      // Never call callback inside critical section, that can cause deadlock
      cb(err_code, stub_buff, m_connection_context);
      return false;
    }

    return true;
  }

  int invoke(int command, message_writer in_msg, std::string& buff_out)
  {
    misc_utils::auto_scope_leave_caller scope_exit_handler = misc_utils::create_scope_leave_handler(
                                      boost::bind(&async_wire_handler::finish_outer_call, this));

    CRITICAL_REGION_LOCAL(m_call_lock);

    boost::interprocess::ipcdetail::atomic_write32(&m_invoke_buf_ready, 0);

    if (command == m_connection_context.handshake_command())
      m_max_packet_size = m_shared_state.m_max_packet_size;

    if (!send_message(in_msg.finalize_invoke(command)))
    {
      LOG_ERROR_CC(m_connection_context, "Failed to send request");
      return LEVIN_ERROR_CONNECTION;
    }

    uint64_t ticks_start = misc_utils::get_tick_count();
    size_t prev_size = 0;

    while(!boost::interprocess::ipcdetail::atomic_read32(&m_invoke_buf_ready) && !m_protocol_released)
    {
      if(m_cache_in_buffer.size() - prev_size >= MIN_BYTES_WANTED)
      {
        prev_size = m_cache_in_buffer.size();
        ticks_start = misc_utils::get_tick_count();
      }
      if(misc_utils::get_tick_count() - ticks_start > m_shared_state.m_invoke_timeout)
      {
        MWARNING(m_connection_context << "invoke timeout (" << m_shared_state.m_invoke_timeout << "), closing connection ");
        close();
        return LEVIN_ERROR_CONNECTION_TIMEDOUT;
      }
      if(!m_pservice_endpoint->call_run_once_service_io())
        return LEVIN_ERROR_CONNECTION_DESTROYED;
    }

    if(m_protocol_released)
      return LEVIN_ERROR_CONNECTION_DESTROYED;

    CRITICAL_REGION_BEGIN(m_local_inv_buff_lock);
    buff_out.swap(m_local_inv_buff);
    m_local_inv_buff.clear();
    CRITICAL_REGION_END();

    return m_invoke_result_code;
  }

  /*! Sends `message` without adding a levin header. The message must have been
      created with `make_noise_notify`, `make_fragmented_notify`, or
      `message_writer::finalize_notify`. See additional instructions for
      `make_fragmented_notify`.

      \return 1 on success */
  int send(byte_slice message)
  {
    const misc_utils::auto_scope_leave_caller scope_exit_handler = misc_utils::create_scope_leave_handler(
      boost::bind(&async_wire_handler::finish_outer_call, this)
    );

    if (!send_message(std::move(message)))
    {
      LOG_ERROR_CC(m_connection_context, "Failed to send message, dropping it");
      return -1;
    }
    return 1;
  }
  //------------------------------------------------------------------------------------------
  boost::uuids::uuid get_connection_id() {return m_connection_context.m_connection_id;}
  //------------------------------------------------------------------------------------------
  t_connection_context& get_context_ref() {return m_connection_context;}
};

#include "levin_wire_async_shared_state_impl.inl"
}
}
