/**
@file
@author from CrypoNote (see copyright below; Andrey N. Sabelnikov)
@monero rfree
@brief the connection templated-class for one peer connection
*/
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



#ifndef _ABSTRACT_TCP_SERVER2_H_ 
#define _ABSTRACT_TCP_SERVER2_H_ 


#include <string>
#include <vector>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <atomic>
#include <cassert>
#include <map>
#include <memory>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/array.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/interprocess/detail/atomic.hpp>
#include <boost/thread/thread.hpp>
#include "byte_slice.h"
#include "net_utils_base.h"
#include "syncobj.h"
#include "connection_basic.hpp"
#include "network_throttle-detail.hpp"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net"

#define ABSTRACT_SERVER_SEND_QUE_MAX_COUNT 1000

#include "connection.inl"
namespace epee
{
namespace net_utils
{

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  template<class t_wire_handler>
  class boosted_tcp_server    : private boost::noncopyable
  {
    enum try_connect_result_t
    {
      CONNECT_SUCCESS,
      CONNECT_FAILURE,
      CONNECT_NO_SSL,
    };

  public:
    typedef boosted_tcp_server<t_wire_handler> MyType;
    typedef connection<t_wire_handler> ConnectionType;
    typedef boost::shared_ptr<connection<t_wire_handler> > connection_ptr;
    typedef typename t_wire_handler::connection_context t_connection_context;
    /// Construct the server to listen on the specified TCP address and port, and
    /// serve up files from the given directory.

    boosted_tcp_server(t_connection_type connection_type);
    explicit boosted_tcp_server(boost::asio::io_service& external_io_service, t_connection_type connection_type);
    ~boosted_tcp_server();
    
    std::map<std::string, t_connection_type> server_type_map;
    void create_server_type_map();

    bool init_server(uint32_t port, const std::string& address = "0.0.0.0",
	uint32_t port_ipv6 = 0, const std::string& address_ipv6 = "::", bool use_ipv6 = false, bool require_ipv4 = true,
	ssl_options_t ssl_options = ssl_support_t::e_ssl_support_autodetect);
    bool init_server(const std::string port,  const std::string& address = "0.0.0.0",
	const std::string port_ipv6 = "", const std::string address_ipv6 = "::", bool use_ipv6 = false, bool require_ipv4 = true,
	ssl_options_t ssl_options = ssl_support_t::e_ssl_support_autodetect);

    /// Run the server's io_service loop.
    bool run_server(size_t threads_count, bool wait = true, const boost::thread::attributes& attrs = boost::thread::attributes());

    /// wait for service workers stop
    bool timed_wait_server_stop(uint64_t wait_mseconds);

    /// Stop the server.
    void send_stop_signal();

    bool is_stop_signal_sent() const noexcept { return m_stop_signal_sent; };

    const std::atomic<bool>& get_stop_signal() const noexcept { return m_stop_signal_sent; }

    void set_threads_prefix(const std::string& prefix_name);

    bool deinit_server(){return true;}

    size_t get_threads_count(){return m_threads_count;}

    void set_connection_filter(i_connection_filter* pfilter);


    bool add_connection(t_connection_context& out, boost::asio::ip::tcp::socket&& sock, network_address real_remote, epee::net_utils::ssl_support_t ssl_support = epee::net_utils::ssl_support_t::e_ssl_support_autodetect);
    try_connect_result_t try_connect(connection_ptr new_connection_l, const std::string& adr, const std::string& port, boost::asio::ip::tcp::socket &sock_, const boost::asio::ip::tcp::endpoint &remote_endpoint, const std::string &bind_ip, uint32_t conn_timeout, epee::net_utils::ssl_support_t ssl_support);
    bool connect(const std::string& adr, const std::string& port, uint32_t conn_timeot, t_connection_context& cn, const std::string& bind_ip = "0.0.0.0", epee::net_utils::ssl_support_t ssl_support = epee::net_utils::ssl_support_t::e_ssl_support_autodetect);
    template<class t_callback>
    bool connect_async(const std::string& adr, const std::string& port, uint32_t conn_timeot, const t_callback &cb, const std::string& bind_ip = "0.0.0.0", epee::net_utils::ssl_support_t ssl_support = epee::net_utils::ssl_support_t::e_ssl_support_autodetect);

    boost::asio::ssl::context& get_ssl_context() noexcept
    {
      assert(m_shared_state != nullptr);
      return m_shared_state->ssl_context;
    }

    typename t_wire_handler::shared_state& get_shared_state()
    {
      assert(m_shared_state != nullptr); // always set in constructor
      return *m_shared_state;
    }

    std::shared_ptr<typename t_wire_handler::shared_state> get_config_shared()
    {
      assert(m_shared_state != nullptr); // always set in constructor
      return {m_shared_state};
    }

    int get_binded_port(){return m_port;}
    int get_binded_port_ipv6(){return m_port_ipv6;}

    long get_connections_count() const
    {
      assert(m_shared_state != nullptr); // always set in constructor
      auto connections_count = m_shared_state->sock_count > 0 ? (m_shared_state->sock_count - 1) : 0; // Socket count minus listening socket
      return connections_count;
    }

    boost::asio::io_service& get_io_service(){return io_service_;}

    struct idle_callback_conext_base
    {
      virtual ~idle_callback_conext_base(){}

      virtual bool call_handler(){return true;}

      idle_callback_conext_base(boost::asio::io_service& io_serice):
                                                          m_timer(io_serice)
      {}
      boost::asio::deadline_timer m_timer;
    };

    template <class t_handler>
    struct idle_callback_conext: public idle_callback_conext_base
    {
      idle_callback_conext(boost::asio::io_service& io_serice, t_handler& h, uint64_t period):
                                                    idle_callback_conext_base(io_serice),
                                                    m_handler(h)
      {this->m_period = period;}

      t_handler m_handler;
      virtual bool call_handler()
      {
        return m_handler();
      }
      uint64_t m_period;
    };

    template<class t_handler>
    bool add_idle_handler(t_handler t_callback, uint64_t timeout_ms)
      {
        boost::shared_ptr<idle_callback_conext<t_handler>> ptr(new idle_callback_conext<t_handler>(io_service_, t_callback, timeout_ms));
        //needed call handler here ?...
        ptr->m_timer.expires_from_now(boost::posix_time::milliseconds(ptr->m_period));
        ptr->m_timer.async_wait(boost::bind(&MyType::global_timer_handler<t_handler>, this, ptr));
        return true;
      }

    template<class t_handler>
    bool global_timer_handler(/*const boost::system::error_code& err, */boost::shared_ptr<idle_callback_conext<t_handler>> ptr)
    {
      //if handler return false - he don't want to be called anymore
      if(!ptr->call_handler())
        return true;
      ptr->m_timer.expires_from_now(boost::posix_time::milliseconds(ptr->m_period));
      ptr->m_timer.async_wait(boost::bind(&MyType::global_timer_handler<t_handler>, this, ptr));
      return true;
    }

    template<class t_handler>
    bool async_call(t_handler t_callback)
    {
      io_service_.post(t_callback);
      return true;
    }

  private:
    /// Run the server's io_service loop.
    bool worker_thread();
    /// Handle completion of an asynchronous accept operation.
    void handle_accept_ipv4(const boost::system::error_code& e);
    void handle_accept_ipv6(const boost::system::error_code& e);
    void handle_accept(const boost::system::error_code& e, bool ipv6 = false);

    bool is_thread_worker();

    const std::shared_ptr<typename connection<t_wire_handler>::shared_state> m_shared_state;

    /// The io_service used to perform asynchronous operations.
    struct worker
    {
      worker()
        : io_service(), work(io_service)
      {}

      boost::asio::io_service io_service;
      boost::asio::io_service::work work;
    };
    std::unique_ptr<worker> m_io_service_local_instance;
    boost::asio::io_service& io_service_;    

    /// Acceptor used to listen for incoming connections.
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ip::tcp::acceptor acceptor_ipv6;

    std::atomic<bool> m_stop_signal_sent;
    uint32_t m_port;
    uint32_t m_port_ipv6;
    std::string m_address;
    std::string m_address_ipv6;
    bool m_use_ipv6;
    bool m_require_ipv4;
    std::string m_thread_name_prefix; //TODO: change to enum server_type, now used
    size_t m_threads_count;
    std::vector<boost::shared_ptr<boost::thread> > m_threads;
    boost::thread::id m_main_thread_id;
    critical_section m_threads_lock;
    volatile uint32_t m_thread_index; // TODO change to std::atomic

    t_connection_type m_connection_type;

    /// The next connection to be accepted
    connection_ptr new_connection_;
    connection_ptr new_connection_ipv6;


    boost::mutex connections_mutex;
    std::set<connection_ptr> connections_;
  }; // class <>boosted_tcp_server


} // namespace
} // namespace

#include "abstract_tcp_server2.inl"

#endif
