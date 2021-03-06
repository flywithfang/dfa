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



#include <boost/foreach.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/chrono.hpp>
#include <boost/utility/value_init.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time.hpp> // TODO
#include <boost/thread/condition_variable.hpp> // TODO
#include <boost/make_shared.hpp>
#include <boost/thread.hpp>
#include "warnings.h"
#include "string_tools_lexical.h"
#include "misc_language.h"
#include "net/local_ip.h"
#include "pragma_comp_defs.h"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <random>
#include "common/stack_trace.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net"

#define AGGRESSIVE_TIMEOUT_THRESHOLD 120 // sockets
#define NEW_CONNECTION_TIMEOUT_LOCAL 1200000 // 2 minutes
#define NEW_CONNECTION_TIMEOUT_REMOTE 10000 // 10 seconds
#define DEFAULT_TIMEOUT_MS_LOCAL 1800000 // 30 minutes
#define DEFAULT_TIMEOUT_MS_REMOTE 300000 // 5 minutes
#define TIMEOUT_EXTRA_MS_PER_BYTE 0.2


#include "connection_impl.inl"

PRAGMA_WARNING_PUSH
namespace epee
{
namespace net_utils
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/

  template<class t_wire_handler>
  boosted_tcp_server<t_wire_handler>::boosted_tcp_server( t_connection_type connection_type ) :
    m_shared_state(std::make_shared<typename connection<t_wire_handler>::shared_state>()),
    m_io_service_local_instance(new worker()),
    io_service_(m_io_service_local_instance->io_service),
    acceptor_(io_service_),
    acceptor_ipv6(io_service_),
    m_stop_signal_sent(false), m_port(0), 
    m_threads_count(0),
    m_thread_index(0),
		m_connection_type( connection_type ),
    new_connection_(),
    new_connection_ipv6()
  {
    create_server_type_map();
    m_thread_name_prefix = "NET";
  }

  template<class t_wire_handler>
  boosted_tcp_server<t_wire_handler>::boosted_tcp_server(boost::asio::io_service& extarnal_io_service, t_connection_type connection_type) :
    m_shared_state(std::make_shared<typename connection<t_wire_handler>::shared_state>()),
    io_service_(extarnal_io_service),
    acceptor_(io_service_),
    acceptor_ipv6(io_service_),
    m_stop_signal_sent(false), m_port(0),
    m_threads_count(0),
    m_thread_index(0),
		m_connection_type(connection_type),
    new_connection_(),
    new_connection_ipv6()
  {
    create_server_type_map();
    m_thread_name_prefix = "NET";
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  boosted_tcp_server<t_wire_handler>::~boosted_tcp_server()
  {
    this->send_stop_signal();
    timed_wait_server_stop(10000);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void boosted_tcp_server<t_wire_handler>::create_server_type_map() 
  {
		server_type_map["NET"] = e_connection_type_NET;
		server_type_map["RPC"] = e_connection_type_RPC;
		server_type_map["P2P"] = e_connection_type_P2P;
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
    bool boosted_tcp_server<t_wire_handler>::init_server(uint32_t port,  const std::string& address,
	uint32_t port_ipv6, const std::string& address_ipv6, bool use_ipv6, bool require_ipv4,
	ssl_options_t ssl_options)
  {
    TRY_ENTRY();
    m_stop_signal_sent = false;
    m_port = port;
    m_port_ipv6 = port_ipv6;
    m_address = address;
    m_address_ipv6 = address_ipv6;
    m_use_ipv6 = use_ipv6;
    m_require_ipv4 = require_ipv4;

    if (ssl_options)
      m_shared_state->configure_ssl(std::move(ssl_options));

    std::string ipv4_failed = "";
    std::string ipv6_failed = "";
    try
    {
      boost::asio::ip::tcp::resolver resolver(io_service_);
      boost::asio::ip::tcp::resolver::query query(address, boost::lexical_cast<std::string>(port), boost::asio::ip::tcp::resolver::query::canonical_name);
      boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);
      acceptor_.open(endpoint.protocol());
#if !defined(_WIN32)
      acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
#endif
      acceptor_.bind(endpoint);
      acceptor_.listen();
      boost::asio::ip::tcp::endpoint binded_endpoint = acceptor_.local_endpoint();
      m_port = binded_endpoint.port();
      MINFO("start accept (IPv4) "<<address<<":"<<port);

      new_connection_.reset(new connection<t_wire_handler>(io_service_, m_shared_state, m_connection_type, m_shared_state->ssl_options().support));
      
      acceptor_.async_accept(new_connection_->socket(),	boost::bind(&MyType::handle_accept_ipv4, this,boost::asio::placeholders::error));
    }
    catch (const std::exception &e)
    {
      ipv4_failed = e.what();
    }

    if (ipv4_failed != "")
    {
      MERROR("Failed to bind IPv4: " << ipv4_failed);
      if (require_ipv4)
      {
        throw std::runtime_error("Failed to bind IPv4 (set to required)");
      }
    }

    if (use_ipv6)
    {
      try
      {
        if (port_ipv6 == 0) port_ipv6 = port; // default arg means bind to same port as ipv4
        boost::asio::ip::tcp::resolver resolver(io_service_);
        boost::asio::ip::tcp::resolver::query query(address_ipv6, boost::lexical_cast<std::string>(port_ipv6), boost::asio::ip::tcp::resolver::query::canonical_name);
        boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);
        acceptor_ipv6.open(endpoint.protocol());
#if !defined(_WIN32)
        acceptor_ipv6.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
#endif
        acceptor_ipv6.set_option(boost::asio::ip::v6_only(true));
        acceptor_ipv6.bind(endpoint);
        acceptor_ipv6.listen();
        boost::asio::ip::tcp::endpoint binded_endpoint = acceptor_ipv6.local_endpoint();
        m_port_ipv6 = binded_endpoint.port();
        MDEBUG("start accept (IPv6)");
        new_connection_ipv6.reset(new connection<t_wire_handler>(io_service_, m_shared_state, m_connection_type, m_shared_state->ssl_options().support));
        
        acceptor_ipv6.async_accept(new_connection_ipv6->socket(),boost::bind(&boosted_tcp_server<t_wire_handler>::handle_accept_ipv6, this,boost::asio::placeholders::error));
      }
      catch (const std::exception &e)
      {
        ipv6_failed = e.what();
      }
    }

      if (use_ipv6 && ipv6_failed != "")
      {
        MERROR("Failed to bind IPv6: " << ipv6_failed);
        if (ipv4_failed != "")
        {
          throw std::runtime_error("Failed to bind IPv4 and IPv6");
        }
      }

    return true;
    }
    catch (const std::exception &e)
    {
      MFATAL("Error starting server: " << e.what());
      return false;
    }
    catch (...)
    {
      MFATAL("Error starting server");
      return false;
    }
  }
  //-----------------------------------------------------------------------------
PUSH_WARNINGS
DISABLE_GCC_WARNING(maybe-uninitialized)
  template<class t_wire_handler>
  bool boosted_tcp_server<t_wire_handler>::init_server(const std::string port,  const std::string& address,
      const std::string port_ipv6, const std::string address_ipv6, bool use_ipv6, bool require_ipv4,
      ssl_options_t ssl_options)
  {
    uint32_t p = 0;
    uint32_t p_ipv6 = 0;

    if (port.size() && !string_tools::get_xtype_from_string(p, port)) {
      MERROR("Failed to convert port no = " << port);
      return false;
    }

    if (port_ipv6.size() && !string_tools::get_xtype_from_string(p_ipv6, port_ipv6)) {
      MERROR("Failed to convert port no = " << port_ipv6);
      return false;
    }
    return this->init_server(p, address, p_ipv6, address_ipv6, use_ipv6, require_ipv4, std::move(ssl_options));
  }
POP_WARNINGS
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool boosted_tcp_server<t_wire_handler>::worker_thread()
  {
    TRY_ENTRY();
    uint32_t local_thr_index = boost::interprocess::ipcdetail::atomic_inc32(&m_thread_index); 
    std::string thread_name = std::string("[") + m_thread_name_prefix;
    thread_name += boost::to_string(local_thr_index) + "]";
    MLOG_SET_THREAD_NAME(thread_name);
    MINFO("Thread name: " << m_thread_name_prefix<<" run");
    while(!m_stop_signal_sent)
    {
      try
      {
        io_service_.run();
        return true;
      }
      catch(const std::exception& ex)
      {
        _erro("Exception at server worker thread, what=" << ex.what());
      }
      catch(...)
      {
        _erro("Exception at server worker thread, unknown execption");
      }
    }
    //_info("Worker thread finished");
    return true;
    CATCH_ENTRY_L0("boosted_tcp_server<t_wire_handler>::worker_thread", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void boosted_tcp_server<t_wire_handler>::set_threads_prefix(const std::string& prefix_name)
  {
    m_thread_name_prefix = prefix_name;
		auto it = server_type_map.find(m_thread_name_prefix);
		if (it==server_type_map.end()) throw std::runtime_error("Unknown prefix/server type:" + std::string(prefix_name));
    auto connection_type = it->second; // the value of type
    MINFO("Set server type to: " << connection_type << " from name: " << m_thread_name_prefix << ", prefix_name = " << prefix_name);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void boosted_tcp_server<t_wire_handler>::set_connection_filter(i_connection_filter* pfilter)
  {
    assert(m_shared_state != nullptr); // always set in constructor
    m_shared_state->pfilter = pfilter;
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool boosted_tcp_server<t_wire_handler>::run_server(size_t threads_count, bool wait, const boost::thread::attributes& attrs)
  {
    TRY_ENTRY();
    m_threads_count = threads_count;
    m_main_thread_id = boost::this_thread::get_id();
    MLOG_SET_THREAD_NAME("[SRV_MAIN]");
    while(!m_stop_signal_sent)
    {

      // Create a pool of threads to run all of the io_services.
      CRITICAL_REGION_BEGIN(m_threads_lock);
      for (std::size_t i = 0; i < threads_count; ++i)
      {
        boost::shared_ptr<boost::thread> thread(new boost::thread(
          attrs, boost::bind(&MyType::worker_thread, this)));

        MINFO("Run server thread name: " << m_thread_name_prefix <<" "<<i);
        m_threads.push_back(thread);
      }
      CRITICAL_REGION_END();
      // Wait for all threads in the pool to exit.
      if (wait)
      {
		    MINFO("JOINING all threads");
        for (std::size_t i = 0; i < m_threads.size(); ++i) {
			   m_threads[i]->join();
         }
         MINFO("JOINING all threads - almost");
        m_threads.clear();
        MINFO("JOINING all threads - DONE");

      } 
      else {
		    MINFO("Reiniting OK.");
        return true;
      }

      if(wait && !m_stop_signal_sent)
      {
        //some problems with the listening socket ?..
        _dbg1("Net service stopped without stop request, restarting...");
        if(!this->init_server(m_port, m_address, m_port_ipv6, m_address_ipv6, m_use_ipv6, m_require_ipv4))
        {
          _dbg1("Reiniting service failed, exit.");
          return false;
        }else
        {
          _dbg1("Reiniting OK.");
        }
      }
    }
    return true;
    CATCH_ENTRY_L0("boosted_tcp_server<t_wire_handler>::run_server", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool boosted_tcp_server<t_wire_handler>::is_thread_worker()
  {
    TRY_ENTRY();
    CRITICAL_REGION_LOCAL(m_threads_lock);
    BOOST_FOREACH(boost::shared_ptr<boost::thread>& thp,  m_threads)
    {
      if(thp->get_id() == boost::this_thread::get_id())
        return true;
    }
    if(m_threads_count == 1 && boost::this_thread::get_id() == m_main_thread_id)
      return true;
    return false;
    CATCH_ENTRY_L0("boosted_tcp_server<t_wire_handler>::is_thread_worker", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool boosted_tcp_server<t_wire_handler>::timed_wait_server_stop(uint64_t wait_mseconds)
  {
    TRY_ENTRY();
    boost::chrono::milliseconds ms(wait_mseconds);
    for (std::size_t i = 0; i < m_threads.size(); ++i)
    {
      if(m_threads[i]->joinable() && !m_threads[i]->try_join_for(ms))
      {
        _dbg1("Interrupting thread " << m_threads[i]->native_handle());
        m_threads[i]->interrupt();
      }
    }
    return true;
    CATCH_ENTRY_L0("boosted_tcp_server<t_wire_handler>::timed_wait_server_stop", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void boosted_tcp_server<t_wire_handler>::send_stop_signal()
  {
    m_stop_signal_sent = true;
    auto *state = static_cast<typename connection<t_wire_handler>::shared_state*>(m_shared_state.get());
    state->stop_signal_sent = true;
    TRY_ENTRY();
    connections_mutex.lock();
    for (auto &c: connections_)
    {
      c->cancel();
    }
    connections_.clear();
    connections_mutex.unlock();
    io_service_.stop();
    CATCH_ENTRY_L0("boosted_tcp_server<t_wire_handler>::send_stop_signal()", void());
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void boosted_tcp_server<t_wire_handler>::handle_accept_ipv4(const boost::system::error_code& e)
  {
    this->handle_accept(e, false);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void boosted_tcp_server<t_wire_handler>::handle_accept_ipv6(const boost::system::error_code& e)
  {
    this->handle_accept(e, true);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void boosted_tcp_server<t_wire_handler>::handle_accept(const boost::system::error_code& e, bool ipv6)
  {
    MINFO("handle_accept");

    boost::asio::ip::tcp::acceptor* current_acceptor = &acceptor_;
    connection_ptr* current_new_connection = &new_connection_;
    auto accept_function_pointer = &MyType::handle_accept_ipv4;
    if (ipv6)
    {
      current_acceptor = &acceptor_ipv6;
      current_new_connection = &new_connection_ipv6;
      accept_function_pointer = &MyType::handle_accept_ipv6;
    }

    try
    {
    if (!e)
    {
      if (m_connection_type == e_connection_type_RPC) {
        const char *ssl_message = "unknown";
        switch ((*current_new_connection)->get_ssl_support())
        {
          case epee::net_utils::ssl_support_t::e_ssl_support_disabled: ssl_message = "disabled"; break;
          case epee::net_utils::ssl_support_t::e_ssl_support_enabled: ssl_message = "enabled"; break;
          case epee::net_utils::ssl_support_t::e_ssl_support_autodetect: ssl_message = "autodetection"; break;
        }
        MDEBUG("New server for RPC connections, SSL " << ssl_message);
        (*current_new_connection)->setRpcStation(); // hopefully this is not needed actually
      }
      connection_ptr conn(std::move((*current_new_connection)));

      (*current_new_connection).reset(new connection<t_wire_handler>(io_service_, m_shared_state, m_connection_type, conn->get_ssl_support()));

      current_acceptor->async_accept((*current_new_connection)->socket(),
          boost::bind(accept_function_pointer, this,boost::asio::placeholders::error));

      boost::asio::socket_base::keep_alive opt(true);
      conn->socket().set_option(opt);

      const bool res = conn->start(true, 1 < m_threads_count);
      if (!res)
      {
        conn->cancel();
        return;
      }
      conn->save_dbg_log();
      return;
    }
    else
    {
      MERROR("Error in boosted_tcp_server<t_wire_handler>::handle_accept: " << e);
    }
    }
    catch (const std::exception &e)
    {
      MERROR("Exception in boosted_tcp_server<t_wire_handler>::handle_accept: " << e.what());
    }

    // error path, if e or exception
    assert(m_shared_state != nullptr); // always set in constructor
    _erro("Some problems at accept: " << e.message() << ", connections_count = " << m_shared_state->sock_count);
    misc_utils::sleep_no_w(100);

    (*current_new_connection).reset(new connection<t_wire_handler>(io_service_, m_shared_state, m_connection_type, (*current_new_connection)->get_ssl_support()));

    current_acceptor->async_accept((*current_new_connection)->socket(),boost::bind(accept_function_pointer, this,boost::asio::placeholders::error));
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool boosted_tcp_server<t_wire_handler>::add_connection(t_connection_context& out, boost::asio::ip::tcp::socket&& sock, network_address real_remote, epee::net_utils::ssl_support_t ssl_support)
  {
    if(std::addressof(get_io_service()) == std::addressof(GET_IO_SERVICE(sock)))
    {
      connection_ptr conn(new connection<t_wire_handler>(std::move(sock), m_shared_state, m_connection_type, ssl_support));
      if(conn->start(false, 1 < m_threads_count, std::move(real_remote)))
      {
        conn->get_context(out);
        conn->save_dbg_log();
        return true;
      }
    }
    else
    {
	MWARNING(out << " was not added, socket/io_service mismatch");
    }
    return false;
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  typename boosted_tcp_server<t_wire_handler>::try_connect_result_t boosted_tcp_server<t_wire_handler>::try_connect(connection_ptr new_connection_l, const std::string& adr, const std::string& port, boost::asio::ip::tcp::socket &sock_, const boost::asio::ip::tcp::endpoint &remote_endpoint, const std::string &bind_ip, uint32_t conn_timeout, epee::net_utils::ssl_support_t ssl_support)
  {
    TRY_ENTRY();

 MINFO("try_connect "<<adr<<","<<port<<","<<conn_timeout<<"remote "<<remote_endpoint<<",bind_ip "<<bind_ip<<",ssl "<<std::to_string((uint8_t)ssl_support)<<",connections_ size now " << connections_.size());

    sock_.open(remote_endpoint.protocol());
    if(bind_ip != "0.0.0.0" && bind_ip != "0" && bind_ip != "" )
    {
      boost::asio::ip::tcp::endpoint local_endpoint(boost::asio::ip::address::from_string(bind_ip.c_str()), 0);
      boost::system::error_code ec;
      sock_.bind(local_endpoint, ec);
      if (ec)
      {
        MERROR("Error binding to " << bind_ip << ": " << ec.message());
        if (sock_.is_open())
          sock_.close();
        return CONNECT_FAILURE;
      }
    }

    /*
    NOTICE: be careful to make sync connection from event handler: in case if all threads suddenly do sync connect, there will be no thread to dispatch events from io service.
    */

    boost::system::error_code ec = boost::asio::error::would_block;

    //have another free thread(s), work in wait mode, without event handling
    struct local_async_context
    {
      boost::system::error_code ec;
      boost::mutex connect_mut;
      boost::condition_variable cond;
    };

    boost::shared_ptr<local_async_context> local_shared_context(new local_async_context());
    local_shared_context->ec = boost::asio::error::would_block;
    boost::unique_lock<boost::mutex> lock(local_shared_context->connect_mut);
    auto connect_callback = [](boost::system::error_code ec_, boost::shared_ptr<local_async_context> shared_context)
    {
      shared_context->connect_mut.lock(); 
      shared_context->ec = ec_; 
      shared_context->cond.notify_one(); 
      shared_context->connect_mut.unlock();
    };

    sock_.async_connect(remote_endpoint, std::bind<void>(connect_callback, std::placeholders::_1, local_shared_context));
    while(local_shared_context->ec == boost::asio::error::would_block)
    {
      bool r = local_shared_context->cond.timed_wait(lock, boost::get_system_time() + boost::posix_time::milliseconds(conn_timeout));
      if (m_stop_signal_sent)
      {
        if (sock_.is_open())
          sock_.close();
        return CONNECT_FAILURE;
      }
      if(local_shared_context->ec == boost::asio::error::would_block && !r)
      {
        //timeout
        sock_.close();
        MINFO("Failed to connect to " << adr << ":" << port << ", because of timeout (" << conn_timeout << ")");
        return CONNECT_FAILURE;
      }
    }
    ec = local_shared_context->ec;

    if (ec || !sock_.is_open())
    {
      MINFO("Some problems at connect, message: " << ec.message());
      if (sock_.is_open())
        sock_.close();
      return CONNECT_FAILURE;
    }

    MINFO("Connected success to " << adr << ':' << port);
    tools::log_stack_trace("conn");
    const ssl_support_t ssl_support = new_connection_l->get_ssl_support();
    if (ssl_support == epee::net_utils::ssl_support_t::e_ssl_support_enabled || ssl_support == epee::net_utils::ssl_support_t::e_ssl_support_autodetect)
    {
      // Handshake
      MDEBUG("Handshaking SSL...");
      if (!new_connection_l->handshake(boost::asio::ssl::stream_base::client))
      {
        if (ssl_support == epee::net_utils::ssl_support_t::e_ssl_support_autodetect)
        {
          boost::system::error_code ignored_ec;
          sock_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
          sock_.close();
          return CONNECT_NO_SSL;
        }
        MERROR("SSL handshake failed");
        if (sock_.is_open())
          sock_.close();
        return CONNECT_FAILURE;
      }
    }

    return CONNECT_SUCCESS;

    CATCH_ENTRY_L0("boosted_tcp_server<t_wire_handler>::try_connect", CONNECT_FAILURE);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool boosted_tcp_server<t_wire_handler>::connect(const std::string& adr, const std::string& port, uint32_t conn_timeout, t_connection_context& conn_context, const std::string& bind_ip, epee::net_utils::ssl_support_t ssl_support)
  {


    TRY_ENTRY();

    connection_ptr new_connection_l(new connection<t_wire_handler>(io_service_, m_shared_state, m_connection_type, ssl_support) );
    connections_mutex.lock();
    connections_.insert(new_connection_l);
    MINFO("connect "<<adr<<","<<port<<","<<conn_timeout<<",bind_ip "<<bind_ip<<",ssl "<<std::to_string((uint8_t)ssl_support)<<",connections_ size now " << connections_.size());
    connections_mutex.unlock();
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){ CRITICAL_REGION_LOCAL(connections_mutex); connections_.erase(new_connection_l); });
    boost::asio::ip::tcp::socket&  sock_ = new_connection_l->socket();

    bool try_ipv6 = false;

    boost::asio::ip::tcp::resolver resolver(io_service_);
    boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), adr, port, boost::asio::ip::tcp::resolver::query::canonical_name);
    boost::system::error_code resolve_error;
    boost::asio::ip::tcp::resolver::iterator iterator;
    try
    {
      //resolving ipv4 address as ipv6 throws, catch here and move on
      iterator = resolver.resolve(query, resolve_error);
    }
    catch (const boost::system::system_error& e)
    {
      if (!m_use_ipv6 || (resolve_error != boost::asio::error::host_not_found &&
            resolve_error != boost::asio::error::host_not_found_try_again))
      {
        throw;
      }
      try_ipv6 = true;
    }
    catch (...)
    {
      throw;
    }

    std::string bind_ip_to_use;

    boost::asio::ip::tcp::resolver::iterator end;
    if(iterator == end)
    {
      if (!m_use_ipv6)
      {
        _erro("Failed to resolve " << adr);
        return false;
      }
      else
      {
        try_ipv6 = true;
        MINFO("Resolving address as IPv4 failed, trying IPv6");
      }
    }
    else
    {
      bind_ip_to_use = bind_ip;
    }

    if (try_ipv6)
    {
      boost::asio::ip::tcp::resolver::query query6(boost::asio::ip::tcp::v6(), adr, port, boost::asio::ip::tcp::resolver::query::canonical_name);

      iterator = resolver.resolve(query6, resolve_error);

      if(iterator == end)
      {
        _erro("Failed to resolve " << adr);
        return false;
      }
      else
      {
        if (bind_ip == "0.0.0.0")
        {
          bind_ip_to_use = "::";
        }
        else
        {
          bind_ip_to_use = "";
        }

      }

    }

      MINFO("Trying to connect to " << adr << ":" << port << ", bind_ip = " << bind_ip_to_use);

    //boost::asio::ip::tcp::endpoint remote_endpoint(boost::asio::ip::address::from_string(addr.c_str()), port);
    boost::asio::ip::tcp::endpoint remote_endpoint(*iterator);

    auto try_connect_result = try_connect(new_connection_l, adr, port, sock_, remote_endpoint, bind_ip_to_use, conn_timeout, ssl_support);
    if (try_connect_result == CONNECT_FAILURE)
      return false;
    if (ssl_support == epee::net_utils::ssl_support_t::e_ssl_support_autodetect && try_connect_result == CONNECT_NO_SSL)
    {
      // we connected, but could not connect with SSL, try without
      MERROR("SSL handshake failed on an autodetect connection, reconnecting without SSL");
      new_connection_l->disable_ssl();
      try_connect_result = try_connect(new_connection_l, adr, port, sock_, remote_endpoint, bind_ip_to_use, conn_timeout, epee::net_utils::ssl_support_t::e_ssl_support_disabled);
      if (try_connect_result != CONNECT_SUCCESS)
        return false;
    }

    // start adds the connection to the config object's list, so we don't need to have it locally anymore
    connections_mutex.lock();
    connections_.erase(new_connection_l);
    connections_mutex.unlock();
    bool r = new_connection_l->start(false, 1 < m_threads_count);
    if (r)
    {
      new_connection_l->get_context(conn_context);
      //new_connection_l.reset(new connection<t_wire_handler>(io_service_, m_shared_state, m_sock_count, m_pfilter));
    }
    else
    {
      assert(m_shared_state != nullptr); // always set in constructor
      _erro("[sock " << new_connection_l->socket().native_handle() << "] Failed to start connection, connections_count = " << m_shared_state->sock_count);
    }
    
	new_connection_l->save_dbg_log();

    return r;

    CATCH_ENTRY_L0("boosted_tcp_server<t_wire_handler>::connect", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler> template<class t_callback>
  bool boosted_tcp_server<t_wire_handler>::connect_async(const std::string& adr, const std::string& port, uint32_t conn_timeout, const t_callback &cb, const std::string& bind_ip, epee::net_utils::ssl_support_t ssl_support)
  {
    TRY_ENTRY();    
    connection_ptr new_connection_l(new connection<t_wire_handler>(io_service_, m_shared_state, m_connection_type, ssl_support) );
    connections_mutex.lock();
    connections_.insert(new_connection_l);
    MINFO("connect_async "<<adr<<","<<port<<","<<conn_timeout<<",bind_ip "<<bind_ip<<",ssl "<<(uint8_t)ssl_support<<",connections_ size now " << connections_.size());
    connections_mutex.unlock();
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){ CRITICAL_REGION_LOCAL(connections_mutex); connections_.erase(new_connection_l); });
    boost::asio::ip::tcp::socket&  sock_ = new_connection_l->socket();
    
    bool try_ipv6 = false;

    boost::asio::ip::tcp::resolver resolver(io_service_);
    boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), adr, port, boost::asio::ip::tcp::resolver::query::canonical_name);
    boost::system::error_code resolve_error;
    boost::asio::ip::tcp::resolver::iterator iterator;
    try
    {
      //resolving ipv4 address as ipv6 throws, catch here and move on
      iterator = resolver.resolve(query, resolve_error);
    }
    catch (const boost::system::system_error& e)
    {
      if (!m_use_ipv6 || (resolve_error != boost::asio::error::host_not_found &&
            resolve_error != boost::asio::error::host_not_found_try_again))
      {
        throw;
      }
      try_ipv6 = true;
    }
    catch (...)
    {
      throw;
    }

    boost::asio::ip::tcp::resolver::iterator end;
    if(iterator == end)
    {
      if (!try_ipv6)
      {
        _erro("Failed to resolve " << adr);
        return false;
      }
      else
      {
        MINFO("Resolving address as IPv4 failed, trying IPv6");
      }
    }

    if (try_ipv6)
    {
      boost::asio::ip::tcp::resolver::query query6(boost::asio::ip::tcp::v6(), adr, port, boost::asio::ip::tcp::resolver::query::canonical_name);

      iterator = resolver.resolve(query6, resolve_error);

      if(iterator == end)
      {
        _erro("Failed to resolve " << adr);
        return false;
      }
    }


    boost::asio::ip::tcp::endpoint remote_endpoint(*iterator);
     
    sock_.open(remote_endpoint.protocol());
    if(bind_ip != "0.0.0.0" && bind_ip != "0" && bind_ip != "" )
    {
      boost::asio::ip::tcp::endpoint local_endpoint(boost::asio::ip::address::from_string(bind_ip.c_str()), 0);
      boost::system::error_code ec;
      sock_.bind(local_endpoint, ec);
      if (ec)
      {
        MERROR("Error binding to " << bind_ip << ": " << ec.message());
        if (sock_.is_open())
          sock_.close();
        return false;
      }
    }
    
    boost::shared_ptr<boost::asio::deadline_timer> sh_deadline(new boost::asio::deadline_timer(io_service_));
    //start deadline
    sh_deadline->expires_from_now(boost::posix_time::milliseconds(conn_timeout));
    sh_deadline->async_wait([=](const boost::system::error_code& error)
      {
          if(error != boost::asio::error::operation_aborted) 
          {
            MINFO("Failed to connect to " << adr << ':' << port << ", because of timeout (" << conn_timeout << ")");
            new_connection_l->socket().close();
          }
      });
    //start async connect
    sock_.async_connect(remote_endpoint, [=](const boost::system::error_code& ec_)
      {
        t_connection_context conn_context = AUTO_VAL_INIT(conn_context);
        boost::system::error_code ignored_ec;
        boost::asio::ip::tcp::socket::endpoint_type lep = new_connection_l->socket().local_endpoint(ignored_ec);
        if(!ec_)
        {//success
          if(!sh_deadline->cancel())
          {
            cb(conn_context, boost::asio::error::operation_aborted);//this mean that deadline timer already queued callback with cancel operation, rare situation
          }else
          {
            MINFO("[sock " << new_connection_l->socket().native_handle() << "] Connected success to " << adr << ':' << port <<
              " from " << lep.address().to_string() << ':' << lep.port());

            // start adds the connection to the config object's list, so we don't need to have it locally anymore
            connections_mutex.lock();
            connections_.erase(new_connection_l);
            connections_mutex.unlock();
            bool r = new_connection_l->start(false, 1 < m_threads_count);
            if (r)
            {
              new_connection_l->get_context(conn_context);
              cb(conn_context, ec_);
            }
            else
            {
              MINFO("[sock " << new_connection_l->socket().native_handle() << "] Failed to start connection to " << adr << ':' << port);
              cb(conn_context, boost::asio::error::fault);
            }
          }
        }else
        {
          MINFO("[sock " << new_connection_l->socket().native_handle() << "] Failed to connect to " << adr << ':' << port <<
            " from " << lep.address().to_string() << ':' << lep.port() << ": " << ec_.message() << ':' << ec_.value());
          cb(conn_context, ec_);
        }
      });
    return true;
    CATCH_ENTRY_L0("boosted_tcp_server<t_wire_handler>::connect_async", false);
  }
  
} // namespace
} // namespace
PRAGMA_WARNING_POP
