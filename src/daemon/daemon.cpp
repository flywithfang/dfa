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

#include <memory>
#include <stdexcept>
#include <boost/algorithm/string/split.hpp>
#include "misc_log_ex.h"
#include "daemon/daemon.h"

#include "common/password.h"
#include "common/util.h"
#include "cryptonote_basic/events.h"
#include "daemon/command_server.h"
#include "daemon/command_line_args.h"
#include "net/net_ssl.h"
#include "version.h"

using namespace epee;

#include <functional>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

struct t_internals {
private:
  typedef cryptonote::t_cryptonote_protocol_handler<cryptonote::core> t_protocol_raw;
  typedef nodetool::node_server<t_protocol_raw> t_node_server;
private:
  std::string m_rpc_port;
  t_protocol_raw m_protocol;
  cryptonote::core m_core;
  t_node_server m_p2p;
  std::unique_ptr<cryptonote::core_rpc_server> m_rpc;

public:
  t_internals(boost::program_options::variables_map const & vm): m_core{nullptr}, m_protocol{ m_core,nullptr, command_line::get_arg(vm, cryptonote::arg_offline)}, m_p2p{m_protocol}
  {
    MGINFO("Initializing cryptonote protocol...");
    if (!m_protocol.init(vm))
    {
      throw std::runtime_error("Failed to initialize cryptonote protocol.");
    }
    MGINFO("Cryptonote protocol initialized OK");

    // Handle circular dependencies
    m_protocol.set_p2p_endpoint(&m_p2p);
    m_core.set_cryptonote_protocol(&m_protocol);


    if (!m_core.init(vm))
    {
      throw std::runtime_error("Failed to initialize core.");
    }

  {
   const bool restricted = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_restricted_rpc);
    m_rpc_port = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);
    m_rpc.reset(new  cryptonote::core_rpc_server{m_core, m_p2p});
     MGINFO("Initializing  RPC server...");

    if (!m_rpc->init(vm, restricted, m_rpc_port))
    {
      throw std::runtime_error("Failed to initialize RPC server.");
    }
    MGINFO( " RPC server initialized OK on port: " << m_rpc->get_binded_port());
  }
  }

 static void init_options(boost::program_options::options_description & option_spec)
  {
    cryptonote::core::init_options(option_spec);
    t_node_server::init_options(option_spec);
    cryptonote::core_rpc_server::init_options(option_spec);
  }

  bool run(bool interactive)
{
  std::atomic<bool> stop(false), shutdown(false);
  boost::thread stop_thread = boost::thread([&stop, &shutdown, this] {
    while (!stop)
      epee::misc_utils::sleep_no_w(100);
    if (shutdown)
      this->stop_p2p();
  });

  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){
    stop = true;
    stop_thread.join();
  });
  tools::signal_handler::install([&stop, &shutdown](int){ stop = shutdown = true; });

  try
  {
    std::unique_ptr<daemonize::t_command_server> rpc_cmd_handler;
    if (interactive)
    {
      // The first three variables are not used when the fourth is false
      rpc_cmd_handler.reset(new daemonize::t_command_server(0, 0, boost::none, epee::net_utils::ssl_support_t::e_ssl_support_disabled, false, m_rpc.get(),m_core));
      rpc_cmd_handler->start_handling(std::bind(&daemonize::t_internals::stop_p2p, this));
    }

    if (m_rpc_port.size()>0)
    {
      MGINFO("Public RPC port " << m_rpc_port << " will be advertised to other peers over P2P");
      m_p2p.set_rpc_port(boost::lexical_cast<uint16_t>(m_rpc_port));
    }
    
    m_p2p.run(); // blocks until p2p goes down

    if (rpc_cmd_handler)
      rpc_cmd_handler->stop_handling();

    MGINFO("Node stopped.");
    return true;
  }
  catch (std::exception const & ex)
  {
    MFATAL("Uncaught exception! " << ex.what());
    return false;
  }
  catch (...)
  {
    MFATAL("Uncaught exception!");
    return false;
  }
}

void stop()
{
  m_p2p.send_stop_signal();
}

void stop_p2p()
{
 m_p2p.send_stop_signal();
}
  ~t_internals(){

        MGINFO("Deinitializing p2p...");
    try {
      m_p2p.deinit();
    } catch (...) {
      MERROR("Failed to deinitialize p2p...");
    }

      MGINFO("Stopping cryptonote protocol...");
    try {
      m_protocol.deinit();
      m_protocol.set_p2p_endpoint(nullptr);
      MGINFO("Cryptonote protocol stopped successfully");
    } catch (...) {
      LOG_ERROR("Failed to stop cryptonote protocol!");
    }

     MGINFO("Deinitializing core...");
    try {
      m_core.deinit();
      m_core.set_cryptonote_protocol(nullptr);
    } catch (...) {
      MERROR("Failed to deinitialize core...");
    }
  }
};

void t_daemon::init_options(boost::program_options::options_description & option_spec)
{
  t_internals::init_options(option_spec);
}

t_daemon::t_daemon(boost::program_options::variables_map const & vm)
  : m_impl{new t_internals{vm}}
{
}

bool t_daemon::run(bool interactive)
{
  return m_impl->run(interactive);
}
void t_daemon::stop(){
  m_impl->stop();
  delete m_impl;
  m_impl=nullptr;
}
t_daemon::~t_daemon(){
  delete m_impl;
  m_impl=nullptr;
}


} // namespace daemonize
