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

// IP blocking adapted from Boolberry

#include <algorithm>
#include <boost/bind/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/optional/optional.hpp>
#include <boost/thread/thread.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/algorithm/string.hpp>
#include <atomic>
#include <functional>
#include <limits>
#include <memory>
#include <tuple>
#include <vector>

#include "version.h"
#include "string_tools.h"
#include "common/util.h"
#include "common/dns_utils.h"
#include "common/pruning.h"
#include "net/error.h"
#include "net/net_helper.h"
#include "math_helper.h"
#include "misc_log_ex.h"
#include "p2p_protocol_defs.h"
#include "net/local_ip.h"
#include "crypto/crypto.h"
#include "storages/levin_abstract_invoke2.h"
#include "cryptonote_core/cryptonote_core.h"
#include "net/parse.h"

#include <miniupnp/miniupnpc/miniupnpc.h>
#include <miniupnp/miniupnpc/upnpcommands.h>
#include <miniupnp/miniupnpc/upnperrors.h>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.p2p"

#define NET_MAKE_IP(b1,b2,b3,b4)  ((LPARAM)(((DWORD)(b1)<<24)+((DWORD)(b2)<<16)+((DWORD)(b3)<<8)+((DWORD)(b4))))

#define MIN_WANTED_SEED_NODES 12

static inline boost::asio::ip::address_v4 make_address_v4_from_v6(const boost::asio::ip::address_v6& a)
{
  const auto &bytes = a.to_bytes();
  uint32_t v4 = 0;
  v4 = (v4 << 8) | bytes[12];
  v4 = (v4 << 8) | bytes[13];
  v4 = (v4 << 8) | bytes[14];
  v4 = (v4 << 8) | bytes[15];
  return boost::asio::ip::address_v4(v4);
}

namespace nodetool
{

  //-----------------------------------------------------------------------------------
  inline bool append_net_address(std::vector<epee::net_utils::network_address> & seed_nodes, std::string const & addr, uint16_t default_port);
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  void node_server<t_payload_handler>::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_p2p_bind_ip);
    command_line::add_arg(desc, arg_p2p_bind_ipv6_address);
    command_line::add_arg(desc, arg_p2p_bind_port, false);
    command_line::add_arg(desc, arg_p2p_bind_port_ipv6, false);
    command_line::add_arg(desc, arg_p2p_use_ipv6);
    command_line::add_arg(desc, arg_p2p_ignore_ipv4);
    command_line::add_arg(desc, arg_p2p_external_port);
    command_line::add_arg(desc, arg_p2p_allow_local_ip);
    command_line::add_arg(desc, arg_p2p_add_peer);
    command_line::add_arg(desc, arg_p2p_add_priority_node);
    command_line::add_arg(desc, arg_p2p_add_exclusive_node);
    command_line::add_arg(desc, arg_p2p_seed_node);
    command_line::add_arg(desc, arg_ban_list);
    command_line::add_arg(desc, arg_p2p_hide_my_port);
    command_line::add_arg(desc, arg_no_sync);
    command_line::add_arg(desc, arg_enable_dns_blocklist);
    command_line::add_arg(desc, arg_no_igd);
    command_line::add_arg(desc, arg_igd);
    command_line::add_arg(desc, arg_out_peers);
    command_line::add_arg(desc, arg_in_peers);
    command_line::add_arg(desc, arg_limit_rate_up);
    command_line::add_arg(desc, arg_limit_rate_down);
    command_line::add_arg(desc, arg_limit_rate);
    command_line::add_arg(desc, arg_pad_transactions);
    command_line::add_arg(desc, arg_max_connections_per_ip);
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>  bool node_server<t_payload_handler>::init_config()
  {
    TRY_ENTRY();
    auto storage = peerlist_storage::open(m_config_folder + "/" + P2P_NET_DATA_FILENAME);
    if (storage)
     {
      m_peerlist_storage = std::move(*storage);
    }

    network_zone& public_zone = m_network;
    public_zone.m_shared_state.m_support_flags = P2P_SUPPORT_FLAGS;
    public_zone.m_shared_state.m_peer_id = crypto::rand<uint64_t>();
    m_first_connection_maker_call = true;

    CATCH_ENTRY_L0("node_server::init_config", false);
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  void node_server<t_payload_handler>::for_each_connection(std::function<bool(typename t_payload_handler::peer_context&, peerid_type, uint32_t)> f)
  {
     m_network.m_net_server.get_shared_state().foreach_connection([&](p2p_connection_context& cntx){
        return f(cntx, cntx.peer_id, cntx.support_flags);
      });
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::for_connection(const boost::uuids::uuid &connection_id, std::function<bool(typename t_payload_handler::peer_context&, peerid_type, uint32_t)> f)
  {
      const bool result = m_network.m_net_server.get_shared_state().for_connection(connection_id, [&](p2p_connection_context& cntx){
        return f(cntx, cntx.peer_id, cntx.support_flags);
      });
      return result;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::is_remote_host_allowed(const epee::net_utils::network_address &address, time_t *t)
  {
    CRITICAL_REGION_LOCAL(m_blocked_hosts_lock);

    const time_t now = time(nullptr);

    // look in the hosts list
    auto it = m_blocked_hosts.find(address.host_str());
    if (it != m_blocked_hosts.end())
    {
      if (now >= it->second)
      {
        m_blocked_hosts.erase(it);
        MCLOG_CYAN(el::Level::Info, "global", "Host " << address.host_str() << " unblocked.");
        it = m_blocked_hosts.end();
      }
      else
      {
        if (t)
          *t = it->second - now;
        return false;
      }
    }

    // manually loop in subnets
    if (address.get_type_id() == epee::net_utils::address_type::ipv4)
    {
      auto ipv4_address = address.template as<epee::net_utils::ipv4_network_address>();
      std::map<epee::net_utils::ipv4_network_subnet, time_t>::iterator it;
      for (it = m_blocked_subnets.begin(); it != m_blocked_subnets.end(); )
      {
        if (now >= it->second)
        {
          it = m_blocked_subnets.erase(it);
          MCLOG_CYAN(el::Level::Info, "global", "Subnet " << it->first.host_str() << " unblocked.");
          continue;
        }
        if (it->first.matches(ipv4_address))
        {
          if (t)
            *t = it->second - now;
          return false;
        }
        ++it;
      }
    }

    // not found in hosts or subnets, allowed
    return true;
  }
  
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::unblock_host(const epee::net_utils::network_address &address)
  {
    CRITICAL_REGION_LOCAL(m_blocked_hosts_lock);
    auto i = m_blocked_hosts.find(address.host_str());
    if (i == m_blocked_hosts.end())
      return false;
    m_blocked_hosts.erase(i);
    MCLOG_CYAN(el::Level::Info, "global", "Host " << address.host_str() << " unblocked.");
    return true;
  }
  
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::unblock_subnet(const epee::net_utils::ipv4_network_subnet &subnet)
  {
    CRITICAL_REGION_LOCAL(m_blocked_hosts_lock);
    auto i = m_blocked_subnets.find(subnet);
    if (i == m_blocked_subnets.end())
      return false;
    m_blocked_subnets.erase(i);
    MCLOG_CYAN(el::Level::Info, "global", "Subnet " << subnet.host_str() << " unblocked.");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::add_host_fail(const epee::net_utils::network_address &address, unsigned int score)
  {
    if(!address.is_blockable())
      return false;

    CRITICAL_REGION_LOCAL(m_host_fails_score_lock);
    uint64_t fails = m_host_fails_score[address.host_str()] += score;
    MDEBUG("Host " << address.host_str() << " fail score=" << fails);
    if(fails > P2P_IP_FAILS_BEFORE_BLOCK)
    {
      auto it = m_host_fails_score.find(address.host_str());
      CHECK_AND_ASSERT_MES(it != m_host_fails_score.end(), false, "internal error");
      it->second = P2P_IP_FAILS_BEFORE_BLOCK/2;
      block_host(address);
    }
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::handle_command_line(const boost::program_options::variables_map& vm)
  {
    bool testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
    bool stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
    m_nettype = testnet ? cryptonote::TESTNET : stagenet ? cryptonote::STAGENET : cryptonote::MAINNET;

    network_zone& public_zone = m_network;
    public_zone.m_bind_ip = command_line::get_arg(vm, arg_p2p_bind_ip);
    public_zone.m_bind_ipv6_address = command_line::get_arg(vm, arg_p2p_bind_ipv6_address);
    public_zone.m_port = command_line::get_arg(vm, arg_p2p_bind_port);
    public_zone.m_port_ipv6 = command_line::get_arg(vm, arg_p2p_bind_port_ipv6);
    public_zone.m_can_pingback = true;
    m_external_port = command_line::get_arg(vm, arg_p2p_external_port);
    m_allow_local_ip = command_line::get_arg(vm, arg_p2p_allow_local_ip);
    const bool has_no_igd = command_line::get_arg(vm, arg_no_igd);
    const std::string sigd = command_line::get_arg(vm, arg_igd);
    if (sigd == "enabled")
    {
      if (has_no_igd)
      {
        MFATAL("Cannot have both --" << arg_no_igd.name << " and --" << arg_igd.name << " enabled");
        return false;
      }
      m_igd = igd;
    }
    else if (sigd == "disabled")
    {
      m_igd =  no_igd;
    }
    else if (sigd == "delayed")
    {
      if (has_no_igd && !command_line::is_arg_defaulted(vm, arg_igd))
      {
        MFATAL("Cannot have both --" << arg_no_igd.name << " and --" << arg_igd.name << " delayed");
        return false;
      }
      m_igd = has_no_igd ? no_igd : delayed_igd;
    }
    else
    {
      MFATAL("Invalid value for --" << arg_igd.name << ", expected enabled, disabled or delayed");
      return false;
    }
    m_offline = command_line::get_arg(vm, cryptonote::arg_offline);
    m_use_ipv6 = command_line::get_arg(vm, arg_p2p_use_ipv6);
    m_require_ipv4 = !command_line::get_arg(vm, arg_p2p_ignore_ipv4);

    public_zone.m_notifier = cryptonote::levin::notify{
      m_network.m_net_server.get_io_service(), public_zone.m_net_server.get_config_shared(), m_payload_handler};

    if (command_line::has_arg(vm, arg_p2p_add_peer))
    {
      std::vector<std::string> perrs = command_line::get_arg(vm, arg_p2p_add_peer);
      for(const std::string& pr_str: perrs)
      {
        MINFO("peer "<<pr_str);
        nodetool::peerlist_entry pe {};
        pe.id = crypto::rand<uint64_t>();
        const uint16_t default_port = cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT;
        expect<epee::net_utils::network_address> adr = net::get_network_address(pr_str, default_port);
        if (adr)
        {
          pe.adr = std::move(*adr);
          MINFO("add peer "<<pe);
          m_command_line_peers.push_back(std::move(pe));
        
          continue;
        }
        CHECK_AND_ASSERT_MES(
          adr == net::error::unsupported_address, false, "Bad address (\"" << pr_str << "\"): " << adr.error().message()
        );

        std::vector<epee::net_utils::network_address> resolved_addrs;
        bool r = append_net_address(resolved_addrs, pr_str, default_port);
        CHECK_AND_ASSERT_MES(r, false, "Failed to parse or resolve address from string: " << pr_str);
        for (const auto & addr : resolved_addrs)
        {
          pe.id = crypto::rand<uint64_t>();
          pe.adr = addr;
          MINFO("add resolved peer "<<pe);
          m_command_line_peers.push_back(pe);
        }
      }
    }

    if (command_line::has_arg(vm,arg_p2p_add_exclusive_node))
    {
      if (!parse_peers_and_add_to_container(vm, arg_p2p_add_exclusive_node, m_exclusive_peers))
        return false;
    }

    if (command_line::has_arg(vm, arg_p2p_add_priority_node))
    {
      if (!parse_peers_and_add_to_container(vm, arg_p2p_add_priority_node, m_priority_peers))
        return false;
    }

    if (command_line::has_arg(vm, arg_p2p_seed_node))
    {
      boost::unique_lock<boost::shared_mutex> lock(public_zone.m_seed_nodes_lock);

      if (!parse_peers_and_add_to_container(vm, arg_p2p_seed_node, public_zone.m_seed_nodes))
        return false;
    }

    if (!command_line::is_arg_defaulted(vm, arg_ban_list))
    {
      const std::string ban_list = command_line::get_arg(vm, arg_ban_list);

      const boost::filesystem::path ban_list_path(ban_list);
      boost::system::error_code ec;
      if (!boost::filesystem::exists(ban_list_path, ec))
      {
        throw std::runtime_error("Can't find ban list file " + ban_list + " - " + ec.message());
      }

      std::string banned_ips;
      if (!epee::file_io_utils::load_file_to_string(ban_list_path.string(), banned_ips))
      {
        throw std::runtime_error("Failed to read ban list file " + ban_list);
      }

      std::istringstream iss(banned_ips);
      for (std::string line; std::getline(iss, line); )
      {
        auto subnet = net::get_ipv4_subnet_address(line);
        if (subnet)
        {
          block_subnet(*subnet, std::numeric_limits<time_t>::max());
          continue;
        }
        const expect<epee::net_utils::network_address> parsed_addr = net::get_network_address(line, 0);
        if (parsed_addr)
        {
          block_host(*parsed_addr, std::numeric_limits<time_t>::max());
          continue;
        }
        MERROR("Invalid IP address or IPv4 subnet: " << line);
      }
    }

    if(command_line::has_arg(vm, arg_p2p_hide_my_port))
      m_hide_my_port = true;

    if (command_line::has_arg(vm, arg_no_sync))
      m_payload_handler.set_no_sync(true);

    m_enable_dns_blocklist = command_line::get_arg(vm, arg_enable_dns_blocklist);

    if ( !set_max_out_peers(public_zone, command_line::get_arg(vm, arg_out_peers) ) )
      return false;
    else
      m_payload_handler.set_max_out_peers(public_zone.m_shared_state.m_net_config.max_out_connection_count);


    if ( !set_max_in_peers(public_zone, command_line::get_arg(vm, arg_in_peers) ) )
      return false;

    if ( !set_rate_up_limit(vm, command_line::get_arg(vm, arg_limit_rate_up) ) )
      return false;

    if ( !set_rate_down_limit(vm, command_line::get_arg(vm, arg_limit_rate_down) ) )
      return false;

    if ( !set_rate_limit(vm, command_line::get_arg(vm, arg_limit_rate) ) )
      return false;


    max_connections = command_line::get_arg(vm, arg_max_connections_per_ip);

    return true;
  }
  //-----------------------------------------------------------------------------------
  inline bool append_net_address(
      std::vector<epee::net_utils::network_address> & seed_nodes
    , std::string const & addr
    , uint16_t default_port
    )
  {
    using namespace boost::asio;

    std::string host = addr;
    std::string port = std::to_string(default_port);
    size_t colon_pos = addr.find_last_of(':');
    size_t dot_pos = addr.find_last_of('.');
    size_t square_brace_pos = addr.find('[');

    // IPv6 will have colons regardless.  IPv6 and IPv4 address:port will have a colon but also either a . or a [
    // as IPv6 addresses specified as address:port are to be specified as "[addr:addr:...:addr]:port"
    // One may also specify an IPv6 address as simply "[addr:addr:...:addr]" without the port; in that case
    // the square braces will be stripped here.
    if ((std::string::npos != colon_pos && std::string::npos != dot_pos) || std::string::npos != square_brace_pos)
    {
      net::get_network_address_host_and_port(addr, host, port);
    }
    MINFO("Resolving node address: host=" << host << ", port=" << port);

    io_service io_srv;
    ip::tcp::resolver resolver(io_srv);
    ip::tcp::resolver::query query(host, port, boost::asio::ip::tcp::resolver::query::canonical_name);
    boost::system::error_code ec;
    ip::tcp::resolver::iterator i = resolver.resolve(query, ec);
    CHECK_AND_ASSERT_MES(!ec, false, "Failed to resolve host name '" << host << "': " << ec.message() << ':' << ec.value());

    ip::tcp::resolver::iterator iend;
    for (; i != iend; ++i)
    {
      ip::tcp::endpoint endpoint = *i;
      if (endpoint.address().is_v4())
      {
        epee::net_utils::network_address na{epee::net_utils::ipv4_network_address{boost::asio::detail::socket_ops::host_to_network_long(endpoint.address().to_v4().to_ulong()), endpoint.port()}};
        seed_nodes.push_back(na);
        MINFO("Added node: " << na.str());
      }
      else
      {
        epee::net_utils::network_address na{epee::net_utils::ipv6_network_address{endpoint.address().to_v6(), endpoint.port()}};
        seed_nodes.push_back(na);
        MINFO("Added node: " << na.str());
      }
    }
    return true;
  }


  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::init(const boost::program_options::variables_map& vm)
  {
    bool res = handle_command_line(vm);

    CHECK_AND_ASSERT_MES(res, false, "Failed to handle command line");

    if (m_nettype == cryptonote::TESTNET)
    {
      memcpy(&m_network_id, &::config::testnet::NETWORK_ID, 16);
    }
    else if (m_nettype == cryptonote::STAGENET)
    {
      memcpy(&m_network_id, &::config::stagenet::NETWORK_ID, 16);
    }
    else
    {
      memcpy(&m_network_id, &::config::NETWORK_ID, 16);
    }

    m_config_folder = command_line::get_arg(vm, cryptonote::arg_data_dir);
    network_zone& public_zone = m_network;

    if ((m_nettype == cryptonote::MAINNET && public_zone.m_port != std::to_string(::config::P2P_DEFAULT_PORT))
        || (m_nettype == cryptonote::TESTNET && public_zone.m_port != std::to_string(::config::testnet::P2P_DEFAULT_PORT))
        || (m_nettype == cryptonote::STAGENET && public_zone.m_port != std::to_string(::config::stagenet::P2P_DEFAULT_PORT))) {
      m_config_folder = m_config_folder + "/" + public_zone.m_port;
    }

    res = init_config();
    CHECK_AND_ASSERT_MES(res, false, "Failed to init config.");

    MINFO("node_server init()");
      res = m_network.m_peerlist.init(m_peerlist_storage.take_zone(), m_allow_local_ip);
      CHECK_AND_ASSERT_MES(res, false, "Failed to init peerlist.");

      m_network.m_peerlist.foreach(true,[](const peerlist_entry & e){

        MINFO("peerlist_entry id"<<e.id<<", adr "<<e.adr.str()); return true;
      });

    for(const auto& p: m_command_line_peers)
      m_network.m_peerlist.append_with_peer_white(p);

    //only in case if we really sure that we have external visible ip
    m_have_address = true;

    //configure self

    public_zone.m_net_server.set_threads_prefix("P2P"); // all zones use these threads/asio::io_service

    // from here onwards, it's online stuff
    if (m_offline)
      return res;

    //try to bind
    m_ssl_support = epee::net_utils::ssl_support_t::e_ssl_support_disabled;
   
    {
      m_network.m_net_server.get_shared_state().set_handler(this);

      m_network.m_net_server.get_shared_state().m_invoke_timeout = P2P_DEFAULT_INVOKE_TIMEOUT;

      if (!m_network.m_bind_ip.empty())
      {
        std::string ipv6_addr = "";
        std::string ipv6_port = "";
        m_network.m_net_server.set_connection_filter(this);
        MINFO("Binding (IPv4) on " << m_network.m_bind_ip << ":" << m_network.m_port);
        if (!m_network.m_bind_ipv6_address.empty() && m_use_ipv6)
        {
          ipv6_addr = m_network.m_bind_ipv6_address;
          ipv6_port = m_network.m_port_ipv6;
          MINFO("Binding (IPv6) on " << m_network.m_bind_ipv6_address << ":" << m_network.m_port_ipv6);
        }
        res = m_network.m_net_server.init_server(m_network.m_port, m_network.m_bind_ip, ipv6_port, ipv6_addr, m_use_ipv6, m_require_ipv4, epee::net_utils::ssl_support_t::e_ssl_support_disabled);
        CHECK_AND_ASSERT_MES(res, false, "Failed to bind server");
      }
    }

    m_listening_port = m_network.m_net_server.get_binded_port();
    MLOG_GREEN(el::Level::Info, "P2P service bound (IPv4) to " << public_zone.m_bind_ip << ":" << m_listening_port);
    if (m_use_ipv6)
    {
      m_listening_port_ipv6 = m_network.m_net_server.get_binded_port_ipv6();
      MLOG_GREEN(el::Level::Info, "P2P service bound (IPv6) to " << public_zone.m_bind_ipv6_address << ":" << m_listening_port_ipv6);
    }
    if(m_external_port)
      MDEBUG("External port defined as " << m_external_port);

    // add UPnP port mapping
    if(m_igd == igd)
    {
      add_upnp_port_mapping_v4(m_listening_port);
      if (m_use_ipv6)
      {
        add_upnp_port_mapping_v6(m_listening_port_ipv6);
      }
    }

    return res;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  t_payload_handler& node_server<t_payload_handler>::get_crypto_protocol()
  {
    return m_payload_handler;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::run()
  {
    // creating thread to log number of connections
    mPeersLoggerThread.reset(new boost::thread([&]()
    {
      MINFO("Thread monitor number of peers - start");
      const network_zone& public_zone = m_network;
      while (!m_is_closing && !public_zone.m_net_server.is_stop_signal_sent())
      { // main loop of thread
        //number_of_peers = m_net_server.get_shared_state().get_connections_count();
        {
          unsigned int number_of_in_peers = 0;
          unsigned int number_of_out_peers = 0;
          m_network.m_net_server.get_shared_state().foreach_connection([&](const p2p_connection_context& cntxt)
          {
            if (cntxt.m_is_income)
            {
              ++number_of_in_peers;
            }
            else
            {
              ++number_of_out_peers;
            }
            return true;
          }); // lambda
          m_network.m_current_number_of_in_peers = number_of_in_peers;
          m_network.m_current_number_of_out_peers = number_of_out_peers;
        }
        boost::this_thread::sleep_for(boost::chrono::seconds(1));
      } // main loop of thread
      MINFO("Thread monitor number of peers - done");
    })); // lambda

    m_network.m_net_server.add_idle_handler(boost::bind(&MyType::idle_worker, this), 1000);
    m_network.m_net_server.add_idle_handler(boost::bind(&t_payload_handler::on_idle, &m_payload_handler), 1000);

    //here you can set worker threads count
    int thrds_count = 2;
    boost::thread::attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);
    //go to loop
    MINFO("Run p2p net_service loop( " << thrds_count << " threads)... staack size "<<THREAD_STACK_SIZE);
    if(!m_network.m_net_server.run_server(thrds_count, true, attrs))
    {
      LOG_ERROR("Failed to run net tcp server!");
    }

    MINFO("net_service loop stopped.");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  uint64_t node_server<t_payload_handler>::get_public_connections_count()
  {
    return m_network.m_net_server.get_shared_state().get_connections_count();
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::deinit()
  {
    kill();

    if (!m_offline)
    {
      m_network.m_net_server.deinit_server();
      // remove UPnP port mapping
      if(m_igd == igd)
        delete_upnp_port_mapping(m_listening_port);
    }
    return store_config();
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::store_config()
  {
    TRY_ENTRY();

    if (!tools::create_directories_if_necessary(m_config_folder))
    {
      MWARNING("Failed to create data directory \"" << m_config_folder);
      return false;
    }

    peerlist_types active{};
      m_network.m_peerlist.get_peerlist(active);

    const std::string state_file_path = m_config_folder + "/" + P2P_NET_DATA_FILENAME;
    if (!m_peerlist_storage.store(state_file_path, active))
    {
      MWARNING("Failed to save config to file " << state_file_path);
      return false;
    }
    MINFO( "save peerlist to file " << state_file_path);
    m_network.m_peerlist.foreach(true,[](const peerlist_entry & e){
        MDEBUG("peerlist_entry id"<<e); return true;
      }); 
    CATCH_ENTRY_L0("node_server::store", false);
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::send_stop_signal()
  {
    MDEBUG("[node] sending stop signal");
        m_network.m_net_server.send_stop_signal();
    MDEBUG("[node] Stop signal sent");

    {
      std::list<boost::uuids::uuid> connection_ids;
      m_network.m_net_server.get_shared_state().foreach_connection([&](const p2p_connection_context& cntxt) {
        connection_ids.push_back(cntxt.m_connection_id);
        return true;
      });
      for (const auto &connection_id: connection_ids)
        m_network.m_net_server.get_shared_state().close(connection_id);
    }
    m_payload_handler.stop();
    return true;
  }

  
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  size_t node_server<t_payload_handler>::get_random_index_with_fixed_probability(size_t max_index)
  {
    //divide by zero workaround
    if(!max_index)
      return 0;

    size_t x = crypto::rand<size_t>()%(16*max_index+1);
    size_t res = (x*x*x)/(max_index*max_index*16*16*16); //parabola \/
    MDEBUG("Random connection index=" << res << "(x="<< x << ", max_index=" << max_index << ")");
    return res;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::is_peer_used(const peerlist_entry& peer)
  {
 
    if( m_network.m_shared_state.m_peer_id == peer.id)
      return true;//dont make connections to ourself

    bool used = false;
    m_network.m_net_server.get_shared_state().foreach_connection([&](const p2p_connection_context& cntxt)
    {
      if((cntxt.peer_id == peer.id) || (!cntxt.m_is_income && peer.adr == cntxt.m_remote_address))
      {
        used = true;
        return false;//stop enumerating
      }
      return true;
    });
    return used;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::is_peer_used(const anchor_peerlist_entry& peer)
  {

    if(m_network.m_shared_state.m_peer_id == peer.id)
      return true;//dont make connections to ourself

    bool used = false;
    m_network.m_net_server.get_shared_state().foreach_connection([&](const p2p_connection_context& cntxt)
    {
      if((cntxt.peer_id == peer.id) || (!cntxt.m_is_income && peer.adr == cntxt.m_remote_address))
      {
        used = true;
        return false;//stop enumerating
      }
      return true;
    });
    return used;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::is_addr_connected(const epee::net_utils::network_address& peer)
  {


    bool connected = false;
    m_network.m_net_server.get_shared_state().foreach_connection([&](const p2p_connection_context& cntxt)
    {
      if(!cntxt.m_is_income && peer == cntxt.m_remote_address)
      {
        connected = true;
        return false;//stop enumerating
      }
      return true;
    });

    return connected;
  }


  template<class t_payload_handler>
  bool node_server<t_payload_handler>::check_connection_and_handshake_with_peer(const epee::net_utils::network_address& na, uint64_t last_seen_stamp)
  {
    MINFO("Connecting to " << na.str() << "(last_seen: " << (last_seen_stamp ? epee::misc_utils::get_time_interval_string(time(NULL) - last_seen_stamp):"never")<< ")...");

    auto con = m_network.connect( na, m_ssl_support);
    if (!con) {
      bool is_priority = is_priority_node(na);
      MINFO("Connect failed to " << na.str()<<","<<is_priority);
      record_addr_failed(na);

      return false;
    }

    con->m_anchor = false;
    peerid_type pi = AUTO_VAL_INIT(pi);
    const bool res = do_handshake_with_peer(pi, *con, true);
    if (!res) {
      bool is_priority = is_priority_node(na);

      MINFO("Failed to HANDSHAKE with peer " << na.str()<<","<<is_priority);
      record_addr_failed(na);
      return false;
    }

    m_network.m_net_server.get_shared_state().close(con->m_connection_id);

    LOG_DEBUG_CC(*con, "CONNECTION HANDSHAKED OK AND CLOSED.");

    return true;
  }

#include "net_node_p2p.inl"

  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  void node_server<t_payload_handler>::record_addr_failed(const epee::net_utils::network_address& addr)
  {
    CRITICAL_REGION_LOCAL(m_conn_fails_cache_lock);
    m_conn_fails_cache[addr.host_str()] = time(NULL);
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::is_addr_recently_failed(const epee::net_utils::network_address& addr)
  {
    CRITICAL_REGION_LOCAL(m_conn_fails_cache_lock);
    auto it = m_conn_fails_cache.find(addr.host_str());
    if(it == m_conn_fails_cache.end())
      return false;

    if(time(NULL) - it->second > P2P_FAILED_ADDR_FORGET_SECONDS)
      return false;
    else
      return true;
  }
 
 
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  size_t node_server<t_payload_handler>::get_outgoing_connections_count()
  {
   size_t count = 0;
    {
      m_network.m_net_server.get_shared_state().foreach_connection([&](const p2p_connection_context& cntxt)
      {
        if(!cntxt.m_is_income)
          ++count;
        return true;
      });
    }
    return count;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  size_t node_server<t_payload_handler>::get_incoming_connections_count()
  {
    size_t count = 0;
    {
      m_network.m_net_server.get_shared_state().foreach_connection([&](const p2p_connection_context& cntxt)
      {
        if(cntxt.m_is_income)
          ++count;
        return true;
      });
    }
    return count;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  size_t node_server<t_payload_handler>::get_public_white_peers_count()
  {
    return m_network.m_peerlist.get_white_peers_count();
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  size_t node_server<t_payload_handler>::get_public_gray_peers_count()
  {
    return m_network.m_peerlist.get_gray_peers_count();
  }
 
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  void node_server<t_payload_handler>::get_peerlist(std::vector<peerlist_entry>& gray, std::vector<peerlist_entry>& white)
  {
      m_network.m_peerlist.get_peerlist(gray, white); // appends
  }
 #include "net_node_idle.inl"
 
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::check_incoming_connections()
  {
    if (m_offline)
      return true;

    if (get_incoming_connections_count() == 0)
    {
      if (m_hide_my_port || m_network.m_shared_state.m_net_config.max_in_connection_count == 0)
      {
        MGINFO("Incoming connections disabled, enable them for full connectivity");
      }
      else
      {
        if (m_igd == delayed_igd)
        {
          MWARNING("No incoming connections, trying to setup IGD");
          add_upnp_port_mapping(m_listening_port);
          m_igd = igd;
        }
        else
        {
          const el::Level level = el::Level::Warning;
          MCLOG_RED(level, "global", "No incoming connections - check firewalls/routers allow port " << get_this_peer_port());
        }
      }
    }
    return true;
  }
 
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::get_local_node_data(basic_node_data& node_data)
  {
    node_data.peer_id = m_network.m_shared_state.m_peer_id;
    if(!m_hide_my_port && m_network.m_can_pingback)
      node_data.my_port = m_external_port ? m_external_port : m_listening_port;
    else
      node_data.my_port = 0;
    node_data.rpc_port = m_network.m_can_pingback ? m_rpc_port : 0;
    node_data.rpc_credits_per_hash = m_network.m_can_pingback ? m_rpc_credits_per_hash : 0;
    node_data.network_id = m_network_id;
    node_data.support_flags = m_network.m_shared_state.m_support_flags;
    return true;
  }

  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  void node_server<t_payload_handler>::request_callback(const epee::net_utils::connection_context_base& context)
  {
    m_network.m_net_server.get_shared_state().request_callback(context.m_connection_id);
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::relay_notify_to_list(int command, epee::levin::message_writer data_buff, std::vector<boost::uuids::uuid> connections)
  {
    epee::byte_slice message = data_buff.finalize_notify(command);
    for(const auto& c_id: connections)
    {
        m_network.m_net_server.get_shared_state().send(message.clone(), c_id);
    }
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
 bool node_server<t_payload_handler>::send_txs(std::vector<cryptonote::blobdata> txs,const boost::uuids::uuid& source, const cryptonote::relay_method tx_relay)
  {
      return m_network.m_notifier.send_txs(std::move(txs), source, tx_relay);
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  void node_server<t_payload_handler>::callback(p2p_connection_context& context)
  {
    m_payload_handler.on_callback(context);
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::invoke_notify_to_peer(const int command, epee::levin::message_writer message, const epee::net_utils::connection_context_base& context)
  {
    if(is_filtered_command(context.m_remote_address, command))
      return false;

    int res = m_network.m_net_server.get_shared_state().send(message.finalize_notify(command), context.m_connection_id);
    return res > 0;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::drop_connection(const epee::net_utils::connection_context_base& context)
  {
    m_network.m_net_server.get_shared_state().close(context.m_connection_id);
    return true;
  }

  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::log_peerlist()
  {
    std::vector<peerlist_entry> pl_white;
    std::vector<peerlist_entry> pl_gray;
      m_network.m_peerlist.get_peerlist(pl_gray, pl_white);
    MINFO(ENDL << "Peerlist white:" << ENDL << print_peerlist_to_string(pl_white) << ENDL << "Peerlist gray:" << ENDL << print_peerlist_to_string(pl_gray) );
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::log_connections()
  {
    MINFO("Connections: \r\n" << print_connections_container() );
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  std::string node_server<t_payload_handler>::print_connections_container()
  {

    std::stringstream ss;
    {
      m_network.m_net_server.get_shared_state().foreach_connection([&](const p2p_connection_context& cntxt)
      {
        ss << cntxt.m_remote_address.str()
          << " \t\tpeer_id " << peerid_to_string(cntxt.peer_id)
          << " \t\tconn_id " << cntxt.m_connection_id << (cntxt.m_is_income ? " INC":" OUT")
          << std::endl;
        return true;
      });
    }
    std::string s = ss.str();
    return s;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  void node_server<t_payload_handler>::on_connection_new(p2p_connection_context& context)
  {
    MINFO("["<< epee::net_utils::print_connection_context(context) << "] NEW CONNECTION");
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  void node_server<t_payload_handler>::on_connection_close(p2p_connection_context& context)
  {
    if (!m_network.m_net_server.is_stop_signal_sent() && !context.m_is_income) {
      epee::net_utils::network_address na = AUTO_VAL_INIT(na);
      na = context.m_remote_address;

      m_network.m_peerlist.remove_from_peer_anchor(na);
    }

    m_payload_handler.on_connection_close(context);

    MINFO("["<< epee::net_utils::print_connection_context(context) << "] CLOSE CONNECTION");
  }

  template<class t_payload_handler>
  bool node_server<t_payload_handler>::is_priority_node(const epee::net_utils::network_address& na)
  {
    return (std::find(m_priority_peers.begin(), m_priority_peers.end(), na) != m_priority_peers.end()) || (std::find(m_exclusive_peers.begin(), m_exclusive_peers.end(), na) != m_exclusive_peers.end());
  }

  template<class t_payload_handler> template <class Container>
  bool node_server<t_payload_handler>::connect_to_peerlist(const Container& peers)
  {
    for(const epee::net_utils::network_address& na: peers)
    {
      if(m_network.m_net_server.is_stop_signal_sent())
        return false;

      if(is_addr_connected(na))
        continue;

      try_to_connect_and_handshake_with_new_peer(na);
    }

    return true;
  }

  template<class t_payload_handler> template <class Container>
  bool node_server<t_payload_handler>::parse_peers_and_add_to_container(const boost::program_options::variables_map& vm, const command_line::arg_descriptor<std::vector<std::string> > & arg, Container& container)
  {
    std::vector<std::string> perrs = command_line::get_arg(vm, arg);

    for(const std::string& pr_str: perrs)
    {
      const uint16_t default_port = cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT;
      expect<epee::net_utils::network_address> adr = net::get_network_address(pr_str, default_port);
      if (adr)
      {
        container.push_back(std::move(*adr));
        continue;
      }
      std::vector<epee::net_utils::network_address> resolved_addrs;
      bool r = append_net_address(resolved_addrs, pr_str, default_port);
      CHECK_AND_ASSERT_MES(r, false, "Failed to parse or resolve address from string: " << pr_str);
      for (const epee::net_utils::network_address& addr : resolved_addrs)
      {
        container.push_back(addr);
      }
    }

    return true;
  }

  template<class t_payload_handler>
  bool node_server<t_payload_handler>::set_max_out_peers(network_zone& zone, int64_t max)
  {
    if(max == -1) {
      zone.m_shared_state.m_net_config.max_out_connection_count = P2P_DEFAULT_CONNECTIONS_COUNT;
      return true;
    }
    zone.m_shared_state.m_net_config.max_out_connection_count = max;
    return true;
  }

  template<class t_payload_handler>
  bool node_server<t_payload_handler>::set_max_in_peers(network_zone& zone, int64_t max)
  {
    zone.m_shared_state.m_net_config.max_in_connection_count = max;
    return true;
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::change_max_out_public_peers(size_t count)
  {
    {
      const auto current = m_network.m_net_server.get_shared_state().get_out_connections_count();
      m_network.m_shared_state.m_net_config.max_out_connection_count = count;
      if(current > count)
        m_network.m_net_server.get_shared_state().del_out_connections(current - count);
      m_payload_handler.set_max_out_peers(count);
    }
  }

  template<class t_payload_handler>
  uint32_t node_server<t_payload_handler>::get_max_out_public_peers() const
  {
    return m_network.m_shared_state.m_net_config.max_out_connection_count;
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::change_max_in_public_peers(size_t count)
  {
    {
      const auto current = m_network.m_net_server.get_shared_state().get_in_connections_count();
      m_network.m_shared_state.m_net_config.max_in_connection_count = count;
      if(current > count)
        m_network.m_net_server.get_shared_state().del_in_connections(current - count);
    }
  }

  template<class t_payload_handler>
  uint32_t node_server<t_payload_handler>::get_max_in_public_peers() const
  {
    return m_network.m_shared_state.m_net_config.max_in_connection_count;
  }

  template<class t_payload_handler>
  bool node_server<t_payload_handler>::set_rate_up_limit(const boost::program_options::variables_map& vm, int64_t limit)
  {
    this->islimitup=(limit != -1) && (limit != default_limit_up);

    if (limit==-1) {
      limit=default_limit_up;
    }

    //epee::net_utils::connection<epee::levin::async_wire_handler<p2p_connection_context> >::set_rate_up_limit( limit );
    net_server::ConnectionType::set_rate_up_limit(limit);
    MINFO("Set limit-up to " << limit << " kB/s");
    return true;
  }

  template<class t_payload_handler>
  bool node_server<t_payload_handler>::set_rate_down_limit(const boost::program_options::variables_map& vm, int64_t limit)
  {
    this->islimitdown=(limit != -1) && (limit != default_limit_down);
    if(limit==-1) {
      limit=default_limit_down;
    }
    net_server::ConnectionType::set_rate_down_limit( limit );
    MINFO("Set limit-down to " << limit << " kB/s");
    return true;
  }

  template<class t_payload_handler>
  bool node_server<t_payload_handler>::set_rate_limit(const boost::program_options::variables_map& vm, int64_t limit)
  {
    int64_t limit_up = 0;
    int64_t limit_down = 0;

    if(limit == -1)
    {
      limit_up = default_limit_up;
      limit_down = default_limit_down;
    }
    else
    {
      limit_up = limit;
      limit_down = limit;
    }
    if(!this->islimitup) {
      epee::net_utils::connection<epee::levin::async_wire_handler<p2p_connection_context> >::set_rate_up_limit(limit_up);
      MINFO("Set limit-up to " << limit_up << " kB/s");
    }
    if(!this->islimitdown) {
      epee::net_utils::connection<epee::levin::async_wire_handler<p2p_connection_context> >::set_rate_down_limit(limit_down);
      MINFO("Set limit-down to " << limit_down << " kB/s");
    }

    return true;
  }

  template<class t_payload_handler>
  bool node_server<t_payload_handler>::has_too_many_connections(const epee::net_utils::network_address &address)
  {
    uint32_t count = 0;

    m_network.m_net_server.get_shared_state().foreach_connection([&](const p2p_connection_context& cntxt)
    {
      if (cntxt.m_is_income && cntxt.m_remote_address.is_same_host(address)) {
        count++;

        if (count > max_connections) {
          return false;
        }
      }

      return true;
    });

    return count > max_connections;
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::add_used_stripe_peer(const typename t_payload_handler::peer_context &context)
  {
    const uint32_t stripe = tools::get_pruning_stripe(context.m_pruning_seed);
    if (stripe == 0 || stripe > (1ul << CRYPTONOTE_PRUNING_LOG_STRIPES))
      return;
    const uint32_t index = stripe - 1;
    CRITICAL_REGION_LOCAL(m_used_stripe_peers_mutex);
    MINFO("adding stripe " << stripe << " peer: " << context.m_remote_address.str());
    m_used_stripe_peers[index].erase(std::remove_if(m_used_stripe_peers[index].begin(), m_used_stripe_peers[index].end(),
        [&context](const epee::net_utils::network_address &na){ return context.m_remote_address == na; }), m_used_stripe_peers[index].end());
    m_used_stripe_peers[index].push_back(context.m_remote_address);
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::remove_used_stripe_peer(const typename t_payload_handler::peer_context &context)
  {
    const uint32_t stripe = tools::get_pruning_stripe(context.m_pruning_seed);
    if (stripe == 0 || stripe > (1ul << CRYPTONOTE_PRUNING_LOG_STRIPES))
      return;
    const uint32_t index = stripe - 1;
    CRITICAL_REGION_LOCAL(m_used_stripe_peers_mutex);
    MINFO("removing stripe " << stripe << " peer: " << context.m_remote_address.str());
    m_used_stripe_peers[index].erase(std::remove_if(m_used_stripe_peers[index].begin(), m_used_stripe_peers[index].end(),
        [&context](const epee::net_utils::network_address &na){ return context.m_remote_address == na; }), m_used_stripe_peers[index].end());
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::clear_used_stripe_peers()
  {
    CRITICAL_REGION_LOCAL(m_used_stripe_peers_mutex);
    MINFO("clearing used stripe peers");
    for (auto &e: m_used_stripe_peers)
      e.clear();
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::add_upnp_port_mapping_impl(uint32_t port, bool ipv6) // if ipv6 false, do ipv4
  {
    std::string ipversion = ipv6 ? "(IPv6)" : "(IPv4)";
    MDEBUG("Attempting to add IGD port mapping " << ipversion << ".");
    int result;
    const int ipv6_arg = ipv6 ? 1 : 0;

#if MINIUPNPC_API_VERSION > 13
    // default according to miniupnpc.h
    unsigned char ttl = 2;
    UPNPDev* deviceList = upnpDiscover(1000, NULL, NULL, 0, ipv6_arg, ttl, &result);
#else
    UPNPDev* deviceList = upnpDiscover(1000, NULL, NULL, 0, ipv6_arg, &result);
#endif
    UPNPUrls urls;
    IGDdatas igdData;
    char lanAddress[64];
    result = UPNP_GetValidIGD(deviceList, &urls, &igdData, lanAddress, sizeof lanAddress);
    freeUPNPDevlist(deviceList);
    if (result > 0) {
      if (result == 1) {
        std::ostringstream portString;
        portString << port;

        // Delete the port mapping before we create it, just in case we have dangling port mapping from the daemon not being shut down correctly
        UPNP_DeletePortMapping(urls.controlURL, igdData.first.servicetype, portString.str().c_str(), "TCP", 0);

        int portMappingResult;
        portMappingResult = UPNP_AddPortMapping(urls.controlURL, igdData.first.servicetype, portString.str().c_str(), portString.str().c_str(), lanAddress, CRYPTONOTE_NAME, "TCP", 0, "0");
        if (portMappingResult != 0) {
          LOG_ERROR("UPNP_AddPortMapping failed, error: " << strupnperror(portMappingResult));
        } else {
          MLOG_GREEN(el::Level::Info, "Added IGD port mapping.");
        }
      } else if (result == 2) {
        MWARNING("IGD was found but reported as not connected.");
      } else if (result == 3) {
        MWARNING("UPnP device was found but not recognized as IGD.");
      } else {
        MWARNING("UPNP_GetValidIGD returned an unknown result code.");
      }

      FreeUPNPUrls(&urls);
    } else {
      MINFO("No IGD was found.");
    }
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::add_upnp_port_mapping_v4(uint32_t port)
  {
    add_upnp_port_mapping_impl(port, false);
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::add_upnp_port_mapping_v6(uint32_t port)
  {
    add_upnp_port_mapping_impl(port, true);
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::add_upnp_port_mapping(uint32_t port, bool ipv4, bool ipv6)
  {
    if (ipv4) add_upnp_port_mapping_v4(port);
    if (ipv6) add_upnp_port_mapping_v6(port);
  }


  template<class t_payload_handler>
  void node_server<t_payload_handler>::delete_upnp_port_mapping_impl(uint32_t port, bool ipv6)
  {
    std::string ipversion = ipv6 ? "(IPv6)" : "(IPv4)";
    MDEBUG("Attempting to delete IGD port mapping " << ipversion << ".");
    int result;
    const int ipv6_arg = ipv6 ? 1 : 0;
#if MINIUPNPC_API_VERSION > 13
    // default according to miniupnpc.h
    unsigned char ttl = 2;
    UPNPDev* deviceList = upnpDiscover(1000, NULL, NULL, 0, ipv6_arg, ttl, &result);
#else
    UPNPDev* deviceList = upnpDiscover(1000, NULL, NULL, 0, ipv6_arg, &result);
#endif
    UPNPUrls urls;
    IGDdatas igdData;
    char lanAddress[64];
    result = UPNP_GetValidIGD(deviceList, &urls, &igdData, lanAddress, sizeof lanAddress);
    freeUPNPDevlist(deviceList);
    if (result > 0) {
      if (result == 1) {
        std::ostringstream portString;
        portString << port;

        int portMappingResult;
        portMappingResult = UPNP_DeletePortMapping(urls.controlURL, igdData.first.servicetype, portString.str().c_str(), "TCP", 0);
        if (portMappingResult != 0) {
          LOG_ERROR("UPNP_DeletePortMapping failed, error: " << strupnperror(portMappingResult));
        } else {
          MLOG_GREEN(el::Level::Info, "Deleted IGD port mapping.");
        }
      } else if (result == 2) {
        MWARNING("IGD was found but reported as not connected.");
      } else if (result == 3) {
        MWARNING("UPnP device was found but not recognized as IGD.");
      } else {
        MWARNING("UPNP_GetValidIGD returned an unknown result code.");
      }

      FreeUPNPUrls(&urls);
    } else {
      MINFO("No IGD was found.");
    }
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::delete_upnp_port_mapping_v4(uint32_t port)
  {
    delete_upnp_port_mapping_impl(port, false);
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::delete_upnp_port_mapping_v6(uint32_t port)
  {
    delete_upnp_port_mapping_impl(port, true);
  }

  template<class t_payload_handler>
  void node_server<t_payload_handler>::delete_upnp_port_mapping(uint32_t port)
  {
    delete_upnp_port_mapping_v4(port);
    delete_upnp_port_mapping_v6(port);
  }

}
