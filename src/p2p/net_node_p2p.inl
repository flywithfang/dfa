//-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  std::set<std::string> node_server<t_payload_handler>::get_seed_nodes()
  {
      return get_dns_seed_nodes();
   
  }

   //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  std::set<std::string> node_server<t_payload_handler>::get_ip_seed_nodes() const
  {
    std::set<std::string> full_addrs;
    if (m_nettype == cryptonote::TESTNET)
    {
    }
    else if (m_nettype == cryptonote::STAGENET)
    {
    }
    else if (m_nettype == cryptonote::FAKECHAIN)
    {
    }
    else
    {
//      full_addrs.insert("88.99.173.38:18080");
    }
    return full_addrs;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  std::set<std::string> node_server<t_payload_handler>::get_dns_seed_nodes()
  {
    if (!m_exclusive_peers.empty() || m_offline)
    {
      return {};
    }
    if (m_nettype == cryptonote::TESTNET)
    {
      return get_ip_seed_nodes();
    }
    if (m_nettype == cryptonote::STAGENET)
    {
      return get_ip_seed_nodes();
    }

    std::set<std::string> full_addrs;

    // for each hostname in the seed nodes list, attempt to DNS resolve and
    // add the result addresses as seed nodes
    // TODO: at some point add IPv6 support, but that won't be relevant
    // for some time yet.

    std::vector<std::vector<std::string>> dns_results;
    dns_results.resize(m_seed_nodes_list.size());

    // some libc implementation provide only a very small stack
    // for threads, e.g. musl only gives +- 80kb, which is not
    // enough to do a resolve with unbound. we request a stack
    // of 1 mb, which should be plenty
    boost::thread::attributes thread_attributes;
    thread_attributes.set_stack_size(1024*1024);

    std::list<boost::thread> dns_threads;
    uint64_t result_index = 0;
    for (const std::string& addr_str : m_seed_nodes_list)
    {
      boost::thread th = boost::thread(thread_attributes, [=, &dns_results, &addr_str]
      {
        MDEBUG("dns_threads[" << result_index << "] created for: " << addr_str);
        // TODO: care about dnssec avail/valid
        bool avail, valid;
        std::vector<std::string> addr_list;

        try
        {
          addr_list = tools::DNSResolver::instance().get_ipv4(addr_str, avail, valid);
          MDEBUG("dns_threads[" << result_index << "] DNS resolve done");
          boost::this_thread::interruption_point();
        }
        catch(const boost::thread_interrupted&)
        {
          // thread interruption request
          // even if we now have results, finish thread without setting
          // result variables, which are now out of scope in main thread
          MWARNING("dns_threads[" << result_index << "] interrupted");
          return;
        }

        MINFO("dns_threads[" << result_index << "] addr_str: " << addr_str << "  number of results: " << addr_list.size());
        dns_results[result_index] = addr_list;
      });

      dns_threads.push_back(std::move(th));
      ++result_index;
    }

    MDEBUG("dns_threads created, now waiting for completion or timeout of " << CRYPTONOTE_DNS_TIMEOUT_MS << "ms");
    boost::chrono::system_clock::time_point deadline = boost::chrono::system_clock::now() + boost::chrono::milliseconds(CRYPTONOTE_DNS_TIMEOUT_MS);
    uint64_t i = 0;
    for (boost::thread& th : dns_threads)
    {
      if (! th.try_join_until(deadline))
      {
        MWARNING("dns_threads[" << i << "] timed out, sending interrupt");
        th.interrupt();
      }
      ++i;
    }

    i = 0;
    for (const auto& result : dns_results)
    {
      MDEBUG("DNS lookup for " << m_seed_nodes_list[i] << ": " << result.size() << " results");
      // if no results for node, thread's lookup likely timed out
      if (result.size())
      {
        for (const auto& addr_string : result)
          full_addrs.insert(addr_string + ":" + std::to_string(cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT));
      }
      ++i;
    }

    // append the fallback nodes if we have too few seed nodes to start with
    if (full_addrs.size() < MIN_WANTED_SEED_NODES)
    {
      if (full_addrs.empty())
        MINFO("DNS seed node lookup either timed out or failed, falling back to defaults");
      else
        MINFO("Not enough DNS seed nodes found, using fallback defaults too");

      for (const auto &peer: get_ip_seed_nodes())
        full_addrs.insert(peer);

      m_fallback_seed_nodes_added.test_and_set();
    }

    return full_addrs;
  }

//-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  int node_server<t_payload_handler>::handle_handshake(int command, typename COMMAND_HANDSHAKE::request& arg, typename COMMAND_HANDSHAKE::response& rsp, p2p_connection_context& context)
  {
    if(arg.node_data.network_id != m_network_id)
    {

      LOG_INFO_CC(context, "WRONG NETWORK AGENT CONNECTED! id=" << arg.node_data.network_id);
      drop_connection(context);
      add_host_fail(context.m_remote_address);
      return 1;
    }

    if(!context.m_is_income)
    {
      LOG_WARNING_CC(context, "COMMAND_HANDSHAKE came not from incoming connection");
      drop_connection(context);
      add_host_fail(context.m_remote_address);
      return 1;
    }

    if(context.peer_id)
    {
      LOG_WARNING_CC(context, "COMMAND_HANDSHAKE came, but seems that connection already have associated peer_id (double COMMAND_HANDSHAKE?)");
      drop_connection(context);
      return 1;
    }

    // test only the remote end's zone, otherwise an attacker could connect to you on clearnet
    // and pass in a tor connection's peer id, and deduce the two are the same if you reject it
    if(arg.node_data.peer_id == m_network.m_shared_state.m_peer_id)
    {
      LOG_DEBUG_CC(context,"Connection to self detected, dropping connection");
      drop_connection(context);
      return 1;
    }

    if (m_network.m_current_number_of_in_peers >= m_network.m_shared_state.m_net_config.max_in_connection_count) // in peers limit
    {
      LOG_WARNING_CC(context, "COMMAND_HANDSHAKE came, but already have max incoming connections, so dropping this one.");
      drop_connection(context);
      return 1;
    }

    if(!m_payload_handler.process_payload_sync_data(arg.payload_data, context, true))
    {
      LOG_WARNING_CC(context, "COMMAND_HANDSHAKE came, but process_payload_sync_data returned false, dropping connection.");
      drop_connection(context);
      return 1;
    }

    if(has_too_many_connections(context.m_remote_address))
    {
      LOG_PRINT_CCONTEXT_L1("CONNECTION FROM " << context.m_remote_address.host_str() << " REFUSED, too many connections from the same address");
      drop_connection(context);
      return 1;
    }

    //associate peer_id with this connection
    context.peer_id = arg.node_data.peer_id;
    context.m_in_timedsync = false;
    context.m_rpc_port = arg.node_data.rpc_port;
    context.m_rpc_credits_per_hash = arg.node_data.rpc_credits_per_hash;
    context.support_flags = arg.node_data.support_flags;

    if(arg.node_data.my_port && m_network.m_can_pingback)
    {
      peerid_type peer_id_l = arg.node_data.peer_id;
      uint32_t port_l = arg.node_data.my_port;
      //try ping to be sure that we can add this peer to peer_list
      try_ping(arg.node_data, context, [peer_id_l, port_l, context, this]()
      {
        CHECK_AND_ASSERT_MES((context.m_remote_address.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id() || context.m_remote_address.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id()), void(),
            "Only IPv4 or IPv6 addresses are supported here");
        //called only(!) if success pinged, update local peerlist
        peerlist_entry pe;
        const epee::net_utils::network_address na = context.m_remote_address;
        if (context.m_remote_address.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
        {
          pe.adr = epee::net_utils::ipv4_network_address(na.as<epee::net_utils::ipv4_network_address>().ip(), port_l);
        }
        else
        {
          pe.adr = epee::net_utils::ipv6_network_address(na.as<epee::net_utils::ipv6_network_address>().ip(), port_l);
        }
        time_t last_seen;
        time(&last_seen);
        pe.last_seen = static_cast<int64_t>(last_seen);
        pe.id = peer_id_l;
        pe.pruning_seed = context.m_pruning_seed;
        pe.rpc_port = context.m_rpc_port;
        pe.rpc_credits_per_hash = context.m_rpc_credits_per_hash;
        m_network.m_peerlist.append_with_peer_white(pe);
        LOG_DEBUG_CC(context, "PING SUCCESS " << context.m_remote_address.host_str() << ":" << port_l);
      });
    }


    //fill response
    m_network.m_peerlist.get_peerlist_head(rsp.local_peerlist_new, true);
    for (const auto &e: rsp.local_peerlist_new)
      context.sent_addresses.insert(e.adr);

    get_local_node_data(rsp.node_data);
    m_payload_handler.get_payload_sync_data(rsp.payload_data);
    LOG_DEBUG_CC(context, "COMMAND_HANDSHAKE");
    return 1;
  }

    //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  int node_server<t_payload_handler>::handle_timed_sync(int command, typename COMMAND_TIMED_SYNC::request& arg, typename COMMAND_TIMED_SYNC::response& rsp, p2p_connection_context& context)
  {
    if(!m_payload_handler.process_payload_sync_data(arg.payload_data, context, false))
    {
      LOG_WARNING_CC(context, "Failed to process_payload_sync_data(), dropping connection");
      drop_connection(context);
      return 1;
    }

    //fill response
    std::vector<peerlist_entry> local_peerlist_new;
    m_network.m_peerlist.get_peerlist_head(local_peerlist_new, true, P2P_DEFAULT_PEERS_IN_HANDSHAKE);

    //only include out peers we did not already send
    rsp.local_peerlist_new.reserve(local_peerlist_new.size());
    for (auto &pe: local_peerlist_new)
    {
      if (!context.sent_addresses.insert(pe.adr).second)
        continue;
      rsp.local_peerlist_new.push_back(std::move(pe));
    }
    m_payload_handler.get_payload_sync_data(rsp.payload_data);

    /* Tor/I2P nodes receiving connections via forwarding (from tor/i2p daemon)
    do not know the address of the connecting peer. This is relayed to them,
    iff the node has setup an inbound hidden service. The other peer will have
    to use the random peer_id value to link the two. My initial thought is that
    the inbound peer should leave the other side marked as `<unknown tor host>`,
    etc., because someone could give faulty addresses over Tor/I2P to get the
    real peer with that identity banned/blacklisted. */

    if(!context.m_is_income)
      rsp.local_peerlist_new.push_back(peerlist_entry{m_network.m_our_address, m_network.m_shared_state.m_peer_id, std::time(nullptr)});

    LOG_DEBUG_CC(context, "COMMAND_TIMED_SYNC");
    return 1;
  }

    //-----------------------------------------------------------------------------------
  template<class t_payload_handler> template<class t_callback>
  bool node_server<t_payload_handler>::try_ping(basic_node_data& node_data, p2p_connection_context& context, const t_callback &cb)
  {
    if(!node_data.my_port)
      return false;

    bool address_ok = (context.m_remote_address.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id() || context.m_remote_address.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id());
    CHECK_AND_ASSERT_MES(address_ok, false,
        "Only IPv4 or IPv6 addresses are supported here");

    const epee::net_utils::network_address na = context.m_remote_address;
    std::string ip;
    uint32_t ipv4_addr = 0;
    boost::asio::ip::address_v6 ipv6_addr;
    bool is_ipv4;
    if (na.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
    {
      ipv4_addr = na.as<const epee::net_utils::ipv4_network_address>().ip();
      ip = epee::string_tools::get_ip_string_from_int32(ipv4_addr);
      is_ipv4 = true;
    }
    else
    {
      ipv6_addr = na.as<const epee::net_utils::ipv6_network_address>().ip();
      ip = ipv6_addr.to_string();
      is_ipv4 = false;
    }
    if(!m_network.m_peerlist.is_host_allowed(context.m_remote_address))
      return false;

    std::string port = epee::string_tools::num_to_string_fast(node_data.my_port);

    epee::net_utils::network_address address;
    if (is_ipv4)
    {
      address = epee::net_utils::network_address{epee::net_utils::ipv4_network_address(ipv4_addr, node_data.my_port)};
    }
    else
    {
      address = epee::net_utils::network_address{epee::net_utils::ipv6_network_address(ipv6_addr, node_data.my_port)};
    }
    peerid_type pr = node_data.peer_id;
    bool r = m_network.m_net_server.connect_async(ip, port, m_network.m_shared_state.m_net_config.ping_connection_timeout, [cb, /*context,*/ address, pr, this](
      const typename net_server::t_connection_context& ping_context,
      const boost::system::error_code& ec)->bool
    {
      if(ec)
      {
        LOG_WARNING_CC(ping_context, "back ping connect failed to " << address.str());
        return false;
      }
      COMMAND_PING::request req;
      COMMAND_PING::response rsp;
      //vc2010 workaround
      /*std::string ip_ = ip;
      std::string port_=port;
      peerid_type pr_ = pr;
      auto cb_ = cb;*/

      // GCC 5.1.0 gives error with second use of uint64_t (peerid_type) variable.
      peerid_type pr_ = pr;

      bool inv_call_res = epee::net_utils::async_invoke_remote_command2<COMMAND_PING::response>(ping_context, COMMAND_PING::ID, req, m_network.m_net_server.get_shared_state(),
        [=](int code, const COMMAND_PING::response& rsp, p2p_connection_context& context)
      {
        if(code <= 0)
        {
          LOG_WARNING_CC(ping_context, "Failed to invoke COMMAND_PING to " << address.str() << "(" << code <<  ", " << epee::levin::get_err_descr(code) << ")");
          return;
        }

        if(rsp.status != PING_OK_RESPONSE_STATUS_TEXT || pr != rsp.peer_id)
        {
          LOG_WARNING_CC(ping_context, "back ping invoke wrong response \"" << rsp.status << "\" from" << address.str() << ", hsh_peer_id=" << pr_ << ", rsp.peer_id=" << peerid_to_string(rsp.peer_id));
          m_network.m_net_server.get_shared_state().close(ping_context.m_connection_id);
          return;
        }
        m_network.m_net_server.get_shared_state().close(ping_context.m_connection_id);
        cb();
      });

      if(!inv_call_res)
      {
        LOG_WARNING_CC(ping_context, "back ping invoke failed to " << address.str());
        m_network.m_net_server.get_shared_state().close(ping_context.m_connection_id);
        return false;
      }
      return true;
    });
    if(!r)
    {
      LOG_WARNING_CC(context, "Failed to call connect_async, network error.");
    }
    return r;
  }

    //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  int node_server<t_payload_handler>::handle_ping(int command, COMMAND_PING::request& arg, COMMAND_PING::response& rsp, p2p_connection_context& context)
  {
    LOG_DEBUG_CC(context, "COMMAND_PING");
    rsp.status = PING_OK_RESPONSE_STATUS_TEXT;
    rsp.peer_id = m_network.m_shared_state.m_peer_id;
    return 1;
  }



   template<class t_payload_handler>
  bool node_server<t_payload_handler>::try_to_connect_and_handshake_with_new_peer(const epee::net_utils::network_address& na, bool just_take_peerlist, uint64_t last_seen_stamp, PeerType peer_type, uint64_t first_seen_stamp)
  {

    if (m_network.m_our_address == na)
      return false;

    if (m_network.m_current_number_of_out_peers == m_network.m_shared_state.m_net_config.max_out_connection_count) // out peers limit
    {
      return false;
    }
    else if (m_network.m_current_number_of_out_peers > m_network.m_shared_state.m_net_config.max_out_connection_count)
    {
      m_network.m_net_server.get_shared_state().del_out_connections(1);
      --(m_network.m_current_number_of_out_peers); // atomic variable, update time = 1s
      return false;
    }


    MDEBUG("Connecting to " << na.str() << "(peer_type=" << peer_type << ", last_seen: "
        << (last_seen_stamp ? epee::misc_utils::get_time_interval_string(time(NULL) - last_seen_stamp):"never")
        << ")...");

    auto con = m_network.connect( na, m_ssl_support);
    if(!con)
    {
      bool is_priority = is_priority_node(na);
      MINFO( "Connect failed to " << na.str()<<","<<is_priority); 
      record_addr_failed(na);
      return false;
    }

    con->m_anchor = peer_type == anchor;
    peerid_type pi = AUTO_VAL_INIT(pi);
    bool res = do_handshake_with_peer(pi, *con, just_take_peerlist);

    if(!res)
    {
      bool is_priority = is_priority_node(na);
      MINFO("Failed to HANDSHAKE with peer " << na.str() << is_priority);
      record_addr_failed(na);
      return false;
    }

    if(just_take_peerlist)
    {
      m_network.m_net_server.get_shared_state().close(con->m_connection_id);
      LOG_DEBUG_CC(*con, "CONNECTION HANDSHAKED OK AND CLOSED.");
      return true;
    }

    peerlist_entry pe_local = AUTO_VAL_INIT(pe_local);
    pe_local.adr = na;
    pe_local.id = pi;
    time_t last_seen;
    time(&last_seen);
    pe_local.last_seen = static_cast<int64_t>(last_seen);
    pe_local.pruning_seed = con->m_pruning_seed;
    pe_local.rpc_port = con->m_rpc_port;
    pe_local.rpc_credits_per_hash = con->m_rpc_credits_per_hash;
    m_network.m_peerlist.append_with_peer_white(pe_local);
    //update last seen and push it to peerlist manager

    anchor_peerlist_entry ape = AUTO_VAL_INIT(ape);
    ape.adr = na;
    ape.id = pi;
    ape.first_seen = first_seen_stamp ? first_seen_stamp : time(nullptr);

    m_network.m_peerlist.append_with_peer_anchor(ape);
    m_network.m_notifier.new_out_connection();

    LOG_DEBUG_CC(*con, "CONNECTION HANDSHAKED OK.");
    return true;
  }

    //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::do_handshake_with_peer(peerid_type& pi, p2p_connection_context& context_, bool just_take_peerlist)
  {

    typename COMMAND_HANDSHAKE::request arg;
    typename COMMAND_HANDSHAKE::response rsp;
    get_local_node_data(arg.node_data);
    m_payload_handler.get_payload_sync_data(arg.payload_data);

    epee::simple_event ev;
    std::atomic<bool> hsh_result(false);
    bool timeout = false;

    bool r = epee::net_utils::async_invoke_remote_command2<typename COMMAND_HANDSHAKE::response>(context_, COMMAND_HANDSHAKE::ID, arg, m_network.m_net_server.get_shared_state(),
      [this, &pi, &ev, &hsh_result, &just_take_peerlist, &context_, &timeout](int code, const typename COMMAND_HANDSHAKE::response& rsp, p2p_connection_context& context)
    {
      epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){ev.raise();});

      if(code < 0)
      {
        LOG_WARNING_CC(context, "COMMAND_HANDSHAKE invoke failed. (" << code <<  ", " << epee::levin::get_err_descr(code) << ")");
        if (code == LEVIN_ERROR_CONNECTION_TIMEDOUT || code == LEVIN_ERROR_CONNECTION_DESTROYED)
          timeout = true;
        return;
      }

      if(rsp.node_data.network_id != m_network_id)
      {
        LOG_WARNING_CC(context, "COMMAND_HANDSHAKE Failed, wrong network!  (" << rsp.node_data.network_id << "), closing connection.");
        return;
      }

      if(!handle_remote_peerlist(rsp.local_peerlist_new, context))
      {
        LOG_WARNING_CC(context, "COMMAND_HANDSHAKE: failed to handle_remote_peerlist(...), closing connection.");
        add_host_fail(context.m_remote_address);
        return;
      }
      hsh_result = true;
      if(!just_take_peerlist)
      {
        if(!m_payload_handler.process_payload_sync_data(rsp.payload_data, context, true))
        {
          LOG_WARNING_CC(context, "COMMAND_HANDSHAKE invoked, but process_payload_sync_data returned false, dropping connection.");
          hsh_result = false;
          return;
        }

        pi = context.peer_id = rsp.node_data.peer_id;
        context.m_rpc_port = rsp.node_data.rpc_port;
        context.m_rpc_credits_per_hash = rsp.node_data.rpc_credits_per_hash;
        context.support_flags = rsp.node_data.support_flags;
        m_network.m_peerlist.set_peer_just_seen(rsp.node_data.peer_id, context.m_remote_address, context.m_pruning_seed, context.m_rpc_port, context.m_rpc_credits_per_hash);

        // move
        if( rsp.node_data.peer_id == m_network.m_shared_state.m_peer_id)
        {
          LOG_DEBUG_CC(context, "Connection to self detected, dropping connection");
          hsh_result = false;
          return;
        }
        LOG_INFO_CC(context, "New connection handshaked, pruning seed " << epee::string_tools::to_string_hex(context.m_pruning_seed));
        LOG_DEBUG_CC(context, " COMMAND_HANDSHAKE INVOKED OK");
      }else
      {
        LOG_DEBUG_CC(context, " COMMAND_HANDSHAKE(AND CLOSE) INVOKED OK");
      }
      context_ = context;
    }, P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT);

    if(r)
    {
      ev.wait();
    }

    if(!hsh_result)
    {
      LOG_WARNING_CC(context_, "COMMAND_HANDSHAKE Failed");
      if (!timeout)
        m_network.m_net_server.get_shared_state().close(context_.m_connection_id);
    }

    return hsh_result;
  }


  //-----------------------------------------------------------------------------------
  template<class t_payload_handler>
  bool node_server<t_payload_handler>::connect_to_seed()
  {
      boost::upgrade_lock<boost::shared_mutex> seed_nodes_upgrade_lock(m_network.m_seed_nodes_lock);

      if (!m_network.m_seed_nodes_initialized)
      {
        const std::uint16_t default_port = cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT;
        boost::upgrade_to_unique_lock<boost::shared_mutex> seed_nodes_lock(seed_nodes_upgrade_lock);
        m_network.m_seed_nodes_initialized = true;
        for (const auto& full_addr : get_seed_nodes())
        {
          // seeds should have hostname converted to IP already
          MDEBUG("Seed node: " << full_addr);
          m_network.m_seed_nodes.push_back(MONERO_UNWRAP(net::get_network_address(full_addr, default_port)));
        }
        MDEBUG("Number of seed nodes: " << m_network.m_seed_nodes.size());
      }

      if (m_network.m_seed_nodes.empty() || m_offline || !m_exclusive_peers.empty())
        return true;

      size_t try_count = 0;
      bool is_connected_to_at_least_one_seed_node = false;
      size_t current_index = crypto::rand_idx(m_network.m_seed_nodes.size());
      while(true)
      {
        if(m_network.m_net_server.is_stop_signal_sent())
          return false;

        peerlist_entry pe_seed{};
        pe_seed.adr = m_network.m_seed_nodes[current_index];
        if (is_peer_used(pe_seed))
          is_connected_to_at_least_one_seed_node = true;
        else if (try_to_connect_and_handshake_with_new_peer(m_network.m_seed_nodes[current_index], true))
          break;
        if(++try_count > m_network.m_seed_nodes.size())
        {
          // only IP zone has fallback (to direct IP) seeds
          if ( !m_fallback_seed_nodes_added.test_and_set())
          {
            MWARNING("Failed to connect to any of seed peers, trying fallback seeds");
            current_index = m_network.m_seed_nodes.size() - 1;
            {
              boost::upgrade_to_unique_lock<boost::shared_mutex> seed_nodes_lock(seed_nodes_upgrade_lock);

              for (const auto &peer: get_ip_seed_nodes())
              {
                MDEBUG("Fallback seed node: " << peer);
                append_net_address(m_network.m_seed_nodes, peer, cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT);
              }
            }
            if (current_index == m_network.m_seed_nodes.size() - 1)
            {
              MWARNING("No fallback seeds, continuing without seeds");
              break;
            }
            // continue for another few cycles
          }
          else
          {
            if (!is_connected_to_at_least_one_seed_node)
              MWARNING("Failed to connect to any of seed peers, continuing without seeds");
            break;
          }
        }
        if(++current_index >= m_network.m_seed_nodes.size())
          current_index = 0;
      }
      return true;
  }
 