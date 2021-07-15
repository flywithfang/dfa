 //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::idle_worker()
  {
    m_connections_maker_interval.do_call(boost::bind(&MyType::connections_maker, this));
    m_peer_handshake_idle_maker_interval.do_call(boost::bind(&MyType::peer_sync_idle_maker, this));
    
    m_gray_peerlist_housekeeping_interval.do_call(boost::bind(&MyType::gray_peerlist_housekeeping, this));
    m_peerlist_store_interval.do_call(boost::bind(&MyType::store_config, this));
    m_incoming_connections_interval.do_call(boost::bind(&MyType::check_incoming_connections, this));
    return true;
  }

   //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::peer_sync_idle_maker()
  {
    MDEBUG("STARTED PEERLIST IDLE HANDSHAKE");
    typedef std::list<std::pair<epee::net_utils::connection_context_base, peerid_type> > local_connects_type;
    local_connects_type cncts;
    for(auto& zone : m_network_zones)
    {
      zone.second.m_net_server.get_config_object().foreach_connection([&](p2p_connection_context& cntxt)
      {
        if(cntxt.peer_id && !cntxt.m_in_timedsync)
        {
          cntxt.m_in_timedsync = true;
          cncts.push_back(local_connects_type::value_type(cntxt, cntxt.peer_id));//do idle sync only with handshaked connections
        }
        return true;
      });
    }

    std::for_each(cncts.begin(), cncts.end(), [&](const typename local_connects_type::value_type& vl){do_peer_timed_sync(vl.first, vl.second);});

    MDEBUG("FINISHED PEERLIST IDLE HANDSHAKE");
    return true;
  }
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::do_peer_timed_sync(const epee::net_utils::connection_context_base& context_, peerid_type peer_id)
  {
    typename COMMAND_TIMED_SYNC::request arg = AUTO_VAL_INIT(arg);
    m_payload_handler.get_payload_sync_data(arg.payload_data);

    network_zone& zone = m_network_zones.at(context_.m_remote_address.get_zone());
    bool r = epee::net_utils::async_invoke_remote_command2<typename COMMAND_TIMED_SYNC::response>(context_, COMMAND_TIMED_SYNC::ID, arg, zone.m_net_server.get_config_object(),
      [this](int code, const typename COMMAND_TIMED_SYNC::response& rsp, p2p_connection_context& context)
    {
      context.m_in_timedsync = false;
      if(code < 0)
      {
        LOG_WARNING_CC(context, "COMMAND_TIMED_SYNC invoke failed. (" << code <<  ", " << epee::levin::get_err_descr(code) << ")");
        return;
      }

      if(!handle_remote_peerlist(rsp.local_peerlist_new, context))
      {
        LOG_WARNING_CC(context, "COMMAND_TIMED_SYNC: failed to handle_remote_peerlist(...), closing connection.");
        m_network_zones.at(context.m_remote_address.get_zone()).m_net_server.get_config_object().close(context.m_connection_id );
        add_host_fail(context.m_remote_address);
      }
      if(!context.m_is_income)
        m_network_zones.at(context.m_remote_address.get_zone()).m_peerlist.set_peer_just_seen(context.peer_id, context.m_remote_address, context.m_pruning_seed, context.m_rpc_port, context.m_rpc_credits_per_hash);
      if (!m_payload_handler.process_payload_sync_data(rsp.payload_data, context, false))
      {
        m_network_zones.at(context.m_remote_address.get_zone()).m_net_server.get_config_object().close(context.m_connection_id );
      }
    });

    if(!r)
    {
      LOG_WARNING_CC(context_, "COMMAND_TIMED_SYNC Failed");
      return false;
    }
    return true;
  }

   //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::handle_remote_peerlist(const std::vector<peerlist_entry>& peerlist, const epee::net_utils::connection_context_base& context)
  {
    if (peerlist.size() > P2P_MAX_PEERS_IN_HANDSHAKE)
    {
      MWARNING(context << "peer sent " << peerlist.size() << " peers, considered spamming");
      return false;
    }
    std::vector<peerlist_entry> peerlist_ = peerlist;
    if(!sanitize_peerlist(peerlist_))
      return false;

    const epee::net_utils::zone zone = context.m_remote_address.get_zone();
    for(const auto& peer : peerlist_)
    {
      if(peer.adr.get_zone() != zone)
      {
        MWARNING(context << " sent peerlist from another zone, dropping");
        return false;
      }
    }

    MINFO(context<< "REMOTE PEERLIST: remote peerlist size=" << peerlist_.size());
    MINFO(context<< "REMOTE PEERLIST: " << ENDL << print_peerlist_to_string(peerlist_));
    CRITICAL_REGION_LOCAL(m_blocked_hosts_lock);
    return m_network_zones.at(context.m_remote_address.get_zone()).m_peerlist.merge_peerlist(peerlist_, [this](const peerlist_entry &pe) {
      return !is_addr_recently_failed(pe.adr) && is_remote_host_allowed(pe.adr);
    });
  }


  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::sanitize_peerlist(std::vector<peerlist_entry>& local_peerlist)
  {
    for (size_t i = 0; i < local_peerlist.size(); ++i)
    {
      bool ignore = false;
      peerlist_entry &be = local_peerlist[i];
      epee::net_utils::network_address &na = be.adr;
      if (na.is_loopback() || na.is_local())
      {
        ignore = true;
      }
      else if (be.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
      {
        const epee::net_utils::ipv4_network_address &ipv4 = na.as<const epee::net_utils::ipv4_network_address>();
        if (ipv4.ip() == 0)
          ignore = true;
        else if (ipv4.port() == be.rpc_port)
          ignore = true;
      }
      if (be.pruning_seed && (be.pruning_seed < tools::make_pruning_seed(1, CRYPTONOTE_PRUNING_LOG_STRIPES) || be.pruning_seed > tools::make_pruning_seed(1ul << CRYPTONOTE_PRUNING_LOG_STRIPES, CRYPTONOTE_PRUNING_LOG_STRIPES)))
        ignore = true;
      if (ignore)
      {
        MDEBUG("Ignoring " << be.adr.str());
        std::swap(local_peerlist[i], local_peerlist[local_peerlist.size() - 1]);
        local_peerlist.resize(local_peerlist.size() - 1);
        --i;
        continue;
      }
      local_peerlist[i].last_seen = 0;
    }
    return true;
  }
 
 ///////////////////////////////////////////////////////////////////////
 
  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::connections_maker()
  {
    using zone_type = epee::net_utils::zone;

    if (m_offline) return true;

    if (!connect_to_peerlist(m_exclusive_peers)) 
      return false;

    if (!m_exclusive_peers.empty())
     return true;

    bool one_succeeded = false;
    for(auto& zone : m_network_zones)
    {
      size_t start_conn_count = get_outgoing_connections_count(zone.second);
      if(!zone.second.m_peerlist.get_white_peers_count() && !connect_to_seed(zone.first))
      {
        continue;
      }

      if (zone.first == zone_type::public_ && !connect_to_peerlist(m_priority_peers)) continue;

      size_t base_expected_white_connections = (zone.second.m_config.m_net_config.max_out_connection_count*P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT)/100;

      // carefully avoid `continue` in nested loop
      
      size_t conn_count = get_outgoing_connections_count(zone.second);
      while(conn_count < zone.second.m_config.m_net_config.max_out_connection_count)
      {
        const size_t expected_white_connections = m_payload_handler.get_next_needed_pruning_stripe().second ? zone.second.m_config.m_net_config.max_out_connection_count : base_expected_white_connections;
        if(conn_count < expected_white_connections)
        {
          //start from anchor list
          while (get_outgoing_connections_count(zone.second) < P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT
            && make_expected_connection(zone.second, PeerType::anchor, P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT))
            ;
          //then do white list
          while (get_outgoing_connections_count(zone.second) < expected_white_connections
            && make_expected_connection(zone.second, white, expected_white_connections))
            ;
          //then do grey list
          while (get_outgoing_connections_count(zone.second) < zone.second.m_config.m_net_config.max_out_connection_count
            && make_expected_connection(zone.second, gray, zone.second.m_config.m_net_config.max_out_connection_count))
            ;
        }else
        {
          //start from grey list
          while (get_outgoing_connections_count(zone.second) < zone.second.m_config.m_net_config.max_out_connection_count
            && make_expected_connection(zone.second, gray, zone.second.m_config.m_net_config.max_out_connection_count))
            ;
          //and then do white list
          while (get_outgoing_connections_count(zone.second) < zone.second.m_config.m_net_config.max_out_connection_count
            && make_expected_connection(zone.second, white, zone.second.m_config.m_net_config.max_out_connection_count));
        }
        if(zone.second.m_net_server.is_stop_signal_sent())
          return false;
        size_t new_conn_count = get_outgoing_connections_count(zone.second);
        if (new_conn_count <= conn_count)
        {
          // we did not make any connection, sleep a bit to avoid a busy loop in case we don't have
          // any peers to try, then break so we will try seeds to get more peers
          boost::this_thread::sleep_for(boost::chrono::seconds(1));
          break;
        }
        conn_count = new_conn_count;
      }//while


      if (start_conn_count == get_outgoing_connections_count(zone.second) && start_conn_count < zone.second.m_config.m_net_config.max_out_connection_count)
      {
        MINFO("Failed to connect to any, trying seeds");
        if (!connect_to_seed(zone.first))
          continue;
      }
      one_succeeded = true;
    }

    return one_succeeded;
  }

   //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::make_expected_connection(network_zone& zone, PeerType peer_type, size_t expected_connections)
  {
    if (m_offline)
      return false;

    std::vector<anchor_peerlist_entry> apl;

    if (peer_type == anchor) {
      zone.m_peerlist.get_and_empty_anchor_peerlist(apl);
    }

    size_t conn_count = get_outgoing_connections_count(zone);
    //add new connections from white peers
    if(conn_count < expected_connections)
    {
      if(zone.m_net_server.is_stop_signal_sent())
        return false;

      MDEBUG("Making expected connection, type " << peer_type << ", " << conn_count << "/" << expected_connections << " connections");

      if (peer_type == anchor && !make_new_connection_from_anchor_peerlist(apl)) {
        return false;
      }

      if (peer_type == white && !make_new_connection_from_peerlist(zone, true)) {
        return false;
      }

      if (peer_type == gray && !make_new_connection_from_peerlist(zone, false)) {
        return false;
      }
    }
    return true;
  }

   //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::make_new_connection_from_anchor_peerlist(const std::vector<anchor_peerlist_entry>& anchor_peerlist)
  {
    for (const auto& pe: anchor_peerlist) {
      MGINFO("Considering connecting (out) to anchor peer: " << peerid_to_string(pe.id) << " " << pe.adr.str());

      if(is_peer_used(pe)) {
        MGINFO("Peer is used");
        continue;
      }

      if(!is_remote_host_allowed(pe.adr)) {
        continue;
      }

      if(is_addr_recently_failed(pe.adr)) {
        continue;
      }

      MGINFO("Selected peer: " << peerid_to_string(pe.id) << " " << pe.adr.str()
                               << "[peer_type=" << anchor
                               << "] first_seen: " << epee::misc_utils::get_time_interval_string(time(NULL) - pe.first_seen));

      if(!try_to_connect_and_handshake_with_new_peer(pe.adr, false, 0, PeerType::anchor, pe.first_seen)) {
        MINFO("Handshake failed");
        continue;
      }

      return true;
    }

    return false;
  }




   //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::make_new_connection_from_peerlist(network_zone& zone, bool use_white_list)
  {
    size_t max_random_index = 0;

    std::set<size_t> tried_peers;

    size_t try_count = 0;
    size_t rand_count = 0;

    zone.m_peerlist.foreach(true,[](const peerlist_entry & e){

        MINFO("peerlist_entry id"<<e.id<<", adr "<<e.adr.str()); return true;
      });   
    while(rand_count < (max_random_index+1)*3 &&  try_count < 10 && !zone.m_net_server.is_stop_signal_sent())
    {
      ++rand_count;
      size_t random_index;
      const uint32_t next_needed_pruning_stripe = m_payload_handler.get_next_needed_pruning_stripe().second;

      // build a set of all the /16 we're connected to, and prefer a peer that's not in that set
      std::set<uint32_t> classB;
      if (&zone == &m_network_zones.at(epee::net_utils::zone::public_)) // at returns reference, not copy
      {
        zone.m_net_server.get_config_object().foreach_connection([&](const p2p_connection_context& cntxt)
        {
          if (cntxt.m_remote_address.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
          {

            const epee::net_utils::network_address na = cntxt.m_remote_address;
            const uint32_t actual_ip = na.as<const epee::net_utils::ipv4_network_address>().ip();
            classB.insert(actual_ip & 0x0000ffff);
          }
          else if (cntxt.m_remote_address.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
          {
            const epee::net_utils::network_address na = cntxt.m_remote_address;
            const boost::asio::ip::address_v6 &actual_ip = na.as<const epee::net_utils::ipv6_network_address>().ip();
            if (actual_ip.is_v4_mapped())
            {
              boost::asio::ip::address_v4 v4ip = make_address_v4_from_v6(actual_ip);
              uint32_t actual_ipv4;
              memcpy(&actual_ipv4, v4ip.to_bytes().data(), sizeof(actual_ipv4));
              classB.insert(actual_ipv4 & ntohl(0xffff0000));
            }
          }
          return true;
        });
      }

      auto get_host_string = [](const epee::net_utils::network_address &address) {
        if (address.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
        {
          boost::asio::ip::address_v6 actual_ip = address.as<const epee::net_utils::ipv6_network_address>().ip();
          if (actual_ip.is_v4_mapped())
          {
            boost::asio::ip::address_v4 v4ip = make_address_v4_from_v6(actual_ip);
            uint32_t actual_ipv4;
            memcpy(&actual_ipv4, v4ip.to_bytes().data(), sizeof(actual_ipv4));
            return epee::net_utils::ipv4_network_address(actual_ipv4, 0).host_str();
          }
        }
        return address.host_str();
      };
      std::unordered_set<std::string> hosts_added;
      std::deque<size_t> filtered;
      const size_t limit = use_white_list ? 20 : std::numeric_limits<size_t>::max();
      for (int step = 0; step < 2; ++step)
      {
        bool skip_duplicate_class_B = step == 0;
        size_t idx = 0, skipped = 0;
        zone.m_peerlist.foreach (use_white_list, [&classB, &filtered, &idx, &skipped, skip_duplicate_class_B, limit, next_needed_pruning_stripe, &hosts_added, &get_host_string](const peerlist_entry &pe)
        {
          if (filtered.size() >= limit)
            return false;
          bool skip = false;
          if (skip_duplicate_class_B && pe.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
          {
            const epee::net_utils::network_address na = pe.adr;
            uint32_t actual_ip = na.as<const epee::net_utils::ipv4_network_address>().ip();
            skip = classB.find(actual_ip & 0x0000ffff) != classB.end();
          }
          else if (skip_duplicate_class_B && pe.adr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
          {
            const epee::net_utils::network_address na = pe.adr;
            const boost::asio::ip::address_v6 &actual_ip = na.as<const epee::net_utils::ipv6_network_address>().ip();
            if (actual_ip.is_v4_mapped())
            {
              boost::asio::ip::address_v4 v4ip = make_address_v4_from_v6(actual_ip);
              uint32_t actual_ipv4;
              memcpy(&actual_ipv4, v4ip.to_bytes().data(), sizeof(actual_ipv4));
              skip = classB.find(actual_ipv4 & ntohl(0xffff0000)) != classB.end();
            }
          }

          // consider each host once, to avoid giving undue inflence to hosts running several nodes
          if (!skip)
          {
            const auto i = hosts_added.find(get_host_string(pe.adr));
            if (i != hosts_added.end())
              skip = true;
          }

          if (skip)
            ++skipped;
          else if (next_needed_pruning_stripe == 0 || pe.pruning_seed == 0)
            filtered.push_back(idx);
          else if (next_needed_pruning_stripe == tools::get_pruning_stripe(pe.pruning_seed))
            filtered.push_front(idx);
          ++idx;
          hosts_added.insert(get_host_string(pe.adr));
          return true;
        });

        if (skipped == 0 || !filtered.empty())
          break;
        if (skipped)
          MDEBUG("Skipping " << skipped << " possible peers as they share a class B with existing peers");
      }
      if (filtered.empty())
      {
        MINFO("No available peer in " << (use_white_list ? "white" : "gray") << " list filtered by " << next_needed_pruning_stripe);
        return false;
      }
      if (use_white_list)
      {
        // if using the white list, we first pick in the set of peers we've already been using earlier
        random_index = get_random_index_with_fixed_probability(std::min<uint64_t>(filtered.size() - 1, 20));
        CRITICAL_REGION_LOCAL(m_used_stripe_peers_mutex);
        if (next_needed_pruning_stripe > 0 && next_needed_pruning_stripe <= (1ul << CRYPTONOTE_PRUNING_LOG_STRIPES) && !m_used_stripe_peers[next_needed_pruning_stripe-1].empty())
        {
          const epee::net_utils::network_address na = m_used_stripe_peers[next_needed_pruning_stripe-1].front();
          m_used_stripe_peers[next_needed_pruning_stripe-1].pop_front();
          for (size_t i = 0; i < filtered.size(); ++i)
          {
            peerlist_entry pe;
            if (zone.m_peerlist.get_white_peer_by_index(pe, filtered[i]) && pe.adr == na)
            {
              MDEBUG("Reusing stripe " << next_needed_pruning_stripe << " peer " << pe.adr.str());
              random_index = i;
              break;
            }
          }
        }
      }
      else
        random_index = crypto::rand_idx(filtered.size());

      CHECK_AND_ASSERT_MES(random_index < filtered.size(), false, "random_index < filtered.size() failed!!");
      random_index = filtered[random_index];
      CHECK_AND_ASSERT_MES(random_index < (use_white_list ? zone.m_peerlist.get_white_peers_count() : zone.m_peerlist.get_gray_peers_count()),
          false, "random_index < peers size failed!!");

      if(tried_peers.count(random_index))
        continue;

      tried_peers.insert(random_index);
      peerlist_entry pe = AUTO_VAL_INIT(pe);
      bool r = use_white_list ? zone.m_peerlist.get_white_peer_by_index(pe, random_index):zone.m_peerlist.get_gray_peer_by_index(pe, random_index);
      CHECK_AND_ASSERT_MES(r, false, "Failed to get random peer from peerlist(white:" << use_white_list << ")");

      ++try_count;

      MINFO("Considering connecting (out) to " << (use_white_list ? "white" : "gray") << " list peer: " <<
          peerid_to_string(pe.id) << " " << pe.adr.str() << ", pruning seed " << epee::string_tools::to_string_hex(pe.pruning_seed) <<
          " (stripe " << next_needed_pruning_stripe << " needed)");

      if(zone.m_our_address == pe.adr)
        continue;

      if(is_peer_used(pe)) {
        MINFO("Peer is used");
        continue;
      }

      if(!is_remote_host_allowed(pe.adr))
        continue;

      if(is_addr_recently_failed(pe.adr))
        continue;

      MDEBUG("Selected peer: " << peerid_to_string(pe.id) << " " << pe.adr.str()
                    << ", pruning seed " << epee::string_tools::to_string_hex(pe.pruning_seed) << " "
                    << "[peer_list=" << (use_white_list ? white : gray)
                    << "] last_seen: " << (pe.last_seen ? epee::misc_utils::get_time_interval_string(time(NULL) - pe.last_seen) : "never"));

      if(!try_to_connect_and_handshake_with_new_peer(pe.adr, false, pe.last_seen, use_white_list ? white : gray)) {
        MINFO("Handshake failed");
        continue;
      }

      return true;
    }
    return false;
  }

  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::block_host(epee::net_utils::network_address addr, time_t seconds, bool add_only)
  {
    if(!addr.is_blockable())
      return false;

    const time_t now = time(nullptr);
    bool added = false;

    CRITICAL_REGION_LOCAL(m_blocked_hosts_lock);
    time_t limit;
    if (now > std::numeric_limits<time_t>::max() - seconds)
      limit = std::numeric_limits<time_t>::max();
    else
      limit = now + seconds;
    const std::string host_str = addr.host_str();
    auto it = m_blocked_hosts.find(host_str);
    if (it == m_blocked_hosts.end())
    {
      m_blocked_hosts[host_str] = limit;
      added = true;
    }
    else if (it->second < limit || !add_only)
      it->second = limit;

    // drop any connection to that address. This should only have to look into
    // the zone related to the connection, but really make sure everything is
    // swept ...
    std::vector<boost::uuids::uuid> conns;
    for(auto& zone : m_network_zones)
    {
      zone.second.m_net_server.get_config_object().foreach_connection([&](const p2p_connection_context& cntxt)
      {
        if (cntxt.m_remote_address.is_same_host(addr))
        {
          conns.push_back(cntxt.m_connection_id);
        }
        return true;
      });

      peerlist_entry pe{};
      pe.adr = addr;
      zone.second.m_peerlist.remove_from_peer_white(pe);
      zone.second.m_peerlist.remove_from_peer_gray(pe);
      zone.second.m_peerlist.remove_from_peer_anchor(addr);

      for (const auto &c: conns)
        zone.second.m_net_server.get_config_object().close(c);

      conns.clear();
    }

    if (added)
      MCLOG_CYAN(el::Level::Info, "global", "Host " << host_str << " blocked.");
    else
      MINFO("Host " << host_str << " block time updated.");
    return true;
  }

  //-----------------------------------------------------------------------------------
  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::block_subnet(const epee::net_utils::ipv4_network_subnet &subnet, time_t seconds)
  {
    const time_t now = time(nullptr);

    CRITICAL_REGION_LOCAL(m_blocked_hosts_lock);
    time_t limit;
    if (now > std::numeric_limits<time_t>::max() - seconds)
      limit = std::numeric_limits<time_t>::max();
    else
      limit = now + seconds;
    m_blocked_subnets[subnet] = limit;

    // drop any connection to that subnet. This should only have to look into
    // the zone related to the connection, but really make sure everything is
    // swept ...
    std::vector<boost::uuids::uuid> conns;
    for(auto& zone : m_network_zones)
    {
      zone.second.m_net_server.get_config_object().foreach_connection([&](const p2p_connection_context& cntxt)
      {
        if (cntxt.m_remote_address.get_type_id() != epee::net_utils::ipv4_network_address::get_type_id())
          return true;
        auto ipv4_address = cntxt.m_remote_address.template as<epee::net_utils::ipv4_network_address>();
        if (subnet.matches(ipv4_address))
        {
          conns.push_back(cntxt.m_connection_id);
        }
        return true;
      });
      for (const auto &c: conns)
        zone.second.m_net_server.get_config_object().close(c);

      conns.clear();
    }

    MCLOG_CYAN(el::Level::Info, "global", "Subnet " << subnet.host_str() << " blocked.");
    return true;
  }



  template<class t_payload_net_handler>
  bool node_server<t_payload_net_handler>::gray_peerlist_housekeeping()
  {
    if (m_offline) return true;
    if (!m_exclusive_peers.empty()) return true;
    if (m_payload_handler.needs_new_sync_connections()) 
      return true;

    for (auto& zone : m_network_zones)
    {
      if (zone.second.m_net_server.is_stop_signal_sent())
        return false;

      if (zone.second.m_connect == nullptr)
        continue;

      peerlist_entry pe{};
      if (!zone.second.m_peerlist.get_random_gray_peer(pe))
        continue;

      if (!check_connection_and_handshake_with_peer(pe.adr, pe.last_seen))
      {
        zone.second.m_peerlist.remove_from_peer_gray(pe);
        LOG_PRINT_L2("PEER EVICTED FROM GRAY PEER LIST: address: " << pe.adr.host_str() << " Peer ID: " << peerid_to_string(pe.id));
      }
      else
      {
        zone.second.m_peerlist.set_peer_just_seen(pe.id, pe.adr, pe.pruning_seed, pe.rpc_port, pe.rpc_credits_per_hash);
        LOG_PRINT_L2("PEER PROMOTED TO WHITE PEER LIST IP address: " << pe.adr.host_str() << " Peer ID: " << peerid_to_string(pe.id));
      }
    }
    return true;
  }
