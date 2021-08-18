 
  
 //------------------------------------------------------------------------------------------------------------------------

  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::on_idle()
  {
     relay_txpool_transactions(); // txpool handles periodic DB checking

    m_idle_peer_kicker.do_call(boost::bind(&t_cryptonote_protocol_handler<t_core>::kick_idle_peers, this));
    m_standby_checker.do_call(boost::bind(&t_cryptonote_protocol_handler<t_core>::check_standby_peers, this));
    m_sync_search_checker.do_call(boost::bind(&t_cryptonote_protocol_handler<t_core>::update_sync_search, this));
    return m_core.on_idle();
  }


  //-----------------------------------------------------------------------------------------------
   template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::relay_txpool_transactions()
  {
    // we attempt to relay txes that should be relayed, but were not
   const auto txs=m_core.get_relayable_transactions();
    if (!txs.empty())
    {
      NOTIFY_NEW_TRANSACTIONS::request public_req{};
      NOTIFY_NEW_TRANSACTIONS::request private_req{};
      NOTIFY_NEW_TRANSACTIONS::request stem_req{};
      for (auto& tx : txs)
      {
        switch (std::get<2>(tx))
        {
          default:
          case relay_method::none:
            break;
          case relay_method::local:
            private_req.txs.push_back(std::move(std::get<1>(tx)));
            break;
          case relay_method::forward:
            stem_req.txs.push_back(std::move(std::get<1>(tx)));
            break;
          case relay_method::block:
          case relay_method::fluff:
          case relay_method::stem:
            public_req.txs.push_back(std::move(std::get<1>(tx)));
            break;
        }
      }

      /* All txes are sent on randomized timers per connection in
         `src/cryptonote_protocol/levin_notify.cpp.` They are either sent with
         "white noise" delays or via  diffusion (Dandelion++ fluff). So
         re-relaying public and private _should_ be acceptable here. */
      const boost::uuids::uuid source = boost::uuids::nil_uuid();
      if (!public_req.txs.empty())
        relay_transactions(public_req, source, epee::net_utils::zone::public_, relay_method::fluff);
      if (!private_req.txs.empty())
        relay_transactions(private_req, source, epee::net_utils::zone::invalid, relay_method::local);
      if (!stem_req.txs.empty())
        relay_transactions(stem_req, source, epee::net_utils::zone::public_, relay_method::stem);
    }
    return true;
  }


//------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::kick_idle_peers()
  {
    MTRACE("Checking for idle peers...");
    m_p2p->for_each_connection([&](cryptonote_peer_context& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags)->bool
    {
      if (peer_cxt.m_state == cryptonote_peer_context::state_synchronizing && peer_cxt.m_last_request_time != boost::date_time::not_a_date_time)
      {
        const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
        const boost::posix_time::time_duration dt = now - peer_cxt.m_last_request_time;
        const auto ms = dt.total_microseconds();
        if (ms > IDLE_PEER_KICK_TIME || (peer_cxt.m_expect_response && ms > NON_RESPONSIVE_PEER_KICK_TIME))
        {
          peer_cxt.m_idle_peer_notification = true;
          MDEBUG(peer_cxt<<"requesting callback");
          ++peer_cxt.m_callback_request_count;
          m_p2p->request_callback(peer_cxt);
          MDEBUG(peer_cxt<<"requesting callback");
        }
      }
      return true;
    });

    return true;
  }

 //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::check_standby_peers()
  {
    m_p2p->for_each_connection([&](cryptonote_peer_context& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags)->bool
    {
      if (peer_cxt.m_state == cryptonote_peer_context::state_standby)
      {
        MDEBUG(peer_cxt<<"requesting callback");
        ++peer_cxt.m_callback_request_count;
        m_p2p->request_callback(peer_cxt);
      }
      return true;
    });
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::update_sync_search()
  {
    const uint64_t target = m_core.get_target_blockchain_height();
    const uint64_t height = m_core.get_current_blockchain_height();
    if (target > height) // if we're not synced yet, don't do it
      return true;

    MTRACE("Checking for outgoing syncing peers...");
    unsigned n_syncing = 0, n_synced = 0;
    boost::uuids::uuid last_synced_peer_id(boost::uuids::nil_uuid());
    m_p2p->for_each_connection([&](cryptonote_peer_context& peer_cxt, nodetool::peerid_type peer_id, uint32_t support_flags)->bool
    {
      if (!peer_id || peer_cxt.m_is_income) // only consider connected outgoing peers
        return true;
      if (peer_cxt.m_state == cryptonote_peer_context::state_synchronizing)
        ++n_syncing;
      if (peer_cxt.m_state == cryptonote_peer_context::state_normal)
      {
        ++n_synced;
        if (!peer_cxt.m_anchor)
          last_synced_peer_id = peer_cxt.m_connection_id;
      }
      return true;
    });
    MTRACE(n_syncing << " syncing, " << n_synced << " synced");

    // if we're at max out peers, and not enough are syncing
    if (n_synced + n_syncing >= m_max_out_peers && n_syncing < P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT && last_synced_peer_id != boost::uuids::nil_uuid())
    {
      if (!m_p2p->for_connection(last_synced_peer_id, [&](cryptonote_peer_context& ctx, nodetool::peerid_type peer_id, uint32_t f)->bool{
        MINFO(ctx << "dropping synced peer, " << n_syncing << " syncing, " << n_synced << " synced");
        drop_connection(ctx, false, false);
        return true;
      }))
        MDEBUG("Failed to find peer we wanted to drop");
    }

    return true;
  }


  //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::on_callback(cryptonote_peer_context& peer_cxt)
  {
    MDEBUG(peer_cxt<<"callback fired");
    CHECK_AND_ASSERT_MES( peer_cxt.m_callback_request_count > 0, false, "false callback fired, but peer_cxt.m_callback_request_count=" << peer_cxt.m_callback_request_count);
    --peer_cxt.m_callback_request_count;

    uint32_t notified = true;
    if (peer_cxt.m_idle_peer_notification.compare_exchange_strong(notified, not notified))
    {
      if (peer_cxt.m_state == cryptonote_peer_context::state_synchronizing && peer_cxt.m_last_request_time != boost::date_time::not_a_date_time)
      {
        const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
        const boost::posix_time::time_duration dt = now - peer_cxt.m_last_request_time;
        const auto ms = dt.total_microseconds();
        if (ms > IDLE_PEER_KICK_TIME || (peer_cxt.m_expect_response && ms > NON_RESPONSIVE_PEER_KICK_TIME))
        {
          if (peer_cxt.m_score-- >= 0)
          {
            MINFO(peer_cxt << " kicking idle peer, last update " << (dt.total_microseconds() / 1.e6) << " seconds ago, expecting " << (int)peer_cxt.m_expect_response);
            peer_cxt.m_last_request_time = boost::date_time::not_a_date_time;
            peer_cxt.m_expect_response = 0;
            peer_cxt.m_expect_height = 0;
            peer_cxt.m_state = cryptonote_peer_context::state_standby; // we'll go back to adding, then (if we can't), download
          }
          else
          {
            MINFO(peer_cxt << "dropping idle peer with negative score");
            drop_connection_with_score(peer_cxt, peer_cxt.m_expect_response == 0 ? 1 : 5, false);
            return false;
          }
        }
      }
    }

    notified = true;
    if (peer_cxt.m_new_stripe_notification.compare_exchange_strong(notified, not notified))
    {
      if (peer_cxt.m_state == cryptonote_peer_context::state_normal)
        peer_cxt.m_state = cryptonote_peer_context::state_synchronizing;
    }

    if(peer_cxt.m_state == cryptonote_peer_context::state_synchronizing && peer_cxt.m_last_request_time == boost::posix_time::not_a_date_time)
    {
      NOTIFY_REQUEST_CHAIN::request r = {};
      peer_cxt.m_needed_objects.clear();
      peer_cxt.m_expect_height = m_core.get_current_blockchain_height();
      m_core.get_short_chain_history(r.block_ids);
      r.prune = m_sync_pruned_blocks;
      peer_cxt.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
      peer_cxt.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
      MDEBUG(peer_cxt<<"-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << r.block_ids.size() );
      post_notify<NOTIFY_REQUEST_CHAIN>(r, peer_cxt);
      MDEBUG(peer_cxt<<"requesting chain");
    }
    else if(peer_cxt.m_state == cryptonote_peer_context::state_standby)
    {
      peer_cxt.m_state = cryptonote_peer_context::state_synchronizing;
      try_add_next_blocks(peer_cxt);
    }

    return true;
  }

   //------------------------------------------------------------------------------------------------------------------------
  template<class t_core>
  bool t_cryptonote_protocol_handler<t_core>::process_payload_sync_data(const CORE_SYNC_DATA& peer_sync_info, cryptonote_peer_context& peer_cxt, bool is_inital)
  {
    if(peer_cxt.m_state == cryptonote_peer_context::state_before_handshake && !is_inital)
      return true;

    if(peer_cxt.m_state == cryptonote_peer_context::state_synchronizing)
      return true;

    // from v6, if the peer advertises a top block version, reject if it's not what it should be (will only work if no voting)
    if (peer_sync_info.current_height > 0)
    {
      const uint8_t version = m_core.get_ideal_hard_fork_version(peer_sync_info.current_height - 1);
      if (version != peer_sync_info.top_version)
      {
        if (version < peer_sync_info.top_version && version == m_core.get_ideal_hard_fork_version())
          MDEBUG(peer_cxt << " peer claims higher version than we think (" <<
              (unsigned)peer_sync_info.top_version << " for " << (peer_sync_info.current_height - 1) << " instead of " << (unsigned)version <<") - we may be forked from the network and a software upgrade may be needed, or that peer is broken or malicious");
        return false;
      }
    }

    // reject weird pruning schemes
    if (peer_sync_info.pruning_seed)
    {
      const uint32_t log_stripes = tools::get_pruning_log_stripes(peer_sync_info.pruning_seed);
      if (log_stripes != CRYPTONOTE_PRUNING_LOG_STRIPES || tools::get_pruning_stripe(peer_sync_info.pruning_seed) > (1u << log_stripes))
      {
        MWARNING(peer_cxt << " peer claim unexpected pruning seed " << epee::string_tools::to_string_hex(peer_sync_info.pruning_seed) << ", disconnecting");
        return false;
      }
    }

    if (peer_sync_info.current_height < peer_cxt.m_remote_blockchain_height)
    {
      MINFO(peer_cxt << "Claims " << peer_sync_info.current_height << ", claimed " << peer_cxt.m_remote_blockchain_height << " before");
      hit_score(peer_cxt, 1);
    }
    peer_cxt.m_remote_blockchain_height = peer_sync_info.current_height;
    peer_cxt.m_pruning_seed = peer_sync_info.pruning_seed;

    const uint64_t target = m_core.get_target_blockchain_height()|| m_core.get_current_blockchain_height();

    if(m_core.have_block(peer_sync_info.top_id))
    {
      peer_cxt.m_state = cryptonote_peer_context::state_normal;
      if(is_inital  && peer_sync_info.current_height >= target && target == m_core.get_current_blockchain_height())
        on_connection_synchronized();
      return true;
    }

  
    if (peer_sync_info.current_height > target)
    {
    /* As I don't know if accessing peer_sync_info from core could be a good practice,
    I prefer pushing target height to the core at the same time it is pushed to the user.
    Nz. */
    int64_t diff = static_cast<int64_t>(peer_sync_info.current_height) - static_cast<int64_t>(m_core.get_current_blockchain_height());
    uint64_t abs_diff = std::abs(diff);
    MCLOG(is_inital ? el::Level::Info : el::Level::Debug, "global", el::Color::Yellow, peer_cxt <<  "Sync data returned a new top block candidate: " << m_core.get_current_blockchain_height() << " -> " << peer_sync_info.current_height
      << " [Your node is " << abs_diff << " blocks (" << tools::get_human_readable_timespan(abs_diff * DIFFICULTY_TARGET) << ") "<< (0 <= diff ? std::string("behind") : std::string("ahead"))<< "] " << ENDL << "SYNCHRONIZATION started");

      if (peer_sync_info.current_height >= m_core.get_current_blockchain_height() + 5) // don't switch to unsafe mode just for a few blocks
      {
        m_core.safesyncmode(false);
      }
      if (m_core.get_target_blockchain_height() == 0) // only when sync starts
      {
        m_sync_timer.resume();
        m_sync_timer.reset();
        m_add_timer.pause();
        m_add_timer.reset();
        m_last_add_end_time = 0;
        m_sync_spans_downloaded = 0;
        m_sync_old_spans_downloaded = 0;
        m_sync_bad_spans_downloaded = 0;
        m_sync_download_chain_size = 0;
        m_sync_download_objects_size = 0;
      }
      m_core.set_target_blockchain_height(peer_sync_info.current_height);
    }
    MINFO(peer_cxt << "Remote blockchain height: " << peer_sync_info.current_height << ", id: " << peer_sync_info.top_id);

    if (m_no_sync)
    {
      peer_cxt.m_state = cryptonote_peer_context::state_normal;
      return true;
    }

    peer_cxt.m_state = cryptonote_peer_context::state_synchronizing;
    //let the socket to send response to handshake, but request callback, to let send request data after response
    MDEBUG(peer_cxt<<"requesting callback");
    ++peer_cxt.m_callback_request_count;
    m_p2p->request_callback(peer_cxt);
    MDEBUG(peer_cxt<<"requesting callback");
    peer_cxt.m_num_requested = 0;
    return true;
  }