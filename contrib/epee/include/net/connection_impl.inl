
PRAGMA_WARNING_PUSH
namespace epee
{
namespace net_utils
{
  template<typename T>
  T& check_and_get(std::shared_ptr<T>& ptr)
  {
    CHECK_AND_ASSERT_THROW_MES(bool(ptr), "shared_state cannot be null");
    return *ptr;
  }

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
PRAGMA_WARNING_DISABLE_VS(4355)

  template<class t_wire_handler>
  connection<t_wire_handler>::connection( boost::asio::io_service& io_service,std::shared_ptr<shared_state> state,t_connection_type connection_type, ssl_support_t ssl_support	)
	: connection(boost::asio::ip::tcp::socket{io_service}, std::move(state), connection_type, ssl_support)
  {
  }

  template<class t_wire_handler>
  connection<t_wire_handler>::connection( boost::asio::ip::tcp::socket&& sock,std::shared_ptr<shared_state> state,t_connection_type connection_type,ssl_support_t ssl_support	)
	: connection_basic(std::move(sock), state, ssl_support),
		m_wire_handler(this, check_and_get(state), m_con_context),
		buffer_ssl_init_fill(0),
		m_connection_type( connection_type ),
		m_throttle_speed_in("speed_in", "throttle_speed_in"),
		m_throttle_speed_out("speed_out", "throttle_speed_out"),
		m_timer(GET_IO_SERVICE(socket_)),
		m_local(false),
		m_ready_to_close(false)
  {
    MDEBUG("test, connection constructor set m_connection_type="<<m_connection_type);
  }

PRAGMA_WARNING_DISABLE_VS(4355)
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  connection<t_wire_handler>::~connection() noexcept(false)
  {
    if(!m_was_shutdown)
    {
      MINFO("[sock " << socket().native_handle() << "] Socket destroyed without shutdown.");
      shutdown();
    }

    MINFO("[sock " << socket().native_handle() << "] Socket destroyed");
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  boost::shared_ptr<connection<t_wire_handler> > connection<t_wire_handler>::safe_shared_from_this()
  {
    try
    {
      return connection<t_wire_handler>::shared_from_this();
    }
    catch (const boost::bad_weak_ptr&)
    {
      // It happens when the connection is being deleted
      return boost::shared_ptr<connection<t_wire_handler> >();
    }
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool connection<t_wire_handler>::start(bool is_income, bool is_multithreaded)
  {
    TRY_ENTRY();

    boost::system::error_code ec;
    auto remote_ep = socket().remote_endpoint(ec);
    CHECK_AND_NO_ASSERT_MES(!ec, false, "Failed to get remote endpoint: " << ec.message() << ':' << ec.value());
    CHECK_AND_NO_ASSERT_MES(remote_ep.address().is_v4() || remote_ep.address().is_v6(), false, "only IPv4 and IPv6 supported here");

    if (remote_ep.address().is_v4())
    {
      const unsigned long ip_ = boost::asio::detail::socket_ops::host_to_network_long(remote_ep.address().to_v4().to_ulong());
      return start(is_income, is_multithreaded, ipv4_network_address{uint32_t(ip_), remote_ep.port()});
    }
    else
    {
      const auto ip_ = remote_ep.address().to_v6();
      return start(is_income, is_multithreaded, ipv6_network_address{ip_, remote_ep.port()});
    }
    CATCH_ENTRY_L0("connection<t_wire_handler>::start()", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool connection<t_wire_handler>::start(bool is_income, bool is_multithreaded, network_address real_remote)
  {
    TRY_ENTRY();

    // Use safe_shared_from_this, because of this is public method and it can be called on the object being deleted
    auto self = safe_shared_from_this();
    if(!self)
      return false;

    m_is_multithreaded = is_multithreaded;
    m_local = real_remote.is_loopback() || real_remote.is_local();

    // create a random uuid, we don't need crypto strength here
    const boost::uuids::uuid random_uuid = boost::uuids::random_generator()();

    m_con_context = t_connection_context{};
    bool ssl = m_ssl_support == epee::net_utils::ssl_support_t::e_ssl_support_enabled;
    m_con_context.set_details(random_uuid, std::move(real_remote), is_income, ssl);

    boost::system::error_code ec;
    auto local_ep = socket().local_endpoint(ec);
    CHECK_AND_NO_ASSERT_MES(!ec, false, "Failed to get local endpoint: " << ec.message() << ':' << ec.value());

    MINFO("connection start() [sock " << socket_.native_handle() << "] from " << print_connection_context_short(m_con_context) <<
      " to " << local_ep.address().to_string() << ':' << local_ep.port() <<
      ", total sockets objects " << get_state().sock_count);

    if(static_cast<shared_state&>(get_state()).pfilter && !static_cast<shared_state&>(get_state()).pfilter->is_remote_host_allowed(m_con_context.m_remote_address))
    {
      MINFO("[sock " << socket().native_handle() << "] host denied " << m_con_context.m_remote_address.host_str() << ", shutdowning connection");
      close();
      return false;
    }

    m_host = m_con_context.m_remote_address.host_str();
    try { host_count(m_host, 1); } catch(...) { /* ignore */ }

    m_wire_handler.after_init_connection();

    reset_timer(boost::posix_time::milliseconds(m_local ? NEW_CONNECTION_TIMEOUT_LOCAL : NEW_CONNECTION_TIMEOUT_REMOTE), false);

    // first read on the raw socket to detect SSL for the server
    buffer_ssl_init_fill = 0;
    if (is_income && m_ssl_support != epee::net_utils::ssl_support_t::e_ssl_support_disabled)
      socket().async_receive(boost::asio::buffer(buffer_),
        strand_.wrap(std::bind(&MyType::handle_receive, self,
            std::placeholders::_1,std::placeholders::_2)));
    else
      async_read_some(boost::asio::buffer(buffer_),
        strand_.wrap(std::bind(&MyType::handle_read, self,std::placeholders::_1,std::placeholders::_2)));

  	boost::asio::ip::tcp::no_delay noDelayOption(false);
  	socket().set_option(noDelayOption);
	
    return true;

    CATCH_ENTRY_L0("connection<t_wire_handler>::start()", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool connection<t_wire_handler>::request_callback()
  {
    TRY_ENTRY();
    MINFO("[" << print_connection_context_short(m_con_context) << "] request_callback");
    // Use safe_shared_from_this, because of this is public method and it can be called on the object being deleted
    auto self = safe_shared_from_this();
    if(!self)
      return false;

    strand_.post(boost::bind(&connection<t_wire_handler>::call_back_starter, self));
    CATCH_ENTRY_L0("connection<t_wire_handler>::request_callback()", false);
    return true;
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  boost::asio::io_service& connection<t_wire_handler>::get_io_service()
  {;
    auto & s = socket();
    return ((boost::asio::io_context&)(s).get_executor().context());
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool connection<t_wire_handler>::add_ref()
  {
    TRY_ENTRY();

    // Use safe_shared_from_this, because of this is public method and it can be called on the object being deleted
    auto self = safe_shared_from_this();
    if(!self)
      return false;
    //MINFO("[sock " << socket().native_handle() << "] add_ref, m_peer_number=" << mI->m_peer_number);
    CRITICAL_REGION_LOCAL(self->m_self_refs_lock);
    //MINFO("[sock " << socket().native_handle() << "] add_ref 2, m_peer_number=" << mI->m_peer_number);
    ++m_reference_count;
    m_self_ref = std::move(self);
    return true;
    CATCH_ENTRY_L0("connection<t_wire_handler>::add_ref()", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool connection<t_wire_handler>::release()
  {
    TRY_ENTRY();
    boost::shared_ptr<connection<t_wire_handler> >  back_connection_copy;
    LOG_TRACE_CC(m_con_context, "[sock " << socket().native_handle() << "] release");
    CRITICAL_REGION_BEGIN(m_self_refs_lock);
    CHECK_AND_ASSERT_MES(m_reference_count, false, "[sock " << socket().native_handle() << "] m_reference_count already at 0 at connection<t_wire_handler>::release() call");
    // is this the last reference?
    if (--m_reference_count == 0) {
        // move the held reference to a local variable, keeping the object alive until the function terminates
        std::swap(back_connection_copy, m_self_ref);
    }
    CRITICAL_REGION_END();
    return true;
    CATCH_ENTRY_L0("connection<t_wire_handler>::release()", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void connection<t_wire_handler>::call_back_starter()
  {
    TRY_ENTRY();
    MINFO("[" << print_connection_context_short(m_con_context) << "] fired_callback");

    m_wire_handler.handle_qued_callback();
    
    CATCH_ENTRY_L0("connection<t_wire_handler>::call_back_starter()", void());
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void connection<t_wire_handler>::save_dbg_log()
  {
    std::string address, port;
    boost::system::error_code e;

    boost::asio::ip::tcp::endpoint endpoint = socket().remote_endpoint(e);
    if (e)
    {
      address = "<not connected>";
      port = "<not connected>";
    }
    else
    {
      address = endpoint.address().to_string();
      port = boost::lexical_cast<std::string>(endpoint.port());
    }
    MDEBUG("save_dbg_log  connection type " << to_string( m_connection_type ) << " "
        << socket().local_endpoint().address().to_string() << ":" << socket().local_endpoint().port()
        << " <--> " << m_con_context.m_remote_address.str() << " (via " << address << ":" << port << ")");
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void connection<t_wire_handler>::handle_read(const boost::system::error_code& e,
    std::size_t bytes_transferred)
  {
    TRY_ENTRY();
    //_info("[sock " << socket().native_handle() << "] Async read calledback.");
    
    if (m_was_shutdown)
        return;

    if (!e)
    {
        double current_speed_down;
		{
			CRITICAL_REGION_LOCAL(m_throttle_speed_in_mutex);
			m_throttle_speed_in.handle_trafic_exact(bytes_transferred);
			current_speed_down = m_throttle_speed_in.get_current_speed();
		}
        m_con_context.m_current_speed_down = current_speed_down;
        m_con_context.m_max_speed_down = std::max(m_con_context.m_max_speed_down, current_speed_down);
    
    {
			CRITICAL_REGION_LOCAL(	epee::net_utils::network_throttle_manager::network_throttle_manager::m_lock_get_global_throttle_in );
			epee::net_utils::network_throttle_manager::network_throttle_manager::get_global_throttle_in().handle_trafic_exact(bytes_transferred);
		}

		double delay=0; // will be calculated - how much we should sleep to obey speed limit etc


		if (speed_limit_is_enabled()) {
			do // keep sleeping if we should sleep
			{
				{ //_scope_dbg1("CRITICAL_REGION_LOCAL");
					CRITICAL_REGION_LOCAL(	epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_in );
					delay = epee::net_utils::network_throttle_manager::get_global_throttle_in().get_sleep_time_after_tick( bytes_transferred );
				}

				if (m_was_shutdown)
					return;
				
				delay *= 0.5;
				long int ms = (long int)(delay * 100);
				if (ms > 0) {
					reset_timer(boost::posix_time::milliseconds(ms + 1), true);
					boost::this_thread::sleep_for(boost::chrono::milliseconds(ms));
				}
			} while(delay > 0);
		} // any form of sleeping
		
      //_info("[sock " << socket().native_handle() << "] RECV " << bytes_transferred);
      logger_handle_net_read(bytes_transferred);
      m_con_context.m_last_recv = time(NULL);
      m_con_context.m_recv_cnt += bytes_transferred;
      m_ready_to_close = false;
      bool recv_res = m_wire_handler.handle_recv(buffer_.data(), bytes_transferred);
      if(!recv_res)
      {  
        //_info("[sock " << socket().native_handle() << "] protocol_want_close");
        //some error in protocol, protocol handler ask to close connection
        boost::interprocess::ipcdetail::atomic_write32(&m_want_close_connection, 1);
        bool do_shutdown = false;
        CRITICAL_REGION_BEGIN(m_send_que_lock);
        if(!m_send_que.size())
          do_shutdown = true;
        CRITICAL_REGION_END();
        if(do_shutdown)
          shutdown();
      }else
      {
        reset_timer(get_timeout_from_bytes_read(bytes_transferred), false);
        async_read_some(boost::asio::buffer(buffer_),
          strand_.wrap(
            boost::bind(&MyType::handle_read, connection<t_wire_handler>::shared_from_this(),
              boost::asio::placeholders::error,
              boost::asio::placeholders::bytes_transferred)));
        //_info("[sock " << socket().native_handle() << "]Async read requested.");
      }
    }else
    {
      MINFO("[sock " << socket().native_handle() << "] Some not success at read: " << e.message() << ':' << e.value());
      if(e.value() != 2)
      {
        MINFO("[sock " << socket().native_handle() << "] Some problems at read: " << e.message() << ':' << e.value());
        shutdown();
      }
      else
      {
        MINFO("[sock " << socket().native_handle() << "] peer closed connection");
        bool do_shutdown = false;
        CRITICAL_REGION_BEGIN(m_send_que_lock);
        if(!m_send_que.size())
          do_shutdown = true;
        CRITICAL_REGION_END();
        if (m_ready_to_close || do_shutdown)
          shutdown();
      }
      m_ready_to_close = true;
    }
    // If an error occurs then no new asynchronous operations are started. This
    // means that all shared_ptr references to the connection object will
    // disappear and the object will be destroyed automatically after this
    // handler returns. The connection class's destructor closes the socket.
    CATCH_ENTRY_L0("connection<t_wire_handler>::handle_read", void());
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void connection<t_wire_handler>::handle_receive(const boost::system::error_code& e,
    std::size_t bytes_transferred)
  {
    TRY_ENTRY();

    if (m_was_shutdown) return;

    if (e)
    {
      // offload the error case
      handle_read(e, bytes_transferred);
      return;
    }

    buffer_ssl_init_fill += bytes_transferred;
    MTRACE("we now have " << buffer_ssl_init_fill << "/" << get_ssl_magic_size() << " bytes needed to detect SSL");
    if (buffer_ssl_init_fill < get_ssl_magic_size())
    {
      socket().async_receive(boost::asio::buffer(buffer_.data() + buffer_ssl_init_fill, buffer_.size() - buffer_ssl_init_fill),
        strand_.wrap(
          boost::bind(&connection<t_wire_handler>::handle_receive, connection<t_wire_handler>::shared_from_this(),
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred)));
      return;
    }

    // detect SSL
    if (m_ssl_support == epee::net_utils::ssl_support_t::e_ssl_support_autodetect)
    {
      if (is_ssl((const unsigned char*)buffer_.data(), buffer_ssl_init_fill))
      {
        MDEBUG("That looks like SSL");
        m_ssl_support = epee::net_utils::ssl_support_t::e_ssl_support_enabled; // read/write to the SSL socket
      }
      else
      {
        MDEBUG("That does not look like SSL");
        m_ssl_support = epee::net_utils::ssl_support_t::e_ssl_support_disabled; // read/write to the raw socket
      }
    }

    if (m_ssl_support == epee::net_utils::ssl_support_t::e_ssl_support_enabled)
    {
      // Handshake
      if (!handshake(boost::asio::ssl::stream_base::server, boost::asio::const_buffer(buffer_.data(), buffer_ssl_init_fill)))
      {
        MERROR("SSL handshake failed");
        boost::interprocess::ipcdetail::atomic_write32(&m_want_close_connection, 1);
        m_ready_to_close = true;
        bool do_shutdown = false;
        CRITICAL_REGION_BEGIN(m_send_que_lock);
        if(!m_send_que.size())
          do_shutdown = true;
        CRITICAL_REGION_END();
        if(do_shutdown)
          shutdown();
        return;
      }
    }
    else
    {
      handle_read(e, buffer_ssl_init_fill);
      return;
    }

    async_read_some(boost::asio::buffer(buffer_),
      strand_.wrap(
        boost::bind(&MyType::handle_read, connection<t_wire_handler>::shared_from_this(),
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred)));

    // If an error occurs then no new asynchronous operations are started. This
    // means that all shared_ptr references to the connection object will
    // disappear and the object will be destroyed automatically after this
    // handler returns. The connection class's destructor closes the socket.
    CATCH_ENTRY_L0("connection<t_wire_handler>::handle_receive", void());
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool connection<t_wire_handler>::call_run_once_service_io()
  {
    TRY_ENTRY();
    if(!m_is_multithreaded)
    {
      //single thread model, we can wait in blocked call
      size_t cnt = GET_IO_SERVICE(socket()).run_one();
      if(!cnt)//service is going to quit
        return false;
    }else
    {
      //multi thread model, we can't(!) wait in blocked call
      //so we make non blocking call and releasing CPU by calling sleep(0); 
      //if no handlers were called
      //TODO: Maybe we need to have have critical section + event + callback to upper protocol to
      //ask it inside(!) critical region if we still able to go in event wait...
      size_t cnt = ((boost::asio::io_context&)(socket()).get_executor().context()).poll_one();
      if(!cnt)
        misc_utils::sleep_no_w(1);
    }
    
    return true;
    CATCH_ENTRY_L0("connection<t_wire_handler>::call_run_once_service_io", false);
  }
  //---------------------------------------------------------------------------------
    template<class t_wire_handler>
  bool connection<t_wire_handler>::do_send(byte_slice message) {
    TRY_ENTRY();

    // Use safe_shared_from_this, because of this is public method and it can be called on the object being deleted
    auto self = safe_shared_from_this();
    if (!self) return false;
    if (m_was_shutdown) return false;
		// TODO avoid copy

		std::uint8_t const* const message_data = message.data();
		const std::size_t message_size = message.size();

		const double factor = 32; // TODO config
		typedef long long signed int t_safe; // my t_size to avoid any overunderflow in arithmetic
		const t_safe chunksize_good = (t_safe)( 1024 * std::max(1.0,factor) );
        const t_safe chunksize_max = chunksize_good * 2 ;
		const bool allow_split = (m_connection_type == e_connection_type_RPC) ? false : true; // do not split RPC data

        CHECK_AND_ASSERT_MES(! (chunksize_max<0), false, "Negative chunksize_max" ); // make sure it is unsigned before removin sign with cast:
        long long unsigned int chunksize_max_unsigned = static_cast<long long unsigned int>( chunksize_max ) ;

        if (allow_split && (message_size > chunksize_max_unsigned)) {
			{ // LOCK: chunking
    		epee::critical_region_t<decltype(m_chunking_lock)> send_guard(m_chunking_lock); // *** critical *** 

				MDEBUG("do_send() will SPLIT into small chunks, from packet="<<message_size<<" B for ptr="<<(const void*)message_data);
				// 01234567890 
				// ^^^^        (pos=0, len=4)     ;   pos:=pos+len, pos=4
				//     ^^^^    (pos=4, len=4)     ;   pos:=pos+len, pos=8
				//         ^^^ (pos=8, len=4)    ;   

				// const size_t bufsize = chunksize_good; // TODO safecast
				// char* buf = new char[ bufsize ];

				bool all_ok = true;
				while (!message.empty()) {
					byte_slice chunk = message.take_slice(chunksize_good);

					MDEBUG("chunk_start="<<(void*)chunk.data()<<" ptr="<<(const void*)message_data<<" pos="<<(chunk.data() - message_data));
					MDEBUG("part of " << message.size() << ": pos="<<(chunk.data() - message_data) << " len="<<chunk.size());

					bool ok = do_send_chunk(std::move(chunk)); // <====== ***

					all_ok = all_ok && ok;
					if (!all_ok) {
						MDEBUG("do_send() DONE ***FAILED*** from packet="<<message_size<<" B for ptr="<<(const void*)message_data);
						MDEBUG("do_send() SEND was aborted in middle of big package - this is mostly harmless "
							<< " (e.g. peer closed connection) but if it causes trouble tell us at #monero-dev. " << message_size);
						return false; // partial failure in sending
					}
					// (in catch block, or uniq pointer) delete buf;
				} // each chunk

				MDEBUG("do_send() DONE SPLIT from packet="<<message_size<<" B for ptr="<<(const void*)message_data);

                MDEBUG("do_send() m_connection_type = " << m_connection_type);

				return all_ok; // done - e.g. queued - all the chunks of current do_send call
			} // LOCK: chunking
		} // a big block (to be chunked) - all chunks
		else { // small block
			return do_send_chunk(std::move(message)); // just send as 1 big chunk
		}

    CATCH_ENTRY_L0("connection<t_wire_handler>::do_send", false);
	} // do_send()

  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool connection<t_wire_handler>::do_send_chunk(byte_slice chunk)
  {
    TRY_ENTRY();
    // Use safe_shared_from_this, because of this is public method and it can be called on the object being deleted
    auto self = safe_shared_from_this();
    if(!self)
      return false;
    if(m_was_shutdown)
      return false;
    double current_speed_up;
    {
		CRITICAL_REGION_LOCAL(m_throttle_speed_out_mutex);
		m_throttle_speed_out.handle_trafic_exact(chunk.size());
		current_speed_up = m_throttle_speed_out.get_current_speed();
	}
    m_con_context.m_current_speed_up = current_speed_up;
    m_con_context.m_max_speed_up = std::max(m_con_context.m_max_speed_up, current_speed_up);

    //_info("[sock " << socket().native_handle() << "] SEND " << cb);
    m_con_context.m_last_send = time(NULL);
    m_con_context.m_send_cnt += chunk.size();
    //some data should be wrote to stream
    //request complete
    
    // No sleeping here; sleeping is done once and for all in "handle_write"

    m_send_que_lock.lock(); // *** critical ***
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){m_send_que_lock.unlock();});

    long int retry=0;
    const long int retry_limit = 5*4;
    while (m_send_que.size() > ABSTRACT_SERVER_SEND_QUE_MAX_COUNT)
    {
        retry++;

        /* if ( ::cryptonote::core::get_is_stopping() ) { // TODO re-add fast stop
            _fact("ABORT queue wait due to stopping");
            return false; // aborted
        }*/

        using engine = std::mt19937;

        engine rng;
        std::random_device dev;
        std::seed_seq::result_type rand[engine::state_size]{};  // Use complete bit space

        std::generate_n(rand, engine::state_size, std::ref(dev));
        std::seed_seq seed(rand, rand + engine::state_size);
        rng.seed(seed);

        long int ms = 250 + (rng() % 50);
        MDEBUG("Sleeping because QUEUE is FULL, in " << __FUNCTION__ << " for " << ms << " ms before packet_size="<<chunk.size()); // XXX debug sleep
        m_send_que_lock.unlock();
        boost::this_thread::sleep(boost::posix_time::milliseconds( ms ) );
        m_send_que_lock.lock();
        _dbg1("sleep for queue: " << ms);
	if (m_was_shutdown)
		return false;

        if (retry > retry_limit) {
            MWARNING("send que size is more than ABSTRACT_SERVER_SEND_QUE_MAX_COUNT(" << ABSTRACT_SERVER_SEND_QUE_MAX_COUNT << "), shutting down connection");
            shutdown();
            return false;
        }
    }

    m_send_que.push_back(std::move(chunk));

    if(m_send_que.size() > 1)
    { // active operation should be in progress, nothing to do, just wait last operation callback
        auto size_now = m_send_que.back().size();
        MDEBUG("do_send_chunk() NOW just queues: packet="<<size_now<<" B, is added to queue-size="<<m_send_que.size());
        //do_send_handler_delayed( ptr , size_now ); // (((H))) // empty function
      
      LOG_TRACE_CC(m_con_context, "[sock " << socket().native_handle() << "] Async send requested " << m_send_que.front().size());
    }
    else
    { // no active operation

        if(m_send_que.size()!=1)
        {
            _erro("Looks like no active operations, but send que size != 1!!");
            return false;
        }

        auto size_now = m_send_que.front().size();
        MDEBUG("do_send_chunk() NOW SENSD: packet="<<size_now<<" B");
        if (speed_limit_is_enabled())
			do_send_handler_write( m_send_que.back().data(), m_send_que.back().size() ); // (((H)))

        CHECK_AND_ASSERT_MES( size_now == m_send_que.front().size(), false, "Unexpected queue size");
        reset_timer(get_default_timeout(), false);
            async_write(boost::asio::buffer(m_send_que.front().data(), size_now ) ,
                                 strand_.wrap(
                                 std::bind(&connection<t_wire_handler>::handle_write, self, std::placeholders::_1, std::placeholders::_2)
                                 )
                                 );
        //MINFO("(chunk): " << size_now);
        //logger_handle_net_write(size_now);
        //_info("[sock " << socket().native_handle() << "] Async send requested " << m_send_que.front().size());
    }
    
    //do_send_handler_stop( ptr , cb ); // empty function

    return true;

    CATCH_ENTRY_L0("connection<t_wire_handler>::do_send_chunk", false);
  } // do_send_chunk
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  boost::posix_time::milliseconds connection<t_wire_handler>::get_default_timeout()
  {
    unsigned count;
    try { count = host_count(m_host); } catch (...) { count = 0; }
    const unsigned shift = get_state().sock_count > AGGRESSIVE_TIMEOUT_THRESHOLD ? std::min(std::max(count, 1u) - 1, 8u) : 0;
    boost::posix_time::milliseconds timeout(0);
    if (m_local)
      timeout = boost::posix_time::milliseconds(DEFAULT_TIMEOUT_MS_LOCAL >> shift);
    else
      timeout = boost::posix_time::milliseconds(DEFAULT_TIMEOUT_MS_REMOTE >> shift);
    return timeout;
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  boost::posix_time::milliseconds connection<t_wire_handler>::get_timeout_from_bytes_read(size_t bytes)
  {
    boost::posix_time::milliseconds ms = (boost::posix_time::milliseconds)(unsigned)(bytes * TIMEOUT_EXTRA_MS_PER_BYTE);
    const auto cur = m_timer.expires_from_now().total_milliseconds();
    if (cur > 0)
      ms += (boost::posix_time::milliseconds)cur;
    if (ms > get_default_timeout())
      ms = get_default_timeout();
    return ms;
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  unsigned int connection<t_wire_handler>::host_count(const std::string &host, int delta)
  {
    static boost::mutex hosts_mutex;
    CRITICAL_REGION_LOCAL(hosts_mutex);
    static std::map<std::string, unsigned int> hosts;
    unsigned int &val = hosts[host];
    if (delta > 0)
      MTRACE("New connection from host " << host << ": " << val);
    else if (delta < 0)
      MTRACE("Closed connection from host " << host << ": " << val);
    CHECK_AND_ASSERT_THROW_MES(delta >= 0 || val >= (unsigned)-delta, "Count would go negative");
    CHECK_AND_ASSERT_THROW_MES(delta <= 0 || val <= std::numeric_limits<unsigned int>::max() - (unsigned)delta, "Count would wrap");
    val += delta;
    return val;
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void connection<t_wire_handler>::reset_timer(boost::posix_time::milliseconds ms, bool add)
  {
    const auto tms = ms.total_milliseconds();
    if (tms < 0 || (add && tms == 0))
    {
      MWARNING("Ignoring negative timeout " << ms);
      return;
    }
    MTRACE((add ? "Adding" : "Setting") << " " << ms << " expiry");
    auto self = safe_shared_from_this();
    if(!self)
    {
      MERROR("Resetting timer on a dead object");
      return;
    }
    if (m_was_shutdown)
    {
      MERROR("Setting timer on a shut down object");
      return;
    }
    if (add)
    {
      const auto cur = m_timer.expires_from_now().total_milliseconds();
      if (cur > 0)
        ms += (boost::posix_time::milliseconds)cur;
    }
    m_timer.expires_from_now(ms);
    m_timer.async_wait([=](const boost::system::error_code& ec)
    {
      if(ec == boost::asio::error::operation_aborted)
        return;
      MDEBUG(m_con_context << "connection timeout, closing");
      self->close();
    });
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool connection<t_wire_handler>::shutdown()
  {
    CRITICAL_REGION_BEGIN(m_shutdown_lock);
    if (m_was_shutdown)
      return true;
    m_was_shutdown = true;
    // Initiate graceful connection closure.
    m_timer.cancel();
    boost::system::error_code ignored_ec;
    if (m_ssl_support == epee::net_utils::ssl_support_t::e_ssl_support_enabled)
    {
      const shared_state &state = static_cast<const shared_state&>(get_state());
      if (!state.stop_signal_sent)
        socket_.shutdown(ignored_ec);
    }
    socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
    if (!m_host.empty())
    {
      try { host_count(m_host, -1); } catch (...) { /* ignore */ }
      m_host = "";
    }
    CRITICAL_REGION_END();
    m_wire_handler.release_protocol();
    return true;
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool connection<t_wire_handler>::close()
  {
    TRY_ENTRY();
    auto self = safe_shared_from_this();
    if(!self)
      return false;
    //_info("[sock " << socket().native_handle() << "] Que Shutdown called.");
    m_timer.cancel();
    size_t send_que_size = 0;
    CRITICAL_REGION_BEGIN(m_send_que_lock);
    send_que_size = m_send_que.size();
    CRITICAL_REGION_END();
    boost::interprocess::ipcdetail::atomic_write32(&m_want_close_connection, 1);
    if(!send_que_size)
    {
      shutdown();
    }
    
    return true;
    CATCH_ENTRY_L0("connection<t_wire_handler>::close", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool connection<t_wire_handler>::send_done()
  {
    if (m_ready_to_close)
      return close();
    m_ready_to_close = true;
    return true;
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  bool connection<t_wire_handler>::cancel()
  {
    return close();
  }
  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void connection<t_wire_handler>::handle_write(const boost::system::error_code& e, size_t cb)
  {
    TRY_ENTRY();
    LOG_TRACE_CC(m_con_context, "[sock " << socket().native_handle() << "] Async send calledback " << cb);

    if (e)
    {
      _dbg1("[sock " << socket().native_handle() << "] Some problems at write: " << e.message() << ':' << e.value());
      shutdown();
      return;
    }
    logger_handle_net_write(cb);

                // The single sleeping that is needed for correctly handling "out" speed throttling
		if (speed_limit_is_enabled()) {
			sleep_before_packet(cb, 1, 1);
		}

    bool do_shutdown = false;
    CRITICAL_REGION_BEGIN(m_send_que_lock);
    if(m_send_que.empty())
    {
      _erro("[sock " << socket().native_handle() << "] m_send_que.size() == 0 at handle_write!");
      return;
    }

    m_send_que.pop_front();
    if(m_send_que.empty())
    {
      if(boost::interprocess::ipcdetail::atomic_read32(&m_want_close_connection))
      {
        do_shutdown = true;
      }
    }else
    {
      //have more data to send
		reset_timer(get_default_timeout(), false);
		auto size_now = m_send_que.front().size();
		MDEBUG("handle_write() NOW SENDS: packet="<<size_now<<" B" <<", from  queue size="<<m_send_que.size());
		if (speed_limit_is_enabled())
			do_send_handler_write_from_queue(e, m_send_que.front().size() , m_send_que.size()); // (((H)))

		CHECK_AND_ASSERT_MES( size_now == m_send_que.front().size(), void(), "Unexpected queue size");
    
		  async_write(boost::asio::buffer(m_send_que.front().data(), size_now) , 
           strand_.wrap(
            std::bind(&connection<t_wire_handler>::handle_write, connection<t_wire_handler>::shared_from_this(), std::placeholders::_1, std::placeholders::_2)
			  )
          );
      //MINFO("(normal)" << size_now);
    }
    CRITICAL_REGION_END();

    if(do_shutdown)
    {
      shutdown();
    }
    CATCH_ENTRY_L0("connection<t_wire_handler>::handle_write", void());
  }

  //---------------------------------------------------------------------------------
  template<class t_wire_handler>
  void connection<t_wire_handler>::setRpcStation()
  {
    m_connection_type = e_connection_type_RPC; 
    MDEBUG("set m_connection_type = RPC ");
  }


  template<class t_wire_handler>
  bool connection<t_wire_handler>::speed_limit_is_enabled() const {
		return m_connection_type != e_connection_type_RPC ;
	}
}
}
PRAGMA_WARNING_POP