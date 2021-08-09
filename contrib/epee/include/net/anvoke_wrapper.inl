
  struct invoke_response_handler_base
  {
    virtual bool handle(int res, const epee::span<const uint8_t> buff, connection_context& context)=0;
    virtual bool is_timer_started() const=0;
    virtual void cancel()=0;
    virtual bool cancel_timer()=0;
    virtual void reset_timer()=0;
  };
  template <class callback_t>
  struct anvoke_handler: invoke_response_handler_base
  {
    anvoke_handler(const callback_t& cb, uint64_t timeout,  async_wire_handler& con, int command)
      :m_cb(cb), m_timeout(timeout), m_con(con), m_timer(con.m_pservice_endpoint->get_io_service()), m_timer_started(false),
      m_cancel_timer_called(false), m_timer_cancelled(false), m_command(command)
    {
      if(m_con.start_outer_call())
      {
        MDEBUG(con.get_context_ref() << "anvoke_handler, timeout: " << timeout);
        m_timer.expires_from_now(boost::posix_time::milliseconds(timeout));
        m_timer.async_wait([&con, command, cb, timeout](const boost::system::error_code& ec)
        {
          if(ec == boost::asio::error::operation_aborted)
            return;
          MINFO(con.get_context_ref() << "Timeout on invoke operation happened, command: " << command << " timeout: " << timeout);
          epee::span<const uint8_t> fake;
          cb(LEVIN_ERROR_CONNECTION_TIMEDOUT, fake, con.get_context_ref());
          con.close();
          con.finish_outer_call();
        });
        m_timer_started = true;
      }
    }
    virtual ~anvoke_handler()
    {}
  public:
    callback_t m_cb;
    async_wire_handler& m_con;
    boost::asio::deadline_timer m_timer;
    bool m_timer_started;
    bool m_cancel_timer_called;
    bool m_timer_cancelled;
    uint64_t m_timeout;
    int m_command;
    virtual bool handle(int res, const epee::span<const uint8_t> buff, typename async_wire_handler::connection_context& context)
    {
      if(!cancel_timer())
        return false;
      m_cb(res, buff, context);
      m_con.finish_outer_call();
      return true;
    }
    virtual bool is_timer_started() const
    {
      return m_timer_started;
    }
    virtual void cancel()
    {
      if(cancel_timer())
      {
        epee::span<const uint8_t> fake;
        m_cb(LEVIN_ERROR_CONNECTION_DESTROYED, fake, m_con.get_context_ref());
        m_con.finish_outer_call();
      }
    }
    virtual bool cancel_timer()
    {
      if(!m_cancel_timer_called)
      {
        m_cancel_timer_called = true;
        boost::system::error_code ignored_ec;
        m_timer_cancelled = 1 == m_timer.cancel(ignored_ec);
      }
      return m_timer_cancelled;
    }
    virtual void reset_timer()
    {
      boost::system::error_code ignored_ec;
      if (!m_cancel_timer_called && m_timer.cancel(ignored_ec) > 0)
      {
        callback_t& cb = m_cb;
        uint64_t timeout = m_timeout;
        async_wire_handler& con = m_con;
        int command = m_command;
        m_timer.expires_from_now(boost::posix_time::milliseconds(m_timeout));
        m_timer.async_wait([&con, cb, command, timeout](const boost::system::error_code& ec)
        {
          if(ec == boost::asio::error::operation_aborted)
            return;
          MINFO(con.get_context_ref() << "Timeout on invoke operation happened, command: " << command << " timeout: " << timeout);
          epee::span<const uint8_t> fake;
          cb(LEVIN_ERROR_CONNECTION_TIMEDOUT, fake, con.get_context_ref());
          con.close();
          con.finish_outer_call();
        });
      }
    }
  };