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

 
namespace epee
{
namespace net_utils
{

  struct i_connection_filter
  {
    virtual bool is_remote_host_allowed(const epee::net_utils::network_address &address, time_t *t = NULL)=0;
  protected:
    virtual ~i_connection_filter(){}
  };
  

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  /// Represents a single connection from a client.
  template<class t_wire_handler>
  class connection: public boost::enable_shared_from_this<connection<t_wire_handler> >,private boost::noncopyable, public i_service_endpoint,public connection_basic
  {
  public:
    typedef typename t_wire_handler::connection_context t_connection_context;
    typedef connection<t_wire_handler> MyType;
    struct shared_state : connection_basic_shared_state, t_wire_handler::shared_state
    {
      shared_state()
        : connection_basic_shared_state(), t_wire_handler::shared_state(), pfilter(nullptr), stop_signal_sent(false)
      {}

      i_connection_filter* pfilter;
      bool stop_signal_sent;
    };

    /// Construct a connection with the given io_service.
    explicit connection( boost::asio::io_service& io_service,std::shared_ptr<shared_state> state,
			t_connection_type connection_type,epee::net_utils::ssl_support_t ssl_support);

    explicit connection( boost::asio::ip::tcp::socket&& sock,	std::shared_ptr<shared_state> state,
			t_connection_type connection_type,epee::net_utils::ssl_support_t ssl_support);



    virtual ~connection() noexcept(false);

    /// Start the first asynchronous operation for the connection.
    bool start(bool is_income, bool is_multithreaded);

    // `real_remote` is the actual endpoint (if connection is to proxy, etc.)
    bool start(bool is_income, bool is_multithreaded, network_address real_remote);

    void get_context(t_connection_context& context_){context_ = m_con_context;}

    void call_back_starter();
    
    void save_dbg_log();


		bool speed_limit_is_enabled() const; ///< tells us should we be sleeping here (e.g. do not sleep on RPC connections)

    bool cancel();
    
  private:
    //----------------- i_service_endpoint ---------------------
    virtual bool do_send(byte_slice message); ///< (see do_send from i_service_endpoint)
    virtual bool send_done();
    virtual bool close();
    virtual bool call_run_once_service_io();
    virtual bool request_callback();
    virtual boost::asio::io_service& get_io_service();
    virtual bool add_ref();
    virtual bool release();
    //------------------------------------------------------
    bool do_send_chunk(byte_slice chunk); ///< will send (or queue) a part of data. internal use only

    boost::shared_ptr<connection<t_wire_handler> > safe_shared_from_this();
    bool shutdown();
    /// Handle completion of a receive operation.
    void handle_receive(const boost::system::error_code& e,std::size_t bytes_transferred);

    /// Handle completion of a read operation.
    void handle_read(const boost::system::error_code& e, std::size_t bytes_transferred);

    /// Handle completion of a write operation.
    void handle_write(const boost::system::error_code& e, size_t cb);

    /// reset connection timeout timer and callback
    void reset_timer(boost::posix_time::milliseconds ms, bool add);
    boost::posix_time::milliseconds get_default_timeout();
    boost::posix_time::milliseconds get_timeout_from_bytes_read(size_t bytes);

    /// host connection count tracking
    unsigned int host_count(const std::string &host, int delta = 0);

private:
    /// Buffer for incoming data.
    boost::array<char, 8192> buffer_;
    size_t buffer_ssl_init_fill;

    t_connection_context m_con_context;

	// TODO what do they mean about wait on destructor?? --rfree :
    //this should be the last one, because it could be wait on destructor, while other activities possible on other threads
    t_wire_handler m_wire_handler;
    //typename t_wire_handler::shared_state m_dummy_config;
    size_t m_reference_count = 0; // reference count managed through add_ref/release support
    boost::shared_ptr<connection<t_wire_handler> > m_self_ref; // the reference to hold
    critical_section m_self_refs_lock;
    critical_section m_chunking_lock; // held while we add small chunks of the big do_send() to small do_send_chunk()
    critical_section m_shutdown_lock; // held while shutting down
    
    t_connection_type m_connection_type;
    
    // for calculate speed (last 60 sec)
    network_throttle m_throttle_speed_in;
    network_throttle m_throttle_speed_out;
    boost::mutex m_throttle_speed_in_mutex;
    boost::mutex m_throttle_speed_out_mutex;

    boost::asio::deadline_timer m_timer;
    bool m_local;
    bool m_ready_to_close;
    std::string m_host;

	public:
			void setRpcStation();
  };
}
}