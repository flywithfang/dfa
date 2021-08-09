
template<class t_connection_context>
class async_wire_shared_state
{
private:
  typedef  async_wire_handler<t_connection_context>  AsyncConn;
  typedef boost::unordered_map<boost::uuids::uuid, AsyncConn* > connections_map;

public:
  typedef t_connection_context connection_context;
  uint64_t m_initial_max_packet_size;
  uint64_t m_max_packet_size;
  uint64_t m_invoke_timeout;


  async_wire_shared_state():m_pcommands_handler(NULL), m_pcommands_handler_destroy(NULL), m_initial_max_packet_size(LEVIN_INITIAL_MAX_PACKET_SIZE), m_max_packet_size(LEVIN_DEFAULT_MAX_PACKET_SIZE), m_invoke_timeout(LEVIN_DEFAULT_TIMEOUT_PRECONFIGURED)
  {}
  ~async_wire_shared_state() { set_handler(NULL, NULL); }
  
  int invoke(int command, message_writer in_msg, std::string& buff_out, boost::uuids::uuid connection_id);
  
  template<class callback_t>
  int invoke_async(int command, message_writer in_msg, boost::uuids::uuid connection_id, const callback_t &cb, size_t timeout = LEVIN_DEFAULT_TIMEOUT_PRECONFIGURED);

  int send(epee::byte_slice message, const boost::uuids::uuid& connection_id);

  bool close(boost::uuids::uuid connection_id);
  bool update_connection_context(const t_connection_context& contxt);
  bool request_callback(boost::uuids::uuid connection_id);
  template<class callback_t>
  bool foreach_connection(const callback_t &cb);
  template<class callback_t>
  bool for_connection(const boost::uuids::uuid &connection_id, const callback_t &cb);
  size_t get_connections_count();
  size_t get_out_connections_count();
  size_t get_in_connections_count();
  void set_handler(i_levin_commands_handler<t_connection_context>* handler, void (*destroy)(i_levin_commands_handler<t_connection_context>*) = NULL);


  void del_out_connections(size_t count);
  void del_in_connections(size_t count);


private:


  void add_connection(AsyncConn* pc);
  void del_connection(AsyncConn* pc);

  AsyncConn* find_connection(boost::uuids::uuid connection_id) const;
  int find_and_lock_connection(boost::uuids::uuid connection_id, AsyncConn*& aph);

  friend class async_wire_handler<t_connection_context>;

  
  void (*m_pcommands_handler_destroy)(i_levin_commands_handler<t_connection_context>*);

  void delete_connections (size_t count, bool incoming);

private:

  critical_section m_connects_lock;
  connections_map m_connections;
  i_levin_commands_handler<t_connection_context>* m_pcommands_handler;

};

