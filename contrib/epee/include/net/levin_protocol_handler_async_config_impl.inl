//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::del_connection(async_protocol_handler<t_connection_context>* pconn)
{
  CRITICAL_REGION_BEGIN(m_connects_lock);
  m_connects.erase(pconn->get_connection_id());
  CRITICAL_REGION_END();
  m_pcommands_handler->on_connection_close(pconn->m_connection_context);
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::delete_connections(size_t count, bool incoming)
{
  std::vector<typename connections_map::mapped_type> connections;

  auto scope_exit_handler = misc_utils::create_scope_leave_handler([&connections]{
    for (auto &aph: connections)
      aph->finish_outer_call();
  });

  CRITICAL_REGION_BEGIN(m_connects_lock);
  for (auto& c: m_connects)
  {
    if (c.second->m_connection_context.m_is_income == incoming)
      if (c.second->start_outer_call())
        connections.push_back(c.second);
  }

  // close random connections from  the provided set
  // TODO or better just keep removing random elements (performance)
  unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
  shuffle(connections.begin(), connections.end(), std::default_random_engine(seed));
  for (size_t i = 0; i < connections.size() && i < count; ++i)
    m_connects.erase(connections[i]->get_connection_id());

  CRITICAL_REGION_END();

  for (size_t i = 0; i < connections.size() && i < count; ++i)
    connections[i]->close();
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::del_out_connections(size_t count)
{
  delete_connections(count, false);
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::del_in_connections(size_t count)
{
  delete_connections(count, true);
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::add_connection(AsyncConn* pconn)
{
 MINFO("async_protocol_handler_config<t_connection_context>::add_connection ");
  CRITICAL_REGION_BEGIN(m_connects_lock);
  m_connects[pconn->get_connection_id()] = pconn;
  CRITICAL_REGION_END();
  m_pcommands_handler->on_connection_new(pconn->m_connection_context);
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
async_protocol_handler<t_connection_context>* async_protocol_handler_config<t_connection_context>::find_connection(boost::uuids::uuid connection_id) const
{
  auto it = m_connects.find(connection_id);
  return it == m_connects.end() ? 0 : it->second;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
int async_protocol_handler_config<t_connection_context>::find_and_lock_connection(boost::uuids::uuid connection_id, AsyncConn*& aph)
{
  CRITICAL_REGION_LOCAL(m_connects_lock);
  aph = find_connection(connection_id);
  if(0 == aph)
    return LEVIN_ERROR_CONNECTION_NOT_FOUND;
  if(!aph->start_outer_call())
    return LEVIN_ERROR_CONNECTION_DESTROYED;
  return LEVIN_OK;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
int async_protocol_handler_config<t_connection_context>::invoke(int command, message_writer in_msg, std::string& buff_out, boost::uuids::uuid connection_id)
{
  async_protocol_handler<t_connection_context>* aph;
  int r = find_and_lock_connection(connection_id, aph);
  return LEVIN_OK == r ? aph->invoke(command, std::move(in_msg), buff_out) : r;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context> template<class callback_t>
int async_protocol_handler_config<t_connection_context>::invoke_async(int command, message_writer in_msg, boost::uuids::uuid connection_id, const callback_t &cb, size_t timeout)
{
  async_protocol_handler<t_connection_context>* aph;
  int r = find_and_lock_connection(connection_id, aph);
  return LEVIN_OK == r ? aph->async_invoke(command, std::move(in_msg), cb, timeout) : r;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context> template<class callback_t>
bool async_protocol_handler_config<t_connection_context>::foreach_connection(const callback_t &cb)
{
  std::vector<typename connections_map::mapped_type> conn;

  auto scope_exit_handler = misc_utils::create_scope_leave_handler([&conn]{
    for (auto &aph: conn)
      aph->finish_outer_call();
  });

  CRITICAL_REGION_BEGIN(m_connects_lock);
  conn.reserve(m_connects.size());
  for (auto &e: m_connects)
    if (e.second->start_outer_call())
      conn.push_back(e.second);
  CRITICAL_REGION_END()

  for (auto &aph: conn)
    if (!cb(aph->get_context_ref()))
      return false;

  return true;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context> template<class callback_t>
bool async_protocol_handler_config<t_connection_context>::for_connection(const boost::uuids::uuid &connection_id, const callback_t &cb)
{
  async_protocol_handler<t_connection_context>* aph = nullptr;
  if (find_and_lock_connection(connection_id, aph) != LEVIN_OK)
    return false;
  auto scope_exit_handler = misc_utils::create_scope_leave_handler(
    boost::bind(&async_protocol_handler<t_connection_context>::finish_outer_call, aph));
  if(!cb(aph->get_context_ref()))
    return false;
  return true;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
size_t async_protocol_handler_config<t_connection_context>::get_connections_count()
{
  CRITICAL_REGION_LOCAL(m_connects_lock);
  return m_connects.size();
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
size_t async_protocol_handler_config<t_connection_context>::get_out_connections_count()
{
  CRITICAL_REGION_LOCAL(m_connects_lock);
  size_t count = 0;
  for (const auto &c: m_connects)
    if (!c.second->m_connection_context.m_is_income)
      ++count;
  return count;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
size_t async_protocol_handler_config<t_connection_context>::get_in_connections_count()
{
  CRITICAL_REGION_LOCAL(m_connects_lock);
  size_t count = 0;
  for (const auto &c: m_connects)
    if (c.second->m_connection_context.m_is_income)
      ++count;
  return count;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::set_handler(levin_commands_handler<t_connection_context>* handler, void (*destroy)(levin_commands_handler<t_connection_context>*))
{
  if (m_pcommands_handler && m_pcommands_handler_destroy)
    (*m_pcommands_handler_destroy)(m_pcommands_handler);
  m_pcommands_handler = handler;
  m_pcommands_handler_destroy = destroy;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
int async_protocol_handler_config<t_connection_context>::send(byte_slice message, const boost::uuids::uuid& connection_id)
{
  async_protocol_handler<t_connection_context>* aph;
  int r = find_and_lock_connection(connection_id, aph);
  return LEVIN_OK == r ? aph->send(std::move(message)) : 0;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
bool async_protocol_handler_config<t_connection_context>::close(boost::uuids::uuid connection_id)
{
  async_protocol_handler<t_connection_context>* aph = nullptr;
  if (find_and_lock_connection(connection_id, aph) != LEVIN_OK)
    return false;
  auto scope_exit_handler = misc_utils::create_scope_leave_handler(
    boost::bind(&async_protocol_handler<t_connection_context>::finish_outer_call, aph));
  if (!aph->close())
    return false;
  CRITICAL_REGION_LOCAL(m_connects_lock);
  m_connects.erase(connection_id);
  return true;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
bool async_protocol_handler_config<t_connection_context>::update_connection_context(const t_connection_context& contxt)
{
  CRITICAL_REGION_LOCAL(m_connects_lock);
  async_protocol_handler<t_connection_context>* aph = find_connection(contxt.m_connection_id);
  if(0 == aph)
    return false;
  aph->update_connection_context(contxt);
  return true;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
bool async_protocol_handler_config<t_connection_context>::request_callback(boost::uuids::uuid connection_id)
{
  async_protocol_handler<t_connection_context>* aph;
  int r = find_and_lock_connection(connection_id, aph);
  if(LEVIN_OK == r)
  {
    aph->request_callback();
    return true;
  }
  else
  {
    return false;
  }
}
