// Copyright (c) 2019-2020, The Monero Project
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

#include "tx_pool.h"

#include <boost/chrono/chrono.hpp>
#include <boost/thread/thread_only.hpp>
#include <limits>
#include "string_tools.h"

#define INIT_MEMPOOL_TEST()                                   \
  uint64_t send_amount = 1000;                                \
  uint64_t ts_start = 1338224400;                             \
  GENERATE_ACCOUNT(miner_account);                            \
  GENERATE_ACCOUNT(bob_account);                              \
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start); \
  REWIND_BLOCKS(events, blk_0r, blk_0, miner_account);        \


txpool_base::txpool_base()
  : test_chain_unit_base()
  , m_broadcasted_tx_count(0)
  , m_all_tx_count(0)
{
  REGISTER_CALLBACK_METHOD(txpool_spend_key_public, increase_broadcasted_tx_count);
  REGISTER_CALLBACK_METHOD(txpool_spend_key_public, increase_all_tx_count);
  REGISTER_CALLBACK_METHOD(txpool_spend_key_public, check_txpool_spent_keys);
}

bool txpool_base::increase_broadcasted_tx_count(cryptonote::core& /*c*/, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
{
  ++m_broadcasted_tx_count;
  return true;
}

bool txpool_base::increase_all_tx_count(cryptonote::core& /*c*/, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
{
  ++m_all_tx_count;
  return true;
}

bool txpool_base::check_txpool_spent_keys(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& events)
{
  std::vector<cryptonote::tx_info> infos{};
  std::vector<cryptonote::spent_key_image_info> key_images{};
  if (!c.get_pool_transactions_and_spent_keys_info(infos, key_images) || infos.size() != m_broadcasted_tx_count || key_images.size() != m_broadcasted_tx_count)
  {
    MERROR("Failed broadcasted spent keys retrieval - Expected Broadcasted Count: " << m_broadcasted_tx_count << " Actual Info Count: " << infos.size() << " Actual Key Image Count: " << key_images.size());
    return false;
  }

  infos.clear();
  key_images.clear();
  if (!c.get_pool_transactions_and_spent_keys_info(infos, key_images, false) || infos.size() != m_broadcasted_tx_count || key_images.size() != m_broadcasted_tx_count)
  {
    MERROR("Failed broadcasted spent keys retrieval - Expected Broadcasted Count: " << m_broadcasted_tx_count << " Actual Info Count: " << infos.size() << " Actual Key Image Count: " << key_images.size());
    return false;
  }

  infos.clear();
  key_images.clear();
  if (!c.get_pool_transactions_and_spent_keys_info(infos, key_images, true) || infos.size() != m_all_tx_count || key_images.size() != m_all_tx_count)
  {
    MERROR("Failed all spent keys retrieval - Expected All Count: " << m_all_tx_count << " Actual Info Count: " << infos.size() << " Actual Key Image Count: " << key_images.size());
    return false;
  }

  return true;
}

bool txpool_spend_key_public::generate(std::vector<test_event_entry>& events) const
{
  INIT_MEMPOOL_TEST();

  DO_CALLBACK(events, "check_txpool_spent_keys");
  MAKE_TX(events, tx_0, miner_account, bob_account, send_amount, blk_0);
  DO_CALLBACK(events, "increase_broadcasted_tx_count");
  DO_CALLBACK(events, "increase_all_tx_count");
  DO_CALLBACK(events, "check_txpool_spent_keys");

  return true;
}

bool txpool_spend_key_all::generate(std::vector<test_event_entry>& events)
{
  INIT_MEMPOOL_TEST();
  SET_EVENT_VISITOR_SETT(events, event_visitor_settings::set_txs_do_not_relay);

  DO_CALLBACK(events, "check_txpool_spent_keys");
  MAKE_TX(events, tx_0, miner_account, bob_account, send_amount, blk_0);
  DO_CALLBACK(events, "increase_all_tx_count");
  DO_CALLBACK(events, "check_txpool_spent_keys");

  return true;
}

txpool_double_spend_base::txpool_double_spend_base()
  : txpool_base()
  , m_broadcasted_hashes()
  , m_no_relay_hashes()
  , m_all_hashes()
  , m_no_new_index(0)
  , m_failed_index(0)
  , m_new_timestamp_index(0)
  , m_last_tx(crypto::hash{})
{
  REGISTER_CALLBACK_METHOD(txpool_double_spend_base, mark_no_new);
  REGISTER_CALLBACK_METHOD(txpool_double_spend_base, mark_failed);
  REGISTER_CALLBACK_METHOD(txpool_double_spend_base, mark_timestamp_change);
  REGISTER_CALLBACK_METHOD(txpool_double_spend_base, timestamp_change_pause);
  REGISTER_CALLBACK_METHOD(txpool_double_spend_base, check_unchanged);
  REGISTER_CALLBACK_METHOD(txpool_double_spend_base, check_new_broadcasted);
  REGISTER_CALLBACK_METHOD(txpool_double_spend_base, check_new_hidden);
  REGISTER_CALLBACK_METHOD(txpool_double_spend_base, check_new_no_relay);
}

bool txpool_double_spend_base::mark_no_new(cryptonote::core& /*c*/, size_t ev_index, const std::vector<test_event_entry>& /*events*/)
{
  m_no_new_index = ev_index + 1;
  return true;
}

bool txpool_double_spend_base::mark_failed(cryptonote::core& /*c*/, size_t ev_index, const std::vector<test_event_entry>& /*events*/)
{
  m_failed_index = ev_index + 1;
  return true;
}

bool txpool_double_spend_base::mark_timestamp_change(cryptonote::core& /*c*/, size_t ev_index, const std::vector<test_event_entry>& /*events*/)
{
  m_new_timestamp_index = ev_index + 1;
  return true;
}

bool txpool_double_spend_base::timestamp_change_pause(cryptonote::core& /*c*/, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
{
  boost::this_thread::sleep_for(boost::chrono::seconds{1} + boost::chrono::milliseconds{100});
  return true;
}

bool txpool_double_spend_base::check_changed(cryptonote::core& c, const size_t ev_index, relay_test condition)
{
  
  return true;
}

bool txpool_double_spend_base::check_unchanged(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& /*events */)
{
  return check_changed(c, ev_index, relay_test::no_change);
}

bool txpool_double_spend_base::check_new_broadcasted(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& /*events */)
{
  return check_changed(c, ev_index, relay_test::broadcasted);
}

bool txpool_double_spend_base::check_new_hidden(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& /*events */)
{
  return check_changed(c, ev_index, relay_test::hidden);
}
bool txpool_double_spend_base::check_new_no_relay(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& /*events */)
{
  return check_changed(c, ev_index, relay_test::no_relay);
}

bool txpool_double_spend_base::check_tx_verification_context(const cryptonote::tx_verification_context& tvc, bool tx_added, size_t event_idx, const cryptonote::transaction& tx) 
{
  m_last_tx = cryptonote::get_transaction_hash(tx);
  if (m_no_new_index == event_idx)
    return !tvc.m_verifivation_failed && !tx_added;
  else if (m_failed_index == event_idx)
    return tvc.m_verifivation_failed;// && !tx_added;
  else
    return !tvc.m_verifivation_failed && tx_added;
}

bool txpool_double_spend_norelay::generate(std::vector<test_event_entry>& events) const
{
  INIT_MEMPOOL_TEST();

  DO_CALLBACK(events, "check_txpool_spent_keys");
  SET_EVENT_VISITOR_SETT(events, event_visitor_settings::set_txs_do_not_relay);
  DO_CALLBACK(events, "mark_no_new");

  MAKE_TX(events, tx_0, miner_account, bob_account, send_amount, blk_0);

  DO_CALLBACK(events, "increase_all_tx_count");
  DO_CALLBACK(events, "check_txpool_spent_keys");
  DO_CALLBACK(events, "mark_timestamp_change");
  DO_CALLBACK(events, "check_new_no_relay");
  DO_CALLBACK(events, "timestamp_change_pause");
  DO_CALLBACK(events, "mark_no_new");
  events.push_back(tx_0);
  DO_CALLBACK(events, "check_txpool_spent_keys");
  DO_CALLBACK(events, "check_unchanged");
  SET_EVENT_VISITOR_SETT(events, 0);
  DO_CALLBACK(events, "timestamp_change_pause");
  DO_CALLBACK(events, "mark_no_new");
  events.push_back(tx_0);
  DO_CALLBACK(events, "check_txpool_spent_keys");
  DO_CALLBACK(events, "check_unchanged");

  // kepped by block currently does not change txpool status
  SET_EVENT_VISITOR_SETT(events, event_visitor_settings::set_txs_keeped_by_block);
  DO_CALLBACK(events, "timestamp_change_pause");
  DO_CALLBACK(events, "mark_no_new");
  events.push_back(tx_0);
  DO_CALLBACK(events, "check_txpool_spent_keys");
  DO_CALLBACK(events, "check_unchanged");

  return true;
}

bool txpool_double_spend_local::generate(std::vector<test_event_entry>& events) const
{
  INIT_MEMPOOL_TEST();

  DO_CALLBACK(events, "check_txpool_spent_keys");
  SET_EVENT_VISITOR_SETT(events, event_visitor_settings::set_local_relay);
  DO_CALLBACK(events, "mark_no_new");

  MAKE_TX(events, tx_0, miner_account, bob_account, send_amount, blk_0);

  DO_CALLBACK(events, "increase_all_tx_count");
  DO_CALLBACK(events, "check_txpool_spent_keys");
  DO_CALLBACK(events, "mark_timestamp_change");
  DO_CALLBACK(events, "check_new_hidden");
  DO_CALLBACK(events, "timestamp_change_pause");
  DO_CALLBACK(events, "mark_no_new");
  events.push_back(tx_0);
  DO_CALLBACK(events, "check_txpool_spent_keys");
  DO_CALLBACK(events, "check_unchanged");
  SET_EVENT_VISITOR_SETT(events, 0);
  DO_CALLBACK(events, "timestamp_change_pause");
  events.push_back(tx_0);
  DO_CALLBACK(events, "increase_broadcasted_tx_count");
  DO_CALLBACK(events, "check_txpool_spent_keys");
  DO_CALLBACK(events, "mark_timestamp_change");
  DO_CALLBACK(events, "check_new_broadcasted");
  DO_CALLBACK(events, "timestamp_change_pause");
  DO_CALLBACK(events, "mark_no_new");
  events.push_back(tx_0);
  DO_CALLBACK(events, "check_unchanged");

  return true;
}

bool txpool_double_spend_keyimage::generate(std::vector<test_event_entry>& events) const
{
  INIT_MEMPOOL_TEST();

  DO_CALLBACK(events, "check_txpool_spent_keys");
  SET_EVENT_VISITOR_SETT(events, event_visitor_settings::set_local_relay);
  DO_CALLBACK(events, "mark_no_new");

  const std::size_t tx_index1 = events.size();
  MAKE_TX(events, tx_0, miner_account, bob_account, send_amount, blk_0);

  SET_EVENT_VISITOR_SETT(events, event_visitor_settings::set_txs_stem);
  DO_CALLBACK(events, "increase_all_tx_count");
  DO_CALLBACK(events, "check_txpool_spent_keys");
  DO_CALLBACK(events, "mark_timestamp_change");
  DO_CALLBACK(events, "check_new_hidden");
  DO_CALLBACK(events, "timestamp_change_pause");
  DO_CALLBACK(events, "mark_no_new");
  const std::size_t tx_index2 = events.size();
  events.push_back(tx_0);
  DO_CALLBACK(events, "check_txpool_spent_keys");
  DO_CALLBACK(events, "mark_timestamp_change");
  DO_CALLBACK(events, "check_unchanged");

  // use same key image with different id
  cryptonote::transaction tx_1;
  {
    auto events_copy = events;
    events_copy.erase(events_copy.begin() + tx_index1);
    events_copy.erase(events_copy.begin() + tx_index2 - 1);
    MAKE_TX(events_copy, tx_temp, miner_account, bob_account, send_amount, blk_0);
    tx_1 = tx_temp;
  }

  // same key image
  DO_CALLBACK(events, "timestamp_change_pause");
  DO_CALLBACK(events, "mark_failed");
  events.push_back(tx_1);
  DO_CALLBACK(events, "check_unchanged");

  return true;
}

bool txpool_stem_loop::generate(std::vector<test_event_entry>& events) const
{
  INIT_MEMPOOL_TEST();

  DO_CALLBACK(events, "check_txpool_spent_keys");
  SET_EVENT_VISITOR_SETT(events, event_visitor_settings::set_txs_stem);
  DO_CALLBACK(events, "mark_no_new");

  MAKE_TX(events, tx_0, miner_account, bob_account, send_amount, blk_0);

  DO_CALLBACK(events, "increase_all_tx_count");
  DO_CALLBACK(events, "check_txpool_spent_keys");
  DO_CALLBACK(events, "mark_timestamp_change");
  DO_CALLBACK(events, "check_new_hidden");
  DO_CALLBACK(events, "timestamp_change_pause");
  events.push_back(tx_0);
  DO_CALLBACK(events, "increase_broadcasted_tx_count");
  DO_CALLBACK(events, "check_txpool_spent_keys");
  DO_CALLBACK(events, "mark_timestamp_change");
  DO_CALLBACK(events, "check_new_broadcasted");
  DO_CALLBACK(events, "timestamp_change_pause");
  DO_CALLBACK(events, "mark_no_new");
  events.push_back(tx_0);
  DO_CALLBACK(events, "check_unchanged");

  return true;
}
