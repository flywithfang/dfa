// Copyright (c) 2017-2020, The Monero Project
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

#include <vector>
#include <unordered_map>
#include <boost/uuid/nil_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include "string_tools.h"
#include "cryptonote_protocol_defs.h"
#include "common/pruning.h"
#include "block_queue.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn.block_queue"

namespace std {
  static_assert(sizeof(size_t) <= sizeof(boost::uuids::uuid), "boost::uuids::uuid too small");
  template<> struct hash<boost::uuids::uuid> {
    std::size_t operator()(const boost::uuids::uuid &_v) const {
      return reinterpret_cast<const std::size_t &>(_v);
    }
  };
}

namespace cryptonote
{


std::pair<uint64_t, uint64_t> block_queue::start_span(cryptonote_peer_context & peer_cxt, uint64_t batch_size)
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);

  const auto conn_id = peer_cxt.m_connection_id;
  const auto addr =peer_cxt.m_remote_address;
  const auto time = boost::posix_time::microsec_clock::universal_time();
  if (last_block_height < first_block_height )
  {
    throw_and_log("start_span: early out: first_block_height " << first_block_height << ", last_block_height " << last_block_height );
  }

  // skip everything we've already requested
  uint64_t span_start_height = last_block_height - peer_cxt.m_needed_blocks.size() + 1;

  uint64_t span_length = 0;
  std::vector<crypto::hash> hashes;
  auto i = peer_cxt.m_needed_blocks.begin();
  while (i != need_blocks.end() && span_length < batch_size)
  {
 
    hashes.push_back((*i));
    ++i;
    ++span_length;
  }
  if (span_length == 0)
  {
    throw_and_log("span_length 0, cannot reserve");
  }
  MDEBUG("Reserving span " << span_start_height << " - " << (span_start_height + span_length - 1) << " for " << conn_id);

  m_spans.insert(span(span_start_height, span_length, conn_id, addr, time));

  set_span_hashes(span_start_height, conn_id, hashes);
  return std::make_pair(span_start_height, span_length);
}


void block_queue::finish_span(uint64_t start_height, std::vector<cryptonote::block_complete_entry> bcel, const boost::uuids::uuid &connection_id)
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  std::vector<crypto::hash> hashes = remove_span(start_height);
  m_spans.insert(span(start_height, std::move(bcel), connection_id, addr, rate, size));
  {
    for (const crypto::hash &h: hashes)
    {
      m_requested_hashes.insert(h);
      m_down_blocks.insert(h);
    }
    set_span_hashes(start_height, connection_id, hashes);
  }
}
void block_queue::set_span_hashes(uint64_t start_height, const boost::uuids::uuid &connection_id, std::vector<crypto::hash> hashes)
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  for (auto i = m_spans.begin(); i != m_spans.end(); ++i)
  {
    if (i->start_height == start_height && i->connection_id == connection_id)
    {
      span s = *i;
      erase_span(i);
      s.hashes = std::move(hashes);
      for (const crypto::hash &h: s.hashes)
        m_requested_hashes.insert(h);
      m_spans.insert(s);
      return;
    }
  }
}

void block_queue::flush_spans(const boost::uuids::uuid &connection_id)
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  span_series::iterator i = m_spans.begin();
  while (i != m_spans.end())
  {
    span_series::iterator j = i++;
    if (j->connection_id == connection_id )
    {
      erase_span(j);
    }
  }
}

void block_queue::flush_stale_spans(const std::set<boost::uuids::uuid> &live_connections)
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  span_series::iterator i = m_spans.begin();
  while (i != m_spans.end())
  {
    span_series::iterator j = i++;
    if (j->bces.empty() && live_connections.count(j->connection_id) == 0)
    {
      erase_span(j);
    }
  }
}


void block_queue::erase_span(span_series::iterator j)
{
  CHECK_AND_ASSERT_THROW_MES(j != m_spans.end(), "Invalid iterator");
  for (const crypto::hash &h: j->hashes)
  {
    m_requested_hashes.erase(h);
    m_down_blocks.erase(h);
  }
  m_spans.erase(j);
}


std::vector<crypto::hash> block_queue::remove_span(uint64_t start_height)
{
  std::vector<crypto::hash> hashes;
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  for (auto i = m_spans.begin(); i != m_spans.end(); ++i)
  {
    if (i->start_height == start_height)
    {
      hashes = std::move(i->hashes);
      erase_span(i);
    }
  }
  return hashes;
}


uint64_t block_queue::get_max_block_height() const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  uint64_t height = 0;
  for (const auto &span: m_spans)
  {
    const uint64_t h = span.start_height + span.nblocks - 1;
    if (h > height)
      height = h;
  }
  return height;
}

uint64_t block_queue::get_next_needed_height(uint64_t cur_chain_height) const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  if (m_spans.empty())
    return cur_chain_height;
  uint64_t last_needed_height = cur_chain_height;
  bool first = true;
  for (const auto &span: m_spans)
  {
    if ( cur_chain_height > span.end_height() )
      continue;
    if (span.start_height != last_needed_height || (first && span.bces.empty()))
      return last_needed_height;
    last_needed_height = span.start_height + span.nblocks;
    first = false;
  }
  return last_needed_height;
}

void block_queue::print() const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  MDEBUG("Block queue has " << m_spans.size() << " spans");
  for (const auto &span: m_spans)
    MDEBUG("  " << span.start_height << " - " << (span.start_height+span.nblocks-1) << " (" << span.nblocks << ") - " << (span.bces.empty() ? "scheduled" : "filled    ") << "  " << span.connection_id << " (" << ((unsigned)(span.rate*10/1024.f))/10.f << " kB/s)");
}

std::string block_queue::get_overview(uint64_t blockchain_height) const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  if (m_spans.empty())
    return "[]";
  span_series::const_iterator i = m_spans.begin();
  std::string s = std::string("[");
  uint64_t expected = blockchain_height;
  while (i != m_spans.end())
  {
    if (expected > i->start_height)
    {
      s += "<";
    }
    else
    {
      if (expected < i->start_height)
        s += std::string(std::max((uint64_t)1, (i->start_height - expected) / (i->nblocks ? i->nblocks : 1)), '_');
      s += i->bces.empty() ? "." : i->start_height == blockchain_height ? "m" : "o";
      expected = i->start_height + i->nblocks;
    }
    ++i;
  }
  s += "]";
  return s;
}

inline bool block_queue::requested_internal(const crypto::hash &bh) const
{
  return m_requested_hashes.count(bh) >0;
}

bool block_queue::requested(const crypto::hash &bh) const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  return requested_internal(bh);
}

bool block_queue::have_downloaded(const crypto::hash &hash) const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  return m_down_blocks.count(hash) >0;
}


void block_queue::reset_next_span_time(boost::posix_time::ptime t)
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  CHECK_AND_ASSERT_THROW_MES(!m_spans.empty(), "No next span to reset time");
  span_series::iterator i = m_spans.begin();
  CHECK_AND_ASSERT_THROW_MES(i != m_spans.end(), "No next span to reset time");
  CHECK_AND_ASSERT_THROW_MES(i->bces.empty(), "Next span is not empty");
  (boost::posix_time::ptime&)i->time = t; // sod off, time doesn't influence sorting
}


std::pair<uint64_t, uint64_t> block_queue::get_next_span_if_scheduled(std::vector<crypto::hash> &hashes, boost::uuids::uuid &connection_id, boost::posix_time::ptime &time) const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  if (m_spans.empty())
    return std::make_pair(0, 0);
  auto i = m_spans.begin();
  if (i == m_spans.end())
    return std::make_pair(0, 0);
  if (!i->bces.empty())
    return std::make_pair(0, 0);

  hashes = i->hashes;
  connection_id = i->connection_id;
  time = i->time;
  return std::make_pair(i->start_height, i->nblocks);
}

std::optional<block_queue::span&> block_queue::get_next_span() const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  if (m_spans.empty())
    return {};
    auto & span =*m_spans.begin();
    if(span.is_down_over())
      return span;
    else
      return  {};
}

bool block_queue::has_next_span(const boost::uuids::uuid &connection_id, bool &filled, boost::posix_time::ptime &time) const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  if (m_spans.empty())
    return false;
  span_series::const_iterator i = m_spans.begin();
  if (i == m_spans.end())
    return false;
  if (i->connection_id != connection_id)
    return false;
  filled = !i->bces.empty();
  time = i->time;
  return true;
}

bool block_queue::has_next_span(uint64_t height, bool &filled, boost::posix_time::ptime &time, boost::uuids::uuid &connection_id) const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  if (m_spans.empty())
    return false;
  span_series::const_iterator i = m_spans.begin();
  if (i == m_spans.end())
    return false;
  if (i->start_height > height)
    return false;
  filled = !i->bces.empty();
  time = i->time;
  connection_id = i->connection_id;
  return true;
}

size_t block_queue::get_data_size() const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  size_t size = 0;
  for (const auto &span: m_spans)
    size += span.size;
  return size;
}

size_t block_queue::get_num_filled_spans_prefix() const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);

  if (m_spans.empty())
    return 0;
  span_series::const_iterator i = m_spans.begin();
  size_t size = 0;
  while (i != m_spans.end() && !i->bces.empty())
  {
    ++i;
    ++size;
  }
  return size;
}

size_t block_queue::get_num_filled_spans() const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  size_t size = 0;
  for (const auto &span: m_spans)
  if (!span.bces.empty())
    ++size;
  return size;
}

crypto::hash block_queue::get_last_known_hash(const boost::uuids::uuid &connection_id) const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  crypto::hash hash = crypto::null_hash;
  uint64_t highest_height = 0;
  for (const auto &span: m_spans)
  {
    if (span.connection_id != connection_id)
      continue;
    uint64_t h = span.start_height + span.nblocks - 1;
    if (h > highest_height && span.hashes.size() == span.nblocks)
    {
      hash = span.hashes.back();
      highest_height = h;
    }
  }
  return hash;
}

bool block_queue::has_spans(const boost::uuids::uuid &connection_id) const
{
  for (const auto &span: m_spans)
  {
    if (span.connection_id == connection_id)
      return true;
  }
  return false;
}

float block_queue::get_speed(const boost::uuids::uuid &connection_id) const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  std::unordered_map<boost::uuids::uuid, float> speeds;
  for (const auto &span: m_spans)
  {
    if (span.bces.empty())
      continue;
    // note that the average below does not average over the whole set, but over the
    // previous pseudo average and the latest rate: this gives much more importance
    // to the latest measurements, which is fine here
    auto i = speeds.find(span.connection_id);
    if (i == speeds.end())
      speeds.insert(std::make_pair(span.connection_id, span.rate));
    else
      i->second = (i->second + span.rate) / 2;
  }
  float conn_rate = -1, best_rate = 0;
  for (const auto &i: speeds)
  {
    if (i.first == connection_id)
      conn_rate = i.second;
    if (i.second > best_rate)
      best_rate = i.second;
  }

  if (conn_rate <= 0)
    return 1.0f; // not found, assume good speed
  if (best_rate == 0)
    return 1.0f; // everything dead ? Can't happen, but let's trap anyway

  const float speed = conn_rate / best_rate;
  MTRACE(" Relative speed for " << connection_id << ": " << speed << " (" << conn_rate << "/" << best_rate);
  return speed;
}

float block_queue::get_download_rate(const boost::uuids::uuid &connection_id) const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  float conn_rate = -1.f;
  for (const auto &span: m_spans)
  {
    if (span.bces.empty())
      continue;
    if (span.connection_id != connection_id)
      continue;
    // note that the average below does not average over the whole set, but over the
    // previous pseudo average and the latest rate: this gives much more importance
    // to the latest measurements, which is fine here
    if (conn_rate < 0.f)
      conn_rate = span.rate;
    else
      conn_rate = (conn_rate + span.rate) / 2;
  }

  if (conn_rate < 0)
    conn_rate = 0.0f;
  MTRACE("Download rate for " << connection_id << ": " << conn_rate << " b/s");
  return conn_rate;
}

bool block_queue::foreach(std::function<bool(const span&)> f) const
{
  boost::unique_lock<boost::recursive_mutex> lock(m_mutex);
  span_series::const_iterator i = m_spans.begin();
  while (i != m_spans.end())
    if (!f(*i++))
      return false;
  return true;
}

}
