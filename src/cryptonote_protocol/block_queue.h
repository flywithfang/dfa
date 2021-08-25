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

#pragma once

#include <string>
#include <vector>
#include <set>
#include <unordered_set>
#include <boost/thread/recursive_mutex.hpp>
#include <boost/uuid/uuid.hpp>
#include "net/net_utils_base.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn.block_queue"

namespace cryptonote
{
  struct block_complete_entry;

  class block_queue
  {
  public:
    struct span
    {
      enum STATE{
        DOWNING,
        DOWN_OVER,
      };
      STATE state;
      uint64_t start_height;
      uint64_t nblocks;
      std::vector<crypto::hash> hashes;
      std::vector<cryptonote::block_complete_entry> bces;
      boost::uuids::uuid connection_id;
     
      bool operator<(const span &s) const { return start_height < s.start_height; }
      uint64_t end_height()const{
        return start_height+nblocks-1;
      }
      bool is_down_over()const{return state== DOWN_OVER;}

    };
    typedef std::set<span> span_series;

  public:
    span start_span(cryptonote_peer_context & peer_cxt,uint64_t batch_size);

    void finish_span(uint64_t height, std::vector<cryptonote::block_complete_entry> bcel, const boost::uuids::uuid &connection_id);

    void flush_spans(const boost::uuids::uuid &connection_id);
    void flush_stale_spans(const std::set<boost::uuids::uuid> &live_connections);
    


    uint64_t get_max_block_height() const;
    void print() const;
    std::string get_overview(uint64_t blockchain_height) const;
  

    uint64_t get_next_needed_height(uint64_t blockchain_height) const;
    std::pair<uint64_t, uint64_t> get_next_span_if_scheduled(std::vector<crypto::hash> &hashes, boost::uuids::uuid &connection_id, boost::posix_time::ptime &time) const;
    void reset_next_span_time(boost::posix_time::ptime t = boost::posix_time::microsec_clock::universal_time());
    void set_span_hashes(uint64_t start_height, const boost::uuids::uuid &connection_id, std::vector<crypto::hash> hashes);
   std::optional<block_queue::span&> get_next_span(bool filled) const;
    bool has_next_span(const boost::uuids::uuid &connection_id, bool &filled, boost::posix_time::ptime &time) const;
    bool has_next_span(uint64_t height, bool &filled, boost::posix_time::ptime &time, boost::uuids::uuid &connection_id) const;
    size_t get_data_size() const;
    size_t get_num_filled_spans_prefix() const;
    size_t get_num_filled_spans() const;
    crypto::hash get_last_known_hash(const boost::uuids::uuid &connection_id) const;
    bool has_spans(const boost::uuids::uuid &connection_id) const;
    float get_speed(const boost::uuids::uuid &connection_id) const;
    float get_download_rate(const boost::uuids::uuid &connection_id) const;
    bool foreach(std::function<bool(const span&)> f) const;

    bool requested(const crypto::hash &hash) const;
    bool have_downloaded(const crypto::hash &hash) const;

  private:
    std::vector<crypto::hash> remove_span(uint64_t start_height);
    void erase_span(span_series::iterator j);
    inline bool requested_internal(const crypto::hash &hash) const;

  private:
    std::set<span> m_spans;//not unorder_set
    mutable boost::recursive_mutex m_mutex;
    std::unordered_set<crypto::hash> m_requested_hashes;
    std::unordered_set<crypto::hash> m_down_blocks;
  };
}
