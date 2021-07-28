// Copyright (c) 2014-2020, The Monero Project
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

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "int-util.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "difficulty.h"
#include "misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "difficulty"

namespace cryptonote {

  using std::size_t;
  using std::uint64_t;
  using std::vector;

#if defined(__x86_64__)
  static inline void mul(uint64_t a, uint64_t b, uint64_t &low, uint64_t &high) {
    low = mul128(a, b, &high);
  }

#else

  static inline void mul(uint64_t a, uint64_t b, uint64_t &low, uint64_t &high) {
    // __int128 isn't part of the standard, so the previous function wasn't portable. mul128() in Windows is fine,
    // but this portable function should be used elsewhere. Credit for this function goes to latexi95.

    uint64_t aLow = a & 0xFFFFFFFF;
    uint64_t aHigh = a >> 32;
    uint64_t bLow = b & 0xFFFFFFFF;
    uint64_t bHigh = b >> 32;

    uint64_t res = aLow * bLow;
    uint64_t lowRes1 = res & 0xFFFFFFFF;
    uint64_t carry = res >> 32;

    res = aHigh * bLow + carry;
    uint64_t highResHigh1 = res >> 32;
    uint64_t highResLow1 = res & 0xFFFFFFFF;

    res = aLow * bHigh;
    uint64_t lowRes2 = res & 0xFFFFFFFF;
    carry = res >> 32;

    res = aHigh * bHigh + carry;
    uint64_t highResHigh2 = res >> 32;
    uint64_t highResLow2 = res & 0xFFFFFFFF;

    //Addition

    uint64_t r = highResLow1 + lowRes2;
    carry = r >> 32;
    low = (r << 32) | lowRes1;
    r = highResHigh1 + highResLow2 + carry;
    uint64_t d3 = r & 0xFFFFFFFF;
    carry = r >> 32;
    r = highResHigh2 + carry;
    high = d3 | (r << 32);
  }

#endif

  static inline bool cadd(uint64_t a, uint64_t b) {
    return a + b < a;
  }

  static inline bool cadc(uint64_t a, uint64_t b, bool c) {
    return a + b < a || (c && a + b == (uint64_t) -1);
  }

  bool check_hash_64(const crypto::hash &hash, uint64_t difficulty) {
    uint64_t low, high, top, cur;
    // First check the highest word, this will most likely fail for a random hash.
    mul(swap64le(((const uint64_t *) &hash)[3]), difficulty, top, high);
    if (high != 0) {
      return false;
    }
    mul(swap64le(((const uint64_t *) &hash)[0]), difficulty, low, cur);
    mul(swap64le(((const uint64_t *) &hash)[1]), difficulty, low, high);
    bool carry = cadd(cur, low);
    cur = high;
    mul(swap64le(((const uint64_t *) &hash)[2]), difficulty, low, high);
    carry = cadc(cur, low, carry);
    carry = cadc(high, top, carry);
    return !carry;
  }

  uint64_t next_difficulty_64(std::vector<std::uint64_t> history_tss, std::vector<uint64_t> history_diffs, size_t target_seconds) {

    if(history_tss.size() > DIFFICULTY_WINDOW)
    {
      history_tss.resize(DIFFICULTY_WINDOW);
      history_diffs.resize(DIFFICULTY_WINDOW);
    }


    size_t length = history_tss.size();
    assert(length == history_diffs.size());
    if (length <= 1) {
      return 1;
    }
    static_assert(DIFFICULTY_WINDOW >= 2, "Window is too small");
    assert(length <= DIFFICULTY_WINDOW);
    sort(history_tss.begin(), history_tss.end());
    assert(/*cut_begin >= 0 &&*/ cut_begin + 2 <= cut_end && cut_end <= length);
    uint64_t time_span = history_tss[length - 1] - history_tss[0];
    if (time_span == 0) {
      time_span = 1;
    }
    uint64_t total_work = history_diffs[length - 1] - history_diffs[0];
    assert(total_work > 0);
    uint64_t low, high;
    mul(total_work, target_seconds, low, high);
    // blockchain errors "difficulty overhead" if this function returns zero.
    // TODO: consider throwing an exception instead
    if (high != 0 || low + time_span - 1 < low) {
      return 0;
    }
    return (low + time_span - 1) / time_span;
  }

#if defined(_MSC_VER)
#ifdef max
#undef max
#endif
#endif

  const difficulty_type max64bit(std::numeric_limits<std::uint64_t>::max());
  const boost::multiprecision::uint256_t max128bit(std::numeric_limits<boost::multiprecision::uint128_t>::max());
  const boost::multiprecision::uint512_t max256bit(std::numeric_limits<boost::multiprecision::uint256_t>::max());

#define FORCE_FULL_128_BITS

  bool check_hash_128(const crypto::hash &hash, difficulty_type difficulty) {
#ifndef FORCE_FULL_128_BITS
    // fast check
    if (difficulty >= max64bit && ((const uint64_t *) &hash)[3] > 0)
      return false;
#endif
    // usual slow check
    boost::multiprecision::uint512_t hashVal = 0;
    for(int i = 3; i >=0; i--) { // highest word is zero
      hashVal |= swap64le(((const uint64_t *) &hash)[i]);
      hashVal <<= 64;
    }
    return hashVal * difficulty <= max256bit;
  }

  bool check_hash(const crypto::hash &hash, difficulty_type difficulty) {
    if (difficulty <= max64bit) // if can convert to small difficulty - do it
      return check_hash_64(hash, difficulty.convert_to<std::uint64_t>());
    else
      return check_hash_128(hash, difficulty);
  }

  difficulty_type next_difficulty(std::vector<uint64_t> history_tss, std::vector<difficulty_type> history_diffs, size_t block_time) {

    //cutoff DIFFICULTY_LAG
    if(history_tss.size() > DIFFICULTY_WINDOW)
    {
      history_tss.resize(DIFFICULTY_WINDOW);
      history_diffs.resize(DIFFICULTY_WINDOW);
    }

    size_t length = history_tss.size();
    assert(length == history_diffs.size());
    if (length <= 1) {
      return 1;
    }
    static_assert(DIFFICULTY_WINDOW >= 2, "Window is too small");
    assert(length <= DIFFICULTY_WINDOW);
    sort(history_tss.begin(), history_tss.end());
    uint64_t time_span = history_tss[length - 1] - history_tss[0];
    if (time_span == 0) {
      time_span = 1;
    }
    difficulty_type total_work = history_diffs[length - 1] - history_diffs[0];
    assert(total_work > 0);
    boost::multiprecision::uint256_t d =  (boost::multiprecision::uint256_t(total_work) * block_time + time_span - 1) / time_span;
    
    if(d > max128bit)
      return 0; 
     const auto block_diff = d.convert_to<difficulty_type>();
     MDEBUG("block_diff" << static_cast<uint64_t>(block_diff) << ",total_work "<<total_work<<", time_span "<<time_span);
     return block_diff;
  }

  std::string hex(difficulty_type v)
  {
    static const char chars[] = "0123456789abcdef";
    std::string s;
    while (v > 0)
    {
      s.push_back(chars[(v & 0xf).convert_to<unsigned>()]);
      v >>= 4;
    }
    if (s.empty())
      s += "0";
    std::reverse(s.begin(), s.end());
    return "0x" + s;
  }

}
