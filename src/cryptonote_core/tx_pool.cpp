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
#include <boost/filesystem.hpp>
#include <unordered_set>
#include <vector>

#include "tx_pool.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_config.h"
#include "blockchain.h"
#include "blockchain_db/locked_txn.h"
#include "blockchain_db/blockchain_db.h"
#include "common/boost_serialization_helper.h"
#include "int-util.h"
#include "misc_language.h"
#include "warnings.h"
#include "common/perf_timer.h"
#include "crypto/hash.h"
#include "crypto/duration.h"
#include "string_tools.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "txpool"

DISABLE_VS_WARNINGS(4244 4345 4503) //'boost::foreach_detail_::or_' : decorated name length exceeded, name was truncated

using namespace crypto;

namespace cryptonote
{
  namespace
  {
    /*! The Dandelion++ has formula for calculating the average embargo timeout:
                          (-k*(k-1)*hop)/(2*log(1-ep))
        where k is the number of hops before this node and ep is the probability
        that one of the k hops hits their embargo timer, and hop is the average
        time taken between hops. So decreasing ep will make it more probable
        that "this" node is the first to expire the embargo timer. Increasing k
        will increase the number of nodes that will be "hidden" as a prior
        recipient of the tx.

        As example, k=5 and ep=0.1 means "this" embargo timer has a 90%
        probability of being the first to expire amongst 5 nodes that saw the
        tx before "this" one. These values are independent to the fluff
        probability, but setting a low k with a low p (fluff probability) is
        not ideal since a blackhole is more likely to reveal earlier nodes in
        the chain.

        This value was calculated with k=5, ep=0.10, and hop = 175 ms. A
        testrun from a recent Intel laptop took ~80ms to
        receive+parse+proces+send transaction. At least 50ms will be added to
        the latency if crossing an ocean. So 175ms is the fudge factor for
        a single hop with 39s being the embargo timer. */
    constexpr const std::chrono::seconds dandelionpp_embargo_average{CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE};

    //TODO: constants such as these should at least be in the header,
    //      but probably somewhere more accessible to the rest of the
    //      codebase.  As it stands, it is at best nontrivial to test
    //      whether or not changing these parameters (or adding new)
    //      will work correctly.
    time_t const MIN_RELAY_TIME = (60 * 5); // only start re-relaying transactions after that many seconds
    time_t const MAX_RELAY_TIME = (60 * 60 * 4); // at most that many seconds between resends
    float const ACCEPT_THRESHOLD = 1.0f;

    //! Max DB check interval for relayable txes
    constexpr const std::chrono::minutes max_relayable_check{2};

    constexpr const std::chrono::seconds forward_delay_average{CRYPTONOTE_FORWARD_DELAY_AVERAGE};

    // a kind of increasing backoff within min/max bounds
    uint64_t get_relay_delay(time_t now, time_t received)
    {
      time_t d = (now - received + MIN_RELAY_TIME) / MIN_RELAY_TIME * MIN_RELAY_TIME;
      if (d > MAX_RELAY_TIME)
        d = MAX_RELAY_TIME;
      return d;
    }



    uint64_t get_transaction_weight_limit(uint8_t version)
    {
     return 0;
    }

    // external lock must be held for the comparison+set to work properly
    void set_if_less(std::atomic<time_t>& next_check, const time_t candidate) noexcept
    {
      if (candidate < next_check.load(std::memory_order_relaxed))
        next_check = candidate;
    }
  }
  //---------------------------------------------------------------------------------
  //---------------------------------------------------------------------------------
  tx_memory_pool::tx_memory_pool(Blockchain& bchs): m_blockchain(bchs), m_cookie(0), m_txpool_max_weight(DEFAULT_TXPOOL_MAX_WEIGHT), m_txpool_weight(0), m_mine_stem_txes(false), m_next_check(std::time(nullptr))
  {
    // class code expects unsigned values throughout
    if (m_next_check < time_t(0))
      throw std::runtime_error{"Unexpected time_t (system clock) value"};
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_tx(transaction &tx,  const crypto::hash &id, const cryptonote::blobdata &blob, size_t tx_weight, tx_verification_context& tvc, relay_method tx_relay, bool relayed, uint8_t version)
  {
    const bool kept_by_block = (tx_relay == relay_method::block);

    // this should already be called with that lock, but let's make it explicit for clarity
    CRITICAL_REGION_LOCAL(m_transactions_lock);

    PERF_TIMER(add_tx);

    // we do not accept transactions that timed out before, unless they're
    // kept_by_block
    if (!kept_by_block && m_timed_out_transactions.find(id) != m_timed_out_transactions.end())
    {
      // not clear if we should set that, since verifivation (sic) did not fail before, since
      // the tx was accepted before timing out.
      tvc.m_verifivation_failed = true;
      return false;
    }

    if(!check_inputs_types_supported(tx))
    {
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_input = true;
      return false;
    }

    // fee per kilobyte, size rounded up.
    uint64_t fee=tx.rct_signatures.txnFee;

    
    if (!kept_by_block && !m_blockchain.check_fee(tx_weight, fee))
    {
      tvc.m_verifivation_failed = true;
      tvc.m_fee_too_low = true;
      return false;
    }

    // if the transaction came from a block popped from the chain,
    // don't check if we have its key images as spent.
    // TODO: Investigate why not?
    if(!kept_by_block)
    {
      if(have_tx_keyimges_as_spent(tx))
      {
        LOG_PRINT_L1("Transaction with id= "<< id << " used already spent key images");
        tvc.m_verifivation_failed = true;
        tvc.m_double_spend = true;
        return false;
      }
    }

    if (!m_blockchain.check_tx_outputs(tx, tvc))
    {
      LOG_PRINT_L1("Transaction with id= "<< id << " has at least one invalid output");
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_output = true;
      return false;
    }

    // assume failure during verification steps until success is certain
    tvc.m_verifivation_failed = true;

    time_t receive_time = time(nullptr);

    cryptonote::txpool_tx_meta_t meta{};
    bool ch_inp_res = m_blockchain.check_tx_inputs(tx, tvc);
    if(!ch_inp_res)
    {
      // if the transaction was valid before (kept_by_block), then it
      // may become valid again, so ignore the failed inputs check.
      if(kept_by_block)
      {
        meta.weight = tx_weight;
        meta.fee = fee;
        meta.receive_time = receive_time;
        meta.last_relayed_time = time(NULL);
        meta.relayed = relayed;
        meta.set_relay_method(tx_relay);
        meta.pruned = tx.pruned;
        meta.bf_padding = 0;
        memset(meta.padding, 0, sizeof(meta.padding));
        try
        {
          if (kept_by_block)
            m_parsed_tx_cache.insert(std::make_pair(id, tx));
          CRITICAL_REGION_LOCAL1(m_blockchain);
          LockedTXN lock(m_blockchain.get_db());
          if (!insert_key_images(tx, id, tx_relay))
            return false;

          m_blockchain.add_txpool_tx(id, blob, meta);
          m_txs_by_fee_and_time.emplace(std::pair<double, std::time_t>(fee / (double)(tx_weight ? tx_weight : 1), receive_time), id);
          lock.commit();
        }
        catch (const std::exception &e)
        {
          MERROR("Error adding transaction to txpool: " << e.what());
          return false;
        }
        tvc.m_verifivation_impossible = true;
        tvc.m_added_to_pool = true;
      }else
      {
        LOG_PRINT_L1("tx used wrong inputs, rejected");
        tvc.m_verifivation_failed = true;
        tvc.m_invalid_input = true;
        return false;
      }
    }else
    {
      try
      {
        if (kept_by_block)
          m_parsed_tx_cache.insert(std::make_pair(id, tx));
        CRITICAL_REGION_LOCAL1(m_blockchain);
        LockedTXN lock(m_blockchain.get_db());

        const bool existing_tx = m_blockchain.get_txpool_tx_meta(id, meta);
        if (existing_tx)
        {
          /* If Dandelion++ loop. Do not use txes in the `local` state in the
             loop detection - txes in that state should be outgoing over i2p/tor
             then routed back via public dandelion++ stem. Pretend to be
             another stem node in that situation, a loop over the public
             network hasn't been hit yet. */
          if (tx_relay == relay_method::stem && meta.dandelionpp_stem)
            tx_relay = relay_method::fluff;
        }
        else
          meta.set_relay_method(relay_method::none);

        if (meta.upgrade_relay_method(tx_relay) || !existing_tx) // synchronize with embargo timer or stem/fluff out-of-order messages
        {
          using clock = std::chrono::system_clock;
          auto last_relayed_time = std::numeric_limits<decltype(meta.last_relayed_time)>::max();
          if (tx_relay == relay_method::forward)
          {
            last_relayed_time = clock::to_time_t(clock::now() + crypto::random_poisson_seconds{forward_delay_average}());
            set_if_less(m_next_check, time_t(last_relayed_time));
          }
          // else the `set_relayed` function will adjust the time accordingly later

          //update transactions container
          meta.last_relayed_time = last_relayed_time;
          meta.receive_time = receive_time;
          meta.weight = tx_weight;
          meta.fee = fee;
          meta.relayed = relayed;
          meta.pruned = tx.pruned;
          meta.bf_padding = 0;
          memset(meta.padding, 0, sizeof(meta.padding));

          if (!insert_key_images(tx, id, tx_relay))
            return false;

          m_blockchain.remove_txpool_tx(id);
          m_blockchain.add_txpool_tx(id, blob, meta);
          m_txs_by_fee_and_time.emplace(std::pair<double, std::time_t>(fee / (double)(tx_weight ? tx_weight : 1), receive_time), id);
        }
        lock.commit();
      }
      catch (const std::exception &e)
      {
        MERROR("internal error: error adding transaction to txpool: " << e.what());
        return false;
      }
      tvc.m_added_to_pool = true;

      static_assert(unsigned(relay_method::none) == 0, "expected relay_method::none value to be zero");
      if(meta.fee > 0 && tx_relay != relay_method::forward)
        tvc.m_relay = tx_relay;
    }

    tvc.m_verifivation_failed = false;
    m_txpool_weight += tx_weight;

    ++m_cookie;

    MINFO("Transaction added to pool: tx_hash " << id << " weight: " << tx_weight << " fee/byte: " << (fee / (double)(tx_weight ? tx_weight : 1)));

    prune(m_txpool_max_weight);

    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_tx(transaction &tx, tx_verification_context& tvc, relay_method tx_relay, bool relayed, uint8_t version)
  {
    crypto::hash h = null_hash;
    cryptonote::blobdata bl;
    t_serializable_object_to_blob(tx, bl);
    if (bl.size() == 0 || !get_transaction_hash(tx, h))
      return false;
    return add_tx(tx, h, bl, get_transaction_weight(tx, bl.size()), tvc, tx_relay, relayed, version);
  }
  //---------------------------------------------------------------------------------
  size_t tx_memory_pool::get_txpool_weight() const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    return m_txpool_weight;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::set_txpool_max_weight(size_t bytes)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    m_txpool_max_weight = bytes;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::prune(size_t bytes)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    if (bytes == 0)
      bytes = m_txpool_max_weight;
    CRITICAL_REGION_LOCAL1(m_blockchain);
    LockedTXN lock(m_blockchain.get_db());
    bool changed = false;

    // this will never remove the first one, but we don't care
    auto it = --m_txs_by_fee_and_time.end();
    while (it != m_txs_by_fee_and_time.begin())
    {
      if (m_txpool_weight <= bytes)
        break;
      try
      {
        const crypto::hash &tx_hash = it->second;
        txpool_tx_meta_t meta;
        if (!m_blockchain.get_txpool_tx_meta(tx_hash, meta))
        {
          MERROR("Failed to find tx_meta in txpool");
          return;
        }
        // don't prune the kept_by_block ones, they're likely added because we're adding a block with those
        if (meta.kept_by_block)
        {
          --it;
          continue;
        }
        cryptonote::blobdata txblob = m_blockchain.get_txpool_tx_blob(tx_hash, relay_category::all);
        cryptonote::transaction_prefix tx;
        if (!parse_and_validate_tx_prefix_from_blob(txblob, tx))
        {
          MERROR("Failed to parse tx from txpool");
          return;
        }
        // remove first, in case this throws, so key images aren't removed
        MINFO("Pruning tx " << tx_hash << " from txpool: weight: " << meta.weight << ", fee/byte: " << it->first.first);
        m_blockchain.remove_txpool_tx(tx_hash);
        m_txpool_weight -= meta.weight;
        remove_transaction_keyimages(tx, tx_hash);
        MINFO("Pruned tx " << tx_hash << " from txpool: weight: " << meta.weight << ", fee/byte: " << it->first.first);
        m_txs_by_fee_and_time.erase(it--);
        changed = true;
      }
      catch (const std::exception &e)
      {
        MERROR("Error while pruning txpool: " << e.what());
        return;
      }
    }
    lock.commit();
    if (changed)
      ++m_cookie;
    if (m_txpool_weight > bytes)
      MINFO("Pool weight after pruning is larger than limit: " << m_txpool_weight << "/" << bytes);
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::insert_key_images(const transaction_prefix &tx, const crypto::hash &id, relay_method tx_relay)
  {
     for(const auto& in: tx.vin)
    {
      const auto & ki = boost::get<txin_to_key>(in).k_image;
      if(m_spent_kis.count(ki))
        return false;
    }
      

    for(const auto& in: tx.vin)
    {
      const auto & ki = boost::get<txin_to_key>(in).k_image;
      m_spent_kis.insert(ki);
    }
    ++m_cookie;
    return true;
  }
  //---------------------------------------------------------------------------------
  //FIXME: Can return early before removal of all of the key images.
  //       At the least, need to make sure that a false return here
  //       is treated properly.  Should probably not return early, however.
  bool tx_memory_pool::remove_transaction_keyimages(const transaction_prefix& tx, const crypto::hash &actual_hash)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    // ND: Speedup
    for(const txin_v& vi: tx.vin)
    {
      const auto & ki = boost::get<txin_to_key>(vi).k_image;

      const auto c = m_spent_kis.erase(ki);
      if(c==0){
        MERROR("key image not found " <<epee::string_tools::pod_to_hex(ki));
      }
    }
    ++m_cookie;
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::take_tx(const crypto::hash &id, transaction &tx, cryptonote::blobdata &txblob, size_t& tx_weight, uint64_t& fee, bool &relayed, bool &do_not_relay, bool &pruned)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    auto sorted_it = find_tx_in_sorted_container(id);

    try
    {
      LockedTXN lock(m_blockchain.get_db());
      txpool_tx_meta_t meta;
      if (!m_blockchain.get_txpool_tx_meta(id, meta))
      {
        MERROR("Failed to find tx_meta in txpool");
        return false;
      }
      txblob = m_blockchain.get_txpool_tx_blob(id, relay_category::all);
      auto ci = m_parsed_tx_cache.find(id);
      if (ci != m_parsed_tx_cache.end())
      {
        tx = ci->second;
      }
      else if (!(meta.pruned ? parse_and_validate_tx_base_from_blob(txblob, tx) : parse_and_validate_tx_from_blob(txblob, tx)))
      {
        MERROR("Failed to parse tx from txpool");
        return false;
      }
      else
      {
        tx.set_hash(id);
      }
      tx_weight = meta.weight;
      fee = meta.fee;
      relayed = meta.relayed;
      do_not_relay = meta.do_not_relay;
      pruned = meta.pruned;

      // remove first, in case this throws, so key images aren't removed
      m_blockchain.remove_txpool_tx(id);
      m_txpool_weight -= tx_weight;
      remove_transaction_keyimages(tx, id);
      lock.commit();
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to remove tx from txpool: " << e.what());
      return false;
    }

    if (sorted_it != m_txs_by_fee_and_time.end())
      m_txs_by_fee_and_time.erase(sorted_it);
    ++m_cookie;
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::get_transaction_info(const crypto::hash &tx_hash, tx_details &td) const
  {
    PERF_TIMER(get_transaction_info);
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    try
    {
      LockedTXN lock(m_blockchain.get_db());
      txpool_tx_meta_t meta;
      if (!m_blockchain.get_txpool_tx_meta(tx_hash, meta))
      {
        MERROR("Failed to find tx in txpool");
        return false;
      }
      cryptonote::blobdata txblob = m_blockchain.get_txpool_tx_blob(tx_hash, relay_category::all);
      auto ci = m_parsed_tx_cache.find(tx_hash);
      if (ci != m_parsed_tx_cache.end())
      {
        td.tx = ci->second;
      }
      else if (!(meta.pruned ? parse_and_validate_tx_base_from_blob(txblob, td.tx) : parse_and_validate_tx_from_blob(txblob, td.tx)))
      {
        MERROR("Failed to parse tx from txpool");
        return false;
      }
      else
      {
        td.tx.set_hash(tx_hash);
      }
      td.blob_size = txblob.size();
      td.weight = meta.weight;
      td.fee = meta.fee;
      td.kept_by_block = meta.kept_by_block;
      td.receive_time = meta.receive_time;
      td.last_relayed_time = meta.dandelionpp_stem ? 0 : meta.last_relayed_time;
      td.relayed = meta.relayed;
      td.do_not_relay = meta.do_not_relay;
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to get tx from txpool: " << e.what());
      return false;
    }

    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::get_complement(const std::vector<crypto::hash> &hashes, std::vector<cryptonote::blobdata> &txes) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    m_blockchain.for_all_txpool_txes([this, &hashes, &txes](const crypto::hash &tx_hash, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref*) {
      const auto tx_relay_method = meta.get_relay_method();
      if (tx_relay_method != relay_method::block && tx_relay_method != relay_method::fluff)
        return true;
      const auto i = std::find(hashes.begin(), hashes.end(), tx_hash);
      if (i == hashes.end())
      {
        cryptonote::blobdata bd;
        try
        {
          if (!m_blockchain.get_txpool_tx_blob(tx_hash, bd, cryptonote::relay_category::broadcasted))
          {
            MERROR("Failed to get blob for txpool transaction " << tx_hash);
            return true;
          }
          txes.emplace_back(std::move(bd));
        }
        catch (const std::exception &e)
        {
          MERROR("Failed to get blob for txpool transaction " << tx_hash << ": " << e.what());
          return true;
        }
      }
      return true;
    }, false);
    return true;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::on_idle()
  {
    m_remove_stuck_tx_interval.do_call([this](){
      return remove_stuck_transactions();
    });
  }
  //---------------------------------------------------------------------------------
  sorted_tx_container::iterator tx_memory_pool::find_tx_in_sorted_container(const crypto::hash& id) const
  {
    return std::find_if( m_txs_by_fee_and_time.begin(), m_txs_by_fee_and_time.end()
                       , [&](const sorted_tx_container::value_type& a){
                         return a.second == id;
                       }
    );
  }
  //---------------------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::remove_stuck_transactions()
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    std::list<std::pair<crypto::hash, uint64_t>> remove;
    m_blockchain.for_all_txpool_txes([this, &remove](const crypto::hash &tx_hash, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref*) {
      const uint64_t tx_age = time(nullptr) - meta.receive_time;

      if(tx_age > CRYPTONOTE_MEMPOOL_TX_LIVETIME  )
      {
        LOG_PRINT_L1("Tx " << tx_hash << " removed from tx pool due to outdated, age: " << tx_age );
        auto sorted_it = find_tx_in_sorted_container(tx_hash);
        if (sorted_it == m_txs_by_fee_and_time.end())
        {
          LOG_PRINT_L1("Removing tx " << tx_hash << " from tx pool, but it was not found in the sorted txs container!");
        }
        else
        {
          m_txs_by_fee_and_time.erase(sorted_it);
        }
        m_timed_out_transactions.insert(tx_hash);
        remove.push_back(std::make_pair(tx_hash, meta.weight));
      }
      return true;
    }, false, relay_category::all);

    if (!remove.empty())
    {
      LockedTXN lock(m_blockchain.get_db());
      for (const std::pair<crypto::hash, uint64_t> &entry: remove)
      {
        const crypto::hash &tx_hash = entry.first;
        try
        {
          cryptonote::blobdata bd = m_blockchain.get_txpool_tx_blob(tx_hash, relay_category::all);
          cryptonote::transaction_prefix tx;
          if (!parse_and_validate_tx_prefix_from_blob(bd, tx))
          {
            MERROR("Failed to parse tx from txpool");
            // continue
          }
          else
          {
            // remove first, so we only remove key images if the tx removal succeeds
            m_blockchain.remove_txpool_tx(tx_hash);
            m_txpool_weight -= entry.second;
            remove_transaction_keyimages(tx, tx_hash);
          }
        }
        catch (const std::exception &e)
        {
          MWARNING("Failed to remove stuck transaction: " << tx_hash);
          // ignore error
        }
      }
      lock.commit();
      ++m_cookie;
    }
    return true;
  }
 
  //---------------------------------------------------------------------------------
  void tx_memory_pool::set_relayed(const epee::span<const crypto::hash> hashes, const relay_method method)
  {
    crypto::random_poisson_seconds embargo_duration{dandelionpp_embargo_average};
    const auto now = std::chrono::system_clock::now();
    uint64_t next_relay = uint64_t{std::numeric_limits<time_t>::max()};

    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    LockedTXN lock(m_blockchain.get_db());
    for (const auto& hash : hashes)
    {
      try
      {
        txpool_tx_meta_t meta;
        if (m_blockchain.get_txpool_tx_meta(hash, meta))
        {
          // txes can be received as "stem" or "fluff" in either order
          meta.upgrade_relay_method(method);
          meta.relayed = true;

          if (meta.dandelionpp_stem)
          {
            meta.last_relayed_time = std::chrono::system_clock::to_time_t(now + embargo_duration());
            next_relay = std::min(next_relay, meta.last_relayed_time);
          }
          else
            meta.last_relayed_time = std::chrono::system_clock::to_time_t(now);

          m_blockchain.update_txpool_tx(hash, meta);
        }
      }
      catch (const std::exception &e)
      {
        MERROR("Failed to update txpool transaction metadata: " << e.what());
        // continue
      }
    }
    lock.commit();
    set_if_less(m_next_check, time_t(next_relay));
  }
  //---------------------------------------------------------------------------------
  size_t tx_memory_pool::get_transactions_count(bool include_sensitive) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    return m_blockchain.get_txpool_tx_count(include_sensitive);
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::get_transactions(std::vector<transaction>& txs, bool include_sensitive) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    const relay_category category = include_sensitive ? relay_category::all : relay_category::broadcasted;
    txs.reserve(m_blockchain.get_txpool_tx_count(include_sensitive));
    m_blockchain.for_all_txpool_txes([&txs](const crypto::hash &tx_hash, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd){
      transaction tx;
      if (!(meta.pruned ? parse_and_validate_tx_base_from_blob(*bd, tx) : parse_and_validate_tx_from_blob(*bd, tx)))
      {
        MERROR("Failed to parse tx from txpool");
        // continue
        return true;
      }
      tx.set_hash(tx_hash);
      txs.push_back(std::move(tx));
      return true;
    }, true, category);
  }
  //------------------------------------------------------------------
  void tx_memory_pool::get_transaction_hashes(std::vector<crypto::hash>& txs, bool include_sensitive) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    const relay_category category = include_sensitive ? relay_category::all : relay_category::broadcasted;
    txs.reserve(m_blockchain.get_txpool_tx_count(include_sensitive));
    m_blockchain.for_all_txpool_txes([&txs](const crypto::hash &tx_hash, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd){
      txs.push_back(tx_hash);
      return true;
    }, false, category);
  }
  //------------------------------------------------------------------
  void tx_memory_pool::get_transaction_backlog(std::vector<tx_backlog_entry>& backlog, bool include_sensitive) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    const uint64_t now = time(NULL);
    const relay_category category = include_sensitive ? relay_category::all : relay_category::broadcasted;
    backlog.reserve(m_blockchain.get_txpool_tx_count(include_sensitive));
    m_blockchain.for_all_txpool_txes([&backlog, now](const crypto::hash &tx_hash, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd){
      backlog.push_back({meta.weight, meta.fee, meta.receive_time - now});
      return true;
    }, false, category);
  }
  //------------------------------------------------------------------
  void tx_memory_pool::get_transaction_stats(struct txpool_stats& stats, bool include_sensitive) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    const uint64_t now = time(NULL);
    const relay_category category = include_sensitive ? relay_category::all : relay_category::broadcasted;
    std::map<uint64_t, txpool_histo> agebytes;
    stats.txs_total = m_blockchain.get_txpool_tx_count(include_sensitive);
    std::vector<uint32_t> weights;
    weights.reserve(stats.txs_total);
    m_blockchain.for_all_txpool_txes([&stats, &weights, now, &agebytes](const crypto::hash &tx_hash, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd){
      weights.push_back(meta.weight);
      stats.bytes_total += meta.weight;
      if (!stats.bytes_min || meta.weight < stats.bytes_min)
        stats.bytes_min = meta.weight;
      if (meta.weight > stats.bytes_max)
        stats.bytes_max = meta.weight;
      if (!meta.relayed)
        stats.num_not_relayed++;
      stats.fee_total += meta.fee;
      if (!stats.oldest || meta.receive_time < stats.oldest)
        stats.oldest = meta.receive_time;
      if (meta.receive_time < now - 600)
        stats.num_10m++;
      uint64_t age = now - meta.receive_time + (now == meta.receive_time);
      agebytes[age].txs++;
      agebytes[age].bytes += meta.weight;
      return true;
    }, false, category);

    stats.bytes_med = epee::misc_utils::median(weights);
    if (stats.txs_total > 1)
    {
      /* looking for 98th percentile */
      size_t end = stats.txs_total * 0.02;
      uint64_t delta, factor;
      std::map<uint64_t, txpool_histo>::iterator it, i2;
      if (end)
      {
        /* If enough txs, spread the first 98% of results across
         * the first 9 bins, drop final 2% in last bin.
         */
        it = agebytes.end();
        size_t cumulative_num = 0;
        /* Since agebytes is not empty and end is nonzero, the
         * below loop can always run at least once.
         */
        do {
          --it;
          cumulative_num += it->second.txs;
        } while (it != agebytes.begin() && cumulative_num < end);
        stats.histo_98pc = it->first;
        factor = 9;
        delta = it->first;
        stats.histo.resize(10);
      } else
      {
        /* If not enough txs, don't reserve the last slot;
         * spread evenly across all 10 bins.
         */
        stats.histo_98pc = 0;
        it = agebytes.end();
        factor = stats.txs_total > 9 ? 10 : stats.txs_total;
        delta = now - stats.oldest;
        stats.histo.resize(factor);
      }
      if (!delta)
        delta = 1;
      for (i2 = agebytes.begin(); i2 != it; i2++)
      {
        size_t i = (i2->first * factor - 1) / delta;
        stats.histo[i].txs += i2->second.txs;
        stats.histo[i].bytes += i2->second.bytes;
      }
      for (; i2 != agebytes.end(); i2++)
      {
        stats.histo[factor].txs += i2->second.txs;
        stats.histo[factor].bytes += i2->second.bytes;
      }
    }
  }
  //------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::get_transactions_and_spent_keys_info(std::vector<tx_info>& tx_infos,  bool include_sensitive_data) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    const relay_category category = include_sensitive_data ? relay_category::all : relay_category::broadcasted;
    const size_t count = m_blockchain.get_txpool_tx_count(include_sensitive_data);
    tx_infos.reserve(count);
    m_blockchain.for_all_txpool_txes([&tx_infos,  include_sensitive_data](const crypto::hash &tx_hash, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd){
      tx_info txi;
      txi.id_hash = epee::string_tools::pod_to_hex(tx_hash);
      txi.tx_blob = blobdata(bd->data(), bd->size());
      transaction tx;
      if (!(meta.pruned ? parse_and_validate_tx_base_from_blob(*bd, tx) : parse_and_validate_tx_from_blob(*bd, tx)))
      {
        MERROR("Failed to parse tx from txpool");
        // continue
        return true;
      }
      tx.set_hash(tx_hash);
      txi.tx_json = obj_to_json_str(tx);
      txi.blob_size = bd->size();
      txi.weight = meta.weight;
      txi.fee = meta.fee;
      txi.kept_by_block = meta.kept_by_block;
      // In restricted mode we do not include this data:
      txi.receive_time = include_sensitive_data ? meta.receive_time : 0;
      txi.relayed = meta.relayed;
      // In restricted mode we do not include this data:
      txi.last_relayed_time = (include_sensitive_data && !meta.dandelionpp_stem) ? meta.last_relayed_time : 0;
      txi.do_not_relay = meta.do_not_relay;
      tx_infos.push_back(std::move(txi));
      return true;
    }, true, category);


    return true;
  }
 
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::check_for_key_images(const std::vector<crypto::key_image>& key_images, std::vector<bool>& spent) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    spent.clear();

    for (const auto& ki : key_images)
    {
      const auto is_spent = m_spent_kis.count(ki)>0;
    
      spent.push_back(is_spent);
    }

    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::get_transaction(const crypto::hash& id, cryptonote::blobdata& txblob, relay_category tx_category) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    try
    {
      return m_blockchain.get_txpool_tx_blob(id, txblob, tx_category);
    }
    catch (const std::exception &e)
    {
      return false;
    }
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::on_blockchain_inc(uint64_t new_block_height, const crypto::hash& top_block_id)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    m_parsed_tx_cache.clear();
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::on_blockchain_dec(uint64_t new_block_height, const crypto::hash& top_block_id)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    m_parsed_tx_cache.clear();
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx(const crypto::hash &id, relay_category tx_category) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    return m_blockchain.get_db().txpool_has_tx(id, tx_category);
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx_keyimges_as_spent(const transaction& tx) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, true);//should never fail
      if(have_tx_keyimg_as_spent(tokey_in.k_image))
         return true;
    }
    return false;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx_keyimg_as_spent(const crypto::key_image& key_im) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    return m_spent_kis.count(key_im)!=0;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::lock() const
  {
    m_transactions_lock.lock();
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::unlock() const
  {
    m_transactions_lock.unlock();
  }

  
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_key_images(const std::unordered_set<crypto::key_image>& k_images, const transaction_prefix& tx)
  {
    for(size_t i = 0; i!= tx.vin.size(); i++)
    {
      CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_to_key, itk, false);
      if(k_images.count(itk.k_image))
        return true;
    }
    return false;
  }
 
  //---------------------------------------------------------------------------------
  std::string tx_memory_pool::print_pool(bool short_format) const
  {
    std::stringstream ss;
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    m_blockchain.for_all_txpool_txes([&ss, short_format](const crypto::hash &tx_hash, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *txblob) {
      ss << "id: " << tx_hash << std::endl;
      if (!short_format) {
        cryptonote::transaction tx;
        if (!(meta.pruned ? parse_and_validate_tx_base_from_blob(*txblob, tx) : parse_and_validate_tx_from_blob(*txblob, tx)))
        {
          MERROR("Failed to parse tx from txpool");
          return true; // continue
        }
        ss << obj_to_json_str(tx) << std::endl;
      }
      ss << "blob_size: " << (short_format ? "-" : std::to_string(txblob->size())) << std::endl
        << "weight: " << meta.weight << std::endl
        << "fee: " << print_money(meta.fee) << std::endl
        << "kept_by_block: " << (meta.kept_by_block ? 'T' : 'F') << std::endl
        << "is_local" << (meta.is_local ? 'T' : 'F') << std::endl;
      return true;
    }, !short_format, relay_category::all);

    return ss.str();
  }
  //---------------------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::fill_block_template(BlockTemplate & bt)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    block &bl = bt.b;
    uint64_t fee = 0;

    //baseline empty block
   const auto block_reward = get_block_reward();
  
    const size_t max_total_weight =16*1024*1024;

    MINFO("Filling block template, median weight " << m_txs_by_fee_and_time.size() << " txes in the pool");

    LockedTXN lock(m_blockchain.get_db());

    uint64_t total_weight =0;
    for (auto & e: m_txs_by_fee_and_time)
    {
      const auto & tx_hash = e.second;
      txpool_tx_meta_t meta;
      if (!m_blockchain.get_txpool_tx_meta(tx_hash, meta))
      {
        MERROR("  failed to find tx meta: " << tx_hash<< " (will only print once)");
        continue;
      }

      if (meta.pruned)
      {
        throw_and_log(" tx is pruned"<<tx_hash);
        continue;
      }

      // Can not exceed maximum block weight
      if (max_total_weight < total_weight + meta.weight)
      {
        MINFO("  would exceed maximum block weight");
        continue;
      }

      // "local" and "stem" txes are filtered above

      bl.tx_hashes.push_back(tx_hash);
      total_weight += meta.weight;
      fee += meta.fee;
      MDEBUG("  added, new block weight " << total_weight << "/" << max_total_weight );
    }
    
    lock.commit();
    bt.fee = fee;
    bt.expected_reward = block_reward + fee;
    bt.txs_weight = total_weight;
    MINFO("Block template filled with " << bl.tx_hashes.size() << " txes, weight "
        << total_weight << "/" << max_total_weight << ", coinbase " << print_money(bt.expected_reward )
        << " (including " << print_money(fee) << " in fees)");
    return true;
  }
  //---------------------------------------------------------------------------------
  size_t tx_memory_pool::validate(uint8_t version)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    std::unordered_set<crypto::hash> remove;

    m_txpool_weight = 0;
    m_blockchain.for_all_txpool_txes([this, &remove](const crypto::hash &tx_hash, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref*) {
      m_txpool_weight += meta.weight;
      if (m_blockchain.have_tx(tx_hash)) {
        LOG_PRINT_L1("Transaction " << tx_hash << " is in the blockchain, removing it from pool");
        remove.insert(tx_hash);
      }
      return true;
    }, false, relay_category::all);

    size_t n_removed = 0;
    if (!remove.empty())
    {
      LockedTXN lock(m_blockchain.get_db());
      for (const crypto::hash &tx_hash: remove)
      {
        try
        {
          cryptonote::blobdata txblob = m_blockchain.get_txpool_tx_blob(tx_hash, relay_category::all);
          cryptonote::transaction tx;
          if (!parse_and_validate_tx_from_blob(txblob, tx)) // remove pruned ones on startup, they're meant to be temporary
          {
            MERROR("Failed to parse tx from txpool");
            continue;
          }
          // remove tx from db first
          m_blockchain.remove_txpool_tx(tx_hash);
          m_txpool_weight -= get_transaction_weight(tx, txblob.size());
          remove_transaction_keyimages(tx, tx_hash);
          auto sorted_it = find_tx_in_sorted_container(tx_hash);
          if (sorted_it == m_txs_by_fee_and_time.end())
          {
            LOG_PRINT_L1("Removing tx " << tx_hash << " from tx pool, but it was not found in the sorted txs container!");
          }
          else
          {
            m_txs_by_fee_and_time.erase(sorted_it);
          }
          ++n_removed;
        }
        catch (const std::exception &e)
        {
          MERROR("Failed to remove invalid tx from pool");
          // continue
        }
      }
      lock.commit();
    }
    if (n_removed > 0)
      ++m_cookie;
    return n_removed;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::init(size_t max_txpool_weight, bool mine_stem_txes)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    m_txpool_max_weight = max_txpool_weight ? max_txpool_weight : DEFAULT_TXPOOL_MAX_WEIGHT;
    m_txs_by_fee_and_time.clear();
    m_spent_kis.clear();
    m_txpool_weight = 0;
    std::vector<crypto::hash> remove;

    // first add the not kept by block, then the kept by block,
    // to avoid rejection due to key image collision
    for (int pass = 0; pass < 2; ++pass)
    {
      const bool kept = pass == 1;
      bool r = m_blockchain.for_all_txpool_txes([this, &remove, kept](const crypto::hash &tx_hash, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd) {
        if (!!kept != !!meta.kept_by_block)
          return true;
        cryptonote::transaction_prefix tx;
        if (!parse_and_validate_tx_prefix_from_blob(*bd, tx))
        {
          MWARNING("Failed to parse tx from txpool, removing");
          remove.push_back(tx_hash);
          return true;
        }
        if (!insert_key_images(tx, tx_hash, meta.get_relay_method()))
        {
          MFATAL("Failed to insert key images from txpool tx");
          return false;
        }
        m_txs_by_fee_and_time.emplace(std::pair<double, time_t>(meta.fee / (double)meta.weight, meta.receive_time), tx_hash);
        m_txpool_weight += meta.weight;
        return true;
      }, true, relay_category::all);
      if (!r)
        return false;
    }
    if (!remove.empty())
    {
      LockedTXN lock(m_blockchain.get_db());
      for (const auto &tx_hash: remove)
      {
        try
        {
          m_blockchain.remove_txpool_tx(tx_hash);
        }
        catch (const std::exception &e)
        {
          MWARNING("Failed to remove corrupt transaction: " << tx_hash);
          // ignore error
        }
      }
      lock.commit();
    }

    m_mine_stem_txes = mine_stem_txes;
    m_cookie = 0;

    // Ignore deserialization error
    return true;
  }

  //---------------------------------------------------------------------------------
  bool tx_memory_pool::deinit()
  {
    return true;
  }

   //---------------------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::get_relayable_transactions(std::vector<std::tuple<crypto::hash, cryptonote::blobdata, relay_method>> &txs)
  {
    using clock = std::chrono::system_clock;

    const uint64_t now = time(NULL);
    if (uint64_t{std::numeric_limits<time_t>::max()} < now || time_t(now) < m_next_check)
      return false;

    uint64_t next_check = clock::to_time_t(clock::from_time_t(time_t(now)) + max_relayable_check);
    std::vector<std::pair<crypto::hash, txpool_tx_meta_t>> change_timestamps;

    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    LockedTXN lock(m_blockchain.get_db());
    txs.reserve(m_blockchain.get_txpool_tx_count());
    m_blockchain.for_all_txpool_txes([this, now, &txs, &change_timestamps, &next_check](const crypto::hash &tx_hash, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *){
      // 0 fee transactions are never relayed
      if(!meta.pruned && meta.fee > 0 && !meta.do_not_relay)
      {
        const relay_method tx_relay = meta.get_relay_method();
        switch (tx_relay)
        {
          case relay_method::stem:
          case relay_method::forward:
            if (meta.last_relayed_time > now)
            {
              next_check = std::min(next_check, meta.last_relayed_time);
              return true; // continue to next tx
            }
            change_timestamps.emplace_back(tx_hash, meta);
            break;
          default:
          case relay_method::none:
            return true;
          case relay_method::local:
          case relay_method::fluff:
          case relay_method::block:
            if (now - meta.last_relayed_time <= get_relay_delay(now, meta.receive_time))
              return true; // continue to next tx
            break;
        }

        // if the tx is older than half the max lifetime, we don't re-relay it, to avoid a problem
        // mentioned by smooth where nodes would flush txes at slightly different times, causing
        // flushed txes to be re-added when received from a node which was just about to flush it
        uint64_t max_age =  CRYPTONOTE_MEMPOOL_TX_LIVETIME;
        if (now - meta.receive_time <= max_age / 2)
        {
          try
          {
            txs.emplace_back(tx_hash, m_blockchain.get_txpool_tx_blob(tx_hash, relay_category::all), tx_relay);
          }
          catch (const std::exception &e)
          {
            MERROR("Failed to get transaction blob from db");
            // ignore error
          }
        }
      }
      return true;
    }, false, relay_category::relayable);

    for (auto& elem : change_timestamps)
    {
      /* These transactions are still in forward or stem state, so the field
         represents the next time a relay should be attempted. Will be
         overwritten when the state is upgraded to stem, fluff or block. This
         function is only called every ~2 minutes, so this resetting should be
         unnecessary, but is primarily a precaution against potential changes
   to the callback routines. */
      elem.second.last_relayed_time = now + get_relay_delay(now, elem.second.receive_time);
      m_blockchain.update_txpool_tx(elem.first, elem.second);
    }

    m_next_check = time_t(next_check);
    return true;
  }

}
