#include <algorithm>
#include <cstdio>
#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/format.hpp>

#include "include_base_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "tx_pool.h"
#include "blockchain.h"
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/miner.h"
#include "hardforks/hardforks.h"
#include "misc_language.h"
#include "profile_tools.h"
#include "file_io_utils.h"
#include "int-util.h"
#include "common/threadpool.h"
#include "common/boost_serialization_helper.h"
#include "warnings.h"
#include "crypto/hash.h"
#include "cryptonote_core.h"
#include "ringct/rctSigs.h"
#include "common/perf_timer.h"
#include "common/notify.h"
#include "common/varint.h"
#include "common/pruning.h"
#include "time_helper.h"
#include "string_tools.h"
#include "crypto/rx-hash.h"

namespace cryptonote{


  //-----------------------------------------------------------------------------------------------
  static bool check_tx_inputs_keyimages_diff(const transaction& tx) const
  {
    std::unordered_set<crypto::key_image> ki;
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      if(!ki.insert(tokey_in.k_image).second)
        return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  static bool check_tx_inputs_ring_members_diff(const transaction& tx) const
  {
      for(const auto& in: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
        for (size_t n = 1; n < tokey_in.key_offsets.size(); ++n)
          if (tokey_in.key_offsets[n] == 0)
            return false;
      }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  static bool check_tx_inputs_keyimages_domain(const transaction& tx) const
  {
    std::unordered_set<crypto::key_image> ki;
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      if (!(rct::scalarmultKey(rct::ki2rct(tokey_in.k_image), rct::curveOrder()) == rct::identity()))
        return false;
    }
    return true;
  }


  //-----------------------------------------------------------------------------------------------
  bool check_tx_semantic(const transaction& tx)
  {
    if(!tx.vin.size())
    {
      MERROR_VER("tx with empty inputs, rejected for tx id= " << get_transaction_hash(tx));
      return false;
    }

    if(!check_inputs_types_supported(tx))
    {
      MERROR_VER("unsupported input types for tx id= " << get_transaction_hash(tx));
      return false;
    }

    if(!check_outs_valid(tx))
    {
      MERROR_VER("tx with invalid outputs, rejected for tx id= " << get_transaction_hash(tx));
      return false;
    }
 
    //check if tx use different key images
    if(!check_tx_inputs_keyimages_diff(tx))
    {
      MERROR_VER("tx uses a single key image more than once");
      return false;
    }

    if (!check_tx_inputs_ring_members_diff(tx))
    {
      MERROR_VER("tx uses duplicate ring members");
      return false;
    }

    if (!check_tx_inputs_keyimages_domain(tx))
    {
      MERROR_VER("tx uses key image not in the valid domain");
      return false;
    }

    return true;
  }
//------------------------------------------------------------------
bool check_tx_outputs(const transaction& tx, tx_verification_context &tvc) const
{
  MTRACE("Blockchain::" << __func__);
  // in a v2 tx, all outputs must have 0 amount
      for (auto &o: tx.vout) {
        if (o.amount != 0) {
          tvc.m_invalid_output = true;
          return false;
        }
      }

    for (const auto &o: tx.vout) {
      if (o.target.type() == typeid(txout_to_key)) {
        const txout_to_key& out_to_key = boost::get<txout_to_key>(o.target);
        if (!crypto::check_key(out_to_key.key)) {
          tvc.m_invalid_output = true;
          return false;
        }
      }
    }
  
  return true;
}

static bool check_fee( uint64_t fee) const
{

   const uint64_t needed_fee= BASE_FEE;
  if (fee < BASE_FEE) {
    MERROR_VER("transaction fee is not enough: " << print_money(fee) << ", minimum fee: " << print_money(needed_fee));
    return false;
  }
  return true;
}

static std::vector<rct::ctkey> fill_mix_ring(BlockchainDB&db, const txin_to_key& txin) const
{
  MTRACE("Blockchain::" << __func__);
  std::vector<rct::ctkey> decoys;

  const auto oids = cryptonote::relative_output_offsets_to_absolute(tx_in_to_key.key_offsets);
  const auto outputs=m_db->get_output_keys(oids);
  
  const auto chain_height=db.get_chain_height();
  for (const auto & out: outputs)
  {
      if (!is_tx_spendtime_unlocked(chain_height,out.unlock_time))
      {
        MERROR_VER("One of outputs for one of inputs has wrong tx.unlock_time = " << out.unlock_time);
        return false;
      }

      decoys.push_back(rct::ctkey({rct::pk2rct(out.otk), out.commitment}));
  }

  // rct_signatures will be expanded after this
  return decoys;
}
//------------------------------------------------------------------
// This function validates transaction inputs and their keys.
// FIXME: consider moving functionality specific to one input into
//        check_tx_input() rather than here, and use this function simply
//        to iterate the inputs as necessary (splitting the task
//        using threads, etc.)
bool check_tx_inputs(BlockchainDB& db,transaction& tx, tx_verification_context &tvc) const
{
  PERF_TIMER(check_tx_inputs);
  MTRACE("Blockchain::" << __func__);
  size_t sig_index = 0;
  
  try{
  // pruned txes are skipped, as they're only allowed in sync-pruned-blocks mode, which is within the builtin hashes
  if (tx.pruned)
    return true;

  if(!check_fee(tx.rct_signatures.txnFee))
  {
      tvc.m_verifivation_failed = true;
      tvc.m_fee_too_low = true; 
    return false;
  }

  const auto tx_prefix_hash = cryptonote::get_transaction_prefix_hash(tx);

  // from hard fork 2, we require mixin at least 2 unless one output cannot mix with 2 others
  // if one output cannot mix with 2 others, we accept at most 1 output that can mix
    for (const auto& txin : tx.vin)
    {
      // non txin_to_key inputs will be rejected below
      if (txin.type() == typeid(txin_to_key))
      {
        const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);
       
        size_t ring_mixin = in_to_key.key_offsets.size() - 1;
        if (ring_mixin <2 || ring_mixin>10)
          return false;
      }
    }
  
  // from v7, sorted ins
  {
    const crypto::key_image *last_key_image = NULL;
    for (size_t n = 0; n < tx.vin.size(); ++n)
    {
      const txin_v &txin = tx.vin[n];
      if (txin.type() == typeid(txin_to_key))
      {
        const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);
        if (last_key_image && memcmp(&in_to_key.k_image, last_key_image, sizeof(*last_key_image)) >= 0)
        {
          MERROR_VER("transaction has unsorted inputs");
          tvc.m_verifivation_failed = true;
          return false;
        }
        last_key_image = &in_to_key.k_image;
      }
    }
  }

  std::vector<std::vector<rct::ctkey>> mix_rings(tx.vin.size());
  for (const auto& txin : tx.vin)
  {
    const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);

    if(db.has_key_image(in_to_key.k_image))
    {
      MERROR_VER("Key image already spent in blockchain: " << epee::string_tools::pod_to_hex(in_to_key.k_image));
      tvc.m_double_spend = true;
      return false;
    }
    // make sure that output being spent matches up correctly with the
    // signature spending it.
    auto & decoys = mix_rings[sig_index];
    decoys=fill_mix_ring(db,in_to_key);
   
    sig_index++;
  }
 
    // from version 2, check ringct signatures
    // obviously, the original and simple rct APIs use a mixRing that's indexes
    // in opposite orders, because it'd be too simple otherwise...
    const rct::rctSig &rv = tx.rct_signatures;
    switch (rv.type)
    {
    default: {
      // we only accept no signatures for coinbase txes
      throw_and_log("Null rct signature on non-coinbase tx");
    }
    case rct::RCTTypeCLSAG:
    {
        // message - hash of the transaction prefix
        rv.message = rct::hash2rct(tx_prefix_hash);
        rv.mixRing=mix_rings;

        for (size_t n = 0; n < tx.vin.size(); ++n)
        {
          rv.p.CLSAGs[n].I = rct::ki2rct(boost::get<txin_to_key>(tx.vin[n]).k_image);
        }

      if (!rct::verRctNonSemanticsSimple(rv))
      {
        throw_and_log("Failed to check ringct signatures!");
      }
      break;
    }
  }
  catch(std::exception &ex){
     tvc.m_verifivation_failed = true;
    return false;
  }
  return true;
}
}