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

#include <unordered_set>
#include <random>
#include "include_base_utils.h"
#include "string_tools.h"
using namespace epee;

#include "common/apply_permutation.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_config.h"
#include "blockchain.h"
#include "cryptonote_basic/miner.h"
#include "cryptonote_basic/tx_extra.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctSigs.h"
#include "crypto/rx-hash.h"

using namespace crypto;

namespace cryptonote
{

  //---------------------------------------------------------------
  std::tuple<bool, transaction> construct_miner_tx(size_t height, uint64_t fee, const account_public_address &miner_address, const varbinary& blob_reserve,  uint8_t hard_fork_version) {
    transaction tx{};
    const  std::tuple<bool, transaction> failed={false,tx};

    keypair txkey = keypair::generate();
    tx.tx_pub_key = txkey.pub;
    if(blob_reserve.size()> TX_EXTRA_MAX_COUNT)
       return {false,tx};
     tx.extra = blob_reserve;

    txin_gen in{height};
    //lock
    tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(in);

    const uint64_t block_reward=get_block_reward();
    const auto total_reward = block_reward + fee;

    {
      crypto::key_derivation kA{};
      crypto::public_key otk{};
      //otk=H(kA,i)G+B, kG=R
      const auto & A=miner_address.m_view_public_key;
      const auto & B=miner_address.m_spend_public_key;
      bool r = crypto::generate_key_derivation(A, txkey.sec, kA);
      CHECK_AND_ASSERT_MES(r, failed, "while creating outs: failed to generate_key_derivation(" << miner_address.m_view_public_key << ", " << txkey.sec << ")");

      std::tie(r,otk) = crypto::derive_public_key(kA, 0, B);
      CHECK_AND_ASSERT_MES(r,  failed, "while creating outs: failed to derive_public_key(" << kA << ", "  << ", "<< miner_address.m_spend_public_key << ")");

      txout_to_key tk{otk};

      tx_out out{total_reward,tk};
      tx.vout.push_back(out);
    }

    tx.invalidate_hashes();
    MDEBUG("construct_miner_tx: reward " << print_money(block_reward) <<", fee " << fee << ",height "<<height<<",extra size "<<tx.extra.size());
    return std::make_tuple(true,tx);
  }
  

 bool   generate_otk(const crypto::secret_key &tx_sec,const cryptonote::tx_destination_entry &dst_entr, const size_t output_index,rct::key & shared_sec,  crypto::public_key &otk) {

        crypto::key_derivation derivation;
            //H(kA,i)G+B=H(Ra,i)G+B
        const auto & A=dst_entr.addr.m_view_public_key;
        const auto & B=dst_entr.addr.m_spend_public_key;
        bool r = generate_key_derivation(A,  tx_sec, derivation);
        CHECK_AND_ASSERT_MES(r, false, "at creation outs: failed to generate_key_derivation(" << dst_entr.addr.m_view_public_key << ", " << ( tx_sec) << ")");
        {
            //shared secret H(kA,i)=H(Ra,i)
            crypto::secret_key otk_a;
            derivation_to_scalar(derivation, output_index, otk_a);
            shared_sec = rct::sk2rct(otk_a);
        }
        r = derive_public_key(derivation, output_index, dst_entr.addr.m_spend_public_key, otk);
        CHECK_AND_ASSERT_MES(r, false, "at creation outs: failed to derive_public_key(" << derivation << ", " << output_index << ", "<< B << ")");

        return r;
    }


    //---------------------------------------------------------------
  bool construct_tx(const account_keys& sender_account_keys,  std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& dsts,  const blobdata &extra, transaction& tx, uint64_t unlock_time, crypto::secret_key &tx_sec)
  {
    tx=transaction{}; //clear everthing

    cryptonote::keypair txkey = cryptonote::keypair::generate();
    tx_sec = txkey.sec;
    tx.tx_pub_key = txkey.pub;
    if (sources.empty())
    {
      LOG_ERROR("Empty sources");
      return false;
    }

    tx.unlock_time = unlock_time;
    tx.extra =std::move(extra);
      // if we have a stealth payment id, find it and encrypt it with the tx key now
    if (extra.size()>TX_EXTRA_MAX_COUNT)
    {
      throw_and_log("Failed to parse tx extra");
      return false;
    }


    //std::sort(sources.begin(),sources.end(),)
    //fill inputs
    for(const auto& in:  sources)
    {
      if(in.real_output >= in.decoys.size())
      {
        LOG_ERROR("real_output index (" << in.real_output << ")bigger than output_keys.size()=" << in.decoys.size());
        return false;
      }

      //put key image into tx input
      txin_to_key txin{0,{},in.ki};

      //fill outputs array and use relative offsets
      std::vector<uint64_t> v; 
      std::transform(in.decoys.begin(),in.decoys.end(),std::back_inserter(v),[&](const auto&d){return d.global_oi;});
      txin.key_offsets = absolute_output_offsets_to_relative(v);
      tx.vin.push_back(txin);
    }

    std::shuffle(dsts.begin(), dsts.end(), crypto::random_device{});

    //fill outputs
    size_t output_index = 0;
    std::vector<rct::key> shared_secs;
    for(const auto& dst_entr: dsts)
    {
      crypto::public_key otk;
      rct::key shared_sec{};
      auto r = generate_otk(tx_sec,dst_entr,  output_index,shared_sec, otk);
      CHECK_AND_ASSERT_MES(!r, false, "generate_otk " );

      shared_secs.push_back(shared_sec);

      txout_to_key tk{otk};
      tx_out out{0,tk};
      tx.vout.push_back(out);
      output_index++;
    }
    {
      uint64_t amount_in = 0, amount_out = 0;
      std::vector<rct::ctkey> real_ins;
      real_ins.reserve(sources.size());
    
      std::vector<uint64_t> inamounts, outamounts;
      std::vector<unsigned int> real_in_index;
      for (const  auto & in : sources)
      {
        amount_in += in.amount;
        inamounts.push_back(in.amount);
        real_in_index.push_back(in.real_output);
        real_ins.push_back(rct::ctkey{in.otk_sec,in.noise});
      }
       rct::keyV dst_otks;
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        const auto & otk=boost::get<txout_to_key>(tx.vout[i].target).key;
        dst_otks.push_back(rct::pk2rct(otk));

        const auto & dst = dsts[i];
        outamounts.push_back(dst.amount);
        amount_out += dst.amount;
      }

  // rings indexing is done the other way round for simple
      std::vector<std::vector<rct::ctkey>> rings;
      {
        // rings indexing is done the other way round for simple
        for (const auto & in : sources)
        {
          std::vector<rct::ctkey> ring;
          auto & decoys = in.decoys;
          for (auto & decoy : decoys)
          {
            ring.emplace_back(rct::ctkey{decoy.otk,decoy.commitment});//otk,commitment
          }
          rings.emplace_back(ring);
        }
      }
   
      const crypto::hash tx_prefix_hash=get_transaction_prefix_hash(tx);
      rct::ctkeyV outSk;

      const auto & message= rct::hash2rct(tx_prefix_hash);
      const auto fee = amount_in - amount_out;
      tx.rct_signatures = rct::genRctSimple(message, real_ins, dst_otks, inamounts, outamounts,fee , rings, shared_secs,   real_in_index, outSk);
    
      memwipe(real_ins.data(), real_ins.size() * sizeof(rct::ctkey));

      CHECK_AND_ASSERT_MES(tx.vout.size() == outSk.size(), false, "outSk size does not match vout");

      MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL);
    }

    tx.invalidate_hashes();

    return true;
  }

  //---------------------------------------------------------------
  block make_genesis_block( std::string const & genesis_tx , uint32_t nonce    )
  {
    //genesis block
    block bl = {};

    blobdata tx_bl = string_tools::parse_hexstr_to_binbuff(genesis_tx);
      auto r = parse_tx_from_blob(tx_bl, bl.miner_tx);
    if(!r)
      throw_and_log("failed to parse coinbase tx from hard coded blob");
    bl.major_version = CURRENT_BLOCK_MAJOR_VERSION;
    bl.minor_version = CURRENT_BLOCK_MINOR_VERSION;
    bl.timestamp = 0;
    bl.nonce = nonce;
    for(; bl.nonce != std::numeric_limits<uint32_t>::max(); bl.nonce++)
    {
        blobdata bd = get_block_hashing_blob(bl);
        crypto::hash K{};
        const auto pow = rx_slow_hash(K, bd.data(), bd.size());
        if(cryptonote::check_hash(pow, 1))
        {
          MINFO("find_nonce_for_given_block "<<h<<"/"<<diffic<<","<<bl.prev_id<<",n="<<bl.nonce<<",h="<<height);
          break;
        }
    }
    bl.invalidate_hashes();
    return bl;
  }
 

//------------------------------------------------------------------
// This function checks to see if a tx is unlocked.  unlock_time is either
// a block index or a unix time.
bool is_tx_spendtime_unlocked(uint64_t chain_height,uint64_t unlock_time) 
{
  MTRACE("Blockchain::" << __func__);
  if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
  {
    // ND: Instead of calling get_chain_height(), call m_db->height()
    //    directly as get_chain_height() locks the recursive mutex.
    if(chain_height-1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
      return true;
    else
      return false;
  }
  else
  {
    //interpret as time
    const uint64_t current_time =  static_cast<uint64_t>(time(NULL));
    if(current_time +  CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS >= unlock_time)
      return true;
    else
      return false;
  }
  return false;
}
 bool  verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) {
      crypto::public_key calculated_pub;
      bool r = crypto::secret_key_to_public_key(secret_key, calculated_pub);
      return r && public_key == calculated_pub;
  }

}
