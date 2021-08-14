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
  void classify_addresses(const std::vector<tx_destination_entry> &destinations, const boost::optional<cryptonote::account_public_address>& change_addr, size_t &num_stdaddresses)
  {
    num_stdaddresses = 0;
    std::unordered_set<cryptonote::account_public_address> unique_dst_addresses;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      if (change_addr && dst_entr.addr == change_addr)
        continue;
      if (unique_dst_addresses.count(dst_entr.addr) == 0)
      {
        unique_dst_addresses.insert(dst_entr.addr);
        {
          ++num_stdaddresses;
        }
      }
    }
    MINFO("destinations include " << num_stdaddresses << " standard addresses " );
  }

  //---------------------------------------------------------------
  std::tuple<bool, transaction> construct_miner_tx(size_t height, size_t median_weight, uint64_t already_generated_coins, size_t current_block_weight, uint64_t fee, const account_public_address &miner_address, const blobdata& blob_reserve,  uint8_t hard_fork_version) {
    transaction tx{};
    const  std::tuple<bool, transaction> failed={false,tx};

    keypair txkey = keypair::generate();
    add_tx_pub_key_to_extra(tx, txkey.pub);
    if(!blob_reserve.empty())
      if(!add_extra_nonce_to_tx_extra(tx.extra, blob_reserve))
        return {false,tx};
    if (!sort_tx_extra(tx.extra, tx.extra))
      return {false,tx};

    txin_gen in{height};
    //lock
    tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(in);

    uint64_t block_reward;
    if(!get_block_reward(median_weight, current_block_weight, already_generated_coins, block_reward, hard_fork_version))
    {
      LOG_PRINT_L0("Block is too big");
       return {false,tx};
    }

    MDEBUG("construct_miner_tx: reward " << print_money(block_reward) <<", fee " << fee << ",height "<<height<<",coins"<<already_generated_coins);
    block_reward += fee;

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

      tx_out out{block_reward,tk};
      tx.vout.push_back(out);
    }

    tx.invalidate_hashes();

    return std::make_tuple(true,tx);
  }
  //---------------------------------------------------------------
  crypto::public_key get_destination_view_key_pub(const std::vector<tx_destination_entry> &destinations, const boost::optional<cryptonote::account_public_address>& change_addr)
  {
    account_public_address addr = {null_pkey, null_pkey};
    size_t count = 0;
    for (const auto &i : destinations)
    {
      if (i.amount == 0)
        continue;
      if (change_addr && i.addr == *change_addr)
        continue;
      if (i.addr == addr)
        continue;
      if (count > 0)
        return null_pkey;
      addr = i.addr;
      ++count;
    }
    if (count == 0 && change_addr)
      return change_addr->m_view_public_key;
    return addr.m_view_public_key;
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
  bool construct_tx_and_get_tx_key(const account_keys& sender_account_keys,  std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, crypto::secret_key &tx_sec,  const rct::RCTConfig &rct_config,bool shuffle_outs)
  {
    tx=transaction{}; //clear everthing

    cryptonote::keypair txkey = cryptonote::keypair::generate();
    tx_sec = txkey.sec;
    const crypto::public_key txkey_pub=txkey.pub;
   

    if (sources.empty())
    {
      LOG_ERROR("Empty sources");
      return false;
    }

    tx.set_null();
  
    tx.version = 2;
    tx.unlock_time = unlock_time;

    tx.extra = extra;
      // if we have a stealth payment id, find it and encrypt it with the tx key now
    std::vector<tx_extra_field> tx_extra_fields;
    if (parse_tx_extra(tx.extra, tx_extra_fields))
    {
    }
    else
    {
      MWARNING("Failed to parse tx extra");
      tx_extra_fields.clear();
    }

    struct input_generation_context_data
    {
      keypair in_ephemeral;
    };
    std::vector<input_generation_context_data> in_contexts;

    uint64_t summary_inputs_money = 0;
    //fill inputs
    int idx = -1;
    for(const tx_source_entry& src_entr:  sources)
    {
      ++idx;
      if(src_entr.real_output >= src_entr.decoys.size())
      {
        LOG_ERROR("real_output index (" << src_entr.real_output << ")bigger than output_keys.size()=" << src_entr.decoys.size());
        return false;
      }
      summary_inputs_money += src_entr.amount;

      //key_derivation recv_derivation;
      in_contexts.push_back(input_generation_context_data());
      keypair& in_ephemeral = in_contexts.back().in_ephemeral;
      crypto::key_image img;
      const auto & real_input= src_entr.decoys[src_entr.real_output];
      if(!generate_key_image_helper(sender_account_keys, src_entr.real_out_tx_key,  src_entr.real_output_in_tx_index, in_ephemeral,img))
      {
        LOG_ERROR("Key image generation failed!");
        return false;
      }
      const auto & old_otk=real_input.second.otk;
      //check that derivated key is equal with real output key (if non multisig)
      if( !(in_ephemeral.pub == old_otk) )
      {
        LOG_ERROR("derived public key mismatch with output public key at index " << idx << ", real out " << src_entr.real_output << "! "<< ENDL << "derived_key:"
          << string_tools::pod_to_hex(in_ephemeral.pub) << ENDL << "real otk:"
          << string_tools::pod_to_hex(old_otk) );
        LOG_ERROR("amount " << src_entr.amount );
        LOG_ERROR("tx pubkey " << src_entr.real_out_tx_key << ", real_output_in_tx_index " << src_entr.real_output_in_tx_index);
        return false;
      }

      //put key image into tx input
      txin_to_key txin{0,{},img};

      //fill outputs array and use relative offsets
      for(auto decoy: src_entr.decoys)
        txin.key_offsets.push_back(decoy.first);

      txin.key_offsets = absolute_output_offsets_to_relative(txin.key_offsets);
      tx.vin.push_back(txin);
    }

    if (shuffle_outs)
    {
      std::shuffle(destinations.begin(), destinations.end(), crypto::random_device{});
    }

    // sort ins by their key image
    std::vector<size_t> ins_order(sources.size());
    for (size_t n = 0; n < sources.size(); ++n)
      ins_order[n] = n;
    std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
      const txin_to_key &tk0 = boost::get<txin_to_key>(tx.vin[i0]);
      const txin_to_key &tk1 = boost::get<txin_to_key>(tx.vin[i1]);
      return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
    });
    tools::apply_permutation(ins_order, [&] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
      std::swap(in_contexts[i0], in_contexts[i1]);
      std::swap(sources[i0], sources[i1]);
    });

   
    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_pub_key));
    add_tx_pub_key_to_extra(tx, txkey_pub);

    std::vector<crypto::public_key> additional_tx_public_keys;

    // we don't need to include additional tx keys if:
    //   - all the destinations are standard addresses
    //   - there's only one destination which is a subaddress

    uint64_t summary_outs_money = 0;
    //fill outputs
    size_t output_index = 0;
    std::vector<rct::key> shared_secs;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      CHECK_AND_ASSERT_MES(dst_entr.amount==0, false, "Destination with wrong amount: " << dst_entr.amount);
      crypto::public_key otk;
      rct::key shared_sec{};
      auto r = generate_otk(tx_sec,dst_entr,  output_index,shared_sec, otk);
      CHECK_AND_ASSERT_MES(!r, false, "generate_otk " );

      shared_secs.push_back(shared_sec);

      txout_to_key tk{otk};
      tx_out out{0,tk};
      tx.vout.push_back(out);
      output_index++;
      summary_outs_money += dst_entr.amount;
    }

    MINFO("tx pubkey: " << txkey_pub);
    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    //check money
    if(summary_outs_money > summary_inputs_money )
    {
      LOG_ERROR("Transaction inputs money ("<< summary_inputs_money << ") less than outputs money (" << summary_outs_money << ")");
      return false;
    }

    //ver=2
    {

      uint64_t amount_in = 0, amount_out = 0;
      std::vector<rct::ctkey> real_ins;
      real_ins.reserve(sources.size());
    
      std::vector<uint64_t> inamounts, outamounts;
      std::vector<unsigned int> ring_index;
      for (size_t i = 0; i < sources.size(); ++i)
      {
        rct::ctkey ctkey;
        const auto & in=sources[i];

        amount_in += in.amount;
        inamounts.push_back(in.amount);
        ring_index.push_back(in.real_output);
        // real_ins: (secret key, mask)
        const auto  & otk_sec =rct::sk2rct(in_contexts[i].in_ephemeral.sec);//b
        ctkey.otk_sec = otk_sec;
        ctkey.noise = in.noise;//aG+bH amount commit
        real_ins.push_back(ctkey);
        memwipe(&ctkey, sizeof(rct::ctkey));
       
      }
       rct::keyV dst_otks;
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        const auto & otk=boost::get<txout_to_key>(tx.vout[i].target).key;
        dst_otks.push_back(rct::pk2rct(otk));

        const auto & dst = destinations[i];
        outamounts.push_back(dst.amount);
        amount_out += dst.amount;
      }

  // mixRing indexing is done the other way round for simple
      std::vector<std::vector<rct::ctkey>> mixRing(tx.vin.size());
      {
        // mixRing indexing is done the other way round for simple
        for (size_t i = 0; i < sources.size(); ++i)
        {
          auto & ring=mixRing[i];
          auto & in = sources[i];
          ring.resize(in.decoys.size());
          for (size_t i = 0; i < in.decoys.size(); ++i)
          {
            auto & decoy= in.decoys[i];
            ring[i] = decoy.second;//otk,commitment
          }
        }
      }
   
      crypto::hash tx_prefix_hash;
      get_transaction_prefix_hash(tx, tx_prefix_hash);
      rct::ctkeyV outSk;

      const auto & message= rct::hash2rct(tx_prefix_hash);
      const auto fee = amount_in - amount_out;
      tx.rct_signatures = rct::genRctSimple(message, real_ins, dst_otks, inamounts, outamounts,fee , mixRing, shared_secs,   ring_index, outSk, rct_config);
    
      memwipe(real_ins.data(), real_ins.size() * sizeof(rct::ctkey));

      CHECK_AND_ASSERT_MES(tx.vout.size() == outSk.size(), false, "outSk size does not match vout");

      MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL);
    }

    tx.invalidate_hashes();

    return true;
  }

  //---------------------------------------------------------------
  bool construct_tx(const account_keys& sender_account_keys, std::vector<tx_source_entry>& sources, const std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time)
  {
     crypto::secret_key tx_sec;
     std::vector<tx_destination_entry> destinations_copy = destinations;
     return construct_tx_and_get_tx_key(sender_account_keys, sources, destinations_copy, change_addr, extra, tx, unlock_time, tx_sec);
  }
  //---------------------------------------------------------------
  bool generate_genesis_block(block& bl, std::string const & genesis_tx , uint32_t nonce    )
  {
    //genesis block
    bl = {};

    blobdata tx_bl;
    bool r = string_tools::parse_hexstr_to_binbuff(genesis_tx, tx_bl);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    r = parse_and_validate_tx_from_blob(tx_bl, bl.miner_tx);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    bl.major_version = CURRENT_BLOCK_MAJOR_VERSION;
    bl.minor_version = CURRENT_BLOCK_MINOR_VERSION;
    bl.timestamp = 0;
    bl.nonce = nonce;
    miner::find_nonce_for_given_block(nullptr,bl, 1, 0);
    bl.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  void get_altblock_longhash(const block& b, crypto::hash& res, const uint64_t main_height, const uint64_t height, const uint64_t seed_height, const crypto::hash& seed_hash)
  {
    blobdata bd = get_block_hashing_blob(b);
    rx_slow_hash(main_height, seed_height, seed_hash.data, bd.data(), bd.size(), res.data, false, 1);
  }

  bool get_block_longhash(const Blockchain *pbc, const block& b, crypto::hash& res, const uint64_t height)
  {
   
    blobdata bd = get_block_hashing_blob(b);
    {
      uint64_t seed_height, main_height;
      crypto::hash seed_hash{};
      if (pbc != NULL)
      {
        seed_height = rx_seedheight(height);
        seed_hash = pbc->get_pending_block_id_by_height(seed_height);
        main_height = pbc->get_current_blockchain_height();
      } else
      {
        memset(&seed_hash, 0, sizeof(hash));  // only happens when generating genesis block
        seed_height = 0;
        main_height = 0;
      }
      rx_slow_hash(main_height, seed_height, seed_hash.data, bd.data(), bd.size(), res.data,  false, false);
    }

    return true;
  }

  crypto::hash get_block_longhash(const Blockchain *pbc, const block& b, const uint64_t height)
  {
    crypto::hash p = crypto::null_hash;
    get_block_longhash(pbc, b, p, height);
    return p;
  }

  void get_block_longhash_reorg(const uint64_t split_height)
  {
    rx_reorg(split_height);
  }

 bool  verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) {
      crypto::public_key calculated_pub;
      bool r = crypto::secret_key_to_public_key(secret_key, calculated_pub);
      return r && public_key == calculated_pub;
  }

}
