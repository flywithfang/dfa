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

#pragma once
#include "blobdatatype.h"
#include "cryptonote_basic_impl.h"
#include "tx_extra.h"
#include "account.h"

#include "include_base_utils.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include <unordered_map>
#include <boost/multiprecision/cpp_int.hpp>

namespace epee
{
  class wipeable_string;
}

namespace cryptonote
{
  //---------------------------------------------------------------
  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx);
  bool parse_and_validate_tx_prefix_from_blob(const blobdata_ref& tx_blob, transaction_prefix& tx);
  transaction parse_tx_from_blob(const blobdata_ref& tx_blob);
  transaction parse_tx_from_blob_entry(const tx_blob_entry & tb );
  transaction parse_tx_base_from_blob(const blobdata_ref& tx_blob);
  
  bool is_out_to_acc(const account_keys& acc, const txout_to_key& out_key,  size_t output_index);

  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, const crypto::public_key& tx_pub_key,  std::vector<size_t>& outs, uint64_t& money_transfered);
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, std::vector<size_t>& outs, uint64_t& money_transfered);
  bool get_tx_fee(const transaction& tx, uint64_t & fee);
  uint64_t get_tx_fee(const transaction& tx);
  bool generate_key_image_helper(const account_keys& ack, const crypto::public_key& tx_public_key, size_t real_output_index, keypair& otk, crypto::key_image& ki);
  void get_blob_hash(const blobdata& blob, crypto::hash& res);
  void get_blob_hash(const blobdata_ref& blob, crypto::hash& res);
  crypto::hash get_blob_hash(const blobdata& blob);
  crypto::hash get_blob_hash(const blobdata_ref& blob);
  std::string short_hash_str(const crypto::hash& h);

  crypto::hash get_transaction_hash(const transaction& t);
  crypto::hash calculate_transaction_prunable_hash(const transaction& t, const cryptonote::blobdata_ref *blob);
  crypto::hash get_transaction_prunable_hash(const transaction& t, const cryptonote::blobdata_ref *blob = NULL);
  crypto::hash calculate_transaction_hash(const transaction& t, size_t* blob_size);
  crypto::hash get_pruned_transaction_hash(const transaction& t, const crypto::hash &pruned_data_hash);

  blobdata get_block_hashing_blob(const block& b);
  bool calculate_block_hash(const block& b, crypto::hash& res, const blobdata_ref *blob = NULL);
  bool get_block_hash(const block& b, crypto::hash& res);
  crypto::hash get_block_hash(const block& b);
  block parse_block_from_blob(const blobdata_ref& b_blob);
  uint64_t get_outs_money_amount(const transaction& tx);
  bool check_inputs_types_supported(const transaction& tx);
  bool check_outs_valid(const transaction& tx);
  bool parse_amount(uint64_t& amount, const std::string& str_amount);
  uint64_t get_transaction_weight(const transaction &tx);

  bool check_money_overflow(const transaction& tx);
  bool check_outs_overflow(const transaction& tx);
  bool check_inputs_overflow(const transaction& tx);
  uint64_t get_block_height(const block& b);
  std::vector<uint64_t> relative_output_offsets_to_absolute(const std::vector<uint64_t>& off);
  std::vector<uint64_t> absolute_output_offsets_to_relative(const std::vector<uint64_t>& off);
  void set_default_decimal_point(unsigned int decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT);
  unsigned int get_default_decimal_point();
  std::string get_unit(unsigned int decimal_point = -1);
  std::string print_money(uint64_t amount, unsigned int decimal_point = -1);
  std::string print_money(const boost::multiprecision::uint128_t &amount, unsigned int decimal_point = -1);
  //---------------------------------------------------------------
  template<class t_object>
  bool t_serializable_object_from_blob(t_object& to, const blobdata& b_blob)
  {
    std::stringstream ss;
    ss << b_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, to);
    return r;
  }
  //---------------------------------------------------------------
  template<class t_object>
  bool t_serializable_object_to_blob(const t_object& to, blobdata& b_blob)
  {
    
    std::stringstream ss;
    binary_archive<true> ba(ss);
    bool r = ::serialization::serialize(ba, const_cast<t_object&>(to));
    b_blob = ss.str();
   // std::cout<<"t_serializable_object_to_blob "<<b_blob.size()<<" "<<typeid(to).name()<<std::endl;
    return r;
  }
  //---------------------------------------------------------------
  template<class t_object>
  blobdata t_serializable_object_to_blob(const t_object& to)
  {
    blobdata b;
    t_serializable_object_to_blob(to, b);
    return b;
  }
  //---------------------------------------------------------------
  template<class t_object>
  bool get_object_hash(const t_object& o, crypto::hash& res)
  {
    get_blob_hash(t_serializable_object_to_blob(o), res);
    return true;
  }
  //---------------------------------------------------------------
  template<class t_object>
  size_t get_object_blobsize(const t_object& o)
  {
    blobdata b = t_serializable_object_to_blob(o);
    return b.size();
  }
  //---------------------------------------------------------------
  template<class t_object>
  bool get_object_hash(const t_object& o, crypto::hash& res, size_t& blob_size)
  {
    blobdata bl = t_serializable_object_to_blob(o);
    blob_size = bl.size();
    get_blob_hash(bl, res);
    return true;
  }
  //---------------------------------------------------------------
  template <typename T>
  std::string obj_to_json_str(T& obj)
  {
    std::stringstream ss;
    json_archive<true> ar(ss, true);
    bool r = ::serialization::serialize(ar, obj);
    CHECK_AND_ASSERT_MES(r, "", "obj_to_json_str failed: serialization::serialize returned false");
    return ss.str();
  }
 
  //---------------------------------------------------------------
  blobdata block_to_blob(const block& b);
  bool block_to_blob(const block& b, blobdata& b_blob);
  blobdata tx_to_blob(const transaction& b);
  bool tx_to_blob(const transaction& b, blobdata& b_blob);
  crypto::hash get_tx_tree_hash(const block& b);
  bool is_valid_decomposed_amount(uint64_t amount);
  void get_hash_stats(uint64_t &tx_hashes_calculated, uint64_t &tx_hashes_cached, uint64_t &block_hashes_calculated, uint64_t & block_hashes_cached);

  crypto::secret_key encrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase);
  crypto::secret_key decrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase);
#define CHECKED_GET_SPECIFIC_VARIANT(variant_var, specific_type, variable_name, fail_return_val) \
  CHECK_AND_ASSERT_MES(variant_var.type() == typeid(specific_type), fail_return_val, "wrong variant type: " << variant_var.type().name() << ", expected " << typeid(specific_type).name()); \
  specific_type& variable_name = boost::get<specific_type>(variant_var);
}
