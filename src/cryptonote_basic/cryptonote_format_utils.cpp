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

#include <atomic>
#include <boost/algorithm/string.hpp>
#include "wipeable_string.h"
#include "string_tools.h"
#include "string_tools_lexical.h"
#include "serialization/string.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctSigs.h"

using namespace epee;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

// #define ENABLE_HASH_CASH_INTEGRITY_CHECK

using namespace crypto;

static const uint64_t valid_decomposed_outputs[] = {
  (uint64_t)1, (uint64_t)2, (uint64_t)3, (uint64_t)4, (uint64_t)5, (uint64_t)6, (uint64_t)7, (uint64_t)8, (uint64_t)9, // 1 piconero
  (uint64_t)10, (uint64_t)20, (uint64_t)30, (uint64_t)40, (uint64_t)50, (uint64_t)60, (uint64_t)70, (uint64_t)80, (uint64_t)90,
  (uint64_t)100, (uint64_t)200, (uint64_t)300, (uint64_t)400, (uint64_t)500, (uint64_t)600, (uint64_t)700, (uint64_t)800, (uint64_t)900,
  (uint64_t)1000, (uint64_t)2000, (uint64_t)3000, (uint64_t)4000, (uint64_t)5000, (uint64_t)6000, (uint64_t)7000, (uint64_t)8000, (uint64_t)9000,
  (uint64_t)10000, (uint64_t)20000, (uint64_t)30000, (uint64_t)40000, (uint64_t)50000, (uint64_t)60000, (uint64_t)70000, (uint64_t)80000, (uint64_t)90000,
  (uint64_t)100000, (uint64_t)200000, (uint64_t)300000, (uint64_t)400000, (uint64_t)500000, (uint64_t)600000, (uint64_t)700000, (uint64_t)800000, (uint64_t)900000,
  (uint64_t)1000000, (uint64_t)2000000, (uint64_t)3000000, (uint64_t)4000000, (uint64_t)5000000, (uint64_t)6000000, (uint64_t)7000000, (uint64_t)8000000, (uint64_t)9000000, // 1 micronero
  (uint64_t)10000000, (uint64_t)20000000, (uint64_t)30000000, (uint64_t)40000000, (uint64_t)50000000, (uint64_t)60000000, (uint64_t)70000000, (uint64_t)80000000, (uint64_t)90000000,
  (uint64_t)100000000, (uint64_t)200000000, (uint64_t)300000000, (uint64_t)400000000, (uint64_t)500000000, (uint64_t)600000000, (uint64_t)700000000, (uint64_t)800000000, (uint64_t)900000000,
  (uint64_t)1000000000, (uint64_t)2000000000, (uint64_t)3000000000, (uint64_t)4000000000, (uint64_t)5000000000, (uint64_t)6000000000, (uint64_t)7000000000, (uint64_t)8000000000, (uint64_t)9000000000,
  (uint64_t)10000000000, (uint64_t)20000000000, (uint64_t)30000000000, (uint64_t)40000000000, (uint64_t)50000000000, (uint64_t)60000000000, (uint64_t)70000000000, (uint64_t)80000000000, (uint64_t)90000000000,
  (uint64_t)100000000000, (uint64_t)200000000000, (uint64_t)300000000000, (uint64_t)400000000000, (uint64_t)500000000000, (uint64_t)600000000000, (uint64_t)700000000000, (uint64_t)800000000000, (uint64_t)900000000000,
  (uint64_t)1000000000000, (uint64_t)2000000000000, (uint64_t)3000000000000, (uint64_t)4000000000000, (uint64_t)5000000000000, (uint64_t)6000000000000, (uint64_t)7000000000000, (uint64_t)8000000000000, (uint64_t)9000000000000, // 1 monero
  (uint64_t)10000000000000, (uint64_t)20000000000000, (uint64_t)30000000000000, (uint64_t)40000000000000, (uint64_t)50000000000000, (uint64_t)60000000000000, (uint64_t)70000000000000, (uint64_t)80000000000000, (uint64_t)90000000000000,
  (uint64_t)100000000000000, (uint64_t)200000000000000, (uint64_t)300000000000000, (uint64_t)400000000000000, (uint64_t)500000000000000, (uint64_t)600000000000000, (uint64_t)700000000000000, (uint64_t)800000000000000, (uint64_t)900000000000000,
  (uint64_t)1000000000000000, (uint64_t)2000000000000000, (uint64_t)3000000000000000, (uint64_t)4000000000000000, (uint64_t)5000000000000000, (uint64_t)6000000000000000, (uint64_t)7000000000000000, (uint64_t)8000000000000000, (uint64_t)9000000000000000,
  (uint64_t)10000000000000000, (uint64_t)20000000000000000, (uint64_t)30000000000000000, (uint64_t)40000000000000000, (uint64_t)50000000000000000, (uint64_t)60000000000000000, (uint64_t)70000000000000000, (uint64_t)80000000000000000, (uint64_t)90000000000000000,
  (uint64_t)100000000000000000, (uint64_t)200000000000000000, (uint64_t)300000000000000000, (uint64_t)400000000000000000, (uint64_t)500000000000000000, (uint64_t)600000000000000000, (uint64_t)700000000000000000, (uint64_t)800000000000000000, (uint64_t)900000000000000000,
  (uint64_t)1000000000000000000, (uint64_t)2000000000000000000, (uint64_t)3000000000000000000, (uint64_t)4000000000000000000, (uint64_t)5000000000000000000, (uint64_t)6000000000000000000, (uint64_t)7000000000000000000, (uint64_t)8000000000000000000, (uint64_t)9000000000000000000, // 1 meganero
  (uint64_t)10000000000000000000ull
};

static std::atomic<unsigned int> default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT);

static std::atomic<uint64_t> tx_hashes_calculated_count(0);
static std::atomic<uint64_t> tx_hashes_cached_count(0);
static std::atomic<uint64_t> block_hashes_calculated_count(0);
static std::atomic<uint64_t> block_hashes_cached_count(0);

#define CHECK_AND_ASSERT_THROW_MES_L1(expr, message) {if(!(expr)) {MWARNING(message); throw std::runtime_error(message);}}

namespace cryptonote
{
  static inline unsigned char *operator &(ec_point &point) {
    return &reinterpret_cast<unsigned char &>(point);
  }
  static inline const unsigned char *operator &(const ec_point &point) {
    return &reinterpret_cast<const unsigned char &>(point);
  }



  uint64_t get_transaction_weight_clawback(const transaction &tx, size_t n_padded_outputs)
  {
    const uint64_t bp_base = 368;
    const size_t n_outputs = tx.vout.size();
    if (n_padded_outputs <= 2)
      return 0;
    size_t nlr = 0;
    while ((1u << nlr) < n_padded_outputs)
      ++nlr;
    nlr += 6;
    const size_t bp_size = 32 * (9 + 2 * nlr);
    CHECK_AND_ASSERT_THROW_MES_L1(n_outputs <= BULLETPROOF_MAX_OUTPUTS, "maximum number of outputs is " + std::to_string(BULLETPROOF_MAX_OUTPUTS) + " per transaction");
    CHECK_AND_ASSERT_THROW_MES_L1(bp_base * n_padded_outputs >= bp_size, "Invalid bulletproof clawback: bp_base " + std::to_string(bp_base) + ", n_padded_outputs "
        + std::to_string(n_padded_outputs) + ", bp_size " + std::to_string(bp_size));
    const uint64_t bp_clawback = (bp_base * n_padded_outputs - bp_size) * 4 / 5;
    return bp_clawback;
  }
  //---------------------------------------------------------------
}

namespace cryptonote
{
  

  //---------------------------------------------------------------
  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx)
  {
    crypto::hash h = null_hash;
    std::ostringstream s;
    binary_archive<true> a(s);
    ::serialization::serialize(a, const_cast<transaction_prefix&>(tx));
    crypto::cn_fast_hash(s.str().data(), s.str().size(), h);
    return h;
  }


  //---------------------------------------------------------------
  bool expand_transaction_1(transaction &tx, bool base_only)
  {
 //  if ( !is_coinbase(tx))
    {
      rct::rctSig &rv = tx.rct_signatures;
      if (rv.type == rct::RCTTypeNull)
        return true;
      if (rv.outCommitments.size() != tx.vout.size())
      {
        MINFO("Failed to parse transaction from blob, bad outCommitments size in tx " << get_transaction_hash(tx));
        return false;
      }
      for (size_t n = 0; n < tx.rct_signatures.outCommitments.size(); ++n)
      {
        if (tx.vout[n].target.type() != typeid(txout_to_key))
        {
          MINFO("Unsupported output type in tx " << get_transaction_hash(tx));
          return false;
        }
        rv.outCommitments[n].otk = rct::pk2rct(boost::get<txout_to_key>(tx.vout[n].target).key);
      }

      if (!base_only)
      {
        //const bool bulletproof = rct::is_rct_bulletproof(rv.type);
     //   if (bulletproof)
        {
          if (rv.p.bulletproofs.size() != 1)
          {
            MINFO("Failed to parse transaction from blob, bad bulletproofs size in tx " << get_transaction_hash(tx));
            return false;
          }
          if (rv.p.bulletproofs[0].L.size() < 6)
          {
            MINFO("Failed to parse transaction from blob, bad bulletproofs L size in tx " << get_transaction_hash(tx));
            return false;
          }
          const size_t max_outputs = 1 << (rv.p.bulletproofs[0].L.size() - 6);
          if (max_outputs < tx.vout.size())
          {
            MINFO("Failed to parse transaction from blob, bad bulletproofs max outputs in tx " << get_transaction_hash(tx));
            return false;
          }
          const size_t n_amounts = tx.vout.size();
          CHECK_AND_ASSERT_MES(n_amounts == rv.outCommitments.size(), false, "Internal error filling out V");
          rv.p.bulletproofs[0].V.resize(n_amounts);
          for (size_t i = 0; i < n_amounts; ++i)
            rv.p.bulletproofs[0].V[i] = rct::scalarmultKey(rv.outCommitments[i].commitment, rct::INV_EIGHT);
        }
      }
    }
    return true;
  }
 
 transaction parse_tx_from_blob_entry(const tx_blob_entry & tb )
 {
    if(tb.prunable_hash==null_hash){
      return parse_tx_from_blob(tb.tx_blob);
    }
    else{
      auto tx = parse_tx_base_from_blob(tb.tx_blob);
      tx.set_prunable_hash(tb.prunable_hash);
      return tx;
    }
 }
  transaction parse_tx_from_blob(const blobdata_ref& tx_blob)
  {
    if(tx_blob.size() > CRYPTONOTE_MAX_TX_SIZE)
    {
      throw_and_log("WRONG TRANSACTION BLOB, too big size " << tx_blob.size() << ", rejected");
    }
    transaction tx{};
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, tx);
    if(!r) 
      throw_and_log(std::string("Failed to parse transaction from blob") + string_tools::buff_to_hex(tx_blob));
    r = expand_transaction_1(tx, false);
    if(!r)
      throw_and_log(std::string("Failed to expand transaction data")+string_tools::buff_to_hex(tx_blob));
    tx.invalidate_hashes();
    return tx;
  }
  //---------------------------------------------------------------
  transaction parse_tx_base_from_blob(const blobdata_ref& tx_blob)
  {
    transaction tx{};
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = tx.serialize_base(ba);
    if(!r)
      throw_and_log("Failed to parse transaction from blob"+ string_tools::buff_to_hex(tx_blob));
    
    r = expand_transaction_1(tx, true);
    if(!r)
      throw_and_log("Failed to expand transaction data"+ string_tools::buff_to_hex(tx_blob));

    tx.invalidate_hashes();
    return tx;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_prefix_from_blob(const blobdata_ref& tx_blob, transaction_prefix& tx)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize_noeof(ba, tx);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse transaction prefix from blob");
    return true;
  }
 
  //---------------------------------------------------------------
  bool is_v1_tx(const blobdata_ref& tx_blob)
  {
    uint64_t version;
    const char* begin = static_cast<const char*>(tx_blob.data());
    const char* end = begin + tx_blob.size();
    int read = tools::read_varint(begin, end, version);
    if (read <= 0)
      throw std::runtime_error("Internal error getting transaction version");
    return version <= 1;
  }
  //---------------------------------------------------------------
  bool is_v1_tx(const blobdata& tx_blob)
  {
    return is_v1_tx(blobdata_ref{tx_blob.data(), tx_blob.size()});
  }
  //---------------------------------------------------------------
  bool generate_key_image_helper(const account_keys& ack,   const crypto::public_key& tx_public_key,  size_t oi, keypair& otk_p, crypto::key_image& ki)
  {
    crypto::key_derivation kA{};
    //rGa=rA
    //H(rA)+b
    const auto & a= ack.m_view_secret_key;
    const auto & b= ack.m_spend_secret_key;
    bool r = crypto::generate_key_derivation(tx_public_key, a, kA);
    if (!r)
    {
      MWARNING("key image helper: failed to generate_key_derivation(" << tx_public_key << ", " << ack.m_view_secret_key << ")");
      memcpy(&kA, rct::identity().bytes, sizeof(kA));
    }

 //computes Hs(a*R || idx) + b
      crypto::derive_secret_key(kA, oi, b, otk_p.sec); // 
    
      CHECK_AND_ASSERT_MES(crypto::secret_key_to_public_key(otk_p.sec, otk_p.pub), false, "Failed to derive public key");
    crypto::generate_key_image(otk_p.pub, otk_p.sec, ki);
    return true;

  }
  //---------------------------------------------------------------
  uint64_t power_integral(uint64_t a, uint64_t b)
  {
    if(b == 0)
      return 1;
    uint64_t total = a;
    for(uint64_t i = 1; i != b; i++)
      total *= a;
    return total;
  }
  //---------------------------------------------------------------
  bool parse_amount(uint64_t& amount, const std::string& str_amount_)
  {
    std::string str_amount = str_amount_;
    boost::algorithm::trim(str_amount);

    size_t point_index = str_amount.find_first_of('.');
    size_t fraction_size;
    if (std::string::npos != point_index)
    {
      fraction_size = str_amount.size() - point_index - 1;
      while (default_decimal_point < fraction_size && '0' == str_amount.back())
      {
        str_amount.erase(str_amount.size() - 1, 1);
        --fraction_size;
      }
      if (default_decimal_point < fraction_size)
        return false;
      str_amount.erase(point_index, 1);
    }
    else
    {
      fraction_size = 0;
    }

    if (str_amount.empty())
      return false;

    if (fraction_size < default_decimal_point)
    {
      str_amount.append(default_decimal_point - fraction_size, '0');
    }

    return string_tools::get_xtype_from_string(amount, str_amount);
  }
 
  //---------------------------------------------------------------
  uint64_t get_transaction_weight(const transaction &tx)
  {
     const auto w = tx.vin.size()+tx.vout.size();
    return w;
  }
  //---------------------------------------------------------------
  bool get_tx_fee(const transaction& tx, uint64_t & fee)
  {
      fee = tx.rct_signatures.txnFee;
      return true;
  }
  //---------------------------------------------------------------
  uint64_t get_tx_fee(const transaction& tx)
  {
    uint64_t r = 0;
    if(!get_tx_fee(tx, r))
      return 0;
    return r;
  }
  
 
  //---------------------------------------------------------------
  uint64_t get_block_height(const block& b)
  {
    CHECK_AND_ASSERT_MES(b.miner_tx.vin.size() == 1, 0, "wrong miner tx in block: " << get_block_hash(b) << ", b.miner_tx.vin.size() != 1");
    CHECKED_GET_SPECIFIC_VARIANT(b.miner_tx.vin[0], const txin_gen, coinbase_in, 0);
    return coinbase_in.height;
  }
  //---------------------------------------------------------------
  bool check_inputs_types_supported(const transaction& tx)
  {
    for(const auto& in: tx.vin)
    {
      CHECK_AND_ASSERT_MES(in.type() == typeid(txin_to_key), false, "wrong variant type: "
        << in.type().name() << ", expected " << typeid(txin_to_key).name()
        << ", in transaction id=" << get_transaction_hash(tx));

    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool check_outs_valid(const transaction& tx)
  {
    for(const tx_out& out: tx.vout)
    {
      CHECK_AND_ASSERT_MES(out.target.type() == typeid(txout_to_key), false, "wrong variant type: "
        << out.target.type().name() << ", expected " << typeid(txout_to_key).name()
        << ", in transaction id=" << get_transaction_hash(tx));

      if(!check_key(boost::get<txout_to_key>(out.target).key))
        return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool check_money_overflow(const transaction& tx)
  {
    return check_inputs_overflow(tx) && check_outs_overflow(tx);
  }
  //---------------------------------------------------------------
  bool check_inputs_overflow(const transaction& tx)
  {
    uint64_t money = 0;
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      if(money > tokey_in.amount + money)
        return false;
      money += tokey_in.amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  bool check_outs_overflow(const transaction& tx)
  {
    uint64_t money = 0;
    for(const auto& o: tx.vout)
    {
      if(money > o.amount + money)
        return false;
      money += o.amount;
    }
    if(tx.vout.size()>2)
      return false;
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_outs_money_amount(const transaction& tx)
  {
    uint64_t outputs_amount = 0;
    for(const auto& o: tx.vout)
      outputs_amount += o.amount;
    return outputs_amount;
  }
  //---------------------------------------------------------------
  std::string short_hash_str(const crypto::hash& h)
  {
    std::string res = string_tools::pod_to_hex(h);
    CHECK_AND_ASSERT_MES(res.size() == 64, res, "wrong hash256 with string_tools::pod_to_hex conversion");
    auto erased_pos = res.erase(8, 48);
    res.insert(8, "....");
    return res;
  }
  //---------------------------------------------------------------
  bool is_out_to_acc(const account_keys& acc, const txout_to_key& otk, const crypto::public_key& tx_pub_key, size_t output_index)
  {
    crypto::key_derivation derivation;
    bool r = crypto::generate_key_derivation(tx_pub_key, acc.m_view_secret_key, derivation);
    CHECK_AND_ASSERT_MES(r, false, "Failed to generate key derivation");
    crypto::public_key pk;
    r = crypto::derive_public_key(derivation, output_index, acc.m_account_address.m_spend_public_key, pk);
    CHECK_AND_ASSERT_MES(r, false, "Failed to derive public key");
    if (pk == otk.key)
      return true;
  
    return false;
  }

  //---------------------------------------------------------------
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, std::vector<size_t>& outs, uint64_t& money_transfered)
  {
    crypto::public_key tx_pub_key = tx.tx_pub_key;
    if(null_pkey == tx_pub_key)
      return false;
    return lookup_acc_outs(acc, tx, tx_pub_key,  outs, money_transfered);
  }
  //---------------------------------------------------------------
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, const crypto::public_key& tx_pub_key,  std::vector<size_t>& outs, uint64_t& money_transfered)
  {

    money_transfered = 0;
    size_t i = 0;
    for(const tx_out& o:  tx.vout)
    {
      CHECK_AND_ASSERT_MES(o.target.type() ==  typeid(txout_to_key), false, "wrong type id in transaction out" );
      if(is_out_to_acc(acc, boost::get<txout_to_key>(o.target), tx_pub_key,  i))
      {
        outs.push_back(i);
        money_transfered += o.amount;
      }
      i++;
    }
    return true;
  }
  //---------------------------------------------------------------
  void get_blob_hash(const blobdata_ref& blob, crypto::hash& res)
  {
    cn_fast_hash(blob.data(), blob.size(), res);
  }
  //---------------------------------------------------------------
  void get_blob_hash(const blobdata& blob, crypto::hash& res)
  {
    cn_fast_hash(blob.data(), blob.size(), res);
  }
  //---------------------------------------------------------------
  void set_default_decimal_point(unsigned int decimal_point)
  {
    switch (decimal_point)
    {
      case 12:
      case 9:
      case 6:
      case 3:
      case 0:
        default_decimal_point = decimal_point;
        break;
      default:
        throw_and_log("Invalid decimal point specification: " << decimal_point);
    }
  }
  //---------------------------------------------------------------
  unsigned int get_default_decimal_point()
  {
    return default_decimal_point;
  }
  //---------------------------------------------------------------
  std::string get_unit(unsigned int decimal_point)
  {
    if (decimal_point == (unsigned int)-1)
      decimal_point = default_decimal_point;
    switch (decimal_point)
    {
      case 8:
        return "dfa";
      case 5:
        return "mdf";
      case 0:
        return "pdf";
      default:
        throw_and_log("Invalid decimal point specification: " << decimal_point);
    }
  }
  //---------------------------------------------------------------
  static void insert_money_decimal_point(std::string &s, unsigned int decimal_point)
  {
    if (decimal_point == (unsigned int)-1)
      decimal_point = default_decimal_point;
    if(s.size() < decimal_point+1)
    {
      s.insert(0, decimal_point+1 - s.size(), '0');
    }
    if (decimal_point > 0)
      s.insert(s.size() - decimal_point, ".");
  }
  //---------------------------------------------------------------
  std::string print_money(uint64_t amount, unsigned int decimal_point)
  {
    std::string s = std::to_string(amount);
    insert_money_decimal_point(s, decimal_point);
    return s;
  }
  //---------------------------------------------------------------
  std::string print_money(const boost::multiprecision::uint128_t &amount, unsigned int decimal_point)
  {
    std::stringstream ss;
    ss << amount;
    std::string s = ss.str();
    insert_money_decimal_point(s, decimal_point);
    return s;
  }
  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const blobdata& blob)
  {
    crypto::hash h = null_hash;
    get_blob_hash(blob, h);
    return h;
  }
  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const blobdata_ref& blob)
  {
    crypto::hash h = null_hash;
    get_blob_hash(blob, h);
    return h;
  }
 
 
  //---------------------------------------------------------------
  bool calculate_transaction_prunable_hash(const transaction& t, const cryptonote::blobdata_ref *blob, crypto::hash& res)
  {
    const unsigned int unprunable_size = t.unprunable_size;
    if (blob && unprunable_size)
    {
      CHECK_AND_ASSERT_MES(unprunable_size <= blob->size(), false, "Inconsistent transaction unprunable and blob sizes");
      cryptonote::get_blob_hash(blobdata_ref(blob->data() + unprunable_size, blob->size() - unprunable_size), res);
    }
    else
    {
      if(pruned())
        throw_and_log("cannot calculate purnnable hash from prunned tx");
      
      transaction &tt = const_cast<transaction&>(t);
      std::stringstream ss;
      binary_archive<true> ba(ss);
      const size_t inputs = t.vin.size();
      const size_t outputs = t.vout.size();
      const size_t mixin = t.vin.empty() ? 0 : t.vin[0].type() == typeid(txin_to_key) ? boost::get<txin_to_key>(t.vin[0]).key_offsets.size() - 1 : 0;
      bool r = tt.rct_signatures.p.serialize_rctsig_prunable(ba, t.rct_signatures.type, inputs, outputs, mixin);
      CHECK_AND_ASSERT_MES(r, false, "Failed to serialize rct signatures prunable");
      cryptonote::get_blob_hash(ss.str(), res);
    }
    return true;
  }
  //---------------------------------------------------------------
  crypto::hash get_transaction_prunable_hash(const transaction& t, const cryptonote::blobdata_ref *blobdata)
  {
    crypto::hash res;
    if (t.is_prunable_hash_valid())
    {
      res = t.prunable_hash;
      ++tx_hashes_cached_count;
      return res;
    }

    ++tx_hashes_calculated_count;
    res = calculate_transaction_prunable_hash(t, blobdata);
    t.set_prunable_hash(res);
    return res;
  }
  //---------------------------------------------------------------
  crypto::hash get_pruned_transaction_hash(const transaction& t, const crypto::hash &pruned_data_hash)
  {

    // v2 transactions hash different parts together, than hash the set of those hashes
    crypto::hash hashes[3];

    // prefix
    hashes[0] = get_transaction_prefix_hash(t);

    transaction &tt = const_cast<transaction&>(t);

    // base rct
    {
      std::stringstream ss;
      binary_archive<true> ba(ss);
      const size_t inputs = t.vin.size();
      const size_t outputs = t.vout.size();
      bool r = tt.rct_signatures.serialize_rctsig_base(ba, inputs, outputs);
      CHECK_AND_ASSERT_THROW_MES(r, "Failed to serialize rct signatures base");
      hashes[1]=cryptonote::get_blob_hash(ss.str());
    }

    // prunable rct
    if (t.rct_signatures.type == rct::RCTTypeNull)
      hashes[2] = crypto::null_hash;
    else
      hashes[2] = pruned_data_hash;

    // the tx hash is the hash of the 3 hashes
    crypto::hash res = cn_fast_hash(hashes, sizeof(hashes));
    t.set_hash(res);
    return res;
  }
  //---------------------------------------------------------------
  crypto::hash calculate_transaction_hash(const transaction& t)
  {
    CHECK_AND_ASSERT_MES(!t.pruned, false, "Cannot calculate the hash of a pruned transaction");

    // v2 transactions hash different parts together, than hash the set of those hashes
    crypto::hash hashes[3];

    // prefix
    hashes[0]=get_transaction_prefix_hash(t);

    const blobdata blob = tx_to_blob(t);
    const unsigned int unprunable_size = t.unprunable_size;
    const unsigned int prefix_size = t.prefix_size;

    // base rct
    CHECK_AND_ASSERT_MES(prefix_size <= unprunable_size && unprunable_size <= blob.size(), false, "Inconsistent transaction prefix, unprunable and blob sizes "<<prefix_size<<","<<unprunable_size<<","<<blob.size());
    
     hashes[1] =cryptonote::get_blob_hash(blobdata_ref(blob.data() + prefix_size, unprunable_size - prefix_size));

    // prunable rct
    if (t.rct_signatures.type == rct::RCTTypeNull)
    {
      hashes[2] = crypto::null_hash;
    }
    else
    {
        if(tx.is_prunable_hash_valid()){
          hashes[2]=tx.prunable_hash;
        }
        else{
        cryptonote::blobdata_ref blobref(blob);
        hashes[2]=calculate_transaction_prunable_hash(t, &blobref);
      }
    }

    // the tx hash is the hash of the 3 hashes
    const auto h = cn_fast_hash(hashes, sizeof(hashes));
    return h;
  }
  //---------------------------------------------------------------
  crypto::hash get_transaction_hash(const transaction& t)
  {
    if (t.is_hash_valid())
    {
      ++tx_hashes_cached_count;
      return t.hash;
    }

    ++tx_hashes_calculated_count;
    res = calculate_transaction_hash(t);
    t.set_hash(res);
    return res;
  }
 
  //---------------------------------------------------------------
  blobdata get_block_hashing_blob(const block& b)
  {
    //header+tx
    const block_header & header=b;
    blobdata blob = t_serializable_object_to_blob(header);
    crypto::hash tree_root_hash = get_tx_tree_hash(b);
    blob.append(reinterpret_cast<const char*>(&tree_root_hash), sizeof(tree_root_hash));
    blob.append(tools::get_varint_data(b.tx_hashes.size()+1));
    return blob;
  }
  //---------------------------------------------------------------
  bool calculate_block_hash(const block& b, crypto::hash& res, const blobdata_ref *blob)
  {
   
    bool hash_result = get_object_hash(get_block_hashing_blob(b), res);
    if (!hash_result)
      return false;

    return hash_result;
  }
  //---------------------------------------------------------------
  bool get_block_hash(const block& b, crypto::hash& res)
  {
    if (b.is_hash_valid())
    {
#ifdef ENABLE_HASH_CASH_INTEGRITY_CHECK
      CHECK_AND_ASSERT_THROW_MES(!calculate_block_hash(b, res) || b.hash == res, "block hash cash integrity failure");
#endif
      res = b.hash;
      ++block_hashes_cached_count;
      return true;
    }
    ++block_hashes_calculated_count;
    bool ret = calculate_block_hash(b, res);
    if (!ret)
      return false;
    b.set_hash(res);
    return true;
  }
  //---------------------------------------------------------------
  crypto::hash get_block_hash(const block& b)
  {
    crypto::hash p = null_hash;
    get_block_hash(b, p);
    return p;
  }
  //---------------------------------------------------------------
  std::vector<uint64_t> relative_output_offsets_to_absolute(const std::vector<uint64_t>& off)
  {
    std::vector<uint64_t> res = off;
    for(size_t i = 1; i < res.size(); i++)
      res[i] += res[i-1];
    return res;
  }
  //---------------------------------------------------------------
  std::vector<uint64_t> absolute_output_offsets_to_relative(const std::vector<uint64_t>& off)
  {
    std::vector<uint64_t> res = off;
    if(!off.size())
      return res;
    std::sort(res.begin(), res.end());//just to be sure, actually it is already should be sorted
    for(size_t i = res.size()-1; i != 0; i--)
      res[i] -= res[i-1];

    return res;
  }
  //---------------------------------------------------------------
  block parse_block_from_blob(const blobdata_ref& b_blob)
  {

     if(b_blob.size() > 16*1024*1024)
    {
       throw std::runtime_error("too large block");
    }
    block b;
    std::stringstream ss;
    ss << b_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, b);
    if(!r)
    {
      std::ostringstream ost;
      ost<<"Failed to parse block from blob ";
      ost<<to_hex::string(to_byte_span(to_span(b_blob)));
     throw std::runtime_error(ost.str());
    }
    b.invalidate_hashes();
    b.miner_tx.invalidate_hashes();
    return b;
  }
 
  //---------------------------------------------------------------
  blobdata block_to_blob(const block& b)
  {
    return t_serializable_object_to_blob(b);
  }
  //---------------------------------------------------------------
  bool block_to_blob(const block& b, blobdata& b_blob)
  {
    return t_serializable_object_to_blob(b, b_blob);
  }
  //---------------------------------------------------------------
  blobdata tx_to_blob(const transaction& tx)
  {
    return t_serializable_object_to_blob(tx);
  }
  //---------------------------------------------------------------
  bool tx_to_blob(const transaction& tx, blobdata& b_blob)
  {
    return t_serializable_object_to_blob(tx, b_blob);
  }
 
 
  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const block& b)
  {
    std::vector<crypto::hash> tx_hashes;
    tx_hashes.reserve(1 + b.tx_hashes.size());
   const crypto::hash miner_h = get_transaction_hash(b.miner_tx);
    tx_hashes.push_back(miner_h);
    for(auto& th: b.tx_hashes)
      tx_hashes.push_back(th);
   
    crypto::hash h = null_hash;
    tree_hash(tx_hashes.data(), tx_hashes.size(), h);
    return h;
  }
  //---------------------------------------------------------------
  bool is_valid_decomposed_amount(uint64_t amount)
  {
    const uint64_t *begin = valid_decomposed_outputs;
    const uint64_t *end = valid_decomposed_outputs + sizeof(valid_decomposed_outputs) / sizeof(valid_decomposed_outputs[0]);
    return std::binary_search(begin, end, amount);
  }
  //---------------------------------------------------------------
  void get_hash_stats(uint64_t &tx_hashes_calculated, uint64_t &tx_hashes_cached, uint64_t &block_hashes_calculated, uint64_t & block_hashes_cached)
  {
    tx_hashes_calculated = tx_hashes_calculated_count;
    tx_hashes_cached = tx_hashes_cached_count;
    block_hashes_calculated = block_hashes_calculated_count;
    block_hashes_cached = block_hashes_cached_count;
  }
  //---------------------------------------------------------------
  crypto::secret_key encrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase)
  {
    crypto::hash hash;
    crypto::cn_fast_hash(passphrase.data(), passphrase.size(), hash);
    sc_add((unsigned char*)key.data, (const unsigned char*)key.data, (const unsigned char*)hash.data);
    return key;
  }
  //---------------------------------------------------------------
  crypto::secret_key decrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase)
  {
    crypto::hash hash;
    crypto::cn_fast_hash(passphrase.data(), passphrase.size(), hash);
    sc_sub((unsigned char*)key.data, (const unsigned char*)key.data, (const unsigned char*)hash.data);
    return key;
  }
}
