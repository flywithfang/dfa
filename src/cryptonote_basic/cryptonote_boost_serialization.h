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

#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/serialization/variant.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/is_bitwise_serializable.hpp>
#include <boost/archive/portable_binary_iarchive.hpp>
#include <boost/archive/portable_binary_oarchive.hpp>
#include "cryptonote_basic.h"
#include "difficulty.h"
#include "common/unordered_containers_boost_serialization.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "ringct/rctOps.h"

namespace boost
{
  namespace serialization
  {

  //---------------------------------------------------
  template <class Archive>
  inline void serialize(Archive &a, crypto::public_key &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::public_key)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::secret_key &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::secret_key)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::key_derivation &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::key_derivation)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::key_image &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::key_image)]>(x);
  }

  template <class Archive>
  inline void serialize(Archive &a, crypto::signature &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::signature)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::hash &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::hash)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::hash8 &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::hash8)]>(x);
  }



  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txout_to_key &x, const boost::serialization::version_type ver)
  {
    a & x.key;
  }


  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txin_gen &x, const boost::serialization::version_type ver)
  {
    a & x.height;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txin_to_key &x, const boost::serialization::version_type ver)
  {
    a & x.amount;
    a & x.key_offsets;
    a & x.k_image;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::tx_out &x, const boost::serialization::version_type ver)
  {
    a & x.amount;
    a & x.target;
  }


  template <class Archive>
  inline void serialize(Archive &a, cryptonote::transaction_prefix &x, const boost::serialization::version_type ver)
  {
    a & x.version;
    a & x.unlock_time;
    a & x.vin;
    a & x.vout;
    a & x.extra;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::transaction &x, const boost::serialization::version_type ver)
  {
    a & x.version;
    a & x.unlock_time;
    a & x.vin;
    a & x.vout;
    a & x.extra;
    {
      a & (rct::rctSigBase&)x.rct_signatures;
      if (x.rct_signatures.type != rct::RCTTypeNull)
        a & x.rct_signatures.p;
    }
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::block &b, const boost::serialization::version_type ver)
  {
    a & b.major_version;
    a & b.minor_version;
    a & b.timestamp;
    a & b.prev_id;
    a & b.nonce;
    //------------------
    a & b.miner_tx;
    a & b.tx_hashes;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::key &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(rct::key)]>(x);
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::ctkey &x, const boost::serialization::version_type ver)
  {
    a & x.otk;
    a & x.commitment;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::rangeSig &x, const boost::serialization::version_type ver)
  {
    a & x.asig;
    a & x.Ci;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::Bulletproof &x, const boost::serialization::version_type ver)
  {
    a & x.V;
    a & x.A;
    a & x.S;
    a & x.T1;
    a & x.T2;
    a & x.taux;
    a & x.mu;
    a & x.L;
    a & x.R;
    a & x.a;
    a & x.b;
    a & x.t;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::boroSig &x, const boost::serialization::version_type ver)
  {
    a & x.s0;
    a & x.s1;
    a & x.ee;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::mgSig &x, const boost::serialization::version_type ver)
  {
    a & x.ss;
    a & x.cc;
    // a & x.II; // not serialized, we can recover it from the tx vin
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::clsag &x, const boost::serialization::version_type ver)
  {
    a & x.s;
    a & x.c1;
    // a & x.I; // not serialized, we can recover it from the tx vin
    a & x.D;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::ecdhTuple &x, const boost::serialization::version_type ver)
  {
    a & x.amount;
  }

  template <class Archive>
  inline typename std::enable_if<Archive::is_loading::value, void>::type serializeOutPk(Archive &a, rct::ctkeyV &outPk_, const boost::serialization::version_type ver)
  {
    rct::keyV outCommitments;
    a & outCommitments;
    outPk_.resize(outCommitments.size());
    for (size_t n = 0; n < outPk_.size(); ++n)
    {
      outPk_[n].otk = rct::identity();
      outPk_[n].commitment = outCommitments[n];
    }
  }

  template <class Archive>
  inline typename std::enable_if<Archive::is_saving::value, void>::type serializeOutPk(Archive &a, rct::ctkeyV &outPk_, const boost::serialization::version_type ver)
  {
    rct::keyV outCommitments(outPk_.size());
    for (size_t n = 0; n < outPk_.size(); ++n)
      outCommitments[n] = outPk_[n].commitment;
    a & outCommitments;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::rctSigBase &x, const boost::serialization::version_type ver)
  {
    a & x.type;
    if (x.type == rct::RCTTypeNull)
      return;
    if (x.type != rct::RCTTypeFull && x.type != rct::RCTTypeSimple && x.type != rct::RCTTypeBulletproof && x.type != rct::RCTTypeBulletproof2 && x.type != rct::RCTTypeCLSAG)
      throw boost::archive::archive_exception(boost::archive::archive_exception::other_exception, "Unsupported rct type");
 
    a & x.ecdhInfo;
    serializeOutPk(a, x.outCommitments, ver);
    a & x.txnFee;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::rctSigPrunable &x, const boost::serialization::version_type ver)
  {
      a & x.bulletproofs;
      a & x.CLSAGs;
      a & x.pseudoOuts;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::rctSig &x, const boost::serialization::version_type ver)
  {
    a & x.type;
    if (x.type == rct::RCTTypeNull)
      return;
    if (x.type != rct::RCTTypeFull && x.type != rct::RCTTypeSimple && x.type != rct::RCTTypeBulletproof && x.type != rct::RCTTypeBulletproof2 && x.type != rct::RCTTypeCLSAG)
      throw boost::archive::archive_exception(boost::archive::archive_exception::other_exception, "Unsupported rct type");
    // a & x.message; message is not serialized, as it can be reconstructed from the tx data
    // a & x.mixRing; mixRing is not serialized, as it can be reconstructed from the offsets
    a & x.ecdhInfo;
    serializeOutPk(a, x.outCommitments, ver);
    a & x.txnFee;
    //--------------
    a & x.p.bulletproofs;

    a & x.p.CLSAGs;
    if (x.type == rct::RCTTypeBulletproof || x.type == rct::RCTTypeBulletproof2 || x.type == rct::RCTTypeCLSAG)
      a & x.p.pseudoOuts;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::RCTConfig &x, const boost::serialization::version_type ver)
  {
    a & x.range_proof_type;
    a & x.bp_version;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::difficulty_type &x, const boost::serialization::version_type ver)
  {
    if (Archive::is_loading::value)
    {
      // load high part
      uint64_t v = 0;
      a & v;
      x = v;
      // load low part
      x = x << 64;
      a & v;
      x += v;
    }
    else
    {
      // store high part
      cryptonote::difficulty_type x_ = (x >> 64) & 0xffffffffffffffff;
      uint64_t v = x_.convert_to<uint64_t>();
      a & v;
      // store low part
      x_ = x & 0xffffffffffffffff;
      v = x_.convert_to<uint64_t>();
      a & v;
    }
  }

}
}

BOOST_CLASS_VERSION(rct::rctSigPrunable, 1)
BOOST_CLASS_VERSION(rct::rctSig, 1)
