// Copyright (c) 2016, Monero Research Labs
//
// Author: Shen Noether <shen.noether@gmx.com>
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

#include "misc_log_ex.h"
#include "misc_language.h"
#include "common/perf_timer.h"
#include "common/threadpool.h"
#include "common/util.h"
#include "rctSigs.h"
#include "bulletproofs.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"

using namespace crypto;
using namespace std;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

#define CHECK_AND_ASSERT_MES_L1(expr, ret, message) {if(!(expr)) {MCERROR("verify", message); return ret;}}

namespace
{
    rct::Bulletproof make_dummy_bulletproof(const std::vector<uint64_t> &outamounts, rct::keyV &C, rct::keyV &masks)
    {
        const size_t n_outs = outamounts.size();
        const rct::key I = rct::identity();
        size_t nrl = 0;
        while ((1u << nrl) < n_outs)
          ++nrl;
        nrl += 6;

        C.resize(n_outs);
        masks.resize(n_outs);
        for (size_t i = 0; i < n_outs; ++i)
        {
            masks[i] = I;
            rct::key sv8, sv;
            sv = rct::zero();
            sv.bytes[0] = outamounts[i] & 255;
            sv.bytes[1] = (outamounts[i] >> 8) & 255;
            sv.bytes[2] = (outamounts[i] >> 16) & 255;
            sv.bytes[3] = (outamounts[i] >> 24) & 255;
            sv.bytes[4] = (outamounts[i] >> 32) & 255;
            sv.bytes[5] = (outamounts[i] >> 40) & 255;
            sv.bytes[6] = (outamounts[i] >> 48) & 255;
            sv.bytes[7] = (outamounts[i] >> 56) & 255;
            sc_mul(sv8.bytes, sv.bytes, rct::INV_EIGHT.bytes);
            //
            rct::addKeys2(C[i], rct::INV_EIGHT, sv8, rct::H);
        }

        return rct::Bulletproof{rct::keyV(n_outs, I), I, I, I, I, I, I, rct::keyV(nrl, I), rct::keyV(nrl, I), I, I, I};
    }
}

namespace rct {
    Bulletproof proveRangeBulletproof(keyV &C, keyV &noises, const std::vector<uint64_t> &amounts, const std::vector<key>& shared_secs, hw::device &hwdev)
    {
        CHECK_AND_ASSERT_THROW_MES(amounts.size() == shared_secs.size(), "Invalid amounts/sk sizes");
        noises.resize(amounts.size());
        for (size_t i = 0; i < amounts.size(); ++i)
         {
            const key & shared_sec = shared_secs[i];
            noises[i] = rct::genCommitmentMask(shared_sec);
         }
        Bulletproof proof = bulletproof_PROVE(amounts, noises);
        CHECK_AND_ASSERT_THROW_MES(proof.V.size() == amounts.size(), "V does not have the expected size");
        C = proof.V;
        return proof;
    }

    bool verBulletproof(const Bulletproof &proof)
    {
      try { return bulletproof_VERIFY(proof); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    bool verBulletproof(const std::vector<const Bulletproof*> &proofs)
    {
      try { return bulletproof_VERIFY(proofs); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    //Borromean (c.f. gmax/andytoshi's paper)
    boroSig genBorromean(const key64 x, const key64 P1, const key64 P2, const bits indices) {
        key64 L[2], alpha;
        auto wiper = epee::misc_utils::create_scope_leave_handler([&](){memwipe(alpha, sizeof(alpha));});
        key c;
        int naught = 0, prime = 0, ii = 0, jj=0;
        boroSig bb;
        for (ii = 0 ; ii < 64 ; ii++) {
            naught = indices[ii]; prime = (indices[ii] + 1) % 2;
            skGen(alpha[ii]);
            scalarmultBase(L[naught][ii], alpha[ii]);
            if (naught == 0) {
                skGen(bb.s1[ii]);
                c = hash_to_scalar(L[naught][ii]);
                addKeys2(L[prime][ii], bb.s1[ii], c, P2[ii]);
            }
        }
        bb.ee = hash_to_scalar(L[1]); //or L[1]..
        key LL, cc;
        for (jj = 0 ; jj < 64 ; jj++) {
            if (!indices[jj]) {
                sc_mulsub(bb.s0[jj].bytes, x[jj].bytes, bb.ee.bytes, alpha[jj].bytes);
            } else {
                skGen(bb.s0[jj]);
                addKeys2(LL, bb.s0[jj], bb.ee, P1[jj]); //different L0
                cc = hash_to_scalar(LL);
                sc_mulsub(bb.s1[jj].bytes, x[jj].bytes, cc.bytes, alpha[jj].bytes);
            }
        }
        return bb;
    }
    
    //see above.
    bool verifyBorromean(const boroSig &bb, const ge_p3 P1[64], const ge_p3 P2[64]) {
        key64 Lv1; key chash, LL;
        int ii = 0;
        ge_p2 p2;
        for (ii = 0 ; ii < 64 ; ii++) {
            // equivalent of: addKeys2(LL, bb.s0[ii], bb.ee, P1[ii]);
            ge_double_scalarmult_base_vartime(&p2, bb.ee.bytes, &P1[ii], bb.s0[ii].bytes);
            ge_tobytes(LL.bytes, &p2);
            chash = hash_to_scalar(LL);
            // equivalent of: addKeys2(Lv1[ii], bb.s1[ii], chash, P2[ii]);
            ge_double_scalarmult_base_vartime(&p2, chash.bytes, &P2[ii], bb.s1[ii].bytes);
            ge_tobytes(Lv1[ii].bytes, &p2);
        }
        key eeComputed = hash_to_scalar(Lv1); //hash function fine
        return equalKeys(eeComputed, bb.ee);
    }

    bool verifyBorromean(const boroSig &bb, const key64 P1, const key64 P2) {
      ge_p3 P1_p3[64], P2_p3[64];
      for (size_t i = 0 ; i < 64 ; ++i) {
        CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&P1_p3[i], P1[i].bytes) == 0, false, "point conv failed");
        CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&P2_p3[i], P2[i].bytes) == 0, false, "point conv failed");
      }
      return verifyBorromean(bb, P1_p3, P2_p3);
    }

    // Generate a CLSAG signature
    // See paper by Goodell et al. (https://eprint.iacr.org/2019/654)
    //
    // The keys are set as follows:
    //   P[l] == p*G
    //   C[l] == z*G
    //   C[i] == C_nonzero[i] - C_offset (for hashing purposes) for all i
    clsag CLSAG_Gen(const key &message, const keyV & P, const key & p, const keyV & C, const key & z, const keyV & C_nonzero, const key & C_offset, const unsigned int l,  hw::device &hwdev) {
        clsag sig;
        size_t n = P.size(); // ring size
        CHECK_AND_ASSERT_THROW_MES(n == C.size(), "Signing and commitment key vector sizes must match!");
        CHECK_AND_ASSERT_THROW_MES(n == C_nonzero.size(), "Signing and commitment key vector sizes must match!");
        CHECK_AND_ASSERT_THROW_MES(l < n, "Signing index out of range!");

        // Key images
        ge_p3 H_p3;
        hash_to_p3(H_p3,P[l]);
        key H;
        ge_p3_tobytes(H.bytes,&H_p3);

        key D;

        // Initial values
        key a;
        key aG;
        key aH;

        {
            hwdev.clsag_prepare(p,z,sig.I,D,H,a,aG,aH);
        }

        geDsmp I_precomp;
        geDsmp D_precomp;
        precomp(I_precomp.k,sig.I);
        precomp(D_precomp.k,D);

        // Offset key image
        scalarmultKey(sig.D,D,INV_EIGHT);

        // Aggregation hashes
        keyV mu_P_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        keyV mu_C_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        sc_0(mu_P_to_hash[0].bytes);
        memcpy(mu_P_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_0,sizeof(config::HASH_KEY_CLSAG_AGG_0)-1);
        sc_0(mu_C_to_hash[0].bytes);
        memcpy(mu_C_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_1,sizeof(config::HASH_KEY_CLSAG_AGG_1)-1);
        for (size_t i = 1; i < n+1; ++i) {
            mu_P_to_hash[i] = P[i-1];
            mu_C_to_hash[i] = P[i-1];
        }
        for (size_t i = n+1; i < 2*n+1; ++i) {
            mu_P_to_hash[i] = C_nonzero[i-n-1];
            mu_C_to_hash[i] = C_nonzero[i-n-1];
        }
        mu_P_to_hash[2*n+1] = sig.I;
        mu_P_to_hash[2*n+2] = sig.D;
        mu_P_to_hash[2*n+3] = C_offset;
        mu_C_to_hash[2*n+1] = sig.I;
        mu_C_to_hash[2*n+2] = sig.D;
        mu_C_to_hash[2*n+3] = C_offset;
        key mu_P, mu_C;
        mu_P = hash_to_scalar(mu_P_to_hash);
        mu_C = hash_to_scalar(mu_C_to_hash);

        // Initial commitment
        keyV c_to_hash(2*n+5); // domain, P, C, C_offset, message, aG, aH
        key c;
        sc_0(c_to_hash[0].bytes);
        memcpy(c_to_hash[0].bytes,config::HASH_KEY_CLSAG_ROUND,sizeof(config::HASH_KEY_CLSAG_ROUND)-1);
        for (size_t i = 1; i < n+1; ++i)
        {
            c_to_hash[i] = P[i-1];
            c_to_hash[i+n] = C_nonzero[i-1];
        }
        c_to_hash[2*n+1] = C_offset;
        c_to_hash[2*n+2] = message;

        {
            c_to_hash[2*n+3] = aG;
            c_to_hash[2*n+4] = aH;
        }
        hwdev.clsag_hash(c_to_hash,c);
        
        size_t i;
        i = (l + 1) % n;
        if (i == 0)
            copy(sig.c1, c);

        // Decoy indices
        sig.s = keyV(n);
        key c_new;
        key L;
        key R;
        key c_p; // = c[i]*mu_P
        key c_c; // = c[i]*mu_C
        geDsmp P_precomp;
        geDsmp C_precomp;
        geDsmp H_precomp;
        ge_p3 Hi_p3;

        while (i != l) {
            sig.s[i] = skGen();
            sc_0(c_new.bytes);
            sc_mul(c_p.bytes,mu_P.bytes,c.bytes);
            sc_mul(c_c.bytes,mu_C.bytes,c.bytes);

            // Precompute points
            precomp(P_precomp.k,P[i]);
            precomp(C_precomp.k,C[i]);

            // Compute L
            addKeys_aGbBcC(L,sig.s[i],c_p,P_precomp.k,c_c,C_precomp.k);

            // Compute R
            hash_to_p3(Hi_p3,P[i]);
            ge_dsm_precomp(H_precomp.k, &Hi_p3);
            addKeys_aAbBcC(R,sig.s[i],H_precomp.k,c_p,I_precomp.k,c_c,D_precomp.k);

            c_to_hash[2*n+3] = L;
            c_to_hash[2*n+4] = R;
            hwdev.clsag_hash(c_to_hash,c_new);
            copy(c,c_new);
            
            i = (i + 1) % n;
            if (i == 0)
                copy(sig.c1,c);
        }

        // Compute final scalar
        hwdev.clsag_sign(c,a,p,z,mu_P,mu_C,sig.s[l]);
        memwipe(&a, sizeof(key));

        return sig;
    }

    clsag CLSAG_Gen(const key &message, const keyV & P, const key & p, const keyV & C, const key & z, const keyV & C_nonzero, const key & C_offset, const unsigned int l) {
        return CLSAG_Gen(message, P, p, C, z, C_nonzero, C_offset, l,  hw::get_device("default"));
    }

    key get_pre_mlsag_hash(const rctSig &rv, hw::device &hwdev)
    {
      keyV hashes;
      hashes.reserve(3);
      hashes.push_back(rv.message);
      crypto::hash h;

      std::stringstream ss;
      binary_archive<true> ba(ss);
      CHECK_AND_ASSERT_THROW_MES(!rv.mixRing.empty(), "Empty mixRing");
      const size_t inputs = rv.mixRing.size() ;
      const size_t outputs = rv.ecdhInfo.size();
      key prehash;
      CHECK_AND_ASSERT_THROW_MES(const_cast<rctSig&>(rv).serialize_rctsig_base(ba, inputs, outputs),
          "Failed to serialize rctSigBase");
      cryptonote::get_blob_hash(ss.str(), h);
      hashes.push_back(hash2rct(h));

      std::vector<key> kv;
      if (rv.type == RCTTypeBulletproof || rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG)
      {
        kv.reserve((6*2+9) * rv.p.bulletproofs.size());
        for (const auto &p: rv.p.bulletproofs)
        {
          // V are not hashed as they're expanded from outPk.mask
          // (and thus hashed as part of rctSigBase above)
          kv.push_back(p.A);
          kv.push_back(p.S);
          kv.push_back(p.T1);
          kv.push_back(p.T2);
          kv.push_back(p.taux);
          kv.push_back(p.mu);
          for (size_t n = 0; n < p.L.size(); ++n)
            kv.push_back(p.L[n]);
          for (size_t n = 0; n < p.R.size(); ++n)
            kv.push_back(p.R[n]);
          kv.push_back(p.a);
          kv.push_back(p.b);
          kv.push_back(p.t);
        }
      }
    
      hashes.push_back(cn_fast_hash(kv));
   
      prehash = rct::cn_fast_hash(hashes);
      return  prehash;
    }



    clsag proveRctCLSAGSimple(const key &message, const std::vector<ctkey> &decoys, const ctkey &real_in, const key &noise, const key &in_C2,  unsigned int index, hw::device &hwdev) {
        //setup vars
        size_t rows = 1;
        size_t cols = decoys.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 1, "Empty pubs");
        keyV tmp(rows + 1);
      //  std::vector<key> sk(rows + 1);
        keyM M(cols, tmp);

        keyV P, C, C_nonzero;
        P.reserve(decoys.size());
        C.reserve(decoys.size());
        C_nonzero.reserve(decoys.size());
        for (const ctkey &decoy: decoys)
        {
            const key &otk=decoy.otk;
            const key &commitment=decoy.commitment;
            P.push_back(otk);//otk
            C_nonzero.push_back(commitment);
            rct::key tmp;
            ///Ci-C2
            subKeys(tmp, commitment, in_C2);
            C.push_back(tmp);
        }

        //otk_sec
        const key & otk_sec=real_in.otk_sec;
        const key & real_noise=real_in.noise;
       // sk[0] = copy(otk_sec);
        key noise_delta;
        sc_sub(noise_delta.bytes, real_noise.bytes, noise.bytes);
        clsag result = CLSAG_Gen(message, P, otk_sec, C, noise_delta, C_nonzero, in_C2, index,  hwdev);
      //  memwipe(sk.data(), sk.size() * sizeof(key));
        return result;
    }


    bool verRctCLSAGSimple(const key &message, const clsag &sig, const ctkeyV & pubs, const key & C_offset) {
        try
        {
            PERF_TIMER(verRctCLSAGSimple);
            const size_t n = pubs.size();

            // Check data
            CHECK_AND_ASSERT_MES(n >= 1, false, "Empty pubs");
            CHECK_AND_ASSERT_MES(n == sig.s.size(), false, "Signature scalar vector is the wrong size!");
            for (size_t i = 0; i < n; ++i)
                CHECK_AND_ASSERT_MES(sc_check(sig.s[i].bytes) == 0, false, "Bad signature scalar!");
            CHECK_AND_ASSERT_MES(sc_check(sig.c1.bytes) == 0, false, "Bad signature commitment!");
            CHECK_AND_ASSERT_MES(!(sig.I == rct::identity()), false, "Bad key image!");

            // Cache commitment offset for efficient subtraction later
            ge_p3 C_offset_p3;
            CHECK_AND_ASSERT_MES(ge_frombytes_vartime(&C_offset_p3, C_offset.bytes) == 0, false, "point conv failed");
            ge_cached C_offset_cached;
            ge_p3_to_cached(&C_offset_cached, &C_offset_p3);

            // Prepare key images
            key c = copy(sig.c1);
            key D_8 = scalarmult8(sig.D);
            CHECK_AND_ASSERT_MES(!(D_8 == rct::identity()), false, "Bad auxiliary key image!");
            geDsmp I_precomp;
            geDsmp D_precomp;
            precomp(I_precomp.k,sig.I);
            precomp(D_precomp.k,D_8);

            // Aggregation hashes
            keyV mu_P_to_hash(2*n+4); // domain, I, D, P, C, C_offset
            keyV mu_C_to_hash(2*n+4); // domain, I, D, P, C, C_offset
            sc_0(mu_P_to_hash[0].bytes);
            memcpy(mu_P_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_0,sizeof(config::HASH_KEY_CLSAG_AGG_0)-1);
            sc_0(mu_C_to_hash[0].bytes);
            memcpy(mu_C_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_1,sizeof(config::HASH_KEY_CLSAG_AGG_1)-1);
            for (size_t i = 1; i < n+1; ++i) {
                mu_P_to_hash[i] = pubs[i-1].dest;
                mu_C_to_hash[i] = pubs[i-1].dest;
            }
            for (size_t i = n+1; i < 2*n+1; ++i) {
                mu_P_to_hash[i] = pubs[i-n-1].mask;
                mu_C_to_hash[i] = pubs[i-n-1].mask;
            }
            mu_P_to_hash[2*n+1] = sig.I;
            mu_P_to_hash[2*n+2] = sig.D;
            mu_P_to_hash[2*n+3] = C_offset;
            mu_C_to_hash[2*n+1] = sig.I;
            mu_C_to_hash[2*n+2] = sig.D;
            mu_C_to_hash[2*n+3] = C_offset;
            key mu_P, mu_C;
            mu_P = hash_to_scalar(mu_P_to_hash);
            mu_C = hash_to_scalar(mu_C_to_hash);

            // Set up round hash
            keyV c_to_hash(2*n+5); // domain, P, C, C_offset, message, L, R
            sc_0(c_to_hash[0].bytes);
            memcpy(c_to_hash[0].bytes,config::HASH_KEY_CLSAG_ROUND,sizeof(config::HASH_KEY_CLSAG_ROUND)-1);
            for (size_t i = 1; i < n+1; ++i)
            {
                c_to_hash[i] = pubs[i-1].dest;
                c_to_hash[i+n] = pubs[i-1].mask;
            }
            c_to_hash[2*n+1] = C_offset;
            c_to_hash[2*n+2] = message;
            key c_p; // = c[i]*mu_P
            key c_c; // = c[i]*mu_C
            key c_new;
            key L;
            key R;
            geDsmp P_precomp;
            geDsmp C_precomp;
            size_t i = 0;
            ge_p3 hash8_p3;
            geDsmp hash_precomp;
            ge_p3 temp_p3;
            ge_p1p1 temp_p1;

            while (i < n) {
                sc_0(c_new.bytes);
                sc_mul(c_p.bytes,mu_P.bytes,c.bytes);
                sc_mul(c_c.bytes,mu_C.bytes,c.bytes);

                // Precompute points for L/R
                precomp(P_precomp.k,pubs[i].dest);

                CHECK_AND_ASSERT_MES(ge_frombytes_vartime(&temp_p3, pubs[i].mask.bytes) == 0, false, "point conv failed");
                ge_sub(&temp_p1,&temp_p3,&C_offset_cached);
                ge_p1p1_to_p3(&temp_p3,&temp_p1);
                ge_dsm_precomp(C_precomp.k,&temp_p3);

                // Compute L
                addKeys_aGbBcC(L,sig.s[i],c_p,P_precomp.k,c_c,C_precomp.k);

                // Compute R
                hash_to_p3(hash8_p3,pubs[i].dest);
                ge_dsm_precomp(hash_precomp.k, &hash8_p3);
                addKeys_aAbBcC(R,sig.s[i],hash_precomp.k,c_p,I_precomp.k,c_c,D_precomp.k);

                c_to_hash[2*n+3] = L;
                c_to_hash[2*n+4] = R;
                c_new = hash_to_scalar(c_to_hash);
                CHECK_AND_ASSERT_MES(!(c_new == rct::zero()), false, "Bad signature hash");
                copy(c,c_new);

                i = i + 1;
            }
            sc_sub(c_new.bytes,c.bytes,sig.c1.bytes);
            return sc_isnonzero(c_new.bytes) == 0;
        }
        catch (...) { return false; }
    }


    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).    
    void getKeyFromBlockchain(ctkey & a, size_t reference_index) {
        a.noise = pkGen();
        a.otk = pkGen();
    }

    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" + 1 columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).     
    tuple<ctkeyM, xmr_amount> populateFromBlockchain(ctkeyV inPk, int mixin) {
        int rows = inPk.size();
        ctkeyM rv(mixin + 1, inPk);
        int index = randXmrAmount(mixin);
        int i = 0, j = 0;
        for (i = 0; i <= mixin; i++) {
            if (i != index) {
                for (j = 0; j < rows; j++) {
                    getKeyFromBlockchain(rv[i][j], (size_t)randXmrAmount);
                }
            }
        }
        return make_tuple(rv, index);
    }

    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).     
    xmr_amount populateFromBlockchainSimple(ctkeyV & mixRing, const ctkey & inPk, int mixin) {
        int index = randXmrAmount(mixin);
        int i = 0;
        for (i = 0; i <= mixin; i++) {
            if (i != index) {
                getKeyFromBlockchain(mixRing[i], (size_t)randXmrAmount(1000));
            } else {
                mixRing[i] = inPk;
            }
        }
        return index;
    }

  

    
    //RCT simple    
    //for post-rct only
    rctSig genRctSimple(const key &message, const std::vector<ctkey> & inSk, const keyV & destinations, const vector<xmr_amount> &inamounts, const vector<xmr_amount> &outamounts, xmr_amount txnFee, const ctkeyM & mixRing, const std::vector<key> &shared_secs,  const std::vector<unsigned int> & index, std::vector<ctkey> &outSk, const RCTConfig &rct_config, hw::device &hwdev) {
        const bool bulletproof = rct_config.range_proof_type != RangeProofBorromean;
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() > 0, "Empty inamounts");
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() == inSk.size(), "Different number of inamounts/inSk");
        CHECK_AND_ASSERT_THROW_MES(outamounts.size() == destinations.size(), "Different number of amounts/destinations");
        CHECK_AND_ASSERT_THROW_MES(shared_secs.size() == destinations.size(), "Different number of shared_secs/destinations");
        CHECK_AND_ASSERT_THROW_MES(index.size() == inSk.size(), "Different number of index/inSk");
        CHECK_AND_ASSERT_THROW_MES(mixRing.size() == inSk.size(), "Different number of mixRing/inSk");
        for (size_t n = 0; n < mixRing.size(); ++n) {
          CHECK_AND_ASSERT_THROW_MES(index[n] < mixRing[n].size(), "Bad index into mixRing");
        }
  

        rctSig rv{};
        rv.type = RCTTypeCLSAG;
        
        rv.message = message;
        rv.outPk.resize(destinations.size());
        rv.ecdhInfo.resize(destinations.size());

        size_t i;
        //keyV masks(destinations.size()); //sk mask..
        outSk.resize(destinations.size());
        for (i = 0; i < destinations.size(); i++) {

            //add destination to sig
            rv.outPk[i].otk = copy(destinations[i]);
        }

        rv.p.bulletproofs.clear();
        {
          //  if (rct_config.range_proof_type == RangeProofPaddedBulletproof)
            {
                rct::keyV C, noises;
                if (hwdev.get_mode() == hw::device::TRANSACTION_CREATE_FAKE)
                {
                    // use a fake bulletproof for speed
                    rv.p.bulletproofs.push_back(make_dummy_bulletproof(outamounts, C, noises));
                }
                else
                {
                    rv.p.bulletproofs.push_back(proveRangeBulletproof(C, noises, outamounts, shared_secs, hwdev));
                    #ifdef DBG
                    CHECK_AND_ASSERT_THROW_MES(verBulletproof(rv.p.bulletproofs.back()), "verBulletproof failed on newly created proof");
                    #endif
                }
                for (i = 0; i < outamounts.size(); ++i)
                {
                    rv.outPk[i].commitment = rct::scalarmult8(C[i]);
                    outSk[i].noise = noises[i];
                }
            }
          
        }

        key sumout = zero();
        for (i = 0; i < outamounts.size(); ++i)
        {
            const key & noise=outSk[i].noise;
            sc_add(sumout.bytes, noise.bytes, sumout.bytes);

            //mask amount 
            auto a = outamounts[i];
            auto a2 = rct::ecdhEncode(a, shared_secs[i]);
            rv.ecdhInfo[i].amount = a2;
        }
            
        //set txn fee
        rv.txnFee = txnFee;
//        TODO: unused ??
//        key txnFeeKey = scalarmultH(d2h(rv.txnFee));
        rv.mixRing = mixRing;
        std::vector<key> &in_C2s =  rv.p.pseudoOuts ;
        in_C2s.resize(inamounts.size());
        if (rv.type == RCTTypeCLSAG)
            rv.p.CLSAGs.resize(inamounts.size());

        key sum_in = zero(); //sum pseudoOut masks
        std::vector<key> noises(inamounts.size());
        for (i = 0 ; i < inamounts.size() - 1; i++) {
            skGen(noises[i]);
            sc_add(sum_in.bytes, noises[i].bytes, sum_in.bytes);
            //aG+bH
            genC(in_C2s[i], noises[i], inamounts[i]);
        }
        sc_sub(noises[i].bytes, sumout.bytes, sum_in.bytes);
        //
        genC(in_C2s[i], noises[i], inamounts[i]);
        DP(in_C2s[i]);

        key full_message = get_pre_mlsag_hash(rv,hwdev);
      
        for (i = 0 ; i < inamounts.size(); i++)
        {
            if (rv.type == RCTTypeCLSAG)
            {
                const ctkey & real_in = inSk[i];
                const std::vector<ctkey> & decoys=rv.mixRing[i];
                const key & in_C2=in_C2s[i];
                const key & noise=noises[i];
                rv.p.CLSAGs[i] = proveRctCLSAGSimple(full_message, decoys, real_in, noise, in_C2, index[i], hwdev);
            }
           
        }
        return rv;
    }

    rctSig genRctSimple(const key &message, const ctkeyV & inSk, const ctkeyV & inPk, const keyV & destinations, const vector<xmr_amount> &inamounts, const vector<xmr_amount> &outamounts, const keyV &amount_keys, xmr_amount txnFee, unsigned int mixin, const RCTConfig &rct_config, hw::device &hwdev) {
        std::vector<unsigned int> index;
        index.resize(inPk.size());
        ctkeyM mixRing;
        ctkeyV outSk;
        mixRing.resize(inPk.size());
        for (size_t i = 0; i < inPk.size(); ++i) {
          mixRing[i].resize(mixin+1);
          index[i] = populateFromBlockchainSimple(mixRing[i], inPk[i], mixin);
        }
        return genRctSimple(message, inSk, destinations, inamounts, outamounts, txnFee, mixRing, amount_keys,  index, outSk, rct_config, hwdev);
    }

   
    //ver RingCT simple
    //assumes only post-rct style inputs (at least for max anonymity)
    bool verRctSemanticsSimple(const std::vector<const rctSig*> & rvv) {
      try
      {
        PERF_TIMER(verRctSemanticsSimple);

        tools::threadpool& tpool = tools::threadpool::getInstance();
        tools::threadpool::waiter waiter(tpool);
        std::deque<bool> results;
        std::vector<const Bulletproof*> proofs;
        size_t max_non_bp_proofs = 0;

        for (const rctSig *rvp: rvv)
        {
          CHECK_AND_ASSERT_MES(rvp, false, "rctSig pointer is NULL");
          const rctSig &rv = *rvp;
          CHECK_AND_ASSERT_MES(rv.type == RCTTypeSimple || rv.type == RCTTypeBulletproof || rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG,
              false, "verRctSemanticsSimple called on non simple rctSig");
          const bool bulletproof = is_rct_bulletproof(rv.type);
          {
            CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_amounts(rv.p.bulletproofs), false, "Mismatched sizes of outPk and bulletproofs");
            if (rv.type == RCTTypeCLSAG)
            {
              CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.p.CLSAGs.size(), false, "Mismatched sizes of rv.p.pseudoOuts and rv.p.CLSAGs");
            }
       
          }
        
          CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.ecdhInfo.size(), false, "Mismatched sizes of outPk and rv.ecdhInfo");

        }

        results.resize(max_non_bp_proofs);
        for (const rctSig *rvp: rvv)
        {
          const rctSig &rv = *rvp;

          const bool bulletproof = true;
          const keyV &pseudoOuts = rv.p.pseudoOuts ;

          rct::keyV masks(rv.outPk.size());
          for (size_t i = 0; i < rv.outPk.size(); i++) {
            masks[i] = rv.outPk[i].mask;
          }
          key sumOutpks = addKeys(masks);
          DP(sumOutpks);
          const key txnFeeKey = scalarmultH(d2h(rv.txnFee));
          addKeys(sumOutpks, txnFeeKey, sumOutpks);

          key sumPseudoOuts = addKeys(pseudoOuts);
          DP(sumPseudoOuts);

          //check pseudoOuts vs Outs..
          if (!equalKeys(sumPseudoOuts, sumOutpks)) {
            MINFO("Sum check failed");
            return false;
          }

          if (bulletproof)
          {
            for (size_t i = 0; i < rv.p.bulletproofs.size(); i++)
              proofs.push_back(&rv.p.bulletproofs[i]);
          }
       
        }
        if (!proofs.empty() && !verBulletproof(proofs))
        {
          MINFO("Aggregate range proof verified failed");
          return false;
        }

        if (!waiter.wait())
          return false;
        for (size_t i = 0; i < results.size(); ++i) {
          if (!results[i]) {
            MINFO("Range proof verified failed for proof " << i);
            return false;
          }
        }

        return true;
      }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (const std::exception &e)
      {
        MINFO("Error in verRctSemanticsSimple: " << e.what());
        return false;
      }
      catch (...)
      {
        MINFO("Error in verRctSemanticsSimple, but not an actual exception");
        return false;
      }
    }

    bool verRctSemanticsSimple(const rctSig & rv)
    {
      return verRctSemanticsSimple(std::vector<const rctSig*>(1, &rv));
    }

    //ver RingCT simple
    //assumes only post-rct style inputs (at least for max anonymity)
    bool verRctNonSemanticsSimple(const rctSig & rv) {
      try
      {
        PERF_TIMER(verRctNonSemanticsSimple);

        CHECK_AND_ASSERT_MES(rv.type == RCTTypeSimple || rv.type == RCTTypeBulletproof || rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG,
            false, "verRctNonSemanticsSimple called on non simple rctSig");
        const bool bulletproof = true;
        // semantics check is early, and mixRing/MGs aren't resolved yet
        if (bulletproof)
          CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.mixRing.size(), false, "Mismatched sizes of rv.p.pseudoOuts and mixRing");

        const size_t threads = std::max(rv.outPk.size(), rv.mixRing.size());

        std::deque<bool> results(threads);
        tools::threadpool& tpool = tools::threadpool::getInstance();
        tools::threadpool::waiter waiter(tpool);

        const keyV &pseudoOuts =  rv.p.pseudoOuts ;

        const key message = get_pre_mlsag_hash(rv, hw::get_device("default"));

        results.clear();
        results.resize(rv.mixRing.size());
        for (size_t i = 0 ; i < rv.mixRing.size() ; i++) {
          tpool.submit(&waiter, [&, i] {
              if (rv.type == RCTTypeCLSAG)
              {
                  results[i] = verRctCLSAGSimple(message, rv.p.CLSAGs[i], rv.mixRing[i], pseudoOuts[i]);
              }
   
          });
        }
        if (!waiter.wait())
          return false;

        for (size_t i = 0; i < results.size(); ++i) {
          if (!results[i]) {
            MINFO("verRctMGSimple/verRctCLSAGSimple failed for input " << i);
            return false;
          }
        }

        return true;
      }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (const std::exception &e)
      {
        MINFO("Error in verRctNonSemanticsSimple: " << e.what());
        return false;
      }
      catch (...)
      {
        MINFO("Error in verRctNonSemanticsSimple, but not an actual exception");
        return false;
      }
    }
 std::tuple<xmr_amount,key> decodeRctSimple(const rctSig & rv, const rct::key & shared_sec, unsigned int i)
 {
       CHECK_AND_ASSERT_THROW_MES(rv.type == RCTTypeSimple || rv.type == RCTTypeBulletproof || rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG, "decodeRct called on non simple rctSig");
        CHECK_AND_ASSERT_THROW_MES(i < rv.ecdhInfo.size(), "Bad index");
        CHECK_AND_ASSERT_THROW_MES(rv.outPk.size() == rv.ecdhInfo.size(), "Mismatched sizes of rv.outPk and rv.ecdhInfo");

     
        //mask amount and mask
        ecdhTuple ecdh_info = rv.ecdhInfo[i];
        const uint64_t amount = rct::ecdhDecode(ecdh_info.amount, shared_sec);

        const auto noise = rct::genCommitmentMask(shared_sec);
        key C = rv.outPk[i].mask;
        DP("C");DP(C);

        key C2;
        CHECK_AND_ASSERT_THROW_MES(sc_check(noise.bytes) == 0, "warning, bad ECDH mask");
        //mask*G+bH
        addKeys2(C2, noise, rct::d2h(amount), H);

        DP("C2");DP(C2);

        if (rct::equalKeys(C, C2) == false) {
            CHECK_AND_ASSERT_THROW_MES(false, "warning, amount decoded incorrectly, will be unable to spend");
        }
        return {amount,noise};

 }
    std::tuple<xmr_amount,key> decodeRctSimple(const rctSig & rv, const crypto::key_derivation & kA, unsigned int i ) { 
        crypto::secret_key ss;
        crypto::derivation_to_scalar(kA,i,ss);
        const rct::key shared_sec = rct::sk2rct(ss);
        return decodeRctSimple(rv,shared_sec,i);
    }


}
