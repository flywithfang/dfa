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




#include "device_default.hpp"
#include "int-util.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "ringct/rctOps.h"
#include "cryptonote_config.h"

namespace hw {

    namespace core {

        device_default::device_default() { }

        device_default::~device_default() { }

        /* ===================================================================== */
        /* ===                        Misc                                ==== */
        /* ===================================================================== */
        static inline unsigned char *operator &(crypto::ec_scalar &scalar) {
            return &reinterpret_cast<unsigned char &>(scalar);
        }
        static inline const unsigned char *operator &(const crypto::ec_scalar &scalar) {
            return &reinterpret_cast<const unsigned char &>(scalar);
        }

        /* ======================================================================= */
        /*                              SETUP/TEARDOWN                             */
        /* ======================================================================= */
        bool device_default::set_name(const std::string &name)  {
            this->name = name;
            return true;
        }
        const std::string device_default::get_name()  const {
            return this->name;
        }
        
        bool device_default::init(void) {
            return true;
        }
        bool device_default::release() {
            return true;
        }

        bool device_default::connect(void) {
            return true;
        }
        bool device_default::disconnect() {
            return true;
        }

        bool  device_default::set_mode(device_mode mode) {
            return device::set_mode(mode);
        }

        /* ======================================================================= */
        /*  LOCKER                                                                 */
        /* ======================================================================= */ 
    
        void device_default::lock() { }

        bool device_default::try_lock() { return true; }

        void device_default::unlock() { }

        /* ======================================================================= */
        /*                             WALLET & ADDRESS                            */
        /* ======================================================================= */

        bool  device_default::generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key, uint64_t kdf_rounds) {
            const crypto::secret_key &view_key = keys.m_view_secret_key;
            const crypto::secret_key &spend_key = keys.m_spend_secret_key;
            epee::mlocked<tools::scrubbed_arr<char, sizeof(view_key) + sizeof(spend_key) + 1>> data;
            memcpy(data.data(), &view_key, sizeof(view_key));
            memcpy(data.data() + sizeof(view_key), &spend_key, sizeof(spend_key));
            data[sizeof(data) - 1] = config::HASH_KEY_WALLET;
            crypto::generate_chacha_key(data.data(), sizeof(data), key, kdf_rounds);
            return true;
        }
        bool  device_default::get_public_address(cryptonote::account_public_address &pubkey) {
             dfns();
        }
        bool  device_default::get_secret_keys(crypto::secret_key &viewkey , crypto::secret_key &spendkey)  {
             dfns();
        }
        /* ======================================================================= */
        /*                               SUB ADDRESS                               */
        /* ======================================================================= */

        bool device_default::derive_subaddress_public_key(const crypto::public_key &otk, const crypto::key_derivation &derivation, const std::size_t output_index, crypto::public_key &derived_key) {
            return crypto::derive_subaddress_public_key(otk, derivation, output_index,derived_key);
        }


        /* ======================================================================= */
        /*                            DERIVATION & KEY                             */
        /* ======================================================================= */

        bool  device_default::verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) {
            crypto::public_key calculated_pub;
            bool r = crypto::secret_key_to_public_key(secret_key, calculated_pub);
            return r && public_key == calculated_pub;
        }

        bool device_default::scalarmultKey(rct::key & aP, const rct::key &P, const rct::key &a) {
            rct::scalarmultKey(aP, P,a);
            return true;
        }

        bool device_default::scalarmultBase(rct::key &aG, const rct::key &a) {
            rct::scalarmultBase(aG,a);
            return true;
        }

        bool device_default::sc_secret_add(crypto::secret_key &r, const crypto::secret_key &a, const crypto::secret_key &b) {
            sc_add(&r, &a, &b);
            return true;
        }

        crypto::secret_key  device_default::generate_keys(crypto::public_key &pub, crypto::secret_key &sec, const crypto::secret_key& recovery_key, bool recover) {
            return crypto::generate_keys(pub, sec, recovery_key, recover);
        }

        bool device_default::generate_key_derivation(const crypto::public_key &key1, const crypto::secret_key &key2, crypto::key_derivation &derivation) {
            return crypto::generate_key_derivation(key1, key2, derivation);
        }

        bool device_default::derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res){
            crypto::derivation_to_scalar(derivation,output_index, res);
            return true;
        }

        bool device_default::derive_secret_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &base, crypto::secret_key &derived_key){
            crypto::derive_secret_key(derivation, output_index, base, derived_key);
            return true;
        }

        bool device_default::derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &base, crypto::public_key &derived_key){
            return crypto::derive_public_key(derivation, output_index, base, derived_key);
        }

        bool device_default::secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub) {
            return crypto::secret_key_to_public_key(sec,pub);
        }

        bool device_default::generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image){
            crypto::generate_key_image(pub, sec,image);
            return true;
        }

        bool device_default::conceal_derivation(crypto::key_derivation &derivation, const crypto::public_key &tx_pub_key,  const crypto::key_derivation &main_derivation){
            return true;
        }

        /* ======================================================================= */
        /*                               TRANSACTION                               */
        /* ======================================================================= */
        void device_default::generate_tx_proof(const crypto::hash &prefix_hash, 
                                               const crypto::public_key &R, const crypto::public_key &A, const boost::optional<crypto::public_key> &B, const crypto::public_key &D, const crypto::secret_key &r, 
                                               crypto::signature &sig) {
            crypto::generate_tx_proof(prefix_hash, R, A, B, D, r, sig);
        }

        bool device_default::open_tx(crypto::secret_key &tx_key) {
            cryptonote::keypair txkey = cryptonote::keypair::generate(*this);
            tx_key = txkey.sec;
            return true;
        }

        void device_default::get_transaction_prefix_hash(const cryptonote::transaction_prefix& tx, crypto::hash& h) {
            cryptonote::get_transaction_prefix_hash(tx, h);
        }



        bool device_default::mlsag_prepare(const rct::key &H, const rct::key &xx,
                                         rct::key &a, rct::key &aG, rct::key &aHP, rct::key &II) {
            rct::skpkGen(a, aG);
            rct::scalarmultKey(aHP, H, a);
            rct::scalarmultKey(II, H, xx);
            return true;
        }
        bool  device_default::mlsag_prepare(rct::key &a, rct::key &aG) {
            rct::skpkGen(a, aG);
            return true;
        }
        bool  device_default::mlsag_prehash(const std::string &blob, size_t inputs_size, size_t outputs_size, const rct::keyV &hashes, const rct::ctkeyV &outPk, rct::key &prehash) {
            prehash = rct::cn_fast_hash(hashes);
            return true;
        }


        bool device_default::mlsag_hash(const rct::keyV &toHash, rct::key &c_old) {
            c_old = rct::hash_to_scalar(toHash);
            return true;
        }

        bool device_default::mlsag_sign(const rct::key &c,  const rct::keyV &xx, const rct::keyV &alpha, const size_t rows, const size_t dsRows, rct::keyV &ss ) {
            CHECK_AND_ASSERT_THROW_MES(dsRows<=rows, "dsRows greater than rows");
            CHECK_AND_ASSERT_THROW_MES(xx.size() == rows, "xx size does not match rows");
            CHECK_AND_ASSERT_THROW_MES(alpha.size() == rows, "alpha size does not match rows");
            CHECK_AND_ASSERT_THROW_MES(ss.size() == rows, "ss size does not match rows");
            for (size_t j = 0; j < rows; j++) {
                sc_mulsub(ss[j].bytes, c.bytes, xx[j].bytes, alpha[j].bytes);
            }
            return true;
        }

        bool device_default::clsag_prepare(const rct::key &p, const rct::key &z, rct::key &I, rct::key &D, const rct::key &H, rct::key &a, rct::key &aG, rct::key &aH) {
            rct::skpkGen(a,aG); // aG = a*G
            rct::scalarmultKey(aH,H,a); // aH = a*H
            rct::scalarmultKey(I,H,p); // I = p*H
            rct::scalarmultKey(D,H,z); // D = z*H
            return true;
        }

        bool device_default::clsag_hash(const rct::keyV &data, rct::key &hash) {
            hash = rct::hash_to_scalar(data);
            return true;
        }

        bool device_default::clsag_sign(const rct::key &c, const rct::key &a, const rct::key &p, const rct::key &z, const rct::key &mu_P, const rct::key &mu_C, rct::key &s) {
            rct::key s0_p_mu_P;
            sc_mul(s0_p_mu_P.bytes,mu_P.bytes,p.bytes);
            rct::key s0_add_z_mu_C;
            sc_muladd(s0_add_z_mu_C.bytes,mu_C.bytes,z.bytes,s0_p_mu_P.bytes);
            sc_mulsub(s.bytes,c.bytes,s0_add_z_mu_C.bytes,a.bytes);

            return true;
        }

        bool device_default::close_tx() {
            return true;
        }


        /* ---------------------------------------------------------- */
        static device_default *default_core_device = NULL;
        void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
            if (!default_core_device) {
                default_core_device = new device_default();
                default_core_device->set_name("default_core_device");

            }
            registry.insert(std::make_pair("default", std::unique_ptr<device>(default_core_device)));
        }


    }

}
