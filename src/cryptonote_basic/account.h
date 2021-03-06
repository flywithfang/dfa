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

#include "cryptonote_basic.h"
#include "crypto/crypto.h"
#include "serialization/keyvalue_serialization.h"

namespace cryptonote
{

  struct account_keys
  {
    account_public_address m_account_address;
    crypto::secret_key   m_spend_secret_key;
    crypto::secret_key   m_view_secret_key;
    crypto::chacha_iv m_encryption_iv;

    BEGIN_KV_SERIALIZE_MAP()  
      KV_SERIALIZE(m_account_address)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_spend_secret_key)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_view_secret_key)
      const crypto::chacha_iv default_iv{{0, 0, 0, 0, 0, 0, 0, 0}};
      KV_SERIALIZE_VAL_POD_AS_BLOB_OPT(m_encryption_iv, default_iv)
    END_KV_SERIALIZE_MAP()

    account_keys& operator=(account_keys const&) = default;

    void encrypt(const crypto::chacha_key &key);
    void decrypt(const crypto::chacha_key &key);
    void encrypt_viewkey(const crypto::chacha_key &key);
    void decrypt_viewkey(const crypto::chacha_key &key);

  private:
    void xor_with_key_stream(const crypto::chacha_key &key);
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class account_base
  {
  public:
    account_base();
    crypto::secret_key generate(const crypto::secret_key& recovery_key = crypto::secret_key(), bool recover = false);
    const account_keys& get_keys() const;
    std::string get_public_address_str(network_type nettype) const;

    void deinit();

    uint64_t get_createtime() const { return m_creation_timestamp; }
    void set_createtime(uint64_t val) { m_creation_timestamp = val; }

    bool load(const std::string& file_path);
    bool store(const std::string& file_path);

    void forget_spend_key();

    void encrypt_keys(const crypto::chacha_key &key) { m_keys.encrypt(key); }
    void decrypt_keys(const crypto::chacha_key &key) { m_keys.decrypt(key); }
    void encrypt_viewkey(const crypto::chacha_key &key) { m_keys.encrypt_viewkey(key); }
    void decrypt_viewkey(const crypto::chacha_key &key) { m_keys.decrypt_viewkey(key); }

    const account_public_address& get_address()const{
      return m_keys.m_account_address;
    }
    const crypto::public_key& get_view_public_key()const { return m_keys.m_account_address.m_view_public_key;}
    const crypto::public_key& get_spend_public_key()const { return m_keys.m_account_address.m_spend_public_key;}

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int /*ver*/)
    {
      a & m_keys;
      a & m_creation_timestamp;
    }

//    BEGIN_KV_SERIALIZE_MAP()

public: 
  template<class t_storage> 
  bool store( t_storage& st, typename t_storage::hsection hparent_section = nullptr) const
  {
    using type = typename std::remove_const<typename std::remove_reference<decltype(*this)>::type>::type; 
    auto &self = const_cast<type&>(*this); 
    return self.template serialize_map<true>(st, hparent_section); 
  }
  template<class t_storage> 
  bool _load( t_storage& stg, typename t_storage::hsection hparent_section = nullptr)
  {
    return serialize_map<false>(stg, hparent_section);
  }
  template<class t_storage> 
  bool load( t_storage& stg, typename t_storage::hsection hparent_section = nullptr)
  {
    try{
    return serialize_map<false>(stg, hparent_section);
    }
    catch(const std::exception& err) 
    { 
      (void)(err); 
      LOG_ERROR("Exception on unserializing: " << err.what());
      return false; 
    }
  }
  /*template<typename T> T& this_type_resolver() { return *this; }*/ 
  /*using this_type = std::result_of<decltype(this_type_resolver)>::type;*/ 
  template<bool is_store, class t_storage> 
  bool serialize_map(t_storage& stg, typename t_storage::hsection hparent_section) 
  { 
    decltype(*this) &this_ref = *this; 
    (void) this_ref; // Suppress unused var warnings. Sometimes this var is used, sometimes not.

      epee::serialization::selector<is_store>::serialize(this_ref.m_keys, stg, hparent_section, "m_keys");
    //  KV_SERIALIZE(m_creation_timestamp)
      epee::serialization::selector<is_store>::serialize(this_ref.m_creation_timestamp, stg, hparent_section, "m_creation_timestamp");
    
    return true;
}

  private:
    void set_null();
    account_keys m_keys;
    uint64_t m_creation_timestamp;
  };
}
