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
#include "cryptonote_basic/cryptonote_format_utils.h"
#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>
#include "ringct/rctOps.h"
#include <tuple>
namespace cryptonote
{

  std::tuple<bool, transaction> construct_miner_tx(size_t height, uint64_t fee, const account_public_address &miner_address,  const varbinary& extra_nonce = varbinary(),  uint8_t hard_fork_version = 1);
  
  struct AltChain;

  struct tx_source_entry
  {
      struct  OutAsIn{
    uint64_t global_oi;
    rct::key otk;
    rct::key commitment;
  };

    std::vector<OutAsIn> decoys;  //index + key + optional ringct commitment
    uint64_t real_output;               //index in outputs vector of real output_entry
    crypto::public_key real_out_tx_key; //incoming real tx public key
    uint64_t real_output_in_tx_index;   //index in transaction outputs vector
    uint64_t amount;                    //money
    rct::key noise;                      //ringct amount mask
    rct::key otk_sec;
    crypto::key_image ki;

  };

  struct tx_destination_entry
  {
    uint64_t amount;                    //money
    account_public_address addr;        //destination address

    tx_destination_entry() : amount(0), addr(AUTO_VAL_INIT(addr)) { }
    tx_destination_entry(uint64_t a, const account_public_address &ad) : amount(a), addr(ad) { }

    std::string address(network_type nettype) const
    {
      return get_account_address_as_str(nettype,  addr);
    }

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(addr)
    END_SERIALIZE()
  };

  bool construct_tx(const account_keys& sender_account_keys, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations,  const blobdata &extra, transaction& tx, uint64_t unlock_time, crypto::secret_key &tx_sec);

  block make_genesis_block( std::string const & genesis_tx, uint32_t nonce);

 
 bool  verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) ;
}

