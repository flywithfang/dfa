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


#define TX_EXTRA_PADDING_MAX_COUNT          255
#define TX_EXTRA_NONCE_MAX_COUNT            255

#define TX_EXTRA_TAG_PUBKEY                 0x01
#define TX_EXTRA_NONCE                      0x02

namespace cryptonote
{
 
  struct tx_extra_nonce
  {
    std::string nonce;

   // BEGIN_SERIALIZE()
     template < template <bool> class Archive>     
  bool do_serialize(Archive<true> &ar) {
     // FIELD(nonce)
     do {             
    ar.tag("nonce");      
   bool r = ::do_serialize(ar, nonce);     
  
    if (!r || !ar.stream().good()) return false;  
  } while(0);

      if(TX_EXTRA_NONCE_MAX_COUNT < nonce.size()) return false;
    //END_SERIALIZE()
    return ar.stream().good();     
  }
  template < template <bool> class Archive>     
  bool do_serialize(Archive<false> &ar) {
     // FIELD(nonce)
     do {             
    ar.tag("nonce");      
   bool r =true;// ::do_serialize(ar, nonce);     
   std::string & str = nonce;
     {
        size_t size = 0;

        ar.serialize_varint(size);
      //  std::cout<<"string size "<<str.size()<<"/"<<size<<","<<ar.remaining_bytes()<<std::endl;
        if (ar.remaining_bytes() < size)
        {
          ar.stream().setstate(std::ios::failbit);
          return false;
        }

        std::unique_ptr<std::string::value_type[]> buf(new std::string::value_type[size]);
        ar.serialize_blob(buf.get(), size);
        str.erase();
        str.append(buf.get(), size);

     }
    if (!r || !ar.stream().good()) return false;  
  } while(0);
  
      if(TX_EXTRA_NONCE_MAX_COUNT < nonce.size()) return false;
    //END_SERIALIZE()
    return ar.stream().good();     
  }

  };



  // tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
  //   varint tag;
  //   varint size;
  //   varint data[];
  typedef boost::variant<tx_extra_nonce> tx_extra_field;
}

VARIANT_TAG(binary_archive, cryptonote::tx_extra_nonce, TX_EXTRA_NONCE);

