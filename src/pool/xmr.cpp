/*
Copyright (c) 2018, The Monero Project

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_basic/difficulty.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "crypto/rx-hash.h"
#include "cryptonote_config.h"
#include "serialization/binary_utils.h"
#include "ringct/rctSigs.h"
#include "common/base58.h"
#include "common/util.h"
#include "string_tools.h"

#include "xmr.h"

using namespace epee::string_tools;
using namespace cryptonote;
using namespace crypto;
using namespace config;

static int nettype_from_prefix(uint8_t *nettype, uint64_t prefix)
{
    static const struct { cryptonote::network_type type; uint64_t prefix; } nettype_prefix[] = {
        { MAINNET, CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX },
        { TESTNET, testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX },
        { STAGENET, stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX },
    };
    int rv = XMR_MISMATCH_ERROR;
    for (auto ntp : nettype_prefix)
    {
        if (ntp.prefix == prefix)
        {
            rv = XMR_NO_ERROR;
            *nettype = ntp.type;
            break;
        }
    }
    return rv;
}

int get_hashing_blob(const unsigned char *input, const size_t in_size,unsigned char **output, size_t *out_size)
{
  
    blobdata bd = std::string((const char*)input, in_size);
    const auto b = parse_block_from_blob(bd);

    blobdata blob = get_block_hashing_blob(b);
    *out_size = blob.length();
    *output = (unsigned char*) malloc(*out_size);
    memcpy(*output, blob.data(), *out_size);
    return XMR_NO_ERROR;
}

int parse_address(const char *input, uint64_t *prefix,uint8_t *nettype, unsigned char *pub_spend)
{
    uint64_t tag;
    std::string decoded;
    if (!tools::base58::decode_addr(input, tag, decoded))
        return XMR_PARSE_ERROR;
    if (prefix)
        *prefix = tag;
    if (nettype && nettype_from_prefix(nettype, tag))
        return XMR_MISMATCH_ERROR;
    if (pub_spend)
    {
        account_public_address address;
        if (!::serialization::parse_binary(decoded, address))
            return XMR_PARSE_ERROR;
        public_key S = address.m_spend_public_key;
        memcpy(pub_spend, &S, 32);
    }
    return XMR_NO_ERROR;
}

crypto::hash get_block_hash(const unsigned char *input, const size_t in_size)
{
    blobdata bd = std::string((const char*)input, in_size);
    auto b = parse_block_from_blob(bd);
    std::cout<<"parse block"<<std::endl;
    const auto h=get_block_hash(b);
    std::cout<<"get_block_hash"<<h<<std::endl;
    return  h;
}


void get_rx_hash(const unsigned char *input, const size_t in_size,unsigned char *output, const unsigned char *seed_hash,const uint64_t height)
{
    static unsigned miners = tools::get_max_concurrency();
    uint64_t seed_height = rx_seedheight(height);
    const auto pow = rx_slow_hash(height, seed_height, (const char*)seed_hash,(const char*)input, in_size,  miners, 0);
    memcpy(output,pow.data,sizeof(pow));
}

int validate_block_from_blob(const char *blob_hex,const unsigned char *sec_view,const unsigned char *pub_spend)
{
    /*
      The only validation needed is that the data parses to a block and the
      miner tx only pays out to the pool.
    */
    blobdata bd;
    const secret_key &a = *reinterpret_cast<const secret_key*>(sec_view);
    const public_key &B = *reinterpret_cast<const public_key*>(pub_spend);

    if (!parse_hexstr_to_binbuff(blob_hex, bd))
        return XMR_PARSE_ERROR;

    const auto b= parse_block_from_blob(bd);

    transaction tx = b.miner_tx;

    /*
      Ensure we have only one in, one out and in is gen.
    */
    if (tx.vin.size() != 1)
        return XMR_VIN_COUNT_ERROR;

    if (tx.vout.size() != 1)
        return XMR_VOUT_COUNT_ERROR;

    if (tx.vin[0].type() != typeid(txin_gen))
        return XMR_VIN_TYPE_ERROR;

    /*
      Ensure that the miner tx single output key is destined for the pool
      wallet.

      Don't bother checking any additional pub keys in tx extra. The daemon
      created miner tx only has one public key in extra. If we can't derive
      from the first (which should be only) found, reject.
    */
    const public_key R = tx.tx_pub_key;
    public_key otk = boost::get<txout_to_key>(tx.vout[0].target).key;
    key_derivation derivation;
    generate_key_derivation(R, a, derivation);
    public_key B2;
    derive_subaddress_public_key(otk, derivation, 0, B2);
    if (B != B2)
        return XMR_MISMATCH_ERROR;

    return XMR_NO_ERROR;
}

