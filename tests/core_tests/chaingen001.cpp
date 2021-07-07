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

#include <vector>
#include <iostream>

#include "include_base_utils.h"

#include "console_handler.h"

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

#include "chaingen.h"
#include "chaingen_tests_list.h"

using namespace std;

using namespace epee;
using namespace cryptonote;

////////
// class one_block;

one_block::one_block()
{
  REGISTER_CALLBACK("verify_1", one_block::verify_1);
}

bool one_block::generate(std::vector<test_event_entry> &events)
{
    uint64_t ts_start = 1338224400;

    MAKE_GENESIS_BLOCK(events, blk_0, alice, ts_start);
    MAKE_ACCOUNT(events, alice);
    DO_CALLBACK(events, "verify_1");

    return true;
}

bool one_block::verify_1(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
    DEFINE_TESTS_ERROR_CONTEXT("one_block::verify_1");

    alice = boost::get<cryptonote::account_base>(events[1]);

    // check balances
    //std::vector<const cryptonote::block*> chain;
    //map_hash2tx_t mtx;
    //CHECK_TEST_CONDITION(find_block_chain(events, chain, mtx, get_block_hash(boost::get<cryptonote::block>(events[1]))));
    //CHECK_TEST_CONDITION(get_block_reward(0) == get_balance(alice, events, chain, mtx));

    // check height
    std::vector<cryptonote::block> blocks;
    std::list<crypto::public_key> outs;
    bool r = c.get_blocks(0, 100, blocks);
    //c.get_outs(100, outs);
    CHECK_TEST_CONDITION(r);
    CHECK_TEST_CONDITION(blocks.size() == 1);
    //CHECK_TEST_CONDITION(outs.size() == blocks.size());
    CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 1);
    CHECK_TEST_CONDITION(blocks.back() == boost::get<cryptonote::block>(events[0]));

    return true;
}

typedef cryptonote::account_base Account;

////////
// class gen_simple_chain_001;

gen_simple_chain_001::gen_simple_chain_001()
{
 // REGISTER_CALLBACK("verify_callback_1", gen_simple_chain_001::verify_callback_1);

   m_callbacks["verify_callback_1"]= std::bind(&gen_simple_chain_001::verify_callback_1, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    m_callbacks["verify_callback_2"]=std::bind(&gen_simple_chain_001::verify_callback_2, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

 // REGISTER_CALLBACK("verify_callback_2", gen_simple_chain_001::verify_callback_2);
}

transaction make_tx(std::vector<test_event_entry> &events,const cryptonote::block &blk, const Account & from, const var_addr_t & to,uint64_t n,uint64_t nmix=0)
{
      cryptonote::transaction t;                                                           
    construct_tx_to_key(events, t, blk, from, to, n, TESTS_DEFAULT_FEE, nmix); 
    events.push_back(t);    
    return t;
}
cryptonote::block rewind_block(test_generator & generator,std::vector<test_event_entry> &events, cryptonote::block blk_last, cryptonote::account_base & miner)
{
    for (size_t i = 0; i < CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; ++i)                                                
    {                                                                                 
       cryptonote::block blk;                                                         
      generator.construct_block(blk, blk_last, miner, std::list<cryptonote::transaction>(),  boost::none);                     
      events.push_back(blk);
      blk_last = blk;                                                                 
    }                                                                                 
    return blk_last;                                                            
}

bool gen_simple_chain_001::generate(std::vector<test_event_entry> &events)
{
    cryptonote::account_base miner; 
    miner.generate();

    cryptonote::account_base alice; 
    alice.generate();

   cout<<"gen_simple_chain_001::generate"<<endl;
   test_generator generator;          
    ///MAKE_GENESIS_BLOCK(events, blk_0, miner, ts_start);
    auto blk_0=make_genesis_block(generator,events,miner);
    auto blk_1=make_block(generator,events,blk_0,miner);
    auto blk_1_side=make_block(generator,events,blk_0,miner);
    auto blk_2=make_block(generator,events,blk_1,miner);
    
    //MAKE_NEXT_BLOCK(events, blk_1, blk_0, miner);
    //MAKE_NEXT_BLOCK(events, blk_1_side, blk_0, miner);
   // MAKE_NEXT_BLOCK(events, blk_2, blk_1, miner);

   // MAKE_TX(events, tx_0, first_miner_account, alice, 151, blk_2);

    crypto::hash head_hash = get_block_hash(boost::get<cryptonote::block>(events[3]));
    cout<<"blk hash "<<head_hash;
    /*bool r = */
    auto [r, chain, mtx] = events_to_block_chain(events,  head_hash);
    std::cout << "BALANCE = " << get_balance(miner, chain, mtx) << std::endl;
#if 1
   // REWIND_BLOCKS(events, blk_2r, blk_2, miner);
      cryptonote::block blk_2r= rewind_block(generator, events,blk_2,miner) ;                                                     
   // MAKE_TX_LIST_START(events, txlist_0, miner, alice, MK_COINS(1), blk_2);
    std::list<cryptonote::transaction> txlist_0; 
    {
        auto t1 = make_tx(events,blk_2,miner,alice,mk_coins(1));                                                                                                            
        txlist_0.push_back(t1);
       auto t2=make_tx(events,blk_2,miner,alice,mk_coins(2));    
        txlist_0.push_back(t2);                                                                                                            
        auto t3=make_tx(events,blk_2,miner,alice,mk_coins(4));                                                    
        txlist_0.push_back(t3);    
  }
   
    auto blk_3= make_block(generator,events,blk_2r,miner,txlist_0);
    auto blk_3r=rewind_block(generator,events,blk_3,miner);
    //MAKE_TX(events, tx_1, miner, alice, MK_COINS(50), blk_3);
    auto tx_1=make_tx(events,blk_3,miner,alice,mk_coins(50));
   // MAKE_NEXT_BLOCK_TX1(events, blk_4, blk_3r, miner, tx_1);

  auto blk_4 = make_block(generator, events,blk_3r,miner,{tx_1});
   // REWIND_BLOCKS(events, blk_4r, blk_4, miner);
    auto blk_4r=rewind_block(generator,events,blk_4,miner);
    //MAKE_TX(events, tx_2, miner, alice, MK_COINS(50), blk_4);
    auto tx_2=make_tx(events,blk_4,miner,alice,mk_coins(50));
    //MAKE_NEXT_BLOCK_TX1(events, blk_5, blk_4r, miner, tx_2);
    auto blk_5=make_block(generator,events,blk_4r,miner,{tx_2});
  //  REWIND_BLOCKS(events, blk_5r, blk_5, miner);
    auto blk_5r=rewind_block(generator,events,blk_5,miner);
  //  MAKE_TX(events, tx_3, miner, alice, MK_COINS(50), blk_5);
    auto tx_3=make_tx(events,blk_5,miner,alice,mk_coins(50));
    //MAKE_NEXT_BLOCK_TX1(events, blk_6, blk_5r, miner, tx_3);
    auto blk_6=make_block(generator,events,blk_5r,miner,{tx_3});

    //DO_CALLBACK(events, "verify_callback_1");
      callback_entry CALLBACK_ENTRY; 
      CALLBACK_ENTRY.callback_name = "verify_callback_1"; 
      events.push_back(CALLBACK_ENTRY); 
#endif
    //e.t.c.
    //MAKE_BLOCK_TX1(events, blk_3, 3, get_block_hash(blk_0), get_test_target(), first_miner_account, ts_start + 10, tx_0);
    //MAKE_BLOCK_TX1(events, blk_3, 3, get_block_hash(blk_0), get_test_target(), first_miner_account, ts_start + 10, tx_0);
    //DO_CALLBACK(events, "verify_callback_2");

/*    std::vector<const cryptonote::block*> chain;
    map_hash2tx_t mtx;
    if (!find_block_chain(events, chain, mtx, get_block_hash(blk_6)))
        throw;
    cout << "miner = " << get_balance(first_miner_account, events, chain, mtx) << endl;
    cout << "alice = " << get_balance(alice, events, chain, mtx) << endl;*/

    return true;
}

bool gen_simple_chain_001::verify_callback_1(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
    std::cout<<"gen_simple_chain_001 verify_callback_1"<<std::endl;
  return true;
}

bool gen_simple_chain_001::verify_callback_2(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  return true;
}
