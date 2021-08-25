#include <algorithm>
#include <cstdio>
#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/format.hpp>

#include "include_base_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "tx_pool.h"
#include "blockchain.h"
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/miner.h"
#include "hardforks/hardforks.h"
#include "misc_language.h"
#include "profile_tools.h"
#include "file_io_utils.h"
#include "int-util.h"
#include "common/threadpool.h"
#include "common/boost_serialization_helper.h"
#include "warnings.h"
#include "crypto/hash.h"
#include "cryptonote_core.h"
#include "ringct/rctSigs.h"
#include "common/perf_timer.h"
#include "common/notify.h"
#include "common/varint.h"
#include "common/pruning.h"
#include "time_helper.h"
#include "string_tools.h"
#include "crypto/rx-hash.h"
namespace cryptonote{

  AltChain::AltChain(BlockchainDB&db,const crypto::hash &prev_id):m_db(db){
      //build alternative subchain, front -> mainchain, back -> alternative head
    cryptonote::alt_block_data_t alt_block;
    cryptonote::blobdata blob;
    bool found = m_db.get_alt_block(prev_id, &alt_block, &blob);
    while(found)
    {
      block_extended_info bei;
      bei.bl = cryptonote::parse_block_from_blob(blob);
      bei.height = alt_block.height;
      bei.block_cumulative_weight = alt_block.cumulative_weight;
      bei.cum_diff = alt_block.cumulative_difficulty_high;
      bei.cum_diff = (bei.cum_diff << 64) + alt_block.cumulative_difficulty_low;
      bei.already_generated_coins = alt_block.already_generated_coins;
      alt_chain.push_front(std::move(bei));//push_front
      found = m_db.get_alt_block(bei.bl.prev_id, &alt_block, &blob);
    }

    // if block to be added connects to known blocks that aren't part of the
    // main chain -- that is, if we're adding on to an alternate chain
    if(!alt_chain.empty())
    {
      const auto alt_root = alt_chain.front();
      // make sure alt chain doesn't somehow start past the end of the main chain
      const auto alt_root_height =alt_root.height;
      const auto main_block_heigth = m_db->height()-1;
      if(main_block_heigth < alt_root_height)
        throw_and_log("main blockchain wrong height"<<main_block_heigth);

      // make sure that the blockchain contains the block that should connect
      // this alternate chain with it.
      if (!m_db.block_exists(alt_root.bl.prev_id))
      {
        throw_and_log("alternate chain does not appear to connect to main chain..."<<alt_root.bl.prev_id);
      }

      // make sure block connects correctly to the main chain
      const split_pos = alt_root.height - 1;
      auto split_hash = m_db.get_block_hash_from_height(split_pos);
      if(split_hash != alt_root.bl.prev_id)
        throw_and_log("alternative chain has wrong connection to main chain");
    }
    // if block not associated with known alternate chain
    else
    {
      // if block parent is not part of main chain or an alternate chain,
      // we ignore it
      bool parent_in_main = m_db->block_exists(prev_id);
      if(!parent_in_main)
        throw_and_log("internal error: broken imperative condition: parent_in_main");

    }
  }


 crypto::hash AltChain::get_block_hash_by_height(uint64_t block_height) const
 {

    if(block_height<=split_b_height)
      return m_db.get_block_hash_from_height(height);

    const auto chain_height= height();
    if(block_height>=chain_height)
      throw_and_log("bad alt block height "<<block_height<<"/"<<chain_height);
    const auto index = block_height - split_b_height-1;
    block_extended_info & alt = alt_chain[index];
    return get_block_hash(alt.b);

 }
  uint64_t AltChain::get_block_timestamp(const uint64_t& block_height) const{
       if(block_height<=split_b_height)
      return m_db.get_block_timestamp(height);

    const auto chain_height= height();
    if(block_height>=chain_height)
      throw_and_log("bad alt block height "<<block_height<<"/"<<chain_height);

    const auto index = block_height - split_b_height-1;
    block_extended_info & alt = alt_chain[index];
    return alt.b.timestamp;
  }
    difficulty_type AltChain::get_block_cumulative_difficulty(uint64_t height) const
    {
       if(block_height<=split_b_height)
        return m_db.get_block_cumulative_difficulty(height);

      const auto chain_height= height();
      if(block_height>=chain_height)
        throw_and_log("bad alt block height "<<block_height<<"/"<<chain_height);

      const auto index = block_height - split_b_height-1;
      block_extended_info & alt = alt_chain[index];
      return alt.cum_diff;
    }
    uint64_t AltChain::get_block_already_generated_coins( uint64_t height) const
    {
       if(block_height<=split_b_height)
        return m_db.get_block_already_generated_coins(height);

      const auto chain_height= height();
      if(block_height>=chain_height)
        throw_and_log("bad alt block height "<<block_height<<"/"<<chain_height);

      const auto index = block_height - split_b_height-1;
      block_extended_info & alt = alt_chain[index];
      return alt.already_generated_coins;

    }
      std::tuple<crypto::hash,uint64_t> AltChain::get_top_block_hash()const
      {
         if(block_height<=split_b_height)
          return m_db->get_top_block_hash(height);

        const auto chain_height= height();
        if(block_height>=chain_height)
          throw_and_log("bad alt block height "<<block_height<<"/"<<chain_height);

        const auto index = block_height - split_b_height-1;
        block_extended_info & alt = alt_chain[index];

        auto hash =  get_block_hash(atl.b);
        return {hash,alt.height};

      }


}


