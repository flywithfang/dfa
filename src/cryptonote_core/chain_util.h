
#include "cryptonote_basic/difficulty.h"

namespace cryptonote{

template<class Blockchain>
   crypto::hash get_block_pow(const Blockchain &bc, const block& b, const uint64_t chain_height)
  {
  
    blobdata bd = get_block_hashing_blob(b);
    
    crypto::hash K{};
    {
      const auto K_heigth = rx_seedheight(chain_height);
      K = bc.get_block_hash_by_height(K_heigth);
    } 
    auto pow = rx_slow_hash(K, bd.data(), bd.size());
    return pow;
  }


template<class Blockchain>
  bool check_block_timestamp(const blockChain & chain,const block& b) const {

  const auto max_time =  (uint64_t)time(NULL) + BLOCK_MINE_TIME_LIMIT;
  if(b.timestamp > max_time)
  {
    MERROR_VER("Timestamp of block with bh: " << get_block_hash(b) << ", " << b.timestamp << ", bigger than local time + 2 hours");
    return false;
  }

  const auto h = cryptonote::get_block_height(b);
  if(h<1)
    throw_and_log("bad block height"<<h);

  auto prev_time = chain.get_block_timestamp(h-1);
  
  const auto min_time = prev_time - BLOCK_MINE_TIME_LIMIT;
  if( b.timestamp<min_time)
  {  MERROR("Timestamp of block less 10 minutes " << get_block_hash(b) << ", " << b.timestamp << " ");
    return false;
  }
}
template<class Blockchain>
difficulty_type get_blockchain_diff(const blockChain & chain)
{
 	 MTRACE("Blockchain::" << __func__);

    const auto [ _,cur_height]= chain.get_top_block_hash(); // get it again now that we have the lock
    const uint64_t  height= cur_height+1;

    const auto  W = DIFFICULTY_WINDOW;

    const int64_t end_h = height-W-height%W;
    const int64_t start_h=end_h-W;
    if(start_h<0)
      return 1;

    std::vector<uint64_t> tss;
    std::vector<difficulty_type> difficulties;
   
    for (auto h = start_h;h<end_h;++h)
    {
      tss.push_back(chain.get_block_timestamp(h));
      difficulties.push_back(chain.get_block_cumulative_difficulty(h));
    }

  const difficulty_type diff = next_difficulty(tss, difficulties, DIFFICULTY_TARGET);

  return diff;
}

bool prevalidate_miner_transaction(const block& b, uint64_t height)
{
  MTRACE("Blockchain::" << __func__);
  CHECK_AND_ASSERT_MES(b.miner_tx.vin.size() == 1, false, "coinbase transaction in the block has no inputs");
  CHECK_AND_ASSERT_MES(b.miner_tx.vin[0].type() == typeid(txin_gen), false, "coinbase transaction in the block has the wrong type");

  // for v2 txes (ringct), we only accept empty rct signatures for miner transactions,
  {
    CHECK_AND_ASSERT_MES(b.miner_tx.rct_signatures.type == rct::RCTTypeNull, false, "RingCT signatures not allowed in coinbase transactions");
  }

  if(boost::get<txin_gen>(b.miner_tx.vin[0]).height != height)
  {
    MWARNING("The miner transaction in block has invalid height: " << boost::get<txin_gen>(b.miner_tx.vin[0]).height << ", expected: " << height);
    return false;
  }
  MDEBUG("Miner tx hash: " << get_transaction_hash(b.miner_tx));
  CHECK_AND_ASSERT_MES(b.miner_tx.unlock_time == height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, false, "coinbase transaction transaction has the wrong unlock time=" << b.miner_tx.unlock_time << ", expected " << height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);

  //check outs overflow
  //NOTE: not entirely sure this is necessary, given that this function is
  //      designed simply to make sure the total amount for a transaction
  //      does not overflow a uint64_t, and this transaction *is* a uint64_t...
  if(!check_outs_overflow(b.miner_tx))
  {
    MERROR("miner transaction has money overflow in block " << get_block_hash(b));
    return false;
  }

  return true;
}


bool validate_miner_transaction(const block& b,  uint64_t fee,  uint8_t version)
{
  MTRACE("Blockchain::" << __func__);
  //validate reward
  uint64_t money_in_use = 0;
  for (auto& o: b.miner_tx.vout)
    money_in_use += o.amount;
  const auto base_reward=get_block_reward();
    if(base_reward + fee != money_in_use)
    {
      MDEBUG("coinbase transaction doesn't use full amount of block reward:  spent: " << money_in_use << ",  block reward " << base_reward + fee << "(" << base_reward << "+" << fee << ")");
      return false;
    }
 
  return true;
}

template<class Blockchain>
block_verification_context validate_new_block(const Blockchain & chain, const tx_memory_pool & pool, const block &bl){
  block_verification_context bvc{};

  db_rtxn_guard rtxn_guard(m_db);
  const auto bh = get_block_hash(bl);
  const auto chain_height= chain.get_chain_height();

  if(chain_height>0){
      const auto [top_hash,top_height] chain.get_top_block_hash();
      if(bl.prev_id != top_hash)
      {
        MERROR_VER("Block has wrong prev_id: " << bl.prev_id << std::endl << "expected: " << top_hash);
        bvc.m_verifivation_failed = true;

        return bvc;
      }
  }

  // make sure block timestamp is not less than the median timestamp
  // of a set number of the most recent blocks.
  if(!check_block_timestamp(chain,bl))
  {
    MERROR_VER("Block with bh: " << bh << std::endl << "has invalid timestamp: " << bl.timestamp);
    bvc.m_verifivation_failed = true;
    return bvc;
  }

    const auto new_b_height=chain_height;

  // get the target difficulty for the block.
  // the calculation can overflow, among other failure cases,
  // so we need to check the return type.
  // FIXME: get_blockchain_diff can also assert, look into
  // changing this to throwing exceptions instead so we can clean up.
  const auto block_diff = get_blockchain_diff(chain);

  const auto pow = get_block_pow(chain, bl, new_b_height);
  if(!check_hash(pow, block_diff))
  {
    MERROR_VER("Block with bh: " << bh << std::endl << "does not have enough proof of work: " << pow << " at height " << new_b_height << ", unexpected difficulty: " << block_diff);
    bvc.m_verifivation_failed = true;
    bvc.m_bad_pow = true;
    return bvc;
  }

  // sanity check basic miner tx properties;
  if(!prevalidate_miner_transaction(bl, new_b_height))
  {
    MERROR_VER("Block with bh: " << bh << " failed to pass prevalidation");
    bvc.m_verifivation_failed = true;
    return bvc;
  }
  uint64_t fee=0;
 for (const auto& tx_hash : bl.tx_hashes)
  {
    transaction tx_tmp;
    blobdata txblob;
  // XXX old code does not check whether tx exists
    if (m_db->tx_exists(tx_hash))
    {
      MERROR("Block with bh: " << bh << " attempting to add transaction already in blockchain with bh: " << tx_hash);
      bvc.m_verifivation_failed = true;
      return bvc;
    }

    // get transaction with hash <tx_hash> from tx_pool
    if(!pool.have_tx(tx_hash, relay_category::all))
    {
      MERROR_VER("Block with bh: " << bh  << " has at least one unknown transaction with bh: " << tx_hash);
      bvc.m_verifivation_failed = true;
      return bvc;
    }

    fee += tx.fee();
  }

  if(!validate_miner_transaction(bl,  fee, m_hardfork->get_current_version()))
  {
    MERROR_VER("Block with bh: " << bh << " has incorrect miner transaction");
    bvc.m_verifivation_failed = true;
    return bvc;
  }
  return bvc;
}


block_verification_context Blockchain::validate_sync_block(const BlobBlock& bb, std::vector<BlobTx> &tx_ps){

  block_verification_context bvc{};

  db_rtxn_guard rtxn_guard(m_db);

  const auto chain_height= m_db.height();
  const auto top_hash = chain_height==0 ? null_hash : get_top_hash();
  const auto new_b_height=chain_height;
  const auto & bl = bb.b;
  if(bl.prev_id != top_hash)
  {
    MERROR_VER("Block with id: " << id << std::endl << "has wrong prev_id: " << bl.prev_id << std::endl << "expected: " << top_hash);
    bvc.m_verifivation_failed = true;

    return bvc;
  }

  // make sure block timestamp is not less than the median timestamp
  // of a set number of the most recent blocks.
  if(!check_block_timestamp(*this,bl))
  {
    MERROR_VER("Block with id: " << id << std::endl << "has invalid timestamp: " << bl.timestamp);
    bvc.m_verifivation_failed = true;
    return bvc;
  }

  // get the target difficulty for the block.
  // the calculation can overflow, among other failure cases,
  // so we need to check the return type.
  // FIXME: get_blockchain_diff can also assert, look into
  // changing this to throwing exceptions instead so we can clean up.
  const difficulty_type block_diff = get_blockchain_diff();

  const auto pow = get_block_pow(*this, bl, new_b_height);
  if(!check_hash(pow, block_diff))
  {
    MERROR_VER("Block with id: " << id << std::endl << "does not have enough proof of work: " << pow << " at height " << new_b_height << ", unexpected difficulty: " << block_diff);
    bvc.m_verifivation_failed = true;
    bvc.m_bad_pow = true;
    return bvc;
  }

  // sanity check basic miner tx properties;
  if(!prevalidate_miner_transaction(bl, new_b_height))
  {
    MERROR_VER("Block with id: " << id << " failed to pass prevalidation");
    bvc.m_verifivation_failed = true;
    return bvc;
  }

  if(bl.tx_hashes.size()!=tx_ps.size()){
     bvc.m_verifivation_failed = true;
    return bvc;
  }

  uint64_t fee=0;
 for (const auto& tx_hash : bl.tx_hashes)
  {
    transaction tx_tmp;
    blobdata txblob;
  // XXX old code does not check whether tx exists
    if (m_db->tx_exists(tx_hash))
    {
      MERROR("Block with id: " << id << " attempting to add transaction already in blockchain with id: " << tx_hash);
      bvc.m_verifivation_failed = true;
      return bvc;
    }

    // get transaction with hash <tx_hash> from tx_pool
    if(!m_tx_pool.have_tx(tx_hash, relay_category::all))
    {
      MERROR_VER("Block with id: " << id  << " has at least one unknown transaction with id: " << tx_hash);
      bvc.m_verifivation_failed = true;
      return bvc;
    }

    fee += tx.fee();
  }

  uint64_t base_reward = 0;

  if(!validate_miner_transaction(bl,  fee, base_reward,  m_hardfork->get_current_version()))
  {
    MERROR_VER("Block with id: " << id << " has incorrect miner transaction");
    bvc.m_verifivation_failed = true;
    return bvc;
  }

  for(auto & e : tx_ps){
    const auto & h2= get_transaction_hash(e.tx);
    if(std::find(bl.tx_hashes.begin(),bl.tx_hashes.end(),h2)==b.tx_hashes.end()){
      MERROR("cannot find tx hash in block"<<h2);
       bvc.m_verifivation_failed = true;
        return bvc;
    }
  }
  return bvc;

}
 bool swap_chain(Blockchain main,Blockchain alt){

 }

}