
  //------------------------------------------------------------------------------------------------------------------------------
  // equivalent of strstr, but with arbitrary bytes (ie, NULs)
  // This does not differentiate between "not found" and "found at offset 0"
  size_t slow_memmem(const void* start_buff, size_t buflen,const void* pat,size_t patlen)
  {
    const void* buf = start_buff;
    const void* end=(const char*)buf+buflen;
    if (patlen > buflen || patlen == 0) return 0;
    while(buflen>0 && (buf=memchr(buf,((const char*)pat)[0],buflen-patlen+1)))
    {
      if(memcmp(buf,pat,patlen)==0)
        return (const char*)buf - (const char*)start_buff;
      buf=(const char*)buf+1;
      buflen = (const char*)end - (const char*)buf;
    }
    return 0;
  }

//------------------------------------------------------------------
//TODO: This function only needed minor modification to work with BlockchainDB,
//      and *works*.  As such, to reduce the number of things that might break
//      in moving to BlockchainDB, this function will remain otherwise
//      unchanged for the time being.
//
// This function makes a new block for a miner to mine the hash for
//
// FIXME: this codebase references #if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
// in a lot of places.  That flag is not referenced in any of the code
// nor any of the makefiles, howeve.  Need to look into whether or not it's
// necessary at all.
cryptonote::BlockTemplate Blockchain::create_block_template( const crypto::hash *from_block, const account_public_address& miner_address,   const blobdata& blob_reserve)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  BlockTemplate bt{};
  block & b = bt.b;
  uint64_t seed_height{},n_seed_height{};
  uint64_t height{};
  crypto::hash seed_hash{},n_seed_hash{};

  m_tx_pool.lock();
  const auto unlock_guard = epee::misc_utils::create_scope_leave_handler([&]() { m_tx_pool.unlock(); });
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  

  if (from_block)
  {
    //build alternative subchain, front -> mainchain, back -> alternative head
    //block is not related with head of main chain
    //first of all - look in alternative chains container
    alt_block_data_t prev_alt_block;
    bool parent_in_alt = m_db->get_alt_block(*from_block, &prev_alt_block, NULL);
    bool parent_in_main = m_db->block_exists(*from_block);
    if (!parent_in_alt && !parent_in_main)
    {
      throw_and_log("Unknown from block");
    }

    //we have new block in alternative chain
    std::list<block_extended_info> alt_chain;
    block_verification_context bvc = {};
    if (!build_alt_chain(*from_block, alt_chain,  bvc))
      throw_and_log("fail to build atl_chain");

    if (parent_in_main)
    {
      cryptonote::block prev_block;
      auto r = get_block_by_hash(*from_block, prev_block);
      if(!r) throw_and_log("From block not found"); 
      uint64_t from_block_height = cryptonote::get_block_height(prev_block);
      height = from_block_height + 1;
      {
        uint64_t next_height;
        rx_seedheights(height, &seed_height, &next_height);
        seed_hash = get_block_hash_by_height(seed_height);
      }
    }
    else
    {
      height = alt_chain.back().height + 1;
      rx_seedheights(height, &seed_height, &n_seed_height);

      if (alt_chain.size() && alt_chain.front().height <= seed_height)
      {
        for (auto&alt:alt_chain)
        {
          if (alt.height == seed_height+1)
          {
            seed_hash = alt.bl.prev_id;
            break;
          }
        }
      }
      else
      {
        seed_hash = get_block_hash_by_height(seed_height);
      }
    }
    b.major_version = m_hardfork->get_ideal_version(height);
    b.minor_version = m_hardfork->get_ideal_version();
    b.prev_id = *from_block;

    // FIXME: consider moving away from block_extended_info at some point
    block_extended_info bei = {};
    bei.bl = b;
    bei.height = alt_chain.size() ? prev_alt_block.height + 1 : m_db->get_block_height(*from_block) + 1;

    bt.diff = get_next_difficulty_for_alternative_chain(alt_chain, bei);
  }
  else
  {
    height = m_db->height();
    b.major_version = m_hardfork->get_current_version();
    b.minor_version = m_hardfork->get_ideal_version();
    b.prev_id = get_top_hash();
    bt.diff = get_blockchain_diff();
    {
      rx_seedheights(height, &seed_height, &n_seed_height);
      seed_hash = get_block_hash_by_height(seed_height);
    }
  }

  if (n_seed_height != seed_height)
    n_seed_hash = get_block_hash_by_height(n_seed_height);
  else
    n_seed_hash = seed_hash;

  b.timestamp = time(NULL);
  bt.height = height;
  bt.seed_height=seed_height;
  bt.seed_hash=seed_hash;
  bt.n_seed_height=n_seed_height;
  bt.n_seed_hash = n_seed_hash;


  if (!m_tx_pool.fill_block_template(bt))
  {
    throw_and_log("fail to fill_block_template");
  }

  /*
   two-phase miner transaction generation:
    we don't know exact block weight until we prepare block, but we don't know reward until we know
   block weight, so first miner transaction generated with fake amount of money, and with phase we know think we know expected block weight
   */
  //make blocks coin-base tx looks close to real coinbase tx to get truthful blob weight
  uint8_t hf_version = b.major_version;
  bool r=false;
  const varbinary bb(blob_reserve);
   std::tie(r,b.miner_tx)  = construct_miner_tx(height,  bt.fee, miner_address, bb, hf_version);
   if(!r)
      throw_and_log("Failed to construct miner tx");

    const blobdata block_blob = t_serializable_object_to_blob(bt.b);
    const auto &tx_pub_key =b.miner_tx.tx_pub_key;
    const uint64_t off = slow_memmem((void*)block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key));
    if(off==0)
    {
      throw_and_log("Failed to find tx pub key in blockblob");
    }
    bt.reserved_offset = off+ sizeof(tx_pub_key)+ (bb.size()>127 ? 2:1) ; 
    if(bt.reserved_offset + blob_reserve.size() > block_blob.size())
    {
      throw_and_log("Failed to calculate offset for ");
    }

  return bt;
}

