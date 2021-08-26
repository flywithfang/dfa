
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
cryptonote::BlockTemplate Blockchain::create_block_template(const account_public_address& miner_address,   const blobdata& blob_reserve)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  BlockTemplate bt{};
  block & b = bt.b;
  uint64_t seed_height{},n_seed_height{};
  uint64_t height{};
  crypto::hash K{},n_seed_hash{};

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  
  {
    height = m_db->height();
    b.major_version = m_hardfork->get_current_version();
    b.minor_version = m_hardfork->get_ideal_version();
    b.prev_id = get_top_hash();
    bt.diff = get_blockchain_diff(*this);
    {
      rx_seedheights(height, &seed_height, &n_seed_height);
      K = get_block_hash_by_height(seed_height);
    }
  }

  if (n_seed_height != seed_height)
    n_seed_hash = get_block_hash_by_height(n_seed_height);
  else
    n_seed_hash = K;

  b.timestamp = time(NULL);
  bt.height = height;
  bt.seed_height=seed_height;
  bt.seed_hash=K;
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

