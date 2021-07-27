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
bool Blockchain::create_block_template(block& b, const crypto::hash *from_block, const account_public_address& miner_address, difficulty_type& diffic, uint64_t& height, uint64_t& expected_reward, const blobdata& ex_nonce, uint64_t &seed_height, crypto::hash &seed_hash)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  size_t median_weight;
  uint64_t already_generated_coins;
  uint64_t pool_cookie;

  seed_hash = crypto::null_hash;

  m_tx_pool.lock();
  const auto unlock_guard = epee::misc_utils::create_scope_leave_handler([&]() { m_tx_pool.unlock(); });
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if (m_btc_valid && !from_block) {
    // The pool cookie is atomic. The lack of locking is OK, as if it changes
    // just as we compare it, we'll just use a slightly old template, but
    // this would be the case anyway if we'd lock, and the change happened
    // just after the block template was created
    if (!memcmp(&miner_address, &m_btc_address, sizeof(cryptonote::account_public_address)) && m_btc_nonce == ex_nonce
      && m_btc_pool_cookie == m_tx_pool.cookie() && m_btc.prev_id == get_tail_id()) {
      MDEBUG("Using cached template");
      const uint64_t now = time(NULL);
      if (m_btc.timestamp < now) // ensures it can't get below the median of the last few blocks
        m_btc.timestamp = now;
      b = m_btc;
      diffic = m_btc_difficulty;
      height = m_btc_height;
      expected_reward = m_btc_expected_reward;
      seed_height = m_btc_seed_height;
      seed_hash = m_btc_seed_hash;
      return true;
    }
    MDEBUG("Not using cached template: address " << (!memcmp(&miner_address, &m_btc_address, sizeof(cryptonote::account_public_address))) << ", nonce " << (m_btc_nonce == ex_nonce) << ", cookie " << (m_btc_pool_cookie == m_tx_pool.cookie()) << ", from_block " << (!!from_block));
    invalidate_block_template_cache();
  }

  if (from_block)
  {
    //build alternative subchain, front -> mainchain, back -> alternative head
    //block is not related with head of main chain
    //first of all - look in alternative chains container
    alt_block_data_t prev_data;
    bool parent_in_alt = m_db->get_alt_block(*from_block, &prev_data, NULL);
    bool parent_in_main = m_db->block_exists(*from_block);
    if (!parent_in_alt && !parent_in_main)
    {
      MERROR("Unknown from block");
      return false;
    }

    //we have new block in alternative chain
    std::list<block_extended_info> alt_chain;
    block_verification_context bvc = {};
    std::vector<uint64_t> timestamps;
    if (!build_alt_chain(*from_block, alt_chain, timestamps, bvc))
      return false;

    if (parent_in_main)
    {
      cryptonote::block prev_block;
      CHECK_AND_ASSERT_MES(get_block_by_hash(*from_block, prev_block), false, "From block not found"); // TODO
      uint64_t from_block_height = cryptonote::get_block_height(prev_block);
      height = from_block_height + 1;
      {
        uint64_t next_height;
        crypto::rx_seedheights(height, &seed_height, &next_height);
        seed_hash = get_block_id_by_height(seed_height);
      }
    }
    else
    {
      height = alt_chain.back().height + 1;
      uint64_t next_height;
      crypto::rx_seedheights(height, &seed_height, &next_height);

      if (alt_chain.size() && alt_chain.front().height <= seed_height)
      {
        for (auto it=alt_chain.begin(); it != alt_chain.end(); it++)
        {
          if (it->height == seed_height+1)
          {
            seed_hash = it->bl.prev_id;
            break;
          }
        }
      }
      else
      {
        seed_hash = get_block_id_by_height(seed_height);
      }
    }
    b.major_version = m_hardfork->get_ideal_version(height);
    b.minor_version = m_hardfork->get_ideal_version();
    b.prev_id = *from_block;

    // cheat and use the weight of the block we start from, virtually certain to be acceptable
    // and use 1.9 times rather than 2 times so we're even more sure
    if (parent_in_main)
    {
      median_weight = m_db->get_block_weight(height - 1);
      already_generated_coins = m_db->get_block_already_generated_coins(height - 1);
    }
    else
    {
      median_weight = prev_data.cumulative_weight - prev_data.cumulative_weight / 20;
      already_generated_coins = alt_chain.back().already_generated_coins;
    }

    // FIXME: consider moving away from block_extended_info at some point
    block_extended_info bei = {};
    bei.bl = b;
    bei.height = alt_chain.size() ? prev_data.height + 1 : m_db->get_block_height(*from_block) + 1;

    diffic = get_next_difficulty_for_alternative_chain(alt_chain, bei);
  }
  else
  {
    height = m_db->height();
    b.major_version = m_hardfork->get_current_version();
    b.minor_version = m_hardfork->get_ideal_version();
    b.prev_id = get_tail_id();
    median_weight = m_current_block_cumul_weight_limit / 2;
    diffic = get_difficulty_for_next_block();
    already_generated_coins = m_db->get_block_already_generated_coins(height - 1);
    {
      uint64_t next_height;
      crypto::rx_seedheights(height, &seed_height, &next_height);
      seed_hash = get_block_id_by_height(seed_height);
    }
  }
  b.timestamp = time(NULL);

  uint64_t median_ts;
  if (!check_block_timestamp(b, median_ts))
  {
    b.timestamp = median_ts;
  }

  CHECK_AND_ASSERT_MES(diffic, false, "difficulty overhead.");

  size_t txs_weight;
  uint64_t fee;
  if (!m_tx_pool.fill_block_template(b, median_weight, already_generated_coins, txs_weight, fee, expected_reward, b.major_version))
  {
    return false;
  }
  pool_cookie = m_tx_pool.cookie();

  /*
   two-phase miner transaction generation:
    we don't know exact block weight until we prepare block, but we don't know reward until we know
   block weight, so first miner transaction generated with fake amount of money, and with phase we know think we know expected block weight
   */
  //make blocks coin-base tx looks close to real coinbase tx to get truthful blob weight
  uint8_t hf_version = b.major_version;
  bool r=false;
   std::tie(r,b.miner_tx)  = construct_miner_tx(height, median_weight, already_generated_coins, txs_weight, fee, miner_address, ex_nonce, hf_version);
  CHECK_AND_ASSERT_MES(r, false, "Failed to construct miner tx, first chance");
  size_t cumulative_weight = txs_weight + get_transaction_weight(b.miner_tx);
  MDEBUG("Creating block template: miner tx weight " << get_transaction_weight(b.miner_tx) <<
      ", cumulative weight " << cumulative_weight);
  for (size_t try_count = 0; try_count != 10; ++try_count)
  {
    std::tie(r,b.miner_tx) = construct_miner_tx(height, median_weight, already_generated_coins, cumulative_weight, fee, miner_address, ex_nonce,  hf_version);

    CHECK_AND_ASSERT_MES(r, false, "Failed to construct miner tx, second chance");
    size_t coinbase_weight = get_transaction_weight(b.miner_tx);
    if (coinbase_weight > cumulative_weight - txs_weight)
    {
      cumulative_weight = txs_weight + coinbase_weight;
      MDEBUG("Creating block template: miner tx weight " << coinbase_weight <<
          ", cumulative weight " << cumulative_weight << " is greater than before");

      continue;
    }

    if (coinbase_weight < cumulative_weight - txs_weight)
    {
      size_t delta = cumulative_weight - txs_weight - coinbase_weight;

      b.miner_tx.extra.insert(b.miner_tx.extra.end(), delta, 0);
      //here  could be 1 byte difference, because of extra field counter is varint, and it can become from 1-byte len to 2-bytes len.
      if (cumulative_weight != txs_weight + get_transaction_weight(b.miner_tx))
      {
        CHECK_AND_ASSERT_MES(cumulative_weight + 1 == txs_weight + get_transaction_weight(b.miner_tx), false, "unexpected case: cumulative_weight=" << cumulative_weight << " + 1 is not equal txs_cumulative_weight=" << txs_weight << " + get_transaction_weight(b.miner_tx)=" << get_transaction_weight(b.miner_tx));
        b.miner_tx.extra.resize(b.miner_tx.extra.size() - 1);
        if (cumulative_weight != txs_weight + get_transaction_weight(b.miner_tx))
        {
          //fuck, not lucky, -1 makes varint-counter size smaller, in that case we continue to grow with cumulative_weight
          MDEBUG("Miner tx creation has no luck with delta_extra size = " << delta << " and " << delta - 1);
          cumulative_weight += delta - 1;
          continue;
        }
        MDEBUG("Setting extra for block: " << b.miner_tx.extra.size() << ", try_count=" << try_count);
      }
    }
    CHECK_AND_ASSERT_MES(cumulative_weight == txs_weight + get_transaction_weight(b.miner_tx), false, "unexpected case: cumulative_weight=" << cumulative_weight << " is not equal txs_cumulative_weight=" << txs_weight << " + get_transaction_weight(b.miner_tx)=" << get_transaction_weight(b.miner_tx));


    if (!from_block)
      cache_block_template(b, miner_address, ex_nonce, diffic, height, expected_reward, seed_height, seed_hash, pool_cookie);
    return true;
  }
  LOG_ERROR("Failed to create_block_template with " << 10 << " tries");
  return false;
}

//------------------------------------------------------------------
bool Blockchain::create_block_template(block& b, const account_public_address& miner_address, difficulty_type& diffic, uint64_t& height, uint64_t& expected_reward, const blobdata& ex_nonce, uint64_t &seed_height, crypto::hash &seed_hash)
{
  return create_block_template(b, NULL, miner_address, diffic, height, expected_reward, ex_nonce, seed_height, seed_hash);
}