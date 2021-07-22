#include <numeric>
#include <tuple>
#include <queue>
#include <boost/format.hpp>
#include <boost/optional/optional.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <openssl/evp.h>
#include "include_base_utils.h"
using namespace epee;

#include "cryptonote_config.h"
#include "cryptonote_core/tx_sanity_check.h"

#include "wallet2.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "net/parse.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/core_rpc_server_error_codes.h"
#include "rpc/rpc_payment_signature.h"
#include "rpc/rpc_payment_costs.h"
#include "misc_language.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"

#include "common/boost_serialization_helper.h"
#include "common/command_line.h"
#include "common/threadpool.h"
#include "int-util.h"
#include "profile_tools.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "cryptonote_basic/blobdatatype.h"
#include "mnemonics/electrum-words.h"
#include "common/i18n.h"
#include "common/util.h"
#include "common/apply_permutation.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "common/json_util.h"
#include "memwipe.h"
#include "common/base58.h"
#include "common/combinator.h"
#include "common/dns_utils.h"
#include "common/notify.h"
#include "common/perf_timer.h"
#include "ringct/rctSigs.h"
#include "ringdb.h"
#include "device/device_cold.hpp"
//#include "device_trezor/device_trezor.hpp"
#include "net/socks_connect.h"

extern "C"
{
#include "crypto/keccak.h"
#include "crypto/crypto-ops.h"
}
using namespace std;
using namespace crypto;
using namespace cryptonote;


namespace tools
{
    void add_reason(std::string &reasons, const char *reason)
  {
    if (!reasons.empty())
      reasons += ", ";
    reasons += reason;
  }

  
  std::string get_text_reason(const cryptonote::COMMAND_RPC_SEND_RAW_TX::response &res)
  {
      std::string reason;
      if (res.low_mixin)
        add_reason(reason, "bad ring size");
      if (res.double_spend)
        add_reason(reason, "double spend");
      if (res.invalid_input)
        add_reason(reason, "invalid input");
      if (res.invalid_output)
        add_reason(reason, "invalid output");
      if (res.too_few_outputs)
        add_reason(reason, "too few outputs");
      if (res.too_big)
        add_reason(reason, "too big");
      if (res.overspend)
        add_reason(reason, "overspend");
      if (res.fee_too_low)
        add_reason(reason, "fee too low");
      if (res.sanity_check_failed)
        add_reason(reason, "tx sanity check failed");
      if (res.not_relayed)
        add_reason(reason, "tx was not relayed");
      return reason;
  }

  struct TX {
    std::vector<size_t> selected_transfers;
    std::vector<cryptonote::tx_destination_entry> dsts;
    cryptonote::transaction tx;
    tools::wallet2::pending_tx ptx;
    size_t weight;
    uint64_t needed_fee;
    std::vector<std::vector<tools::wallet2::get_outs_entry>> outs;

    TX() : weight(0), needed_fee(0) {}

    /* Add an output to the transaction.
     * Returns True if the output was added, False if there are no more available output slots.
     */
    bool add(const cryptonote::tx_destination_entry &de, uint64_t amount, unsigned int original_output_index, bool merge_destinations, size_t max_dsts) {
      if (merge_destinations)
      {
        std::vector<cryptonote::tx_destination_entry>::iterator i;
        i = std::find_if(dsts.begin(), dsts.end(), [&](const cryptonote::tx_destination_entry &d) { 
          return !memcmp (&d.addr, &de.addr, sizeof(de.addr)); });
        if (i == dsts.end())
        {
          if (dsts.size() >= max_dsts)
            return false;
          dsts.push_back(de);
          i = dsts.end() - 1;
          i->amount = 0;
        }
        i->amount += amount;
      }
      else
      {
        THROW_WALLET_EXCEPTION_IF(original_output_index > dsts.size(), error::wallet_internal_error,
            std::string("original_output_index too large: ") + std::to_string(original_output_index) + " > " + std::to_string(dsts.size()));
        if (original_output_index == dsts.size())
        {
          if (dsts.size() >= max_dsts)
            return false;
          dsts.push_back(de);
          dsts.back().amount = 0;
        }
        THROW_WALLET_EXCEPTION_IF(memcmp(&dsts[original_output_index].addr, &de.addr, sizeof(de.addr)), error::wallet_internal_error, "Mismatched destination address");
        dsts[original_output_index].amount += amount;
      }
      return true;
    }
  };



uint64_t calculate_fee(uint64_t fee_per_kb, size_t bytes, uint64_t fee_multiplier)
{
  uint64_t kB = (bytes + 1023) / 1024;
  return kB * fee_per_kb * fee_multiplier;
}

uint64_t calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
{
  uint64_t fee = weight * base_fee * fee_multiplier;
  fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
  return fee;
}

std::string get_weight_string(size_t weight)
{
  return std::to_string(weight) + " weight";
}

std::string get_weight_string(const cryptonote::transaction &tx, size_t blob_size)
{
  return get_weight_string(get_transaction_weight(tx, blob_size));
}


  uint8_t get_bulletproof_fork()
{
  return 8;
}
uint8_t get_clsag_fork()
{
  return HF_VERSION_CLSAG;
}


size_t estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag)
{
  size_t size = 0;

  // tx prefix

  // first few bytes
  size += 1 + 6;

  // vin
  size += n_inputs * (1+6+(mixin+1)*2+32);

  // vout
  size += n_outputs * (6+32);

  // extra
  size += extra_size;

  // rct signatures

  // type
  size += 1;

  // rangeSigs
  if (bulletproof)
  {
    size_t log_padded_outputs = 0;
    while ((1<<log_padded_outputs) < n_outputs)
      ++log_padded_outputs;
    size += (2 * (6 + log_padded_outputs) + 4 + 5) * 32 + 3;
  }
  else
    size += (2*64*32+32+64*32) * n_outputs;

  // MGs/CLSAGs
    size += n_inputs * (32 * (mixin+1) + 64);

  // mixRing - not serialized, can be reconstructed
  /* size += 2 * 32 * (mixin+1) * n_inputs; */

  // pseudoOuts
  size += 32 * n_inputs;
  // ecdhInfo
  size += 8 * n_outputs;
  // outPk - only commitment is saved
  size += 32 * n_outputs;
  // txnFee
  size += 4;

  MINFO("estimated " << (bulletproof ? "bulletproof" : "borromean") << " rct tx size for " << n_inputs << " inputs with ring size " << (mixin+1) << " and " << n_outputs << " outputs: " << size << " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)");
  return size;
}

size_t estimate_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag)
{
  if (use_rct)
    return estimate_rct_tx_size(n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag);
  else
    return n_inputs * (mixin+1) * APPROXIMATE_INPUT_BYTES + extra_size;
}

uint64_t estimate_tx_weight( int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag)
{
  size_t size = estimate_tx_size(true, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag);
  if (bulletproof && n_outputs > 2)
  {
    const uint64_t bp_base = 368;
    size_t log_padded_outputs = 2;
    while ((1<<log_padded_outputs) < n_outputs)
      ++log_padded_outputs;
    uint64_t nlr = 2 * (6 + log_padded_outputs);
    const uint64_t bp_size = 32 * (9 + nlr);
    const uint64_t bp_clawback = (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
    MDEBUG("clawback on size " << size << ": " << bp_clawback);
    size += bp_clawback;
  }
  return size;
}



//----------------------------------------------------------------------------------------------------
uint64_t wallet2::estimate_fee(bool use_per_byte_fee, bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask) const
{
 
    const size_t estimated_tx_weight = estimate_tx_weight(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag);
    return calculate_fee_from_weight(base_fee, estimated_tx_weight, fee_multiplier, fee_quantization_mask);
  
}

uint64_t wallet2::get_fee_multiplier(uint32_t priority, int fee_algorithm)
{
  static const struct
  {
    size_t count;
    uint64_t multipliers[4];
  }
  multipliers[] =
  {
    { 3, {1, 2, 3} },
    { 3, {1, 20, 166} },
    { 4, {1, 4, 20, 166} },
    { 4, {1, 5, 25, 1000} },
  };

  if (fee_algorithm == -1)
    fee_algorithm = get_fee_algorithm();

  // 0 -> default (here, x1 till fee algorithm 2, x4 from it)
  if (priority == 0)
    priority = m_default_priority;
  if (priority == 0)
  {
    if (fee_algorithm >= 2)
      priority = 2;
    else
      priority = 1;
  }

  THROW_WALLET_EXCEPTION_IF(fee_algorithm < 0 || fee_algorithm > 3, error::invalid_priority);

  // 1 to 3/4 are allowed as priorities
  const uint32_t max_priority = multipliers[fee_algorithm].count;
  if (priority >= 1 && priority <= max_priority)
  {
    return multipliers[fee_algorithm].multipliers[priority-1];
  }

  THROW_WALLET_EXCEPTION_IF (false, error::invalid_priority);
  return 1;
}

//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_base_fee()
{

    return FEE_PER_KB;

}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_fee_quantization_mask()
{


    return 1;

}
//----------------------------------------------------------------------------------------------------
int wallet2::get_fee_algorithm()
{
  // changes at v3, v5, v8
  if (use_fork_rules(HF_VERSION_PER_BYTE_FEE, 0))
    return 3;
  if (use_fork_rules(5, 0))
    return 2;
  if (use_fork_rules(3, -30 * 14))
   return 1;
  return 0;
}


uint64_t calculate_fee(bool use_per_byte_fee, const cryptonote::transaction &tx, size_t blob_size, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
{
  if (use_per_byte_fee)
    return calculate_fee_from_weight(base_fee, cryptonote::get_transaction_weight(tx, blob_size), fee_multiplier, fee_quantization_mask);
  else
    return calculate_fee(base_fee, blob_size, fee_multiplier);
}
static uint32_t get_count_above(const std::vector<wallet2::transfer_details> &transfers, const std::vector<size_t> &indices, uint64_t threshold)
{
  uint32_t count = 0;
  for (size_t idx: indices)
    if (transfers[idx].amount() >= threshold)
      ++count;
  return count;
}

size_t get_num_outputs(const std::vector<cryptonote::tx_destination_entry> &dsts, const std::vector<tools::wallet2::transfer_details> &transfers, const std::vector<size_t> &selected_transfers)
  {
    size_t outputs = dsts.size();
    uint64_t needed_money = 0;
    for (const auto& dt: dsts)
      needed_money += dt.amount;
    uint64_t found_money = 0;
    for(size_t idx: selected_transfers)
      found_money += transfers[idx].amount();
    if (found_money != needed_money)
      ++outputs; // change
    if (outputs < 2)
      ++outputs; // extra 0 dummy output
    return outputs;
  }

// Another implementation of transaction creation that is hopefully better
// While there is anything left to pay, it goes through random outputs and tries
// to fill the next destination/amount. If it fully fills it, it will use the
// remainder to try to fill the next one as well.
// The tx size if roughly estimated as a linear function of only inputs, and a
// new tx will be created when that size goes above a given fraction of the
// max tx size. At that point, more outputs may be added if the fee cannot be
// satisfied.
// If the next output in the next tx would go to the same destination (ie, we
// cut off at a tx boundary in the middle of paying a given destination), the
// fee will be carved out of the current input if possible, to avoid having to
// add another output just for the fee and getting change.
// This system allows for sending (almost) the entire balance, since it does
// not generate spurious change in all txes, thus decreasing the instantaneous
// usable balance.
std::vector<wallet2::pending_tx> wallet2::create_transactions_2(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra)
{
  cout<<"create_transactions_2 "<<fake_outs_count<<","<<unlock_time<<","<<priority<<endl;
  cout<<"extra "<<extra<<endl;
  for(auto dst : dsts){
    cout<<"dst "<<dst.original<<","<<dst.amount<<","<<dst.addr.m_view_public_key<<","<<","<<dst.is_integrated<<endl;
  }
  
  //ensure device is let in NONE mode in any case
  hw::device &hwdev = m_account.get_device();
  auto original_dsts = dsts;

  std::vector<size_t> unused_transfers_indices;
  std::vector<size_t> unused_dust_indices;
  uint64_t needed_money;
  uint64_t accumulated_fee, accumulated_outputs, accumulated_change;

  std::vector<TX> txes;
  bool adding_fee; // true if new outputs go towards fee, rather than destinations
  uint64_t needed_fee, available_for_fee = 0;
  uint64_t upper_transaction_weight_limit = get_upper_transaction_weight_limit();
  const bool use_per_byte_fee = use_fork_rules(HF_VERSION_PER_BYTE_FEE, 0);
  const bool use_rct =true;
  const bool bulletproof = true;
  const bool clsag = true;


  const uint64_t base_fee  = get_base_fee();
  const uint64_t fee_multiplier = get_fee_multiplier(priority, get_fee_algorithm());
  const uint64_t fee_quantization_mask = get_fee_quantization_mask();

  // throw if attempting a transaction with no destinations
  THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);

  // calculate total amount being sent to all destinations
  // throw if total amount overflows uint64_t
  needed_money = 0;
  for(auto& dt: dsts)
  {
    THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_amount);
    needed_money += dt.amount;
    THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, 0, m_nettype);
  }

  // throw if attempting a transaction with no money
  THROW_WALLET_EXCEPTION_IF(needed_money == 0, error::zero_amount);


  // early out if we know we can't make it anyway
  // we could also check for being within FEE_PER_KB, but if the fee calculation
  // ever changes, this might be missed, so let this go through
  const uint64_t min_fee = (fee_multiplier * base_fee * estimate_tx_size(use_rct, 1, fake_outs_count, 2, extra.size(), bulletproof, clsag));
  uint64_t balance_subtotal = this->balance(false);
  uint64_t unlocked_balance_subtotal = unlocked_balance(false);
 
  THROW_WALLET_EXCEPTION_IF(needed_money + min_fee > balance_subtotal, error::not_enough_money,
    balance_subtotal, needed_money, 0);
  // first check overall balance is enough, then unlocked one, so we throw distinct exceptions
  THROW_WALLET_EXCEPTION_IF(needed_money + min_fee > unlocked_balance_subtotal, error::not_enough_unlocked_money,unlocked_balance_subtotal, needed_money, 0);


  // determine threshold for fractional amount
  const size_t tx_weight_one_ring = estimate_tx_weight(use_rct, 1, fake_outs_count, 2, 0, bulletproof, clsag);
  const size_t tx_weight_two_rings = estimate_tx_weight(use_rct, 2, fake_outs_count, 2, 0, bulletproof, clsag);
  THROW_WALLET_EXCEPTION_IF(tx_weight_one_ring > tx_weight_two_rings, error::wallet_internal_error, "Estimated tx weight with 1 input is larger than with 2 inputs!");
  const size_t tx_weight_per_ring = tx_weight_two_rings - tx_weight_one_ring;
  const uint64_t fractional_threshold = (fee_multiplier * base_fee * tx_weight_per_ring) / (use_per_byte_fee ? 1 : 1024);

  // gather all dust and non-dust outputs belonging to specified subaddresses
  size_t num_nondust_outputs = 0;
  size_t num_dust_outputs = 0;
  for (size_t i = 0; i < m_transfers_in.size(); ++i)
  {
    const transfer_details& td = m_transfers_in[i];
    if (m_ignore_fractional_outputs && td.amount() < fractional_threshold)
    {
      MDEBUG("Ignoring output " << i << " of amount " << print_money(td.amount()) << " which is below fractional threshold " << print_money(fractional_threshold));
      continue;
    }
    if (!is_spent(td, false) && !td.m_frozen  && is_transfer_unlocked(td))
    {
      if (td.amount() > m_ignore_outputs_above || td.amount() < m_ignore_outputs_below)
      {
        MDEBUG("Ignoring output " << i << " of amount " << print_money(td.amount()) << " which is outside prescribed range [" << print_money(m_ignore_outputs_below) << ", " << print_money(m_ignore_outputs_above) << "]");
        continue;
      }
     
        unused_transfers_indices.push_back(i);
        ++num_nondust_outputs;
      }
  }

  
  cout<<"Starting with " << num_nondust_outputs << " non-dust outputs and " << num_dust_outputs << " dust outputs"<<endl;

  if (unused_dust_indices.empty() && unused_transfers_indices.empty())
    return std::vector<wallet2::pending_tx>();

  // if empty, put dummy entry so that the front can be referenced later in the loop
  if (unused_dust_indices.empty())
    unused_dust_indices.push_back({});
  if (unused_transfers_indices.empty())
    unused_transfers_indices.push_back({});

  // start with an empty tx
  txes.push_back(TX());
  accumulated_fee = 0;
  accumulated_outputs = 0;
  accumulated_change = 0;
  adding_fee = false;
  needed_fee = 0;
  std::vector<std::vector<tools::wallet2::get_outs_entry>> outs;

  // for rct, since we don't see the amounts, we will try to make all transactions
  // look the same, with 1 or 2 inputs, and 2 outputs. One input is preferable, as
  // this prevents linking to another by provenance analysis, but two is ok if we
  // try to pick outputs not from the same block. We will get two outputs, one for
  // the destination, and one for change.
  MINFO("checking preferred");
  uint64_t rct_outs_needed = 2 * (fake_outs_count + 1);
  rct_outs_needed += 100; // some fudge factor since we don't know how many are locked

  
    // this is used to build a tx that's 1 or 2 inputs, and 2 outputs, which
    // will get us a known fee.
  uint64_t estimated_fee = estimate_fee(use_per_byte_fee, use_rct, 2, fake_outs_count, 2, extra.size(), bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask);

  std::vector<size_t> preferred_inputs = pick_preferred_rct_inputs(needed_money + estimated_fee);
  if (!preferred_inputs.empty())
  {
    string s;
    for (auto i: preferred_inputs)
     s += boost::lexical_cast<std::string>(i) + " (" + print_money(m_transfers_in[i].amount()) + ") ";
    MINFO("Found preferred rct inputs for rct tx: " << s);
  }
  
  MINFO("done checking preferred");

  // while:
  // - we have something to send
  // - or we need to gather more fee
  // - or we have just one input in that tx, which is rct (to try and make all/most rct txes 2/2)
  unsigned int original_output_index = 0;
  std::vector<size_t>* unused_transfers_indices = &unused_transfers_indices[0].second;
  std::vector<size_t>* unused_dust_indices      = &unused_dust_indices[0].second;
  
  while ((!dsts.empty() && dsts[0].amount > 0) || adding_fee || !preferred_inputs.empty() || should_pick_a_second_output( txes.back().selected_transfers.size(), *unused_transfers_indices, *unused_dust_indices)) 
  {
    TX &tx = txes.back();

    MINFO("Start of loop with " << unused_transfers_indices->size() << " " << unused_dust_indices->size() << ", tx.dsts.size() " << tx.dsts.size());
    MINFO("unused_transfers_indices: " << strjoin(*unused_transfers_indices, " "));
    MINFO("unused_dust_indices: " << strjoin(*unused_dust_indices, " "));
    MINFO("dsts size " << dsts.size() << ", first " << (dsts.empty() ? "-" : cryptonote::print_money(dsts[0].amount)));
    MINFO("adding_fee " << adding_fee << ", use_rct " << use_rct);

    // if we need to spend money and don't have any left, we fail
    if (unused_dust_indices->empty() && unused_transfers_indices->empty()) {
      MINFO("No more outputs to choose from");
      THROW_WALLET_EXCEPTION_IF(1, error::tx_not_possible, unlocked_balance(false), needed_money, accumulated_fee + needed_fee);
    }

    // get a random unspent output and use it to pay part (or all) of the current destination (and maybe next one, etc)
    // This could be more clever, but maybe at the cost of making probabilistic inferences easier
    size_t idx;
    if (!preferred_inputs.empty()) {
      idx = pop_back(preferred_inputs);
      pop_if_present(*unused_transfers_indices, idx);
      pop_if_present(*unused_dust_indices, idx);
    } else if ((dsts.empty() || dsts[0].amount == 0) && !adding_fee) {
      // the "make rct txes 2/2" case - we pick a small value output to "clean up" the wallet too
      std::vector<size_t> indices = get_only_rct(*unused_dust_indices, *unused_transfers_indices);
      idx = pop_best_value(indices, tx.selected_transfers, true);

      // we might not want to add it if it's a large output and we don't have many left
      uint64_t min_output_value = m_min_output_value;
      uint32_t min_output_count = m_min_output_count;
      if (min_output_value == 0 && min_output_count == 0)
      {
        min_output_value = DEFAULT_MIN_OUTPUT_VALUE;
        min_output_count = DEFAULT_MIN_OUTPUT_COUNT;
      }
      if (m_transfers_in[idx].amount() >= min_output_value) {
        if (get_count_above(m_transfers_in, *unused_transfers_indices, min_output_value) < min_output_count) {
          MINFO("Second output was not strictly needed, and we're running out of outputs above " << print_money(min_output_value) << ", not adding");
          break;
        }
      }

      // since we're trying to add a second output which is not strictly needed,
      // we only add it if it's unrelated enough to the first one
      float relatedness = get_output_relatedness(m_transfers_in[idx], m_transfers_in[tx.selected_transfers.front()]);
      if (relatedness > SECOND_OUTPUT_RELATEDNESS_THRESHOLD)
      {
        MINFO("Second output was not strictly needed, and relatedness " << relatedness << ", not adding");
        break;
      }
      pop_if_present(*unused_transfers_indices, idx);
      pop_if_present(*unused_dust_indices, idx);
    } else
      idx = pop_best_value(unused_transfers_indices->empty() ? *unused_dust_indices : *unused_transfers_indices, tx.selected_transfers);

    const transfer_details &td = m_transfers_in[idx];
    MINFO("Picking output " << idx << ", amount " << print_money(td.amount()) << ", ki " << td.m_key_image);

    // add this output to the list to spend
    tx.selected_transfers.push_back(idx);
    uint64_t available_amount = td.amount();
    accumulated_outputs += available_amount;

    // clear any fake outs we'd already gathered, since we'll need a new set
    outs.clear();

    bool out_slots_exhausted = false;
    if (adding_fee)
    {
      MINFO("We need more fee, adding it to fee");
      available_for_fee += available_amount;
    }
    else
    {
      while (!dsts.empty() && dsts[0].amount <= available_amount && estimate_tx_weight(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size()+1, extra.size(), bulletproof, clsag) < TX_WEIGHT_TARGET(upper_transaction_weight_limit))
      {
        auto & d=dsts[0];
        // we can fully pay that destination
        MINFO("We can fully pay " << get_account_address_as_str(m_nettype,  d.addr) <<
          " for " << print_money(d.amount));
        if (!tx.add(d, d.amount, original_output_index, m_merge_destinations, BULLETPROOF_MAX_OUTPUTS-1))
        {
          MINFO("Didn't pay: ran out of output slots");
          out_slots_exhausted = true;
          break;
        }
        available_amount -= d.amount;
        d.amount = 0;
        pop_index(dsts, 0);
        ++original_output_index;
      }

      if (!out_slots_exhausted && available_amount > 0 && !dsts.empty() && estimate_tx_weight(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size()+1, extra.size(), bulletproof, clsag) < TX_WEIGHT_TARGET(upper_transaction_weight_limit)) {
        // we can partially fill that destination
        MINFO("We can partially pay " << get_account_address_as_str(m_nettype, dsts[0].addr) <<
          " for " << print_money(available_amount) << "/" << print_money(dsts[0].amount));
        if (tx.add(dsts[0], available_amount, original_output_index, m_merge_destinations, BULLETPROOF_MAX_OUTPUTS-1))
        {
          dsts[0].amount -= available_amount;
          available_amount = 0;
        }
        else
        {
          MINFO("Didn't pay: ran out of output slots");
          out_slots_exhausted = true;
        }
      }
    }

    // here, check if we need to sent tx and start a new one
    MINFO("Considering whether to create a tx now, " << tx.selected_transfers.size() << " inputs, tx limit "
      << upper_transaction_weight_limit);
    bool try_tx = false;

    // If the new transaction is full, create it and start a new one
    if (out_slots_exhausted)
    {
      MINFO("Transaction is full, will create it and start a new tx");
      return false;
      try_tx = true;
    }
    // if we have preferred picks, but haven't yet used all of them, continue
    else if (preferred_inputs.empty())
    {
      if (adding_fee)
      {
        /* might not actually be enough if adding this output bumps size to next kB, but we need to try */
        try_tx = available_for_fee >= needed_fee;
      }
      else
      {
        const size_t estimated_rct_tx_weight = estimate_tx_weight(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size()+1, extra.size(), bulletproof, clsag);
        try_tx = dsts.empty() || (estimated_rct_tx_weight >= TX_WEIGHT_TARGET(upper_transaction_weight_limit));
        THROW_WALLET_EXCEPTION_IF(try_tx && tx.dsts.empty(), error::tx_too_big, estimated_rct_tx_weight, upper_transaction_weight_limit);
      }
    }

    if (try_tx) {
      cryptonote::transaction test_tx;
      pending_tx test_ptx;

      const size_t num_outputs = get_num_outputs(tx.dsts, m_transfers_in, tx.selected_transfers);
      needed_fee = estimate_fee(use_per_byte_fee, use_rct ,tx.selected_transfers.size(), fake_outs_count, num_outputs, extra.size(), bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask);

      uint64_t inputs = 0, outputs = needed_fee;
      for (size_t idx: tx.selected_transfers)
       inputs += m_transfers_in[idx].amount();
      for (const auto &o: tx.dsts) outputs += o.amount;

      if (inputs < outputs)
      {
        MINFO("We don't have enough for the basic fee, switching to adding_fee");
        adding_fee = true;
        goto skip_tx;
      }

      MINFO("Trying to create a tx now, with " << tx.dsts.size() << " outputs and " <<
        tx.selected_transfers.size() << " inputs");


        transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,test_tx, test_ptx, rct_config);
    
      auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
      needed_fee = calculate_fee(use_per_byte_fee, test_ptx.tx, txBlob.size(), base_fee, fee_multiplier, fee_quantization_mask);
      available_for_fee = test_ptx.fee + test_ptx.change_dts.amount + (!test_ptx.dust_added_to_fee ? test_ptx.dust : 0);
      MINFO("Made a " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(available_for_fee) << " available for fee (" <<
        print_money(needed_fee) << " needed)");

      if (needed_fee > available_for_fee && !dsts.empty() && dsts[0].amount > 0)
      {
        // we don't have enough for the fee, but we've only partially paid the current address,
        // so we can take the fee from the paid amount, since we'll have to make another tx anyway
        std::vector<cryptonote::tx_destination_entry>::iterator i;
        i = std::find_if(tx.dsts.begin(), tx.dsts.end(),
          [&](const cryptonote::tx_destination_entry &d) { return !memcmp (&d.addr, &dsts[0].addr, sizeof(dsts[0].addr)); });
        THROW_WALLET_EXCEPTION_IF(i == tx.dsts.end(), error::wallet_internal_error, "paid address not found in outputs");
        if (i->amount > needed_fee)
        {
          uint64_t new_paid_amount = i->amount /*+ test_ptx.fee*/ - needed_fee;
          MINFO("Adjusting amount paid to " << get_account_address_as_str(m_nettype, i->addr) << " from " <<
            print_money(i->amount) << " to " << print_money(new_paid_amount) << " to accommodate " <<
            print_money(needed_fee) << " fee");
          dsts[0].amount += i->amount - new_paid_amount;
          i->amount = new_paid_amount;
          test_ptx.fee = needed_fee;
          available_for_fee = needed_fee;
        }
      }

      if (needed_fee > available_for_fee)
      {
        MINFO("We could not make a tx, switching to fee accumulation");

        adding_fee = true;
      }
      else
      {
        MINFO("We made a tx, adjusting fee and saving it, we need " << print_money(needed_fee) << " and we have " << print_money(test_ptx.fee));
        while (needed_fee > test_ptx.fee) {
            transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,test_tx, test_ptx, rct_config);
        
          txBlob = t_serializable_object_to_blob(test_ptx.tx);
          needed_fee = calculate_fee(use_per_byte_fee, test_ptx.tx, txBlob.size(), base_fee, fee_multiplier, fee_quantization_mask);
          MINFO("Made an attempt at a  final " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(test_ptx.fee) <<
            " fee  and " << print_money(test_ptx.change_dts.amount) << " change");
        }

        MINFO("Made a final " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(test_ptx.fee) <<
          " fee  and " << print_money(test_ptx.change_dts.amount) << " change");

        tx.tx = test_tx;
        tx.ptx = test_ptx;
        tx.weight = get_transaction_weight(test_tx, txBlob.size());
        tx.outs = outs;
        tx.needed_fee = test_ptx.fee;
        accumulated_fee += test_ptx.fee;
        accumulated_change += test_ptx.change_dts.amount;
        adding_fee = false;
        if (!dsts.empty())
        {
          MINFO("We have more to pay, starting another tx");
          txes.push_back(TX());
          original_output_index = 0;
        }
      }
    }

skip_tx:

  }

  if (adding_fee)
  {
    MINFO("We ran out of outputs while trying to gather final fee");
    THROW_WALLET_EXCEPTION_IF(1, error::tx_not_possible, unlocked_balance(false), needed_money, accumulated_fee + needed_fee);
  }

  MINFO("Done creating " << txes.size() << " transactions, " << print_money(accumulated_fee) <<
    " total fee, " << print_money(accumulated_change) << " total change");

  for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
  {
    TX &tx = *i;
    cryptonote::transaction test_tx;
    pending_tx test_ptx;
      transfer_selected_rct(tx.dsts,                    /* NOMOD std::vector<cryptonote::tx_destination_entry> dsts,*/
                            tx.selected_transfers,      /* const std::list<size_t> selected_transfers */
                            fake_outs_count,            /* CONST size_t fake_outputs_count, */
                            tx.outs,                    /* MOD   std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, */
                            unlock_time,                /* CONST uint64_t unlock_time,  */
                            tx.needed_fee,              /* CONST uint64_t fee, */
                            extra,                      /* const std::vector<uint8_t>& extra, */
                            test_tx,                    /* OUT   cryptonote::transaction& tx, */
                            test_ptx,                   /* OUT   cryptonote::transaction& tx, */
                            rct_config);

    auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
    tx.tx = test_tx;
    tx.ptx = test_ptx;
    tx.weight = get_transaction_weight(test_tx, txBlob.size());
  }

  std::vector<wallet2::pending_tx> ptx_vector;
  for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
  {
    TX &tx = *i;
    uint64_t tx_money = 0;
    for (size_t idx: tx.selected_transfers)
      tx_money += m_transfers_in[idx].amount();
    MINFO("  Transaction " << (1+std::distance(txes.begin(), i)) << "/" << txes.size() <<
      " " << get_transaction_hash(tx.ptx.tx) << ": " << get_weight_string(tx.weight) << ", sending " << print_money(tx_money) << " in " << tx.selected_transfers.size() <<
      " outputs to " << tx.dsts.size() << " destination(s), including " <<
      print_money(tx.ptx.fee) << " fee, " << print_money(tx.ptx.change_dts.amount) << " change");
    ptx_vector.push_back(tx.ptx);
  }

  THROW_WALLET_EXCEPTION_IF(!sanity_check (ptx_vector, original_dsts), error::wallet_internal_error, "Created transaction(s) failed sanity check");

  // if we made it this far, we're OK to actually send the transactions
  return ptx_vector;
}



bool wallet2::sanity_check(const std::vector<wallet2::pending_tx> &ptx_vector, std::vector<cryptonote::tx_destination_entry> dsts) const
{
  MDEBUG("sanity_check: " << ptx_vector.size() << " txes, " << dsts.size() << " destinations");

  THROW_WALLET_EXCEPTION_IF(ptx_vector.empty(), error::wallet_internal_error, "No transactions");

  // check every party in there does receive at least the required amount
  std::unordered_map<account_public_address, std::pair<uint64_t, bool>> required;
  for (const auto &d: dsts)
  {
    required[d.addr].first += d.amount;
    required[d.addr].second = false;
  }

  // add change
  uint64_t change = 0;
  for (const auto &ptx: ptx_vector)
  {
    for (size_t idx: ptx.selected_transfers)
      change += m_transfers_in[idx].amount();
    change -= ptx.fee;
  }
  for (const auto &r: required)
    change -= r.second.first;
  MDEBUG("Adding " << cryptonote::print_money(change) << " expected change");

  // for all txes that have actual change, check change is coming back to the sending wallet
  for (const pending_tx &ptx: ptx_vector)
  {
    if (ptx.change_dts.amount == 0)
      continue;
    THROW_WALLET_EXCEPTION_IF(ptx.change_dts.addr.m_spend_public_key != m_account.get_view_public_Key(),
         error::wallet_internal_error, "Change address is not ours");
    required[ptx.change_dts.addr].first += ptx.change_dts.amount;
    required[ptx.change_dts.addr].second = false;
  }

  for (const auto &r: required)
  {
    const account_public_address &address = r.first;

    uint64_t total_received = 0;
    for (const auto &ptx: ptx_vector)
    {
      uint64_t received = 0;
      try
      {
        std::string proof = get_tx_proof(ptx.tx, ptx.tx_key, address,  "automatic-sanity-check");
        check_tx_proof(ptx.tx, address,  "automatic-sanity-check", proof, received);
      }
      catch (const std::exception &e) { received = 0; }
      total_received += received;
    }

    std::stringstream ss;
    ss << "Total received by " << cryptonote::get_account_address_as_str(m_nettype,  address) << ": "
        << cryptonote::print_money(total_received) << ", expected " << cryptonote::print_money(r.second.first);
    MDEBUG(ss.str());
    THROW_WALLET_EXCEPTION_IF(total_received < r.second.first, error::wallet_internal_error, ss.str());
  }

  return true;
}



std::vector<wallet2::pending_tx> wallet2::create_transactions_all(uint64_t below, const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra)
{
  std::vector<size_t> unused_transfers_indices;
  std::vector<size_t> unused_dust_indices;
  const bool use_rct = true;

  // determine threshold for fractional amount
  const bool use_per_byte_fee =true;
  const bool bulletproof = true;
  const bool clsag = true;
  const uint64_t base_fee  = get_base_fee();
  const uint64_t fee_multiplier = get_fee_multiplier(priority, get_fee_algorithm());
  const size_t tx_weight_one_ring = estimate_tx_weight(use_rct, 1, fake_outs_count, 2, 0, bulletproof, clsag);
  const size_t tx_weight_two_rings = estimate_tx_weight(use_rct, 2, fake_outs_count, 2, 0, bulletproof, clsag);
  THROW_WALLET_EXCEPTION_IF(tx_weight_one_ring > tx_weight_two_rings, error::wallet_internal_error, "Estimated tx weight with 1 input is larger than with 2 inputs!");
  const size_t tx_weight_per_ring = tx_weight_two_rings - tx_weight_one_ring;
  const uint64_t fractional_threshold = (fee_multiplier * base_fee * tx_weight_per_ring) / (use_per_byte_fee ? 1 : 1024);

  THROW_WALLET_EXCEPTION_IF(unlocked_balance(subaddr_account, false) == 0, error::wallet_internal_error, "No unlocked balance in the specified account");

  std::map<uint32_t, std::pair<std::vector<size_t>, std::vector<size_t>>> unused_transfer_dust_indices_per_subaddr;

  // gather all dust and non-dust outputs of specified subaddress (if any) and below specified threshold (if any)
  bool fund_found = false;
  for (size_t i = 0; i < m_transfers_in.size(); ++i)
  {
    const transfer_details& td = m_transfers_in[i];
    if (m_ignore_fractional_outputs && td.amount() < fractional_threshold)
    {
      MDEBUG("Ignoring output " << i << " of amount " << print_money(td.amount()) << " which is below threshold " << print_money(fractional_threshold));
      continue;
    }
    if (!is_spent(td, false) && !td.m_frozen && !td.m_key_image_partial && is_transfer_unlocked(td)  )
    {
      fund_found = true;
      if (below == 0 || td.amount() < below)
      {
        if ((td.is_rct()) || is_valid_decomposed_amount(td.amount()))
          unused_transfer_dust_indices_per_subaddr[td.m_subaddr_index.minor].first.push_back(i);
      }
    }
  }
  THROW_WALLET_EXCEPTION_IF(!fund_found, error::wallet_internal_error, "No unlocked balance in the specified subaddress(es)");
  THROW_WALLET_EXCEPTION_IF(unused_transfer_dust_indices_per_subaddr.empty(), error::wallet_internal_error, "The smallest amount found is not below the specified threshold");


  return create_transactions_from(address, is_subaddress, outputs, unused_transfers_indices, unused_dust_indices, fake_outs_count, unlock_time, priority, extra);
}


std::vector<wallet2::pending_tx> wallet2::create_transactions_single(const crypto::key_image &ki, const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra)
{
  std::vector<size_t> unused_transfers_indices;
  std::vector<size_t> unused_dust_indices;
  const bool use_rct = use_fork_rules(4, 0);
  // find output with the given key image
  for (size_t i = 0; i < m_transfers_in.size(); ++i)
  {
    const transfer_details& td = m_transfers_in[i];
    if (td.m_key_image == ki && !is_spent(td, false) && !td.m_frozen && is_transfer_unlocked(td))
    {
        unused_transfers_indices.push_back(i);
      
      break;
    }
  }
  return create_transactions_from(address, is_subaddress, outputs, unused_transfers_indices, unused_dust_indices, fake_outs_count, unlock_time, priority, extra);
}

std::vector<wallet2::pending_tx> wallet2::create_transactions_from(const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, std::vector<size_t> unused_transfers_indices, std::vector<size_t> unused_dust_indices, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra)
{
  //ensure device is let in NONE mode in any case
  hw::device &hwdev = m_account.get_device();
  boost::unique_lock<hw::device> hwdev_lock (hwdev);
  hw::reset_mode rst(hwdev);  

  uint64_t accumulated_fee, accumulated_outputs, accumulated_change;
  struct TX {
    std::vector<size_t> selected_transfers;
    std::vector<cryptonote::tx_destination_entry> dsts;
    cryptonote::transaction tx;
    pending_tx ptx;
    size_t weight;
    uint64_t needed_fee;
    std::vector<std::vector<get_outs_entry>> outs;

    TX() : weight(0), needed_fee(0) {}
  };
  std::vector<TX> txes;
  uint64_t needed_fee, available_for_fee = 0;
  uint64_t upper_transaction_weight_limit = get_upper_transaction_weight_limit();
  std::vector<std::vector<get_outs_entry>> outs;

  const bool use_per_byte_fee = use_fork_rules(HF_VERSION_PER_BYTE_FEE);
  const bool use_rct = fake_outs_count > 0 && use_fork_rules(4, 0);
  const bool bulletproof = true;
  const bool clsag = use_fork_rules(get_clsag_fork(), 0);
  const rct::RCTConfig rct_config {
    rct::RangeProofPaddedBulletproof,3
  };
  const uint64_t base_fee  = get_base_fee();
  const uint64_t fee_multiplier = get_fee_multiplier(priority, get_fee_algorithm());
  const uint64_t fee_quantization_mask = get_fee_quantization_mask();

  MINFO("Starting with " << unused_transfers_indices.size() << " non-dust outputs and " << unused_dust_indices.size() << " dust outputs");

  if (unused_dust_indices.empty() && unused_transfers_indices.empty())
    return std::vector<wallet2::pending_tx>();

  // start with an empty tx
  txes.push_back(TX());
  accumulated_fee = 0;
  accumulated_outputs = 0;
  accumulated_change = 0;
  needed_fee = 0;

  // while we have something to send
  hwdev.set_mode(hw::device::TRANSACTION_CREATE_FAKE);
  while (!unused_dust_indices.empty() || !unused_transfers_indices.empty()) {
    TX &tx = txes.back();

    // get a random unspent output and use it to pay next chunk. We try to alternate
    // dust and non dust to ensure we never get with only dust, from which we might
    // get a tx that can't pay for itself
    uint64_t fee_dust_threshold;
    if (use_fork_rules(HF_VERSION_PER_BYTE_FEE))
    {
      const uint64_t estimated_tx_weight_with_one_extra_output = estimate_tx_weight(use_rct, tx.selected_transfers.size() + 1, fake_outs_count, tx.dsts.size()+1, extra.size(), bulletproof, clsag);
      fee_dust_threshold = calculate_fee_from_weight(base_fee, estimated_tx_weight_with_one_extra_output, fee_multiplier, fee_quantization_mask);
    }
    else
    {
      fee_dust_threshold = base_fee * fee_multiplier * (upper_transaction_weight_limit + 1023) / 1024;
    }

    size_t idx =
      unused_transfers_indices.empty()
        ? pop_best_value(unused_dust_indices, tx.selected_transfers)
      : unused_dust_indices.empty()
        ? pop_best_value(unused_transfers_indices, tx.selected_transfers)
      : ((tx.selected_transfers.size() & 1) || accumulated_outputs > fee_dust_threshold)
        ? pop_best_value(unused_dust_indices, tx.selected_transfers)
      : pop_best_value(unused_transfers_indices, tx.selected_transfers);

    const transfer_details &td = m_transfers_in[idx];
    MINFO("Picking output " << idx << ", amount " << print_money(td.amount()));

    // add this output to the list to spend
    tx.selected_transfers.push_back(idx);
    uint64_t available_amount = td.amount();
    accumulated_outputs += available_amount;

    // clear any fake outs we'd already gathered, since we'll need a new set
    outs.clear();

    // here, check if we need to sent tx and start a new one
    MINFO("Considering whether to create a tx now, " << tx.selected_transfers.size() << " inputs, tx limit "
      << upper_transaction_weight_limit);
    const size_t estimated_rct_tx_weight = estimate_tx_weight(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size() + 2, extra.size(), bulletproof, clsag);
    bool try_tx = (unused_dust_indices.empty() && unused_transfers_indices.empty()) || ( estimated_rct_tx_weight >= TX_WEIGHT_TARGET(upper_transaction_weight_limit));

    if (try_tx) {
      cryptonote::transaction test_tx;
      pending_tx test_ptx;

      const size_t num_outputs = get_num_outputs(tx.dsts, m_transfers_in, tx.selected_transfers);
      needed_fee = estimate_fee(use_per_byte_fee, use_rct, tx.selected_transfers.size(), fake_outs_count, num_outputs, extra.size(), bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask);

      // add N - 1 outputs for correct initial fee estimation
      for (size_t i = 0; i < ((outputs > 1) ? outputs - 1 : outputs); ++i)
        tx.dsts.push_back(tx_destination_entry(1, address));

      MINFO("Trying to create a tx now, with " << tx.dsts.size() << " destinations and " <<
        tx.selected_transfers.size() << " outputs");

        transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
          test_tx, test_ptx, rct_config);

      auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
      needed_fee = calculate_fee(use_per_byte_fee, test_ptx.tx, txBlob.size(), base_fee, fee_multiplier, fee_quantization_mask);
      available_for_fee = test_ptx.fee + test_ptx.change_dts.amount;
      for (auto &dt: test_ptx.dests)
        available_for_fee += dt.amount;
      MINFO("Made a " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(available_for_fee) << " available for fee (" <<
        print_money(needed_fee) << " needed)");

      // add last output, missed for fee estimation
      if (outputs > 1)
        tx.dsts.push_back(tx_destination_entry(1, address));

      THROW_WALLET_EXCEPTION_IF(needed_fee > available_for_fee, error::wallet_internal_error, "Transaction cannot pay for itself");

      do {
        MINFO("We made a tx, adjusting fee and saving it");
        // distribute total transferred amount between outputs
        uint64_t amount_transferred = available_for_fee - needed_fee;
        uint64_t dt_amount = amount_transferred / outputs;
        // residue is distributed as one atomic unit per output until it reaches zero
        uint64_t residue = amount_transferred % outputs;
        for (auto &dt: tx.dsts)
        {
          uint64_t dt_residue = 0;
          if (residue > 0)
          {
            dt_residue = 1;
            residue -= 1;
          }
          dt.amount = dt_amount + dt_residue;
        }
          transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra, 
            test_tx, test_ptx, rct_config);
  
        txBlob = t_serializable_object_to_blob(test_ptx.tx);
        needed_fee = calculate_fee(use_per_byte_fee, test_ptx.tx, txBlob.size(), base_fee, fee_multiplier, fee_quantization_mask);
        MINFO("Made an attempt at a final " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(test_ptx.fee) <<
          " fee  and " << print_money(test_ptx.change_dts.amount) << " change");
      } while (needed_fee > test_ptx.fee);

      MINFO("Made a final " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(test_ptx.fee) <<
        " fee  and " << print_money(test_ptx.change_dts.amount) << " change");

      tx.tx = test_tx;
      tx.ptx = test_ptx;
      tx.weight = get_transaction_weight(test_tx, txBlob.size());
      tx.outs = outs;
      tx.needed_fee = test_ptx.fee;
      accumulated_fee += test_ptx.fee;
      accumulated_change += test_ptx.change_dts.amount;
      if (!unused_transfers_indices.empty() || !unused_dust_indices.empty())
      {
        MINFO("We have more to pay, starting another tx");
        txes.push_back(TX());
      }
    }
  }

  MINFO("Done creating " << txes.size() << " transactions, " << print_money(accumulated_fee) <<
    " total fee, " << print_money(accumulated_change) << " total change");
 
  hwdev.set_mode(hw::device::TRANSACTION_CREATE_REAL);
  for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
  {
    TX &tx = *i;
    cryptonote::transaction test_tx;
    pending_tx test_ptx;
      transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, tx.outs, unlock_time, tx.needed_fee, extra,
        test_tx, test_ptx, rct_config);

    auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
    tx.tx = test_tx;
    tx.ptx = test_ptx;
    tx.weight = get_transaction_weight(test_tx, txBlob.size());
  }

  std::vector<wallet2::pending_tx> ptx_vector;
  for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
  {
    TX &tx = *i;
    uint64_t tx_money = 0;
    for (size_t idx: tx.selected_transfers)
      tx_money += m_transfers_in[idx].amount();
    MINFO("  Transaction " << (1+std::distance(txes.begin(), i)) << "/" << txes.size() <<
      " " << get_transaction_hash(tx.ptx.tx) << ": " << get_weight_string(tx.weight) << ", sending " << print_money(tx_money) << " in " << tx.selected_transfers.size() <<
      " outputs to " << tx.dsts.size() << " destination(s), including " <<
      print_money(tx.ptx.fee) << " fee, " << print_money(tx.ptx.change_dts.amount) << " change");
    ptx_vector.push_back(tx.ptx);
  }

  uint64_t a = 0;
  for (const TX &tx: txes)
  {
    for (size_t idx: tx.selected_transfers)
    {
      a += m_transfers_in[idx].amount();
    }
    a -= tx.ptx.fee;
  }
  std::vector<cryptonote::tx_destination_entry> synthetic_dsts(1, cryptonote::tx_destination_entry("", a, address));
  THROW_WALLET_EXCEPTION_IF(!sanity_check(ptx_vector, synthetic_dsts), error::wallet_internal_error, "Created transaction(s) failed sanity check");

  // if we made it this far, we're OK to actually send the transactions
  return ptx_vector;
}



//----------------------------------------------------------------------------------------------------
std::vector<wallet2::pending_tx> wallet2::create_unmixable_sweep_transactions()
{
  // From hard fork 1, we don't consider small amounts to be dust anymore
  const bool hf1_rules = use_fork_rules(2, 10); // first hard fork has version 2
  tx_dust_policy dust_policy(hf1_rules ? 0 : ::config::DEFAULT_DUST_THRESHOLD);

  const uint64_t base_fee  = get_base_fee();

  // may throw
  std::vector<size_t> unmixable_outputs = select_available_unmixable_outputs();
  size_t num_dust_outputs = unmixable_outputs.size();

  if (num_dust_outputs == 0)
  {
    return std::vector<wallet2::pending_tx>();
  }

  // split in "dust" and "non dust" to make it easier to select outputs
  std::vector<size_t> unmixable_transfer_outputs, unmixable_dust_outputs;
  for (auto n: unmixable_outputs)
  {
    if (m_transfers_in[n].amount() < base_fee)
      unmixable_dust_outputs.push_back(n);
    else
      unmixable_transfer_outputs.push_back(n);
  }

  return create_transactions_from(m_account_public_address, false, 1, unmixable_transfer_outputs, unmixable_dust_outputs, 0 /*fake_outs_count */, 0 /* unlock_time */, 1 /*priority */, std::vector<uint8_t>());
}
//----------------------------------------------------------------------------------------------------
std::pair<size_t, uint64_t> wallet2::estimate_tx_size_and_weight(bool use_rct, int n_inputs, int ring_size, int n_outputs, size_t extra_size)
{
  THROW_WALLET_EXCEPTION_IF(n_inputs <= 0, tools::error::wallet_internal_error, "Invalid n_inputs");
  THROW_WALLET_EXCEPTION_IF(n_outputs < 0, tools::error::wallet_internal_error, "Invalid n_outputs");
  THROW_WALLET_EXCEPTION_IF(ring_size < 0, tools::error::wallet_internal_error, "Invalid ring size");

  if (ring_size == 0)
    ring_size = get_min_ring_size();
  if (n_outputs == 1)
    n_outputs = 2; // extra dummy output

  const bool bulletproof = true;
  const bool clsag = use_fork_rules(get_clsag_fork(), 0);
  size_t size = estimate_tx_size(use_rct, n_inputs, ring_size - 1, n_outputs, extra_size, bulletproof, clsag);
  uint64_t weight = estimate_tx_weight(use_rct, n_inputs, ring_size - 1, n_outputs, extra_size, bulletproof, clsag);
  return std::make_pair(size, weight);
}


// take a pending tx and actually send it to the daemon
void wallet2::commit_tx(pending_tx& ptx)
{
  using namespace cryptonote;
  {
    // Normal submit
    COMMAND_RPC_SEND_RAW_TX::request req;
    req.tx_as_hex = epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(ptx.tx));
    req.do_not_relay = false;
    req.do_sanity_checks = true;
    COMMAND_RPC_SEND_RAW_TX::response daemon_send_resp;

    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};

      bool r = epee::net_utils::invoke_http_json("/sendrawtransaction", req, daemon_send_resp, *m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR(r, {}, daemon_send_resp, "sendrawtransaction", error::tx_rejected, ptx.tx, get_rpc_status(daemon_send_resp.status), get_text_reason(daemon_send_resp));
    }

    // sanity checks
    for (size_t idx: ptx.selected_transfers)
    {
      THROW_WALLET_EXCEPTION_IF(idx >= m_transfers_in.size(), error::wallet_internal_error,
          "Bad output index in selected transfers: " + boost::lexical_cast<std::string>(idx));
    }
  }
  crypto::hash txid= get_transaction_hash(ptx.tx);
  std::vector<cryptonote::tx_destination_entry> dests=ptx.dests;
  uint64_t amount_in = 0;
  crypto::hash payment_id  = get_payment_id(ptx);
  for(size_t idx: ptx.selected_transfers)
    amount_in += m_transfers_in[idx].amount();
  add_unconfirmed_tx(ptx.tx, amount_in, dests, payment_id, ptx.change_dts.amount);
  if ( ptx.tx_key != crypto::null_skey)
  {
    m_tx_keys[txid] = ptx.tx_key;
  }

  MINFO("transaction " << txid << " generated ok and sent to daemon, key_images: [" << ptx.key_images << "]");

  for(size_t idx: ptx.selected_transfers)
  {
    set_spent(idx, 0);
  }

  //fee includes dust if dust policy specified it.
  MINFO("Transaction successfully sent. <" << txid << ">" << ENDL
            << "Commission: " << print_money(ptx.fee) << " (dust sent to dust addr: " << print_money((ptx.dust_added_to_fee ? 0 : ptx.dust)) << ")" << ENDL
            << "Balance: " << print_money(balance(ptx.construction_data.subaddr_account, false)) << ENDL
            << "Unlocked: " << print_money(unlocked_balance(ptx.construction_data.subaddr_account, false)) << ENDL
            << "Please, wait for confirmation for your balance to be unlocked.");
}

void wallet2::commit_tx(std::vector<pending_tx>& ptx_vector)
{
  for (auto & ptx : ptx_vector)
  {
    commit_tx(ptx);
  }
}

}

