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
#include "wallet_rpc_helpers.h"
#include "wallet2.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "net/parse.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/core_rpc_server_error_codes.h"
#include "rpc/rpc_payment_signature.h"
#include "rpc/rpc_payment_costs.h"
#include "misc_language.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "multisig/multisig.h"
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
void wallet2::transfer_selected_rct(std::vector<cryptonote::tx_destination_entry> dsts, const std::vector<size_t>& selected_transfers, size_t fake_outputs_count,
  std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs,
  uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, cryptonote::transaction& tx, pending_tx &ptx, const rct::RCTConfig &rct_config)
{
  using namespace cryptonote;
  // throw if attempting a transaction with no destinations
  THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);

  uint64_t upper_transaction_weight_limit = get_upper_transaction_weight_limit();
  uint64_t needed_money = fee;
  LOG_PRINT_L2("transfer_selected_rct: starting with fee " << print_money (needed_money));
  LOG_PRINT_L2("selected transfers: " << strjoin(selected_transfers, " "));

  // calculate total amount being sent to all destinations
  // throw if total amount overflows uint64_t
  for(auto& dt: dsts)
  {
    THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_amount);
    needed_money += dt.amount;
    LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
    THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, fee, m_nettype);
  }

  // if this is a multisig wallet, create a list of multisig signers we can use
  std::deque<crypto::public_key> multisig_signers;
  size_t n_multisig_txes = 0;
  std::vector<std::unordered_set<crypto::public_key>> ignore_sets;
  if (m_multisig && !m_transfers.empty())
  {
    const crypto::public_key local_signer = get_multisig_signer_public_key();
    size_t n_available_signers = 1;

    // At this step we need to define set of participants available for signature,
    // i.e. those of them who exchanged with multisig info's
    for (const crypto::public_key &signer: m_multisig_signers)
    {
      if (signer == local_signer)
        continue;
      for (const auto &i: m_transfers[0].m_multisig_info)
      {
        if (i.m_signer == signer)
        {
          multisig_signers.push_back(signer);
          ++n_available_signers;
          break;
        }
      }
    }
    // n_available_signers includes the transaction creator, but multisig_signers doesn't
    MDEBUG("We can use " << n_available_signers << "/" << m_multisig_signers.size() <<  " other signers");
    THROW_WALLET_EXCEPTION_IF(n_available_signers < m_multisig_threshold, error::multisig_import_needed);
    if (n_available_signers > m_multisig_threshold)
    {
      // If there more potential signers (those who exchanged with multisig info)
      // than threshold needed some of them should be skipped since we don't know
      // who will sign tx and who won't. Hence we don't contribute their LR pairs to the signature.

      // We create as many transactions as many combinations of excluded signers may be.
      // For example, if we have 2/4 wallet and wallets are: A, B, C and D. Let A be
      // transaction creator, so we need just 1 signature from set of B, C, D.
      // Using "excluding" logic here we have to exclude 2-of-3 wallets. Combinations go as follows:
      // BC, BD, and CD. We save these sets to use later and counting the number of required txs.
      tools::Combinator<crypto::public_key> c(std::vector<crypto::public_key>(multisig_signers.begin(), multisig_signers.end()));
      auto ignore_combinations = c.combine(multisig_signers.size() + 1 - m_multisig_threshold);
      for (const auto& combination: ignore_combinations)
      {
        ignore_sets.push_back(std::unordered_set<crypto::public_key>(combination.begin(), combination.end()));
      }

      n_multisig_txes = ignore_sets.size();
    }
    else
    {
      // If we have exact count of signers just to fit in threshold we don't exclude anyone and create 1 transaction
      n_multisig_txes = 1;
    }
    MDEBUG("We will create " << n_multisig_txes << " txes");
  }

  bool all_rct = true;
  uint64_t found_money = 0;
  for(size_t idx: selected_transfers)
  {
    found_money += m_transfers[idx].amount();
    all_rct &= m_transfers[idx].is_rct();
  }

  LOG_PRINT_L2("wanted " << print_money(needed_money) << ", found " << print_money(found_money) << ", fee " << print_money(fee));
  THROW_WALLET_EXCEPTION_IF(found_money < needed_money, error::not_enough_unlocked_money, found_money, needed_money - fee, fee);

  uint32_t subaddr_account = m_transfers[*selected_transfers.begin()].m_subaddr_index.major;
  for (auto i = ++selected_transfers.begin(); i != selected_transfers.end(); ++i)
    THROW_WALLET_EXCEPTION_IF(subaddr_account != m_transfers[*i].m_subaddr_index.major, error::wallet_internal_error, "the tx uses funds from multiple accounts");

  if (outs.empty())
    get_outs(outs, selected_transfers, fake_outputs_count, all_rct); // may throw


  //prepare inputs
  LOG_PRINT_L2("preparing outputs");
  size_t i = 0, out_index = 0;
  std::vector<cryptonote::tx_source_entry> sources;
  std::unordered_set<rct::key> used_L;
  for(size_t idx: selected_transfers)
  {
    sources.resize(sources.size()+1);
    cryptonote::tx_source_entry& src = sources.back();
    const transfer_details& td = m_transfers[idx];
    src.amount = td.amount();
    src.rct = td.is_rct();
    //paste mixin transaction

    THROW_WALLET_EXCEPTION_IF(outs.size() < out_index + 1 ,  error::wallet_internal_error, "outs.size() < out_index + 1"); 
    THROW_WALLET_EXCEPTION_IF(outs[out_index].size() < fake_outputs_count ,  error::wallet_internal_error, "fake_outputs_count > random outputs found");
      
    typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
    for (size_t n = 0; n < fake_outputs_count + 1; ++n)
    {
      tx_output_entry oe;
      oe.first = std::get<0>(outs[out_index][n]);
      oe.second.dest = rct::pk2rct(std::get<1>(outs[out_index][n]));
      oe.second.mask = std::get<2>(outs[out_index][n]);
      src.outputs.push_back(oe);
    }
    ++i;

    //paste real transaction to the random index
    auto it_to_replace = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
    {
      return a.first == td.m_global_output_index;
    });
    THROW_WALLET_EXCEPTION_IF(it_to_replace == src.outputs.end(), error::wallet_internal_error,
        "real output not found");

    tx_output_entry real_oe;
    real_oe.first = td.m_global_output_index;
    real_oe.second.dest = rct::pk2rct(td.get_public_key());
    real_oe.second.mask = rct::commit(td.amount(), td.m_mask);
    *it_to_replace = real_oe;
    src.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
    src.real_out_additional_tx_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);
    src.real_output = it_to_replace - src.outputs.begin();
    src.real_output_in_tx_index = td.m_internal_output_index;
    src.mask = td.m_mask;
    if (m_multisig)
    {
      auto ignore_set = ignore_sets.empty() ? std::unordered_set<crypto::public_key>() : ignore_sets.front();
      src.multisig_kLRki = get_multisig_composite_kLRki(idx, ignore_set, used_L, used_L);
    }
    else
      src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
    detail::print_source_entry(src);
    ++out_index;
  }
  LOG_PRINT_L2("outputs prepared");

  // we still keep a copy, since we want to keep dsts free of change for user feedback purposes
  std::vector<cryptonote::tx_destination_entry> splitted_dsts = dsts;
  cryptonote::tx_destination_entry change_dts = AUTO_VAL_INIT(change_dts);
  change_dts.amount = found_money - needed_money;
  if (change_dts.amount == 0)
  {
    if (splitted_dsts.size() == 1)
    {
      // If the change is 0, send it to a random address, to avoid confusing
      // the sender with a 0 amount output. We send a 0 amount in order to avoid
      // letting the destination be able to work out which of the inputs is the
      // real one in our rings
      LOG_PRINT_L2("generating dummy address for 0 change");
      cryptonote::account_base dummy;
      dummy.generate();
      change_dts.addr = dummy.get_keys().m_account_address;
      LOG_PRINT_L2("generated dummy address for 0 change");
      splitted_dsts.push_back(change_dts);
    }
  }
  else
  {
    change_dts.addr = get_subaddress({subaddr_account, 0});
    change_dts.is_subaddress = subaddr_account != 0;
    splitted_dsts.push_back(change_dts);
  }

  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;
  rct::multisig_out msout;
  LOG_PRINT_L2("constructing tx");
  auto sources_copy = sources;
  bool r = cryptonote::construct_tx_and_get_tx_key(m_account.get_keys(), m_subaddresses, sources, splitted_dsts, change_dts.addr, extra, tx, unlock_time, tx_key, additional_tx_keys, true, rct_config, m_multisig ? &msout : NULL);
  LOG_PRINT_L2("constructed tx, r="<<r);
  THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, dsts, unlock_time, m_nettype);
  THROW_WALLET_EXCEPTION_IF(upper_transaction_weight_limit <= get_transaction_weight(tx), error::tx_too_big, tx, upper_transaction_weight_limit);

  // work out the permutation done on sources
  std::vector<size_t> ins_order;
  for (size_t n = 0; n < sources.size(); ++n)
  {
    for (size_t idx = 0; idx < sources_copy.size(); ++idx)
    {
      THROW_WALLET_EXCEPTION_IF((size_t)sources_copy[idx].real_output >= sources_copy[idx].outputs.size(),
          error::wallet_internal_error, "Invalid real_output");
      if (sources_copy[idx].outputs[sources_copy[idx].real_output].second.dest == sources[n].outputs[sources[n].real_output].second.dest)
        ins_order.push_back(idx);
    }
  }
  THROW_WALLET_EXCEPTION_IF(ins_order.size() != sources.size(), error::wallet_internal_error, "Failed to work out sources permutation");

  std::vector<tools::wallet2::multisig_sig> multisig_sigs;
  cout<<"m_multisig"<<m_multisig<<endl;
  if (m_multisig)
  {
    auto ignore = ignore_sets.empty() ? std::unordered_set<crypto::public_key>() : ignore_sets.front();
    multisig_sigs.push_back({tx.rct_signatures, ignore, used_L, std::unordered_set<crypto::public_key>(), msout});

    if (m_multisig_threshold < m_multisig_signers.size())
    {
      const crypto::hash prefix_hash = cryptonote::get_transaction_prefix_hash(tx);

      // create the other versions, one for every other participant (the first one's already done above)
      for (size_t ignore_index = 1; ignore_index < ignore_sets.size(); ++ignore_index)
      {
        std::unordered_set<rct::key> new_used_L;
        size_t src_idx = 0;
        THROW_WALLET_EXCEPTION_IF(selected_transfers.size() != sources.size(), error::wallet_internal_error, "mismatched selected_transfers and sources sixes");
        for(size_t idx: selected_transfers)
        {
          cryptonote::tx_source_entry& src = sources_copy[src_idx];
          src.multisig_kLRki = get_multisig_composite_kLRki(idx, ignore_sets[ignore_index], used_L, new_used_L);
          ++src_idx;
        }

        LOG_PRINT_L2("Creating supplementary multisig transaction");
        cryptonote::transaction ms_tx;
        auto sources_copy_copy = sources_copy;
        bool r = cryptonote::construct_tx_with_tx_key(m_account.get_keys(), m_subaddresses, sources_copy_copy, splitted_dsts, change_dts.addr, extra, ms_tx, unlock_time,tx_key, additional_tx_keys, true, rct_config, &msout, false);
        LOG_PRINT_L2("constructed tx, r="<<r);
        THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, splitted_dsts, unlock_time, m_nettype);
        THROW_WALLET_EXCEPTION_IF(upper_transaction_weight_limit <= get_transaction_weight(tx), error::tx_too_big, tx, upper_transaction_weight_limit);
        THROW_WALLET_EXCEPTION_IF(cryptonote::get_transaction_prefix_hash(ms_tx) != prefix_hash, error::wallet_internal_error, "Multisig txes do not share prefix");
        multisig_sigs.push_back({ms_tx.rct_signatures, ignore_sets[ignore_index], new_used_L, std::unordered_set<crypto::public_key>(), msout});

        ms_tx.rct_signatures = tx.rct_signatures;
        THROW_WALLET_EXCEPTION_IF(cryptonote::get_transaction_hash(ms_tx) != cryptonote::get_transaction_hash(tx), error::wallet_internal_error, "Multisig txes differ by more than the signatures");
      }
    }
  }

  LOG_PRINT_L2("gathering key images");
  std::string key_images;
  bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
  {
    CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
    key_images += boost::to_string(in.k_image) + " ";
    return true;
  });
  THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, tx);
  LOG_PRINT_L2("gathered key images " + std::to_string(tx.vin.size()));

  ptx.key_images = key_images;
  ptx.fee = fee;
  ptx.dust = 0;
  ptx.dust_added_to_fee = false;
  ptx.tx = tx;
  ptx.change_dts = change_dts;
  ptx.selected_transfers = selected_transfers;
  tools::apply_permutation(ins_order, ptx.selected_transfers);
  ptx.tx_key = tx_key;
  ptx.additional_tx_keys = additional_tx_keys;
  ptx.dests = dsts;
  ptx.multisig_sigs = multisig_sigs;
  ptx.construction_data.sources = sources_copy;
  ptx.construction_data.change_dts = change_dts;
  ptx.construction_data.splitted_dsts = splitted_dsts;
  ptx.construction_data.selected_transfers = ptx.selected_transfers;
  ptx.construction_data.extra = tx.extra;
  ptx.construction_data.unlock_time = unlock_time;
  ptx.construction_data.use_rct = true;
  ptx.construction_data.rct_config = {
    tx.rct_signatures.p.bulletproofs.empty() ? rct::RangeProofBorromean : rct::RangeProofPaddedBulletproof,
    use_fork_rules(HF_VERSION_CLSAG, -10) ? 3 : use_fork_rules(HF_VERSION_SMALLER_BP, -10) ? 2 : 1
  };
  ptx.construction_data.dests = dsts;
  // record which subaddress indices are being used as inputs
  ptx.construction_data.subaddr_account = subaddr_account;
  ptx.construction_data.subaddr_indices.clear();
  for (size_t idx: selected_transfers)
    ptx.construction_data.subaddr_indices.insert(m_transfers[idx].m_subaddr_index.minor);
  LOG_PRINT_L2("transfer_selected_rct done");
}

}