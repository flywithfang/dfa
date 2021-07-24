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

  const static int BATCH=8;

namespace tools
{
   struct TX {
    std::vector<size_t> selected;
    cryptonote::tx_destination_entry dst;
  
    uint64_t fee;
    std::vector<std::vector<tools::wallet2::get_outs_entry>> outs;

    TX() : fee(0) {}
  };
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


//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_base_fee()
{
    return FEE_PER_KB;

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
std::vector<wallet2::pending_tx> wallet2::transfer(cryptonote::tx_destination_entry dt, const size_t fake_outs_count, const uint64_t unlock_time, const std::vector<uint8_t>& extra)
{
   std::vector<wallet2::pending_tx> ptx_vector;
  cout<<"transfer "<<fake_outs_count<<","<<unlock_time<<","<<endl;
  cout<<"extra "<<extra<<endl;
{
    cout<<"dst "<<","<<dt.amount<<","<<dt.addr.m_view_public_key<<endl;
  }
  
  //ensure device is let in NONE mode in any case
  hw::device &hwdev = m_account.get_device();
    THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_amount);
  // early out if we know we can't make it anyway
  // we could also check for being within FEE_PER_KB, but if the fee calculation
  // ever changes, this might be missed, so let this go through
  const uint64_t fee = get_base_fee();
  std::vector<size_t> unused;
  uint64_t unlocked_balance=0;
  for (size_t i = 0; i < m_transfers_in.size(); ++i)
  {
    const auto& td = m_transfers_in[i];
    if (!is_spent(td) && is_transfer_unlocked(td))
    {
        unused.push_back(i);
        unlocked_balance += td.amount();
    }
  }

  const auto total_need= dt.amount+fee;
  // first check overall balance is enough, then unlocked one, so we throw distinct exceptions
  THROW_WALLET_EXCEPTION_IF(dt.amount > unlocked_balance, error::not_enough_unlocked_money,unlocked_balance, dt.amount, 0);

  MINFO("Starting with " << unused.size() );

  if (unused.empty())
    return ptx_vector;

  std::sort(unused.begin(),unused.end(),[&](const auto &a,const size_t & b){
    const auto& td1=m_transfers_in[a]; const auto & td2=m_transfers_in[b];
    return td1.amount()<td2.amount();
  });
// while we have something to send
  hwdev.set_mode(hw::device::TRANSACTION_CREATE_REAL);
  std::vector<TX> txes;
   txes.emplace_back();
   TX &tx = txes.back();
   tx.fee=get_base_fee();
   tx.dst = dt;
   uint64_t total =0;
   for(auto i : unused){
       const auto& td=m_transfers_in[i];
        tx.selected.push_back(i);
        total += td.amount();
        if(total>=total_need)
          break;
    }

  for (auto &tx : txes)
  {
     auto ptx= transfer_selected_rct(tx.dst, tx.selected, fake_outs_count, tx.outs, unlock_time, tx.fee, extra);

    ptx_vector.push_back(ptx);
  }
  return ptx_vector;
}

std::vector<wallet2::pending_tx> wallet2::__sweep(const cryptonote::account_public_address &addr,std::vector<size_t> selected, const uint64_t unlock_time, const std::vector<uint8_t>& extra,const size_t fake_outs_count)
{
  std::vector<wallet2::pending_tx> ptx_vector;
   //ensure device is let in NONE mode in any case
  hw::device &hwdev = m_account.get_device();
  
  // while we have something to send
  hwdev.set_mode(hw::device::TRANSACTION_CREATE_REAL);

      TX tx;
      tx.fee=get_base_fee();
      uint64_t total=0;
      tx_destination_entry dst{0,addr};

      for(auto i: selected){
        // add this output to the list to spend
        tx.selected.push_back(i);
        const auto & td = m_transfers_in[i];
        total += td.amount();
      }

    if(total<=tx.fee)
      return ptx_vector;

    tx.dst.amount = total-tx.fee;

  {
     auto ptx= transfer_selected_rct(tx.dst, tx.selected, fake_outs_count, tx.outs, unlock_time, tx.fee, extra);

    ptx_vector.push_back(ptx);
  }

  // if we made it this far, we're OK to actually send the transactions
  return ptx_vector;
}


std::vector<wallet2::pending_tx> wallet2::sweep_transfers(uint64_t below, const cryptonote::account_public_address &address,   const size_t fake_outs_count, const uint64_t unlock_time, const std::vector<uint8_t>& extra)
{
  THROW_WALLET_EXCEPTION_IF(unlocked_balance() == 0, error::wallet_internal_error, "No unlocked balance in the specified account");

  std::vector<size_t> selected;

  // gather all dust and non-dust outputs of specified subaddress (if any) and below specified threshold (if any)
  for (size_t i = 0; i < m_transfers_in.size(); ++i)
  {
    const transfer_details& td = m_transfers_in[i];
   
    if (!is_spent(td)  && is_transfer_unlocked(td)  )
    {
      if (below == 0 || td.amount() < below)
      {
          selected.push_back(i);
      }
    }
  }
  THROW_WALLET_EXCEPTION_IF(selected.empty(), error::wallet_internal_error, "The smallest amount found is not below the specified threshold");

  return __sweep(address,selected,unlock_time,extra,fake_outs_count);
 
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
  cryptonote::tx_destination_entry dst=ptx.dst;
  uint64_t amount_in = 0;
  for(size_t idx: ptx.selected_transfers)
    amount_in += m_transfers_in[idx].amount();

  add_unconfirmed_tx(ptx.tx, amount_in, dst,  ptx.change_dts.amount);
  if ( ptx.tx_sec != crypto::null_skey)
  {
    m_tx_secs[txid] = ptx.tx_sec;
  }

  MINFO("transaction " << txid << " generated ok and sent to daemon, key_images: [" << ptx.key_images << "]");

  for(size_t idx: ptx.selected_transfers)
  {
    set_spent(idx, 0);
  }

  //fee includes dust if dust policy specified it.
  MINFO("Transaction successfully sent. <" << txid << ">" << ENDL
            << "Commission: " << print_money(ptx.fee)  << ")" << ENDL
            << "Balance: " << print_money(balance()) << ENDL
            << "Unlocked: " << print_money(unlocked_balance()) << ENDL
            << "Please, wait for confirmation for your balance to be unlocked.");
}

void wallet2::commit_tx(std::vector<pending_tx>& ptx_vector)
{
  for (auto & ptx : ptx_vector)
  {
    commit_tx(ptx);
  }
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
    THROW_WALLET_EXCEPTION_IF(ptx.change_dts.addr.m_spend_public_key != m_account.get_spend_public_key(),
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
        std::string proof = get_tx_proof(ptx.tx, ptx.tx_sec, address,  "automatic-sanity-check");
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

}

