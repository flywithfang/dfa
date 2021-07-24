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

namespace tools
{
wallet2::pending_tx wallet2::transfer_selected_rct(const cryptonote::tx_destination_entry & dt, const std::vector<size_t>& selected_transfers, size_t fake_outputs_count,  std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs,  uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra)
{
  using namespace cryptonote;

  cryptonote::transaction tx;
   pending_tx ptx;

  // throw if attempting a transaction with no destinations
  uint64_t needed_money = fee;
  MINFO("transfer_selected_rct: starting with fee " << print_money (needed_money));
  MINFO("selected transfers: " << strjoin(selected_transfers, " "));

  // calculate total amount being sent to all destinations
  // throw if total amount overflows uint64_t
  {
    THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_amount);
    needed_money += dt.amount;
    MINFO("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
    THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dt, fee, m_nettype);
  }

  uint64_t found_money = 0;
  for(size_t idx: selected_transfers)
  {
    found_money += m_transfers_in[idx].amount();
  }

  MINFO("wanted " << print_money(needed_money) << ", found " << print_money(found_money) << ", fee " << print_money(fee));
  THROW_WALLET_EXCEPTION_IF(found_money < needed_money, error::not_enough_unlocked_money, found_money, needed_money - fee, fee);

  if (outs.empty())
     get_outs(outs, selected_transfers, fake_outputs_count); // may throw

  //prepare inputs
  MINFO("preparing outputs");
  size_t dst_index = 0;
  std::vector<cryptonote::tx_source_entry> sources;
  for(size_t idx: selected_transfers)
  {
    sources.resize(sources.size()+1);
    cryptonote::tx_source_entry& in = sources.back();
    const transfer_details& td = m_transfers_in[idx];
    in.amount = td.amount();
    //paste mixin transaction

    THROW_WALLET_EXCEPTION_IF(outs.size() < dst_index + 1 ,  error::wallet_internal_error, "outs.size() < dst_index + 1"); 
    THROW_WALLET_EXCEPTION_IF(outs[dst_index].size() < fake_outputs_count ,  error::wallet_internal_error, "fake_outputs_count > random outputs found");
      
    typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
    for (size_t i = 0; i < fake_outputs_count + 1; ++i)
    {
      tx_output_entry decoy;
      auto [oindex,otk,commitment]=outs[dst_index][i];
      decoy.first = oindex;
      rct::ctkey &ct=  decoy.second;
      ct.otk = rct::pk2rct(otk);
      ct.commitment = commitment;
      in.decoys.push_back(decoy);
    }

    //paste real transaction to the random index
    auto it_real = std::find_if(in.decoys.begin(), in.decoys.end(), [&](const tx_output_entry& a)
    {
      return a.first == td.m_global_output_index;
    });
    THROW_WALLET_EXCEPTION_IF(it_real == in.decoys.end(), error::wallet_internal_error,"real output not found");

    in.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx);
    in.real_output = it_real - in.decoys.begin();
    in.real_output_in_tx_index = td.m_internal_output_index;
    in.noise = td.m_noise;
   
    detail::print_source_entry(in);
    ++dst_index;
  }
  MINFO("outputs prepared");

  // we still keep a copy, since we want to keep dsts free of change for user feedback purposes
  std::vector<cryptonote::tx_destination_entry> splitted_dsts={dt};
  cryptonote::tx_destination_entry change_dts {};
  change_dts.amount = found_money - needed_money;
  if (change_dts.amount > 0)
  {
    change_dts.addr = m_account.get_keys().m_account_address;
    splitted_dsts.push_back(change_dts);
  }

  crypto::secret_key tx_sec;
  MINFO("constructing tx");
  auto sources_copy = sources;
  bool r = cryptonote::construct_tx_and_get_tx_key(m_account.get_keys(),  sources, splitted_dsts, change_dts.addr, extra, tx, unlock_time, tx_sec);
  MINFO("constructed tx, r="<<r);
  THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, dt, unlock_time, m_nettype);

  // work out the permutation done on sources
  std::vector<size_t> ins_order;
  for (size_t n = 0; n < sources.size(); ++n)
  {
     const auto & ne =sources[n];
    for (size_t j = 0; j < sources_copy.size(); ++j)
    {
        const auto & old=sources_copy[j];
      THROW_WALLET_EXCEPTION_IF((size_t)old.real_output >= old.decoys.size(),error::wallet_internal_error, "Invalid real_output");
    
      if (old.decoys[old.real_output].second.otk == ne.decoys[ne.real_output].second.otk)
        ins_order.push_back(j);
    }
  }
  THROW_WALLET_EXCEPTION_IF(ins_order.size() != sources.size(), error::wallet_internal_error, "Failed to work out sources permutation");

  MINFO("gathering key images");
  std::string key_images;
  bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
  {
    CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
    key_images += boost::to_string(in.k_image) + " ";
    return true;
  });
  THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, tx);
  MINFO("gathered key images " + std::to_string(tx.vin.size()));

  ptx.key_images = key_images;
  ptx.fee = fee;
  ptx.tx = tx;
  ptx.change_dts = change_dts;
  ptx.selected_transfers = selected_transfers;
  tools::apply_permutation(ins_order, ptx.selected_transfers);
  ptx.tx_sec = tx_sec;
  ptx.dst = dt;

  // record which subaddress indices are being used as inputs
  MINFO("transfer_selected_rct done");

  return ptx;
}


//----------------------------------------------------------------------------------------------------
bool wallet2::get_rct_distribution(uint64_t &start_height, std::vector<uint64_t> &distribution)
{
  cryptonote::COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request req {};
  cryptonote::COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response res{};
  req.from_height = 0;
  req.cumulative = false;
  req.binary = true;
  req.compress = true;

  bool r;
  try
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};

    r = net_utils::invoke_http_bin("/get_output_distribution.bin", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "/get_output_distribution.bin");
  }
  catch(...)
  {
    return false;
  }

  for (size_t i = 1; i < res.dist.data.distribution.size(); ++i)
    res.dist.data.distribution[i] += res.dist.data.distribution[i-1];

  start_height = res.dist.data.start_height;
  distribution = std::move(res.dist.data.distribution);
  return true;
}
}