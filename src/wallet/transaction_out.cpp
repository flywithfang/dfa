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

std::pair<std::set<uint64_t>, size_t> outs_unique(const std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs)
{
  std::set<uint64_t> unique;
  size_t total = 0;

  for (const auto &it : outs)
  {
    total += it.size();
    for (const auto &out : it)
    {
      const uint64_t global_index = std::get<0>(out);
      unique.insert(global_index);
    }
    
  }

  return std::make_pair(std::move(unique), total);
}

void wallet2::get_outs(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count)
{
  std::vector<uint64_t> rct_offsets;
  for (size_t attempts = 3; attempts > 0; --attempts)
  {
    outs= get_outs(selected_transfers, fake_outputs_count, rct_offsets);

    const auto unique = outs_unique(outs);
    if (tx_sanity_check(unique.first, unique.second, rct_offsets.empty() ? 0 : rct_offsets.back()))
    {
      return;
    }

 
  }

  THROW_WALLET_EXCEPTION(error::wallet_internal_error, tr("Transaction sanity check failed"));
}

std::vector<std::vector<tools::wallet2::get_outs_entry>>  wallet2::get_outs( const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, std::vector<uint64_t> &rct_offsets)
{
  MINFO("fake_outputs_count: " << fake_outputs_count);
  std::vector<std::vector<tools::wallet2::get_outs_entry>> outs;

  if (fake_outputs_count > 0)
  {
    // check whether we're shortly after the fork
    uint64_t height;
    boost::optional<std::string> result = m_node_rpc_proxy.get_height(height);
    THROW_WALLET_EXCEPTION_IF(result, error::wallet_internal_error, "Failed to get height");

    // if we have at least one rct out, get the distribution, or fall back to the previous system
    uint64_t rct_start_height;
    uint64_t max_rct_index = 0;
    for (size_t idx: selected_transfers)
      {
        max_rct_index = std::max(max_rct_index, m_transfers_in[idx].m_global_output_index);
      }
    const bool has_rct_distribution = (!rct_offsets.empty() || get_rct_distribution(rct_start_height, rct_offsets));
    if(!has_rct_distribution) return outs;

    {
      // check we're clear enough of rct start, to avoid corner cases below
      THROW_WALLET_EXCEPTION_IF(rct_offsets.size() <= CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
          error::get_output_distribution, "Not enough rct outputs");
      THROW_WALLET_EXCEPTION_IF(rct_offsets.back() <= max_rct_index,
          error::get_output_distribution, "Daemon reports suspicious number of rct outputs");
    }

    // if we want to segregate fake outs pre or post fork, get distribution
    std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> segregation_limit;


    // we ask for more, to have spares if some outputs are still locked
    size_t base_requested_outputs_count = (size_t)((fake_outputs_count + 1) * 1.5 + 1);
    MINFO("base_requested_outputs_count: " << base_requested_outputs_count);

    // generate output indices to request
    COMMAND_RPC_GET_OUTPUTS_BIN::request req{};
   

    std::unique_ptr<gamma_picker> gamma;
    if (has_rct_distribution)
      gamma.reset(new gamma_picker(rct_offsets));

    size_t num_selected_transfers = 0;
    for(size_t idx: selected_transfers)
    {
      ++num_selected_transfers;
      const transfer_details &td = m_transfers_in[idx];
      std::unordered_set<uint64_t> seen_indices;
      // request more for rct in base recent (locked) coinbases are picked, since they're locked for longer
      size_t requested_outputs_count = base_requested_outputs_count +CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE ;
      size_t start = req.outputs.size();
      uint64_t num_outs = 0;
     
      {
        // the base offset of the first rct output in the first unlocked block (or the one to be if there's none)
        num_outs = rct_offsets[rct_offsets.size() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE];
        MINFO("" << num_outs << " unlocked rct outputs");
        THROW_WALLET_EXCEPTION_IF(num_outs == 0, error::wallet_internal_error,
            "histogram reports no unlocked rct outputs, not even ours");
      }

      size_t recent_outputs_count = 0;
     
      MINFO("Fake output makeup: " << requested_outputs_count << " requested: " << recent_outputs_count  <<
          (requested_outputs_count - recent_outputs_count ) << " full-chain");

      uint64_t num_found = 0;

      if (num_outs <= requested_outputs_count)
      {
        for (uint64_t i = 0; i < num_outs; i++)
          req.outputs.push_back({ i});
        // duplicate to make up shortfall: this will be caught after the RPC call,
        // so we can also output the amounts for which we can't reach the required
        // mixin after checking the actual unlockedness
        for (uint64_t i = num_outs; i < requested_outputs_count; ++i)
          req.outputs.push_back({ num_outs - 1});
      }
      else
      {
        // start with real one
        if (num_found == 0)
        {
          num_found = 1;
          seen_indices.emplace(td.m_global_output_index);
          req.outputs.push_back({0, td.m_global_output_index});
          MINFO("Selecting real output: " << td.m_global_output_index );
        }

        std::unordered_map<const char*, std::set<uint64_t>> picks;

        // while we still need more mixins
        uint64_t num_usable_outs = num_outs;
        bool allow_blackballed = false;
        MDEBUG("Starting gamma picking with " << num_outs << ", num_usable_outs " << num_usable_outs
            << ", requested_outputs_count " << requested_outputs_count);
        while (num_found < requested_outputs_count)
        {
          // if we've gone through every possible output, we've gotten all we can
          if (seen_indices.size() == num_usable_outs)
          {
            // there is a first pass which rejects blackballed outputs, then a second pass
            // which allows them if we don't have enough non blackballed outputs to reach
            // the required amount of outputs (since consensus does not care about blackballed
            // outputs, we still need to reach the minimum ring size)
            if (allow_blackballed)
              break;
            MINFO("Not enough output not marked as spent, we'll allow outputs marked as spent");
            allow_blackballed = true;
            num_usable_outs = num_outs;
          }

          // get a random output index from the DB.  If we've already seen it,
          // return to the top of the loop and try again, otherwise add it to the
          // list of output indices we've seen.

          uint64_t i;
          const char *type = "";
          {
            THROW_WALLET_EXCEPTION_IF(!gamma, error::wallet_internal_error, "No gamma picker");
            // gamma distribution
            {
              do i = gamma->pick(); while (i >= num_outs);
              type = "gamma";
            }
          }
       
          if (seen_indices.count(i))
            continue;
      
          seen_indices.emplace(i);

          picks[type].insert(i);
          req.outputs.push_back({ i});
          ++num_found;
          MDEBUG("picked " << i << ", " << num_found << " now picked");
        }

        for (const auto &pick: picks)
          MDEBUG("picking " << pick.first << " outputs: " <<
              boost::join(pick.second | boost::adaptors::transformed([](uint64_t out){return std::to_string(out);}), " "));

        // if we had enough unusable outputs, we might fall off here and still
        // have too few outputs, so we stuff with one to keep counts good, and
        // we'll error out later
        while (num_found < requested_outputs_count)
        {
          req.outputs.push_back({ 0});
          ++num_found;
        }
      }

      // sort the subsection, to ensure the daemon doesn't know which output is ours
      std::sort(req.outputs.begin() + start, req.outputs.end(),
          [](const get_outputs_out &a, const get_outputs_out &b) { return a.index < b.index; });
    }

    // get the keys for those
    req.get_txid = false;

    COMMAND_RPC_GET_OUTPUTS_BIN::response daemon_resp {};
    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};

      bool r = epee::net_utils::invoke_http_bin("/get_outs.bin", req, daemon_resp, *m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR(r, {}, daemon_resp, "get_outs.bin", error::get_outs_error, get_rpc_status(daemon_resp.status));
      THROW_WALLET_EXCEPTION_IF(daemon_resp.outs.size() != req.outputs.size(), error::wallet_internal_error,
        "daemon returned wrong response for get_outs.bin, wrong amounts count = " +
        std::to_string(daemon_resp.outs.size()) + ", expected " +  std::to_string(req.outputs.size()));
    }

    std::unordered_map<uint64_t, uint64_t> scanty_outs;
    size_t base = 0;
    outs.reserve(num_selected_transfers);
    for(size_t idx: selected_transfers)
    {
      const transfer_details &td = m_transfers_in[idx];
      size_t requested_outputs_count = base_requested_outputs_count + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE ;
      outs.push_back(std::vector<get_outs_entry>());
      auto & decoys= outs.back();
      decoys.reserve(fake_outputs_count + 1);
      const rct::key commitment =  rct::commit(td.amount(), td.m_noise) ;
      const auto & otk=boost::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key;
      //uint64_t num_outs  = rct_offsets[rct_offsets.size() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE];

      // make sure the real outputs we asked for are really included, along
      // with the correct key and mask: this guards against an active attack
      // where the node sends dummy data for all outputs, and we then send
      // the real one, which the node can then tell from the fake outputs,
      // as it has different data than the dummy data it had sent earlier
      bool real_out_found = false;
      for (size_t n = 0; n < requested_outputs_count; ++n)
      {
        size_t i = base + n;
        if (req.outputs[i].index == td.m_global_output_index)
          if (daemon_resp.outs[i].key == otk)
            if (daemon_resp.outs[i].commitment == commitment)
              real_out_found = true;
      }
      THROW_WALLET_EXCEPTION_IF(!real_out_found, error::wallet_internal_error,
          "Daemon response did not include the requested real output");

      // pick real out first (it will be sorted when done)
     decoys.push_back(std::make_tuple(td.m_global_output_index,otk, commitment));


      // then pick others in random order till we reach the required number
      // since we use an equiprobable pick here, we don't upset the triangular distribution
      std::vector<size_t> order;
      order.resize(requested_outputs_count);
      for (size_t n = 0; n < order.size(); ++n)
        order[n] = n;
      std::shuffle(order.begin(), order.end(), crypto::random_device{});

      MINFO("Looking for " << (fake_outputs_count+1) );
      for (size_t o = 0; o < requested_outputs_count && decoys.size() < fake_outputs_count + 1; ++o)
      {
        size_t i = base + order[o];
         const auto & decoy = daemon_resp.outs[i];
         const auto decoy_global_o_index=req.outputs[i].index;
        MINFO("Index " << i << "/" << requested_outputs_count << ": idx " <<decoy_global_o_index << " (real " << td.m_global_output_index << "), unlocked " << decoy.unlocked << ", key " << decoy.key);
       

        tx_add_fake_output(outs, decoy_global_o_index, decoy.key, decoy.commitment, td.m_global_output_index, decoy.unlocked);
      }
      if (decoys.size() < fake_outputs_count + 1)
      {
        scanty_outs[ 0 ] = outs.back().size();
      }
      else
      {
        // sort the subsection, so any spares are reset in order
        std::sort(decoys.begin(), decoys.end(), [](const get_outs_entry &a, const get_outs_entry &b) { return std::get<0>(a) < std::get<0>(b); });
      }
      base += requested_outputs_count;
    }
    THROW_WALLET_EXCEPTION_IF(!scanty_outs.empty(), error::not_enough_outs_to_mix, scanty_outs, fake_outputs_count);
  }
  else
  {
    for (size_t idx: selected_transfers)
    {
      const transfer_details &td = m_transfers_in[idx];
      std::vector<get_outs_entry> v;
      const rct::key commit =  rct::commit(td.amount(), td.m_noise);
      v.push_back({td.m_global_output_index, td.otk(), commit});
      outs.push_back(v);
    }
  }
  return outs;

}

bool wallet2::tx_add_fake_output(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, uint64_t global_index, const crypto::public_key& otk, const rct::key& commit, uint64_t real_index, bool unlocked) const
{
  if (!unlocked) // don't add locked outs
    return false;
  if (global_index == real_index) // don't re-add real one
    return false;
  auto item = std::make_tuple(global_index, otk, commit);
  CHECK_AND_ASSERT_MES(!outs.empty(), false, "internal error: outs is empty");
  if (std::find(outs.back().begin(), outs.back().end(), item) != outs.back().end()) // don't add duplicates
    return false;
  // check the keys are valid
  if (!rct::isInMainSubgroup(rct::pk2rct(otk)))
  {
    MWARNING("Key " << otk << " at index " << global_index << " is not in the main subgroup");
    return false;
  }
  if (!rct::isInMainSubgroup(commit))
  {
    MWARNING("Commitment " << commit << " at index " << global_index << " is not in the main subgroup");
    return false;
  }
//  if (is_output_blackballed(output_public_key)) // don't add blackballed outputs
//    return false;
  outs.back().push_back(item);
  return true;
}


}