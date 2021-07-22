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

std::pair<std::set<uint64_t>, size_t> outs_unique(const std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs)
{
  std::set<uint64_t> unique;
  size_t total = 0;

  for (const auto &it : outs)
  {
    for (const auto &out : it)
    {
      const uint64_t global_index = std::get<0>(out);
      unique.insert(global_index);
    }
    total += it.size();
  }

  return std::make_pair(std::move(unique), total);
}

void wallet2::get_outs(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, bool rct)
{
  std::vector<uint64_t> rct_offsets;
  for (size_t attempts = 3; attempts > 0; --attempts)
  {
    get_outs(outs, selected_transfers, fake_outputs_count, rct_offsets);

    const auto unique = outs_unique(outs);
    if (tx_sanity_check(unique.first, unique.second, rct_offsets.empty() ? 0 : rct_offsets.back()))
    {
      return;
    }

    std::vector<crypto::key_image> key_images;
    key_images.reserve(selected_transfers.size());
    std::for_each(selected_transfers.begin(), selected_transfers.end(), [this, &key_images](size_t index) {
      key_images.push_back(m_transfers_in[index].m_key_image);
    });
    unset_ring(key_images);
  }

  THROW_WALLET_EXCEPTION(error::wallet_internal_error, tr("Transaction sanity check failed"));
}

void wallet2::get_outs(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, std::vector<uint64_t> &rct_offsets)
{
  MINFO("fake_outputs_count: " << fake_outputs_count);
  outs.clear();


  if (fake_outputs_count > 0)
  {
    uint64_t segregation_fork_height = get_segregation_fork_height();
    // check whether we're shortly after the fork
    uint64_t height;
    boost::optional<std::string> result = m_node_rpc_proxy.get_height(height);
    THROW_WALLET_EXCEPTION_IF(result, error::wallet_internal_error, "Failed to get height");
    bool is_shortly_after_segregation_fork =false;
    bool is_after_segregation_fork = true;

    // if we have at least one rct out, get the distribution, or fall back to the previous system
    uint64_t rct_start_height;
    bool has_rct = false;
    uint64_t max_rct_index = 0;
    for (size_t idx: selected_transfers)
      {
        has_rct = true;
        max_rct_index = std::max(max_rct_index, m_transfers_in[idx].m_global_output_index);
      }
    const bool has_rct_distribution = (!rct_offsets.empty() || get_rct_distribution(rct_start_height, rct_offsets));
    if (has_rct_distribution)
    {
      // check we're clear enough of rct start, to avoid corner cases below
      THROW_WALLET_EXCEPTION_IF(rct_offsets.size() <= CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
          error::get_output_distribution, "Not enough rct outputs");
      THROW_WALLET_EXCEPTION_IF(rct_offsets.back() <= max_rct_index,
          error::get_output_distribution, "Daemon reports suspicious number of rct outputs");
    }

    // get histogram for the amounts we need
    cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request req_t = AUTO_VAL_INIT(req_t);
    cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response resp_t = AUTO_VAL_INIT(resp_t);
    // request histogram for all outputs, except 0 if we have the rct distribution
    for(size_t idx: selected_transfers)
      if (!has_rct_distribution)
        req_t.amounts.push_back( 0 );
    if (!req_t.amounts.empty())
    {
      std::sort(req_t.amounts.begin(), req_t.amounts.end());
      auto end = std::unique(req_t.amounts.begin(), req_t.amounts.end());
      req_t.amounts.resize(std::distance(req_t.amounts.begin(), end));
      req_t.unlocked = true;
      req_t.recent_cutoff = time(NULL) - RECENT_OUTPUT_ZONE;

      {
        const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};

        bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_output_histogram", req_t, resp_t, *m_http_client, rpc_timeout);
        THROW_ON_RPC_RESPONSE_ERROR(r, {}, resp_t, "get_output_histogram", error::get_histogram_error, get_rpc_status(resp_t.status));
      }
    }

    // if we want to segregate fake outs pre or post fork, get distribution
    std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> segregation_limit;
    if (is_after_segregation_fork && (m_segregate_pre_fork_outputs || m_key_reuse_mitigation2))
    {
      cryptonote::COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request req_t = AUTO_VAL_INIT(req_t);
      cryptonote::COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response resp_t = AUTO_VAL_INIT(resp_t);
      for(size_t idx: selected_transfers)
        req_t.amounts.push_back(m_transfers_in[idx].is_rct() ? 0 : m_transfers_in[idx].amount());
      std::sort(req_t.amounts.begin(), req_t.amounts.end());
      auto end = std::unique(req_t.amounts.begin(), req_t.amounts.end());
      req_t.amounts.resize(std::distance(req_t.amounts.begin(), end));
      req_t.from_height = std::max<uint64_t>(segregation_fork_height, RECENT_OUTPUT_BLOCKS) - RECENT_OUTPUT_BLOCKS;
      req_t.to_height = segregation_fork_height + 1;
      req_t.cumulative = true;
      req_t.binary = true;

      {
        const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};


        bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_output_distribution", req_t, resp_t, *m_http_client, rpc_timeout * 1000);
        THROW_ON_RPC_RESPONSE_ERROR(r, {}, resp_t, "get_output_distribution", error::get_output_distribution, get_rpc_status(resp_t.status));
        uint64_t expected_cost = 0;
        for (uint64_t amount: req_t.amounts) expected_cost += (amount ? COST_PER_OUTPUT_DISTRIBUTION : COST_PER_OUTPUT_DISTRIBUTION_0);
      }

      // check we got all data
      for(size_t idx: selected_transfers)
      {
        const uint64_t amount = m_transfers_in[idx].is_rct() ? 0 : m_transfers_in[idx].amount();
        bool found = false;
        for (const auto &d: resp_t.distributions)
        {
          if (d.amount == amount)
          {
            THROW_WALLET_EXCEPTION_IF(d.data.start_height > segregation_fork_height, error::get_output_distribution, "Distribution start_height too high");
            THROW_WALLET_EXCEPTION_IF(segregation_fork_height - d.data.start_height >= d.data.distribution.size(), error::get_output_distribution, "Distribution size too small");
            THROW_WALLET_EXCEPTION_IF(segregation_fork_height - RECENT_OUTPUT_BLOCKS - d.data.start_height >= d.data.distribution.size(), error::get_output_distribution, "Distribution size too small");
            THROW_WALLET_EXCEPTION_IF(segregation_fork_height <= RECENT_OUTPUT_BLOCKS, error::wallet_internal_error, "Fork height too low");
            THROW_WALLET_EXCEPTION_IF(segregation_fork_height - RECENT_OUTPUT_BLOCKS < d.data.start_height, error::get_output_distribution, "Bad start height");
            uint64_t till_fork = d.data.distribution[segregation_fork_height - d.data.start_height];
            uint64_t recent = till_fork - d.data.distribution[segregation_fork_height - RECENT_OUTPUT_BLOCKS - d.data.start_height];
            segregation_limit[amount] = std::make_pair(till_fork, recent);
            found = true;
            break;
          }
        }
        THROW_WALLET_EXCEPTION_IF(!found, error::get_output_distribution, "Requested amount not found in response");
      }
    }

    // we ask for more, to have spares if some outputs are still locked
    size_t base_requested_outputs_count = (size_t)((fake_outputs_count + 1) * 1.5 + 1);
    MINFO("base_requested_outputs_count: " << base_requested_outputs_count);

    // generate output indices to request
    COMMAND_RPC_GET_OUTPUTS_BIN::request req = AUTO_VAL_INIT(req);
   

    std::unique_ptr<gamma_picker> gamma;
    if (has_rct_distribution)
      gamma.reset(new gamma_picker(rct_offsets));

    size_t num_selected_transfers = 0;
    for(size_t idx: selected_transfers)
    {
      ++num_selected_transfers;
      const transfer_details &td = m_transfers_in[idx];
      const uint64_t amount = 0;
      std::unordered_set<uint64_t> seen_indices;
      // request more for rct in base recent (locked) coinbases are picked, since they're locked for longer
      size_t requested_outputs_count = base_requested_outputs_count +CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE ;
      size_t start = req.outputs.size();
      bool use_histogram = false;

      const bool output_is_pre_fork = td.m_block_height < segregation_fork_height;
      uint64_t num_outs = 0, num_recent_outs = 0;
      uint64_t num_post_fork_outs = 0;
      float pre_fork_num_out_ratio = 0.0f;
      float post_fork_num_out_ratio = 0.0f;

      if (is_after_segregation_fork && m_segregate_pre_fork_outputs && output_is_pre_fork)
      {
        num_outs = segregation_limit[amount].first;
        num_recent_outs = segregation_limit[amount].second;
      }
      else
      {
        // if there are just enough outputs to mix with, use all of them.
        // Eventually this should become impossible.
        for (const auto &he: resp_t.histogram)
        {
          if (he.amount == amount)
          {
            MINFO("Found " << print_money(amount) << ": " << he.total_instances << " total, "
                << he.unlocked_instances << " unlocked, " << he.recent_instances << " recent");
            num_outs = he.unlocked_instances;
            num_recent_outs = he.recent_instances;
            break;
          }
        }
        if (is_after_segregation_fork && m_key_reuse_mitigation2)
        {
          if (output_is_pre_fork)
          {
            if (is_shortly_after_segregation_fork)
            {
              pre_fork_num_out_ratio = 33.4/100.0f * (1.0f - RECENT_OUTPUT_RATIO);
            }
            else
            {
              pre_fork_num_out_ratio = 33.4/100.0f * (1.0f - RECENT_OUTPUT_RATIO);
              post_fork_num_out_ratio = 33.4/100.0f * (1.0f - RECENT_OUTPUT_RATIO);
            }
          }
          else
          {
            if (is_shortly_after_segregation_fork)
            {
            }
            else
            {
              post_fork_num_out_ratio = 67.8/100.0f * (1.0f - RECENT_OUTPUT_RATIO);
            }
          }
        }
        num_post_fork_outs = num_outs - segregation_limit[amount].first;
      }

      {
        // the base offset of the first rct output in the first unlocked block (or the one to be if there's none)
        num_outs = rct_offsets[rct_offsets.size() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE];
        LOG_PRINT_L1("" << num_outs << " unlocked rct outputs");
        THROW_WALLET_EXCEPTION_IF(num_outs == 0, error::wallet_internal_error,
            "histogram reports no unlocked rct outputs, not even ours");
      }

      // how many fake outs to draw on a pre-fork distribution
      size_t pre_fork_outputs_count = requested_outputs_count * pre_fork_num_out_ratio;
      size_t post_fork_outputs_count = requested_outputs_count * post_fork_num_out_ratio;
      // how many fake outs to draw otherwise
      size_t normal_output_count = requested_outputs_count - pre_fork_outputs_count - post_fork_outputs_count;

      size_t recent_outputs_count = 0;
      if (use_histogram)
      {
        // X% of those outs are to be taken from recent outputs
        recent_outputs_count = normal_output_count * RECENT_OUTPUT_RATIO;
        if (recent_outputs_count == 0)
          recent_outputs_count = 1; // ensure we have at least one, if possible
        if (recent_outputs_count > num_recent_outs)
          recent_outputs_count = num_recent_outs;
        if (td.m_global_output_index >= num_outs - num_recent_outs && recent_outputs_count > 0)
          --recent_outputs_count; // if the real out is recent, pick one less recent fake out
      }
      LOG_PRINT_L1("Fake output makeup: " << requested_outputs_count << " requested: " << recent_outputs_count << " recent, " <<
          pre_fork_outputs_count << " pre-fork, " << post_fork_outputs_count << " post-fork, " <<
          (requested_outputs_count - recent_outputs_count - pre_fork_outputs_count - post_fork_outputs_count) << " full-chain");

      uint64_t num_found = 0;

 
      if (num_outs <= requested_outputs_count)
      {
        for (uint64_t i = 0; i < num_outs; i++)
          req.outputs.push_back({amount, i});
        // duplicate to make up shortfall: this will be caught after the RPC call,
        // so we can also output the amounts for which we can't reach the required
        // mixin after checking the actual unlockedness
        for (uint64_t i = num_outs; i < requested_outputs_count; ++i)
          req.outputs.push_back({amount, num_outs - 1});
      }
      else
      {
        // start with real one
        if (num_found == 0)
        {
          num_found = 1;
          seen_indices.emplace(td.m_global_output_index);
          req.outputs.push_back({amount, td.m_global_output_index});
          LOG_PRINT_L1("Selecting real output: " << td.m_global_output_index << " for " << print_money(amount));
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
          if (amount == 0 && has_rct_distribution)
          {
            THROW_WALLET_EXCEPTION_IF(!gamma, error::wallet_internal_error, "No gamma picker");
            // gamma distribution
            if (num_found -1 < recent_outputs_count + pre_fork_outputs_count)
            {
              do i = gamma->pick(); while (i >= segregation_limit[amount].first);
              type = "pre-fork gamma";
            }
            else if (num_found -1 < recent_outputs_count + pre_fork_outputs_count + post_fork_outputs_count)
            {
              do i = gamma->pick(); while (i < segregation_limit[amount].first || i >= num_outs);
              type = "post-fork gamma";
            }
            else
            {
              do i = gamma->pick(); while (i >= num_outs);
              type = "gamma";
            }
          }
          else if (num_found - 1 < recent_outputs_count) // -1 to account for the real one we seeded with
          {
            // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
            uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
            double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
            i = (uint64_t)(frac*num_recent_outs) + num_outs - num_recent_outs;
            // just in case rounding up to 1 occurs after calc
            if (i == num_outs)
              --i;
            type = "recent";
          }
          else if (num_found -1 < recent_outputs_count + pre_fork_outputs_count)
          {
            // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
            uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
            double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
            i = (uint64_t)(frac*segregation_limit[amount].first);
            // just in case rounding up to 1 occurs after calc
            if (i == num_outs)
              --i;
            type = " pre-fork";
          }
          else if (num_found -1 < recent_outputs_count + pre_fork_outputs_count + post_fork_outputs_count)
          {
            // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
            uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
            double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
            i = (uint64_t)(frac*num_post_fork_outs) + segregation_limit[amount].first;
            // just in case rounding up to 1 occurs after calc
            if (i == num_post_fork_outs+segregation_limit[amount].first)
              --i;
            type = "post-fork";
          }
          else
          {
            // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
            uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
            double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
            i = (uint64_t)(frac*num_outs);
            // just in case rounding up to 1 occurs after calc
            if (i == num_outs)
              --i;
            type = "triangular";
          }

          if (seen_indices.count(i))
            continue;
          if (!allow_blackballed && is_output_blackballed(std::make_pair(amount, i))) // don't add blackballed outputs
          {
            --num_usable_outs;
            continue;
          }
          seen_indices.emplace(i);

          picks[type].insert(i);
          req.outputs.push_back({amount, i});
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
          req.outputs.push_back({amount, 0});
          ++num_found;
        }
      }

      // sort the subsection, to ensure the daemon doesn't know which output is ours
      std::sort(req.outputs.begin() + start, req.outputs.end(),
          [](const get_outputs_out &a, const get_outputs_out &b) { return a.index < b.index; });
    }

    // get the keys for those
    req.get_txid = false;

    COMMAND_RPC_GET_OUTPUTS_BIN::response daemon_resp = AUTO_VAL_INIT(daemon_resp);
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
      outs.back().reserve(fake_outputs_count + 1);
      const rct::key commit =  rct::commit(td.amount(), td.m_noise) ;

      uint64_t num_outs = 0;
      const uint64_t amount = 0;
      const bool output_is_pre_fork =false;
      
      for (const auto &he: resp_t.histogram)
      {
        if (he.amount == amount)
        {
          num_outs = he.unlocked_instances;
          break;
        }
      }
      bool use_histogram =false;
      if (!use_histogram)
        num_outs = rct_offsets[rct_offsets.size() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE];

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
          if (daemon_resp.outs[i].key == boost::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key)
            if (daemon_resp.outs[i].commitment == commit)
              real_out_found = true;
      }
      THROW_WALLET_EXCEPTION_IF(!real_out_found, error::wallet_internal_error,
          "Daemon response did not include the requested real output");

      // pick real out first (it will be sorted when done)
      const auto &otk= boost::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key;
      
      outs.back().push_back(std::make_tuple(td.m_global_output_index,otk, commit));


      // then pick others in random order till we reach the required number
      // since we use an equiprobable pick here, we don't upset the triangular distribution
      std::vector<size_t> order;
      order.resize(requested_outputs_count);
      for (size_t n = 0; n < order.size(); ++n)
        order[n] = n;
      std::shuffle(order.begin(), order.end(), crypto::random_device{});

      MINFO("Looking for " << (fake_outputs_count+1) << " outputs of size " << print_money(td.is_rct() ? 0 : td.amount()));
      for (size_t o = 0; o < requested_outputs_count && outs.back().size() < fake_outputs_count + 1; ++o)
      {
        size_t i = base + order[o];
        MINFO("Index " << i << "/" << requested_outputs_count << ": idx " << req.outputs[i].index << " (real " << td.m_global_output_index << "), unlocked " << daemon_resp.outs[i].unlocked << ", key " << daemon_resp.outs[i].key);
        const auto & decoy = req.outputs[i];
        tx_add_fake_output(outs, decoy.index, decoy.key, decoy.commitment, td.m_global_output_index, decoy.unlocked);
      }
      if (outs.back().size() < fake_outputs_count + 1)
      {
        scanty_outs[ 0 ] = outs.back().size();
      }
      else
      {
        // sort the subsection, so any spares are reset in order
        std::sort(outs.back().begin(), outs.back().end(), [](const get_outs_entry &a, const get_outs_entry &b) { return std::get<0>(a) < std::get<0>(b); });
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
      v.push_back(std::make_tuple(td.m_global_output_index, td.otk(), commit));
      outs.push_back(v);
    }
  }

  // save those outs in the ringdb for reuse
  for (size_t i = 0; i < selected_transfers.size(); ++i)
  {
    const size_t idx = selected_transfers[i];
    THROW_WALLET_EXCEPTION_IF(idx >= m_transfers_in.size(), error::wallet_internal_error, "selected_transfers entry out of range");
    const transfer_details &td = m_transfers_in[idx];
    std::vector<uint64_t> ring;
    ring.reserve(outs[i].size());
    for (const auto &e: outs[i])
      ring.push_back(std::get<0>(e));
    if (!set_ring(td.m_key_image, ring, false))
      MERROR("Failed to set ring for " << td.m_key_image);
  }
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