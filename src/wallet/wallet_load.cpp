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

void do_prepare_file_names(const std::string& file_path, std::string& keys_file, std::string& wallet_file)
{
  keys_file = file_path;
  wallet_file = file_path;
  boost::system::error_code e;
  if(string_tools::get_extension(keys_file) == "keys")
  {//provided keys file name
    wallet_file = string_tools::cut_off_extension(wallet_file);
  }else
  {//provided wallet file name
    keys_file += ".keys";
  }
}

//----------------------------------------------------------------------------------------------------
bool wallet2::prepare_file_names(const std::string& file_path)
{
  do_prepare_file_names(file_path, m_keys_file, m_wallet_file);
  return true;
}

//----------------------------------------------------------------------------------------------------
void wallet2::load(const std::string& _wallet_file, const epee::wipeable_string& password, const std::string& keys_buf, const std::string& cache_buf)
{
  std::cout<<"wallet2::load "<<std::endl;
  clear();
  prepare_file_names(_wallet_file);

  // determine if loading from file system or string buffer
  bool use_fs = !_wallet_file.empty();
  THROW_WALLET_EXCEPTION_IF((use_fs && !keys_buf.empty()) || (!use_fs && keys_buf.empty()), error::file_read_error, "must load keys either from file system or from buffer");\

  boost::system::error_code e;
  if (use_fs)
  {
    bool exists = boost::filesystem::exists(m_keys_file, e);
    THROW_WALLET_EXCEPTION_IF(e || !exists, error::file_not_found, m_keys_file);
    lock_keys_file();
    THROW_WALLET_EXCEPTION_IF(!is_keys_file_locked(), error::wallet_internal_error, "internal error: \"" + m_keys_file + "\" is opened by another wallet program");

    // this temporary unlocking is necessary for Windows (otherwise the file couldn't be loaded).
    unlock_keys_file();
    if (!load_keys(m_keys_file, password))
    {
      THROW_WALLET_EXCEPTION_IF(true, error::file_read_error, m_keys_file);
    }
    LOG_PRINT_L0("Loaded wallet keys file, with public address: " << m_account.get_public_address_str(m_nettype));
    lock_keys_file();
  }
  else if (!load_keys_buf(keys_buf, password))
  {
    THROW_WALLET_EXCEPTION_IF(true, error::file_read_error, "failed to load keys from buffer");
  }

  wallet_keys_unlocker unlocker(*this, m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only, password);

  //keys loaded ok!
  //try to load wallet file. but even if we failed, it is not big problem
  if (use_fs && (!boost::filesystem::exists(m_wallet_file, e) || e))
  {
    LOG_PRINT_L0("file not found: " << m_wallet_file << ", starting with empty blockchain");
    m_account_public_address = m_account.get_keys().m_account_address;
  }
  else if (use_fs || !cache_buf.empty())
  {
    wallet2::cache_file_data cache_file_data;
    std::string cache_file_buf;
    bool r = true;
    if (use_fs)
    {
      load_from_file(m_wallet_file, cache_file_buf, std::numeric_limits<size_t>::max());
      THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, m_wallet_file);
    }

    // try to read it as an encrypted cache
    try
    {
      LOG_PRINT_L1("Trying to decrypt cache data");

      r = ::serialization::parse_binary(use_fs ? cache_file_buf : cache_buf, cache_file_data);
      THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize \"" + m_wallet_file + '\"');
      std::string cache_data;
      cache_data.resize(cache_file_data.cache_data.size());
      crypto::chacha20(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), m_cache_key, cache_file_data.iv, &cache_data[0]);

      try {
        bool loaded = false;

        try
        {
          std::stringstream iss;
          iss << cache_data;
          binary_archive<false> ar(iss);
          if (::serialization::serialize(ar, *this))
            if (::serialization::check_stream_state(ar))
              loaded = true;
          if (!loaded)
          {
            std::stringstream iss;
            iss << cache_data;
            binary_archive<false> ar(iss);
            ar.enable_varint_bug_backward_compatibility();
            if (::serialization::serialize(ar, *this))
              if (::serialization::check_stream_state(ar))
                loaded = true;
          }
        }
        catch(...) { }

        if (!loaded)
        {
          std::stringstream iss;
          iss << cache_data;
          boost::archive::portable_binary_iarchive ar(iss);
          ar >> *this;
        }
      }
      catch(...)
      {
        // try with previous scheme: direct from keys
        crypto::chacha_key key;
        generate_chacha_key_from_secret_keys(key);
        crypto::chacha20(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), key, cache_file_data.iv, &cache_data[0]);
        try {
          std::stringstream iss;
          iss << cache_data;
          boost::archive::portable_binary_iarchive ar(iss);
          ar >> *this;
        }
        catch (...)
        {
          crypto::chacha8(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), key, cache_file_data.iv, &cache_data[0]);
          try
          {
            std::stringstream iss;
            iss << cache_data;
            boost::archive::portable_binary_iarchive ar(iss);
            ar >> *this;
          }
          catch (...)
          {
            LOG_PRINT_L0("Failed to open portable binary, trying unportable");
            if (use_fs) boost::filesystem::copy_file(m_wallet_file, m_wallet_file + ".unportable", boost::filesystem::copy_option::overwrite_if_exists);
            std::stringstream iss;
            iss.str("");
            iss << cache_data;
            boost::archive::binary_iarchive ar(iss);
            ar >> *this;
          }
        }
      }
    }
    catch (...)
    {
      LOG_PRINT_L1("Failed to load encrypted cache, trying unencrypted");
      try {
        std::stringstream iss;
        iss << cache_file_buf;
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> *this;
      }
      catch (...)
      {
        LOG_PRINT_L0("Failed to open portable binary, trying unportable");
        if (use_fs) boost::filesystem::copy_file(m_wallet_file, m_wallet_file + ".unportable", boost::filesystem::copy_option::overwrite_if_exists);
        std::stringstream iss;
        iss.str("");
        iss << cache_file_buf;
        boost::archive::binary_iarchive ar(iss);
        ar >> *this;
      }
    }
    THROW_WALLET_EXCEPTION_IF(
      m_account_public_address.m_spend_public_key != m_account.get_keys().m_account_address.m_spend_public_key ||
      m_account_public_address.m_view_public_key  != m_account.get_keys().m_account_address.m_view_public_key,
      error::wallet_files_doesnt_correspond, m_keys_file, m_wallet_file);
  }

  if (!m_persistent_rpc_client_id)
    set_rpc_client_secret_key(rct::rct2sk(rct::skGen()));

  cryptonote::block genesis;
  generate_genesis(genesis);
  crypto::hash genesis_hash = get_block_hash(genesis);

  if (m_blockchain.empty())
  {
    m_blockchain.push_back(genesis_hash);
    m_last_block_reward = cryptonote::get_outs_money_amount(genesis.miner_tx);
  }
  else
  {
    check_genesis(genesis_hash);
  }

  trim_hashchain();

  if (get_num_subaddress_accounts() == 0)
    add_subaddress_account(tr("Primary account"));

  try
  {
    find_and_save_rings(false);
  }
  catch (const std::exception &e)
  {
    MERROR("Failed to save rings, will try again next time");
  }
  
 
}
void wallet2::wallet_exists(const std::string& file_path, bool& keys_file_exists, bool& wallet_file_exists)
{
  std::string keys_file, wallet_file;
  do_prepare_file_names(file_path, keys_file, wallet_file);

  boost::system::error_code ignore;
  keys_file_exists = boost::filesystem::exists(keys_file, ignore);
  wallet_file_exists = boost::filesystem::exists(wallet_file, ignore);
}

//----------------------------------------------------------------------------------------------------
void wallet2::setup_keys(const epee::wipeable_string &password)
{
  std::cout<<"setup_Keys"<<std::endl;
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);

  // re-encrypt, but keep viewkey unencrypted
  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
  {
    m_account.encrypt_keys(key);
    m_account.decrypt_viewkey(key);
  }

  static_assert(HASH_SIZE == sizeof(crypto::chacha_key), "Mismatched sizes of hash and chacha key");
  epee::mlocked<tools::scrubbed_arr<char, HASH_SIZE+1>> cache_key_data;
  memcpy(cache_key_data.data(), &key, HASH_SIZE);
  cache_key_data[HASH_SIZE] = config::HASH_KEY_WALLET_CACHE;
  cn_fast_hash(cache_key_data.data(), HASH_SIZE+1, (crypto::hash&)m_cache_key);

  MDEBUG("cache key "<<(crypto::hash&)m_cache_key);
  get_ringdb_key();
}


//----------------------------------------------------------------------------------------------------
/*!
 * \brief Load wallet information from wallet file.
 * \param keys_file_name Name of wallet file
 * \param password       Password of wallet file
 */
bool wallet2::load_keys(const std::string& keys_file_name, const epee::wipeable_string& password)
{
  std::string keys_file_buf;
  bool r = load_from_file(keys_file_name, keys_file_buf);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, keys_file_name);

  // Load keys from buffer
  boost::optional<crypto::chacha_key> keys_to_encrypt;
  r = wallet2::load_keys_buf(keys_file_buf, password, keys_to_encrypt);

  // Rewrite with encrypted keys if unencrypted, ignore errors
  if (r && keys_to_encrypt != boost::none)
  {
    if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
      encrypt_keys(keys_to_encrypt.get());
    bool saved_ret = store_keys(keys_file_name, password, m_watch_only);
    if (!saved_ret)
    {
      // just moan a bit, but not fatal
      MERROR("Error saving keys file with encrypted keys, not fatal");
    }
    if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
      decrypt_keys(keys_to_encrypt.get());
    m_keys_file_locker.reset();
  }
  return r;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password) {
  boost::optional<crypto::chacha_key> keys_to_encrypt;
  return wallet2::load_keys_buf(keys_buf, password, keys_to_encrypt);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password, boost::optional<crypto::chacha_key>& keys_to_encrypt) {

std::cout<<"load_keys_buf" << keys_buf.size()<<" pass "<<password.data()<<std::endl;
  // Decrypt the contents
  rapidjson::Document json;
  wallet2::keys_file_data keys_file_data;
  bool encrypted_secret_keys = false;
  bool r = ::serialization::parse_binary(keys_buf, keys_file_data);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize keys buffer");
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
  if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject())
    crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);

  MDEBUG("after chacha account_data "<< account_data);
  // The contents should be JSON if the wallet follows the new format.
  if (json.Parse(account_data.c_str()).HasParseError())
  {
    is_old_file_format = true;
    m_watch_only = false;
    m_always_confirm_transfers = false;
    m_print_ring_members = false;
    m_store_tx_info = true;
    m_default_mixin = 0;
    m_default_priority = 0;
    m_auto_refresh = true;
    m_refresh_type = RefreshType::RefreshDefault;
    m_refresh_from_block_height = 0;
    m_confirm_non_default_ring_size = true;
    m_ask_password = AskPasswordToDecrypt;
    cryptonote::set_default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT);
    m_max_reorg_depth = ORPHANED_BLOCKS_MAX_COUNT;
    m_min_output_count = 0;
    m_min_output_value = 0;
    m_merge_destinations = false;
    m_confirm_backlog = true;
    m_confirm_backlog_threshold = 0;
    m_confirm_export_overwrite = true;
    m_auto_low_priority = true;
    m_segregate_pre_fork_outputs = true;
    m_key_reuse_mitigation2 = true;
    m_segregation_height = 0;
    m_ignore_fractional_outputs = true;
    m_ignore_outputs_above = MONEY_SUPPLY;
    m_ignore_outputs_below = 0;
    m_track_uses = false;
    m_inactivity_lock_timeout = DEFAULT_INACTIVITY_LOCK_TIMEOUT;
    m_setup_background_mining = BackgroundMiningMaybe;
    m_subaddress_lookahead_major = SUBADDRESS_LOOKAHEAD_MAJOR;
    m_subaddress_lookahead_minor = SUBADDRESS_LOOKAHEAD_MINOR;
    m_original_keys_available = false;
    m_export_format = ExportFormat::Binary;
    m_load_deprecated_formats = false;
    m_device_name = "";
    m_device_derivation_path = "";
    m_key_device_type = hw::device::device_type::SOFTWARE;
    encrypted_secret_keys = false;
    m_persistent_rpc_client_id = false;
    m_auto_mine_for_rpc_payment_threshold = -1.0f;
    m_credits_target = 0;
  }
  else if(json.IsObject())
  {
    if (!json.HasMember("key_data"))
    {
      LOG_ERROR("Field key_data not found in JSON");
      return false;
    }
    if (!json["key_data"].IsString())
    {
      LOG_ERROR("Field key_data found in JSON, but not String");
      return false;
    }
    const char *field_key_data = json["key_data"].GetString();
    MDEBUG("key_data "<<field_key_data);
    account_data = std::string(field_key_data, field_key_data + json["key_data"].GetStringLength());

    if (json.HasMember("key_on_device"))
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, key_on_device, int, Int, false, hw::device::device_type::SOFTWARE);
      m_key_device_type = static_cast<hw::device::device_type>(field_key_on_device);
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed_language, std::string, String, false, std::string());
    if (field_seed_language_found)
    {
      set_seed_language(field_seed_language);
    }

  
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, always_confirm_transfers, int, Int, false, true);
    m_always_confirm_transfers = field_always_confirm_transfers;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, print_ring_members, int, Int, false, true);
    m_print_ring_members = field_print_ring_members;
    if (json.HasMember("store_tx_info"))
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, store_tx_info, int, Int, true, true);
      m_store_tx_info = field_store_tx_info;
    }
    else if (json.HasMember("store_tx_keys")) // backward compatibility
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, store_tx_keys, int, Int, true, true);
      m_store_tx_info = field_store_tx_keys;
    }
    else
      m_store_tx_info = true;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_mixin, unsigned int, Uint, false, 0);
    m_default_mixin = field_default_mixin;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_priority, unsigned int, Uint, false, 0);
    if (field_default_priority_found)
    {
      m_default_priority = field_default_priority;
    }
    else
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_fee_multiplier, unsigned int, Uint, false, 0);
      if (field_default_fee_multiplier_found)
        m_default_priority = field_default_fee_multiplier;
      else
        m_default_priority = 0;
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, auto_refresh, int, Int, false, true);
    m_auto_refresh = field_auto_refresh;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, refresh_type, int, Int, false, RefreshType::RefreshDefault);
    m_refresh_type = RefreshType::RefreshDefault;
    if (field_refresh_type_found)
    {
      if (field_refresh_type == RefreshFull || field_refresh_type == RefreshOptimizeCoinbase || field_refresh_type == RefreshNoCoinbase)
        m_refresh_type = (RefreshType)field_refresh_type;
      else
        LOG_PRINT_L0("Unknown refresh-type value (" << field_refresh_type << "), using default");
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, refresh_height, uint64_t, Uint64, false, 0);
    m_refresh_from_block_height = field_refresh_height;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_non_default_ring_size, int, Int, false, true);
    m_confirm_non_default_ring_size = field_confirm_non_default_ring_size;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ask_password, AskPasswordType, Int, false, AskPasswordToDecrypt);
    m_ask_password = field_ask_password;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_decimal_point, int, Int, false, CRYPTONOTE_DISPLAY_DECIMAL_POINT);
    cryptonote::set_default_decimal_point(field_default_decimal_point);
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, max_reorg_depth, uint64_t, Uint64, false, ORPHANED_BLOCKS_MAX_COUNT);
    m_max_reorg_depth = field_max_reorg_depth;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, min_output_count, uint32_t, Uint, false, 0);
    m_min_output_count = field_min_output_count;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, min_output_value, uint64_t, Uint64, false, 0);
    m_min_output_value = field_min_output_value;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, merge_destinations, int, Int, false, false);
    m_merge_destinations = field_merge_destinations;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_backlog, int, Int, false, true);
    m_confirm_backlog = field_confirm_backlog;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_backlog_threshold, uint32_t, Uint, false, 0);
    m_confirm_backlog_threshold = field_confirm_backlog_threshold;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_export_overwrite, int, Int, false, true);
    m_confirm_export_overwrite = field_confirm_export_overwrite;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, auto_low_priority, int, Int, false, true);
    m_auto_low_priority = field_auto_low_priority;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, nettype, uint8_t, Uint, false, static_cast<uint8_t>(m_nettype));
    // The network type given in the program argument is inconsistent with the network type saved in the wallet
    THROW_WALLET_EXCEPTION_IF(static_cast<uint8_t>(m_nettype) != field_nettype, error::wallet_internal_error,
    (boost::format("%s wallet cannot be opened as %s wallet")
    % (field_nettype == 0 ? "Mainnet" : field_nettype == 1 ? "Testnet" : "Stagenet")
    % (m_nettype == MAINNET ? "mainnet" : m_nettype == TESTNET ? "testnet" : "stagenet")).str());
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, segregate_pre_fork_outputs, int, Int, false, true);
    m_segregate_pre_fork_outputs = field_segregate_pre_fork_outputs;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, key_reuse_mitigation2, int, Int, false, true);
    m_key_reuse_mitigation2 = field_key_reuse_mitigation2;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, segregation_height, int, Uint, false, 0);
    m_segregation_height = field_segregation_height;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ignore_fractional_outputs, int, Int, false, true);
    m_ignore_fractional_outputs = field_ignore_fractional_outputs;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ignore_outputs_above, uint64_t, Uint64, false, MONEY_SUPPLY);
    m_ignore_outputs_above = field_ignore_outputs_above;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ignore_outputs_below, uint64_t, Uint64, false, 0);
    m_ignore_outputs_below = field_ignore_outputs_below;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, track_uses, int, Int, false, false);
    m_track_uses = field_track_uses;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, inactivity_lock_timeout, uint32_t, Uint, false, DEFAULT_INACTIVITY_LOCK_TIMEOUT);
    m_inactivity_lock_timeout = field_inactivity_lock_timeout;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, setup_background_mining, BackgroundMiningSetupType, Int, false, BackgroundMiningMaybe);
    m_setup_background_mining = field_setup_background_mining;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, subaddress_lookahead_major, uint32_t, Uint, false, SUBADDRESS_LOOKAHEAD_MAJOR);
    m_subaddress_lookahead_major = field_subaddress_lookahead_major;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, subaddress_lookahead_minor, uint32_t, Uint, false, SUBADDRESS_LOOKAHEAD_MINOR);
    m_subaddress_lookahead_minor = field_subaddress_lookahead_minor;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, encrypted_secret_keys, uint32_t, Uint, false, false);
    encrypted_secret_keys = field_encrypted_secret_keys;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, export_format, ExportFormat, Int, false, Binary);
    m_export_format = field_export_format;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, load_deprecated_formats, int, Int, false, false);
    m_load_deprecated_formats = field_load_deprecated_formats;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, device_name, std::string, String, false, std::string());
    if (m_device_name.empty())
    {
      if (field_device_name_found)
      {
        m_device_name = field_device_name;
      }
      else
      {
        m_device_name = m_key_device_type == hw::device::device_type::LEDGER ? "Ledger" : "default";
      }
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, device_derivation_path, std::string, String, false, std::string());
    m_device_derivation_path = field_device_derivation_path;
    
    if (json.HasMember("original_keys_available"))
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, original_keys_available, int, Int, false, false);
      m_original_keys_available = field_original_keys_available;
      if (m_original_keys_available)
      {
        GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, original_address, std::string, String, true, std::string());
        address_parse_info info;
        bool ok = get_account_address_from_str(info, m_nettype, field_original_address);
        if (!ok)
        {
          LOG_ERROR("Failed to parse original_address from JSON");
          return false;
        }
        m_original_address = info.address;
        GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, original_view_secret_key, std::string, String, true, std::string());
        ok = epee::string_tools::hex_to_pod(field_original_view_secret_key, m_original_view_secret_key);
        if (!ok)
        {
          LOG_ERROR("Failed to parse original_view_secret_key from JSON");
          return false;
        }
      }
    }
    else
    {
      m_original_keys_available = false;
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, persistent_rpc_client_id, int, Int, false, false);
    m_persistent_rpc_client_id = field_persistent_rpc_client_id;
    // save as float, load as double, because it can happen you can't load back as float...
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, credits_target, uint64_t, Uint64, false, 0);
    m_credits_target = field_credits_target;
  }
  else
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "invalid password");
    return false;
  }
  std::cout<<"load account keys"<<std::endl;
  r = epee::serialization::load_t_from_binary(m_account, account_data);
  THROW_WALLET_EXCEPTION_IF(!r, error::invalid_password);
  if (key_on_device()) {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "hardware device not supported");
  }

  if (r)
  {
    if (encrypted_secret_keys)
    {
      m_account.decrypt_keys(key);
    }
    else
    {
      keys_to_encrypt = key;
    }
  }
  const cryptonote::account_keys& keys = m_account.get_keys();
  hw::device &hwdev = m_account.get_device();
  r = r && hwdev.verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key);
  if (!m_watch_only  && hwdev.device_protocol() != hw::device::PROTOCOL_COLD)
    r = r && hwdev.verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_files_doesnt_correspond, m_keys_file, m_wallet_file);

  if (r)
    setup_keys(password);

  return true;
}


bool wallet2::load_from_file(const std::string& path_to_file, std::string& target_str,
                             size_t max_size)
{
  std::cout<<"load_wallet_file "<<path_to_file<<std::endl;
  std::string data;
  bool r = epee::file_io_utils::load_file_to_string(path_to_file, data, max_size);
  if (!r)
  {
    std::cout<<path_to_file<<" not text file"<<std::endl;
    return false;
  }

    // It's NOT our ascii dump.
    target_str = std::move(data);
    return true;
}

}