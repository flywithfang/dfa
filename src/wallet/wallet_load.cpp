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
  throw_wallet_ex_if((use_fs && !keys_buf.empty()) || (!use_fs && keys_buf.empty()), error::file_read_error, "must load keys either from file system or from buffer");\

  boost::system::error_code e;
  if (use_fs)
  {
    bool exists = boost::filesystem::exists(m_keys_file, e);
    throw_wallet_ex_if(e || !exists, error::file_not_found, m_keys_file);

    if (!load_keys(m_keys_file, password))
    {
      throw_wallet_ex_if(true, error::file_read_error, m_keys_file);
    }
    LOG_PRINT_L0("Loaded wallet keys file, with public address: " << m_account.get_public_address_str(m_nettype));
    lock_keys_file();
  }
  else if (!load_keys_buf(keys_buf, password))
  {
    throw_wallet_ex_if(true, error::file_read_error, "failed to load keys from buffer");
  }

  wallet_keys_unlocker unlocker(*this,false , password);

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
      throw_wallet_ex_if(!r, error::file_read_error, m_wallet_file);
    }

    // try to read it as an encrypted cache
    try
    {
      LOG_PRINT_L1("Trying to decrypt cache data");

      r = ::serialization::parse_binary(use_fs ? cache_file_buf : cache_buf, cache_file_data);
      throw_wallet_ex_if(!r, error::wallet_internal_error, "internal error: failed to deserialize \"" + m_wallet_file + '\"');
      std::string cache_data;
      cache_data.resize(cache_file_data.cache_data.size());
      crypto::chacha20(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), m_cache_key, cache_file_data.iv, &cache_data[0]);

        bool loaded = false;

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
    catch (...)
    {
      LOG_PRINT_L1("Failed to load encrypted cache");
    }
    throw_wallet_ex_if(
      m_account_public_address.m_spend_public_key != m_account.get_keys().m_account_address.m_spend_public_key ||
      m_account_public_address.m_view_public_key  != m_account.get_keys().m_account_address.m_view_public_key,
      error::wallet_files_doesnt_correspond, m_keys_file, m_wallet_file);
  }

  cryptonote::block genesis;
  generate_genesis(genesis);
  crypto::hash genesis_hash = get_block_hash(genesis);

  if (m_blockchain.empty())
  {
    m_blockchain.push_back(genesis_hash);
  }
  else
  {
    check_genesis(genesis_hash);
  }

  trim_hashchain();
 
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
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);


  static_assert(HASH_SIZE == sizeof(crypto::chacha_key), "Mismatched sizes of hash and chacha key");
  epee::mlocked<tools::scrubbed_arr<char, HASH_SIZE+1>> cache_key_data;
  memcpy(cache_key_data.data(), &key, HASH_SIZE);
  cache_key_data[HASH_SIZE] = config::HASH_KEY_WALLET_CACHE;
  cn_fast_hash(cache_key_data.data(), HASH_SIZE+1, (crypto::hash&)m_cache_key);

  MDEBUG("cache key "<<(crypto::hash&)m_cache_key);
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
  throw_wallet_ex_if(!r, error::file_read_error, keys_file_name);

  // Load keys from buffer
  boost::optional<crypto::chacha_key> keys_to_encrypt;
  r = wallet2::load_keys_buf(keys_file_buf, password, keys_to_encrypt);

  // Rewrite with encrypted keys if unencrypted, ignore errors
  if (r && keys_to_encrypt != boost::none)
  {
    bool saved_ret = store_keys(keys_file_name, password, false);
    if (!saved_ret)
    {
      // just moan a bit, but not fatal
      MERROR("Error saving keys file with encrypted keys, not fatal");
    }
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
  throw_wallet_ex_if(!r, error::wallet_internal_error, "internal error: failed to deserialize keys buffer");
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
    m_auto_refresh = true;
    m_refresh_from_block_height = 0;
    cryptonote::set_default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT);
    m_max_reorg_depth = ORPHANED_BLOCKS_MAX_COUNT;
    m_inactivity_lock_timeout = DEFAULT_INACTIVITY_LOCK_TIMEOUT;
    encrypted_secret_keys = false;
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

   
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed_language, std::string, String, false, std::string());
    if (field_seed_language_found)
    {
      set_seed_language(field_seed_language);
    }

 
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, auto_refresh, int, Int, false, true);
    m_auto_refresh = field_auto_refresh;
  
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, refresh_height, uint64_t, Uint64, false, 0);
    m_refresh_from_block_height = field_refresh_height;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_decimal_point, int, Int, false, CRYPTONOTE_DISPLAY_DECIMAL_POINT);
    cryptonote::set_default_decimal_point(field_default_decimal_point);
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, max_reorg_depth, uint64_t, Uint64, false, ORPHANED_BLOCKS_MAX_COUNT);
    m_max_reorg_depth = field_max_reorg_depth;


    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, nettype, uint8_t, Uint, false, static_cast<uint8_t>(m_nettype));
    // The network type given in the program argument is inconsistent with the network type saved in the wallet
    throw_wallet_ex_if(static_cast<uint8_t>(m_nettype) != field_nettype, error::wallet_internal_error,
    (boost::format("%s wallet cannot be opened as %s wallet")
    % (field_nettype == 0 ? "Mainnet" : field_nettype == 1 ? "Testnet" : "Stagenet")
    % (m_nettype == MAINNET ? "mainnet" : m_nettype == TESTNET ? "testnet" : "stagenet")).str());

 
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, inactivity_lock_timeout, uint32_t, Uint, false, DEFAULT_INACTIVITY_LOCK_TIMEOUT);
    m_inactivity_lock_timeout = field_inactivity_lock_timeout;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, encrypted_secret_keys, uint32_t, Uint, false, false);
    encrypted_secret_keys = field_encrypted_secret_keys;

  }
  else
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "invalid password");
    return false;
  }
  std::cout<<"load account keys"<<std::endl;
  r = epee::serialization::load_t_from_binary(m_account, account_data);
  throw_wallet_ex_if(!r, error::invalid_password);


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
  r = r && cryptonote::verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key);
    r = r && cryptonote::verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
  throw_wallet_ex_if(!r, error::wallet_files_doesnt_correspond, m_keys_file, m_wallet_file);

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