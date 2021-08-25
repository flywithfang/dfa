#pragma once
#include <boost/asio/io_service.hpp>
#include <boost/function/function_fwd.hpp>
#if BOOST_VERSION >= 107400
#include <boost/serialization/library_version_type.hpp>
#endif
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/version.hpp>
#include <boost/serialization/list.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/global_fun.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <atomic>
#include <functional>
#include <unordered_map>
#include <unordered_set>

#include "span.h"
#include "syncobj.h"
#include "string_tools.h"
#include "rolling_median.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "common/powerof.h"
#include "common/util.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_basic/verification_context.h"
#include "crypto/hash.h"
#include "checkpoints/checkpoints.h"
#include "cryptonote_basic/hardfork.h"
#include "blockchain_db/blockchain_db.h"


namespace cryptonote{
bool check_tx_outputs(const transaction& tx, tx_verification_context &tvc) ;
  bool check_tx_semantic(const transaction& tx);
  bool check_tx_inputs(BlockchainDB& db,transaction& tx, tx_verification_context &tvc) ;
}