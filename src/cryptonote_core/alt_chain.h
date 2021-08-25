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

namespace cryptonote
{

	struct AltChain{
	uint64_t split_b_height;
    std::list<block_extended_info> alt_chain;
    std::vector<uint64_t> &timestamps
    BlockchainDB & m_db;
    AltChain(BlockchainDB&db,const crypto::hash &prev_id);


    uint64_t height(){
    	return split_b_height+alt_chain.size()+1;
    }
    uint64_t coins_generated();
    crypto::hash get_block_hash_by_height(uint64_t block_height) const;
 	uint64_t get_block_timestamp(const uint64_t& height) const;
	difficulty_type get_block_cumulative_difficulty(uint64_t height) const;
	uint64_t get_block_already_generated_coins(uint64_t height) const;

	std::tuple<crypto::hash,uint64_t> get_top_block_hash()const;
  };

}
