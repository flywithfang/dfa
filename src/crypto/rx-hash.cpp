// Copyright (c) 2019-2020, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include "randomx.h"
#include "c_threads.h"
#include "misc_log_ex.h"
#include <thread>
#include <mutex>
#include <vector>
#include "rx-hash.h"

#define RX_LOGCAT	"randomx"


struct rx_state {
  crypto::hash K;
  randomx_cache *rs_cache;
};

static std::mutex rx_mutex ;

using MutexLock = std::lock_guard<std::mutex>;

static rx_state rx_s {};

static randomx_dataset *rx_dataset;
static crypto::hash rx_K;
static thread_local  randomx_vm *rx_vm = nullptr;

static void local_abort(const char *msg)
{
  fprintf(stderr, "%s\n", msg);
  throw std::runtime_error(msg);
}

static inline int enabled_flags(void) {

  auto flags = randomx_get_flags();

  return flags;
}

#define SEEDHASH_EPOCH_BLOCKS	2048	/* Must be same as BLOCKS_SYNCHRONIZING_MAX_COUNT in cryptonote_config.h */
#define SEEDHASH_EPOCH_LAG		64

static inline int is_power_of_2(uint64_t n) { return n && (n & (n-1)) == 0; }


uint64_t rx_seedheight(const uint64_t height) {
  uint64_t s_height =  (height <= SEEDHASH_EPOCH_BLOCKS+SEEDHASH_EPOCH_LAG) ? 0 :
                       (height - SEEDHASH_EPOCH_LAG - 1) & ~(SEEDHASH_EPOCH_BLOCKS-1);
  return s_height;
}

void rx_seedheights(const uint64_t height, uint64_t *seedheight, uint64_t *n_seed_height) {
  *seedheight = rx_seedheight(height);
  *n_seed_height = rx_seedheight(height + SEEDHASH_EPOCH_LAG);
}

 struct seedinfo {
  randomx_cache *si_cache;
  unsigned long si_start;
  unsigned long si_count;
} ;



static void rx_init_cache(randomx_flags flags,rx_state & rx_sp,const crypto::hash & K) {
    auto & cache = rx_sp.rs_cache;
    if (cache == nullptr) {
      {
        cache = randomx_alloc_cache(flags | RANDOMX_FLAG_LARGE_PAGES);
        if (cache == nullptr) {
          mdebug(RX_LOGCAT, "Couldn't use largePages for RandomX cache");
        }
      }
      if (cache == nullptr) {
        cache = randomx_alloc_cache(flags);
        if (cache == nullptr)
          local_abort("Couldn't allocate RandomX cache");
      }
    }

    if ( K !=rx_sp.K) {
      randomx_init_cache(cache, K.data, crypto::HASH_SIZE);
      rx_sp->rs_cache = cache;
      rx_sp->K = K;
    }
  }

static void rx_dataset_init_thread(seedinfo si) {
  randomx_init_dataset(rx_dataset, si.si_cache, si.si_start, si.si_count);
}

static void __rx_init_dataset(randomx_cache *rs_cache, const crypto::hash & K) {
  const auto processor_count = std::thread::hardware_concurrency();
    unsigned long share = randomx_dataset_item_count() / processor_count;
    unsigned long start = 0;
    
    std::vector<std::thread> ts;
    for (size_t i=0; i<processor_count-1; i++) {
       ts.emplace_back(rx_dataset_init_thread,  seedinfo{rs_cache,start,share});
      start += share;
    }
  
    randomx_init_dataset(rx_dataset, rs_cache, start,  randomx_dataset_item_count() - start);
    for(auto & t:ts){
     t.join();
    }
 
  rx_K = K;
}
static void rx_init_dataset(randomx_flags flags,randomx_cache *rs_cache, const crypto::hash & K )
{
        if (rx_dataset == nullptr) {

            rx_dataset = randomx_alloc_dataset(RANDOMX_FLAG_LARGE_PAGES);
            if (rx_dataset == nullptr) {
                mdebug(RX_LOGCAT, "Couldn't use largePages for RandomX dataset");
                rx_dataset = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
            }

        }

       if (rx_dataset != nullptr && rx_K != K)
            __rx_init_dataset(rs_cache,  K);

}
static void rx_init_vm(randomx_flags flags,randomx_cache *rs_cache){

    if (rx_dataset != nullptr)
        flags |= RANDOMX_FLAG_FULL_MEM;

    if ((flags & RANDOMX_FLAG_JIT) && rx_dataset==nullptr) {
        flags |= randomx_flags(RANDOMX_FLAG_SECURE );
    }
    if(rx_vm==nullptr){

          rx_vm = randomx_create_vm(flags | RANDOMX_FLAG_LARGE_PAGES, rs_cache, rx_dataset);
          if(rx_vm == nullptr) { //large pages failed
            mdebug(RX_LOGCAT, "Couldn't use largePages for RandomX VM");
          }
        if (rx_vm == nullptr)
          rx_vm = randomx_create_vm(flags, rs_cache, rx_dataset);
        if(rx_vm == nullptr) {//fallback if everything fails
          flags = rx_dataset ? RANDOMX_FLAG_DEFAULT|RANDOMX_FLAG_FULL_MEM : RANDOMX_FLAG_DEFAULT;
          rx_vm = randomx_create_vm(flags, rs_cache, rx_dataset);
        }

    }

    if (rx_vm == nullptr)
      local_abort("Couldn't allocate RandomX VM");
    else{
      if(rx_dataset == nullptr){
          /* this is a no-op if the cache hasn't changed */
         randomx_vm_set_cache(rx_vm, rs_cache);
      }
    }

}

crypto::hash rx_slow_hash(const crypto::hash & K, const void *data, size_t length,   bool miner) {
  const randomx_flags flags = randomx_flags(enabled_flags() );
    {
      MutexLock ml(rx_mutex);

      rx_init_cache(flags,rx_s,K);

      if (miner) {
        rx_init_dataset(flags,rx_s.rs_cache,K);
      }

      rx_init_vm(flags,rx_sp->rs_cache);
  }
  
  crypto::hash pow;
  randomx_calculate_hash(rx_vm, data, length, pow.data);

  return pow;
}

void rx_slow_hash_allocate_state(void) {
}

void rx_slow_hash_free_state(void) {
  if (rx_vm != nullptr) {
    randomx_destroy_vm(rx_vm);
    rx_vm = nullptr;
  }
}

void rx_stop_mining(void) {
  MutexLock ml(rx_mutex);
  if (rx_dataset != nullptr) {
    randomx_dataset *rd = rx_dataset;
    rx_dataset = nullptr;
    randomx_release_dataset(rd);
  }
}
