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
#include "hash-ops.h"
#include "misc_log_ex.h"
#include <thread>
#include <vector>
#include "rx-hash.h"
#define RX_LOGCAT	"randomx"


typedef struct rx_state {
  CTHR_MUTEX_TYPE rs_mutex;
  char rs_hash[HASH_SIZE];
  uint64_t  rs_height;
  randomx_cache *rs_cache;
} rx_state;

static CTHR_MUTEX_TYPE rx_mutex = CTHR_MUTEX_INIT;
static CTHR_MUTEX_TYPE rx_dataset_mutex = CTHR_MUTEX_INIT;

static rx_state rx_s[2] = {{CTHR_MUTEX_INIT,{0},0,0},{CTHR_MUTEX_INIT,{0},0,0}};

static randomx_dataset *rx_dataset;
static int rx_dataset_nomem;
static uint64_t rx_dataset_height;
static thread_local  randomx_vm *rx_vm = NULL;

static void local_abort(const char *msg)
{
  fprintf(stderr, "%s\n", msg);
#ifdef NDEBUG
  _exit(1);
#else
  abort();
#endif
}

static inline int disabled_flags(void) {
  static int flags = -1;

  if (flags != -1) {
    return flags;
  }

  const char *env = getenv("MONERO_RANDOMX_UMASK");
  if (!env) {
    flags = 0;
  }
  else {
    char* endptr;
    long int value = strtol(env, &endptr, 0);
    if (endptr != env && value >= 0 && value < INT_MAX) {
      flags = value;
    }
    else {
      flags = 0;
    }
  }

  return flags;
}

static inline int enabled_flags(void) {
  static int flags = -1;

  if (flags != -1) {
    return flags;
  }

  flags = randomx_get_flags();

  return flags;
}

#define SEEDHASH_EPOCH_BLOCKS	2048	/* Must be same as BLOCKS_SYNCHRONIZING_MAX_COUNT in cryptonote_config.h */
#define SEEDHASH_EPOCH_LAG		64

static inline int is_power_of_2(uint64_t n) { return n && (n & (n-1)) == 0; }


void rx_reorg(const uint64_t split_height) {
  int i;
  CTHR_MUTEX_LOCK(rx_mutex);
  for (i=0; i<2; i++) {
    if (split_height <= rx_s[i].rs_height) {
      if (rx_s[i].rs_height == rx_dataset_height)
        rx_dataset_height = 1;
      rx_s[i].rs_height = 1;	/* set to an invalid seed height */
    }
  }
  CTHR_MUTEX_UNLOCK(rx_mutex);
}

uint64_t rx_seedheight(const uint64_t height) {
  uint64_t s_height =  (height <= SEEDHASH_EPOCH_BLOCKS+SEEDHASH_EPOCH_LAG) ? 0 :
                       (height - SEEDHASH_EPOCH_LAG - 1) & ~(SEEDHASH_EPOCH_BLOCKS-1);
  return s_height;
}

void rx_seedheights(const uint64_t height, uint64_t *seedheight, uint64_t *nextheight) {
  *seedheight = rx_seedheight(height);
  *nextheight = rx_seedheight(height + SEEDHASH_EPOCH_LAG);
}

 struct seedinfo {
  randomx_cache *si_cache;
  unsigned long si_start;
  unsigned long si_count;
} ;



static void rx_init_cache(randomx_flags flags,rx_state *rx_sp, const uint64_t seedheight,const char *seedhash) {
    auto & cache = rx_sp->rs_cache;
    if (cache == NULL) {
      if (!(disabled_flags() & RANDOMX_FLAG_LARGE_PAGES)) {
        cache = randomx_alloc_cache(flags | RANDOMX_FLAG_LARGE_PAGES);
        if (cache == NULL) {
          mdebug(RX_LOGCAT, "Couldn't use largePages for RandomX cache");
        }
      }
      if (cache == NULL) {
        cache = randomx_alloc_cache(flags);
        if (cache == NULL)
          local_abort("Couldn't allocate RandomX cache");
      }
    }

    if (rx_sp->rs_height != seedheight || rx_sp->rs_cache == NULL || memcmp(seedhash, rx_sp->rs_hash, HASH_SIZE)) {
      randomx_init_cache(cache, seedhash, HASH_SIZE);
      rx_sp->rs_cache = cache;
      rx_sp->rs_height = seedheight;
      memcpy(rx_sp->rs_hash, seedhash, HASH_SIZE);
    }
  }

static void rx_dataset_init_thread(seedinfo si) {
  randomx_init_dataset(rx_dataset, si.si_cache, si.si_start, si.si_count);
}

static void __rx_init_dataset(randomx_cache *rs_cache, const uint64_t seedheight) {
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
 
  rx_dataset_height = seedheight;
}
static void rx_init_dataset(randomx_flags flags,randomx_cache *rs_cache, const uint64_t seedheight)
{
    CTHR_MUTEX_LOCK(rx_dataset_mutex);
      if (!rx_dataset_nomem) {
        if (rx_dataset == NULL) {
          if (!(disabled_flags() & RANDOMX_FLAG_LARGE_PAGES)) {
            rx_dataset = randomx_alloc_dataset(RANDOMX_FLAG_LARGE_PAGES);
            if (rx_dataset == NULL) {
              mdebug(RX_LOGCAT, "Couldn't use largePages for RandomX dataset");
            }
          }
          if (rx_dataset == NULL)
            rx_dataset = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
          if (rx_dataset != NULL)
            __rx_init_dataset(rs_cache,  seedheight);
        }
      }
      if (!rx_dataset)
       {
        if (!rx_dataset_nomem) {
          rx_dataset_nomem = 1;
          mwarning(RX_LOGCAT, "Couldn't allocate RandomX dataset for miner");
        }
      }

       if (rx_dataset != NULL && rx_dataset_height != seedheight)
            __rx_init_dataset(rs_cache,  seedheight);

      CTHR_MUTEX_UNLOCK(rx_dataset_mutex);
}
static void rx_init_vm(randomx_flags flags,randomx_cache *rs_cache){

    if (rx_dataset != NULL)
        flags |= RANDOMX_FLAG_FULL_MEM;

    if ((flags & RANDOMX_FLAG_JIT) && rx_dataset==nullptr) {
        flags |= randomx_flags(RANDOMX_FLAG_SECURE & ~disabled_flags());
    }
    if(rx_vm==nullptr){

        if (!(disabled_flags() & RANDOMX_FLAG_LARGE_PAGES)) {
          rx_vm = randomx_create_vm(flags | RANDOMX_FLAG_LARGE_PAGES, rs_cache, rx_dataset);
          if(rx_vm == NULL) { //large pages failed
            mdebug(RX_LOGCAT, "Couldn't use largePages for RandomX VM");
          }
        }
        if (rx_vm == NULL)
          rx_vm = randomx_create_vm(flags, rs_cache, rx_dataset);
        if(rx_vm == NULL) {//fallback if everything fails
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

void rx_slow_hash(const uint64_t mainheight, const uint64_t seedheight, const char *seedhash, const void *data, size_t length,  char *hash, bool miner, int is_alt) {
  const uint64_t s_height = rx_seedheight(mainheight);
  int toggle = (s_height & SEEDHASH_EPOCH_BLOCKS) != 0;
  const randomx_flags flags = randomx_flags(enabled_flags() & ~disabled_flags());

  CTHR_MUTEX_LOCK(rx_mutex);

  /* if alt block but with same seed as mainchain, no need for alt cache */
  if (is_alt) {
    if (s_height == seedheight && !memcmp(rx_s[toggle].rs_hash, seedhash, HASH_SIZE))
      is_alt = 0;
  } else {
  /* RPC could request an earlier block on mainchain */
    if (s_height > seedheight)
      is_alt = 1;
    /* miner can be ahead of mainchain */
    else if (s_height < seedheight)
      toggle ^= 1;
  }

  toggle ^= (is_alt != 0);

  const auto & rx_sp = &rx_s[toggle];
  CTHR_MUTEX_LOCK(rx_sp->rs_mutex);
  CTHR_MUTEX_UNLOCK(rx_mutex);

    rx_init_cache(flags,rx_sp,seedheight,seedhash);

    if (miner && (disabled_flags() & RANDOMX_FLAG_FULL_MEM)) {
      miner = false;
    }

    if (miner) {
      rx_init_dataset(flags,rx_sp->rs_cache,seedheight);
    }

    rx_init_vm(flags,rx_sp->rs_cache);
  
  /* mainchain users can run in parallel */
  if (!is_alt)
    CTHR_MUTEX_UNLOCK(rx_sp->rs_mutex);

  randomx_calculate_hash(rx_vm, data, length, hash);
  /* altchain slot users always get fully serialized */
  if (is_alt)
    CTHR_MUTEX_UNLOCK(rx_sp->rs_mutex);
}

void rx_slow_hash_allocate_state(void) {
}

void rx_slow_hash_free_state(void) {
  if (rx_vm != NULL) {
    randomx_destroy_vm(rx_vm);
    rx_vm = NULL;
  }
}

void rx_stop_mining(void) {
  CTHR_MUTEX_LOCK(rx_dataset_mutex);
  if (rx_dataset != NULL) {
    randomx_dataset *rd = rx_dataset;
    rx_dataset = NULL;
    randomx_release_dataset(rd);
  }
  rx_dataset_nomem = 0;
  CTHR_MUTEX_UNLOCK(rx_dataset_mutex);
}
