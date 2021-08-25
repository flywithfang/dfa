#pragma once
#include "crypto/hash.h"

void rx_slow_hash_allocate_state(void);
void rx_slow_hash_free_state(void);
uint64_t rx_seedheight(const uint64_t height);
void rx_seedheights(const uint64_t height, uint64_t *seed_height, uint64_t *next_height);

crypto::hash rx_slow_hash(const crypto::hash & K, const void *data, size_t length,bool miner=false);

 void rx_stop_mining(void);
