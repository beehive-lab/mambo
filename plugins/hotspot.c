/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2021 University of Manchester

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#ifdef PLUGINS_NEW
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>

#include "../plugins.h"

#define DEBUG

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

#define HOTSTAT_TABLE_SIZE (1 << 14)

#define HOTSTAT_RESTRICT_ADDR 1
#if HOTSTAT_RESTRICT_ADDR
  #define HOTSTAT_MAX_BB_ADDR 0x7000000000
#endif

int hotstat_pre_thread_cb(mambo_context* ctx) {
  int ret;

  mambo_ht_t* basic_block_freq = NULL;

  basic_block_freq = (mambo_ht_t*) mambo_alloc(ctx, sizeof(mambo_ht_t));
  if(basic_block_freq == NULL) {
    fprintf(stderr, "Hotstat: Couldn't allocate the frequency table on thread %d!\n",
      mambo_get_thread_id(ctx));
    exit(1);
  }

  ret = mambo_ht_init(basic_block_freq, HOTSTAT_TABLE_SIZE, 0, 80, true);
  if(ret) {
    fprintf(stderr, "Hotstat: Couldn't initialize the frequency table on thread %d!\n",
      mambo_get_thread_id(ctx));
    exit(1);
  }

  ret = mambo_set_thread_plugin_data(ctx, (void*) basic_block_freq);
  if(ret) {
    fprintf(stderr, "Hotstat: Couldn't set the thread plugin data on thread %d!\n",
      mambo_get_thread_id(ctx));
    exit(1);
  }
}

int hotstat_post_thread_cb(mambo_context* ctx) {
  int ret;

  mambo_ht_t* basic_block_freq = (mambo_ht_t*) mambo_get_thread_plugin_data(ctx);
  if(basic_block_freq == NULL) {
    fprintf(stderr, "Hotstat: Couldn't get the thread plugin data on thread %d!\n",
      mambo_get_thread_id(ctx));
    exit(1);
  }

  mambo_ht_t* global_basic_block_freq = (mambo_ht_t*) mambo_get_plugin_data(ctx);
  if(global_basic_block_freq == NULL) {
    fprintf(stderr, "Hotstat: Couldn't get the plugin data on thread %d!\n",
      mambo_get_thread_id(ctx));
    exit(1);
  }

  __mambo_ht_lock(global_basic_block_freq);

  for(int index = 0; index < basic_block_freq->size; index++) {

    uintptr_t key = basic_block_freq->entries[index].key;
    uint64_t* counter = (uint64_t*) basic_block_freq->entries[index].value;

    uint64_t* global_counter;

    // Find valid elements in the per thread hash map
    if(key != 0) {
      // Check of the key is already in the global hash map
      if(mambo_ht_get_nolock(global_basic_block_freq, key, (uintptr_t*) &global_counter)) {
        // Add new entry if the key is not in the global map
        global_counter = (uint64_t*) mambo_alloc(ctx, sizeof(uint64_t));
        if(global_counter == NULL) {
          fprintf(stderr, "Hotstat: Couldn't allocate the global counter on thread %d!\n",
            mambo_get_thread_id(ctx));
          exit(1);
        }

        *global_counter = *counter;

        ret = mambo_ht_add_nolock(global_basic_block_freq, key, (uintptr_t) global_counter);
        if(ret) {
          fprintf(stderr, "Hotstat: Couldn't add entry to the global frequency table on thread %d!\n",
            mambo_get_thread_id(ctx));
          exit(1);
        }

        mambo_free(ctx, counter);
      }
      else {
        // Add the count from the local map to the global one if the entry already exists
        *global_counter = *global_counter + *counter;
      }
    }
  }

  __mambo_ht_unlock(global_basic_block_freq);

  mambo_free(ctx, basic_block_freq);
}

int hotstat_pre_basic_block_cb(mambo_context* ctx) {
  int ret;

  void* addr = mambo_get_source_addr(ctx);

  if((uintptr_t) addr >= HOTSTAT_MAX_BB_ADDR)
    return 0;

  mambo_ht_t* basic_block_freq = (mambo_ht_t*) mambo_get_thread_plugin_data(ctx);
  if(basic_block_freq == NULL) {
    fprintf(stderr, "Hotstat: Couldn't get the thread plugin data on thread %d!\n",
      mambo_get_thread_id(ctx));
    exit(1);
  }

  uint64_t* counter = NULL;

  if(mambo_get_fragment_type(ctx) == 0) {
    // For the basic block just create the new counter
    counter = (uint64_t*) mambo_alloc(ctx, sizeof(uint64_t));
    if(counter == NULL) {
      fprintf(stderr, "Hotstat: Couldn't allocate the counter on thread %d!\n",
        mambo_get_thread_id(ctx));
      exit(1);
    }

    ret = mambo_ht_add_nolock(basic_block_freq, (uintptr_t) addr, (uintptr_t) counter);
    if(ret) {
      fprintf(stderr, "Hotstat: Couldn't add entry to the hash map on thread %d!\n",
        mambo_get_thread_id(ctx));
      exit(1);
    }
  } else {
    // For the fragment check if the matching block is already tracked, if so just get
    // the counter address, otherwise create a new counter
    ret = mambo_ht_get_nolock(basic_block_freq, (uintptr_t) addr, (uintptr_t*) &counter);
    if(ret) {
      counter = (uint64_t*) mambo_alloc(ctx, sizeof(uint64_t));
      if(counter == NULL) {
        fprintf(stderr, "Hotstat: Couldn't allocate the counter on thread %d!\n",
          mambo_get_thread_id(ctx));
        exit(1);
      }

      ret = mambo_ht_add_nolock(basic_block_freq, (uintptr_t) addr, (uintptr_t) counter);
      if(ret) {
        fprintf(stderr, "Hotstat: Couldn't add entry to the hash map on thread %d!\n",
          mambo_get_thread_id(ctx));
        exit(1);
      }
    }
  }

  emit_counter64_incr(ctx, counter, 1);
}

int hotstat_exit_cb(mambo_context* ctx) {
  mambo_ht_t* global_basic_block_freq = (mambo_ht_t*) mambo_get_plugin_data(ctx);
  if(global_basic_block_freq == NULL) {
    fprintf(stderr, "Hotstat: Couldn't get the plugin data!\n");
    exit(1);
  }

  printf("************** Basic blocks execution count **************\n");
  fprintf(stdout, "**********************************************************\n");

  for(int index = 0; index < global_basic_block_freq->size; index++) {

    uintptr_t key = global_basic_block_freq->entries[index].key;
    uint64_t* counter = (uint64_t*) global_basic_block_freq->entries[index].value;

    if(key != 0) {
      printf("** Basic block %-16p executed %8lu times **\n", (void*) key, *counter);
    }

    mambo_free(ctx, counter);
  }

  fprintf(stdout, "**********************************************************\n");

  mambo_free(ctx, global_basic_block_freq);
}

__attribute__((constructor)) void init_hotstat() {
  int ret;

  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_ht_t* basic_block_freq = NULL;

  basic_block_freq = (mambo_ht_t*) mambo_alloc(ctx, sizeof(mambo_ht_t));
  if(basic_block_freq == NULL) {
    fprintf(stderr, "Hotstat: Couldn't allocate the global frequency table!\n");
    exit(1);
  }

  ret = mambo_ht_init(basic_block_freq, HOTSTAT_TABLE_SIZE, 0, 80, true);
  if(ret) {
    fprintf(stderr, "Hotstat: Couldn't initialize the global frequency table!\n");
    exit(1);
  }

  ret = mambo_set_plugin_data(ctx, (void*) basic_block_freq);
  if(ret) {
    fprintf(stderr, "Hotstat: Couldn't set the plugin data!\n");
    exit(1);
  }

  mambo_register_pre_thread_cb(ctx, &hotstat_pre_thread_cb);
  mambo_register_post_thread_cb(ctx, &hotstat_post_thread_cb);

  mambo_register_pre_basic_block_cb(ctx, &hotstat_pre_basic_block_cb);

  mambo_register_exit_cb(ctx, &hotstat_exit_cb);

  fprintf(stdout, "**********************************************************\n");
  fprintf(stdout, "********************* MAMBO  HOTSTAT *********************\n");
  fprintf(stdout, "**********************************************************\n");
  fprintf(stdout, "************** Executing the application... **************\n");
  fprintf(stdout, "**********************************************************\n");
}

#endif
