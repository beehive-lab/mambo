/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2022 University of Manchester

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

#include <sys/mman.h>

#include "../plugins.h"

#define DEBUG

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

#define HOTSTAT_TABLE_SIZE (1 << 14)

// When HOTSTAT_RESTRICT_ADDR is disabled the hotstat plugin follows all basic
// blocks executed by the application, including calls to the system libraries.
// This may be a desired behaviour, however it results in a lot of basic blocks
// being traced obscuring a readability of the final report. When enabled
// HOTSTAT_RESTRICT_ADDR is enabled only blocks with an address lower than
// HOTSTAT_MAX_BB_ADDR are followed. Depending in the system setup and how the
// target application is compiled this trick may or may not work. On a simple
// ARM64 board running Ubuntu and with a target application compiled with
// -no-pie, the application code lives in the address space starting with
// 0x400000, and libraries being loaded to addresses above 0x7000000000.
// Note: It does not work with position independent code.
// #define HOTSTAT_RESTRICT_ADDR

#ifdef HOTSTAT_RESTRICT_ADDR
  #define HOTSTAT_MAX_BB_ADDR 0x7000000000
#else
  #define HOTSTAT_MAX_BB_ADDR 0x0
#endif

// They are technically hash map internal functions, but we re-use them here
// directly to enable coarser-grained locking.
void __mambo_ht_lock(mambo_ht_t *ht);
void __mambo_ht_unlock(mambo_ht_t *ht);

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
      // Check if the key is already in the global hash map
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

#ifdef HOTSTAT_RESTRICT_ADDR
  if((uintptr_t) addr >= (uintptr_t) HOTSTAT_MAX_BB_ADDR)
    return 0;
#endif

  mambo_ht_t* basic_block_freq = (mambo_ht_t*) mambo_get_thread_plugin_data(ctx);
  if(basic_block_freq == NULL) {
    fprintf(stderr, "Hotstat: Couldn't get the thread plugin data on thread %d!\n",
      mambo_get_thread_id(ctx));
    exit(1);
  }

  uint64_t* counter = NULL;

  // We have to check if the block already exists as the same block can be scanned
  // multiple times.
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

  emit_counter64_incr(ctx, counter, 1);
}

int hotstat_exit_cb(mambo_context* ctx) {
  mambo_ht_t* global_basic_block_freq = (mambo_ht_t*) mambo_get_plugin_data(ctx);
  if(global_basic_block_freq == NULL) {
    fprintf(stderr, "Hotstat: Couldn't get the plugin data!\n");
    exit(1);
  }

  printf("************** Basic blocks execution count **************\n");
  printf("**********************************************************\n");

  // To avoid sorting the hashmap we print blocks in the descending orders
  // by finding and printing the max value.
  for(int i = 0; i < global_basic_block_freq->size; i++) {
    uint64_t max_counter = 0;
    uint64_t max_idx = 0;
    uintptr_t max_addr = 0;

    // Find max not visited value in the hashmap.
    for(int j = 0; j < global_basic_block_freq->size; j++) {
      uintptr_t key = global_basic_block_freq->entries[j].key;

      if(key == 0) {
        continue;
      }

      uint64_t* counter = (uint64_t*) global_basic_block_freq->entries[j].value;

      if(*counter > max_counter) {
        max_counter = *counter;
        max_addr = key;
        max_idx = j;
      }
    }

    // No new value found so stop printing.
    if(max_addr == 0) {
      break;
    }

    // Mark entry in the hashmap as visited and free the counter.
    global_basic_block_freq->entries[max_idx].key = 0;
    mambo_free(ctx, (void*) global_basic_block_freq->entries[max_idx].value);

    char *sym_name, *filename;
    void *symbol_start_addr;

    get_symbol_info_by_addr(max_addr, &sym_name, &symbol_start_addr, &filename);

    uint64_t relative_addr = (uint64_t) max_addr - (uint64_t) symbol_start_addr;

    printf("%s + 0x%lx (%s) executed %lu times\n", filename, relative_addr,
        (sym_name == NULL ? "none" : sym_name), max_counter);

    free(sym_name);
    free(filename);
  }

  printf("**********************************************************\n");

  mambo_free(ctx, global_basic_block_freq);
}

int hotstat_vm_op_cb(mambo_context* ctx) {
  vm_op_t vm_op = mambo_get_vm_op(ctx);
  int vm_prot = mambo_get_vm_prot(ctx);

  if((vm_op == VM_UNMAP) && (vm_prot & PROT_EXEC)) {
    fprintf(stderr, "Hotstat: VM UNMAP event detected! Mapping of basic blocks to symbols may be incorrect!\n");
  }
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

  mambo_register_vm_op_cb(ctx, &hotstat_vm_op_cb);

  mambo_register_exit_cb(ctx, &hotstat_exit_cb);

  printf("**********************************************************\n");
  printf("********************* MAMBO  HOTSTAT *********************\n");
  printf("**********************************************************\n");
  printf("************** Executing the application... **************\n");
  printf("**********************************************************\n");
}

#endif
