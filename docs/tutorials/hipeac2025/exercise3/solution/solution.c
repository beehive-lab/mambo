/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2024 University of Manchester

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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "../plugins.h"

int tutorial_pre_thread_cb(mambo_context* ctx) {
  fprintf(stderr, "[DEBUG] Starting thread %d!\n", mambo_get_thread_id(ctx));

  int ret;
  mambo_ht_t* basic_blocks = NULL;

  basic_blocks = (mambo_ht_t*) mambo_alloc(ctx, sizeof(mambo_ht_t));
  assert(basic_blocks != NULL);

  ret = mambo_ht_init(basic_blocks, 1024, 0, 80, true);
  assert(ret == 0);

  ret = mambo_set_thread_plugin_data(ctx, (void*) basic_blocks);
  assert(ret == 0);
}

int tutorial_post_thread_cb(mambo_context* ctx) {
  fprintf(stderr, "[DEBUG] Stopping thread %d!\n", mambo_get_thread_id(ctx));

  mambo_ht_t* basic_blocks = (mambo_ht_t*) mambo_get_thread_plugin_data(ctx);
  assert(basic_blocks != NULL);

  for(int i = 0; i < basic_blocks->size; i++) {

    uintptr_t key = basic_blocks->entries[i].key;

    if(key != 0) {

      uint64_t* counter = (uint64_t*) basic_blocks->entries[i].value;

      char *sym_name, *filename;
      void* symbol_start_addr;

      get_symbol_info_by_addr(key, &sym_name, &symbol_start_addr, &filename);

      printf("%s (%p) (%s) executed %lu times\n", filename, symbol_start_addr,
          (sym_name == NULL ? "none" : sym_name), *counter);

      mambo_free(ctx, (void*) counter);

      free(sym_name);
      free(filename);
    }
  }

  mambo_free(ctx, basic_blocks);
}

int tutorial_pre_basic_block_cb(mambo_context* ctx) {
  void* source_addr = mambo_get_source_addr(ctx);

  fprintf(stderr, "Basic block starts at address: %p!\n", source_addr);

  int ret;

  mambo_ht_t* basic_blocks = (mambo_ht_t*) mambo_get_thread_plugin_data(ctx);
  assert(basic_blocks != NULL);

  uint64_t* counter = NULL;

  ret = mambo_ht_get_nolock(basic_blocks, (uintptr_t) source_addr, (uintptr_t*) &counter);
  if(ret) {
    counter = (uint64_t*) mambo_alloc(ctx, sizeof(uint64_t));
    assert(counter != NULL);

    *counter = 0;

    ret = mambo_ht_add_nolock(basic_blocks, (uintptr_t) source_addr, (uintptr_t) counter);
    assert(ret == 0);
  }

  emit_counter64_incr(ctx, counter, 1);
}

int tutorial_post_basic_block_cb(mambo_context* ctx) {
  void* source_addr = mambo_get_source_addr(ctx);

  fprintf(stderr, "Basic block ends at address: %p!\n", source_addr);
}

__attribute__((constructor))
void init_tutorial() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_pre_thread_cb(ctx, &tutorial_pre_thread_cb);
  mambo_register_post_thread_cb(ctx, &tutorial_post_thread_cb);

  mambo_register_pre_basic_block_cb(ctx, &tutorial_pre_basic_block_cb);
  mambo_register_post_basic_block_cb(ctx, &tutorial_post_basic_block_cb);
}

#endif
