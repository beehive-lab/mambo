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
#include <stdio.h>

#include "../plugins.h"

int tutorial_pre_thread_cb(mambo_context* ctx) {
  fprintf(stderr, "[DEBUG] Starting thread %d!\n", mambo_get_thread_id(ctx));
}

int tutorial_post_thread_cb(mambo_context* ctx) {
  fprintf(stderr, "[DEBUG] Stopping thread %d!\n", mambo_get_thread_id(ctx));
}

int tutorial_pre_basic_block_cb(mambo_context* ctx) {
  void* source_addr = mambo_get_source_addr(ctx);

  fprintf(stderr, "Basic block starts at address: %p!\n", source_addr);
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
