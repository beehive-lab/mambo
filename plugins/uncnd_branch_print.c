/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2021 The University of Manchester

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
#include <locale.h>
#include <inttypes.h>
#include "../plugins.h"

int uncnd_branch_print_pre_thread_handler(mambo_context *ctx) {
  uint64_t *uncnd_br_count = mambo_alloc(ctx, sizeof(uint64_t));
  *uncnd_br_count = 0;
  assert(uncnd_br_count != NULL);
  mambo_set_thread_plugin_data(ctx, uncnd_br_count);
  return 0;
}

// Called when a thread exits, or in all threads when the process exits
int uncnd_branch_print_post_thread_handler(mambo_context *ctx) {
  uint64_t *uncnd_br_count = mambo_get_thread_plugin_data(ctx);
  fprintf(stderr, "%'lu unconditional branches executed in thread %d\n", *uncnd_br_count, mambo_get_thread_id(ctx));
  mambo_free(ctx, uncnd_br_count);
  return 0;
}

int uncnd_branch_print_pre_inst_handler(mambo_context *ctx) {
  uint64_t *counter = mambo_get_thread_plugin_data(ctx);
  mambo_branch_type type = mambo_get_branch_type(ctx);
  if (!(type & BRANCH_COND || type & BRANCH_NONE)) {
    emit_counter64_incr(ctx, counter, 1);
  }
  return 0;
}

int uncnd_branch_print_post_inst_handler(mambo_context *ctx) {
  mambo_branch_type type = mambo_get_branch_type(ctx);
  if (!(type & BRANCH_COND || type & BRANCH_NONE)) {
    fprintf(stderr, "RISCV unconditional branch: read_addr: %p, target: 0x%ld, branch type: %d\n", mambo_get_source_addr(ctx), ctx->thread_data->code_cache_meta[mambo_get_fragment_id(ctx)].branch_taken_addr, ctx->code.inst);
  }
  return 0;
}

__attribute__((constructor)) void uncnd_branch_print_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_post_inst_cb(ctx, &uncnd_branch_print_post_inst_handler);
  mambo_register_pre_inst_cb(ctx, &uncnd_branch_print_pre_inst_handler);
  mambo_register_pre_thread_cb(ctx, &uncnd_branch_print_pre_thread_handler);
  mambo_register_post_thread_cb(ctx, &uncnd_branch_print_post_thread_handler);

  setlocale(LC_NUMERIC, "");
}

#endif 