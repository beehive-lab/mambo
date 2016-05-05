/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>

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
#include "../plugins.h"

// Called for each instruction scanned by MAMBO, before the translation is generated
int tb_cnt_pre_inst_handler(mambo_context *ctx) {
  void *skip_branch = NULL;

  if (mambo_get_inst_type(ctx) == THUMB_INST
      && (mambo_get_inst(ctx) == THUMB_TBB32) || (mambo_get_inst(ctx) == THUMB_TBH32)) {

    if (mambo_is_cond(ctx)) {
      skip_branch = mambo_get_cc_addr(ctx);
      mambo_set_cc_addr(ctx, skip_branch + 2);
    }

    emit_thumb_push16(ctx, (1 << r0) | (1 << r1) | (1 << r2)); // PUSH {R0-R2}
    emit_thumb_push_cpsr(ctx, r0);                  // MRS  R0, CPSR; PUSH {R0}
    // MOVW R0, #(ptr_to_ctr & 0xFFFF)
    // MOVT R0, #(ptr_to_ctr >> 16)
    emit_thumb_copy_to_reg_32bit(ctx, r0, (uint32_t)mambo_get_thread_plugin_data(ctx));
    emit_thumb_ldrd32(ctx, 1, 1, 0, r0, r1, r2, 0); // LDRD R1, R2, [R0, #0]
    emit_thumb_addi16(ctx, 1, r1, r1);              // ADDS R1, R1, #1       
    emit_thumb_adci32(ctx, 0, 0, r2, 0, r2, 0);     // ADC  R2, R2, #0        
    emit_thumb_strd32(ctx, 1, 1, 0, r0, r1, r2, 0); // STRD R1, R2, [R0, #0]
    emit_thumb_pop_cpsr(ctx, r0);                   // POP {R0}; MSR CPSR, R0
    emit_thumb_pop16(ctx, (1 << r0) | (1 << r1) | (1 << r2));  // POP {R0-R2}

    if (skip_branch != NULL) {
      emit_thumb_b16_cond(skip_branch, mambo_get_cc_addr(ctx), mambo_get_cond(ctx));
      fprintf(stderr, "TB count: cond TB instrumentation is untested.\n");
      while(1);
    }
  }
  return 0;
}

// Called when a new thread is created, including the initial thread
int tb_cnt_pre_thread_handler(mambo_context *ctx) {
  uint64_t *inst_counter = mambo_alloc(ctx, sizeof(uint64_t));
  *inst_counter = 0;
  assert(inst_counter != NULL);
  mambo_set_thread_plugin_data(ctx, inst_counter);
  return 0;
}

// Called when a thread exits, or in all threads when the process exits
int tb_cnt_post_thread_handler(mambo_context *ctx) {
  uint64_t *inst_counter = mambo_get_thread_plugin_data(ctx);
  fprintf(stderr, "%'llu TB instructions executed in thread %d\n", *inst_counter, mambo_get_thread_id(ctx));
  mambo_free(ctx, inst_counter);
  return 0;
}

__attribute__((constructor)) void tb_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_pre_inst_cb(ctx, &tb_cnt_pre_inst_handler);
  mambo_register_pre_thread_cb(ctx, &tb_cnt_pre_thread_handler);
  mambo_register_post_thread_cb(ctx, &tb_cnt_post_thread_handler);
  
  setlocale(LC_NUMERIC, "");
}
#endif
