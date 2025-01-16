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

void tutorial_print_mul(int64_t rn, int64_t rm) {
  fprintf(stderr, "MUL: %ld * %ld\n", rn, rm);
}

int tutorial_pre_inst_cb(mambo_context* ctx) {
  void* source_addr = mambo_get_source_addr(ctx);
#ifdef __aarch64__
  a64_instruction instruction = a64_decode(source_addr);

  if(instruction == A64_DATA_PROC_REG3) {
    unsigned int sf, op31, rm ,o0, Ra, rn, rd;
    a64_data_proc_reg3_decode_fields(source_addr, &sf, &op31, &rm, &o0, &Ra, &rn, &rd);
    if(op31 == 0x0 && o0 == 0x0 && Ra == 0x1f) {
      emit_push(ctx, (1 << x0) | (1 << x1) | (1 << lr)); 
      emit_mov(ctx, lr, rm);
      emit_mov(ctx, x0, rn);
      emit_mov(ctx, x1, lr);
      emit_safe_fcall(ctx, tutorial_print_mul, 2);
      emit_pop(ctx, (1 << x0) | (1 << x1) | (1 << lr)); 
    }
  }

#elif __riscv
  riscv_instruction instruction = riscv_decode(source_addr);

  if (instruction == RISCV_MULW) {
    unsigned int rd, rs1, rs2;
    riscv_mulw_decode_fields(source_addr, &rd, &rs1, &rs2);
    emit_push(ctx, (1 << a0) | (1 << a1) | (1 << lr));
    emit_mov(ctx, lr, rs2);
    emit_mov(ctx, a0, rs1);
    emit_mov(ctx, a1, lr);
    emit_safe_fcall(ctx, tutorial_print_mul, 2);
    emit_pop(ctx, (1 << a0) | (1 << a1) | (1 << lr));
  }
#endif
}

__attribute__((constructor))
void init_tutorial() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_pre_thread_cb(ctx, &tutorial_pre_thread_cb);
  mambo_register_post_thread_cb(ctx, &tutorial_post_thread_cb);

  mambo_register_pre_basic_block_cb(ctx, &tutorial_pre_basic_block_cb);
  mambo_register_post_basic_block_cb(ctx, &tutorial_post_basic_block_cb);

  mambo_register_pre_inst_cb(ctx, &tutorial_pre_inst_cb);
}

#endif
