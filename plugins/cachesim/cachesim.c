/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2017 The University of Manchester

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
#include <locale.h>
#include "../../plugins.h"

#include "cachesim_buffer.h"
#include "cachesim_model.h"

// Instruction cache configurations

// Cortex-A5, Cortex-A7
/*
#define L1I_SIZE       (32 * 1024) // 4, 8, 16, 32 or 64 KiB for A5
                                   // 8, 16, 32 or 64 KiB for A7
#define L1I_LINE_SIZE  32
#define L1I_ASSOC      2
#define L1I_REPL       REPLACE_RANDOM
*/

// Cortex-A32, Cortex-A35
/*
#define L1I_SIZE       (32 * 1024) // 8, 16, 32 or 64 KiB for A32, A35
#define L1I_LINE_SIZE  64
#define L1I_ASSOC      2
#define L1I_REPL       REPLACE_RANDOM
*/

// Cortex-A9
/*
#define L1I_SIZE       (32 * 1024) // 16, 32 or 64 KiB for A9
#define L1I_LINE_SIZE  32
#define L1I_ASSOC      4
#define L1I_REPL       REPLACE_RANDOM
*/

// Cortex-A8, Cortex-A17
/*
#define L1I_SIZE       (32 * 1024) // 16 or 32 KiB for A8
                                   // 32 or 64 KiB for A17
#define L1I_LINE_SIZE  64
#define L1I_ASSOC      4
#define L1I_REPL       REPLACE_RANDOM
*/

// Cortex-A15
/*
#define L1I_SIZE       (32 * 1024)
#define L1I_LINE_SIZE  64
#define L1I_ASSOC      2
#define L1I_REPL       REPLACE_LRU
*/

// Cortex-A57, Cortex-A72
#define L1I_SIZE       (48 * 1024)
#define L1I_LINE_SIZE  64
#define L1I_ASSOC      3
#define L1I_REPL       REPLACE_LRU
#define L1I_MAX_FETCH  16

// Data cache configurations

// Cortex-A5, Cortex-A9
/*
#define L1D_SIZE       (32 * 1024) // 4, 8, 16, 32 or 64 KiB for A5
                                   // 16, 32 or 64 KiB for A9
#define L1D_LINE_SIZE  32
#define L1D_ASSOC      4
#define L1D_REPL       REPLACE_RANDOM
*/

// Cortex-A7, Cortex-A8, Cortex-A17, Cortex-A32, Cortex-A35, Cortex-A53
/*
#define L1D_SIZE       (32 * 1024) // 16, 32 or 64 KiB for A7
                                   // 16 or 32 KiB for A8
                                   // always 32 KiB for A17
                                   // 8, 16, 32 or 64 KiB for A32, A35, A53
#define L1D_LINE_SIZE  64
#define L1D_ASSOC      4
#define L1D_REPL       REPLACE_RANDOM
*/

// Cortex-A15, Cortex-A57, Cortex-A72
#define L1D_SIZE       (32 * 1024) // always 32 KiB
#define L1D_LINE_SIZE  64
#define L1D_ASSOC      2
#define L1D_REPL       REPLACE_LRU

// Denver 2
/*
#define L1D_SIZE       (64*1024)
#define L1D_LINE_SIZE  64
#define L1D_ASSOC      4
#define L1D_REPL       REPLACE_RANDOM //?
*/


//#define L2_SIZE       (256*1024)
//#define L2_SIZE       (512*1024)
#define L2_SIZE       (1*1024*1024)
//#define L2_SIZE       (2*1024*1024)
#define L2_LINE_SIZE  64
#define L2_ASSOC      16
#define L2_REPL       REPLACE_RANDOM

typedef struct {
  uintptr_t addr;
  uintptr_t info;
} cachesim_trace_entry_t;

typedef struct {
  uint32_t len;
  cachesim_trace_entry_t entries[BUFLEN];
  cachesim_model_t *model;
} cachesim_trace_t;

typedef struct {
  cachesim_trace_t inst_trace_buf;
  cachesim_model_t l1i_model;
  cachesim_trace_t data_trace_buf;
  cachesim_model_t l1d_model;
  void *set_inst_size;
  int fragment_size;
} cachesim_thread_t;

cachesim_model_t global_l1i;
cachesim_model_t global_l1d;
cachesim_model_t l2_model;

extern void cachesim_buf_write(uintptr_t value, cachesim_trace_t *trace);

void cachesim_proc_buf(cachesim_trace_t *trace_buf) {
  cachesim_model_t *model = trace_buf->model;
  unsigned len = trace_buf->len;
  for (int i = 0; i < len; i++) {
    cachesim_ref(model, trace_buf->entries[i].addr,
                 trace_buf->entries[i].info >> 1, trace_buf->entries[i].info & 1);
  }
  trace_buf->len = 0;
}

void inst_code(mambo_context *ctx, cachesim_thread_t *cachesim_thread) {
  emit_push(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << lr));

  void *addr = mambo_get_source_addr(ctx);
  assert(addr != NULL);
  emit_set_reg_ptr(ctx, 0, addr);

  cachesim_thread->set_inst_size = mambo_get_cc_addr(ctx);
  emit_set_reg(ctx, 1, 0);

  emit_set_reg_ptr(ctx, 2, &cachesim_thread->inst_trace_buf.entries);
  emit_fcall(ctx, cachesim_buf_write);

  emit_pop(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << lr));
}

void set_inst_size(mambo_context *ctx, cachesim_thread_t *cachesim_thread ) {
  void *tmp = mambo_get_cc_addr(ctx);
  mambo_set_cc_addr(ctx, cachesim_thread->set_inst_size);
  emit_set_reg(ctx, 1, cachesim_thread->fragment_size << 1);
  mambo_set_cc_addr(ctx, tmp);
}

int cachesim_pre_inst_handler(mambo_context *ctx) {
  cachesim_thread_t *cachesim_thread = mambo_get_thread_plugin_data(ctx);

  bool is_load = mambo_is_load(ctx);
  bool is_store = mambo_is_store(ctx);
  if (is_load || is_store) {
    mambo_cond cond = mambo_get_cond(ctx);
    mambo_branch skip_br;
    int ret;
    if (cond != AL) {
      ret = mambo_reserve_branch(ctx, &skip_br);
      assert(ret == 0);
    }

    emit_push(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << lr));    

    ret = mambo_calc_ld_st_addr(ctx, 0);
    assert(ret == 0);
    int size = mambo_get_ld_st_size(ctx);
    assert(size > 0);

    uintptr_t info = (size << 1) | (is_store ? 1 : 0);
    emit_set_reg(ctx, 1, info);
    emit_set_reg_ptr(ctx, 2, &cachesim_thread->data_trace_buf.entries);
    emit_fcall(ctx, cachesim_buf_write);

    emit_pop(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << lr));

    if (cond != AL) {
      ret = emit_local_branch_cond(ctx, &skip_br, invert_cond(cond));
      assert(ret == 0);
    }
  }

  // The maximum size we can set in one instruction
  if (cachesim_thread->fragment_size > (0x7FFF - 4)) {
    set_inst_size(ctx, cachesim_thread);
    inst_code(ctx, cachesim_thread);
    cachesim_thread->fragment_size = 0;
  }

  cachesim_thread->fragment_size += mambo_get_inst_len(ctx);
}

int cachesim_pre_bb_handler(mambo_context *ctx) {
  cachesim_thread_t *cachesim_thread = mambo_get_thread_plugin_data(ctx);

  cachesim_thread->fragment_size = 0;
  inst_code(ctx, cachesim_thread);
}

int cachesim_post_bb_handler(mambo_context *ctx) {
  cachesim_thread_t *cachesim_thread = mambo_get_thread_plugin_data(ctx);
  set_inst_size(ctx, cachesim_thread);
}

int cachesim_pre_thread_handler(mambo_context *ctx) {
  cachesim_thread_t *cachesim_thread = mambo_alloc(ctx, sizeof(*cachesim_thread));
  assert(cachesim_thread != NULL);

  int ret = cachesim_model_init(&cachesim_thread->l1i_model, "L1i", L1I_SIZE,
                                L1I_LINE_SIZE, L1I_MAX_FETCH, L1I_ASSOC, L1I_REPL);
  assert(ret == 0);
  cachesim_thread->l1i_model.parent = &l2_model;
  cachesim_thread->inst_trace_buf.model = &cachesim_thread->l1i_model;

  ret = cachesim_model_init(&cachesim_thread->l1d_model, "L1d", L1D_SIZE,
                                L1D_LINE_SIZE, 0, L1D_ASSOC, L1D_REPL);
  assert(ret == 0);
  cachesim_thread->l1d_model.parent = &l2_model;
  cachesim_thread->data_trace_buf.model = &cachesim_thread->l1d_model;

  cachesim_thread->inst_trace_buf.len = 0;
  cachesim_thread->data_trace_buf.len = 0;

  ret = mambo_set_thread_plugin_data(ctx, cachesim_thread);
  assert(ret == MAMBO_SUCCESS);
}

int cachesim_post_thread_handler(mambo_context *ctx) {
  cachesim_thread_t *cachesim_thread = mambo_get_thread_plugin_data(ctx);
  cachesim_proc_buf(&cachesim_thread->data_trace_buf);
  cachesim_proc_buf(&cachesim_thread->inst_trace_buf);

  for (int i = 0; i < 2; i++) {
    atomic_increment_u64(&global_l1i.stats.references[i],
                         cachesim_thread->l1i_model.stats.references[i]);
    atomic_increment_u64(&global_l1i.stats.misses[i],
                         cachesim_thread->l1i_model.stats.misses[i]);
    atomic_increment_u64(&global_l1i.stats.writebacks[i],
                         cachesim_thread->l1i_model.stats.writebacks[i]);

    atomic_increment_u64(&global_l1d.stats.references[i],
                         cachesim_thread->l1d_model.stats.references[i]);
    atomic_increment_u64(&global_l1d.stats.misses[i],
                         cachesim_thread->l1d_model.stats.misses[i]);
    atomic_increment_u64(&global_l1d.stats.writebacks[i],
                         cachesim_thread->l1d_model.stats.writebacks[i]);
  }

  cachesim_model_free(&cachesim_thread->l1i_model);
  cachesim_model_free(&cachesim_thread->l1d_model);
  mambo_free(ctx, cachesim_thread);
}

int cachesim_exit_handler(mambo_context *ctx) {
  printf("\n-- MAMBO cachesim " GIT_VERSION " --\n\n");
  cachesim_print_stats(&global_l1i);
  cachesim_print_stats(&global_l1d);
  cachesim_print_stats(&l2_model);
}

__attribute__((constructor)) void cachesim_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  // These L1 models aren't used, they just store the global L1 stats and configuration
  int ret = cachesim_model_init(&global_l1i, "L1i", L1I_SIZE,
                                L1I_LINE_SIZE, L1I_MAX_FETCH, L1I_ASSOC, L1I_REPL);
  assert(ret == 0);
  ret = cachesim_model_init(&global_l1d, "L1d", L1D_SIZE,
                            L1D_LINE_SIZE, 0, L1D_ASSOC, L1D_REPL);
  assert(ret == 0);

  ret = cachesim_model_init(&l2_model, "L2", L2_SIZE,
                            L2_LINE_SIZE, 0, L2_ASSOC, L2_REPL);
  assert(ret == 0);

  mambo_register_pre_thread_cb(ctx, &cachesim_pre_thread_handler);
  mambo_register_post_thread_cb(ctx, &cachesim_post_thread_handler);
  mambo_register_pre_inst_cb(ctx, &cachesim_pre_inst_handler);
  mambo_register_exit_cb(ctx, &cachesim_exit_handler);
  mambo_register_pre_basic_block_cb(ctx, &cachesim_pre_bb_handler);
  mambo_register_post_basic_block_cb(ctx, &cachesim_post_bb_handler);
}
#endif
