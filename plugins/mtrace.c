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
#include "../plugins.h"

#include "mtrace.h"

struct mtrace_entry {
  uintptr_t addr;
  uintptr_t info;
};

struct mtrace {
  uint32_t len;
  struct mtrace_entry entries[BUFLEN];
};

extern void mtrace_print_buf_trampoline(struct mtrace *trace);
extern void mtrace_buf_write(uintptr_t value, struct mtrace *trace);

void mtrace_print_buf(struct mtrace *mtrace_buf) {
  for (int i = 0; i < mtrace_buf->len; i++) {
    /* Warning: printing formatted strings is very slow
       For practical use, you are encouraged to process the data in memory
       or write the trace in the raw binary format */
    int size = (int)(mtrace_buf->entries[i].info >> 1);
    char *type = (mtrace_buf->entries[i].info & 1) ? "w" : "r";
    fprintf(stderr, "%s: %p\t%d\n", type, (void *)mtrace_buf->entries[i].addr, size);
  }
  mtrace_buf->len = 0;
}

int mtrace_pre_inst_handler(mambo_context *ctx) {
  struct mtrace *mtrace_buf = mambo_get_thread_plugin_data(ctx);
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
    emit_set_reg_ptr(ctx, 2, &mtrace_buf->entries);
    emit_fcall(ctx, mtrace_buf_write);

    emit_pop(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << lr));

    if (cond != AL) {
      ret = emit_local_branch_cond(ctx, &skip_br, invert_cond(cond));
      assert(ret == 0);
    }
  }
}

int mtrace_pre_thread_handler(mambo_context *ctx) {
  struct mtrace *mtrace_buf = mambo_alloc(ctx, sizeof(*mtrace_buf));
  assert(mtrace_buf != NULL);
  mtrace_buf->len = 0;

  int ret = mambo_set_thread_plugin_data(ctx, mtrace_buf);
  assert(ret == MAMBO_SUCCESS);
}

int mtrace_post_thread_handler(mambo_context *ctx) {
  struct mtrace *mtrace_buf = mambo_get_thread_plugin_data(ctx);
  mtrace_print_buf(mtrace_buf);
  mambo_free(ctx, mtrace_buf);
}

__attribute__((constructor)) void mtrace_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_pre_thread_cb(ctx, &mtrace_pre_thread_handler);
  mambo_register_post_thread_cb(ctx, &mtrace_post_thread_handler);
  mambo_register_pre_inst_cb(ctx, &mtrace_pre_inst_handler);
}
#endif
