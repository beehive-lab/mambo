/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2017-2019 The University of Manchester

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

#include <assert.h>

#include "../dbm.h"
#include "../plugins.h"

/* Helpers used internally by MAMBO to implement the API */

#ifdef PLUGINS_NEW
void set_mambo_context(mambo_context *ctx, dbm_thread *thread_data, mambo_cb_idx event_type) {
  ctx->thread_data = thread_data;
  ctx->event_type = event_type;
}

void set_mambo_context_code(mambo_context *ctx, dbm_thread *thread_data, mambo_cb_idx event_type,
                            cc_type fragment_type, int fragment_id, inst_set inst_type, int inst,
                            mambo_cond cond, void *read_address, void *write_p, void *data_p, bool *stop) {
  set_mambo_context(ctx, thread_data, event_type);
  ctx->code.inst_type = inst_type;
  ctx->code.fragment_type = fragment_type;
  ctx->code.fragment_id = fragment_id;
  ctx->code.inst = inst;
  ctx->code.cond = cond;
  ctx->code.read_address = read_address;
  ctx->code.write_p = write_p;
  ctx->code.data_p = data_p;
  ctx->code.replace = false;
  ctx->code.pushed_regs = 0;
  ctx->code.available_regs = 0;
  ctx->code.plugin_pushed_reg_count = 0;
  ctx->code.stop = stop;
}

void set_mambo_context_syscall(mambo_context *ctx, dbm_thread *thread_data, mambo_cb_idx event_type,
                               uintptr_t number, uintptr_t *regs) {
  set_mambo_context(ctx, thread_data, event_type);
  ctx->syscall.number = number;
  ctx->syscall.regs = regs;
  ctx->syscall.replace = false;
}
#endif

void mambo_deliver_callbacks_for_ctx(mambo_context *ctx) {
#ifdef PLUGINS_NEW
  unsigned cb_id = ctx->event_type;
  assert(cb_id < CALLBACK_MAX_IDX);

  for (int i = 0; i < global_data.free_plugin; i++) {
    if (global_data.plugins[i].cbs[cb_id] != NULL) {
      ctx->plugin_id = i;
      global_data.plugins[i].cbs[cb_id](ctx);
    } // if
  } // for
#endif
}

void mambo_deliver_callbacks(unsigned cb_id, dbm_thread *thread_data) {
#ifdef PLUGINS_NEW
  mambo_context ctx;

  if (global_data.free_plugin > 0) {
    set_mambo_context(&ctx, thread_data, cb_id);
    mambo_deliver_callbacks_for_ctx(&ctx);
  }
#endif
}

void mambo_deliver_callbacks_code(unsigned cb_id, dbm_thread *thread_data, cc_type fragment_type,
                                  int fragment_id, inst_set inst_type, int inst, mambo_cond cond,
                                  void *read_address, void *write_p, void *data_p, bool *stop) {
#ifdef PLUGINS_NEW
  mambo_context ctx;

  if (global_data.free_plugin > 0) {
    set_mambo_context_code(&ctx, thread_data, cb_id, fragment_type, fragment_id,
                           inst_type, inst, cond, read_address, write_p, data_p, stop);
    mambo_deliver_callbacks_for_ctx(&ctx);
  }
#endif
}

void _function_callback_wrapper(mambo_context *ctx, watched_func_t *func) {
#ifdef PLUGINS_NEW
  ctx->plugin_id = func->plugin_id;
  ctx->code.available_regs = ctx->code.pushed_regs;
  ctx->code.func_name = func->name;

  if (func->post_callback != NULL) {
    emit_push(ctx, (1 << es) | (1 << lr));
  }
  if (func->pre_callback != NULL) {
    ctx->event_type = PRE_FN_C;
    func->pre_callback(ctx);
  }
  if (func->post_callback != NULL) {
    mambo_branch fcall;
    int ret = mambo_reserve_branch(ctx, &fcall);
    assert(ret == 0);

    ret = mambo_add_identity_mapping(ctx);
    assert(ret == 0);

    // Hack; pop the registers pushed by IHL routines
    ctx->code.plugin_pushed_reg_count += 2;
#ifdef __aarch64__
    emit_pop(ctx, (1 << x0) | (1 << x1));
#elif __arm__
    emit_pop(ctx, (1 << r5) | (1 << r6));
#endif

    ctx->event_type = POST_FN_C;
    func->post_callback(ctx);

    emit_pop(ctx, (1 << es) | (1 << lr));
    // IHL(LR) - emulated return to the caller of malloc()
    emit_indirect_branch_by_spc(ctx, lr);
    emit_local_fcall(ctx, &fcall);
  }
#endif
}
