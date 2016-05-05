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

#include <assert.h>
#include <sys/mman.h>

#include "../dbm.h"
#include "../common.h"

#ifdef PLUGINS_NEW

/* Plugin management */
mambo_context *mambo_register_plugin(void) {
  int index = global_data.free_plugin++;
  static mambo_context tmp_ctx;

  if (index >= MAX_PLUGIN_NO) {
    return NULL;
  }

  set_mambo_context(&tmp_ctx, NULL, -1, -1, -1, -1, -1, NULL, NULL, NULL);
  tmp_ctx.plugin_id = index;

  return &tmp_ctx;
}

/* Callback management */
int __mambo_register_cb(mambo_context *ctx, mambo_cb_idx cb_idx, mambo_callback cb) {
  unsigned int p_id = ctx->plugin_id;

  if (cb_idx >= CALLBACK_MAX_IDX || cb_idx < 0) {
    return MAMBO_INVALID_CB;
  }

  if (p_id >= MAX_PLUGIN_NO) {
    return MAMBO_INVALID_PLUGIN_ID;
  }

  if (global_data.plugins[p_id].cbs[cb_idx] != NULL) {
    return MAMBO_CB_ALREADY_SET;
  }

  global_data.plugins[p_id].cbs[cb_idx] = cb;

  return MAMBO_SUCCESS;
}

int mambo_register_pre_inst_cb(mambo_context *ctx, mambo_callback cb) {
  return __mambo_register_cb(ctx, PRE_INST_C, cb);
}

int mambo_register_post_inst_cb(mambo_context *ctx, mambo_callback cb) {
  return __mambo_register_cb(ctx, POST_INST_C, cb);
}

int mambo_register_pre_fragment_cb(mambo_context *ctx, mambo_callback cb) {
  return __mambo_register_cb(ctx, PRE_FRAGMENT_C, cb);
}

int mambo_register_post_fragment_cb(mambo_context *ctx, mambo_callback cb) {
  return __mambo_register_cb(ctx, POST_FRAGMENT_C, cb);
}

int mambo_register_pre_syscall_cb(mambo_context *ctx, mambo_callback cb) {
  return __mambo_register_cb(ctx, PRE_SYSCALL_C, cb);
}

int mambo_register_post_syscall_cb(mambo_context *ctx, mambo_callback cb) {
  return __mambo_register_cb(ctx, POST_SYSCALL_C, cb);
}

int mambo_register_pre_thread_cb(mambo_context *ctx, mambo_callback cb) {
  return __mambo_register_cb(ctx, PRE_THREAD_C, cb);
}

int mambo_register_post_thread_cb(mambo_context *ctx, mambo_callback cb) {
  return __mambo_register_cb(ctx, POST_THREAD_C, cb);
}

int mambo_register_exit_cb(mambo_context *ctx, mambo_callback cb) {
  return __mambo_register_cb(ctx, EXIT_C, cb);
}

/* Access plugin data */
int mambo_set_plugin_data(mambo_context *ctx, void *data) {
  unsigned int p_id = ctx->plugin_id;
  if (p_id >= global_data.free_plugin) {
    return MAMBO_INVALID_PLUGIN_ID;
  }
  return MAMBO_SUCCESS;
}

void *mambo_get_plugin_data(mambo_context *ctx) {
  unsigned int p_id = ctx->plugin_id;
  if (p_id >= global_data.free_plugin) {
    return NULL;
  }
  return global_data.plugins[p_id].data;
}

int mambo_set_thread_plugin_data(mambo_context *ctx, void *data) {
  unsigned int p_id = ctx->plugin_id;
  if (p_id >= global_data.free_plugin) {
    return MAMBO_INVALID_PLUGIN_ID;
  }
  if (ctx->thread_data == NULL) {
    return MAMBO_INVALID_THREAD;
  }
  ctx->thread_data->plugin_priv[p_id] = data;
  return MAMBO_SUCCESS;
}

void *mambo_get_thread_plugin_data(mambo_context *ctx) {
  unsigned int p_id = ctx->plugin_id;
  if (p_id >= global_data.free_plugin) {
    return NULL;
  }
  if (ctx->thread_data == NULL) {
    return NULL;
  }
  return ctx->thread_data->plugin_priv[p_id];
}

/* Memory management */
void *mambo_alloc(mambo_context *ctx, size_t size) {
  return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

void mambo_free(mambo_context *ctx, void *ptr) {
}

/* Other */
int mambo_get_inst(mambo_context *ctx) {
  return ctx->inst;
}

inst_set mambo_get_inst_type(mambo_context *ctx) {
  return ctx->inst_type;
}

int mambo_get_fragment_id(mambo_context *ctx) {
  return ctx->fragment_id;
}

cc_type mambo_get_fragment_type(mambo_context *ctx) {
  return ctx->fragment_type;
}

int mambo_get_inst_len(mambo_context *ctx) {
  int inst = mambo_get_inst(ctx);
  // Not an instruction event
  if (inst == -1) {
    return -1;
  }
  if (mambo_get_inst_type(ctx) == ARM_INST) {
    return 4;
  } else {
    return (inst < THUMB_ADCI32) ? 2 : 4;
  }
}

void *mambo_get_source_addr(mambo_context *ctx) {
  return ctx->read_address;
}

void *mambo_get_cc_addr(mambo_context *ctx) {
  return ctx->write_p;
}

void mambo_set_cc_addr(mambo_context *ctx, void *addr) {
  assert(ctx->write_p != NULL);
  ctx->write_p = addr;
}

int mambo_get_thread_id(mambo_context *ctx) {
  return ctx->thread_data->tid;
}

mambo_cond mambo_get_cond(mambo_context *ctx) {
  return ctx->cond;
}

bool mambo_is_cond(mambo_context *ctx) {
  return ctx->cond != AL;
}

mambo_cond mambo_get_inverted_cond(mambo_context *ctx, mambo_cond cond) {
  return arm_inverse_cond_code[cond & 0xF];
}

#endif
