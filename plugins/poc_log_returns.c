/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2018 The University of Manchester

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

void log_returns_print(void *return_from, void *return_to) {
  fprintf(stderr, "Return from %p to %p\n", return_from, return_to);
}

/* Proof of concept. Note that only a subset of returns are currently instrumented by this code */
int log_returns_pre_inst(mambo_context *ctx) {
  bool instrument = false;
#ifdef __arm__
  inst_set isa = mambo_get_inst_type(ctx);
  int inst = mambo_get_inst(ctx);
  if (isa == ARM_INST) {
    if (inst == ARM_BX) {
      uint32_t rn;
      arm_bx_decode_fields(mambo_get_source_addr(ctx), &rn);
      if (rn == lr) {
        instrument = true;
      }
    }
  } else if (isa == THUMB_INST) {
    fprintf(stderr, "poc_log_returns: Thumb support not implemented yet\n");
  }
#else
  #error "Current ISA not supported yet"
#endif
  if (instrument) {
    emit_push(ctx, (1 << reg0) | (1 << reg1));
    emit_set_reg_ptr(ctx, reg0, mambo_get_source_addr(ctx));
    emit_mov(ctx, reg1, lr);
    emit_safe_fcall(ctx, log_returns_print, 2);
    emit_pop(ctx, (1 << reg0) | (1 << reg1));
  }
}

__attribute__((constructor)) void branch_count_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_pre_inst_cb(ctx, &log_returns_pre_inst);
}
#endif
