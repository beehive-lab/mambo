/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2019 The University of Manchester

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

void log_ib_print(void *br_from, void *br_to) {
  fprintf(stderr, "%p, %p\n", br_from, br_to);
}

int log_ib_pre_inst(mambo_context *ctx) {
  bool instrument = false;

  mambo_branch_type type = mambo_get_branch_type(ctx);
  if (type & BRANCH_INDIRECT) {
    emit_push(ctx, (1 << reg0) | (1 << reg1));
    emit_set_reg_ptr(ctx, reg0, mambo_get_source_addr(ctx));
    int ret = mambo_calc_br_target(ctx, reg1);
    while(ret != 0);
    ret = emit_safe_fcall(ctx, log_ib_print, 2);
    while(ret != 0);
    emit_pop(ctx, (1 << reg0) | (1 << reg1));
  } 
}

__attribute__((constructor)) void log_ib_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_pre_inst_cb(ctx, &log_ib_pre_inst);
}
#endif
