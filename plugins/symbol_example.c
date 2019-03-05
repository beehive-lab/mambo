/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2019-2020 The University of Manchester

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

#include <sys/mman.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

#include "../plugins.h"

void se_print(size_t size, uintptr_t at, uintptr_t caller) {
  char *at_name = NULL;
  char *caller_name = NULL;

  get_symbol_info_by_addr(at, &at_name, NULL, NULL);
  get_symbol_info_by_addr(caller, &caller_name, NULL, NULL);

  printf("malloc(%d) at %p (%s)\n", size, at, at_name);
  printf("  called from %p (%s)\n", caller, caller_name);
}

int se_hook(mambo_context *ctx) {
  emit_push(ctx, (1 << reg0) | (1 << reg1) | (1 << reg2));
  emit_set_reg_ptr(ctx, reg1, mambo_get_source_addr(ctx));
  emit_mov(ctx, reg2, lr);
  emit_safe_fcall(ctx, se_print, 3);
  emit_pop(ctx, (1 << reg0) | (1 << reg1) | (1 << reg2));
  return 0;
}

__attribute__((constructor)) void memcheck_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  int ret = mambo_register_function_cb(ctx, "malloc", &se_hook, NULL, 1);
  assert(ret == MAMBO_SUCCESS);
}
