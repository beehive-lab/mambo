/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2019 University of Manchester

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

#define DEBUG

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

int strace_pre(mambo_context *ctx) {
  uintptr_t call_no;
  uintptr_t *args;
  int ret = mambo_syscall_get_no(ctx, &call_no);
  assert(ret == 0);
  mambo_syscall_get_args(ctx, &args);
  assert(args != NULL);
  fprintf(stderr, "syscall(%"PRIuPTR", 0x%"PRIxPTR", 0x%"PRIxPTR", 0x%"PRIxPTR", 0x%"PRIxPTR", [...])", call_no, args[0], args[1], args[2], args[3]);
}

int strace_post(mambo_context *ctx) {
  uintptr_t syscall_ret;
  int ret = mambo_syscall_get_return(ctx, &syscall_ret);
  assert(ret == 0);
  fprintf(stderr, " = 0x%"PRIxPTR"\n", syscall_ret);
}

__attribute__((constructor)) void init_strace() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);
  mambo_register_pre_syscall_cb(ctx, &strace_pre);
  mambo_register_post_syscall_cb(ctx, &strace_post);
}

#endif
