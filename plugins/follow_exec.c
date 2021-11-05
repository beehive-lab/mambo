/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2021 The University of Manchester

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

/*
  This plugin will make MAMBO 'follow' into any new process started by the
  application under its control by prepending a call to itself on every execve
*/

#ifdef PLUGINS_NEW

//#include <stdio.h>
#include <assert.h>
#include <sys/syscall.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "../plugins.h"

char self_exe[NAME_MAX];

int count_args(uintptr_t *args) {
  // count includes the NULL terminator
  int count = 1;
  while ((*args) != 0) {
    count++;
    args++;
  }
  return count;
}

int follow_exec_syscall(mambo_context *ctx) {
  uintptr_t call_no;
  uintptr_t *args;
  int ret = mambo_syscall_get_no(ctx, &call_no);
  assert(ret == 0);

  if (call_no == __NR_execve) {
    mambo_syscall_get_args(ctx, &args);
    assert(args != NULL);

    mambo_syscall_bypass(ctx);

    /*
      We have to do some error checking here to emulate execve errors.
      If we just try to launch a missing or invalid executable with MAMBO,
      we'll only encounter an error after the parent has been replaced by
      the newly launched MAMBO process, and at that point there's no parent
      to return the error to
    */
    if (access((char *)args[0], F_OK)) {
      mambo_syscall_set_return(ctx, -ENOENT);
      return 0;
    }

    // copy argv
    int arg_count = count_args((uintptr_t *)args[1]);
    uintptr_t *tmp_argv = alloca((arg_count+1) * sizeof(uintptr_t));
    memcpy(&tmp_argv[1], (uintptr_t *)args[1], arg_count * sizeof(uintptr_t));

    // set the original path as the first argument for MAMBO
    tmp_argv[1] = args[0];
    // prepend the path of our own executable to MAMBO's argv
    tmp_argv[0] = (uintptr_t)self_exe;

    uintptr_t ret = raw_syscall(call_no, self_exe, tmp_argv, args[2]);
    /* Normally we shouldn't return here. If we did, it means that
       MAMBO failed to start, rather than the application. */
    mambo_syscall_set_return(ctx, ret);
  }

  return 0;
}

__attribute__((constructor)) void follow_exec_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  ssize_t ret = readlink("/proc/self/exe", self_exe, NAME_MAX);
  assert(ret > 0 && ret < NAME_MAX);
  self_exe[ret] = '\0';

  mambo_register_pre_syscall_cb(ctx, &follow_exec_syscall);
}
#endif
