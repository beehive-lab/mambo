/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2018-2020 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2018-2020 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
  Copyright 2018-2020 Unai Martinez-Corral <unai.martinezcorral at ehu dot eus>
  Copyright 2018-2020 The University of Manchester

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
#include "../../plugins.h"

// The prototype of FR_REPLACEMENT must be provided; here a header file is used
#include <replacement.h>

int FR_HANDLER(mambo_context *ctx) {

  /* specifying MAX_FCALL_ARGS so that only the LR is saved on the stack,
     without the other caller-saved registers
     safe because the application was compiled already expecting a function entry here
     */
  emit_safe_fcall(ctx, FR_REPLACEMENT, MAX_FCALL_ARGS);
  // edit: any post-function code goes here instead of the post-function callback
  emit_indirect_branch_by_spc(ctx, lr);
  mambo_stop_scan(ctx);

  return 0;

}

__attribute__((constructor)) void FR_PLUGIN() {

  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  // note: do NOT register a post-hook; any post-function code goes in FR_HANDLER
  int ret = mambo_register_function_cb(ctx, FR_ORIGINAL, &FR_HANDLER, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  setlocale(LC_NUMERIC, "");

}

#endif
