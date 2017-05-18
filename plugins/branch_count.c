/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
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
#include <locale.h>
#include <inttypes.h>
#include "../plugins.h"

struct br_count {
  uint64_t direct_branch_count;
  uint64_t indirect_branch_count;
  uint64_t return_branch_count;
};

struct br_count global_counters;

int branch_count_pre_thread_handler(mambo_context *ctx) {
  struct br_count *counters = mambo_alloc(ctx, sizeof(struct br_count));
  assert(counters != NULL);
  mambo_set_thread_plugin_data(ctx, counters);

  counters->direct_branch_count = 0;
  counters->indirect_branch_count = 0;
  counters->return_branch_count = 0;
}

void print_counters(struct br_count *counters) {
  fprintf(stderr, "  direct branches: %'" PRIu64 "\n", counters->direct_branch_count);
  fprintf(stderr, "  indirect branches: %'" PRIu64 "\n", counters->indirect_branch_count);
  fprintf(stderr, "  returns: %'" PRIu64 "\n", counters->return_branch_count);
}

int branch_count_post_thread_handler(mambo_context *ctx) {
  struct br_count *counters = mambo_get_thread_plugin_data(ctx);

  fprintf(stderr, "Thread: %d\n", mambo_get_thread_id(ctx));
  print_counters(counters);
  atomic_increment_u64(&global_counters.direct_branch_count,
                       counters->direct_branch_count);
  atomic_increment_u64(&global_counters.indirect_branch_count,
                       counters->indirect_branch_count);
  atomic_increment_u64(&global_counters.return_branch_count,
                       counters->return_branch_count);
  mambo_free(ctx, counters);
}

int branch_count_exit_handler(mambo_context *ctx) {
  fprintf(stderr, "Total:\n");
  print_counters(&global_counters);
}

int branch_count_pre_inst_handler(mambo_context *ctx) {
  struct br_count *counters = mambo_get_thread_plugin_data(ctx);
  uint64_t *counter = NULL;

  mambo_branch_type type = mambo_get_branch_type(ctx);
  if (type & BRANCH_RETURN) {
    counter = &counters->return_branch_count;
  } else if (type & BRANCH_DIRECT) {
    counter = &counters->direct_branch_count;
  } else if (type & BRANCH_INDIRECT) {
    counter = &counters->indirect_branch_count;
  }
 
  if (counter != NULL) {
    emit_counter64_incr(ctx, counter, 1);
  }
}

__attribute__((constructor)) void branch_count_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_pre_inst_cb(ctx, &branch_count_pre_inst_handler);
  mambo_register_pre_thread_cb(ctx, &branch_count_pre_thread_handler);
  mambo_register_post_thread_cb(ctx, &branch_count_post_thread_handler);
  mambo_register_exit_cb(ctx, &branch_count_exit_handler);
  
  setlocale(LC_NUMERIC, "");
}
#endif
