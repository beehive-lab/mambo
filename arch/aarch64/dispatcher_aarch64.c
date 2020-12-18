/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2015-2017 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
  Copyright 2017-2020 The University of Manchester

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

#include <stdio.h>

#include "../../dbm.h"
#include "../../scanner_common.h"

#include "../../pie/pie-a64-encoder.h"

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

void insert_cond_exit_branch(dbm_code_cache_meta *bb_meta, void **o_write_p, int cond) {
  void *write_p = *o_write_p;
  switch(bb_meta->exit_branch_type) {
    case uncond_imm_a64:
      return;
    case cond_imm_a64:
      a64_b_cond_helper(write_p, (uint64_t)write_p + 8, cond);
      break;
    case cbz_a64:
      a64_cbz_cbnz_helper(write_p, cond, (uint64_t)write_p + 8,
                          bb_meta->rn >> 5, bb_meta->rn & 0x1F);
      break;
    case tbz_a64:
      a64_tbz_tbnz_helper(write_p, cond, (uint64_t)write_p + 8,
                          bb_meta->rn & 0x1F, bb_meta->rn >> 5);
      break;
    default:
      fprintf(stderr, "insert_cond_exit_branch(): unknown branch type\n");
      while(1);
  }

  write_p += 4;
  *o_write_p = write_p;
}

void dispatcher_aarch64(dbm_thread *thread_data, uint32_t source_index, branch_type exit_type,
                        uintptr_t target, uintptr_t block_address) {
  uint32_t *branch_addr;
  bool is_taken;
  uintptr_t other_target;
  bool other_target_in_cache;
  mambo_cond cond;

  switch (exit_type) {
  #ifdef DBM_LINK_UNCOND_IMM
    case uncond_imm_a64:
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
      a64_cc_branch(thread_data, branch_addr, block_address + 4);
      __clear_cache((void *)branch_addr, (void *)branch_addr + 4 + 1);
      thread_data->code_cache_meta[source_index].branch_cache_status = BRANCH_LINKED;
      break;
  #endif
  #ifdef DBM_LINK_COND_IMM
    case cond_imm_a64:
  #endif
  #ifdef DBM_LINK_CBZ
    case cbz_a64:
  #endif
  #ifdef DBM_LINK_TBZ
    case tbz_a64:
  #endif
  #if defined(DBM_LINK_COND_IMM) || defined(DBM_LINK_CBZ) || defined(DBM_LINK_TBZ)
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
      is_taken = target == thread_data->code_cache_meta[source_index].branch_taken_addr;

      if (thread_data->code_cache_meta[source_index].branch_cache_status == 0) {
        if (is_taken) {
          other_target = thread_data->code_cache_meta[source_index].branch_skipped_addr;
        } else {
          other_target = thread_data->code_cache_meta[source_index].branch_taken_addr;
        }
        other_target = cc_lookup(thread_data, other_target);
        other_target_in_cache = (other_target != UINT_MAX);

        cond = thread_data->code_cache_meta[source_index].branch_condition;
        if (is_taken) {
          cond = invert_cond(cond);
        }
        insert_cond_exit_branch(&thread_data->code_cache_meta[source_index], (void **)&branch_addr, cond);

        thread_data->code_cache_meta[source_index].branch_cache_status =
                      (is_taken ? BRANCH_LINKED : FALLTHROUGH_LINKED);
      } else {
        branch_addr += 2;
        other_target_in_cache = false;
        thread_data->code_cache_meta[source_index].branch_cache_status |= BOTH_LINKED;
      }

      a64_cc_branch(thread_data, branch_addr, block_address + 4);
      branch_addr++;

      if (other_target_in_cache) {
        a64_cc_branch(thread_data, branch_addr, other_target + 4);
        branch_addr++;
        thread_data->code_cache_meta[source_index].branch_cache_status |= BOTH_LINKED;
      }

      __clear_cache((void *)thread_data->code_cache_meta[source_index].exit_branch_addr,
                    (void *)branch_addr);
      break;
  #endif
  }
}
