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

#include "../../pie/pie-thumb-encoder.h"
#include "../../pie/pie-arm-encoder.h"

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

void insert_cond_exit_branch(dbm_code_cache_meta *bb_meta, void **o_write_p, int cond) {
  void *write_p = *o_write_p;
  switch(bb_meta->exit_branch_type) {
    case cond_imm_thumb:
      thumb_it16((uint16_t **)&write_p, cond, 0x8);
      write_p += 2;
      break;
    case cbz_thumb:
      if (bb_meta->branch_cache_status & FALLTHROUGH_LINKED) {
        thumb_cbz16((uint16_t **)&write_p, 0, 0x01, bb_meta->rn);
      } else {
        thumb_cbnz16((uint16_t **)&write_p, 0, 0x01, bb_meta->rn);
      }
      write_p += 2;
      break;
    case cond_imm_arm:
      break;
    default:
      fprintf(stderr, "insert_cond_exit_branch(): unknown branch type\n");
      while(1);
  }

  *o_write_p = write_p;
}

void dispatcher_aarch32(dbm_thread *thread_data, uint32_t source_index, branch_type exit_type,
                        uintptr_t target, uintptr_t block_address) {
  uint16_t  *branch_addr;
  int       cache_index;
  bool      is_taken;
  uintptr_t other_target;
  bool      other_target_in_cache;
  uint32_t  cond;

  switch (exit_type) {
#ifdef DBM_TB_DIRECT
    case tbb:
    case tbh: {
      /* the index is invalid only when the inline hash lookup is called for a new BB,
         no linking is required */
  #ifdef FAST_BT
      if (thread_data->code_cache_meta[source_index].rn >= TB_CACHE_SIZE) {
        break;
      }
    #else
      if (thread_data->code_cache_meta[source_index].rn >= MAX_TB_INDEX) {
        break;
      }
    #endif
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
    #ifdef FAST_BT
      uint32_t *branch_table = (uint32_t *)(((uint32_t)branch_addr + 20 + 2) & 0xFFFFFFFC);
      branch_table[thread_data->code_cache_meta[source_index].rn] = block_address;
    #else
      branch_addr += 7;
      uint8_t *table = (uint8_t *)branch_addr;
      if (thread_data->code_cache_meta[source_index].free_b == TB_CACHE_SIZE) {
        // if the list of linked blocks is full, link this index to the inline hash lookup
      #ifdef DBM_D_INLINE_HASH
        table[thread_data->code_cache_meta[source_index].rn] = MAX_TB_INDEX / 2 + TB_CACHE_SIZE * 2 + 1;
      #else
        table[thread_data->code_cache_meta[source_index].rn] = MAX_TB_INDEX / 2 + TB_CACHE_SIZE * 2;
      #endif
      } else {
        // allocate a branch slot and link it
        cache_index = thread_data->code_cache_meta[source_index].free_b++;
        table[thread_data->code_cache_meta[source_index].rn] = MAX_TB_INDEX / 2 + cache_index * 2;
        
        // insert the branch to the target BB
        branch_addr += MAX_TB_INDEX / 2 + cache_index * 2;
        thumb_cc_branch(thread_data, branch_addr, (uint32_t)block_address);
        __clear_cache(branch_addr, branch_addr + 5);
      }
    #endif
      
      // invalidate the saved rm value - required to detect calls from the inline hash lookup
      thread_data->code_cache_meta[source_index].rn = INT_MAX;

      break;
    }
  #endif // DBM_TB_DIRECT
  #ifdef DBM_LINK_UNCOND_IMM
    case uncond_imm_thumb:
    case uncond_b_to_bl_thumb:
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
      if (block_address & 0x1) {
        if (exit_type == uncond_b_to_bl_thumb) {
          thumb_b32_helper(branch_addr, (uint32_t)block_address);
        } else {
          thumb_cc_branch(thread_data, branch_addr, (uint32_t)block_address);
        }
        __clear_cache((char *)branch_addr-1, (char *)(branch_addr) + 8);
      } else {
        // The data word used for the address is word-aligned
        if (((uint32_t)branch_addr) & 2) {
          thumb_ldrl32(&branch_addr, pc, 4, 1);
          branch_addr += 3;
        } else {
          thumb_ldrl32(&branch_addr, pc, 0, 1);
          branch_addr += 2;
        }
        *(uint32_t *)branch_addr = block_address;
        __clear_cache((char *)branch_addr-7, (char *)branch_addr);
      }
      break;

    case uncond_imm_arm:
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
      arm_cc_branch(thread_data, (uint32_t *)branch_addr, (uint32_t)block_address, AL);
      __clear_cache(branch_addr, (char *)branch_addr+5);
      break;
  #endif
  #ifdef DBM_LINK_COND_IMM
    case cond_imm_arm:
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
        if (!is_taken) {
          cond = invert_cond(cond);
        }

        thread_data->code_cache_meta[source_index].branch_cache_status =
                     (is_taken ? BRANCH_LINKED : FALLTHROUGH_LINKED);
      } else {
        branch_addr += 2;
        other_target_in_cache = false;
        cond = AL;
        thread_data->code_cache_meta[source_index].branch_cache_status |= BOTH_LINKED;
      }
      arm_cc_branch(thread_data, (uint32_t *)branch_addr, (uint32_t)block_address, cond);
      branch_addr += 2;

      if (other_target_in_cache) {
        arm_cc_branch(thread_data, (uint32_t *)branch_addr, (uint32_t)other_target, AL);
        branch_addr += 2;
        thread_data->code_cache_meta[source_index].branch_cache_status |= BOTH_LINKED;
      }

      __clear_cache(thread_data->code_cache_meta[source_index].exit_branch_addr, branch_addr);
      break;

    case cond_imm_thumb:
      if (block_address & 0x1) {
        branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
        debug("Target is: 0x%x, b taken addr: 0x%x, b skipped addr: 0x%x\n",
               target, thread_data->code_cache_meta[source_index].branch_taken_addr,
               thread_data->code_cache_meta[source_index].branch_skipped_addr);
        debug("Overwriting branches at %p\n", branch_addr);
        if (target == thread_data->code_cache_meta[source_index].branch_taken_addr) {
          other_target = cc_lookup(thread_data, thread_data->code_cache_meta[source_index].branch_skipped_addr);
          other_target_in_cache = (other_target != UINT_MAX);
          thumb_encode_cond_imm_branch(thread_data, &branch_addr, 
                                      source_index,
                                      block_address,
                                      (other_target_in_cache ? other_target : thread_data->code_cache_meta[source_index].branch_skipped_addr),
                                      thread_data->code_cache_meta[source_index].branch_condition,
                                      true,
                                      other_target_in_cache, true);
        } else {
          other_target = cc_lookup(thread_data, thread_data->code_cache_meta[source_index].branch_taken_addr);
          other_target_in_cache = (other_target != UINT_MAX);
          thumb_encode_cond_imm_branch(thread_data, &branch_addr, 
                                      source_index,
                                      (other_target_in_cache ? other_target : thread_data->code_cache_meta[source_index].branch_taken_addr),
                                      block_address,
                                      thread_data->code_cache_meta[source_index].branch_condition,
                                      other_target_in_cache,
                                      true, true);
        }
        debug("Target at 0x%x, other target at 0x%x\n", block_address, other_target);
        // thumb_encode_cond_imm_branch updates branch_addr to point to the next free word
        __clear_cache((char *)(branch_addr)-100, (char *)branch_addr);
      } else {
        fprintf(stderr, "WARN: cond_imm_thumb to arm\n");
        while(1);
      }
      break;
  #endif // DBM_LINK_COND_IMM
  #ifdef DBM_LINK_CBZ
    case cbz_thumb:
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
      debug("Target is: 0x%x, b taken addr: 0x%x, b skipped addr: 0x%x\n",
             target, thread_data->code_cache_meta[source_index].branch_taken_addr,
             thread_data->code_cache_meta[source_index].branch_skipped_addr);
      debug("Overwriting branches at %p\n", branch_addr);
      if (target == thread_data->code_cache_meta[source_index].branch_taken_addr) {
        other_target = cc_lookup(thread_data, thread_data->code_cache_meta[source_index].branch_skipped_addr);
        other_target_in_cache = (other_target != UINT_MAX);
        thumb_encode_cbz_branch(thread_data,
                                thread_data->code_cache_meta[source_index].rn,
                                &branch_addr,
                                source_index,
                                block_address,
                                (other_target_in_cache ? other_target : thread_data->code_cache_meta[source_index].branch_skipped_addr),
                                true,
                                other_target_in_cache, true);
      } else {
        other_target = cc_lookup(thread_data, thread_data->code_cache_meta[source_index].branch_taken_addr);
        other_target_in_cache = (other_target != UINT_MAX);
        thumb_encode_cbz_branch(thread_data,
                                thread_data->code_cache_meta[source_index].rn,
                                &branch_addr,
                                source_index,
                                (other_target_in_cache ? other_target : thread_data->code_cache_meta[source_index].branch_taken_addr),
                                block_address,
                                other_target_in_cache,
                                true, true);
      }
      debug("Target at 0x%x, other target at 0x%x\n", block_address, other_target);
      // tthumb_encode_cbz_branch updates branch_addr to point to the next free word
      __clear_cache((char *)(branch_addr)-100, (char *)branch_addr);
      break;
  #endif // DBM_LINK_CBZ

    case uncond_blxi_thumb:
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;

      thumb_ldrl32(&branch_addr, pc, ((uint32_t)branch_addr & 2) ? 4 : 0, 1);
	    branch_addr += 2;
	    // The target is word-aligned
	    if ((uint32_t)branch_addr & 2) { branch_addr++; }
	    *(uint32_t *)branch_addr = block_address;
	    __clear_cache((char *)(branch_addr)-6, (char *)branch_addr);

	    record_cc_link(thread_data, (uint32_t)branch_addr|FULLADDR, block_address);
      break;

    case uncond_blxi_arm:
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;

      arm_ldr((uint32_t **)&branch_addr, IMM_LDR, pc, pc, 4, 1, 0, 0);
      branch_addr += 2;
      *(uint32_t *)branch_addr = block_address;
      __clear_cache((char *)(branch_addr-2), (char *)branch_addr);

      record_cc_link(thread_data, (uint32_t)branch_addr|FULLADDR, block_address);
      break;
  }
}
