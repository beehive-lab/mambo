/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2017 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2017 Guillermo Callaghan <guillermocallaghan at hotmail dot com>

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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>

#include "dbm.h"
#include "common.h"
#include "scanner_common.h"

#ifdef __arm__
#include "pie/pie-thumb-decoder.h"
#include "pie/pie-thumb-encoder.h"
#include "pie/pie-arm-encoder.h"
#elif __aarch64__
#include "pie/pie-a64-encoder.h"
#endif

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
  #ifndef VERBOSE
    #define VERBOSE
  #endif
#else
  #define debug(...)
#endif

#ifdef DBM_TRACES
uint32_t scan_trace(dbm_thread *thread_data, void *address, cc_type type, int *set_trace_id) {
  uint8_t *write_p = thread_data->trace_cache_next;
  size_t  fragment_len;
  unsigned long thumb = (unsigned long)address & THUMB;
  int trace_id = thread_data->trace_id++;
  if (set_trace_id != NULL) {
    *set_trace_id = trace_id;
  }

  debug("Trace scan: %p to %p, id %d\n", address, write_p, trace_id);

  thread_data->code_cache_meta[trace_id].source_addr = address;

#ifdef PLUGINS_NEW
  mambo_deliver_callbacks(PRE_FRAGMENT_C, thread_data, thumb ? THUMB_INST : ARM_INST,
                          type, trace_id, -1, -1, address, write_p, NULL);
#endif
#ifdef __arm__
  if (thumb) {
    fragment_len = scan_thumb(thread_data, (uint16_t *)(((uint32_t)address)-1), trace_id, type, (uint16_t*)write_p);
  } else {
    fragment_len = scan_arm(thread_data, (uint32_t *)address, trace_id, type, (uint32_t*)write_p);
  }
#endif // __arm__
#ifdef __aarch64__
  fragment_len = scan_a64(thread_data, (uint32_t *)address, trace_id, type, (uint32_t*)write_p);
#endif

#ifdef PLUGINS_NEW
  mambo_deliver_callbacks(POST_FRAGMENT_C, thread_data, thumb ? THUMB_INST : ARM_INST,
                          type, trace_id, -1, -1, address, write_p, NULL);
#endif

  __clear_cache(write_p, write_p + fragment_len);

  thread_data->trace_fragment_count++;

  return fragment_len;
}
#endif

/* This is called from trace_head_incr, which is called by trace heads */
int hot_bb_cnt = 0;
void create_trace(dbm_thread *thread_data, uint32_t bb_source, uintptr_t *trace_addr) {
#ifdef DBM_TRACES
  uint16_t *source_addr;
  uint32_t fragment_len;
  ll_entry *cc_link;
  uintptr_t orig_addr;
  int trace_id;
  uintptr_t trace_entry;

#ifdef __arm__
  uint16_t *bb_addr = (uint16_t *)&thread_data->code_cache->blocks[bb_source];
  bool is_thumb;
#endif
#ifdef __aarch64__
  uint32_t  *bb_addr = (uint32_t *)&thread_data->code_cache->blocks[bb_source];
#endif

  thread_data->trace_fragment_count = 0;
#ifdef __arm__
  if (thread_data->code_cache_meta[bb_source].exit_branch_type == cbz_thumb || thread_data->code_cache_meta[bb_source].exit_branch_type == cond_imm_thumb || thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_imm_thumb || thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_b_to_bl_thumb || thread_data->code_cache_meta[bb_source].exit_branch_type == cond_imm_arm || thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_imm_arm || thread_data->code_cache_meta[bb_source].exit_branch_type == tb_indirect || thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_reg_thumb) {
#endif
#ifdef __aarch64__
  if (thread_data->code_cache_meta[bb_source].exit_branch_type == cbz_a64
      || thread_data->code_cache_meta[bb_source].exit_branch_type == tbz_a64
      || thread_data->code_cache_meta[bb_source].exit_branch_type == cond_imm_a64
      || thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_imm_a64) {
#endif
    source_addr = thread_data->code_cache_meta[bb_source].source_addr;
#ifdef __arm__
    is_thumb = (uintptr_t)source_addr & THUMB;
#endif

    /* Alignment doesn't seem to make much of a difference */
    thread_data->trace_cache_next += (TRACE_ALIGN -
                                     ((uintptr_t)thread_data->trace_cache_next & TRACE_ALIGN_MASK))
                                     & TRACE_ALIGN_MASK;
    if ((uintptr_t)thread_data->trace_cache_next >= (uintptr_t)thread_data->code_cache + MAX_BRANCH_RANGE - TRACE_LIMIT_OFFSET) {
      fprintf(stderr, "trace cache full, flushing the CC\n");
      flush_code_cache(thread_data);
      *trace_addr = lookup_or_scan(thread_data, (uintptr_t)source_addr, NULL);
      return;
    }

    debug("bb: %d, source: %p, ret to: 0x%x\n", bb_source, source_addr, *trace_addr);
    hot_bb_cnt++;

    trace_entry = (uintptr_t)thread_data->trace_cache_next;
    trace_entry |= ((uintptr_t)source_addr) & THUMB;
    *trace_addr = adjust_cc_entry(trace_entry);
#ifdef __arm__
    if (is_thumb) {
  #ifdef HW_RAS
      *trace_addr += 4;
      thumb_b32_helper(bb_addr, *trace_addr-4);
      thumb_b32_helper(bb_addr+2, *trace_addr);
  #else
      thumb_b32_helper(bb_addr, *trace_addr);
  #endif
      //thumb_b32_helper(bb_addr, bb_addr);
    } else {
  #ifdef HW_RAS
      *trace_addr += 8;
      arm_b32_helper((uint32_t *)bb_addr, *trace_addr-8, AL);
      arm_b32_helper(((uint32_t *)bb_addr)+2, *trace_addr, AL);
  #else
      arm_b32_helper((uint32_t *)bb_addr, *trace_addr, AL);
  #endif
    }
    __clear_cache(bb_addr, bb_addr + 5);
#endif // __arm__

#ifdef __aarch64__
    (uintptr_t)bb_addr++; // Jumps the first instruction (POP X0, X1)
    *bb_addr = 0xD4200000; // BRK trap to detect if the basic block remains reachable
    __clear_cache((void *)bb_addr - 1, (void *)bb_addr + 1);
#endif

    debug("\n    Trace head: %p at 0x%x\n\n", source_addr, *trace_addr);

    cc_link = thread_data->code_cache_meta[bb_source].linked_from;
    while(cc_link != NULL) {
      debug("Link from: 0x%x, update to: 0x%x\n", cc_link->data, *trace_addr);
      orig_addr = cc_link->data;
#ifdef __arm__
      orig_addr &= 0xFFFFFFFE;
      if (cc_link->data & THUMB) {
        thumb_adjust_b_bl_target(thread_data, (uint16_t *)orig_addr, *trace_addr);
      } else if ((cc_link->data & 3) == FULLADDR) {
        *(uint32_t *)(orig_addr & (~FULLADDR)) = *trace_addr;
      } else {
        arm_adjust_b_bl_target((uintptr_t *)orig_addr, *trace_addr);
      }
#endif
#ifdef __aarch64__
      a64_b_helper((uint32_t *)orig_addr, *trace_addr + 4);
#endif
      cc_link = cc_link->next;
       __clear_cache((void *)orig_addr, (void *)orig_addr + 5);
    }

    hash_add(&thread_data->trace_entry_address, (uintptr_t)source_addr, trace_entry);
    hash_add(&thread_data->entry_address, (uintptr_t)source_addr, trace_entry);

    fragment_len = scan_trace(thread_data, source_addr, mambo_trace_entry, &trace_id);
    debug("len: %d\n\n", fragment_len);

    // this could be used to detect bugs if first fragment is unlinkable
    switch(thread_data->code_cache_meta[trace_id].exit_branch_type) {
#ifdef __arm__
      case uncond_reg_thumb:
      case cond_reg_thumb:
      case uncond_blxi_thumb:
      case trace_inline_max:
      case tbb:
      case tbh:
        thread_data->trace_cache_next += fragment_len;
        break;
#endif
#ifdef __aarch64__
      // allowed exit types
      case cbz_a64:
      case cond_imm_a64:
      case tbz_a64:
      case uncond_imm_a64:
        break;
      default:
        fprintf(stderr, "Disallowed type of exit in the first trace fragment: %d\n",
                thread_data->code_cache_meta[trace_id].exit_branch_type);
        while(1);
#endif
    }
  } else {
    fprintf(stderr, "\nUnknown exit branch type in trace head: %d\n", thread_data->code_cache_meta[bb_source].exit_branch_type);
    while(1);
  }
}

/* Handles dispatcher calls from traces */
void trace_dispatcher(uintptr_t target, uintptr_t *next_addr, uint32_t source_index, dbm_thread *thread_data) {
  uintptr_t addr;
  dbm_code_cache_meta *bb_meta = &thread_data->code_cache_meta[source_index];
#ifdef __arm__
  uint16_t *write_p = (uint16_t *)bb_meta->exit_branch_addr;
#endif
#ifdef __aarch64__
  uint32_t *write_p = (uint32_t *) bb_meta->exit_branch_addr;
  addr = (bb_meta->branch_taken_addr == target) ? bb_meta->branch_skipped_addr : bb_meta->branch_taken_addr;
#endif
  size_t fragment_len;

  debug("Trace dispatcher (target: 0x%x)\n", target);

  switch(bb_meta->exit_branch_type) {
#ifdef __arm__
    case cbz_thumb:
      thumb_misc_cbz_16(&write_p, (bb_meta->branch_skipped_addr == target) ? 1: 0, 0, 1, bb_meta->rn);
      write_p++;

      addr = (bb_meta->branch_skipped_addr == target) ? bb_meta->branch_taken_addr : bb_meta->branch_skipped_addr;
      debug("other addr: %x %d\n", addr, bb_meta->branch_skipped_addr == target);
      thumb_cc_branch(thread_data, write_p, lookup_or_stub(thread_data, addr));
      write_p += 2;

      __clear_cache(write_p - 4, write_p);

      break;
    case cond_imm_thumb:
      thumb_it16(&write_p, (bb_meta->branch_taken_addr == target) ? arm_inverse_cond_code[bb_meta->branch_condition] : bb_meta->branch_condition, 0x8);
      write_p++;

      addr = (bb_meta->branch_taken_addr == target) ? bb_meta->branch_skipped_addr : bb_meta->branch_taken_addr;
      debug("other addr: %x %d\n", addr, bb_meta->branch_skipped_addr == target);
      thumb_cc_branch(thread_data, write_p, lookup_or_stub(thread_data, addr));
      write_p += 2;

      __clear_cache(write_p - 4, write_p);

      break;
    case uncond_imm_thumb:
    case uncond_b_to_bl_thumb:
    case uncond_imm_arm:
      break;

    case uncond_blxi_thumb:
    #if 1
      if ((uint32_t)write_p & 2) {
        thumb_nop16(&write_p);
        write_p++;
      }
      thumb_bx16(&write_p, pc);
      __clear_cache(write_p-2, write_p+2);
      write_p += 2;
      //while(1);
    #endif

    /* Alternative implementations might be faster on other microarchitectures */
    #if 0
      thumb_push16(&write_p, (1 << r7));
      write_p++;
      thumb_add_from_pc16(&write_p, r7, ((uint32_t)write_p & 2) ? 0 : 0);
      write_p++;
      thumb_bx16(&write_p, r7);
      write_p += ((uint32_t)write_p & 2) ? 1 : 2;
      arm_pop_reg(r7);
      write_p++;
      __clear_cache(write_p-8, write_p + 1);
    #endif

    #if 0
      thumb_ldri32(&write_p, 0, 1, pc, pc, ((uint32_t)write_p & 2) << 1);
      __clear_cache(write_p, write_p + 3);
      write_p += ((uint32_t)write_p & 2) ? 3 : 2;
      *((uint32_t *)write_p) = (uint32_t)write_p + 4;
      write_p += 2;
    #endif
      break;

    case uncond_blxi_arm:
      arm_sub((uint32_t **)&write_p, IMM_PROC, 0, pc, pc, 3);
      write_p += 2;
      break;

    /* This is a new target for an indirect branch from the trace cache, generate a trace head */
    case uncond_reg_thumb:
    case tbh:
    case tbb:
    case uncond_reg_arm:
      *next_addr = lookup_or_scan(thread_data, target, NULL);
      return;

      break;

    case cond_imm_arm:
      addr = (bb_meta->branch_taken_addr == target) ? bb_meta->branch_skipped_addr : bb_meta->branch_taken_addr;

      arm_cc_branch(thread_data, (uint32_t *)write_p, lookup_or_stub(thread_data, addr),
                    (bb_meta->branch_taken_addr == target) ?
                     arm_inverse_cond_code[bb_meta->branch_condition] : bb_meta->branch_condition);
      write_p += 2;

      __clear_cache(write_p-4, write_p);

      break;
#endif
#ifdef __aarch64__
    // TODO change lookup_or_scan to lookup_or_stub
    case cbz_a64:
      a64_CBZ_CBNZ(&write_p, bb_meta->rn >> 5, (bb_meta->branch_taken_addr == target) ? (bb_meta->branch_condition) : (bb_meta->branch_condition ^ 1), 2, bb_meta->rn);
      write_p++;
      a64_cc_branch(thread_data, write_p, lookup_or_scan(thread_data, addr, NULL) + 4);
      write_p++;
      __clear_cache(write_p - 2, write_p);
      break;
    case cond_imm_a64:
      a64_B_cond(&write_p, 2, (bb_meta->branch_taken_addr == target) ? bb_meta->branch_condition : (bb_meta->branch_condition ^ 1));
      write_p++;
      a64_cc_branch(thread_data, write_p, lookup_or_scan(thread_data, addr, NULL) + 4);
      write_p++;
      __clear_cache(write_p - 2, write_p);
      break;
    case tbz_a64:
      a64_TBZ_TBNZ(&write_p, bb_meta->rn >> 10, (bb_meta->branch_taken_addr == target) ? (bb_meta->branch_condition) : (bb_meta->branch_condition ^ 1), bb_meta->rn >> 5, 2, bb_meta->rn);
      write_p++;
      a64_cc_branch(thread_data, write_p, lookup_or_scan(thread_data, addr, NULL) + 4);
      write_p++;
      __clear_cache(write_p - 2, write_p);
      break;
    case uncond_imm_a64:
      break;
    case uncond_branch_reg:
      *next_addr = lookup_or_scan(thread_data, target, NULL);
      return;
      break;
#endif
    default:
      fprintf(stderr, "Trace dispatcher unknown %p\n", write_p);
      while(1);
  }

  *next_addr = (uintptr_t)write_p + (target & THUMB);
  thread_data->trace_cache_next = (uint8_t *)write_p;

  // Check if the fragment count has reached the max limit
  if (thread_data->trace_fragment_count > MAX_TRACE_FRAGMENTS) {
    debug("Trace fragment count limit, branch to: 0x%x, written at: %p\n", target, write_p);

    addr = lookup_or_scan(thread_data, target, NULL);
#ifdef __arm__
    if (target & 1) {
      thumb_cc_branch(thread_data, write_p, addr);
    } else {
      arm_b32_helper((uint32_t *)write_p, addr, AL);
    }
    write_p += 2;
    __clear_cache(write_p - 2, write_p);
#endif
#ifdef __aarch64__
    a64_cc_branch(thread_data, write_p, addr + 4);
    write_p++;
    __clear_cache(write_p - 1, write_p);
#endif
    thread_data->trace_cache_next = (uint8_t *)write_p;
    *next_addr = addr;
    return;
  }

  // Check if the target is already a trace
  addr = hash_lookup(&thread_data->trace_entry_address, target);
  debug("Hash lookup for 0x%x: 0x%x\n", target, addr);
  if (addr != UINT_MAX) {
#ifdef __arm__
    addr = adjust_cc_entry(addr);
    if (addr & 1) {
      thumb_b32_helper(write_p, addr);
    } else {
      arm_b32_helper((uint32_t *)write_p, addr, AL);
    }
    write_p += 2;
    __clear_cache(write_p - 2, write_p);
#endif
#ifdef __aarch64__
    a64_b_helper(write_p, addr + 4);
    write_p++;
    __clear_cache(write_p - 1, write_p);
#endif
    thread_data->trace_cache_next = (uint8_t *)write_p;
    *next_addr = addr;
    return;
  }

  debug("\n   Trace fragment: 0x%x\n", target);
#ifdef __arm__
  fragment_len = scan_trace(thread_data, (uint16_t *)target, mambo_trace, NULL);
#endif
#ifdef __aarch64__
  fragment_len = scan_trace(thread_data, (uint32_t *)target, mambo_trace, NULL);
#endif
  debug("len: %d\n\n", fragment_len);

  thread_data->trace_cache_next += fragment_len;

#ifdef __aarch64__
  // Insert a trampoline which pops {X0, X1} and branches to the new fragment
  write_p = (uint32_t *)(thread_data->trace_cache_next - 4);
  a64_pop_pair_reg(x0, x1);
  a64_b_helper(write_p, *next_addr);
  write_p++;
  __clear_cache(write_p - 2, write_p);

  *next_addr = (uintptr_t)(write_p - 2);
#endif
#endif // DBM_TRACES
}
