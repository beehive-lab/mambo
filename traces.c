/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2017 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>

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
uintptr_t get_active_trace_spc(dbm_thread *thread_data) {
  int bb_id = thread_data->active_trace.source_bb;
  return (uintptr_t)thread_data->code_cache_meta[bb_id].source_addr;
}

uintptr_t active_trace_lookup(dbm_thread *thread_data, uintptr_t target) {
  uintptr_t spc = get_active_trace_spc(thread_data);
  if (target == spc) {
    return adjust_cc_entry(thread_data->active_trace.entry_addr);
  }
  uintptr_t return_tpc = hash_lookup(&thread_data->entry_address, target);
  if (return_tpc >= (uintptr_t)thread_data->code_cache->traces)
    return adjust_cc_entry(return_tpc);
  return UINT_MAX;
}

uintptr_t active_trace_lookup_or_scan(dbm_thread *thread_data, uintptr_t target) {
  uintptr_t spc = get_active_trace_spc(thread_data);
  if (target == spc) {
    return adjust_cc_entry(thread_data->active_trace.entry_addr);
  }
  return lookup_or_scan(thread_data, target, NULL);
}

uintptr_t active_trace_lookup_or_stub(dbm_thread *thread_data, uintptr_t target) {
  uintptr_t spc = get_active_trace_spc(thread_data);
  if (target == spc) {
    return adjust_cc_entry(thread_data->active_trace.entry_addr);
  }
  return lookup_or_stub(thread_data, target);
}

uint32_t scan_trace(dbm_thread *thread_data, void *address, cc_type type, int *set_trace_id) {
  size_t fragment_len;
  uint8_t *write_p = thread_data->active_trace.write_p;
  unsigned long thumb = (unsigned long)address & THUMB;
  int trace_id = thread_data->active_trace.id++;
  if (set_trace_id != NULL) {
    *set_trace_id = trace_id;
  }

  debug("Trace scan: %p to %p, id %d\n", address, write_p, trace_id);

  thread_data->code_cache_meta[trace_id].source_addr = address;
  thread_data->code_cache_meta[trace_id].tpc = (uintptr_t)write_p;
  thread_data->code_cache_meta[trace_id].branch_cache_status = 0;

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

#ifdef __arm__
  inst_set inst_type = thumb ? THUMB_INST : ARM_INST;
#elif __aarch64__
  inst_set inst_type = A64_INST;
#endif
  bool stop = true;
  mambo_deliver_callbacks_code(POST_BB_C, thread_data, type, trace_id, inst_type,
                               -1, -1, address, write_p, NULL, &stop);
  mambo_deliver_callbacks_code(POST_FRAGMENT_C, thread_data, type, trace_id, inst_type,
                               -1, -1, address, write_p, NULL, &stop);
  assert(stop == true);

  __clear_cache(write_p, write_p + fragment_len);

  thread_data->trace_fragment_count++;

  return fragment_len;
}

void install_trace(dbm_thread *thread_data) {
  ll_entry *cc_link;
  uintptr_t orig_branch;
  int bb_source = thread_data->active_trace.source_bb;
  uintptr_t spc = (uintptr_t)thread_data->code_cache_meta[bb_source].source_addr;
  uintptr_t tpc = thread_data->active_trace.entry_addr;
  uintptr_t tpc_direct = adjust_cc_entry(tpc);
  assert(thread_data->active_trace.active);
  thread_data->active_trace.active = false;

  cc_link = thread_data->code_cache_meta[bb_source].linked_from;
  while(cc_link != NULL) {
    debug("Link from: 0x%lx, update to: 0x%lx\n", cc_link->data, tpc);
    orig_branch = cc_link->data;
#ifdef __arm__
    orig_branch &= 0xFFFFFFFE;
    if (cc_link->data & THUMB) {
      thumb_adjust_b_bl_target(thread_data, (uint16_t *)orig_branch, tpc_direct);
    } else if ((cc_link->data & 3) == FULLADDR) {
      *(uint32_t *)(orig_branch & (~FULLADDR)) = tpc_direct;
    } else {
      arm_adjust_b_bl_target((uintptr_t *)orig_branch, tpc_direct);
    }
#elif __aarch64__
    a64_b_helper((uint32_t *)orig_branch, tpc + 4);
#endif
    cc_link = cc_link->next;
    __clear_cache((void *)orig_branch, (void *)orig_branch + 4);
  }

  hash_add(&thread_data->entry_address, spc, tpc);

  thread_data->trace_id = thread_data->active_trace.id;
  thread_data->trace_cache_next = thread_data->active_trace.write_p;

  // Record the trace exits
  for (int i = 0; i < thread_data->active_trace.free_exit_rec; i++) {
    record_cc_link(thread_data, thread_data->active_trace.exits[i].from,
                   thread_data->active_trace.exits[i].to);
  }

  /* Add traps to the source basic block to detect if it remains reachable */
#ifdef __arm__
  void *write_p = (void *)adjust_cc_entry(thread_data->code_cache_meta[bb_source].tpc);
  if (spc & THUMB) {
    thumb_bkpt16((uint16_t **)&write_p, 0);
  } else {
    arm_bkpt((uint32_t **)&write_p, 0, 0);
  }
  __clear_cache(write_p, write_p + 4);
#elif __aarch64__
  uint32_t *write_p = (uint32_t*)thread_data->code_cache_meta[bb_source].tpc;
  write_p++; // Jumps the first instruction (POP X0, X1)
  a64_BRK(&write_p, 0); // BRK trap
  __clear_cache(write_p, write_p + 1);
#endif
}

int trace_record_exit(dbm_thread *thread_data, uintptr_t from, uintptr_t to) {
  int record = thread_data->active_trace.free_exit_rec++;
  if (record >= MAX_TRACE_REC_EXITS) {
    return -1;
  }

  thread_data->active_trace.exits[record].from = from;
  thread_data->active_trace.exits[record].to = to;

  return 0;
}

#ifdef __arm__
void thumb_trace_exit_branch(dbm_thread *thread_data, uint16_t *write_p, uint32_t target) {
  thumb_b32_helper(write_p, target);
  int ret = trace_record_exit(thread_data, (uintptr_t)write_p|THUMB, target);
  assert(ret == 0);
}

void arm_trace_exit_branch(dbm_thread *thread_data, uint32_t *write_p, uint32_t target, uint32_t cond) {
  arm_b32_helper(write_p, target, cond);
  int ret = trace_record_exit(thread_data, (uintptr_t)write_p, target);
  assert(ret == 0);
}
#endif

#ifdef __aarch64__
void generate_trace_exit(dbm_thread *thread_data, uint32_t **o_write_p, int fragment_id, bool is_taken) {
  dbm_code_cache_meta *bb_meta = &thread_data->code_cache_meta[fragment_id];
  uint32_t *write_p = *o_write_p;

  switch (bb_meta->exit_branch_type) {
    case cbz_a64:
      a64_CBZ_CBNZ(&write_p, bb_meta->rn >> 5,
                   is_taken ? (bb_meta->branch_condition) : (bb_meta->branch_condition ^ 1),
                   2, bb_meta->rn);
      break;
    case cond_imm_a64:
      a64_B_cond(&write_p, 2, is_taken ? bb_meta->branch_condition : (bb_meta->branch_condition ^ 1));
      break;
    case tbz_a64:
      a64_TBZ_TBNZ(&write_p, bb_meta->rn >> 10,
                   is_taken ? (bb_meta->branch_condition) : (bb_meta->branch_condition ^ 1),
                   bb_meta->rn >> 5, 2, bb_meta->rn);
      break;
    default:
      fprintf(stderr, "Unknown branch type\n");
      while(1);
  }
  write_p++;

  uintptr_t addr = is_taken ? bb_meta->branch_skipped_addr : bb_meta->branch_taken_addr;
  uintptr_t tpc = active_trace_lookup_or_scan(thread_data, addr) + 4;
  int ret = trace_record_exit(thread_data, (uintptr_t)write_p, tpc);
  assert(ret == 0);
  a64_b_helper(write_p, tpc);
  write_p++;

  *o_write_p = write_p;
}
#endif
#endif

/* This is called from trace_head_incr, which is called by trace heads */
int hot_bb_cnt = 0;
void create_trace(dbm_thread *thread_data, uint32_t bb_source, cc_addr_pair *ret_addr) {
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
  if (thread_data->code_cache_meta[bb_source].exit_branch_type == cbz_thumb ||
      thread_data->code_cache_meta[bb_source].exit_branch_type == cond_imm_thumb ||
      thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_imm_thumb ||
      thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_b_to_bl_thumb ||
      thread_data->code_cache_meta[bb_source].exit_branch_type == tb_indirect ||
      thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_reg_thumb ||
      thread_data->code_cache_meta[bb_source].exit_branch_type == cond_imm_arm ||
      thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_imm_arm ||
      thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_reg_arm ||
      thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_blxi_thumb) {
#endif
#ifdef __aarch64__
  if (thread_data->code_cache_meta[bb_source].exit_branch_type == cbz_a64
      || thread_data->code_cache_meta[bb_source].exit_branch_type == tbz_a64
      || thread_data->code_cache_meta[bb_source].exit_branch_type == cond_imm_a64
      || thread_data->code_cache_meta[bb_source].exit_branch_type == uncond_imm_a64) {
#endif
    source_addr = thread_data->code_cache_meta[bb_source].source_addr;
    ret_addr->spc = (uintptr_t)source_addr;
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
      ret_addr->tpc = lookup_or_scan(thread_data, (uintptr_t)source_addr, NULL);
      return;
    }

    debug("bb: %d, source: %p, ret to: 0x%x\n", bb_source, source_addr, ret_addr->tpc);
    hot_bb_cnt++;

    trace_entry = (uintptr_t)thread_data->trace_cache_next;
    trace_entry |= ((uintptr_t)source_addr) & THUMB;

    thread_data->active_trace.active = true;
    thread_data->active_trace.id = thread_data->trace_id;
    thread_data->active_trace.source_bb = bb_source;
    thread_data->active_trace.write_p = thread_data->trace_cache_next;
    thread_data->active_trace.entry_addr = trace_entry;
    thread_data->active_trace.free_exit_rec = 0;

    debug("Create trace: %d (%p), source_bb: %d, entry: %lx\n",
          thread_data->active_trace.id, thread_data->active_trace.write_p,
          thread_data->active_trace.source_bb, thread_data->active_trace.entry_addr);
    debug("\n    Trace head: %p at 0x%x\n\n", source_addr, ret_addr->tpc);

    ret_addr->tpc = adjust_cc_entry(trace_entry);
    fragment_len = scan_trace(thread_data, source_addr, mambo_trace_entry, &trace_id);
    debug("len: %d\n\n", fragment_len);

    // this could be used to detect bugs if first fragment is unlinkable
    switch(thread_data->code_cache_meta[trace_id].exit_branch_type) {
#ifdef __arm__
      case uncond_reg_thumb:
      case cond_reg_thumb:
      case trace_inline_max:
      case tbb:
      case tbh:
      case uncond_reg_arm:
        thread_data->active_trace.write_p += fragment_len;
        install_trace(thread_data);
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

void early_trace_exit(dbm_thread *thread_data, dbm_code_cache_meta* bb_meta,
                      void *write_p, uintptr_t spc, uintptr_t tpc) {
#ifdef __arm__
  if (spc & THUMB) {
    thumb_cc_branch(thread_data, (uint16_t *)write_p, tpc);
  } else {
    arm_cc_branch(thread_data, (uint32_t *)write_p, tpc, AL);
  }
#endif
#ifdef __aarch64__
  a64_cc_branch(thread_data, (uint32_t *)write_p, tpc + 4);
#endif
  __clear_cache(write_p, write_p+4);
  write_p += 4;
  thread_data->active_trace.write_p = (uint8_t *)write_p;
  install_trace(thread_data);

  bb_meta->branch_cache_status |= BOTH_LINKED;
}

/* Handles dispatcher calls from traces */
void trace_dispatcher(uintptr_t target, uintptr_t *next_addr, uint32_t source_index, dbm_thread *thread_data) {
  uintptr_t addr;
  dbm_code_cache_meta *bb_meta = &thread_data->code_cache_meta[source_index];
  bool is_taken = (bb_meta->branch_taken_addr == target);
#ifdef __arm__
  uint16_t *write_p = (uint16_t *)bb_meta->exit_branch_addr;
#endif
#ifdef __aarch64__
  uint32_t *write_p = (uint32_t *) bb_meta->exit_branch_addr;
#endif
  size_t fragment_len;
  thread_data->was_flushed = false;

  debug("Trace dispatcher (target: 0x%x)\n", target);

  switch(bb_meta->exit_branch_type) {
#ifdef __arm__
    case cbz_thumb:
      thumb_misc_cbz_16(&write_p, (bb_meta->branch_skipped_addr == target) ? 1: 0, 0, 1, bb_meta->rn);
      write_p++;

      addr = (bb_meta->branch_skipped_addr == target) ? bb_meta->branch_taken_addr : bb_meta->branch_skipped_addr;
      debug("other addr: %x %d\n", addr, bb_meta->branch_skipped_addr == target);
      thumb_trace_exit_branch(thread_data, write_p, active_trace_lookup_or_stub(thread_data, addr));
      write_p += 2;
      __clear_cache(write_p - 4, write_p);

      bb_meta->branch_cache_status = is_taken ? FALLTHROUGH_LINKED : BRANCH_LINKED;

      break;
    case cond_imm_thumb:
      thumb_it16(&write_p, (bb_meta->branch_taken_addr == target) ? arm_inverse_cond_code[bb_meta->branch_condition] : bb_meta->branch_condition, 0x8);
      write_p++;

      addr = (bb_meta->branch_taken_addr == target) ? bb_meta->branch_skipped_addr : bb_meta->branch_taken_addr;
      debug("other addr: %x %d\n", addr, bb_meta->branch_skipped_addr == target);
      thumb_trace_exit_branch(thread_data, write_p, active_trace_lookup_or_stub(thread_data, addr));
      write_p += 2;
      __clear_cache(write_p - 4, write_p);

      bb_meta->branch_cache_status = is_taken ? FALLTHROUGH_LINKED : BRANCH_LINKED;

      break;
    case uncond_imm_thumb:
    case uncond_b_to_bl_thumb:
    case uncond_imm_arm:
      bb_meta->branch_cache_status = BRANCH_LINKED;
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
      thumb_ldrl32(&write_p, pc, ((uint32_t)write_p & 2) << 1, 1);
      __clear_cache(write_p, write_p + 3);
      write_p += ((uint32_t)write_p & 2) ? 3 : 2;
      *((uint32_t *)write_p) = (uint32_t)write_p + 4;
      write_p += 2;
    #endif
      break;

    case uncond_blxi_arm:
      arm_sub((uint32_t **)&write_p, IMM_PROC, 0, pc, pc, 3);
      write_p += 2;
      __clear_cache(write_p-2, write_p);
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

      arm_trace_exit_branch(thread_data, (uint32_t *)write_p, active_trace_lookup_or_stub(thread_data, addr),
                            is_taken ? invert_cond(bb_meta->branch_condition) : bb_meta->branch_condition);
      write_p += 2;
      __clear_cache(write_p-4, write_p);

      bb_meta->branch_cache_status = is_taken ? FALLTHROUGH_LINKED : BRANCH_LINKED;

      break;
#endif
#ifdef __aarch64__
    // TODO change lookup_or_scan to lookup_or_stub
    case cbz_a64:
    case cond_imm_a64:
    case tbz_a64:
      generate_trace_exit(thread_data, &write_p, source_index, is_taken);
      __clear_cache(write_p - 2, write_p);
      bb_meta->branch_cache_status = is_taken ? FALLTHROUGH_LINKED : BRANCH_LINKED;
      break;
    case uncond_imm_a64:
      bb_meta->branch_cache_status = BRANCH_LINKED;
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
  thread_data->active_trace.write_p = (uint8_t *)write_p;

  // If the CC was flushed to generate exits, then abort the active trace
  if (thread_data->was_flushed) {
    *next_addr = lookup_or_scan(thread_data, target, NULL);
    return;
  }

  // Check if the fragment count has reached the max limit
  if (thread_data->trace_fragment_count > MAX_TRACE_FRAGMENTS) {
    debug("Trace fragment count limit, branch to: 0x%x, written at: %p\n", target, write_p);
    addr = active_trace_lookup_or_scan(thread_data, target);
    early_trace_exit(thread_data, bb_meta, write_p, target, addr);
    *next_addr = addr;
    return;
  }

  // Check if the target is already a trace
  addr = active_trace_lookup(thread_data, target);
  debug("Hash lookup for 0x%x: 0x%x\n", target, addr);
  if (addr != UINT_MAX) {
    early_trace_exit(thread_data, bb_meta, write_p, target, addr);
    *next_addr = addr;
    return;
  }

  debug("\n   Trace fragment: 0x%x\n", target);
  int fragment_id;
#ifdef __arm__
  fragment_len = scan_trace(thread_data, (uint16_t *)target, mambo_trace, &fragment_id);
#endif
#ifdef __aarch64__
  fragment_len = scan_trace(thread_data, (uint32_t *)target, mambo_trace, &fragment_id);
#endif
  debug("len: %d\n\n", fragment_len);

  thread_data->active_trace.write_p += fragment_len;
  switch(thread_data->code_cache_meta[fragment_id].exit_branch_type) {
#ifdef __arm__
    case uncond_reg_thumb:
    case cond_reg_thumb:
    case uncond_reg_arm:
    case cond_reg_arm:
    case tbb:
    case tbh:
    case tb_indirect:
    case trace_inline_max:
#elif __aarch64__
    case uncond_branch_reg:
#endif
      install_trace(thread_data);
      break;
  }

#ifdef __aarch64__
  // Insert a trampoline which pops {X0, X1} and branches to the new fragment
  write_p = (uint32_t *)(thread_data->active_trace.write_p - 4);
  a64_pop_pair_reg(x0, x1);
  a64_b_helper(write_p, *next_addr);
  write_p++;
  __clear_cache(write_p - 2, write_p);

  *next_addr = (uintptr_t)(write_p - 2);
#endif
#endif // DBM_TRACES
}
