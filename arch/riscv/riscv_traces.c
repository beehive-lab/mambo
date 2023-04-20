/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo
  Copyright 2021-2022 The University of Manchester
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

#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#include "../../dbm.h"
#include "../../arch/riscv/riscv_traces.h"
#include "../../pie/pie-riscv-encoder.h"
#include "../../pie/pie-riscv-decoder.h"
#include "../../pie/pie-riscv-field-decoder.h"
#include "../../scanner_common.h"
#include "../../traces_common.h"

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
  #ifndef VERBOSE
    #define VERBOSE
  #endif
#else
  #define debug(...)
#endif

#define WHOLE_TRACE 4000
#define TRACE_PADDING 1000
#define TRACE_EXIT 15

#ifdef DBM_TRACES
#ifdef __riscv

int trace_record_exit(dbm_thread *thread_data, uintptr_t from, uintptr_t to,
                     uint32_t cond, int fragment_id) {
  int record = thread_data->active_trace.free_exit_rec++;
  if (record >= MAX_TRACE_REC_EXITS) {
    return -1;
  }
  struct trace_exits *trace_exit = &thread_data->active_trace.exits[record];
  trace_exit->from = from;
  trace_exit->to = to;
  trace_exit->exit_condition = cond;
  trace_exit->fragment_id = fragment_id;

  return 0;
}

int riscv_jump_to(uint16_t **o_write_p, uintptr_t target) {
  int ret = riscv_jal_helper((uint16_t **)o_write_p, target + 6, zero);
  if (ret != 0) {
    riscv_push(o_write_p, (1 << a0) | (1 << a1));
    ret = riscv_jalr_helper((uint16_t **)o_write_p, target, zero, a0);
  }
  return ret;
}

int riscv_tribi_jump_to(uint16_t **o_write_p, uintptr_t target) {
  int ret = riscv_jal_helper((uint16_t **)o_write_p, target, zero);
  if (ret != 0) {
    ret = riscv_jalr_helper((uint16_t **)o_write_p, target, zero, a0);
  }
  return ret;
}

void set_up_trace_exit(dbm_thread *thread_data, uint16_t **o_write_p, uintptr_t target) {
  uint16_t *write_p = *o_write_p;
  uint16_t *write_start = *o_write_p;
  if (riscv_jal_helper(&write_p, target + 6, zero) != 0) {
    riscv_push((uint16_t **)&write_p, (1 << a0) | (1 << a1));
    assert(riscv_jalr_helper((uint16_t **)&write_p, target, zero, a0) == 0);
  } else {
    target += 6;
  }
  record_cc_link(thread_data, (uintptr_t)write_start, target);
  __clear_cache(*o_write_p, (write_p));

  *o_write_p = write_p;
}

void patch_trace_branches(dbm_thread *thread_data, uint16_t *orig_branch, uintptr_t tpc) {
  assert(riscv_jump_to(&orig_branch, tpc) == 0);
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
    uintptr_t c_orig_branch = cc_link->data;

    if (orig_branch >= (uintptr_t)thread_data->code_cache->traces) {
      patch_trace_branches(thread_data, (uint16_t *)orig_branch, tpc);
    } else {
      int current_bb = addr_to_bb_id(thread_data, cc_link->data);
      int actual_bb = thread_data->code_cache_meta[current_bb].actual_id;
      if (actual_bb != 0) {
        current_bb = actual_bb;
      }
      dbm_code_cache_meta *current_bb_meta = &thread_data->code_cache_meta[current_bb];
      branch_type exit_type = current_bb_meta->exit_branch_type;
      if (exit_type == branch_riscv) {
        uintptr_t taken_trace = active_trace_lookup(thread_data,
                    current_bb_meta->branch_taken_addr);
        uintptr_t trace_fallthrough = active_trace_lookup(thread_data,
                    current_bb_meta->branch_skipped_addr);
        uintptr_t not_taken = UINTPTR_MAX;
        uintptr_t taken = UINTPTR_MAX;
        int cond = -1;
        orig_branch = (uintptr_t)current_bb_meta->exit_branch_addr;
        uintptr_t *br_start = (uintptr_t *)orig_branch;
        orig_branch = (uintptr_t)(((uint16_t *)orig_branch) + 2);
        if (taken_trace != UINT_MAX) {
          not_taken = active_trace_lookup_or_scan(thread_data,
                        current_bb_meta->branch_skipped_addr);
          taken = active_trace_lookup(thread_data, current_bb_meta->branch_taken_addr);
          cond = current_bb_meta->branch_condition;
        }
        else if (trace_fallthrough != UINT_MAX) {
          not_taken = active_trace_lookup_or_scan(thread_data,
                          current_bb_meta->branch_taken_addr);
          taken = active_trace_lookup(thread_data,
                          current_bb_meta->branch_skipped_addr);
          cond = current_bb_meta->branch_condition ^ 1;
        }

        assert(cond != -1 && (taken != UINTPTR_MAX || not_taken != UINTPTR_MAX));
        int ret = riscv_jump_to((uint16_t **)&orig_branch, not_taken);
        assert(ret == 0);
        ret = riscv_branch_helper((uint16_t **)&br_start, orig_branch,
                                 current_bb_meta->rs1, current_bb_meta->rs2, cond);
        assert(ret == 0);
        ret = riscv_jump_to((uint16_t **)&orig_branch, taken);
        assert(ret == 0);

        if (not_taken < (uintptr_t)thread_data->code_cache->traces) {
          record_cc_link(thread_data, (uintptr_t)orig_branch, not_taken);
        }

      } else {
        assert(riscv_jump_to((uint16_t **)&orig_branch, tpc) == 0);
      }
    }

    cc_link = cc_link->next;
    __clear_cache((void *)c_orig_branch, (void *)orig_branch);
  }

  hash_add(&thread_data->entry_address, spc, tpc);

  for (int i = 0; i < thread_data->active_trace.free_exit_rec; i++) {
    struct trace_exits *trace_exit = &thread_data->active_trace.exits[i];
    uint16_t *write_p = (uint16_t *)(trace_exit->from);
    dbm_code_cache_meta *bb_meta = &thread_data->code_cache_meta[trace_exit->fragment_id];
    int ret = riscv_branch_helper(&write_p, (uintptr_t)thread_data->active_trace.write_p, bb_meta->rs1,
                                   bb_meta->rs2, trace_exit->exit_condition ^ 1);
    assert(ret == 0);
    write_p = thread_data->active_trace.write_p;
    set_up_trace_exit(thread_data, &write_p, trace_exit->to);
    thread_data->active_trace.write_p = write_p;

  }

  thread_data->trace_id = thread_data->active_trace.id;
  thread_data->trace_cache_next = thread_data->active_trace.write_p;


  /* Add traps to the source basic block to detect if it remains reachable */
  uint16_t *write_p = (uint16_t *)(thread_data->code_cache_meta[bb_source].tpc + 6);
  riscv_c_ebreak(&write_p);
  __clear_cache(write_p, write_p + 2);
}

void set_up_trace_exit_branch_placeholder(dbm_thread *thread_data,
              uint16_t **o_write_p, int fragment_id, bool is_taken) {
  dbm_code_cache_meta *bb_meta = &thread_data->code_cache_meta[fragment_id];
  uint32_t condition = bb_meta->branch_condition;
  uint32_t new_condition = is_taken ? condition : (condition ^ 1);
  uint16_t *write_p = *o_write_p;
  uint16_t *write_start = *o_write_p;
  uintptr_t addr = is_taken ? bb_meta->branch_skipped_addr : bb_meta->branch_taken_addr;
  uintptr_t tpc;
  riscv_addi(&write_p, zero, zero, 0); //nop
  write_p += 2;
  tpc = active_trace_lookup(thread_data, addr);
  if (tpc == UINT_MAX) {
    tpc = lookup_or_scan(thread_data, addr);
  }
  *o_write_p = write_p;
  int ret = trace_record_exit(thread_data, (uintptr_t)write_start,
                              tpc, new_condition, fragment_id);
  assert(ret == 0);
}

size_t scan_trace(dbm_thread *thread_data, uint16_t *address, cc_type type, int *set_trace_id) {
  size_t fragment_len;
  uint8_t *write_p = thread_data->active_trace.write_p;
  int trace_id = allocate_trace_fragment(thread_data);
  if (set_trace_id != NULL) {
    *set_trace_id = trace_id;
  }

  debug("Trace scan: %p to %p, id %d\n", address, write_p, trace_id);

  thread_data->code_cache_meta[trace_id].source_addr = address;
  thread_data->code_cache_meta[trace_id].tpc = (uintptr_t)write_p;
  thread_data->code_cache_meta[trace_id].branch_cache_status = 0;

  fragment_len = scan_riscv(thread_data, address, trace_id, type, (uint16_t *)write_p);

  if (((write_p - (uint8_t *)thread_data->active_trace.entry_addr) +
      (uint8_t)((thread_data->trace_fragment_count + 1) * TRACE_EXIT))
                     >= (uint8_t)(WHOLE_TRACE - TRACE_PADDING)) {
    return 0;
  }

  __clear_cache(thread_data->code_cache_meta[trace_id].tpc, write_p + 4);

  thread_data->trace_fragment_count++;

  return fragment_len;
}

void early_trace_exit(dbm_thread *thread_data, dbm_code_cache_meta *bb_meta,
                      void *write_p, uintptr_t spc, uintptr_t tpc) {
  uint16_t *c_write_p = write_p;
  riscv_jump_to((uint16_t **)&write_p, tpc);
  __clear_cache(c_write_p, write_p);
  thread_data->active_trace.write_p = (uint8_t *)write_p;
  install_trace(thread_data);

  bb_meta->branch_cache_status |= BOTH_LINKED;
}

void create_trace(dbm_thread *thread_data, uint16_t bb_source, uintptr_t *ret_addr) {
  uint16_t *source_addr;
  uint32_t fragment_len;
  uintptr_t orig_addr;
  int trace_id;
  uintptr_t trace_entry;

  uint16_t *bb_addr = (uint16_t *)&thread_data->code_cache->blocks[bb_source];

  thread_data->trace_fragment_count = 0;

  if (thread_data->code_cache_meta[bb_source].exit_branch_type == jal_riscv
      || thread_data->code_cache_meta[bb_source].exit_branch_type == branch_riscv) {

    source_addr = thread_data->code_cache_meta[bb_source].source_addr;

    //align trace head
    thread_data->trace_cache_next += (TRACE_ALIGN -
               ((uintptr_t)thread_data->trace_cache_next & TRACE_ALIGN_MASK)) & TRACE_ALIGN_MASK;

    if ((uintptr_t)thread_data->trace_cache_next >=
                     (uintptr_t)thread_data->code_cache + MAX_BRANCH_RANGE - TRACE_LIMIT_OFFSET
         || thread_data->trace_id >= (CODE_CACHE_SIZE + TRACE_FRAGMENT_NO - TRACE_FRAGMENT_OVERP)) {
      fprintf(stderr, "trace cache full, flushing the CC\n");
      flush_code_cache(thread_data);
      *ret_addr = lookup_or_scan(thread_data, (uintptr_t)source_addr);
      return;
    }

    trace_entry = (uintptr_t)thread_data->trace_cache_next;
    trace_entry |= ((uintptr_t)source_addr);

    thread_data->active_trace.active = true;
    thread_data->active_trace.id = thread_data->trace_id;
    thread_data->active_trace.source_bb = bb_source;
    thread_data->active_trace.write_p = thread_data->trace_cache_next;
    thread_data->active_trace.entry_addr = (uintptr_t)thread_data->active_trace.write_p;
    thread_data->active_trace.free_exit_rec = 0;

    *ret_addr = (uintptr_t)thread_data->active_trace.write_p;

    debug("Create trace: %d (%p), source_bb: %d, entry: %lx\n",
         thread_data->active_trace.id, thread_data->active_trace.write_p,
         thread_data->active_trace.source_bb, thread_data->active_trace.entry_addr);

    fragment_len = scan_trace(thread_data, source_addr, mambo_trace_entry, &trace_id);
    debug("len: %d\n\n", fragment_len);

    switch(thread_data->code_cache_meta[trace_id].exit_branch_type) {
      case jal_riscv:
      case branch_riscv:
        break;
      default:
        fprintf(stderr, "Disallowed type of exit in the first trace fragment: %d\n",
                    thread_data->code_cache_meta[trace_id].exit_branch_type);
        while(1);
    }
  } else {
    fprintf(stderr, "\nUnknown exit branch type in trace head: %d\n",
                      thread_data->code_cache_meta[bb_source].exit_branch_type);
    while(1);
  }
}

#ifdef DBM_TRIBI
void insert_tribi_prediction(dbm_thread *thread_data, uint32_t source_index, uintptr_t target) {
  dbm_code_cache_meta *bb_meta = &thread_data->code_cache_meta[source_index];
  int number_of_predictions = bb_meta->number_of_predictions;
  if (number_of_predictions < TRIBI_SLOTS){
    uint16_t *slot = (uint16_t *)bb_meta->next_prediction_slot;
    uint16_t *write_p = slot;
    uint16_t *branch;
    enum reg rs2 = bb_meta->rs1 == a0 ? a1 : a0;
    riscv_copy_to_reg(&write_p, rs2, target);
    branch = write_p;
    write_p += 2;
    if (bb_meta->rd != zero) {
      assert(bb_meta->rd != s1 && bb_meta->rd != a0 && bb_meta->rd != a1);
      riscv_copy_to_reg(&write_p, bb_meta->rd,
            (uintptr_t)bb_meta->read_addr + ((bb_meta->inst >= RISCV_LUI) ? 4 : 2));
    }
    uintptr_t tpc = active_trace_lookup(thread_data, target);
    assert(riscv_tribi_jump_to(&write_p, tpc) == 0);
    bb_meta->next_prediction_slot = (uintptr_t *)write_p;
    bb_meta->number_of_predictions++;
    riscv_branch_helper(&branch, (uintptr_t)write_p, bb_meta->rs1, rs2, BNE);
    riscv_jal_helper(&write_p, (uintptr_t)bb_meta->ihlu_address, zero);
    __clear_cache(slot, write_p);
  } else {
    uint16_t *eba = bb_meta->exit_branch_addr;
    uint16_t *start = eba;
    if (bb_meta->rd != zero) {
      assert(bb_meta->rd != s1);
      assert(bb_meta->rd != a0);
      assert(bb_meta->rd != a1);
    }
    riscv_inline_hash_lookup(thread_data, source_index, &eba,
          (uint16_t *)bb_meta->branch_skipped_addr, bb_meta->rs1,
           bb_meta->imm, bb_meta->link, true, false);
    __clear_cache(start, eba);
  }
}
#endif

void trace_dispatcher(uintptr_t target, uintptr_t *next_addr, uint32_t source_index, dbm_thread *thread_data) {
  uintptr_t addr;
  uintptr_t start_addr;
  dbm_code_cache_meta *bb_meta = &thread_data->code_cache_meta[source_index];
  bool is_taken = (bb_meta->branch_taken_addr == target);

  uint16_t *write_p = (uint16_t *)bb_meta->exit_branch_addr;
  size_t fragment_len;
  thread_data->was_flushed = false;

  debug("Trace dispatcher (target: 0x%x)\n", target);

  switch(bb_meta->exit_branch_type) {
    case branch_riscv:
      set_up_trace_exit_branch_placeholder(thread_data, &write_p, source_index, is_taken);
      bb_meta->branch_cache_status = is_taken ? BRANCH_LINKED : FALLTHROUGH_LINKED;
      break;
    case jal_riscv:
      bb_meta->branch_cache_status = BRANCH_LINKED;
      break;
    case jalr_riscv: {
      *next_addr = lookup_or_scan(thread_data, target);
#ifdef DBM_TRIBI
      if (*next_addr >= thread_data->code_cache->traces) {
        insert_tribi_prediction(thread_data, source_index, target);
      }
#endif
      return;
    }
    default:
      fprintf(stderr, "Trace dispatcher unknown %p\n", write_p);
      while(1);
  }

  start_addr = (uintptr_t)write_p;
  *next_addr = (uintptr_t)write_p + target;
  thread_data->active_trace.write_p = (uint8_t *)write_p;

  if (thread_data->was_flushed) {
    *next_addr = lookup_or_scan(thread_data, target);
    return;
  }

  if (thread_data->trace_fragment_count > MAX_TRACE_FRAGMENTS) {
    debug("Trace fragment count limit, branch to: 0x%x, written at: %p\n", target, write_p);
    addr = active_trace_lookup(thread_data, target);
    if (addr == UINT_MAX) {
      addr = active_trace_lookup_or_scan(thread_data, target);
      record_cc_link(thread_data, (uintptr_t)write_p, addr);
    }
    early_trace_exit(thread_data, bb_meta, write_p, target, addr);
    *next_addr = addr;
    return;
  }

  //Here we check if the target is already a trace.
  //We don't want duplicates.
  addr = active_trace_lookup(thread_data, target);
  debug("Hash lookup for 0x%x: 0x%x\n", target, addr);
  if (addr != UINT_MAX) {
    early_trace_exit(thread_data, bb_meta, write_p, target, addr);
    *next_addr = addr;
    return;
  }

  debug("\n   Trace fragment: 0x%x\n", target);
  int fragment_id;
  fragment_len = scan_trace(thread_data, (uint16_t *)target, mambo_trace, &fragment_id);
  debug("len: %d\n\n", fragment_len);

  if (fragment_len == 0) {
    thread_data->active_trace.write_p = start_addr;
    addr = active_trace_lookup(thread_data, target);
    if (addr == UINT_MAX) {
      addr = active_trace_lookup_or_scan(thread_data, target);
      record_cc_link(thread_data, (uintptr_t)write_p, addr);
    }
    early_trace_exit(thread_data, bb_meta, write_p, target, addr);
    *next_addr = addr;
    return;
  }

  thread_data->active_trace.write_p += 2 * fragment_len;
  switch(thread_data->code_cache_meta[fragment_id].exit_branch_type) {
    case jalr_riscv:
      install_trace(thread_data);
      break;
  }

  // Insert pop a0 and a1 and jump to start of fragment
  //overwritten by next fragment. We only need it for returning
  //from the dispatcher.
  uint16_t *fragment_end = (uint16_t *)(thread_data->active_trace.write_p);
  write_p = (uint16_t *)(thread_data->active_trace.write_p);
  riscv_pop(&write_p, 1 << a0 | 1 <<a1);
  riscv_jal_helper(&write_p, start_addr, zero);
  __clear_cache(fragment_end, write_p);
  *next_addr = (uintptr_t)fragment_end;
}
#endif
#endif

