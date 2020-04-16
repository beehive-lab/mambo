/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2015-2017 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
  Copyright 2016-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
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

#ifdef __aarch64__

#include <assert.h>
#include <stdio.h>

#include "dbm.h"
#include "scanner_common.h"

#include "pie/pie-a64-decoder.h"
#include "pie/pie-a64-encoder.h"
#include "pie/pie-a64-field-decoder.h"

#include "api/helpers.h"

#define NOP 0xD503201F /* NOP Instruction (A64) */
#define MIN_FSPACE 60

//#define DEBUG
#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

/*
 * Macros for Pushing and Poping pair or single registers.
 * ====== === ======= === ====== ==== == ====== =========
 *
 *                     PUSH-POP Pair of registers
 *
 * The "L" field defines if the instruction is a Load (L = 1) or a
 * Store (L = 0).
 * The field "type" controls the addressing mode.
 *      C4.3.15 Load/store register pair (post-indexed, page 205.
 *      C4.3.16 Load/store register pair (pre-indexed), page 206.
 *
 * A64_LDP_STP_encode (address, opc, V, type, L, imm7, Rt2, Rn, Rt)
 * imm7:
 * For the 64-bit post-index and 64-bit pre-index variant: is the signed
 * immediate byte offset, a multiple of 8 in the range -512 to 504, encoded
 * in the "imm7" field as <imm>/8. Page 668.
*/

#define a64_copy() *(write_p++) = *read_address;

#define a64_brk() *(write_p++) = 0xD4200000;

void a64_branch_helper(uint32_t *write_p, uint64_t target, bool link) {
  int64_t difference = target - (uint64_t)write_p;
  assert(((difference & 3) == 0)
         && (difference < 128*1024*1024 && difference >= -128*1024*1024));

  a64_B_BL(&write_p, link ? 1 : 0, difference >> 2);
}

void a64_b_helper(uint32_t *write_p, uint64_t target) {
  a64_branch_helper(write_p, target, false);
}

void a64_cc_branch(dbm_thread *thread_data, uint32_t *write_p, uint64_t target) {
  a64_b_helper(write_p, target);

  record_cc_link(thread_data, (uintptr_t)write_p, target);
}

void a64_bl_helper(uint32_t *write_p, uint64_t target) {
  a64_branch_helper(write_p, target, true);
}

void a64_b_cond_helper(uint32_t *write_p, uint64_t target, mambo_cond cond) {
  int64_t difference = target - (uint64_t)write_p;
  assert(((difference & 3) == 0)
         && (difference < 1024*1024 && difference >= - 1024*1024));

  a64_B_cond(&write_p, difference >> 2, cond);
}

int a64_cbz_cbnz_helper(uint32_t *write_p, bool cbnz, uint64_t target, uint32_t sf, uint32_t rt) {
  int64_t difference = target - (uint64_t)write_p;
  if (((difference & 3) != 0) ||
      (difference >= 1024*1024 && difference < - 1024*1024)) {
    return -1;
  }

  a64_CBZ_CBNZ(&write_p, sf, cbnz ? 1 : 0, difference >> 2, rt);
  return 0;
}

void a64_cbz_helper(uint32_t *write_p, uint64_t target, uint32_t sf, uint32_t rt) {
  int ret = a64_cbz_cbnz_helper(write_p, false, target, sf, rt);
  assert(ret == 0);
}

void a64_cbnz_helper(uint32_t *write_p, uint64_t target, uint32_t sf, uint32_t rt) {
  int ret = a64_cbz_cbnz_helper(write_p, true, target, sf, rt);
  assert(ret == 0);
}

void a64_tbz_tbnz_helper(uint32_t *write_p, bool is_tbnz,
                         uint64_t target, enum reg reg, uint32_t bit) {
  int64_t difference = target - (uint64_t)write_p;
  assert(((difference & 3) == 0)
         && (difference < 32*1024 && difference >= - 32*1024));

  a64_TBZ_TBNZ(&write_p, bit >> 5, is_tbnz ? 1 : 0, bit & 0x1F, difference >> 2, reg);
}

void a64_tbz_helper(uint32_t *write_p, uint64_t target, enum reg reg, uint32_t bit) {
  a64_tbz_tbnz_helper(write_p, false, target, reg, bit);
}

void a64_tbnz_helper(uint32_t *write_p, uint64_t target, enum reg reg, uint32_t bit) {
  a64_tbz_tbnz_helper(write_p, true, target, reg, bit);
}

/*
 * Copy a value up to 64 bits to a register.
 */
void a64_copy_to_reg_64bits(uint32_t **write_p, enum reg reg, uint64_t value)
{
  uint32_t first_half_word = value & 0xFFFF;
  uint32_t second_half_word = (value >> 16) & 0xFFFF;
  uint32_t third_half_word = (value >> 32) & 0xFFFF;
  uint32_t fourth_half_word = (value >> 48) & 0xFFFF;

  // MOVZ
  a64_MOV_wide(write_p, 1, 2, 0, first_half_word, reg);
  (*write_p)++;

  if (second_half_word > 0) { // MOVK
    a64_MOV_wide(write_p, 1, 3, 1, second_half_word, reg);
    (*write_p)++;
  }

  if (third_half_word > 0) { // MOVK
    a64_MOV_wide(write_p, 1, 3, 2, third_half_word, reg);
    (*write_p)++;
  }

  if (fourth_half_word > 0) { // MOVK
    a64_MOV_wide(write_p, 1, 3, 3, fourth_half_word, reg);
    (*write_p)++;
  }
}

void a64_branch_save_context (uint32_t **o_write_p)
{
  uint32_t *write_p = *o_write_p;
  a64_push_pair_reg(x0, x1);
  *o_write_p = write_p;
}

void a64_branch_jump(dbm_thread *thread_data, uint32_t **o_write_p,
                     int basic_block, uint64_t target, uint32_t flags) {
  /*
   *                   +------------------------------+
   *                   |          STP                 |
   *                   |          MOV                 |
   *                   |          MOV                 |
   *                   |          B       DISPATCHER  |
   *                   +------------------------------+
   */
  uint32_t *write_p = *o_write_p;

  debug("A64 branch target: 0x%lx\n", target);

  if (flags & REPLACE_TARGET) {
    a64_copy_to_reg_64bits(&write_p, x0, target);
  }

  if (flags & INSERT_BRANCH) {
    a64_copy_to_reg_64bits(&write_p, x1, basic_block);
    a64_b_helper(write_p, thread_data->dispatcher_addr);
    write_p++;
  }
  *o_write_p = write_p;
}

void a64_branch_jump_cond(dbm_thread *thread_data, uint32_t **o_write_p, int basic_block,
                          uint64_t target, uint32_t *read_address, uint32_t cond) {
   /*
   *                   +-------------------------------+
   * branch_cond    -> |          NOP                  |
   * branch_1       -> |          NOP                  |
   *                   |                               |
   * branch_2       -> |          STP                  |
   *                   |          MOV       X1, BB_ID  |
   *                   |                               |
   *                   |          B.op_cond SKIPPED    |
   *                   |                               |
   *                   |          MOV       X0, TARGET |
   *                   |          B         DISPATCHER |
   *                   |                               |
   *                   | SKIPPED: MOV       X0, READ+4 |
   *                   |          B         DISPATCHER |
   *                   +-------------------------------+
   */
  uint32_t *write_p = *o_write_p;
  uint32_t *cond_branch;

  debug("A64 branch: read_addr: %p, target: 0x%lx\n", read_address, target);

  *write_p = NOP;
  write_p++;
  *write_p = NOP;
  write_p++;

  a64_branch_save_context(&write_p);
  a64_copy_to_reg_64bits(&write_p, x1, basic_block);

  cond_branch = write_p++;

  a64_copy_to_reg_64bits(&write_p, x0, target);
  a64_b_helper(write_p, thread_data->dispatcher_addr);
  write_p++;

  a64_b_cond_helper(cond_branch, (uint64_t)write_p, invert_cond(cond));

  a64_copy_to_reg_64bits(&write_p, x0, (uint64_t)read_address + 4);
  a64_b_helper(write_p, thread_data->dispatcher_addr);
  write_p++;

  *o_write_p = write_p;
}

void a64_branch_imm_reg(dbm_thread *thread_data, uint32_t **o_write_p,
                        int basic_block, a64_instruction inst, uint32_t *read_address) {
  /*
   *                   +------------------------------+
   * cb(n)z_branch     |          NOP                 |
   * b taken/not taken |          NOP                 |
   *                   |                              |
   * b not taken/taken |          STP                 |
   *                   |                              |
   *                   | TAKEN:   [C/T](N)BZ SKIPPED  |
   *                   |                              |
   *                   |          MOV                 |
   *                   |          MOV                 |
   *                   |          B        DISPATCHER |
   *                   |                              |
   *                   | SKIPPED: MOV                 |
   *                   |          MOV                 |
   *                   |          B        DISPATCHER |
   *                   +------------------------------+
   */
  uint32_t *write_p = *o_write_p;
  uint32_t *cbz_branch;
  uint32_t sf, op, b5, b40, imm, rt, bit;
  uint64_t branch_offset, target;

  debug("A64 [c/t](n)bz: read_addr: %p, target: 0x%lx\n", read_address, target);

  switch(inst) {
    case A64_CBZ_CBNZ:
      a64_CBZ_CBNZ_decode_fields(read_address, &sf, &op, &imm, &rt);
      branch_offset = sign_extend64(19, imm) << 2;
#ifdef DBM_LINK_CBZ
      thread_data->code_cache_meta[basic_block].exit_branch_type = cbz_a64;
      thread_data->code_cache_meta[basic_block].branch_condition = op;
      thread_data->code_cache_meta[basic_block].rn = (sf << 5) | rt;
#endif
      break;
    case A64_TBZ_TBNZ:
      a64_TBZ_TBNZ_decode_fields(read_address, &b5, &op, &b40, &imm, &rt);
      branch_offset = sign_extend64(14, imm) << 2;
      bit = (b5 << 5) | b40;
#ifdef DBM_LINK_TBZ
      thread_data->code_cache_meta[basic_block].exit_branch_type = tbz_a64;
      thread_data->code_cache_meta[basic_block].branch_condition = op;
      thread_data->code_cache_meta[basic_block].rn = (bit << 5) | rt ;
#endif
      break;
  }
  target = (uint64_t)read_address + branch_offset;

  thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
  thread_data->code_cache_meta[basic_block].branch_taken_addr = target;
  thread_data->code_cache_meta[basic_block].branch_skipped_addr = (uint64_t)read_address + 4;

  *write_p = NOP;
  write_p++;
  *write_p = NOP;
  write_p++;

  a64_branch_save_context(&write_p);

  cbz_branch = write_p++;

  // TAKEN
  a64_branch_jump(thread_data, &write_p, basic_block, target,
                  REPLACE_TARGET | INSERT_BRANCH);

  switch(inst) {
    case A64_CBZ_CBNZ:
      // Compare and Branch on [Not] Zero to SKIPPED
      a64_cbz_cbnz_helper(cbz_branch, op^1, (uint64_t)write_p, sf, rt);
      break;
    case A64_TBZ_TBNZ:
      // Test bit and Branch on [Not] Zero to SKIPPED
      a64_tbz_tbnz_helper(cbz_branch, op^1, (uint64_t)write_p, rt, bit);
      break;
  }

  // SKIPPED
  a64_branch_jump(thread_data, &write_p, basic_block, (uint64_t)read_address + 4,
                  REPLACE_TARGET | INSERT_BRANCH);

  *o_write_p = write_p;
}

void a64_check_free_space(dbm_thread *thread_data, uint32_t **write_p,
                          uint32_t **data_p, uint32_t size, int cur_block) {
  int basic_block;

  if ((((uint64_t)*write_p) + size) >= (uint64_t)*data_p) {
    basic_block = allocate_bb(thread_data);
    thread_data->code_cache_meta[basic_block].actual_id = cur_block;
    if ((uint32_t *)&thread_data->code_cache->blocks[basic_block] != *data_p) {
      a64_b_helper(*write_p, (uint64_t)&thread_data->code_cache->blocks[basic_block]);
      *write_p = (uint32_t *)&thread_data->code_cache->blocks[basic_block];
    }
    *data_p = (uint32_t *)&thread_data->code_cache->blocks[basic_block];
    *data_p += BASIC_BLOCK_SIZE;
  }
}

void pass1_a64(uint32_t *read_address, branch_type *bb_type) {

  *bb_type = unknown;

  while(*bb_type == unknown) {
    a64_instruction instruction = a64_decode(read_address);

    switch(instruction) {
      case A64_B_BL:
        *bb_type = uncond_imm_a64;
        break;
      case A64_CBZ_CBNZ:
        *bb_type = cbz_a64;
        break;
      case A64_B_COND:
        *bb_type = cond_imm_a64;
        break;
      case A64_TBZ_TBNZ:
        *bb_type = tbz_a64;
        break;
      case A64_BR:
      case A64_BLR:
      case A64_RET:
        *bb_type = uncond_branch_reg;
        break;
      case A64_INVALID:
        return;
    }
    read_address++;
  }
}

bool a64_scanner_deliver_callbacks(dbm_thread *thread_data, mambo_cb_idx cb_id, uint32_t **o_read_address,
                                   a64_instruction inst, uint32_t **o_write_p, uint32_t **o_data_p,
                                   int basic_block, cc_type type, bool allow_write, bool *stop) {
  bool replaced = false;
#ifdef PLUGINS_NEW
  if (global_data.free_plugin > 0) {
    uint32_t *write_p = *o_write_p;
    uint32_t *data_p = *o_data_p;
    uint32_t *read_address = *o_read_address;

    mambo_cond cond = AL;
    if (inst == A64_B_COND) {
      uint32_t tmp;
      a64_B_cond_decode_fields(read_address, &tmp, &cond);
    }

    mambo_context ctx;
    set_mambo_context_code(&ctx, thread_data, cb_id, type, basic_block, A64_INST, inst, cond, read_address, write_p, data_p, stop);

    for (int i = 0; i < global_data.free_plugin; i++) {
      if (global_data.plugins[i].cbs[cb_id] != NULL) {
        ctx.code.write_p = write_p;
        ctx.code.data_p = data_p;
        ctx.plugin_id = i;
        ctx.code.replace = false;
        ctx.code.available_regs = ctx.code.pushed_regs;
        global_data.plugins[i].cbs[cb_id](&ctx);
        if (allow_write) {
          if (replaced && (write_p != ctx.code.write_p || ctx.code.replace)) {
            fprintf(stderr, "MAMBO API WARNING: plugin %d added code for overridden"
                            "instruction (%p).\n", i, read_address);
          }
          if (ctx.code.replace) {
            if (cb_id == PRE_INST_C) {
              replaced = true;
            } else {
              fprintf(stderr, "MAMBO API WARNING: plugin %d set replace_inst for "
                              "a disallowed event (at %p).\n", i, read_address);
            }
          }
          assert(count_bits(ctx.code.pushed_regs) == ctx.code.plugin_pushed_reg_count);
          if (allow_write && ctx.code.pushed_regs) {
            emit_pop(&ctx, ctx.code.pushed_regs);
          }
          write_p = ctx.code.write_p;
          data_p = ctx.code.data_p;
          a64_check_free_space(thread_data, &write_p, &data_p, MIN_FSPACE, basic_block);
        } else {
          assert(ctx.code.write_p == write_p);
          assert(ctx.code.data_p == data_p);
        }
      }
    }

    if (cb_id == PRE_BB_C) {
      watched_functions_t *wf = &global_data.watched_functions;
      for (int i = 0; i < wf->funcp_count; i++) {
        if (read_address == wf->funcps[i].addr) {
          _function_callback_wrapper(&ctx, wf->funcps[i].func);
          if (ctx.code.replace) {
            read_address = ctx.code.read_address;
          }
          write_p = ctx.code.write_p;
          data_p = ctx.code.data_p;
          a64_check_free_space(thread_data, &write_p, &data_p, MIN_FSPACE, basic_block);
        }
      }
    }

    if (allow_write && ctx.code.pushed_regs) {
      emit_a64_pop(&ctx, ctx.code.pushed_regs);
      write_p = ctx.code.write_p;
      data_p = ctx.code.data_p;
    }

    *o_write_p = write_p;
    *o_data_p = data_p;
    *o_read_address = read_address;
  }
#endif
  return replaced;
}

void a64_inline_hash_lookup(dbm_thread *thread_data, int basic_block, uint32_t **o_write_p,
                            uint32_t *read_address, enum reg rn, bool link, bool set_meta) {
  /*
   * Indirect Branch LookUp
   * ======== ====== ======
   *
   *                 STP  X0, X1, [SP, #-16]!
   *                 STP  X2, [SP, #-16]!        **
   *                 MOV  X1, rn                 ** rn = X1
   *                 MOV  LR, read_address + 4   ##
   *                 MOV  X0, #hash_table
   *                 AND  Xtmp, rn, #(hash_mask << 2)
   *                 ADD  X0, X0, Xtmp, LSL #2
   *          loop:
   *                 LDR  Xtmp, [X0], #16
   *                 CBZ  Xtmp, not_found
   *                 SUB  Xtmp, Xtmp, rn
   *                 CBNZ Xtmp, loop
   *                 LDR  X0, [X0,  #-8]
   *                 LDR  X2, [SP], #16           **
   *                 BR   X0
   *     not_found:
   *                 MOV  X0, rn
   *                 MOV  X1, #bb
   *                 LDR  X2, [SP], #16           **
   *                 B    dispatcher
   *
   * ** if rn is X0, X1 or (BLR LR)
   * ## for BLR
   */

  uint32_t *write_p = *o_write_p;
  uint32_t *loop;
  uint32_t *branch_to_not_found;
  uint32_t reg_spc, reg_tmp;
  bool use_x2 = false;

  if ((rn == x0) || (rn == x1) || (link && rn == lr)) {
    reg_spc = x1;
    reg_tmp = x2;
    use_x2 = true;
  } else {
    reg_spc = rn;
    reg_tmp = x1;
  }

  if (set_meta) {
    thread_data->code_cache_meta[basic_block].rn = reg_spc;
  }

  a64_push_pair_reg(x0, x1);

  if (use_x2) {
    a64_push_reg(x2);
    if (rn != reg_spc) {
      a64_logical_reg(&write_p, 1, 1, 0, 0, rn, 0, xzr, reg_spc);
      write_p++;
    }
  }

  if (link) {
    // MOV LR, read_address+4
    a64_copy_to_reg_64bits(&write_p, lr, (uint64_t)read_address + 4);
  }

  a64_copy_to_reg_64bits(&write_p, x0,
                         (uint64_t)&thread_data->entry_address.entries);

  a64_logical_immed(&write_p, 1, 0, 1, 62, 18, reg_spc, reg_tmp);
  write_p++;

  a64_ADD_SUB_shift_reg(&write_p, 1, 0, 0, 0, reg_tmp, 0x2, x0, x0);
  write_p++;

  loop = write_p;
  a64_LDR_STR_immed(&write_p, 3, 0, 1, 16, 1, x0, reg_tmp);
  write_p++;

  branch_to_not_found = write_p++;

  a64_ADD_SUB_shift_reg(&write_p, 1, 1, 0, 0, reg_spc, 0, reg_tmp, reg_tmp);
  write_p++;

  a64_cbnz_helper(write_p, (uint64_t)loop, 1, reg_tmp);
  write_p++;

  a64_LDR_STR_immed(&write_p, 3, 0, 1, -8, 0, x0, x0);
  write_p++;

  if (use_x2) {
    a64_pop_reg(x2);
  }

  a64_BR(&write_p, x0);
  write_p++;

  a64_cbz_helper(branch_to_not_found, (uint64_t)write_p, 1, reg_tmp);

  a64_logical_reg(&write_p, 1, 1, 0, 0, reg_spc, 0, xzr, x0);
  write_p++;

  a64_copy_to_reg_64bits(&write_p, x1, basic_block);

  if (use_x2) {
    a64_pop_reg(x2);
  }

  a64_b_helper(write_p, (uint64_t)thread_data->dispatcher_addr);
  write_p++;

  *o_write_p = write_p;
}

size_t scan_a64(dbm_thread *thread_data, uint32_t *read_address,
                int basic_block, cc_type type, uint32_t *write_p) {
  bool stop = false;

  uint32_t *start_scan = read_address;
  uint32_t *data_p;
  uint32_t *start_address;
  enum reg spilled_reg;

  uint64_t imm;
  uint32_t immlo, immhi, imm14, imm16, imm19, imm26;
  uint32_t CRn, CRm, Rd, Rn, Rt;
  uint32_t b5, b40, cond, hw, o0, op, op1, op2, opc, R, sf, V;

  uint64_t branch_offset;
  uint64_t PC_relative_address;
  uint64_t size;
  uint64_t target;

  bool TPIDR_EL0;

  if (write_p == NULL) {
    write_p = (uint32_t *) &thread_data->code_cache->blocks[basic_block];
  }

  start_address = write_p;

  if (type == mambo_bb) {
    data_p = write_p + BASIC_BLOCK_SIZE;
  } else { // mambo_trace
    data_p = (uint32_t *)&thread_data->code_cache->traces + (TRACE_CACHE_SIZE / 4);
  }

  /*
   * On context switches registers X0 and X1 are used to store the target
   * address and the Basic Block number respectively. Before
   * overwriting the values of these two registers they are pushed to the
   * Stack. This means that at the start of every Basic Block X0 and X1 have
   * to be popped from the Stack. The same is true for trace entries, however
   * trace fragments do not need a pop instruction.
   */
  if (type != mambo_trace) {
    a64_pop_pair_reg(x0, x1);
  }

#ifdef DBM_TRACES
  branch_type bb_type;
  pass1_a64(read_address, &bb_type);

  if (type == mambo_bb && bb_type != uncond_branch_reg && bb_type != unknown) {
    a64_push_pair_reg(x1, x30);

    a64_copy_to_reg_64bits(&write_p, x1, (int)basic_block);

    a64_bl_helper(write_p, thread_data->trace_head_incr_addr);
    write_p++;

    a64_pop_pair_reg(x1, x30);
  }
#endif

  a64_scanner_deliver_callbacks(thread_data, PRE_FRAGMENT_C, &read_address, -1,
                                &write_p, &data_p, basic_block, type, true, &stop);

  a64_scanner_deliver_callbacks(thread_data, PRE_BB_C, &read_address, -1,
                                &write_p, &data_p, basic_block, type, true, &stop);

  while(!stop) {
    debug("A64 scan read_address: %p, w: : %p, bb: %d\n", read_address, write_p, basic_block);
    a64_instruction inst = a64_decode(read_address);
    debug("  instruction enum: %d\n", (inst == A64_INVALID) ? -1 : inst);
    debug("  instruction word: 0x%x\n", *read_address);

#ifdef PLUGINS_NEW
    bool skip_inst = a64_scanner_deliver_callbacks(thread_data, PRE_INST_C, &read_address, inst,
                                                   &write_p, &data_p, basic_block, type, true, &stop);
    if (!skip_inst) {
#endif

    switch (inst){
      case A64_CBZ_CBNZ:
        a64_branch_imm_reg(thread_data, &write_p, basic_block, inst, read_address);
        stop = true;
        break;

      case A64_B_COND:
        a64_B_cond_decode_fields(read_address, &imm19, &cond);

        branch_offset = sign_extend64(19, imm19) << 2;
        target = (uint64_t)read_address + branch_offset;

#ifdef DBM_LINK_COND_IMM
        // Mark this as the beggining of code emulating B.cond
        thread_data->code_cache_meta[basic_block].exit_branch_type = cond_imm_a64;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
        thread_data->code_cache_meta[basic_block].branch_taken_addr = target;
        thread_data->code_cache_meta[basic_block].branch_skipped_addr = (uint64_t)read_address + 4;
        thread_data->code_cache_meta[basic_block].branch_condition = cond;
        thread_data->code_cache_meta[basic_block].branch_cache_status = 0;
#endif
        a64_branch_jump_cond(thread_data, &write_p, basic_block, target, read_address, cond);
        stop = true;
        break;

      case A64_SVC:
        a64_push_pair_reg(x29, x30);
        a64_copy_to_reg_64bits(&write_p, x29, (uint64_t)read_address + 4);
        a64_bl_helper(write_p, thread_data->syscall_wrapper_addr);
        write_p++;
        a64_pop_pair_reg(x0, x1);

        a64_scanner_deliver_callbacks(thread_data, POST_BB_C, &read_address, -1,
                                &write_p, &data_p, basic_block, type, false, &stop);
        // set the correct address for the PRE_BB_C event
        read_address++;
        a64_scanner_deliver_callbacks(thread_data, PRE_BB_C, &read_address, -1,
                                &write_p, &data_p, basic_block, type, true, &stop);
        read_address--;
        break;

      case A64_MRS_MSR_REG:
        /*
         * The R variable defines if the instruction is MSR (R = 0) or
         * MRS (R = 1)
         * Page 617 MRS and 620 MSR
         *

         * MRS
         * Move System Register allows the PE to read an AArch64 System
         * register into a general-purpose register.
         *
         * MSR (immediate)
         * Move immediate value to Special Register moves an immediate
         * value to selected bits of the PSTATE, namely D, A, I, F, and
         * SP. For more information, see PSTATE.
         *
         * MSR (register)
         * Move general-purpose register to System Register allows the PE
         * to write an AArch64 System register from a general-purpose
         * register.
         *
         * TPIDR_EL0 (page 2032)
         *      op0   op1    CRn    CRm    op2
         *       11   011   1101   0000    010
         */
        a64_MRS_MSR_reg_decode_fields(read_address, &R, &o0, &op1, &CRn, &CRm, &op2, &Rt);

        TPIDR_EL0 = (o0 == 1) && (op1 == 3) && (CRn == 13) && (CRm == 0) && (op2 == 2);
        if (TPIDR_EL0) {
          if (Rt == x0) {
            spilled_reg = x1;
          } else {
            spilled_reg = x0;
          }

          a64_push_reg(spilled_reg);
          a64_copy_to_reg_64bits(&write_p, spilled_reg, (uint64_t)&thread_data->tls);

          if (R == 0) { // MSR
            a64_LDR_STR_immed(&write_p, 3, 0, 0, 0, 0, spilled_reg, Rt);
            write_p++;
          } else { // MRS
            a64_LDR_STR_immed(&write_p, 3, 0, 1, 0, 0, spilled_reg, Rt);
            write_p++;
          }

          a64_pop_reg(spilled_reg);
          break;
        } else {
          a64_copy();
        }
        break;

      case A64_TBZ_TBNZ:
        a64_branch_imm_reg(thread_data, &write_p, basic_block, inst, read_address);
        stop = true;
        break;

      case A64_B_BL:
        a64_B_BL_decode_fields(read_address, &op, &imm26);

        if (op == 1) { // Branch Link
          a64_copy_to_reg_64bits(&write_p, lr, (uint64_t)read_address + 4);
        }

        branch_offset = sign_extend64(26, imm26) << 2;
        target = (uint64_t)read_address + branch_offset;

#ifdef DBM_LINK_UNCOND_IMM
        thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_imm_a64;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
        thread_data->code_cache_meta[basic_block].branch_taken_addr = target;
        *write_p = NOP; // Reserves space for linking branch.
        write_p++;
#endif
        a64_branch_save_context(&write_p);
        a64_branch_jump(thread_data, &write_p, basic_block, target,
                        REPLACE_TARGET | INSERT_BRANCH);
        stop = true;
        //while(1);
        break;

      case A64_BR:
      case A64_BLR:
      case A64_RET:
        a64_BR_decode_fields(read_address, &Rn);

#ifdef DBM_INLINE_HASH
        a64_check_free_space(thread_data, &write_p, &data_p, 88, basic_block);
#endif

        thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_branch_reg;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
        thread_data->code_cache_meta[basic_block].rn = Rn;

#ifndef DBM_INLINE_HASH
        a64_branch_save_context(&write_p);

        // MOV X0, Rn (Alias of ORR X0, Rn, XZR)
        a64_logical_reg(&write_p, 1, 1, 0, 0, Rn, 0, xzr, x0);
        write_p++;

        if (inst == A64_BLR) {
          // MOV LR, read_address+4
          a64_copy_to_reg_64bits(&write_p, lr, (uint64_t)read_address + 4);
        }

        a64_branch_jump(thread_data, &write_p, basic_block, 0, INSERT_BRANCH);
#else
        a64_inline_hash_lookup(thread_data, basic_block, &write_p, read_address, Rn, (inst == A64_BLR), true);
#endif
        stop = true;
        break;

      case A64_LDR_LIT:
        /*
         * LDR (literal) calculates an address from the PC value and an
         * immediate offset, loads a word from memory, and writes it to a
         * register.
         *
         *                         LOAD LITERAL
         * ----------------------------------------------------------------
         * opc  V  Instruction                Variant
         * ----------------------------------------------------------------
         *  00  0  LDR   (literal)            32-bit variant on page C6-527
         *  01  0  LDR   (literal)            64-bit variant on page C6-527
         *  10  0  LDRSW (literal)            -
         *  11  0  PRFM  (literal)            -
         *
         *  00  1  LDR   (literal, SIMD&FP)   32-bit variant on page C7-1027
         *  01  1  LDR   (literal, SIMD&FP)   64-bit variant on page C7-1027
         *  10  1  LDR   (literal, SIMD&FP)  128-bit variant on page C7-1027
         */
        a64_LDR_lit_decode_fields(read_address, &opc, &V, &imm19, &Rt);

        uint64_t offset = sign_extend64(19, imm19) << 2;
        PC_relative_address = (uint64_t)read_address + offset;

        if (V== 0) {
          switch(opc) {
            case 0: // LDR literal 32-bit variant
              a64_copy_to_reg_64bits(&write_p, Rt, PC_relative_address);
              a64_LDR_STR_unsigned_immed(&write_p, 2, V, 1, 0, Rt, Rt);
              write_p++;
              break;
            case 1: // LDR literal 64-bit variant
              a64_copy_to_reg_64bits(&write_p, Rt, PC_relative_address);
              a64_LDR_STR_unsigned_immed(&write_p, 3, V, 1, 0, Rt, Rt);
              write_p++;
              break;
            case 2: // LDR Signed Word (literal)
              a64_copy_to_reg_64bits(&write_p, Rt, PC_relative_address);
              a64_LDR_STR_unsigned_immed(&write_p, 2, V, 2, 0, Rt, Rt);
              write_p++;
              break;
            case 3: // PRFM Prefetch
              a64_push_reg(x0);
              a64_copy_to_reg_64bits(&write_p, x0, PC_relative_address);
              a64_LDR_STR_unsigned_immed(&write_p, 3, V, 2, 0, x0, Rt);
              write_p++;
              a64_pop_reg(x0);
              break;
          }
        } else if (V == 1) {
          switch(opc) {
            case 0: // LDR (literal, SIMD&FP) 32-bit variant
              size = 2;
              opc  = 1;
              break;
            case 1: // LDR (literal, SIMD&FP) 64-bit variant
              size = 3;
              opc  = 1;
              break;
            case 2: // LDR (literal, SIMD&FP) 128-bit variant
              size = 0;
              opc  = 3;
              break;
            default:
              printf("unallocated encoding\n");
              while(1);
          }
          a64_push_reg(x0);
          a64_copy_to_reg_64bits(&write_p, x0, PC_relative_address);
          a64_LDR_STR_unsigned_immed(&write_p, size, V, opc, 0, x0, Rt);
          write_p++;
          a64_pop_reg(x0);
        }
        break;

      case A64_ADR:
        /*
         * The ADR instruction needs to be translated as a MOV instruction.
         * Otherwise it will point to the wrong address (somewhere
         * in the code cache).
         */
        a64_ADR_decode_fields(read_address, &op, &immlo, &immhi, &Rd);
        imm = (immhi << 2) | immlo;

        if (op == 0){ // ADR
          imm = sign_extend64(21, imm);
          PC_relative_address = (uint64_t)read_address;
        } else { // ADRP
          imm = sign_extend64(21, imm) << 12;
          PC_relative_address = (uint64_t)read_address & ~(0xFFF);
        }

        PC_relative_address += imm;
        a64_copy_to_reg_64bits(&write_p, Rd, PC_relative_address);
        break;

      case A64_HVC:
      case A64_BRK:
      case A64_HINT:
      case A64_CLREX:
      case A64_DSB:
      case A64_DMB:
      case A64_ISB:
      case A64_SYS:
      case A64_LDX_STX:
      case A64_LDP_STP:
      case A64_LDR_STR_IMMED:
      case A64_LDR_STR_REG:
      case A64_LDR_STR_UNSIGNED_IMMED:
      case A64_LDX_STX_MULTIPLE:
      case A64_LDX_STX_MULTIPLE_POST:
      case A64_LDX_STX_SINGLE:
      case A64_LDX_STX_SINGLE_POST:
      case A64_ADD_SUB_IMMED:
      case A64_BFM:
      case A64_EXTR:
      case A64_LOGICAL_IMMED:
      case A64_MOV_WIDE:
      case A64_ADD_SUB_EXT_REG:
      case A64_ADD_SUB_SHIFT_REG:
      case A64_ADC_SBC:
      case A64_CCMP_CCMN_IMMED:
      case A64_CCMP_CCMN_REG:
      case A64_COND_SELECT:
      case A64_DATA_PROC_REG1:
      case A64_DATA_PROC_REG2:
      case A64_DATA_PROC_REG3:
      case A64_LOGICAL_REG:
      case A64_SIMD_ACROSS_LANE:
      case A64_SIMD_COPY:
      case A64_SIMD_EXTRACT:
      case A64_SIMD_MODIFIED_IMMED:
      case A64_SIMD_PERMUTE:
      case A64_SIMD_SCALAR_COPY:
      case A64_SIMD_SCALAR_PAIRWISE:
      case A64_SIMD_SCALAR_SHIFT_IMMED:
      case A64_SIMD_SCALAR_THREE_DIFF:
      case A64_SIMD_SCALAR_THREE_SAME:
      case A64_SIMD_SHIFT_IMMED:
      case A64_SIMD_TABLE_LOOKUP:
      case A64_SIMD_THREE_DIFF:
      case A64_SIMD_THREE_SAME:
      case A64_SIMD_SCALAR_TWO_REG:
      case A64_SIMD_SCALAR_X_INDEXED:
      case A64_SIMD_TWO_REG:
      case A64_SIMD_X_INDEXED:
      case A64_CRYPTO_AES:
      case A64_CRYPTO_SHA_REG3:
      case A64_CRYPTO_SHA_REG2:
      case A64_FCMP:
      case A64_FCCMP:
      case A64_FCSEL:
      case A64_FLOAT_REG1:
      case A64_FLOAT_REG2:
      case A64_FLOAT_REG3:
      case A64_FMOV_IMMED:
      case A64_FLOAT_CVT_FIXED:
      case A64_FLOAT_CVT_INT:
        a64_copy();
        break;

      case A64_INVALID:
        if (read_address != start_scan) {
          // Branch to lookup_or_stub(thread_data, (uintptr_t)read_address);
          a64_branch_save_context(&write_p);
          a64_branch_jump(thread_data, &write_p, basic_block, (uint64_t)read_address,
                          REPLACE_TARGET | INSERT_BRANCH);
          stop = true;
          debug("WARN: deferred scanning because of unknown instruction at: %p\n", read_address);
        } else {
          fprintf(stderr, "Unknown A64 instruction: %d at %p\n", inst, read_address);
          while(1);
          exit(EXIT_FAILURE);
        }
        break;

      default:
        fprintf(stderr, "Unhandled A64 instruction: %d at %p\n", inst, read_address);
        while(1);
        exit(EXIT_FAILURE);
    }
#ifdef PLUGINS_NEW
    } // if (!skip_inst)
#endif

    if (data_p <= write_p) {
      fprintf(stderr, "%d, inst: %p, :write: %p\n", inst, data_p, write_p);
      while(1);
    }

    if (!stop) {
      a64_check_free_space(thread_data, &write_p, &data_p, MIN_FSPACE, basic_block);
    }
#ifdef PLUGINS_NEW
    a64_scanner_deliver_callbacks(thread_data, POST_INST_C, &read_address, inst, &write_p, &data_p, basic_block, type, !stop, &stop);
#endif

    read_address++;
  } // while(!stop)

  return ((write_p - start_address + 1) * sizeof(*write_p));
}
#endif // __aarch64__
