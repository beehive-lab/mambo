/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
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

#ifdef __arm__
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <limits.h>

#include "../../dbm.h"
#include "../../common.h"
#include "../../scanner_common.h"

#include "../../pie/pie-arm-decoder.h"
#include "../../pie/pie-arm-encoder.h"
#include "../../pie/pie-arm-field-decoder.h"

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

#define copy_arm() *(write_p++) = *read_address;

#define ALLOWED_IHL_REGS (0x5FF8) // {R3 - R12, R14}
#define IHL_SPACE (88)

void arm_copy_to_reg_16bit(uint32_t **write_p, enum reg reg, uint32_t value) {
  arm_movw(write_p, reg, (value >> 12) & 0xF, value & 0xFFF);
  (*write_p)++;
}

void arm_cond_copy_to_reg_16bit(uint32_t **write_p, enum arm_cond_codes cond, enum reg reg, uint32_t value) {
  arm_movw_cond(write_p, cond, reg, (value >> 12) & 0xF, value & 0xFFF);
  (*write_p)++;
}

void arm_copy_to_reg_32bit(uint32_t **write_p, enum reg reg, uint32_t value) {
  arm_movw(write_p, reg, (value >> 12) & 0xF, value & 0xFFF);
  (*write_p)++;
  arm_movt(write_p, reg, (value >> 28), (value >> 16) & 0xFFF);
  (*write_p)++;
}

void arm_cond_copy_to_reg_32bit(uint32_t **write_p, enum arm_cond_codes cond, enum reg reg, uint32_t value) {
  arm_movw_cond(write_p, cond, reg, (value >> 12) & 0xF, value & 0xFFF);
  (*write_p)++;
  arm_movt_cond(write_p, cond, reg, (value >> 28), (value >> 16) & 0xFFF);
  (*write_p)++;
}

void arm_proc_i32bit(uint32_t **write_p, arm_instruction inst, enum reg rd, enum reg rn, uint32_t value) {
  int shift = 0;
  uint32_t op2 = INT_MAX;

  /* Ensure that at least one instruction is generated even for value == 0,
     by executing the loop at least once. */
  while (value || op2 == INT_MAX) {
    while (value && ((0x3 << shift) & value) == 0) {
      shift += 2;
    }

    op2 = ((((32 - shift) >> 1) & 0xF) << 8) | ((value >> shift) & 0xFF);
    switch (inst) {
      case ARM_ADD:
        arm_add(write_p, IMM_PROC, 0, rd, rn, op2);
        *write_p += 1;
        break;
      case ARM_SUB:
        arm_sub(write_p, IMM_PROC, 0, rd, rn, op2);
        *write_p += 1;
        break;
      default:
        fprintf(stderr, "arm_proc_i32bit unknown insts: %d\n", inst);
        while(1);
    }

    rn = rd;
    value &= ~(0xFF << shift);
  }
}

void arm_add_sub_32_bit(uint32_t **write_p, enum reg rd, enum reg rn, int value) {
  arm_instruction inst = ARM_ADD;
  if (value < 0) {
    value = -value;
    inst = ARM_SUB;
  }

  arm_proc_i32bit(write_p, inst, rd, rn, value);
}

void arm_branch_save_context(dbm_thread *thread_data, uint32_t **o_write_p, bool late_app_sp) {
  uint32_t *write_p = *o_write_p;

  arm_sub(&write_p, IMM_PROC, 0, sp, sp, DISP_RES_WORDS*4);
  write_p++;

  arm_push_regs((1 << r0) | (1 << r1) | (1 << r2) | (1 << r3));

  if (!late_app_sp) {
    arm_add(&write_p, IMM_PROC, 0, r3, sp, DISP_SP_OFFSET);
    write_p++;
  }

  *o_write_p = write_p;
}

void arm_branch_jump(dbm_thread *thread_data, uint32_t **o_write_p, int basic_block,
                     uint32_t offset, uint32_t *read_address, uint32_t cond, uint32_t flags) {
  uint32_t *write_p = *o_write_p;
  int32_t  branch_offset;

  debug("ARM branch: read_addr: %p, offset: 0x%x\n", read_address, offset);

  if (flags & SETUP) {
    if (cond < 14) {
      arm_cond_copy_to_reg_32bit(&write_p, arm_inverse_cond_code[cond], r0, (uint32_t)read_address + 4);
    }
  }

  if (flags & REPLACE_TARGET) {  
    branch_offset = (offset & 0x800000) ? 0xFC000000 : 0;
    branch_offset |= (offset<<2);

    arm_cond_copy_to_reg_32bit(&write_p, cond, r0, (uint32_t)read_address + 8 + branch_offset);
  }
   
  if (flags & INSERT_BRANCH) {
    if (flags & LATE_APP_SP) {
      arm_add(&write_p, IMM_PROC, 0, r3, sp, 24);
      write_p++;
    }
    arm_copy_to_reg_32bit(&write_p, r1, basic_block);

    arm_b(&write_p, (thread_data->dispatcher_addr - (uint32_t)write_p - 8) >> 2);
    write_p++;
  }
  
  *o_write_p = write_p;
}

void arm_simple_exit(dbm_thread *thread_data, uint32_t **o_write_p, int bb_index,
                     uint32_t offset, uint32_t *read_address, uint32_t cond) {
  uint32_t *write_p = *o_write_p;
  arm_branch_save_context(thread_data, &write_p, false);
  arm_branch_jump(thread_data, &write_p, bb_index, offset, read_address,
                  cond, SETUP|REPLACE_TARGET|INSERT_BRANCH);
  *o_write_p = write_p;
}

void arm_check_free_space(dbm_thread *thread_data, uint32_t **write_p,
                          uint32_t **data_p, uint32_t size, int cur_block) {
  int basic_block;

  assert(*write_p < (*data_p)+BASIC_BLOCK_SIZE);

  if ((((uint32_t)*write_p)+size) >= (uint32_t)*data_p) {
    basic_block = allocate_bb(thread_data);
    thread_data->code_cache_meta[basic_block].actual_id = cur_block;
    if (*write_p >= *data_p) {
      assert(&thread_data->code_cache->blocks[basic_block].words[0] == *data_p);
    } else {
      arm_b(write_p, ((uint32_t)&thread_data->code_cache->blocks[basic_block] - (uint32_t)*write_p - 8) >> 2);
      *write_p = (uint32_t *)&thread_data->code_cache->blocks[basic_block];
    }
    *data_p = (uint32_t *)&thread_data->code_cache->blocks[basic_block] + BASIC_BLOCK_SIZE;
  }
}

void arm_branch_helper(uint32_t *write_p, uint32_t target, bool link, uint32_t cond) {
  if ((target & 3) == 0) {
    if (link) {
      arm_bl_cond(&write_p, cond, (target - (uint32_t)write_p - 8)>>2);
    } else {
      arm_b_cond(&write_p, cond, (target - (uint32_t)write_p - 8)>>2);
    }
  } else {
    fprintf(stderr, "ERROR: Cannot insert branch from ARM to Thumb\n");
    while(1);
  }
}

void arm_adjust_b_bl_target(uint32_t *write_p, uint32_t dest_addr) {
  arm_instruction inst = arm_decode(write_p);

  if (inst != ARM_B) {
    fprintf(stderr, "ARM: Trying to adjust target of invalid branch instruction.\n");
    while(1);
  }

  arm_branch_helper(write_p, dest_addr, inst == ARM_BL, *write_p >> 28);
}

void arm_b32_helper(uint32_t *write_p, uint32_t target, uint32_t cond) {
  arm_branch_helper(write_p, target, false, cond);
}

void arm_cc_branch(dbm_thread *thread_data, uint32_t *write_p, uint32_t target, uint32_t cond) {
  arm_b32_helper(write_p, target, cond);

  record_cc_link(thread_data, (uint32_t)write_p, target);
}

void arm_bl32_helper(uint32_t *write_p, uint32_t target, uint32_t cond) {
  arm_branch_helper(write_p, target, true, cond);
}

#define MIN_FSPACE 72

bool arm_scanner_deliver_callbacks(dbm_thread *thread_data, mambo_cb_idx cb_id, uint32_t **o_read_address,
                                   arm_instruction inst, uint32_t **o_write_p, uint32_t **o_data_p,
                                   int basic_block, cc_type type, bool allow_write, bool *stop) {
  bool replaced = false;
#ifdef PLUGINS_NEW
  if (global_data.free_plugin > 0) {
    uint32_t *write_p = *o_write_p;
    uint32_t *data_p = *o_data_p;
    uint32_t *read_address = *o_read_address;

    mambo_cond cond = (*read_address >> 28);
    if (cond == ALT) {
      cond = AL;
    }

    mambo_context ctx;
    set_mambo_context_code(&ctx, thread_data, PRE_INST_C, type, basic_block, ARM_INST, inst, cond, read_address, write_p, data_p, stop);

    for (int i = 0; i < global_data.free_plugin; i++) {
      if (global_data.plugins[i].cbs[cb_id] != NULL) {
        ctx.plugin_id = i;
        ctx.code.replace = false;
        ctx.code.write_p = write_p;
        ctx.code.data_p = data_p;
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
            arm_pop_regs(ctx.code.pushed_regs);
          }
          write_p = ctx.code.write_p;
          data_p = ctx.code.data_p;
          arm_check_free_space(thread_data, &write_p, &data_p, MIN_FSPACE, basic_block);
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
          arm_check_free_space(thread_data, &write_p, &data_p, MIN_FSPACE, basic_block);
        }
      }
    }

    *o_write_p = write_p;
    *o_data_p = data_p;
    *o_read_address = read_address;
  }
#endif
  return replaced;
}

bool inline_uncond_imm(dbm_thread *thread_data, bool insert_branch, uint32_t **write_p,
                       uint32_t **data_p, uint32_t **read_addr, uint32_t **bb_entry, uint32_t target,
                       int *inlined_back_count, int basic_block, cc_type type, bool *stop) {
  if (target <= (uint32_t)*read_addr) {
    if (*inlined_back_count >= MAX_BACK_INLINE) {
      if (insert_branch) {
        uint32_t cc_addr = lookup_or_stub(thread_data, target);
        arm_cc_branch(thread_data, *write_p, cc_addr, AL);
        *write_p += 1;
      }

      return false;
    } else {
      *inlined_back_count += 1;
    }
  }

  if (insert_branch) {
    arm_scanner_deliver_callbacks(thread_data, POST_BB_C, bb_entry, -1,
                                  write_p, data_p, basic_block, type, false, stop);
  }
  *read_addr = (uint32_t *)target;
  if (insert_branch) {
    *bb_entry = *read_addr;
    arm_scanner_deliver_callbacks(thread_data, PRE_BB_C, read_addr, -1,
                                  write_p, data_p, basic_block, type, true, stop);
  }

  // Assummes the read pointer is incremented at the end of the current scanner iteration
  *read_addr -= 1;

  return true;
}

void pass1_arm(dbm_thread *thread_data, uint32_t *read_address, branch_type *bb_type) {
  uint32_t null, reglist, rd, offset;
  int32_t branch_offset;
  *bb_type = unknown;
  int inlined_back_count = 0;

  while(*bb_type == unknown) {
    arm_instruction inst = arm_decode(read_address);

    switch(inst) {
      case ARM_B:
      case ARM_BL:
        arm_b_decode_fields(read_address, &offset);

        if ((*read_address >> 28) == AL) {
#ifdef DBM_INLINE_UNCOND_IMM
          branch_offset = (offset & 0x800000) ? 0xFC000000 : 0;
          branch_offset |= (offset<<2);
          uint32_t target = (int32_t)read_address + 8 + branch_offset;

          if(!inline_uncond_imm(thread_data, false, NULL, NULL, &read_address, NULL,
                                target, &inlined_back_count, -1, -1, NULL)) {
            *bb_type = uncond_imm_arm;
          }
#else
          *bb_type = uncond_imm_arm;
#endif
        } else {
          *bb_type = cond_imm_arm;
        }

        break;
      case ARM_BX:
      case ARM_BLX:
        *bb_type = ((*read_address >> 28) == AL) ? uncond_reg_arm : cond_reg_arm;
        break;

      case ARM_BLXI:
        *bb_type = ((*read_address >> 28) == AL) ? uncond_blxi_arm : cond_blxi_arm;
        break;

      case ARM_LDM:
        arm_ldm_decode_fields(read_address, &null, &reglist, &null, &null, &null, &null);

        if (reglist & (1 << pc)) {
          *bb_type = ((*read_address >> 28) == AL) ? uncond_reg_arm : cond_reg_arm;
        }
        break;

      case ARM_LDR:
        arm_ldr_decode_fields(read_address, &null, &rd, &null, &null, &null, &null, &null);

        if (rd == pc) {
          *bb_type = ((*read_address >> 28) == AL) ? uncond_reg_arm : cond_reg_arm;
        }
        break;

      case ARM_ADC:
      case ARM_ADD:
      case ARM_EOR:
      case ARM_MOV:
      case ARM_ORR:
      case ARM_SBC:
      case ARM_SUB:
      case ARM_RSC:
        arm_data_proc_decode_fields(read_address, &null, &null, &null, &rd, &null, &null);
        if (rd == pc) {
          *bb_type = ((*read_address >> 28) == AL) ? uncond_reg_arm : cond_reg_arm;
        }
        break;
    }

    read_address++;
  }
}

void arm_inline_hash_lookup(dbm_thread *thread_data, uint32_t **o_write_p, int basic_block, int r_target) {
  uint32_t *write_p = *o_write_p;
  uint32_t *loop_start;
  uint32_t *branch_miss;

  bool target_reg_clean = (r_target >= r0);
  int target = target_reg_clean ? r_target : r5;
  int r_tmp = target_reg_clean ? r5 : r4;

  if (basic_block != 0) {
    thread_data->code_cache_meta[basic_block].rn = target;
  }

  // MOVW+MOVT r_tmp, hash_mask
  arm_copy_to_reg_32bit(&write_p, r_tmp, CODE_CACHE_HASH_SIZE);

  // MOVW+MOVT r6, hash_table
  arm_copy_to_reg_32bit(&write_p, r6, (uint32_t)thread_data->entry_address.entries);

  // AND r_tmp, target, r_tmp
  arm_and(&write_p, REG_PROC, 0, r_tmp, target, r_tmp);
  write_p++;

  // ADD r_tmp, r6, r_tmp, LSL #3
  arm_add(&write_p, REG_PROC, 0, r_tmp, r6, r_tmp | (LSL << 5) | (3 << 7));
  write_p++;

  // loop:
  loop_start = write_p;

  // LDR r6, [r_tmp], #8
  arm_ldr(&write_p, IMM_LDR, r6, r_tmp, 8, 0, 1, 0);
  write_p++;

  // CMP r6, target
  arm_cmp(&write_p, REG_PROC, r6, target);
  write_p++;

  // BNE miss
  branch_miss = write_p++;

  // jump:
  // LDR r6, [r_tmp, #-4]
  arm_ldr(&write_p, IMM_LDR, r6, r_tmp, 4, 1, 0, 0);
  write_p++;

  // POP {r4}
  arm_pop_reg(r4);

  // BX R6
  arm_bx(&write_p, r6);
  write_p++;

  // miss:
  arm_b32_helper(branch_miss, (uint32_t)write_p, NE);

  // CMP R6, #0
  arm_cmp(&write_p, IMM_PROC, r6, 0);
  write_p++;

  // BNE loop
  arm_b32_helper(write_p, (uint32_t)loop_start, NE);
  write_p++;

  // SUB sp, sp, #8
  arm_sub(&write_p, IMM_PROC, 0, sp, sp, DISP_RES_WORDS*4);
  write_p++;

  // PUSH {r0 - r3}
  arm_push_regs((1 << r0) | (1 << r1) | (1 << r2) | (1 << r3));

  //ADD r3, sp, #24
  arm_add(&write_p, IMM_PROC, 0, r3, sp, DISP_SP_OFFSET);
  write_p++;

  // MOV r0, target
  arm_mov(&write_p, REG_PROC, 0, r0, target);
  write_p++;

  // MOV r1, #bb_id
  arm_copy_to_reg_32bit(&write_p, r1, basic_block);

  // LDMFD R3!, {R4-R6}
  arm_ldm(&write_p, r3, (1 << r4) | (1 << r5) | (1 << r6), 0, 1, 1, 0);
  write_p++;

  // B dispatcher
  arm_b32_helper(write_p, thread_data->dispatcher_addr, AL);
  write_p++;

  *o_write_p = write_p;
}

void arm_ihl_tr_rn_rm(uint32_t **o_write_p, uint32_t *read_address, uint32_t available_regs,
                      enum reg *rn, enum reg *rm, uint32_t *operand2) {
  uint32_t scratch_reg;
  uint32_t *write_p = *o_write_p;

  assert(count_bits(available_regs) >= 2);
  uint32_t sr[2];
  sr[0] = next_reg_in_list(available_regs, 0);
  sr[1] = next_reg_in_list(available_regs, sr[0] + 1);

  assert(*rn != pc || *rm != pc);
  if (*rn == pc || *rm == pc) {
    if (*rn == pc) {
      scratch_reg = (*rm == sr[0]) ? sr[1] : sr[0];
      *rn = scratch_reg;
    } else if (*rm == pc) {
      scratch_reg = (*rn == sr[0]) ? sr[1] : sr[0];
      *rm = scratch_reg;
      *operand2 = (*operand2 & (~0xF)) | *rm;
    }
    arm_copy_to_reg_32bit(&write_p, scratch_reg, (uint32_t)read_address + 8);
  }

  *o_write_p = write_p;
}

size_t scan_a32(dbm_thread *thread_data, uint32_t *read_address, int basic_block, cc_type type, uint32_t *write_p) {
  bool stop = false;

  uint32_t condition_code;
  uint32_t scratch_reg;

  int32_t  branch_offset;
  uint32_t target;
  uint32_t *tr_start;
  uint32_t *start_scan = read_address, *bb_entry = read_address;

  int inlined_back_count = 0;
  
  if (write_p == NULL) {
    write_p = (uint32_t *)&thread_data->code_cache->blocks[basic_block];
  }
  uint32_t start_address = (uint32_t)write_p;

  uint32_t *data_p;
  if (type == mambo_bb) {
    data_p = write_p + BASIC_BLOCK_SIZE;
  } else {
    data_p = (uint32_t *)&thread_data->code_cache->traces + (TRACE_CACHE_SIZE/4);
  }
  
  debug("write_p: %p\n", write_p);
  
  if (type != mambo_trace) {
    arm_pop_regs((1 << r5) | (1 << r6));
  }

#ifdef DBM_TRACES
  branch_type bb_type;
  pass1_arm(thread_data, read_address, &bb_type);
  
  if (type == mambo_bb && bb_type == cond_imm_arm) {
    arm_sub(&write_p, IMM_PROC, 0, sp, sp, 8);
    write_p++;

    arm_push_regs((1 << r0) | (1 << r1) | (1 << r2) | (1 << lr));

    arm_copy_to_reg_32bit(&write_p, r0, basic_block);

    arm_bl32_helper(write_p, thread_data->trace_head_incr_addr-5, AL);
    write_p++;
  }
#endif

  arm_scanner_deliver_callbacks(thread_data, PRE_FRAGMENT_C, &read_address, -1,
                                &write_p, &data_p, basic_block, type, true, &stop);
  arm_scanner_deliver_callbacks(thread_data, PRE_BB_C, &read_address, -1,
                                &write_p, &data_p, basic_block, type, true, &stop);
  
  while(!stop) {
    debug("arm scan read_address: %p\n", read_address);
    arm_instruction inst = arm_decode(read_address);
    debug("Instruction enum: %d\n", (inst == ARM_INVALID) ? -1 : inst);
    
    debug("instruction word: 0x%x\n", *read_address); 
#ifdef PLUGINS_NEW
    bool skip_inst = arm_scanner_deliver_callbacks(thread_data, PRE_INST_C, &read_address, inst,
                                                   &write_p, &data_p, basic_block, type, true, &stop);
    if (!skip_inst) {
#endif

    switch(inst) {
      /* Instructions which are allowed to use the PC */
      case ARM_ADC:
      case ARM_ADD:
      case ARM_EOR:
      case ARM_MOV:
      case ARM_ORR:
      case ARM_SBC:
      case ARM_SUB:
      case ARM_RSC: {
        uint32_t immediate, opcode, set_flags, rd, rn, operand2, rm = reg_invalid;
        arm_data_proc_decode_fields(read_address, &immediate, &opcode, &set_flags, &rd, &rn, &operand2);

        if(rd != pc && rn != pc && (immediate == IMM_PROC || (operand2 & 0xF) != pc)) {
          copy_arm();
        } else {
          if (immediate == REG_PROC) {
            rm = operand2 & 0xF;
          }
          if (rd == pc) {
            assert(rn != sp && rm != sp);
            assert(set_flags == 0);
#ifdef LINK_BX_ALT
            if ((*read_address >> 28) != AL) {
              target = lookup_or_stub(thread_data, (uint32_t)read_address + 4);
              arm_cc_branch(thread_data, write_p, target,
                            arm_inverse_cond_code[*read_address >> 28]);
              write_p++;
            }
#endif

            thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_arm;
            thread_data->code_cache_meta[basic_block].exit_branch_addr = (uint16_t *)write_p;

#ifdef DBM_INLINE_HASH
  #ifndef LINK_BX_ALT
            assert(0);
  #endif
            uint32_t saved_regs = (1 << r4) | (1 << r5) | (1 << r6);

            arm_push_regs(saved_regs);
            arm_ihl_tr_rn_rm(&write_p, read_address, saved_regs, &rn, &rm, &operand2);
            arm_data_proc(&write_p, immediate, opcode, set_flags, r5, rn, operand2);
            write_p++;

            arm_check_free_space(thread_data, &write_p, &data_p, IHL_SPACE, basic_block);
            arm_inline_hash_lookup(thread_data, &write_p, basic_block, -1);

            stop = true;
            break;
#endif
            /* This is an indirect branch */
            arm_branch_save_context(thread_data, &write_p, true);
            arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), SETUP);
          }
          if (rn == pc && rm == pc) {
            fprintf(stderr, "Unhandled ARM ADD, etc\n");
            while(1);
          }

          if (rn == pc || rm == pc) {
            /* If rd != PC and rd != rn && rd != rm, we can use rd as a scratch register */
            if (rd == pc || (rn == pc && rm == rd) || (rm == pc && rn == rd)) {
              scratch_reg = r0;
              while ((rm == scratch_reg) || (rn == scratch_reg) || (rd == scratch_reg)) {
                scratch_reg++;
              }
              // In this case the context hasn't been saved, we need to preserve the value of the scratch register
              if (rd != pc) {
                arm_cond_push_reg(*read_address >> 28, scratch_reg);
              } else {
                // r0, r1 (and optionally r2) are saved, but the value of r1 is set by the prev. call to arm_branch_jump
                assert(scratch_reg == r0);
              }
            } else {
              scratch_reg = rd;
            }
            arm_cond_copy_to_reg_32bit(&write_p, *read_address >> 28, scratch_reg, (uint32_t)read_address + 8);
          }

          arm_data_proc_cond(&write_p, (*read_address >> 28), immediate, opcode, set_flags,
                             (rd == pc) ? r0 : rd, (rn == pc) ? scratch_reg : rn,
                             (rm == pc) ? (scratch_reg | (operand2 & 0xFF0)) : operand2);
          write_p++;

          // Restore the value of the scratch register
          if ((rn == pc || rm == pc) && rd != pc && scratch_reg != rd) {
            arm_cond_pop_reg(*read_address >> 28, scratch_reg);
          }

          if (rd == pc) {
            arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address,
                            (*read_address >> 28), INSERT_BRANCH|LATE_APP_SP);
            stop = true;
          }
        }
        break;
      }

      case ARM_B:
      case ARM_BL: {
        uint32_t offset;
        arm_b_decode_fields(read_address, &offset);

        branch_offset = (offset & 0x800000) ? 0xFC000000 : 0;
        branch_offset |= (offset<<2);
        target = (uint32_t)read_address + 8 + branch_offset;
        condition_code = (*read_address >> 28);

        if (inst == ARM_BL) {
          arm_copy_to_reg_32bit(&write_p, lr, (uint32_t)read_address + 4);
        }

#ifdef DBM_INLINE_UNCOND_IMM
        if (condition_code == AL) {
          thread_data->code_cache_meta[basic_block].exit_branch_addr = (uint16_t *)write_p;
          if (!inline_uncond_imm(thread_data, true, &write_p, &data_p, &read_address, &bb_entry,
                                 target, &inlined_back_count, basic_block, type, &stop)) {
            thread_data->code_cache_meta[basic_block].exit_branch_type = trace_inline_max;
            thread_data->code_cache_meta[basic_block].branch_taken_addr = target;
            stop = true;
          }
          break;
        }
#endif

        thread_data->code_cache_meta[basic_block].exit_branch_type = (condition_code == AL) ? uncond_imm_arm : cond_imm_arm;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = (uint16_t *)write_p;
        thread_data->code_cache_meta[basic_block].branch_taken_addr = target;
        thread_data->code_cache_meta[basic_block].branch_skipped_addr = (uint32_t)read_address + 4;
        thread_data->code_cache_meta[basic_block].branch_condition = condition_code;

        if (condition_code != AL) {
          // Reserve space for the conditional branch instruction
          arm_nop(&write_p);
          write_p++;
        }

        arm_simple_exit(thread_data, &write_p, basic_block, offset, read_address, condition_code);
        stop = true;

        break;
      }

      case ARM_BX:
      case ARM_BLX: {
        uint32_t link, rn;
        arm_bx_t_decode_fields(read_address, &link, &rn);
        assert(rn != pc && rn != sp);

#ifdef LINK_BX_ALT
        if ((*read_address >> 28) != AL) {
          debug("w: %p, r: %p, bb: %d\n", write_p, read_address, basic_block);
          target = lookup_or_stub(thread_data, (uint32_t)read_address + 4);
          debug("stub: 0x%x\n", target);
          arm_cc_branch(thread_data,write_p, target,
                        arm_inverse_cond_code[(*read_address >> 28)]);
          write_p++;
        }
#endif // LINK_BX_ALT

        if (inst == ARM_BLX) {
          arm_copy_to_reg_32bit(&write_p, lr, (uint32_t)read_address + 4);
        }
        thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_arm;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = (uint16_t *)write_p;
        
#ifdef DBM_INLINE_HASH
  #ifndef LINK_BX_ALT
    #error LINK_BX_ALT is required
  #endif
        arm_push_regs((1 << r4) | (1 << r5) | (1 << r6));

        if (rn != r5) {
          arm_mov(&write_p, REG_PROC, 0, r5, rn);
          write_p++;
        }

        arm_check_free_space(thread_data, &write_p, &data_p, IHL_SPACE, basic_block);
        arm_inline_hash_lookup(thread_data, &write_p, basic_block, -1);
#else
        arm_branch_save_context(thread_data, &write_p, true);
        arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), SETUP);

        // Branch taken (not taken MOV is inserted by arm_branch_jump(SETUP))
        arm_mov_cond(&write_p, (*read_address >> 28), REG_PROC, false, r0, rn);
        write_p++;

        arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address,
                        (*read_address >> 28), INSERT_BRANCH|LATE_APP_SP);
#endif
        stop = true;
        break;
      }
      
      case ARM_BLXI: {
        uint32_t h, offset;
        arm_blxi_decode_fields(read_address, &h, &offset);
        
        branch_offset = ((h << 1) | (offset << 2)) + 1;
        if (branch_offset & 0x2000000) { branch_offset |= 0xFC000000; }

        arm_copy_to_reg_32bit(&write_p, lr, (uint32_t)read_address + 4);
        
        thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_blxi_arm;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = (uint16_t *)write_p;

        arm_simple_exit(thread_data, &write_p, basic_block, 0,
                        (uint32_t *)((uint32_t)read_address + branch_offset), AL);
        stop = true;

        break;
      }
      
      case ARM_LDM: {
        uint32_t rn, registers, prepostindex, updown, writeback, psr;
        arm_ldm_decode_fields(read_address, &rn, &registers, &prepostindex, &updown, &writeback, &psr);
        assert(rn != pc);

        if ((registers & (1 << 15)) == 0) {
          copy_arm();
        } else {
          condition_code = *read_address & 0xF0000000;
#ifdef LINK_BX_ALT
          if ((condition_code >> 28) != AL) {
            target = lookup_or_stub(thread_data, (uint32_t)read_address + 4);
            arm_cc_branch(thread_data, write_p, target,
                          arm_inverse_cond_code[condition_code >> 28]);
            write_p++;
          }
#else
          assert((condition_code >> 28) == AL);
#endif
          if ((1 << rn) & registers) {
            // Handles LDM sp, {*, sp, pc}
            assert(rn == sp && !writeback && !prepostindex);
            if (registers & 0x1FFF) {
              arm_ldm(&write_p, rn, registers & 0x1FFF, prepostindex, updown, writeback, psr);
              write_p++;
            }
          } else {
            assert(writeback);
            if (registers & 0x7FFF) {
              arm_ldm(&write_p, rn, registers & 0x7FFF, prepostindex, updown, writeback, psr);
              write_p++;
            }
          }

          thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_arm;
          thread_data->code_cache_meta[basic_block].exit_branch_addr = (uint16_t *)write_p;

#ifdef DBM_INLINE_HASH
          if ((1 << rn) & registers) {
            // We should adjust the offset if LR is also popped
            assert(((1 << lr) & registers) == 0);

            // PUSH {R0, R1}
            arm_push_regs((1 << r0)|(1 << r1));
            // LDR R0 [SP, offset_to_sp]
            arm_ldr(&write_p, IMM_LDR, r0, sp, (count_bits(registers)-2+2)<<2, 1, updown, writeback);
            write_p++;
            // LDR R1 [SP, offset_to_pc]
            arm_ldr(&write_p, IMM_LDR, r1, sp, (count_bits(registers)-1+2)<<2, 1, updown, writeback);
            write_p++;
            // STMFD R0!, {R4-R6}
            arm_stm(&write_p, r0, (1 << r4) | (1 << r5) | (1 << r6), 1, 0, 1, 0);
            write_p++;
            // MOV R5, R1
            arm_mov(&write_p, 0, 0, r5, r1);
            write_p++;
            // MOV R6, R0
            arm_mov(&write_p, 0, 0, r6, r0);
            write_p++;
            // POP {R0, R1}
            arm_pop_regs((1 << r0)|(1 << r1));
            // MOV SP, R6
            arm_mov(&write_p, 0, 0, sp, r6);
            write_p++;
          } else if (rn == sp) {
            assert(!prepostindex && updown && writeback && !psr);
            arm_push_regs((1 << r4) | (1 << r5));
            arm_ldr(&write_p, IMM_LDR, r5, sp, 8, 1, 1, 0);
            write_p++;
            arm_str(&write_p, IMM_LDR, r6, sp, 8, 1, 1, 0);
            write_p++;
          } else {
            arm_push_regs((1 << r4) | (1 << r5) | (1 << r6));
            arm_ldm(&write_p, rn, 1 << r5, prepostindex, updown, writeback, psr);
            write_p++;
            while(1);
          }

          arm_check_free_space(thread_data, &write_p, &data_p, IHL_SPACE, basic_block);
          arm_inline_hash_lookup(thread_data, &write_p, basic_block, -1);
#else
          // instructions of this type are only supported with inline hash table lookups
          assert((1 << rn) & registers == 0);

          arm_branch_save_context(thread_data, &write_p, false);
          arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), SETUP);

          assert(rn != r3);
          if (rn == sp) {
            rn = APP_SP;
          }

          arm_ldm_cond(&write_p, (*read_address >> 28), rn, (1 << r0), prepostindex, updown, writeback, psr);
          write_p++;

          arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), INSERT_BRANCH);
#endif
          stop = true;
        }
        break;
      }

      case ARM_LDRB:
      case ARM_LDR: {
        uint32_t immediate, rd, rn, offset, prepostindex, updown, writeback, rm = reg_invalid;

        switch (inst) {
          case ARM_LDRB:
            arm_ldrb_decode_fields(read_address, &immediate, &rd, &rn, &offset, &prepostindex, &updown, &writeback);
            break;
          case ARM_LDR:
            arm_ldr_decode_fields(read_address, &immediate, &rd, &rn, &offset, &prepostindex, &updown, &writeback);
            break;
        }
        if (immediate == LDR_REG) {
          rm = offset & 0xF;
          assert(rm != pc);
        }

        condition_code = *read_address & 0xF0000000;

#ifdef LINK_BX_ALT
        if (rd == pc && (*read_address >> 28) != AL) {
          target = lookup_or_stub(thread_data, (uint32_t)read_address + 4);
          arm_cc_branch(thread_data, write_p, target,
                        arm_inverse_cond_code[*read_address >> 28]);
          write_p++;
        }
#endif

        if (rd == pc || rn == pc) {
          if (rd == pc) {
            assert(inst == ARM_LDR);
            thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_arm;
            thread_data->code_cache_meta[basic_block].exit_branch_addr = (uint16_t *)write_p;

#ifdef DBM_INLINE_HASH
  #ifndef LINK_BX_ALT
            assert(0);
  #endif
            uint32_t saved_regs;
            assert(rm != pc);
            if (rn == sp && (writeback || !prepostindex)) {
              // POP {PC}
              assert(immediate == IMM_LDR && !prepostindex && updown
                       && !writeback && (offset & 3) == 0 && offset >= 4);
              if (offset == 4) {
                arm_push_regs((1 << r4) | (1 << r5));
                arm_ldr(&write_p, IMM_LDR, r5, sp, 8, 1, 1, 0);
                write_p++;
                arm_str(&write_p, IMM_LDR, r6, sp, 8, 1, 1, 0);
                write_p++;
              } else { // offset > 4
                // STR R6, [SP, #offset-4]
                arm_str(&write_p, IMM_LDR, r6, sp, offset-4, 1, 1, 0);
                write_p++;

                // LDR R6, [SP], #offset-4
                arm_ldr(&write_p, IMM_LDR, r6, sp, offset-4, 0, 1, 0);
                write_p++;

                // PUSH {R4, R5}
                arm_push_regs((1 << r4) | (1 << r5));

                // MOV R5, R6
                arm_mov(&write_p, REG_PROC, 0, r5, r6);
                write_p++;
              }
            } else {
              assert((!writeback && prepostindex) || (rn != r4 && rn != r5 && rn != r6 && rn != sp));
              saved_regs =  (1 << r4) | (1 << r5) | (1 << r6);
              arm_push_regs(saved_regs);
              arm_ihl_tr_rn_rm(&write_p, read_address, saved_regs, &rn, &rm, &offset);
              if (rn == sp) {
                assert(rm == reg_invalid && updown);
                offset += 12;
              }
              arm_ldr(&write_p, immediate, r5, rn, offset, prepostindex, updown, writeback);
              write_p++;
            }
            arm_check_free_space(thread_data, &write_p, &data_p, IHL_SPACE, basic_block);
            arm_inline_hash_lookup(thread_data, &write_p, basic_block, -1);

            stop = true;
            break;
#endif
            assert(rm != sp && rn != r3 && rm != r3);

            arm_branch_save_context(thread_data, &write_p, false);
            arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), SETUP);
          }
          scratch_reg = r0;
          if (rn == pc) {
            while ((rd != pc && scratch_reg == rd) || (immediate == LDR_REG && ((offset & 0xF) == scratch_reg))) {
              scratch_reg++;
            }
            if (rd != pc) {
              arm_cond_push_reg(condition_code >> 28, scratch_reg);
            }
            arm_cond_copy_to_reg_32bit(&write_p, condition_code >> 28, scratch_reg, (uint32_t)read_address + 8);
          }

          if (rd == pc && rn == sp) {
            rn = APP_SP;
          }

          switch (inst) {
            case ARM_LDRB:
              arm_ldrb_cond(&write_p, (condition_code >> 28), immediate, (rd == pc) ? r0 : rd, (rn == pc) ? scratch_reg : rn, offset, prepostindex, updown, writeback);
              break;
            case ARM_LDR:
              arm_ldr_cond(&write_p, (condition_code >> 28), immediate, (rd == pc) ? r0 : rd, (rn == pc) ? scratch_reg : rn, offset, prepostindex, updown, writeback);
              break;
          }
          *write_p |= condition_code;
          write_p++;
          
          // TODO: fixme
          /* LDR is used to load a value into PC, with writeback. 
             If the base register is R0, R1, or R2, it would have 
             already been saved before it is written back. 
             A proper fix should refactor the branching code to save */
          if (rd == pc && writeback) {
            switch (rn) {
              case r0:
              case r1:
              case r2:
                fprintf(stderr, "LDR with writeback");
                while(1);
                break;
            }
          }
            
          if (rd == pc) {
            arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), INSERT_BRANCH);
            stop = true;
          } else {
            arm_cond_pop_reg(condition_code >> 28, scratch_reg);
          }
        } else {
          copy_arm();
        }
        break;
      }

      case ARM_STM: {
        uint32_t rn, registers, prepostindex, updown, writeback, psr, offset;
        arm_stm_decode_fields(read_address, &rn, &registers, &prepostindex, &updown, &writeback, &psr);
        assert(rn != pc);

        if (registers & (1 << pc)) {
          /* Example :            STMFD SP!, {SP, LR, PC}

             is translated to:    STMFD SP!, {SP, LR, PC}
                                  MOW LR, #(spc & 0xFFFF)
                                  MOVT LR, #(spc >> 16)
                                  STR LR, [SP, #8]
                                  LDR LR, [SP, #4]

             Note that if rn is in the reglist, then its value must be stored first.
             This example was encountered in libgcc.
          */
          condition_code = (*read_address >> 28);
          if (condition_code != AL) {
            tr_start = write_p;
            write_p++;
          }

          scratch_reg = ~((1 << pc) | (1 << rn)) & registers;
          assert(scratch_reg);
          copy_arm();

          // Overwrite the saved TPC
          scratch_reg = next_reg_in_list(scratch_reg, 0);
          assert(scratch_reg < pc && scratch_reg != rn);
          arm_copy_to_reg_32bit(&write_p, scratch_reg, (uint32_t)read_address + 8);
          if (writeback) {
            offset = (count_bits(registers) - 1) << 2;
          }
          if (!prepostindex) {
            offset -= 4;
          }
          arm_str(&write_p, IMM_LDR, scratch_reg, rn, offset, 1, 1, 0);
          write_p++;

          // Calculate the offset of the location where the SR was saved
          offset = (scratch_reg > rn && (registers & (1 << rn))) ? 4 : 0;
          offset += prepostindex ? 0 : 4;

          arm_ldr(&write_p, IMM_LDR, scratch_reg, rn, offset, 1, updown ? 0 : 1, 0);
          write_p++;

          while (!writeback || !prepostindex || updown); // implement this

          if (condition_code != AL) {
            arm_b32_helper(tr_start, (uint32_t)write_p, arm_inverse_cond_code[condition_code]);
          }

          while(rn != sp); // Check me
        } else {
          copy_arm();
        }
        break;
      }
        
      case ARM_STRB:
      case ARM_STR: {
        uint32_t immediate, rd, rn, offset, prepostindex, updown, writeback;
        switch (inst) {
          case ARM_STRB:
            arm_strb_decode_fields(read_address, &immediate, &rd, &rn, &offset, &prepostindex, &updown, &writeback);
            break;
          case ARM_STR:
            arm_str_decode_fields(read_address, &immediate, &rd, &rn, &offset, &prepostindex, &updown, &writeback);
            break;
        }
        if (immediate == 1) assert((offset & 0xF) != pc);
        
        if (rd == pc) {
          condition_code = (*read_address & 0xF0000000) >> 28;
          assert(condition_code == AL && rn == sp & prepostindex && !updown && writeback); // PUSH {PC}

          // SUB SP, SP, #8
          arm_add_sub_32_bit(&write_p, sp, sp, -8);

          // STR R0, [SP, #0]
          arm_str(&write_p, IMM_LDR, r0, sp, 0, 1, 1, 0);
          write_p++;

          // MOV{W,T} R0, addr
          arm_copy_to_reg_32bit(&write_p, r0, (uint32_t)read_address + 8);

          // STR R0, [SP, #4]
          arm_str(&write_p, IMM_LDR, r0, sp, 4, 1, 1, 0);
          write_p++;

          // POP {R0}
          arm_pop_reg(r0);
        } else if(rn == pc) {
          condition_code = *read_address & 0xF0000000;

          scratch_reg = r0;
          while (rd == scratch_reg || (offset & 0xF) == scratch_reg) {
            scratch_reg++;
          }

          arm_cond_push_reg(condition_code >> 28, scratch_reg);
          arm_cond_copy_to_reg_32bit(&write_p, condition_code >> 28, scratch_reg, (uint32_t)read_address + 8);
          
          switch (inst) {
            case ARM_STRB:
              arm_strb_cond(&write_p, (condition_code >> 28), immediate, rd, scratch_reg, offset, prepostindex, updown, writeback);
              break;
            case ARM_STR:
              arm_str_cond(&write_p, (condition_code >> 28), immediate, rd, scratch_reg, offset, prepostindex, updown, writeback);
              break;
          }
          *write_p |= condition_code;
          write_p++;
          
          arm_cond_pop_reg(condition_code >> 28, scratch_reg);
        } else {
          copy_arm();
        }
        break;
      }

      /* Other translated sensitive instructions */
      case ARM_MCR:
      case ARM_MRC: {
        uint32_t opc1, load_store, crn, rd, coproc, opc2, crm;
        arm_coproc_trans_decode_fields(read_address, &opc1, &load_store, &crn, &rd, &coproc, &opc2, &crm);
        
        // thread id
        if (coproc == 15 && opc1 == 0 && crn == 13 && crm == 0 && opc2 == 3 && load_store == 1 && rd != pc) {
          condition_code = (*read_address >> 28);
          if (condition_code != AL) {
            tr_start = write_p++;
          }
          arm_copy_to_reg_32bit(&write_p, rd, (uint32_t)(&thread_data->tls));
          arm_ldr(&write_p, IMM_LDR, rd, rd, 0, 1, 1, 0);
          write_p++;
          if (condition_code != AL) {
            arm_b32_helper(tr_start, (uint32_t)write_p, condition_code ^ 1);
          }

        // NEON / FP VMRS/VMSR
        } else if (coproc == 10 && opc1 == 7 && crn == 1 && rd != pc) {
          copy_arm();
        // Performance counter
        // This is used in OpenSSL in OPENSSL_cpuid_setup, a constructor. WTF
        } else if (coproc == 15 && opc1 == 0 && crn == 9 && crm == 13 && opc2 == 0 && load_store == 1 && rd != pc) {
          copy_arm();

        // Data memory barrier operation, deprecated in ARMv7-a in favor of
        // dmb(). This is used in Raspbian Jessie's libc6, which is apparently
        // compiled for ARMv6 due to compatibility reasons. Section B3.12.33 in
        // page B3-136 of ARM DDI 0406B has more information on this mcr op.
        } else if (coproc == 15 && opc1 == 0 && crn == 7 && crm == 10 && opc2 == 5 && load_store == 0 && rd != pc) {
          copy_arm();

        } else {
          fprintf(stderr, "unknown coproc: %d %d %d %d %d %d\n", opc1, crn, rd, coproc, opc2, crm);
          while(1);
        }
        break;
      }

      case ARM_SVC: {
        condition_code = (*read_address >> 28) & 0xF;

        if (condition_code != AL) {
          tr_start = write_p;
          write_p++;
        }

        arm_sub(&write_p, IMM_PROC, 0, sp, sp, 8);
        write_p++;

        // PUSH {R0-R12, R14}
        arm_push_regs(0x5FFF);

        arm_copy_to_reg_32bit(&write_p, r8, (uint32_t)read_address + 4);

        arm_bl(&write_p, (thread_data->syscall_wrapper_addr - (uint32_t)write_p - 8) >> 2);
        write_p++;

        if (condition_code != AL) {
          arm_b32_helper(tr_start, (uint32_t)write_p, condition_code);
        }

        arm_scanner_deliver_callbacks(thread_data, POST_BB_C, &bb_entry, -1,
                                &write_p, &data_p, basic_block, type, false, &stop);
        // set the correct address for the PRE_BB_C event
        read_address++;
        bb_entry = read_address;
        arm_scanner_deliver_callbacks(thread_data, PRE_BB_C, &read_address, -1,
                                &write_p, &data_p, basic_block, type, true, &stop);
        read_address--;
        break;
      }

      /* Instructions which could access the PC, but shouldn't. */
      case ARM_AND:
      case ARM_BIC:
      case ARM_RSB: {
        uint32_t immediate, set_flags, rd, rn, operand2;
        arm_and_decode_fields(read_address, &immediate, &set_flags, &rd, &rn, &operand2);
        assert(rd != pc && rn != pc);
        if (immediate == 0) assert((operand2 & 0xF) != pc);
        copy_arm();
        break;
      }

      case ARM_CMN:
      case ARM_CMP:
      case ARM_TEQ:
      case ARM_TST: {
        uint32_t immediate, rn, operand2;
        arm_cmn_decode_fields(read_address, &immediate, &rn, &operand2);
        assert(rn != pc);
        if (immediate == 0) assert((operand2 & 0xF) != pc);
        copy_arm();
        break;
      }

      case ARM_MOVW:
      case ARM_MOVT: {
        uint32_t immediate, opcode, set_flags, rd, rn, operand2;
        arm_data_proc_decode_fields(read_address, &immediate, &opcode, &set_flags, &rd, &rn, &operand2);
        // Rn is actually the top 4 bits of the immediate value
        assert(rd != pc);
        copy_arm();
        break;
      }

      case ARM_MVN: {
        uint32_t immediate, set_flags, rd, operand2;
        arm_mvn_decode_fields(read_address, &immediate, &set_flags, &rd, &operand2);
        assert(rd != pc);
        if (immediate == REG_PROC) assert((operand2 & 0xF) != pc);
        copy_arm();
        break;
      }

      case ARM_MUL:
      case ARM_MLA:
      case ARM_MLS: {
        uint32_t accumulate, set_flags, rd, rm, rs, rn;
        arm_multiply_decode_fields(read_address, &accumulate, &set_flags, &rd, &rm, &rs, &rn);
        assert(rd != pc && rm != pc && rs != pc && rn != pc);
        copy_arm();
        break;
      }

      case ARM_LDRD:
      case ARM_LDRH:
      case ARM_LDRHT:
      case ARM_LDRSB:
      case ARM_LDRSBT:
      case ARM_LDRSH:
      case ARM_LDRSHT:
      case ARM_STRD:
      case ARM_STRH:
      case ARM_STRHT: {
        uint32_t opcode, size, opcode2, immediate, rd, rn, rm, imm4h, prepostindex, updown, writeback;
        arm_h_data_transfer_decode_fields(read_address, &opcode, &size, &opcode2, &immediate,
                                          &rd, &rn, &rm, &imm4h, &prepostindex, &updown, &writeback);
        assert(rd != pc);
        if (immediate == REG_PROC) assert(rm != pc);
        if (rn == pc) {
          assert(inst != ARM_STRD && inst != ARM_STRH && inst != ARM_STRHT);
          assert(prepostindex && !writeback);
          condition_code = *read_address >> 28;
          arm_cond_copy_to_reg_32bit(&write_p, condition_code, rd, (uint32_t)read_address + 8);
          arm_h_data_transfer_cond(&write_p, condition_code, opcode, size, opcode2, immediate, rd,
                                   rd, rm, imm4h, prepostindex, updown, writeback);
          write_p++;
        } else {
          copy_arm();
        }
        break;
      }

      case ARM_LDREX:
      case ARM_LDREXB:
      case ARM_LDREXD:
      case ARM_LDREXH: {
        uint32_t rd, rn;
        arm_ldrex_decode_fields(read_address, &rd, &rn);
        assert(rd != pc && rn != pc);
        copy_arm();
        break;
      }

      case ARM_STREX:
      case ARM_STREXB:
      case ARM_STREXD:
      case ARM_STREXH: {
        uint32_t rd, rn, rm;
        arm_strex_decode_fields(read_address, &rd, &rn, &rm);
        assert(rd != pc && rn != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_REV:
      case ARM_REV16:
      case ARM_CLZ: {
        uint32_t opcode, size, opcode2, immediate, rd, rn, rm, imm4h, prepostindex, updown, writeback;
        arm_h_data_transfer_decode_fields(read_address, &opcode, &size, &opcode2, &immediate, &rd, &rn, &rm, &imm4h, &prepostindex, &updown, &writeback);
        assert(rd != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_PLD: {
        uint32_t imm, updown, readonly, rn, operand2, rm = reg_invalid;
        arm_pld_decode_fields(read_address, &imm, &updown, &readonly, &rn, &operand2);
        if (imm == LDR_REG) {
          rm = operand2 & 0xF;
        }
        /* The cost of obtaining a scratch register and copying the source PC
             is *probably* too high to be worth translating this. */
        if (rn != pc && rm != pc ) {
          copy_arm();
        }
        break;
      }

      case ARM_STC: {
        uint32_t p, updown, d, writeback, load_store, rn, vd, opcode, immediate;
        arm_vfp_ldm_stm_decode_fields(read_address, &p, &updown, &d, &writeback, &load_store, &rn, &vd, &opcode, &immediate);
        assert(rn != pc);
        copy_arm();
        break;
      }

      case ARM_CDP: {
        uint32_t opc1, crn, crd, coproc, opc2, crm;
        arm_coproc_dp_decode_fields(read_address, &opc1, &crn, &crd, &coproc, &opc2, &crm);
        copy_arm();
        fprintf(stderr, "Untested CDP\n");
        while(1);
        break;
      }
        
      case ARM_UMLAL:
      case ARM_UMULL:
      case ARM_SMULL:
      case ARM_SMLAL: {
        uint32_t opcode, set_flags, rdhi, rdlo, rm, opcode2, setting, rn;
        arm_dsp_long_res_decode_fields(read_address, &opcode, &set_flags, &rdhi, &rdlo, &rm, &opcode2, &setting, &rn);
        assert(rdhi != pc && rdlo != pc && rm != pc && rn != pc);
        copy_arm();
        break;
      }
        
      case ARM_MRS: {
        uint32_t rd;
        arm_mrs_decode_fields(read_address, &rd);
        assert(rd != pc);
        copy_arm();
        break;
      }

      case ARM_MSR: {
        uint32_t rn, mask;
        arm_msr_decode_fields(read_address, &rn, &mask);
        assert(rn != pc);
        copy_arm();
        break;
      }

      case ARM_UDIV:
      case ARM_SDIV: {
        uint32_t opcode, rd, rn, rm;
        arm_divide_decode_fields(read_address, &opcode, &rd, &rn, &rm);
        assert(rd != pc && rn != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_SXTB:
      case ARM_SXTH:
      case ARM_SXTAH:
      case ARM_UXTB:
      case ARM_UXTB16:
      case ARM_UXTH:
      case ARM_UXTAH:
      case ARM_UXTAB:
      case ARM_UXTAB16: {
        uint32_t opcode, rd, rn, rm, rotate;
        arm_extend_decode_fields(read_address, &opcode, &rd, &rn, &rm, &rotate);
        // if rn == pc, it's the version without add which doesn't use pc
        assert(rd != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_LDRBT:
      case ARM_LDRT:
      case ARM_STRBT:
      case ARM_STRT: {
        uint32_t immediate, rd, rn, updown, operand2;
        arm_ldrt_decode_fields(read_address, &immediate, &rd, &rn, &updown, &operand2);
        assert(rd != pc && rn != pc);
        if (immediate == LDR_REG) assert((operand2 & 0xF) != pc);
        copy_arm();
        break;
      }

      case ARM_BFI: {
        uint32_t rd, rn, lsb, msb;
        arm_bfi_decode_fields(read_address, &rd, &rn, &lsb, &msb);
        assert(rd != pc && rn != pc);
        copy_arm();
        break;
      }

      case ARM_UBFX:
      case ARM_SBFX: {
        uint32_t rd, rn, lsb, width;
        arm_ubfx_decode_fields(read_address, &rd, &rn, &lsb, &width);
        assert(rd != pc && rn != pc);
        copy_arm();
        break;
      }

      case ARM_UQSUB8: {
        uint32_t rd, rn, rm;
        arm_uqsub8_decode_fields(read_address, &rd, &rn, &rm);
        assert(rd != pc && rn != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_BFC: {
        uint32_t rd, lsb, msb;
        arm_bfc_decode_fields(read_address, &rd, &lsb, &msb);
        assert(rd != pc);
        copy_arm();
        break;
      }

      case ARM_MRRC: {
        uint32_t coproc, opc1, rd, rd2, crm;
        arm_mrrc_decode_fields(read_address, &coproc, &opc1, &rd, &rd2, &crm);
        assert(rd != pc && rd2 != pc);
        copy_arm();
        break;
      }

      case ARM_UMAAL: {
        uint32_t rd, rd2, rn, rm;
        arm_umaal_decode_fields(read_address, &rd, &rd2, &rn, &rm);
        assert(rd != pc && rd2 != pc && rn != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_SMULBB:
      case ARM_SMULTT: {
        uint32_t rd, rn, rm;
        arm_smulbb_decode_fields(read_address, &rd, &rn, &rm);
        assert(rd != pc && rn != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_SMULWB:
      case ARM_SMULWT: {
        uint32_t rd, rn, rm;
        arm_smulwb_decode_fields(read_address, &rd, &rn, &rm);
        assert(rd != pc && rn != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_RBIT: {
        uint32_t rd, rm;
        arm_rbit_decode_fields(read_address, &rd, &rm);
        assert(rd != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_SMLABB: {
        uint32_t rd, rn, rm, ra;
        arm_smlabb_decode_fields(read_address, &rd, &rn, &rm, &ra);
        assert(rd != pc && rn != pc && rm != pc && ra != pc);
        copy_arm();
        break;
      }

      case ARM_SMLAWB:
      case ARM_SMLAWT: {
        uint32_t rd, rn, rm, ra;
        arm_smlawb_decode_fields(read_address, &rd, &rn, &rm, &ra);
        assert(rd != pc && rn != pc && rm != pc && ra != pc);
        copy_arm();
        break;
      }

      case ARM_PKH: {
        uint32_t rd, rn, rm, tb, imm5;
        arm_pkh_decode_fields(read_address, &rd, &rn, &rm, &tb, &imm5);
        assert(rd != pc && rn != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_SSAT:
      case ARM_USAT: {
        uint32_t rd, sat_imm, rn, sh, imm5;
        arm_usat_decode_fields(read_address, &rd, &sat_imm, &rn, &sh, &imm5);
        assert(rd != pc && rn != pc);
        copy_arm();
        break;
      }

      case ARM_USAT16: {
        uint32_t rd, sat_imm, rn;
        arm_usat16_decode_fields(read_address, &rd, &sat_imm, &rn);
        assert(rd != pc && rn != pc);
        copy_arm();
        break;
      }

      case ARM_UADD8:
      case ARM_UQADD8: {
        uint32_t rd, rn, rm;
        arm_uadd8_decode_fields(read_address, &rd, &rn, &rm);
        assert(rd != pc && rn != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_SEL: {
        uint32_t rd, rn, rm;
        arm_sel_decode_fields(read_address, &rd, &rn, &rm);
        assert(rd != pc && rn != pc && rm != pc);
        copy_arm();
	      break;
      }

      case ARM_RRX: {
        uint32_t set_flags, rd, rm;
        arm_rrx_decode_fields(read_address, &set_flags, &rd, &rm);
        assert(rd != pc && rm != pc);
        copy_arm();
        break;
      }

      case ARM_UDF:
        if (start_scan == read_address) {
          copy_arm();
        } else {
          thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_imm_arm;
          thread_data->code_cache_meta[basic_block].exit_branch_addr = (uint16_t *)write_p;
          thread_data->code_cache_meta[basic_block].branch_taken_addr = (uint32_t)read_address;

          arm_simple_exit(thread_data, &write_p, basic_block, -2, read_address, AL);
          stop = true;
        }
        break;

      /* ARM instructions which can be copied directly */
      case ARM_BKPT:
      case ARM_CLREX:
      case ARM_DMB:
      case ARM_DSB:
      case ARM_ISB:
      case ARM_MSRI:
      case ARM_NOP:
        copy_arm();
        break;

      /* Discarded ARM instructions */
      case ARM_PLII:
        /* Discard instruction preload hints, since they would otherwise only pollute our icache */
        break;

      /* NEON and VFP instructions which might access the PC */
      case ARM_VFP_VSTM_DP:
      case ARM_VFP_VSTM_SP:
      case ARM_VFP_VLDM_SP:
      case ARM_VFP_VLDM_DP:
      case ARM_VFP_VSTR_DP:
      case ARM_VFP_VSTR_SP:
      case ARM_VFP_VLDR_DP:
      case ARM_VFP_VLDR_SP: {
        uint32_t p, updown, d, writeback, load_store, rn, vd, opcode, immediate;
        arm_vfp_ldm_stm_decode_fields(read_address, &p, &updown, &d, &writeback, &load_store, &rn, &vd, &opcode, &immediate);

        if (rn == pc) {
          assert(writeback == 0);

          condition_code = *read_address & 0xF0000000;
          arm_cond_push_reg(condition_code >> 28, r0);

          arm_cond_copy_to_reg_32bit(&write_p, condition_code >> 28, r0, (uint32_t)read_address + 8);
          arm_vfp_ldm_stm_cond(&write_p, (*read_address) >> 28, p, updown, d, writeback, load_store, r0, vd, opcode, immediate);
          write_p++;

          arm_cond_pop_reg(condition_code >> 28, r0);
        } else {
          copy_arm();
        }
        break;
      }

      case ARM_NEON_VLDX_M:
      case ARM_NEON_VLDX_S_O:
      case ARM_NEON_VLDX_S_A:
      case ARM_NEON_VSTX_M:
      case ARM_NEON_VSTX_S_O: {
        uint32_t opcode, opcode2, opcode3, opcode4, params, d, vd, rn, rm;
        arm_v_trans_mult_decode_fields(read_address, &opcode, &opcode2, &opcode3, &opcode4, &params, &d, &vd, &rn, &rm);
        assert(rn != pc); // rm is guaranteed not to be pc
        copy_arm();
        break;
      }

      case ARM_VFP_VMOV_2CORE_DP: {
        uint32_t opcode, rd, rd2, m, vm;
        arm_vfp_vmov_2core_dp_decode_fields(read_address, &opcode, &rd, &rd2, &m, &vm);
        assert(rd != pc && rd2 != pc); // rm is guaranteed not to be pc
        copy_arm();
        break;
      }

      case ARM_VFP_VMOV_CORE_SCAL: {
        uint32_t d, vd, opcode, opcode2, rd;
        arm_vfp_vmov_core_scal_decode_fields(read_address, &d, &vd, &opcode, &opcode2, &rd);
	      assert(rd != pc);
	      copy_arm();
        break;
      }

      case ARM_VFP_VMOV_CORE_SP: {
        uint32_t opcode, rd, n, vn;
        arm_vfp_vmov_core_sp_decode_fields(read_address, &opcode, &rd, &n, &vn);
        assert(rd != pc);
        copy_arm();
        break;
      }

      case ARM_NEON_VDUP_CORE: {
        uint32_t b, e, q, d, vd, rd;
        arm_neon_vdup_core_decode_fields(read_address, &b, &e, &q, &d, &vd, &rd);
        assert(rd != pc);
        copy_arm();
        break;
      }
        
      case ARM_VFP_VMOV_SCAL_CORE: {
        uint32_t opcode, rd, n, vn, opcode2, opcode3;
        arm_vfp_vmov_scal_core_decode_fields(read_address, &opcode, &rd, &n, &vn, &opcode2, &opcode3);
        assert(rd != pc);
        copy_arm();
        break;
      }

      case ARM_VFP_VMSR: {
        uint32_t rd;
        arm_vfp_vmsr_decode_fields(read_address, &rd);
        assert(rd != pc);
        copy_arm();
        break;
      }

      /* NEON and VFP instructions which can't access the PC */
      case ARM_NEON_VABD_I:
      case ARM_NEON_VABDL:
      case ARM_NEON_VABS:
      case ARM_NEON_VADD_F:
      case ARM_NEON_VADD_I:
      case ARM_NEON_VADDL:
      case ARM_NEON_VADDW:
      case ARM_NEON_VAND:
      case ARM_NEON_VBIC:
      case ARM_NEON_VBICI:
      case ARM_NEON_VBSL:
      case ARM_NEON_VCEQ_I:
      case ARM_NEON_VCEQZ:
      case ARM_NEON_VCGE_F:
      case ARM_NEON_VCGE_I:
      case ARM_NEON_VCGEZ:
      case ARM_NEON_VCGT_F:
      case ARM_NEON_VCGT_I:
      case ARM_NEON_VCGTZ:
      case ARM_NEON_VCLEZ:
      case ARM_NEON_VCLTZ:
      case ARM_NEON_VCNT:
      case ARM_NEON_VCVT_F_FP:
      case ARM_NEON_VCVT_F_I:
      case ARM_NEON_VDUP_SCAL:
      case ARM_NEON_VEOR:
      case ARM_NEON_VEXT:
      case ARM_NEON_VHADD:
      case ARM_NEON_VMAX_I:
      case ARM_NEON_VMIN_I:
      case ARM_NEON_VMLA_F:
      case ARM_NEON_VMLA_I:
      case ARM_NEON_VMLAL_I:
      case ARM_NEON_VMLAL_SCAL:
      case ARM_NEON_VMLA_SCAL:
      case ARM_NEON_VMLS_F:
      case ARM_NEON_VMLSL_I:
      case ARM_NEON_VMLSL_SCAL:
      case ARM_NEON_VMLS_SCAL:
      case ARM_NEON_VMOVI:
      case ARM_NEON_VMOVL:
      case ARM_NEON_VMOVN:
      case ARM_NEON_VMUL_F:
      case ARM_NEON_VMUL_I:
      case ARM_NEON_VMULL_I:
      case ARM_NEON_VMULL_SCAL:
      case ARM_NEON_VMUL_SCAL:
      case ARM_NEON_VMVN:
      case ARM_NEON_VMVNI:
      case ARM_NEON_VNEG:
      case ARM_NEON_VORN:
      case ARM_NEON_VORR:
      case ARM_NEON_VORRI:
      case ARM_NEON_VPADD_F:
      case ARM_NEON_VPADD_I:
      case ARM_NEON_VPADDL:
      case ARM_NEON_VQADD:
      case ARM_NEON_VQDMULH_I:
      case ARM_NEON_VQDMULH_SCAL:
      case ARM_NEON_VQMOVUN:
      case ARM_NEON_VQRSHRN:
      case ARM_NEON_VQRSHRUN:
      case ARM_NEON_VQSHRN:
      case ARM_NEON_VQSHRUN:
      case ARM_NEON_VQSUB:
      case ARM_NEON_VREV32:
      case ARM_NEON_VREV64:
      case ARM_NEON_VRHADD:
      case ARM_NEON_VRSHL:
      case ARM_NEON_VRSHR:
      case ARM_NEON_VRSHRN:
      case ARM_NEON_VRSRA:
      case ARM_NEON_VSHL:
      case ARM_NEON_VSHLI:
      case ARM_NEON_VSHLL:
      case ARM_NEON_VSHLL2:
      case ARM_NEON_VSHR:
      case ARM_NEON_VSHRN:
      case ARM_NEON_VSLI:
      case ARM_NEON_VSRA:
      case ARM_NEON_VSUB_F:
      case ARM_NEON_VSUB_I:
      case ARM_NEON_VSUBL:
      case ARM_NEON_VSUBW:
      case ARM_NEON_VSWP:
      case ARM_NEON_VTRN:
      case ARM_NEON_VTST:
      case ARM_NEON_VUZP:
      case ARM_NEON_VZIP:
      case ARM_VFP_VABS:
      case ARM_VFP_VADD:
      case ARM_VFP_VCMP:
      case ARM_VFP_VCMPE:
      case ARM_VFP_VCMPEZ:
      case ARM_VFP_VCMPZ:
      case ARM_VFP_VCVT_DP_SP:
      case ARM_VFP_VCVT_F_FP:
      case ARM_VFP_VCVT_F_I:
      case ARM_VFP_VDIV:
      case ARM_VFP_VFMA:
      case ARM_VFP_VFMS:
      case ARM_VFP_VFNMS:
      case ARM_VFP_VMLA_F:
      case ARM_VFP_VMLS_F:
      case ARM_VFP_VMOV:
      case ARM_VFP_VMOVI:
      case ARM_VFP_VMRS:
      case ARM_VFP_VMUL_F:
      case ARM_VFP_VNEG:
      case ARM_VFP_VNMLA:
      case ARM_VFP_VNMLS:
      case ARM_VFP_VNMUL:
      case ARM_VFP_VPOP_DP:
      case ARM_VFP_VPOP_SP:
      case ARM_VFP_VPUSH_DP:
      case ARM_VFP_VPUSH_SP:
      case ARM_NEON_VRADDHN:
      case ARM_VFP_VSQRT:
      case ARM_VFP_VSUB_F:
        copy_arm();
        break;

      default:
        fprintf(stderr, "Unknown arm instruction: %d at %p\n", inst, read_address);
        while(1);
        exit(EXIT_FAILURE);
    }
#ifdef PLUGINS_NEW
    } // if (!skip_inst)
#endif

    if (write_p >= data_p) {
      printf("w: %p r: %p\n", write_p, data_p);
    }
    assert (write_p < data_p);

    if (!stop) arm_check_free_space(thread_data, &write_p, &data_p, MIN_FSPACE, basic_block);

#ifdef PLUGINS_NEW
    arm_scanner_deliver_callbacks(thread_data, POST_INST_C, &read_address, inst, &write_p, &data_p, basic_block, type, !stop, &stop);
#endif

    debug("write_p: %p\n", write_p);

    read_address++;
    debug("\n");
  }

  arm_scanner_deliver_callbacks(thread_data, POST_BB_C, &bb_entry, -1,
                                &write_p, &data_p, basic_block, type, false, &stop);
  arm_scanner_deliver_callbacks(thread_data, POST_FRAGMENT_C, &start_scan, -1,
                                &write_p, &data_p, basic_block, type, false, &stop);

  // We haven't strictly enforced updating write_p after the last instruction
  return ((uint32_t)write_p - start_address + 4);
}

void arm_encode_stub_bb(dbm_thread *thread_data, int basic_block, uint32_t target) {
  uint32_t *write_p = (uint32_t *)&thread_data->code_cache->blocks[basic_block];
  uint32_t *data_p = (uint32_t *)write_p;
  data_p += BASIC_BLOCK_SIZE;

  debug("Stub BB: %p\n", write_p);
  debug("ARM stub target: 0x%x\n", target);

  arm_pop_regs((1 << r5) | (1 << r6));

  arm_simple_exit(thread_data, &write_p, basic_block, 0, (uint32_t *)(target - 8), AL);
}

#endif // __arm__
