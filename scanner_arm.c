/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>

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
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <limits.h>

#include "dbm.h"
#include "common.h"
#include "scanner_common.h"

#include "pie/pie-arm-decoder.h"
#include "pie/pie-arm-encoder.h"
#include "pie/pie-arm-field-decoder.h"

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

#define copy_arm() *(write_p++) = *read_address;

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

void arm_branch_save_context(dbm_thread *thread_data, uint32_t **o_write_p) {
  uint32_t *write_p = *o_write_p;

  arm_push_reg(r3);
  arm_copy_to_reg_32bit(&write_p, r3, (uint32_t)thread_data->scratch_regs);
  arm_stm(&write_p, r3, (1 << r0) | (1 << r1) | (1 << r2), 0, 1, 0, 0);
  write_p++;
  arm_pop_reg(r3);

  *o_write_p = write_p;
}

#define SETUP (1 << 0)
#define REPLACE_TARGET (1 << 1)
#define INSERT_BRANCH (1 << 2)

void arm_branch_jump(dbm_thread *thread_data, uint32_t **o_write_p, int basic_block,
                     uint32_t offset, uint32_t *read_address, uint32_t cond, uint32_t flags) {
  uint32_t *write_p = *o_write_p;
  
  int32_t  branch_offset;
  
  uint32_t *scratch_data;
  uint32_t scratch_offset;
  uint32_t condition_code = 0xE0000000;

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
    arm_copy_to_reg_32bit(&write_p, r1, basic_block);

    arm_b(&write_p, (thread_data->dispatcher_addr - (uint32_t)write_p - 8) >> 2);
    write_p++;
  }
  
  *o_write_p = write_p;
}

void arm_check_free_space(dbm_thread *thread_data, uint32_t **write_p, uint32_t **data_p, uint32_t size) {
  int basic_block;

  if ((((uint32_t)*write_p)+size) >= (uint32_t)*data_p) {
    assert(thread_data->free_block < (CODE_CACHE_SIZE + CODE_CACHE_OVERP - 1));
    basic_block = thread_data->free_block++;
    arm_b(write_p, ((uint32_t)&thread_data->code_cache->blocks[basic_block] - (uint32_t)*write_p - 8) >> 2);
    *write_p = (uint32_t *)&thread_data->code_cache->blocks[basic_block];
    *data_p = (uint32_t *)*write_p;
    *data_p += BASIC_BLOCK_SIZE;
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

void pass1_arm(dbm_thread *thread_data, uint32_t *read_address, branch_type *bb_type) {
  uint32_t null, reglist, rd, dn, imm, offset;
  int32_t branch_offset;
  *bb_type = unknown;

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
          read_address = (uint32_t *)((int32_t)read_address + 8 + branch_offset) - 1; // read_address is incremented this iteration
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

bool arm_scanner_deliver_callbacks(dbm_thread *thread_data, mambo_cb_idx cb_id, uint32_t *read_address,
                                   arm_instruction inst, uint32_t **o_write_p, uint32_t **o_data_p,
                                   int basic_block, cc_type type, bool allow_write) {
  bool replaced = false;
#ifdef PLUGINS_NEW
  if (global_data.free_plugin > 0) {
    uint32_t *write_p = *o_write_p;
    uint32_t *data_p = *o_data_p;

    mambo_cond cond = (*read_address >> 28);
    if (cond == ALT) {
      cond = AL;
    }

    mambo_context ctx;
    set_mambo_context(&ctx, thread_data, ARM_INST, type, basic_block, inst, cond, read_address, write_p, NULL);

    for (int i = 0; i < global_data.free_plugin; i++) {
      if (global_data.plugins[i].cbs[cb_id] != NULL) {
        ctx.write_p = write_p;
        ctx.plugin_id = i;
        ctx.replace = false;
        global_data.plugins[i].cbs[cb_id](&ctx);
        if (allow_write) {
          if (replaced && (write_p != ctx.write_p || ctx.replace)) {
            fprintf(stderr, "MAMBO API WARNING: plugin %d added code for overridden"
                            "instruction (%p).\n", i, read_address);
          }
          if (ctx.replace) {
            if (cb_id == PRE_INST_C) {
              replaced = true;
            } else {
              fprintf(stderr, "MAMBO API WARNING: plugin %d set replace_inst for "
                              "a disallowed event (at %p).\n", i, read_address);
            }
          }
          write_p = ctx.write_p;
          arm_check_free_space(thread_data, &write_p, &data_p, MIN_FSPACE);
        } else {
          assert(ctx.write_p == write_p);
        }
      }
    }

    *o_write_p = write_p;
    *o_data_p = data_p;
  }
#endif
  return replaced;
}

size_t scan_arm(dbm_thread *thread_data, uint32_t *read_address, int basic_block, cc_type type, uint32_t *write_p) {
  bool stop = false;
  
  uint32_t immediate;
  uint32_t rd;
  uint32_t rd2;
  uint32_t rn;
  uint32_t rm;
  uint32_t offset;
  uint32_t prepostindex;
  uint32_t updown;
  uint32_t writeback;
  uint32_t operand2;
  uint32_t registers;
  uint32_t psr;
  uint32_t readonly;
  uint32_t set_flags;
  uint32_t d;
  uint32_t vd;
  uint32_t opcode;
  uint32_t p;
  uint32_t opc1;
  uint32_t opc2;
  uint32_t crn;
  uint32_t crm;
  uint32_t coproc;
  uint32_t load_store;
  uint32_t imm4h;
  uint32_t imm4l;
  uint32_t size;
  uint32_t h;
  uint32_t rs;
  uint32_t accumulate;
  uint32_t crd;
  uint32_t rdhi;
  uint32_t rdlo;
  uint32_t opcode2;
  uint32_t setting;
  uint32_t opcode3;
  uint32_t opcode4;
  uint32_t params;
  uint32_t link;
  uint32_t rotate;
  uint32_t vn;
  uint32_t n;
  uint32_t vm;
  uint32_t m;
  uint32_t mask;
  uint32_t u;
  
  uint32_t *scratch_data;
  uint32_t scratch_offset;
  uint32_t condition_code;
  uint32_t scratch_reg;
  
  int32_t  branch_offset;
  uint32_t target;
  uint32_t return_addr;
  uint32_t *tr_start;
  
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

#ifdef DBM_TRACES
  branch_type bb_type;
  pass1_arm(thread_data, read_address, &bb_type);
  
  if (type == mambo_bb && bb_type == cond_imm_arm) {
    arm_push_regs((1 << r0) | (1 << r1) | (1 << r2) | (1 << lr));

    arm_copy_to_reg_32bit(&write_p, r0, basic_block);

    arm_bl32_helper(write_p, thread_data->trace_head_incr_addr-5, AL);
    write_p++;
  }
#endif
  
  while(!stop) {
    debug("arm scan read_address: %p\n", read_address);
    arm_instruction inst = arm_decode(read_address);
    debug("Instruction enum: %d\n", (inst == ARM_INVALID) ? -1 : inst);
    
    debug("instruction word: 0x%x\n", *read_address); 

#ifdef PLUGINS_NEW
    bool skip_inst = arm_scanner_deliver_callbacks(thread_data, PRE_INST_C, read_address, inst,
                                                   &write_p, &data_p, basic_block, type, true);
    if (!skip_inst) {
#endif

    switch(inst) {
      case ARM_B:
      case ARM_BL:
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
          read_address = (uint32_t *)target - 1; // read_address is incremented this iteration
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

        arm_branch_save_context(thread_data, &write_p);
        arm_branch_jump(thread_data, &write_p, basic_block, offset, read_address, condition_code, SETUP|REPLACE_TARGET|INSERT_BRANCH);
        stop = true;

        break;
      case ARM_BX:
      case ARM_BLX:
        arm_bx_t_decode_fields(read_address, &link, &rn);
        assert(rn != pc);

#ifdef LINK_BX_ALT
        if ((*read_address >> 28) != AL) {
          debug("w: %p, r: %p, bb: %d\n", write_p, read_address, basic_block);
          target = lookup_or_stub(thread_data, (uint32_t)read_address + 4);
          debug("stub: %p\n", target);
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
        thread_data->code_cache_meta[basic_block].rn = rn;
        
#ifdef DBM_INLINE_HASH
  #ifndef LINK_BX_ALT
        assert(0);
  #endif

          arm_check_free_space(thread_data, &write_p, &data_p,
                               (uint32_t)end_of_inline_hash_lookup - (uint32_t)inline_hash_lookup+4);

          mambo_memcpy(write_p, inline_hash_lookup, (uint32_t)end_of_inline_hash_lookup - (uint32_t)inline_hash_lookup);

          write_p += ((uint32_t)inline_hash_lookup_get_addr - (uint32_t)inline_hash_lookup)/4;
          arm_mov (&write_p, REG_PROC, 0, r0, rn);
          write_p += ((uint32_t)end_of_inline_hash_lookup - (uint32_t)inline_hash_lookup_get_addr)/4;
          
          *(uint32_t *)((uint32_t)write_p - 4) = basic_block;
          *(uint32_t *)((uint32_t)write_p - 12) = (uint32_t)thread_data->entry_address.entries;
          *(uint32_t *)((uint32_t)write_p - 16) = (uint32_t)thread_data->scratch_regs;
          *(uint32_t *)((uint32_t)write_p - 20) = thread_data->dispatcher_addr;
#endif // DBM_INLINE_HASH

#if !defined(DBM_INLINE_HASH)
          arm_branch_save_context(thread_data, &write_p);

          arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), SETUP);

          // Branch taken (not taken MOV is inserted by arm_branch_jump(SETUP))
          arm_mov_cond(&write_p, (*read_address >> 28), REG_PROC, false, r0, rn);
          write_p++;

          arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), INSERT_BRANCH);
#endif
        stop = true;
        
        break;
      
      case ARM_BLXI:
        arm_blxi_decode_fields(read_address, &h, &offset);
        
        branch_offset = ((h << 1) | (offset << 2)) + 1;
        if (branch_offset & 0x2000000) { branch_offset |= 0xFC000000; }

        arm_copy_to_reg_32bit(&write_p, lr, (uint32_t)read_address + 4);
        
        thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_blxi_arm;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = (uint16_t *)write_p;
        
        arm_branch_save_context(thread_data, &write_p);
        arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), SETUP);
        
        arm_copy_to_reg_32bit(&write_p, r0, (uint32_t)read_address + 8 + branch_offset);
        
        arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), INSERT_BRANCH);
        stop = true;
        
        break;
      
      case ARM_ADC:
      case ARM_ADD:
      case ARM_EOR:
      case ARM_MOV:
      case ARM_ORR:
      case ARM_SBC:
      case ARM_SUB:
      case ARM_RSC:
        arm_data_proc_decode_fields(read_address, &immediate, &opcode, &set_flags, &rd, &rn, &operand2);
        //arm_add_decode_fields(read_address, &immediate, &rd, &rn, &operand2);
        rm = 16;
        
        if(rd != pc && rn != pc && (immediate == IMM_PROC || (operand2 & 0xF) != pc)) {
          copy_arm();
        } else {
          if (immediate == REG_PROC) {
            rm = operand2 & 0xF;
          }
          if (rd == pc) {
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
            assert(set_flags == 0 && !(rn == pc && immediate == REG_PROC && ((operand2 & 0xF) == pc)));

            arm_check_free_space(thread_data, &write_p, &data_p,
                                 (uint32_t)end_of_inline_hash_lookup - (uint32_t)inline_hash_lookup+4);

            if (rn == pc || (immediate == REG_PROC && (operand2 & 0xF) == pc)) {
              mambo_memcpy(write_p, inline_hash_lookup, 4*4);
              write_p++;
              *write_p += 8; // adjust offset to scratch_reg_ptr
              write_p += 3;
              mambo_memcpy(write_p+2, inline_hash_lookup+4*4, (uint32_t)end_of_inline_hash_lookup - (uint32_t)inline_hash_lookup - 4*4);
            } else {
              mambo_memcpy(write_p, inline_hash_lookup, (uint32_t)end_of_inline_hash_lookup - (uint32_t)inline_hash_lookup);
              write_p += ((uint32_t)inline_hash_lookup_get_addr - (uint32_t)inline_hash_lookup)/4;
            }

            if (rn == pc || (immediate == REG_PROC && ((operand2 & 0xF) == pc))) {
              arm_copy_to_reg_32bit(&write_p, r0, (uint32_t)read_address + 8);

              if (rn == pc) {
                rn = r0;
              } else { // (immediate = REG_PROC && (operand2 & 0xF) == pc)
                operand2 = operand2 & (~0xF) | r0;
              }
            }

            arm_data_proc_cond(&write_p, (*read_address >> 28), immediate, opcode, set_flags, r0, rn, operand2);
            write_p += ((uint32_t)end_of_inline_hash_lookup - (uint32_t)inline_hash_lookup_get_addr)/4;

            *(uint32_t *)((uint32_t)write_p - 4) = basic_block;
            *(uint32_t *)((uint32_t)write_p - 12) = (uint32_t)thread_data->entry_address.entries;
            *(uint32_t *)((uint32_t)write_p - 16) = (uint32_t)thread_data->scratch_regs;
            *(uint32_t *)((uint32_t)write_p - 20) = thread_data->dispatcher_addr;

            stop = true;
            break;
#endif
            /* This is an indirect branch */
            arm_branch_save_context(thread_data, &write_p);
            
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

          if (inst != ARM_MOV || set_flags == 1) {
            arm_data_proc_cond(&write_p, (*read_address >> 28), immediate, opcode, set_flags,
                          (rd == pc) ? r0 : rd, (rn == pc) ? scratch_reg : rn, (rm == pc) ? (scratch_reg | (operand2 & 0xFF0)) : operand2);
            write_p++;
          }

          // Restore the value of the scratch register
          if ((rn == pc || rm == pc) && rd != pc && scratch_reg != rd) {
            arm_cond_pop_reg(*read_address >> 28, scratch_reg);
          }

          if (rd == pc) {
            arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), INSERT_BRANCH);
            stop = true;
          }
            
          if (rd != pc && ((*read_address >> 28) != AL)) {
            fprintf(stderr, "Untested conditional ARM_ADD, etc\n");
            while(1);
          }
        }
        
        break;
      case ARM_AND:
        arm_and_decode_fields(read_address, &immediate, &set_flags, &rd, &rn, &operand2);
        assert(rd != pc && rn != pc);
        if (immediate == 0) assert((operand2 & 0xF) != pc);
        copy_arm();
        break;
      
      case ARM_BIC:
        arm_bic_decode_fields(read_address, &immediate, &set_flags, &rd, &rn, &operand2);
        assert(rd != pc && rn != pc);
        if (immediate == 0) assert((operand2 & 0xF) != pc);
        copy_arm();
        break;
        
      case ARM_CMN:
        arm_cmn_decode_fields(read_address, &immediate, &rn, &operand2);
        assert(rn != pc);
        if (immediate == 0) assert((operand2 & 0xF) != pc);
        
        copy_arm();
        break;
      case ARM_CMP:
        arm_cmp_decode_fields(read_address, &immediate, &rn, &operand2);

        assert(rn != pc);
        if (immediate == 0) assert((operand2 & 0xF) != pc);        
        copy_arm();

        break;

      case ARM_MOVW:
      case ARM_MOVT:
        arm_data_proc_decode_fields(read_address, &immediate, &opcode, &set_flags, &rd, &rn, &operand2);

        // Rn is actually the top 4 bits of the immediate value
        assert(rd != pc);
        copy_arm();
        break;

      case ARM_MVN:
        arm_mvn_decode_fields(read_address, &immediate, &set_flags, &rd, &operand2);
        assert(rd != pc);
        if (immediate == REG_PROC) assert((operand2 & 0xF) != pc);
        
        copy_arm();
        break;

      case ARM_RSB:
        arm_rsb_decode_fields(read_address, &immediate, &set_flags, &rd, &rn, &operand2);
        
        assert(rd != pc && rn != pc);
        if (immediate == 0) assert((operand2 & 0xF) != pc);
        copy_arm();
        
        break;

      case ARM_TEQ:
        arm_teq_decode_fields(read_address, &immediate, &rn, &operand2);
        assert(rn != pc);
        if (immediate == r0) assert((operand2 & 0xF) != pc);
        
        copy_arm();
        
        break;
      case ARM_TST:
        arm_tst_decode_fields(read_address, &immediate, &rn, &operand2);
        assert(rn != pc);
        if (immediate == 0) assert((operand2 & 0xF) != pc);
        copy_arm();
        break;
        
      case ARM_NOP:
        copy_arm();
        break;

      case ARM_MUL:
      case ARM_MLA:
        arm_multiply_decode_fields(read_address, &accumulate, &set_flags, &rd, &rm, &rs, &rn);
        
        assert(rd != pc && rm != pc && rs != pc && rn != pc);
        copy_arm();
        
        break;

      case ARM_LDRB:
      case ARM_LDR:
        switch (inst) {
          case ARM_LDRB:
            arm_ldrb_decode_fields(read_address, &immediate, &rd, &rn, &offset, &prepostindex, &updown, &writeback);
            break;
          case ARM_LDR:
            arm_ldr_decode_fields(read_address, &immediate, &rd, &rn, &offset, &prepostindex, &updown, &writeback);
            break;
        }
        if (immediate == 1) assert((offset & 0xF) != pc);
        
        condition_code = *read_address & 0xF0000000;
        if (rd == pc || rn == pc) {
          if (rd == pc) {
            thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_arm;
            thread_data->code_cache_meta[basic_block].exit_branch_addr = (uint16_t *)write_p;
          
            arm_branch_save_context(thread_data, &write_p);
            
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
            
          if (rd != pc) {
            arm_cond_pop_reg(condition_code >> 28, scratch_reg);
          } else {
            arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), INSERT_BRANCH);

            stop = true;
          }
        } else {
          copy_arm();
        }
        break;
        
      case ARM_STRB:
      case ARM_STR:
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
        
      case ARM_LDRH:
      case ARM_STRH:
      case ARM_LDRD:
      case ARM_STRD:
        arm_h_data_transfer_decode_fields(read_address, &opcode, &size, &opcode2, &immediate, &rd, &rn, &rm, &imm4h, &prepostindex, &updown, &writeback);
        
        assert(rd != pc && rn != pc);
        if (immediate == REG_PROC) assert(rm != pc);
        
        copy_arm();
        
        break;

      case ARM_LDREX:
      case ARM_STREX:
        arm_h_data_transfer_decode_fields(read_address, &opcode, &size, &opcode2, &immediate, &rd, &rn, &rm, &imm4h, &prepostindex, &updown, &writeback);

        if (inst == ARM_LDREX) {
          assert(rd != pc && rn != pc);
        } else {
          assert(rd != pc && rn != pc && rm != pc);
        }
        copy_arm();

        break;
        
      case ARM_LDRSHI:
        arm_h_data_transfer_decode_fields(read_address, &opcode, &size, &opcode2, &immediate, &rd, &rn, &imm4l, &imm4h, &prepostindex, &updown, &writeback);

        assert(rd != pc && rn != pc); // rm field is actually imm4l

        break;

      case ARM_REV:
      case ARM_CLZ:
        arm_h_data_transfer_decode_fields(read_address, &opcode, &size, &opcode2, &immediate, &rd, &rn, &rm, &imm4h, &prepostindex, &updown, &writeback);
        
        assert(rd != pc && rm != pc);
        
        copy_arm();
        
        break;
        
      case ARM_LDM:
        arm_ldm_decode_fields(read_address, &rn, &registers, &prepostindex, &updown, &writeback, &psr);

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

          if (registers & 0x7FFF) {
            arm_ldm_cond(&write_p, (condition_code >> 28), rn, registers & 0x7FFF, prepostindex, updown, writeback, psr);
            write_p++;
          }
          
          thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_arm;
          thread_data->code_cache_meta[basic_block].exit_branch_addr = (uint16_t *)write_p;

#ifdef DBM_INLINE_HASH
            arm_check_free_space(thread_data, &write_p, &data_p,
                                 (uint32_t)end_of_inline_hash_lookup - (uint32_t)inline_hash_lookup+4);

            mambo_memcpy(write_p, inline_hash_lookup, (uint32_t)end_of_inline_hash_lookup - (uint32_t)inline_hash_lookup);

            write_p += ((uint32_t)inline_hash_lookup_get_addr - (uint32_t)inline_hash_lookup)/4;
            arm_ldm_cond(&write_p, (*read_address >> 28), rn, (1 << r0), prepostindex, updown, writeback, psr);
            write_p += ((uint32_t)end_of_inline_hash_lookup - (uint32_t)inline_hash_lookup_get_addr)/4;

            *(uint32_t *)((uint32_t)write_p - 4) = basic_block;
            *(uint32_t *)((uint32_t)write_p - 12) = (uint32_t)thread_data->entry_address.entries;
            *(uint32_t *)((uint32_t)write_p - 16) = (uint32_t)thread_data->scratch_regs;
            *(uint32_t *)((uint32_t)write_p - 20) = thread_data->dispatcher_addr;
#endif

#if !defined(DBM_INLINE_HASH)
            arm_branch_save_context(thread_data, &write_p);
            arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), SETUP);

            // Branch taken
            arm_ldm_cond(&write_p, (*read_address >> 28), rn, (1 << r0), prepostindex, updown, writeback, psr);
            write_p++;

            arm_branch_jump(thread_data, &write_p, basic_block, 0, read_address, (*read_address >> 28), INSERT_BRANCH);
#endif
          stop = true;
        }
        
        break;
      case ARM_STM:
        arm_stm_decode_fields(read_address, &rn, &registers, &prepostindex, &updown, &writeback, &psr);
        assert(rn != pc);
        
        if (registers & (1 << pc)) {
          condition_code = (*read_address >> 28);
          if (condition_code != AL) {
            tr_start = write_p;
            write_p++;
          }

          arm_add_sub_32_bit(&write_p, rn, rn, updown ? 4 : -4);
          registers &= ~(1 << pc);
          assert(registers);
          arm_stm(&write_p, rn, registers, prepostindex, updown, writeback, psr);
          write_p++;

          scratch_reg = next_reg_in_list(registers, 0);
          assert(scratch_reg < pc && scratch_reg != rn);
          arm_copy_to_reg_32bit(&write_p, scratch_reg, (uint32_t)read_address + 8);
          if (writeback) {
            offset = count_bits(registers) << 2;
          }
          if (!prepostindex) {
            offset -= 4;
          }
          arm_str(&write_p, IMM_LDR, scratch_reg, rn, offset, 1, 1, 0);
          write_p++;
          arm_ldr(&write_p, IMM_LDR, scratch_reg, rn, prepostindex ? 0 : 4, 1, updown ? 0 : 1, 0);
          write_p++;

          while (!writeback || !prepostindex || updown); // implement this

          if (condition_code != AL) {
            arm_b32_helper(tr_start, (uint32_t)write_p, arm_inverse_cond_code[condition_code]);
          }
        } else {
          copy_arm();
        }
        
        break;
      case ARM_SVC:
        condition_code = (*read_address >> 28) & 0xF;

        if (condition_code != AL) {
          tr_start = write_p;
          write_p++;
        }

        arm_push_reg(r0);

        arm_copy_to_reg_32bit(&write_p, r0, (uint32_t)thread_data->scratch_regs);
        arm_stm(&write_p, r0, (1 << r8) | (1 << r9) | (1 << r14), 0, 1, 0, 0);
        write_p++;

        arm_mov(&write_p, REG_PROC, 0, r9, r0);
        write_p++;

        arm_pop_reg(r0);

        arm_copy_to_reg_32bit(&write_p, r8, (uint32_t)read_address + 4);

        arm_bl(&write_p, (thread_data->syscall_wrapper_addr - (uint32_t)write_p - 8) >> 2);
        write_p++;

        if (condition_code != AL) {
          arm_b32_helper(tr_start, (uint32_t)write_p, condition_code);
        }

        break;
      case ARM_PLDI:
        arm_pldi_decode_fields(read_address, &updown, &readonly, &rn, &offset);

        if (rn == pc) {
          /* The cost of obtaining a scratch register and copying the source PC
             is *probably* too high to be worth translating this. */
          break;
        }
        copy_arm();

        break;
        
      case ARM_PLD:
        arm_pld_decode_fields(read_address, &updown, &readonly, &rn, &offset);
        rm = offset & 0xF;
        assert(rn != pc && rm != pc);
        copy_arm();

        break;

      case ARM_PLII:
        /* Discard instruction preload hints, since they would otherwise only pollute our icache */
        break;

      case ARM_VSTM_D:
      case ARM_VSTM_S:
      case ARM_VLDM_S:
      case ARM_VLDM_D:
      case ARM_VSTR_D:
      case ARM_VSTR_S:
      case ARM_VLDR_D:
      case ARM_VLDR_S:
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
        
      case ARM_STC:
        arm_vfp_ldm_stm_decode_fields(read_address, &p, &updown, &d, &writeback, &load_store, &rn, &vd, &opcode, &immediate);
        assert(rn != pc);
        copy_arm();
        
        break;
        
      case ARM_MRC:
      case ARM_MCR:
        arm_coproc_trans_decode_fields(read_address, &opc1, &load_store, &crn, &rd, &coproc, &opc2, &crm);
        
        // thread id
        if (coproc == 15 && opc1 == 0 && crn == 13 && crm == 0 && opc2 == 3 && load_store == 1 && rd != pc) {
          assert((((uint32_t)*read_address) >> 28) == AL);
          arm_copy_to_reg_32bit(&write_p, rd, (uint32_t)(&thread_data->tls));
          arm_ldr(&write_p, IMM_LDR, rd, rd, 0, 1, 1, 0);
          write_p++;
        // NEON / FP VMRS/VMSR
        } else if (coproc == 10 && opc1 == 7 && crn == 1 && rd != pc) {
          copy_arm();
        // Performance counter
        // This is used in OpenSSL in OPENSSL_cpuid_setup, a constructor. WTF
        } else if (coproc == 15 && opc1 == 0 && crn == 9 && crm == 13 && opc2 == 0 && load_store == 1 && rd != pc) {
          copy_arm();
        } else {
          fprintf(stderr, "unknown coproc: %d %d %d %d %d %d\n", opc1, crn, rd, coproc, opc2, crm);
          while(1);
        }
        
        break;
        
      case ARM_CDP:
        arm_coproc_dp_decode_fields(read_address, &opc1, &crn, &crd, &coproc, &opc2, &crm);
        
        copy_arm();
        
        fprintf(stderr, "Untested CDP\n");
        while(1);
        
        break;
        
      case ARM_UMLAL:
      case ARM_UMULL:
      case ARM_SMULL:
      case ARM_SMLAL:
        arm_dsp_long_res_decode_fields(read_address, &opcode, &set_flags, &rdhi, &rdlo, &rm, &opcode2, &setting, &rn);
        
        assert(rdhi != pc && rdlo != pc && rm != pc && rn != pc);
        
        copy_arm();
        
        break;
        
      case ARM_VMULI:
      case ARM_VMULLI:
      case ARM_VRADDHN:
      case ARM_VQADD:
      case ARM_VORR:
      case ARM_VSUBI:
      case ARM_VQDMULHS:
      case ARM_VADDI:
      case ARM_VMLSL_S:
      case ARM_VMLAL_S:
      case ARM_VMULL_S:
        copy_arm(); // no access to general purpose registers
        break;
        
      case ARM_VLDX_M:
      case ARM_VLDX_S_O:
      case ARM_VLDX_S_A:
      case ARM_VSTX_M:
      case ARM_VSTX_S_O:
        arm_v_trans_mult_decode_fields(read_address, &opcode, &opcode2, &opcode3, &opcode4, &params, &d, &vd, &rn, &rm);
        
        assert(rn != pc); // rm is guaranteed not to be pc
        copy_arm();
        
        break;
        
      case ARM_VUZP:
      case ARM_VZIP:
      case ARM_VMVN:
      case ARM_VTRN:
      case ARM_VSWP:
      case ARM_VQMOVUN:
      	copy_arm();
      	break;
        
      case ARM_VRSHR:
      case ARM_VRSHRN:
      case ARM_VSLI:
      case ARM_VRSRA:
      case ARM_VSHLI:
      case ARM_VSHLL:
      case ARM_VSHRN:
      case ARM_VSRI:
        copy_arm(); // doesn't involve general purpose registers
        break;

      case ARM_VMOVI_I:
        copy_arm();
        break;

      case ARM_VMOV_F:
      case ARM_VCVT_F:
      case ARM_VCMP:
      case ARM_VCMPE:
      case ARM_VCMP_ZERO:
      case ARM_VCMPE_ZERO:
        copy_arm();
        break;
        
      case ARM_MRS:
        arm_mrs_decode_fields(read_address, &rd);
        
        assert(rd != pc);
        copy_arm();
        
        break;

      case ARM_MSR:
        arm_msr_decode_fields(read_address, &rn, &mask);

        assert(rn != pc);
        copy_arm();

        break;

      case ARM_MSRI:
        copy_arm();
        break;

      case ARM_UDIV:
      case ARM_SDIV:
        arm_divide_decode_fields(read_address, &opcode, &rd, &rn, &rm);

        assert(rd != pc && rn != pc && rm != pc);
        copy_arm();

        break;

      case ARM_DMB:
        copy_arm();
        break;
        
      case ARM_UXTB:
      case ARM_UXTB16:
      case ARM_UXTH:
        arm_extend_decode_fields(read_address, &opcode, &rd, &rn, &rm, &rotate);

        // if rn == pc, it's the version without add which doesn't use pc
        assert(rd != pc && rm != pc);
        copy_arm();

        break;

      case ARM_VMUL_F32:
      case ARM_VMUL_F64:
      case ARM_VMLS_F64:
      case ARM_VMLA_F32:
      case ARM_VMLA_F64:
        copy_arm();
        break;

      case ARM_VMOV_ARM_S:
        arm_vmov_arm_s_decode_fields(read_address, &opcode, &vn, &rd, &n);

        assert(rd != pc);
        copy_arm();

        break;

      case ARM_VMOV_SCAL_ARM:
        arm_vmov_scal_arm_decode_fields(read_address, &opc1, &opc2, &d, &vd, &rd);

        assert(rd != pc);
        copy_arm();

        break;

      case ARM_VMOV_ARM_SCAL:
        arm_vmov_arm_scal_decode_fields(read_address, &u, &opc1, &opc2, &rd, &n, &vn);

        assert(rd != pc);
        copy_arm();

        break;

      case ARM_VMOVI_F32:
      case ARM_VMOVI_F64:
      case ARM_VMOVI_D:
      case ARM_VMOVI_Q:
        copy_arm();
        break;

      case ARM_VMRS:
        copy_arm();
        break;
        
      case ARM_VMOV_2ARM_D:
        arm_vmov_2arm_d_decode_fields(read_address, &opcode, &rd2, &rd, &m, &vm);
        
        assert(rd != pc && rd2 != pc);
        copy_arm();
        
        break;

      case ARM_VREV:
      case ARM_VPADD:
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

    if (!stop) arm_check_free_space(thread_data, &write_p, &data_p, MIN_FSPACE);

#ifdef PLUGINS_NEW
    arm_scanner_deliver_callbacks(thread_data, POST_INST_C, read_address, inst, &write_p, &data_p, basic_block, type, !stop);
#endif

    debug("write_p: %p\n", write_p);

    read_address++;
    debug("\n");
  }

  // We haven't strictly enforced updating write_p after the last instruction
  return ((uint32_t)write_p - start_address + 4);
}

void arm_encode_stub_bb(dbm_thread *thread_data, int basic_block, uint32_t target) {
  uint32_t *write_p = (uint32_t *)&thread_data->code_cache->blocks[basic_block];
  uint32_t *data_p = (uint32_t *)write_p;
  data_p += BASIC_BLOCK_SIZE;

  debug("Stub BB: %p\n", write_p);
  debug("ARM stub target: 0x%x\n", target);

  arm_branch_save_context(thread_data, &write_p);
  arm_branch_jump(thread_data, &write_p, basic_block, 0, (uint32_t *)(target - 8), AL, SETUP|REPLACE_TARGET|INSERT_BRANCH);
}

