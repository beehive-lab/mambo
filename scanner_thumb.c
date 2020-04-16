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

#ifdef __arm__
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <limits.h>
#include <string.h>

#include "dbm.h"
#include "common.h"
#include "scanner_common.h"

#include "pie/pie-thumb-decoder.h"
#include "pie/pie-thumb-encoder.h"
#include "pie/pie-thumb-field-decoder.h"

#include "pie/pie-arm-decoder.h"
#include "pie/pie-arm-encoder.h"
#include "pie/pie-arm-field-decoder.h"

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

#define MIN_FSPACE (60)
#define IHL_FSPACE (76)

#define copy_thumb_16() *(write_p++) = *read_address;
#define copy_thumb_32() *(write_p++) = *read_address;\
        *(write_p++) = *(read_address + 1)

#define get_original_pc() (((uint32_t)read_address + 4) & 0xFFFFFFFC)
  
#define modify_in_it_pre(skip_size) \
  if (it_state.cond_inst_after_it > 0) { \
          debug("LDR_PC_16 in IT block\n"); \
          if (write_p == it_state.it_inst_addr + 1) { \
            write_p--; \
          } else { \
            debug("LDR_PC_16 in middle of IT block\n"); \
            int inst_to_keep = it_get_no_of_inst(it_state.it_initial_mask) - it_state.cond_inst_after_it; \
            debug("inst to keep in pre: %d\n", inst_to_keep);\
            switch (inst_to_keep) { \
              case 1: \
                it_state.it_initial_mask = 0x8; \
                break; \
              case 2: \
                it_state.it_initial_mask = it_state.it_initial_mask & 0x8 | 0x4; \
                break; \
              case 3: \
                it_state.it_initial_mask = it_state.it_initial_mask & 0xc | 0x2; \
                break; \
              case 4: \
                it_state.it_initial_mask = it_state.it_initial_mask & 0xe | 0x1; \
                break; \
              default: \
                fprintf(stderr, "check me\n"); \
                while(1); \
            } \
            debug("inst to keep: %d\n", inst_to_keep); \
            thumb_it16 (&it_state.it_inst_addr, it_state.it_cond, it_state.it_initial_mask); \
          } \
          /* Encode as: \
             B OP_COND +5 \
             STUFF \
             IT samecond, len -1*/ \
          bool same_cond = (((it_state.it_mask >> 5) & 0x1) == (it_state.it_cond & 1)); \
          debug("it_mask: 0x%x, it_cond: %d, same_cond: %d\n", it_state.it_mask, it_state.it_cond, same_cond); \
          thumb_cond_branch_16 (&write_p, same_cond ? arm_inverse_cond_code[it_state.it_cond] : it_state.it_cond, skip_size); \
          write_p++; \
        }

#define modify_in_it_post() \
  /* Insert IT after the translated instruction */\
        if (it_state.cond_inst_after_it > 1) { \
          debug("cond inst following: %d\n", it_state.cond_inst_after_it-1); \
          it_state.it_initial_mask = it_state.it_mask & 0xF; \
          bool same_cond = (((it_state.it_mask >> 4) & 0x1) == (it_state.it_cond & 1)); \
          if (!same_cond) { \
            assert(it_state.it_cond < 14); \
            switch (it_state.cond_inst_after_it-1) { \
              case 3: \
                it_state.it_initial_mask = it_state.it_initial_mask & 0xC | 0x2; \
                break; \
              case 2: \
                it_state.it_initial_mask = it_state.it_initial_mask & 0x8 | 0x4; \
                break; \
              case 1:  \
                it_state.it_initial_mask = it_state.it_initial_mask & 0x0 | 0x8; \
                break; \
            } \
            it_state.it_cond = arm_inverse_cond_code[it_state.it_cond]; \
          } \
          thumb_it16 (&write_p,	it_state.it_cond, it_state.it_initial_mask); \
          it_state.it_inst_addr = write_p; \
          write_p++; \
        }

typedef struct {
  int cond_inst_after_it;
  uint16_t *it_inst_addr;
  uint32_t it_cond;
  uint32_t it_mask;
  uint32_t it_initial_mask;
  bool is_overwritten;
} thumb_it_state;

int it_get_no_of_inst(uint32_t mask) {
  int cond_inst_after_it = 1;

  if (mask & 1) {
    cond_inst_after_it = 4;
  } else if (mask & 2) {
    cond_inst_after_it = 3;
  } else if (mask & 4) {
    cond_inst_after_it = 2;
  }
  return cond_inst_after_it;
}

void it_clip_len(uint16_t *write_p, uint32_t cond, uint32_t mask, int it_len) {
  switch (it_len) {
    case 1:
      mask = 0x8;
      break;
    case 2:
      mask = mask & 0x8 | 0x4;
      break;
    case 3:
      mask = mask & 0xc | 0x2;
      break;
    case 4:
      mask = mask & 0xe | 0x1;
      break;
    default:
      fprintf(stderr, "check me\n");
      while(1);
  }

  thumb_it16 (&write_p, cond, mask);
}

void it_clip_from_offset(uint16_t *write_p, uint32_t *cond, uint32_t *mask, int offset) {
  int initial_len = it_get_no_of_inst(*mask);
  while (offset < 0 || offset >= initial_len);
  assert(offset >= 0 && offset < initial_len);

  if (offset > 0) {
    /* The first condition in the IT block always executes when the condition is true. If the
       instruction at the new offset has the opposite condition, switch the block to the opposite
       condition, which also flips the 'then'/'else' flags for each subsequent instruction. */
    bool same_cond = ((*mask >> (4 - offset)) & 1) == ((*cond) & 1);
    if (!same_cond) {
     *cond = arm_inverse_cond_code[*cond];
    }
    *mask = (*mask << offset) & 0xF;
  }

  thumb_it16 (&write_p, *cond, *mask);
}

bool create_it_gap(uint16_t **write_p, thumb_it_state *it_state) {
  if (it_state->cond_inst_after_it > 0 && it_state->is_overwritten == false) {
    if ((it_get_no_of_inst(it_state->it_initial_mask) - it_state->cond_inst_after_it) > 0) {
      it_clip_len(it_state->it_inst_addr, it_state->it_cond, it_state->it_initial_mask,
                  it_get_no_of_inst(it_state->it_initial_mask) - it_state->cond_inst_after_it);
    } else {
      assert(it_state->it_inst_addr == *write_p - 1);
      *write_p = it_state->it_inst_addr;
      it_state->is_overwritten = true;
    }
    return true;
  }
  return false;
}

bool close_it_gap(uint16_t **write_p, thumb_it_state *it_state) {
  if (it_state->cond_inst_after_it > 0) {
    it_clip_from_offset(*write_p, &it_state->it_cond, &it_state->it_initial_mask,
                        it_get_no_of_inst(it_state->it_initial_mask) - it_state->cond_inst_after_it);
    it_state->it_inst_addr = *write_p;
    it_state->is_overwritten = false;
    *write_p += 1;
    return true;
  }
  return false;
}

void thumb_check_free_space(dbm_thread *thread_data, uint16_t **o_write_p, uint32_t **o_data_p,
                            thumb_it_state *it_state, bool handle_it, size_t size, int cur_block) {
  uint16_t *write_p = *o_write_p;
  uint32_t *data_p = *o_data_p;

  if ((uint16_t *)data_p <= (write_p + 2)) {
    fprintf(stderr, "Thumb fragment overflowed: limit %p, write_p: %p\n", data_p, write_p);
    while(1);
  }
  if ((((uint32_t)write_p + size) >= (uint32_t)data_p)) {
    int new_block = allocate_bb(thread_data);
    thread_data->code_cache_meta[new_block].actual_id = cur_block;

    if ((uint32_t *)&thread_data->code_cache->blocks[new_block] != data_p) {
      if (handle_it && it_state->cond_inst_after_it > 0) {
        create_it_gap(&write_p, it_state);
      }

      thumb_b32_helper(write_p, (uint32_t)&thread_data->code_cache->blocks[new_block]);
      write_p = (uint16_t *)&thread_data->code_cache->blocks[new_block];

      if (handle_it && it_state->cond_inst_after_it > 0) {
        close_it_gap(&write_p, it_state);
      }
    }
    data_p = (uint32_t *)&thread_data->code_cache->blocks[new_block + 1];
  }

  *o_write_p = write_p;
  *o_data_p = data_p;
}

void copy_to_reg_16bit(uint16_t **write_p, enum reg reg, uint32_t value) {
  thumb_movwi32 (write_p, (value >> 11) & 0x1, (value >> 12) & 0xF, (value >> 8) & 0x7, reg, (value >> 0) & 0xFF);
  *write_p += 2;
}

void copy_to_reg_32bit(uint16_t **write_p, enum reg reg, uint32_t value) {
  thumb_movwi32 (write_p, (value >> 11) & 0x1, (value >> 12) & 0xF, (value >> 8) & 0x7, reg, (value >> 0) & 0xFF);
  *write_p += 2;
  thumb_movti32 (write_p, (value >> 27) & 0x1, (value >> 28) & 0xF, (value >> 24) & 0x7, reg, (value >> 16) & 0xFF);
  *write_p += 2;
}

void thumb_push_regs(uint16_t **write_p, uint32_t regs) {
  if (regs & 0xFFFFA000 || regs == 0) {
    fprintf(stderr, "Trying to push invalid reglist\n");
    while(1);
  } else if (regs & 0xBF00) {
    thumb_stmfd32(write_p, 1, sp, regs);
    *write_p += 2;
  } else {
    if (regs & (1 << lr)) {
      regs &= 0xFF;
      regs |= (1 << 8);
    }
    thumb_push16(write_p, regs);
    *write_p += 1;
  }
}

void thumb_pop_regs(uint16_t **write_p, uint32_t regs) {
  if (regs & 0xFFFFA000 || regs == 0) {
    fprintf(stderr, "Trying to pop invalid reglist\n");
    while(1);
  } else if (regs & 0x7F00) {
    thumb_ldmfd32(write_p, 1, sp, regs);
    *write_p += 2;
  } else {
    if (regs & (1 << pc)) {
      regs &= 0xFF;
      regs |= (1 << 8);
    }
    thumb_pop16(write_p, regs);
    *write_p += 1;
  }
}
  
enum arm_cond_codes arm_inverse_cond_code[] = {NE, EQ, CC, CS, PL, MI, VC, VS, LS, HI, LT, GE, LE, GT, AL, AL};

void thumb_b_bl_helper(uint16_t *write_p, uint32_t dest_addr, bool link, bool to_arm) {
  int difference = dest_addr - ((uint32_t)write_p & (to_arm ? ~2 : ~0)) - 4;

  if (difference < -(16*1024*1024) || difference >= (16*1024*1024)) {
    fprintf(stderr, "Branch out of range\n");
    while(1);
  }
  uint32_t sign_bit = (difference & 0x80000000) ? 1 : 0;
  uint32_t i1 = ~((difference >> 23) ^ sign_bit) & 0x1;
  uint32_t i2 = ~((difference >> 22) ^ sign_bit) & 0x1;
  uint32_t offset_high = (difference >> 12) & 0x3FF;
  uint32_t offset_low = (difference >> 1) & 0x7FF;
  if (link) {
    if (to_arm) {
      thumb_bl_arm32 (&write_p, sign_bit, offset_high, i1, i2, offset_low);
    } else {
      thumb_bl32 (&write_p, sign_bit,	offset_high, i1, i2, offset_low);
    }
  } else {
    thumb_b32 (&write_p, sign_bit, offset_high, i1, i2, offset_low);
  }
}

void thumb_adjust_b_bl_target(dbm_thread *thread_data, uint16_t *write_p, uint32_t dest_addr) {
  thumb_instruction inst = thumb_decode(write_p);

  if (inst != THUMB_BL32 && inst != THUMB_BL_ARM32 && inst != THUMB_B32) {
    fprintf(stderr, "Thumb: Trying to adjust target of invalid branch instruction.\n");
    while(1);
  }

  if (inst == THUMB_BL32) {
    dest_addr -= 4;
  } else if (inst == THUMB_BL_ARM32) {
    dest_addr -= 8;
  }

  thumb_b_bl_helper(write_p, dest_addr, inst != THUMB_B32, inst == THUMB_BL_ARM32);
}

void thumb_b16_cond_helper(uint16_t *write_p, uint32_t dest_addr, mambo_cond cond) {
  int difference = dest_addr -(uint32_t)write_p - 4;
  assert(difference >= -256 && difference < 256);

  thumb_b_cond16(&write_p, cond, (difference >> 1) & 0xFF);
}

void thumb_b32_helper(uint16_t *write_p, uint32_t dest_addr) {
  thumb_b_bl_helper(write_p, dest_addr, false, false);
}

void thumb_cc_branch(dbm_thread *thread_data, uint16_t *write_p, uint32_t dest_addr) {
  thumb_b32_helper(write_p, dest_addr);

  record_cc_link(thread_data, (uint32_t)write_p|THUMB, dest_addr);
}

void thumb_bl32_helper(uint16_t *write_p, uint32_t dest_addr) {
  thumb_b_bl_helper(write_p, dest_addr, true, false);
}

void thumb_blx32_helper(uint16_t *write_p, uint32_t dest_addr) {
  thumb_b_bl_helper(write_p, dest_addr, true, true);
}

void thumb_b32_cond_helper(uint16_t **write_p, uint32_t dest_addr, enum arm_cond_codes condition) {
  int difference = dest_addr -(uint32_t)(*write_p) - 4;
  if (difference < -(1*1024*1024) || difference >= (1*1024*1024)) {
    assert(condition < 14);
    thumb_b_cond16(write_p, arm_inverse_cond_code[condition], 1);
    (*write_p)++;
    thumb_b32_helper(*write_p, dest_addr);
    (*write_p) += 2;
  } else {
    uint32_t sign_bit = (difference & 0x80000000) ? 1 : 0;
    uint32_t j2 = (difference >> 19) & 0x1;
    uint32_t j1 = (difference >> 18) & 0x1;
    uint32_t offset_high = (difference >> 12) & 0x3F;
    uint32_t offset_low = (difference >> 1) & 0x7FF;
    thumb_b_cond32 (write_p, sign_bit, condition, offset_high, j1, j2, offset_low);
    (*write_p) += 2;
  }
}

void thumb_b16_helper(uint16_t *write_p, uint32_t dest_addr, enum arm_cond_codes cond) {
  int difference = dest_addr -(uint32_t)write_p - 4;

  if (cond >= EQ && cond < AL) {
    // Use encoding T1 (conditional with 8b imm)
    assert(difference >= -256 && difference <= 254);
    thumb_b_cond16(&write_p, cond, (difference >> 1) & 0xFF);
    write_p++;
  } else if (cond == AL) {
    // Use encoding T2 (unconditional with 11b imm)
    assert(difference >= -2048 && difference <= 2046);
    thumb_b16(&write_p, (difference >> 1) & 0x7FF);
    write_p++;
    while(1); // Check me
  } else {
    fprintf(stderr, "Requested invalid B16 condition\n");
    while(1);
  }
}

int thumb_cbz_cbnz_helper(uint16_t *write_p, uint32_t target, enum reg reg, bool cbz) {
  int difference = target - (uintptr_t)write_p - 4;

  if (difference < 0 || difference >= 127) return -1;

  thumb_misc_cbz_16(&write_p, cbz ? 0 : 1, difference >> 6, difference >> 1, reg);

  return 0;
}

void thumb_cbz_helper(uint16_t *write_p, uint32_t target, enum reg reg) {
  int ret = thumb_cbz_cbnz_helper(write_p, target, reg, true);
  assert(ret == 0);
}

void thumb_cbnz_helper(uint16_t *write_p, uint32_t target, enum reg reg) {
  int ret = thumb_cbz_cbnz_helper(write_p, target, reg, false);
  assert(ret == 0);
}

#define DISP_CALL_SIZE 76
void branch_save_context(dbm_thread *thread_data, uint16_t **o_write_p, bool late_app_sp) {
  uint16_t *write_p = *o_write_p;

  thumb_sub_sp_i16(&write_p, DISP_RES_WORDS);
  write_p++;

  thumb_push16(&write_p, (1 << r0) | (1 << r1) | (1 << r2) | (1 << r3));
  write_p++;

  if (!late_app_sp) {
    thumb_addi32(&write_p, 0, 0, sp, 0, r3, DISP_SP_OFFSET);
    write_p += 2;
  }

  *o_write_p = write_p;
}

#define SETUP (1 << 0)
#define REPLACE_TARGET (1 << 1)
#define INSERT_BRANCH (1 << 2)

void branch_jump(dbm_thread *thread_data, uint16_t **o_write_p, int bb_index, uint32_t target, uint32_t flags) {
  uint16_t *write_p = *o_write_p;
  uint32_t offset;

  if (flags & SETUP) {
    copy_to_reg_32bit(&write_p, r1, bb_index);
  }
  if (flags & REPLACE_TARGET) {
    copy_to_reg_32bit(&write_p, r0, target);
  }
  if (flags & INSERT_BRANCH) {
    if (flags & LATE_APP_SP) {
      thumb_addi32(&write_p, 0, 0, sp, 0, r3, DISP_SP_OFFSET);
      write_p += 2;
    }
    thumb_b32_helper(write_p, (uint32_t)thread_data->dispatcher_addr-4);
    write_p += 2;
  }
  
  *o_write_p = write_p;
}

void thumb_simple_exit(dbm_thread *thread_data, uint16_t **o_write_p, int bb_index, uint32_t target) {
  uint16_t *write_p = *o_write_p;
  branch_save_context(thread_data, &write_p, false);
  branch_jump(thread_data, &write_p, bb_index, target, SETUP|REPLACE_TARGET|INSERT_BRANCH);
  *o_write_p = write_p;
}

void set_cc_imm_links(dbm_thread *thread_data,
                         int16_t *write_p,
                         int basic_block,
                         uint32_t address_taken,
                         uint32_t address_skipped,
                         bool taken_in_cache,
                         bool skipped_in_cache
                         ) {
  uint32_t offset;

  if ((taken_in_cache || skipped_in_cache) &&
      thread_data->code_cache_meta[basic_block].branch_cache_status == 0) {
    thread_data->code_cache_meta[basic_block].branch_cache_status = taken_in_cache ? BRANCH_LINKED : FALLTHROUGH_LINKED;
    offset = ((uint32_t)write_p + 2) | THUMB;
    if (taken_in_cache) {
      record_cc_link(thread_data, offset, address_taken);
    } else {
      record_cc_link(thread_data, offset, address_skipped);
    }
  }

  if (taken_in_cache && skipped_in_cache &&
      (thread_data->code_cache_meta[basic_block].branch_cache_status & BOTH_LINKED) == 0) {
    thread_data->code_cache_meta[basic_block].branch_cache_status |= BOTH_LINKED;
    offset = ((uint32_t)write_p + 4 + 2) | THUMB;
    if (thread_data->code_cache_meta[basic_block].branch_cache_status & BRANCH_LINKED) {
      record_cc_link(thread_data, offset, address_skipped);
    } else {
      record_cc_link(thread_data, offset, address_taken);
    }
  }
}

#define IMM_SIZE 102
void thumb_encode_cond_imm_branch(dbm_thread *thread_data,
                                  uint16_t **o_write_p,
                                  int basic_block,
                                  uint32_t address_taken,
                                  uint32_t address_skipped,
                                  enum arm_cond_codes condition,
                                  bool taken_in_cache,
                                  bool skipped_in_cache,
                                  bool update) {
  uint16_t *write_p = *o_write_p;

  if (taken_in_cache && skipped_in_cache) {
    if (update && (thread_data->code_cache_meta[basic_block].branch_cache_status & FALLTHROUGH_LINKED)) {
      thumb_it16(&write_p, arm_inverse_cond_code[condition], 0x8);
      write_p++;
      thumb_b32_helper(write_p, address_skipped);
      write_p += 2;
      thumb_b32_helper(write_p, address_taken);
    } else {
      thumb_it16(&write_p, condition, 0x8);
      write_p++;
      thumb_b32_helper(write_p, address_taken);
      write_p += 2;
      thumb_b32_helper(write_p, address_skipped);
    }
    write_p += 2;
  } else {
    if (taken_in_cache) {
      thumb_it16(&write_p, condition, 0x8);
      write_p++;
      thumb_b32_helper(write_p, address_taken);
      write_p += 2;
    }
    if (skipped_in_cache) {
      assert(condition < 14);
      thumb_it16(&write_p, arm_inverse_cond_code[condition], 0x8);
      write_p++;
      thumb_b32_helper(write_p, address_skipped);
      write_p += 2;
    }
    if (!update) {
      if (!taken_in_cache && !skipped_in_cache) {
        // Here we reserve space for one conditional branch, either 2 or 3 halfwords depending on offset
        thumb_nop16(&write_p);
        write_p++;
        thumb_nop16(&write_p);
        write_p++;
        thumb_nop16(&write_p);
        write_p++;
      }
        
      branch_save_context(thread_data, &write_p, false);

      branch_jump(thread_data, &write_p, basic_block, 0, SETUP);
      if (!taken_in_cache && !skipped_in_cache) {
        debug("Writing cond branch at: %p\n", write_p);
        // Branch to branch taken trampoline
        thumb_b_cond16(&write_p, condition, 0x05);
        write_p++;
      }

      if (!skipped_in_cache) {
        // Branch not taken trampoline
        branch_jump(thread_data, &write_p, basic_block, address_skipped, REPLACE_TARGET|INSERT_BRANCH);
      }
      if (!taken_in_cache) {
        // Branch taken trampoline
        branch_jump(thread_data, &write_p, basic_block, address_taken, REPLACE_TARGET|INSERT_BRANCH);
      }
    }
  }

  set_cc_imm_links(thread_data, *o_write_p, basic_block, address_taken, address_skipped, taken_in_cache, skipped_in_cache);

  *o_write_p = write_p;
}

#define CBZ_SIZE 124
void thumb_encode_cbz_branch(dbm_thread *thread_data,
                                  uint32_t rn,
                                  uint16_t **o_write_p,
                                  int basic_block,
                                  uint32_t address_taken,
                                  uint32_t address_skipped,
                                  bool taken_in_cache,
                                  bool skipped_in_cache,
                                  bool update) {
  uint16_t *write_p = *o_write_p;
              
  if (taken_in_cache && skipped_in_cache) {
    if (update && (thread_data->code_cache_meta[basic_block].branch_cache_status & FALLTHROUGH_LINKED)) {
      thumb_cbz16(&write_p, 0, 0x01, rn);
      write_p++;
      thumb_b32_helper(write_p, address_skipped);
      write_p += 2;
      thumb_b32_helper(write_p, address_taken);
      write_p += 2;
    } else {
      thumb_cbnz16(&write_p, 0, 0x01, rn);
      write_p++;
      thumb_b32_helper(write_p, address_taken);
      write_p += 2;
      thumb_b32_helper(write_p, address_skipped);
      write_p += 2;
    }
  } else {
    if (taken_in_cache) {
      thumb_cbnz16(&write_p, 0, 0x01, rn);
      write_p++;
      thumb_b32_helper(write_p, address_taken);
      write_p += 2;
    }
    if (skipped_in_cache) {
      thumb_cbz16(&write_p, 0, 0x01, rn);
      write_p++;
      thumb_b32_helper(write_p, address_skipped);
      write_p += 2;
    }
    if (!update) {
      if (!taken_in_cache && !skipped_in_cache) {
        thumb_nop16(&write_p);
        write_p++;
        thumb_nop16(&write_p);
        write_p++;
        thumb_nop16(&write_p);
        write_p++;
      }
      assert(rn != sp);
      branch_save_context(thread_data, &write_p, true);

      if (!taken_in_cache && !skipped_in_cache) {
        debug("Writing C(N)BZ at: %p\n", write_p);
        // Branch to branch taken trampoline
        thumb_cbz16(&write_p, 0, 0xb, rn);
        write_p++;
      }

      if (!skipped_in_cache) {
        // Branch not taken trampoline
        branch_jump(thread_data, &write_p, basic_block, address_skipped,
                    SETUP|REPLACE_TARGET|INSERT_BRANCH|LATE_APP_SP);
      }

      if (!taken_in_cache) {
        // Branch taken trampoline
        branch_jump(thread_data, &write_p, basic_block, address_taken,
                    SETUP|REPLACE_TARGET|INSERT_BRANCH|LATE_APP_SP);
      }
    }
  } // not both in cache

  set_cc_imm_links(thread_data, *o_write_p, basic_block, address_taken, address_skipped, taken_in_cache, skipped_in_cache);

  *o_write_p = write_p;
}

void thumb_inline_hash_lookup(dbm_thread *thread_data, uint16_t **o_write_p, int basic_block, int r_target) {
  uint16_t *loop_start;
  uint16_t *branch_miss;
  uint16_t *write_p = *o_write_p;

  bool target_reg_clean = (r_target >= r0);
  int target = target_reg_clean ? r_target : r5;
  int r_tmp = target_reg_clean ? r5 : r4;

  thread_data->code_cache_meta[basic_block].rn = target;

  // MOVW+MOVT r_tmp, hash_mask
  copy_to_reg_32bit(&write_p, r_tmp, CODE_CACHE_HASH_SIZE);

  // MOVW+MOVT r6, hash_table
  copy_to_reg_32bit(&write_p, r6, (uint32_t)thread_data->entry_address.entries);

  // AND r_tmp, target, r_tmp
  thumb_and32(&write_p, 0, target, 0, r_tmp, 0, 0, r_tmp);
  write_p += 2;

  // ADD r_tmp, r6, r_tmp, LSL #3
  thumb_add32(&write_p, 0, r6, 0, r_tmp, 3, 0, r_tmp);
  write_p += 2;

  // loop:
  loop_start = write_p;

  // LDR r6, [r_tmp], #8
  thumb_ldri32(&write_p, r6, r_tmp, 8, 0, 1, 1);
  write_p += 2;

  // CMP r6, target
  thumb_cmp32(&write_p, r6, 0, 0, 0, target);
  write_p += 2;

  // BNE miss
  branch_miss = write_p++;

  // jump:
  // LDR r6, [r_tmp, #-4]
  thumb_ldri32(&write_p, r6, r_tmp, 4, 1, 0, 0);
  write_p += 2;

  if (!target_reg_clean) {
    // POP {R4}
    thumb_pop16(&write_p, (1 << r4));
    write_p++;
  }

  // BX r6
  thumb_bx16(&write_p, r6);
  write_p++;

  // miss:
  thumb_b16_helper(branch_miss, (uint32_t)write_p, NE);

  // CMP r6, #0
  thumb_cmpri16(&write_p, r6, 0);
  write_p++;

  // BNE loop
  thumb_b16_helper(write_p, (uint32_t)loop_start, NE);
  write_p++;

  // SUB sp, sp, #8
  // PUSH {R0 - R3}
  branch_save_context(thread_data, &write_p, true);

  // MOV R0, target
  thumb_movh16(&write_p, r0 >> 3, target, r0);
  write_p++;

  // ADD r3, sp, #24
  thumb_addi32(&write_p, 0, 0, sp, 0, r3, DISP_SP_OFFSET);
  write_p += 2;

  // LDMFD r3!, {r4-r6}
  if (target_reg_clean) {
    thumb_ldmfd32(&write_p, 1, r3, (1 << r5) | (1 << r6));
  } else {
    thumb_ldmfd32(&write_p, 1, r3, (1 << r4) | (1 << r5) | (1 << r6));
  }
  write_p += 2;

  // MOV r1, #bb_id
  // B dispatcher
  branch_jump(thread_data, &write_p, basic_block, 0, SETUP | INSERT_BRANCH);

  *o_write_p = write_p;
}

bool link_bx_alt(dbm_thread *thread_data, uint16_t **write_p, int cond_inst_after_it, uint32_t alt_addr) {
#ifdef LINK_BX_ALT
  if (cond_inst_after_it > 0) {
    assert(cond_inst_after_it == 1);
    thumb_b16(write_p, 1);
    (*write_p)++;
    uint32_t block_address = lookup_or_stub(thread_data, (uint32_t)alt_addr);
    thumb_cc_branch(thread_data, *write_p, block_address);
    *write_p += 2;
    return true;
  }
#endif
  return false;
}

void pass1_thumb(dbm_thread *thread_data, uint16_t *read_address, branch_type *bb_type) {
  uint32_t null, reglist, rd, dn, imm;
  int32_t branch_offset;
  *bb_type = unknown;

  while(*bb_type == unknown) {
    thumb_instruction inst = thumb_decode(read_address);

    switch(inst) {
      case THUMB_ADDH16:
      case THUMB_CMPH16:
      case THUMB_MOVH16:
        thumb_special_data_proc_16_decode_fields(read_address, &null, &dn, &null, &rd);
        rd |= dn << 3;
        if (rd == pc) {
          *bb_type = uncond_reg_thumb;
        }
        break;

      case THUMB_BX16:
      case THUMB_BLX16:
        *bb_type = uncond_reg_thumb;
        break;

      case THUMB_CBZ16:
      case THUMB_CBNZ16:
        *bb_type = cbz_thumb;
        break;

      case THUMB_POP16:
        thumb_pop16_decode_fields(read_address, &reglist);
        if(reglist & (1<<8)) {
          *bb_type = uncond_reg_thumb;
        }
        break;

      case THUMB_B_COND16:
        *bb_type = cond_imm_thumb;
        break;

      case THUMB_B16:
#ifdef DBM_INLINE_UNCOND_IMM
        thumb_b16_decode_fields(read_address, &imm);

        branch_offset = (imm & 0x400) ? 0xFFFFF000 : 0;
        branch_offset |= imm << 1;

        read_address = (uint16_t *)((uint32_t)read_address + 4 -2 + branch_offset);
#else
        *bb_type = uncond_imm_thumb;
#endif
        break;

      case THUMB_LDRI32:
      case THUMB_LDRHI32:
      case THUMB_LDRBI32:
        thumb_load_store_single_reg_imm12_32_decode_fields(read_address, &null, &null, &null,
                                                           &null, &null, &rd, &null);
        if (rd == pc) {
          *bb_type = uncond_reg_thumb;
        }
        break;

      case THUMB_LDR32:
      case THUMB_LDRH32:
      case THUMB_LDRB32:
        thumb_load_store_single_reg_off_32_decode_fields(read_address, &null, &null, &null, &null, &rd, &null, &null);
        if (rd == pc) {
          *bb_type = uncond_reg_thumb;
        }
        break;

      case THUMB_B32:
      case THUMB_BL32:
        *bb_type = uncond_imm_thumb;
        break;

      case THUMB_BL_ARM32:
        *bb_type = uncond_blxi_thumb;
        break;

      case THUMB_B_COND32:
        *bb_type = cond_imm_thumb;
        break;

      case THUMB_TBB32:
      case THUMB_TBH32:
        *bb_type = tb_indirect;
        break;

      case THUMB_LDMFD32:
      case THUMB_LDMEA32:
        thumb_load_store_multiple32_decode_fields(read_address, &null, &null, &null, &null, &reglist);
        if(reglist & (1<<pc)) {
          *bb_type = uncond_reg_thumb;
        }
        break;
    }

    if (inst < THUMB_ADC32) {
      read_address++;
    } else {
      read_address+= 2;
    }
  }
}

void do_it_iter(thumb_it_state *state) {
  if (state->cond_inst_after_it > 0) {
    state->cond_inst_after_it--;
    state->it_mask = (state->it_mask << 1) & 0x3F;
  }
}

bool thumb_scanner_deliver_callbacks(dbm_thread *thread_data, mambo_cb_idx cb_id, thumb_it_state *state,
                                     uint16_t **o_read_address, thumb_instruction inst, uint16_t **o_write_p,
                                     uint32_t **o_data_p, int basic_block, cc_type type,
                                     bool allow_write, bool *stop) {
  bool replaced = false;
  void *prev_write_p;
#ifdef PLUGINS_NEW
  if (global_data.free_plugin > 0) {
    uint16_t *write_p = *o_write_p;
    uint32_t *data_p = *o_data_p;
    uint16_t *read_address = *o_read_address;

    mambo_cond cond;
    uint32_t tmp;
    switch(inst) {
      case THUMB_B_COND16:
        thumb_b_cond16_decode_fields(read_address, &cond, &tmp);
        break;
      case THUMB_B_COND32:
        thumb_b_cond32_decode_fields(read_address, &tmp, &cond, &tmp, &tmp, &tmp, &tmp);
        break;
      default:
        if (state->cond_inst_after_it > 0) {
          cond = (((state->it_mask >> 5) & 1) == (state->it_cond & 1))
                 ? state->it_cond : arm_inverse_cond_code[state->it_cond];
        } else {
          cond = AL;
        }
    }

    /* If the previous instruction was IT, allow the plugins to overwrite it */
    if (allow_write && state->cond_inst_after_it > 0) {
      if (state->it_inst_addr == (write_p -1)) {
        write_p--;
        state->is_overwritten = true;
      }
    }

    mambo_context ctx;
    set_mambo_context_code(&ctx, thread_data, PRE_INST_C, type, basic_block, THUMB_INST, inst, cond, read_address, write_p, data_p, stop);

    for (int i = 0; i < global_data.free_plugin; i++) {
      if (global_data.plugins[i].cbs[cb_id] != NULL) {
        ctx.plugin_id = i;
        ctx.code.replace = false;
        ctx.code.available_regs = ctx.code.pushed_regs;
        prev_write_p = ctx.code.write_p;
        global_data.plugins[i].cbs[cb_id](&ctx);

        if (allow_write) {
          if (replaced && (prev_write_p != ctx.code.write_p || ctx.code.replace)) {
            fprintf(stderr, "MAMBO API WARNING: plugin %d added code for overridden "
                            "instruction (at %p).\n", i, read_address);
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
            thumb_pop_regs((uint16_t **)&ctx.code.write_p, ctx.code.pushed_regs);
          }

          thumb_check_free_space(thread_data, (uint16_t **)&ctx.code.write_p, (uint32_t **)&ctx.code.data_p,
                                 state, false, MIN_FSPACE, basic_block);
        } else {
          assert(ctx.code.write_p == write_p);
          assert(ctx.code.data_p == data_p);
        }
      } // global_data.plugins[i].cbs[cb_id] != NULL
    } // plugin iterator

    if (cb_id == PRE_BB_C) {
      watched_functions_t *wf = &global_data.watched_functions;
      for (int i = 0; i < wf->funcp_count; i++) {
        if (read_address == (wf->funcps[i].addr -1)) {
          _function_callback_wrapper(&ctx, wf->funcps[i].func);
          if (ctx.code.replace) {
            read_address = ctx.code.read_address;
          }
          thumb_check_free_space(thread_data, (uint16_t **)&ctx.code.write_p, (uint32_t **)&ctx.code.data_p,
                                 state, false, MIN_FSPACE, basic_block);
        }
      }
    }

    if (allow_write && state->cond_inst_after_it > 0) {
      if (ctx.code.write_p != write_p) {
        // Code was inserted.
        // Reduce the length of the IT block
        create_it_gap((uint16_t **)&ctx.code.write_p, state);
        if (replaced) {
          // If the instruction was replaced by a plugin, remove its
          // condition from the head of the IT block
          do_it_iter(state);
        }
        // Insert an IT instruction for the remaining instructions
        close_it_gap((uint16_t **)&ctx.code.write_p, state);
      } else {
        // If no code was inserted, keep the IT instruction
        if (state->is_overwritten) {
          ctx.code.write_p += 2;
          state->is_overwritten = false;
        }
      }
    }

    write_p = ctx.code.write_p;
    data_p = ctx.code.data_p;

    *o_write_p = write_p;
    *o_data_p = data_p;
    *o_read_address = read_address;
  }
#endif
  return replaced;
}

size_t scan_thumb(dbm_thread *thread_data, uint16_t *read_address, int basic_block, cc_type type, uint16_t *write_p) {
  bool stop = false;

  uint16_t *start_scan = read_address;
  if (write_p == NULL) {
    write_p = (uint16_t *)&thread_data->code_cache->blocks[basic_block];
  }
  uint32_t start_address = (uint32_t)write_p;
  uint32_t *data_p;
  if (type == mambo_bb) {
    data_p = (uint32_t *)write_p + BASIC_BLOCK_SIZE;
  } else {
    data_p = (uint32_t *)&thread_data->code_cache->traces + (TRACE_CACHE_SIZE/4);
  }
  
  debug("write_p: %p\n", write_p);


  // Todo: check that the compiler can optimize the fact that only
  // a small number of these variables is alive per iteration
  uint32_t rm;
  uint32_t rn;
  uint32_t dn;
  uint32_t rdn;
  uint32_t rt;
  uint32_t rdlo;
  uint32_t rdhi;
  uint32_t racc;
  uint32_t imm1;
  uint32_t imm2;
  uint32_t imm3;
  uint32_t imm4;
  uint32_t imm5;
  uint32_t imm8;
  uint32_t set_flags;
  uint32_t sign_ext;
  uint32_t sign_bit;
  uint32_t upwards;
  uint32_t original_pc;
  uint32_t offset_high;
  uint32_t offset_low;
  uint32_t j1;
  uint32_t j2;
  uint32_t reglist;
  uint32_t shift_type;
  uint32_t condition;
  uint32_t writeback;
  uint32_t mask;
  uint32_t pre_index;
  uint32_t shift;
  uint32_t opcode;
  uint32_t opcode2;
  uint32_t byteword;
  uint32_t loadstore;
  uint32_t datasize;
  uint32_t rotate;
  uint32_t rt2;
  uint32_t m;
  uint32_t vm;
  uint32_t to_arm;
  uint32_t thumb_arm;
  uint32_t d;
  uint32_t vd;
  uint32_t load_store;
  uint32_t double_reg;
  uint32_t p;
  uint32_t double_single;
  uint32_t n;
  uint32_t vn;
  uint32_t f2;
  uint32_t n_high;
  uint32_t m_swap;
  uint32_t link;
  uint32_t size;
  uint32_t sz;
  uint32_t element_size;
  uint32_t align;
  
  uint32_t opc1;
  uint32_t crn;
  uint32_t coproc;
  uint32_t opc2;
  uint32_t crm;
  
  uint32_t target;
  uint32_t *scratch_data;
  uint32_t offset;
  uint32_t scratch_reg;
  uint32_t scratch_reg2;
  uint32_t sr[3];

  int32_t  branch_offset;
  uint32_t block_address;
  uint32_t branch_taken_address;
  uint32_t branch_skipped_address;
  uint32_t branch_taken_cached;
  uint32_t branch_skipped_cached;
  uint32_t *saved_data_p;
  int lowest_reg;
  uint32_t to_push;
  uint32_t return_addr;

  bool it_cond_handled = false;
  thumb_it_state it_state;
  it_state.cond_inst_after_it = 0;
  it_state.is_overwritten = false;

  bool ldrex = false;
  bool insert_inline = false;

  uint16_t *inst_pop_regs;
  uint16_t *set_inst_pop_regs = NULL;
  uint32_t *inst_pop_regs_data;
  uint32_t poped_regs = 0;
  bool is_valid;

#ifdef DBM_INLINE_UNCOND_IMM
  int inline_back_count = 0;
#endif

  if (type != mambo_trace) {
    thumb_pop16(&write_p, (1 << r5) | (1 << r6));
    write_p++;
  }

#ifdef DBM_TRACES
  branch_type bb_type;
  pass1_thumb(thread_data, read_address, &bb_type);

  if (type == mambo_bb && (bb_type == uncond_imm_thumb || bb_type == cond_imm_thumb || bb_type == cbz_thumb
  #ifdef BLXI_AS_TRACE_HEAD
    || bb_type == uncond_blxi_thumb
  #endif
  #ifdef TB_AS_TRACE_HEAD
      || bb_type == tb_indirect
  #endif
      )) {
    thumb_sub_sp_i16(&write_p, 2);
    write_p++;

    thumb_push16(&write_p, (1 << r0) | (1 << r1) | (1 << r2) | (1 << 8));
    write_p++;

    copy_to_reg_32bit(&write_p, r0, basic_block);

    thumb_bl32_helper(write_p, thread_data->trace_head_incr_addr);
    write_p += 2;
  }
#endif

  thumb_scanner_deliver_callbacks(thread_data, PRE_FRAGMENT_C, &it_state, &read_address, -1,
                                  &write_p, &data_p, basic_block, type, true, &stop);
  thumb_scanner_deliver_callbacks(thread_data, PRE_BB_C, &it_state, &read_address, -1,
                                  &write_p, &data_p, basic_block, type, true, &stop);

  while(!stop) {
    debug("thumb scan read_address: %p\n", read_address);
    thumb_instruction inst = thumb_decode(read_address);
    debug("Instruction enum: %d\n", (inst == THUMB_INVALID) ? -1 : inst);
    
    debug("instruction word: 0x%x\n", (inst < THUMB_ADC32) ? *read_address : ((*read_address) << 16) |*(read_address+1));
    it_cond_handled = false;

#ifdef PLUGINS_NEW
    bool skip_inst = thumb_scanner_deliver_callbacks(thread_data, PRE_INST_C, &it_state, &read_address,
                                                     inst, &write_p, &data_p, basic_block, type, true, &stop);
#endif

    // Check if the previous instruction is a POP
    if (set_inst_pop_regs) {
      inst_pop_regs = set_inst_pop_regs;
      set_inst_pop_regs = NULL;
    } else {
      inst_pop_regs = NULL;
    }
#ifdef PLUGINS_NEW
    if (skip_inst) {
      it_cond_handled = true;
    } else {
#endif
    switch(inst) {
      case THUMB_MOVI16:
      case THUMB_LSLI16:
      case THUMB_LSRI16:
      case THUMB_ASRI16:
        thumb_shift_i_mov_16_decode_fields(read_address, &opcode, &imm5, &rm, &rdn);

        assert(rm != pc && rdn != pc);
        copy_thumb_16();
        it_cond_handled = true;
        
        break;
      case THUMB_ADD16:
      case THUMB_SUB16:
        thumb_add_sub_16_decode_fields(read_address, &opcode, &rm, &rn, &rdn);

        assert(rm != pc && rn != pc && rdn != pc);
        copy_thumb_16();
        it_cond_handled = true;
        
        break;
      case THUMB_ADDI16:
      case THUMB_SUBI16:
        thumb_add_sub_i_16_decode_fields(read_address, &opcode, &imm3, &rn, &rdn);

        assert(rn != pc && rdn != pc);
        copy_thumb_16();
        it_cond_handled = true;
        
        break;
      case THUMB_MOVRI16:
      case THUMB_CMPRI16:
      case THUMB_ADDRI16:
      case THUMB_SUBRI16:
        thumb_add_sub_comp_mov_i_16_decode_fields(read_address, &opcode, &rdn, &imm8);
        
        assert(rdn != pc);
        copy_thumb_16();
        it_cond_handled = true;
        
        break;
      case THUMB_AND16:
      case THUMB_EOR16:
      case THUMB_LSL16:
      case THUMB_LSR16:
      case THUMB_ASR16:
      case THUMB_ADC16:
      case THUMB_SBC16:
      case THUMB_TST16:
      case THUMB_ROR16:
      case THUMB_RSBI16:
      case THUMB_CMP16:
      case THUMB_CMN16:
      case THUMB_ORR16:
      case THUMB_BIC16:
      case THUMB_MUL16:
      case THUMB_MVN16:
        thumb_data_proc_16_decode_fields(read_address, &opcode, &rm, &rdn);
        
        assert(rm != pc && rdn != pc);
        copy_thumb_16();
        it_cond_handled = true;
        
        break;
      case THUMB_ADDH16:
      case THUMB_CMPH16:
      case THUMB_MOVH16:
        thumb_special_data_proc_16_decode_fields(read_address, &opcode, &dn, &rm, &rdn);

        rdn |= dn << 3;
        debug("ADD/CMP/MOVH16 rm: %d, rdn: %d\n", rm, rdn);

        if (rdn != pc && rm != pc) {
          copy_thumb_16();
          it_cond_handled = true;
          break;
        }

        assert(!(rdn == pc && rm == pc));

        if (rdn == pc) {
          assert(rm != sp);
          thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_thumb;
          thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;

          uint32_t r_target = r0;

#ifdef DBM_INLINE_HASH
          thumb_push16(&write_p, (1 << r4) | (1 << r5) | (1 << r6));
          write_p++;
          r_target = r5;
#else
          branch_save_context(thread_data, &write_p, true);
#endif
          switch(inst) {
            case THUMB_MOVH16:
              if (rm != r_target) {
                thumb_movh16(&write_p, r_target >> 3, rm, r_target);
                write_p++;
              }
              break;
            default:
              fprintf(stderr, "Unsupported encoding\n");
              while(1);
          }

          // ORR Rtarget, Rtarget, #1 - to mark as thumb insts
          thumb_orri32(&write_p, 0, 0, r_target, 0, r_target, 1);
          write_p += 2;

#ifdef DBM_INLINE_HASH
          thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                                 true, IHL_FSPACE, basic_block);
          thumb_inline_hash_lookup(thread_data, &write_p, basic_block, -1);
#else
          branch_jump(thread_data, &write_p, basic_block, 0, SETUP|INSERT_BRANCH|LATE_APP_SP);
#endif
          stop = true;
        } else { // rm == pc
          assert(rdn != pc);
          scratch_reg = (rdn == r0) ? r1 : r0;

          thumb_push16(&write_p, 1 << scratch_reg);
          write_p++;
          
          copy_to_reg_32bit(&write_p, scratch_reg, (uint32_t)read_address + 4);
          switch(inst) {
            case THUMB_ADDH16:
              thumb_addh16(&write_p, dn, scratch_reg, rdn & 0x7);
              break;
            case THUMB_CMPH16:
              thumb_cmph16(&write_p, dn, rm, rdn);
              fprintf(stderr, "Untested CMPH16\n");
              while(1);
              break;
            case THUMB_MOVH16:
              thumb_movh16(&write_p, dn, scratch_reg, rdn & 0x7);
              break;
          }
          write_p++;
          
          thumb_pop16(&write_p, 1 << scratch_reg);
          write_p++;
        }
        
        break;
      case THUMB_BX16:
      case THUMB_BLX16:
        thumb_bx_16_decode_fields(read_address, &link, &rm);
        assert(rm != sp && (rm != pc || inst == THUMB_BX16));
        /* Handle conditional execution: either a direct branch to the basic block for
           read_address + 2 or a call to the dispatcher */
        thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_thumb;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
        if (it_state.cond_inst_after_it == 1) {
#ifdef LINK_BX_ALT
          /* If the previous instruction was POP, we'll overwrite it and place a copy:
             - on the code path where the branch wasn't taken
             - on the code path where the branch was taken
             This allows following code (e.g. the inline hash lookup) to use the dead
             registers as scratch registers.
          */
          if (inst_pop_regs) {
            write_p = inst_pop_regs;
            data_p = inst_pop_regs_data;
            
            thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                                   true, 8, basic_block);

            thumb_b16(&write_p, 3);
            write_p++;

            thumb_ldmfd32(&write_p, 1, sp, poped_regs);
            write_p += 2;
          } else {
            thumb_b16(&write_p, 1);
            write_p++;
          }

          target = lookup_or_stub(thread_data, (uint32_t)read_address + 2 + 1);
          thumb_cc_branch(thread_data, write_p, target);
          write_p += 2;
          
          if (inst_pop_regs) {
            /* If the inline hash lookup is going to use the dead registers, it needs
               to replace the following instruction from the branch-taken path.
            */
            inst_pop_regs = write_p;
            inst_pop_regs_data = data_p;
          
            thumb_ldmfd32(&write_p, 1, sp, poped_regs);
            write_p += 2;
            
            while(1);
          }
#else
          assert(0); // incorrect range
          thumb_b16(&write_p, (((uint32_t)write_p) & 2) ? 29 : 28);
          write_p++;
          
          // This is branch not taken
          thumb_simple_exit(thread_data, &write_p, basic_block, (uint32_t)read_address+2+1);
#endif
      
          it_cond_handled = true;
          it_state.cond_inst_after_it = 0; // allows check_free_space to insert branches
        } else if (it_state.cond_inst_after_it > 1) {
          fprintf(stderr, "BL in middle of IT block\n");
          while(1);
        }

        /* BX PC can be handled as an immediate branch to ARM mode*/
        if (inst == THUMB_BX16 && rm == pc) {
          target = lookup_or_stub(thread_data, get_original_pc());

          if (((uint32_t)write_p) & 2) {
            thumb_ldrl32(&write_p, pc, 4, 1);
            write_p += 3;
          } else {
            thumb_ldrl32(&write_p, pc, 0, 1);
            write_p += 2;
          }

          *(uint32_t *)write_p = target;
          record_cc_link(thread_data, (uint32_t)write_p|FULLADDR, target);
          write_p += 2;

          stop = true;

          break;
        }

#ifdef DBM_INLINE_HASH
        assert(rm != sp && rm != pc);
        int r_target = -1;
        if (rm != r5 && rm != r6 && (inst != THUMB_BLX16 || rm != lr)) {
          r_target = rm;
          thumb_push16(&write_p, (1 << r5) | (1 << r6));
        } else {
          thumb_push16(&write_p, (1 << r4) | (1 << r5) | (1 << r6));
        }
        write_p++;
        if (r_target < r0) {
          thumb_movh16(&write_p, 0, rm, r5);
          write_p++;
        }

        if (inst == THUMB_BLX16) {
          copy_to_reg_32bit(&write_p, lr, ((uint32_t)read_address) + 2 + 1);
        }

        thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                               true, IHL_FSPACE, basic_block);
        thumb_inline_hash_lookup(thread_data, &write_p, basic_block, r_target);
#else
        branch_save_context(thread_data, &write_p, true);

        if (rm == pc) {
          copy_to_reg_32bit(&write_p, r0, get_original_pc());
        } else {
          thumb_movh16(&write_p, 0, rm, 0);
          write_p++;
          if (inst == THUMB_BLX16) {
            copy_to_reg_32bit(&write_p, lr, ((uint32_t)read_address) + 2 + 1);
          }
        }

        branch_jump(thread_data, &write_p, basic_block, 0, SETUP|INSERT_BRANCH|LATE_APP_SP);
#endif
        stop = true;
        
        break;
      case THUMB_LDR_PC_16:
        // needs rewriting
        thumb_ldr_pc_16_decode_fields(read_address, &rdn, &imm8);
        original_pc = get_original_pc();
        offset = imm8 << 2;
        
        modify_in_it_pre(5);
        copy_to_reg_32bit(&write_p, rdn, original_pc);
        thumb_ldrwi32(&write_p, rdn, rdn, offset);
        write_p += 2;
        modify_in_it_post();
        
        it_cond_handled = true;
        
        break;
        
      case THUMB_STR16:
      case THUMB_STRH16:
      case THUMB_STRB16:
      case THUMB_LDRSB16:
      case THUMB_LDR16:
      case THUMB_LDRH16:
      case THUMB_LDRB16:
      case THUMB_LDRSH16:
        // only low 8 regs
        copy_thumb_16();
        it_cond_handled = true;
        break;
        
      case THUMB_STRI16:
      case THUMB_LDRI16:
      case THUMB_STRBI16:
      case THUMB_LDRBI16:
        // only low 8 regs
//        thumb_load_store_byte_word_i_16_decode_fields(read_address, &byteword, &loadstore, &imm5, &rn, &rdn);

        copy_thumb_16();
        it_cond_handled = true;
        
        break;
        
      case THUMB_LDRHI16:
      case THUMB_STRHI16:
        // only low 8 regs
//        thumb_load_store_halfword_i_16_decode_fields(read_address, &loadstore, &imm5, &rn, &rt);
        
        copy_thumb_16();
        it_cond_handled = true;
        
        break;
        
      case THUMB_STR_SP16:
        // check that source isn't pc
        thumb_str_sp16_decode_fields(read_address, &rdn, &imm8);

        assert(rdn != pc);
        copy_thumb_16();
        it_cond_handled = true;

        break;
      case THUMB_LDR_SP16:
        // check that dest isn't pc
        thumb_ldr_sp16_decode_fields(read_address, &rdn, &imm8);
        
        assert(rdn != pc);
        copy_thumb_16();
        it_cond_handled = true;
        
        break;
      
      case THUMB_ADD_FROM_SP16:
        copy_thumb_16();
        it_cond_handled = true;
        break;
        
      case THUMB_ADD_FROM_PC16:
        thumb_add_from_pc16_decode_fields(read_address, &rdn, &imm8);

        modify_in_it_pre(3);
        copy_to_reg_32bit(&write_p, rdn, get_original_pc() + (imm8 << 2));
        modify_in_it_post();

        it_cond_handled = true;

        break;

      // Only affects the SP, safe to copy
      case THUMB_ADD_SP_I16:
      case THUMB_SUB_SP_I16:
        copy_thumb_16();
        it_cond_handled = true;
        break;
        
      case THUMB_SXTH16:
      case THUMB_SXTB16:
      case THUMB_UXTH16:
      case THUMB_UXTB16:
        // Operand fields are 3 bits in width
        copy_thumb_16();
        it_cond_handled = true;
        
        break;
      case THUMB_CBZ16:
      case THUMB_CBNZ16:
        thumb_misc_cbz_16_decode_fields(read_address, &n, &imm1, &imm5, &rn);
        assert(rn != pc);
        
        branch_offset = (imm1 << 6) | (imm5 << 1);
        debug("Branch offset: %d\n", branch_offset);
        
        // Seems ok, but keep an eye on this
        target = (uint32_t)read_address + branch_offset + 4 + 1;
        debug("Branch taken: 0x%x\n", target);

        thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                               true, CBZ_SIZE, basic_block);

        // Mark this as the beggining of code emulating B
        thread_data->code_cache_meta[basic_block].exit_branch_type = cbz_thumb;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
        thread_data->code_cache_meta[basic_block].branch_taken_addr = (inst == THUMB_CBZ16) ? target : ((uint32_t)read_address + 2 + 1);
        thread_data->code_cache_meta[basic_block].branch_skipped_addr = (inst == THUMB_CBZ16) ? ((uint32_t)read_address + 2 + 1) : target;
        thread_data->code_cache_meta[basic_block].rn = rn;

#ifdef DBM_LINK_CBZ
        if (type == mambo_bb) {
          branch_taken_address = cc_lookup(thread_data, thread_data->code_cache_meta[basic_block].branch_taken_addr);
          branch_taken_cached = (branch_taken_address != UINT_MAX);
          branch_skipped_address = cc_lookup(thread_data, thread_data->code_cache_meta[basic_block].branch_skipped_addr);
          branch_skipped_cached = (branch_skipped_address != UINT_MAX);

          thumb_encode_cbz_branch(thread_data, rn, &write_p, basic_block,
                                  (branch_taken_cached) ? branch_taken_address : thread_data->code_cache_meta[basic_block].branch_taken_addr,
                                  (branch_skipped_cached) ? branch_skipped_address : thread_data->code_cache_meta[basic_block].branch_skipped_addr,
                                  branch_taken_cached,
                                  branch_skipped_cached,
                                  false);
        } else {
#endif
          thumb_encode_cbz_branch(thread_data, rn, &write_p, basic_block,
                                  (inst == THUMB_CBZ16) ? target : ((uint32_t)read_address + 2 + 1),
                                  (inst == THUMB_CBZ16) ? ((uint32_t)read_address + 2 + 1) : target,
                                  false,
                                  false,
                                  false);
#ifdef DBM_LINK_CBZ
        }
#endif

        stop = true;

        break;
      case THUMB_PUSH16:
        copy_thumb_16();
        break;
      case THUMB_POP16:
        thumb_pop16_decode_fields(read_address, &reglist);

        if ((reglist & (1<<8)) == 0) {
          set_inst_pop_regs = write_p;
          inst_pop_regs_data = data_p;
          poped_regs = reglist;

          copy_thumb_16();
        } else { // PC is POPed
          thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_thumb;
          thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;

          if (link_bx_alt(thread_data, &write_p, it_state.cond_inst_after_it, (uint32_t)read_address + 3)) {
            it_cond_handled = true;
          }
#ifdef DBM_INLINE_HASH
          if (reglist != ((1 << r4) | (1 << r5) | (1 << 8))) {
            if (reglist & 0xFF) {
              thumb_pop16(&write_p, reglist & 0xFF);
              write_p++;
            }
            thumb_push16(&write_p, (1 << r4) | (1 << r5));
            write_p++;
          }
          thumb_ldr_sp16(&write_p, r5, 2);
          write_p++;
          thumb_str_sp16(&write_p, r6, 2);
          write_p++;

          thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                                 true, IHL_FSPACE, basic_block);
          thumb_inline_hash_lookup(thread_data, &write_p, basic_block, -1);
#else
          thumb_pop16(&write_p, reglist & 0xFF);
          write_p++;

          branch_save_context(thread_data, &write_p, false);
  #ifndef LINK_BX_ALT
          if (it_state.cond_inst_after_it == 1 && type == mambo_bb) {
            fprintf(stderr, "Cond POP16, check if BX PC is marked conditional\n");
            thumb_it16 (&write_p, arm_inverse_cond_code[it_state.it_cond], (arm_inverse_cond_code[it_state.it_cond] & 1) ? 0xa : 0x6 );
            write_p++;
            copy_to_reg_32bit(&write_p, r0, get_original_pc() + 1);
            it_cond_handled = true;
            while(1);
          }
  #endif
          thumb_ldri32(&write_p, r0, APP_SP, 4, 0, 1, 1);
          write_p += 2;
          branch_jump(thread_data, &write_p, basic_block, 0, SETUP|INSERT_BRANCH);
#endif
          stop = true;    
        }
        
        break;
        
      case THUMB_REV16:
      case THUMB_REV1616:
      case THUMB_REVSH16:
        copy_thumb_16();
        it_cond_handled = true;
        break;
        
      case THUMB_IT16:
        thumb_it16_decode_fields(read_address, &condition, &mask);
        it_state.cond_inst_after_it = it_get_no_of_inst(mask) + 1;
        debug("No of cond instructions following from %p: %d\n", read_address, it_state.cond_inst_after_it);
        it_cond_handled = true;
        
        it_state.it_inst_addr = write_p;
        it_state.it_cond = condition;
        it_state.it_mask = mask | (it_state.it_cond & 0x1) << 4;
        it_state.it_initial_mask = mask;
        debug("initial it mask: 0x%x\n", mask);
        
        copy_thumb_16();
        break;
        
      case THUMB_NOP16:
      case THUMB_BKPT16:
      case THUMB_UDF16:
        copy_thumb_16();
        it_cond_handled = true;
        break;
        
      case THUMB_LDMFD16:
      case THUMB_STMEA16:
        copy_thumb_16();
        it_cond_handled = true;
        break;
        
      case THUMB_B_COND16:
        thumb_b_cond16_decode_fields(read_address, &condition, &imm8);
        branch_offset = ((int8_t)imm8) << 1;
        debug("Branch offset: %d\n", branch_offset);
        
        // Seems ok, but keep an eye on this
        target = (uint32_t)read_address + 4 + 1 + branch_offset;
        debug("Branch taken: 0x%x\n", target);

        thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                               true, IMM_SIZE, basic_block);

        // Mark this as the beggining of code emulating B
        thread_data->code_cache_meta[basic_block].exit_branch_type = cond_imm_thumb;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
        thread_data->code_cache_meta[basic_block].branch_taken_addr = target;
        thread_data->code_cache_meta[basic_block].branch_skipped_addr = (uint32_t)read_address + 2 + 1;
        thread_data->code_cache_meta[basic_block].branch_condition = condition;

#ifdef DBM_LINK_COND_IMM
        if (type == mambo_bb) {
          branch_taken_address = cc_lookup(thread_data, target);
          branch_taken_cached = (branch_taken_address != UINT_MAX);
          branch_skipped_address = cc_lookup(thread_data, (uint32_t)read_address + 2 + 1);
          branch_skipped_cached = (branch_skipped_address != UINT_MAX);

          thumb_encode_cond_imm_branch(thread_data, &write_p, basic_block,
                                       branch_taken_cached ? branch_taken_address : target,
                                       branch_skipped_cached ? branch_skipped_address : ((uint32_t)read_address + 2 + 1),
                                       condition, branch_taken_cached, branch_skipped_cached, false);
        } else {
#endif
          thumb_encode_cond_imm_branch(thread_data, &write_p, basic_block,
                                       target,
                                       ((uint32_t)read_address + 2 + 1),
                                       condition, false, false, false);
#ifdef DBM_LINK_COND_IMM
        }
#endif
        stop = true;
        
        break;
        
      case THUMB_SVC16:
        thumb_sub_sp_i16(&write_p, 2);
        write_p++;

        // PUSH {R0-R12, R14}
        thumb_push_regs(&write_p, 0x5FFF);
        
        copy_to_reg_32bit(&write_p, r8, (uint32_t)read_address + 2 + 1);
        
        thumb_blx32_helper(write_p, thread_data->syscall_wrapper_addr);
        write_p += 2;

        thumb_scanner_deliver_callbacks(thread_data, POST_BB_C, &it_state, &read_address, -1,
                                        &write_p, &data_p, basic_block, type, false, &stop);
        // set the correct address for the PRE_BB_C event
        read_address++;
        thumb_scanner_deliver_callbacks(thread_data, PRE_BB_C, &it_state, &read_address, -1,
                                        &write_p, &data_p, basic_block, type, true, &stop);
        read_address--;
        break;
      
      case THUMB_B16:
        thumb_b16_decode_fields(read_address, &imm1);
        
        branch_offset = (imm1 & 0x400) ? 0xFFFFF000 : 0;
        branch_offset |= imm1 << 1;
        debug("offset: %d\n", branch_offset);
        target = (uint32_t)read_address + 4 + 1 + branch_offset;
        debug("target : 0x%x\n", target);
#ifdef DBM_INLINE_UNCOND_IMM
        if ((target - 1) <= (uint32_t)read_address) {
          if (inline_back_count >= MAX_BACK_INLINE) {
            block_address = lookup_or_stub(thread_data, target);
            thumb_cc_branch(thread_data, write_p, block_address);
            write_p += 2;

            thread_data->code_cache_meta[basic_block].exit_branch_type = trace_inline_max;

            stop = true;
            break;
          } else {
            inline_back_count++;
          }
        }
        /* TODO: handle branches to unmapped addresses cleanly
           This is a hack to avoid trying to elide the b.n 0x7e8c instruction in
           in some versions of ld.so */
        if ((uint32_t)target >= 0x8000) {
          thumb_scanner_deliver_callbacks(thread_data, POST_BB_C, &it_state, &read_address, -1,
                                          &write_p, &data_p, basic_block, type, false, &stop);
          // set the correct address for the PRE_BB_C event
          read_address = (uint16_t *)(target -1);
          thumb_scanner_deliver_callbacks(thread_data, PRE_BB_C, &it_state, &read_address, -1,
                                          &write_p, &data_p, basic_block, type, true, &stop);
          read_address--;
          break;
        }
#endif
        // Mark this as the beggining of code emulating B
        thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_imm_thumb;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
#ifdef DBM_LINK_UNCOND_IMM
        block_address = cc_lookup(thread_data, target);

        if (type == mambo_bb && block_address != UINT_MAX && (target & 0x1)) {
          thumb_cc_branch(thread_data, write_p, block_address);
        } else {
#endif
          thumb_simple_exit(thread_data, &write_p, basic_block, target);
#ifdef DBM_LINK_UNCOND_IMM
        }
#endif
        stop = true;
        break;
        
      // thumb_data_proc_12bit_i_32 instructions that use rn and rd
      case THUMB_ADCI32:
      case THUMB_ADDI32:
      case THUMB_ANDI32:
      case THUMB_BICI32:
      case THUMB_EORI32:
      case THUMB_ORNI32:
      case THUMB_ORRI32:
      case THUMB_RSBI32:
      case THUMB_SBCI32:
      case THUMB_SUBI32:
        thumb_data_proc_12bit_i_32_decode_fields(read_address, &imm1, &opcode, &set_flags, &rn, &imm3, &rdn, &imm8);
        
        assert(rn != pc && rdn != pc);
        copy_thumb_32();
        it_cond_handled = true;

        break;
      // thumb_data_proc_12bit_i_32 instructions that only use rn
      case THUMB_CMNI32:
      case THUMB_CMPI32:
      case THUMB_TEQI32:
      case THUMB_TSTI32:
        thumb_data_proc_12bit_i_32_decode_fields(read_address, &imm1, &opcode, &set_flags, &rn, &imm3, &rdn, &imm8);
        
        assert(rn != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_MOVI32:
        // check if dest is pc
        thumb_movi32_decode_fields(read_address, &imm1, &set_flags, &imm3, &rdn, &imm8);
        debug("MOVI32 rdn: %d, imm: %d\n", rdn, (imm1 << 11) | (imm3) | (imm8));
 
        assert(rdn != pc);
        copy_thumb_32();
        it_cond_handled = true;
        break;
        
      case THUMB_MVNI32:
        thumb_mvni32_decode_fields(read_address, &imm1, &set_flags, &imm3, &rdn, &imm8);
        debug("MVNI32 rdn: %d, imm: %d\n", rdn, (imm1 << 11) | (imm3) | (imm8));
 
        assert(rdn != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_MOVTI32:
        // check if dest is pc
        thumb_movti32_decode_fields(read_address, &imm1, &imm4, &imm3, &rdn, &imm8);
 
        assert(rdn != pc); 
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_MOVWI32:
        // check that dest isn't pc
        thumb_movwi32_decode_fields(read_address, &imm1, &imm4, &imm3, &rdn, &imm8);
        
        assert(rdn != pc);
        copy_thumb_32();
        it_cond_handled = true;

        break;
        
      case THUMB_BFC32:
        thumb_bfc32_decode_fields(read_address, &imm3, &rdn, &imm2, &imm5);
        
        assert(rdn != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_BFI32:
      case THUMB_SBFX32:
      case THUMB_SSAT_LSL32:
      case THUMB_SSAT_ASR32:
      case THUMB_SSAT1632:
      case THUMB_UBFX32:
      case THUMB_USAT_LSL32:
      case THUMB_USAT_ASR32:
      case THUMB_USAT1632:
        thumb_data_proc_bit_field_decode_fields(read_address, &opcode, &rn, &imm3, &rdn, &imm2, &imm5);
        
        assert(rn != pc && rdn != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;

      case THUMB_NOP32:
        copy_thumb_32();
        it_cond_handled = true;
        break;
        
      case THUMB_ADDWI32:
        thumb_addwi32_decode_fields(read_address, &imm1, &rn, &imm3, &rdn, &imm8);
        
        assert(rdn != pc);
        if (rn == pc) {
          modify_in_it_pre(3);
          copy_to_reg_32bit(&write_p, rdn, get_original_pc() + ((imm1 << 11) | (imm3 << 8) | imm8 ));
          modify_in_it_post();
        } else {
          copy_thumb_32();
        }
        it_cond_handled = true;
        
        break;
        
      case THUMB_SUBWI32:
        thumb_subwi32_decode_fields(read_address, &imm1, &rn, &imm3, &rdn, &imm8);
        
        assert(rdn != pc);
        if (rn == pc) {
          modify_in_it_pre(3);
          copy_to_reg_32bit(&write_p, rdn, get_original_pc() - ((imm1 << 11) | (imm3 << 8) | imm8 ));
          modify_in_it_post();
        } else {
          copy_thumb_32();
        }
        it_cond_handled = true;
        
        break;
        
      case THUMB_LDRI32:
      case THUMB_LDRHI32:
      case THUMB_LDRSHI32:
      case THUMB_LDRBI32:
      case THUMB_LDRSBI32:
      case THUMB_LDRT32:
      case THUMB_LDRBT32:
      case THUMB_LDRHT32:
      case THUMB_LDRSBT32:
      case THUMB_LDRSHT32:
        thumb_ldri32_decode_fields(read_address, &rdn, &rn, &imm8, &pre_index, &upwards, &writeback);

        assert(rn != pc);

        if (rdn == pc) {
          thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_thumb;
          thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
        }

        if (rdn != pc) {
          copy_thumb_32();
          it_cond_handled = true;
        } else {
          if (rdn == pc) {
            assert(inst == THUMB_LDRI32);
#ifdef DBM_INLINE_HASH
            if (rn == sp) {
              if (writeback) {
                assert(upwards && pre_index == 0 && (imm8 & 3) == 0 && imm8 >= 4);
                if (imm8 == 4) {
                  thumb_push16(&write_p, (1 << r4) | (1 << r5));
                  write_p++;
                  thumb_ldr_sp16(&write_p, r5, 2);
                  write_p++;
                  thumb_str_sp16(&write_p, r6, 2);
                  write_p++;
                } else { // imm8 > 4
                  thumb_str_sp16(&write_p, r6, (imm8 >> 2) - 1);
                  write_p++;

                  thumb_ldri32(&write_p, r6, sp, imm8 - 4, 0, 1, 1);
                  write_p += 2;

                  thumb_push16(&write_p, (1 << r4) | (1 << r5));
                  write_p++;

                  thumb_movh16(&write_p, r5 >> 4, r6, r5);
                  write_p++;
                }
              } else { // !writeback
                assert(pre_index);

                int offset = (int)imm8;
                if (upwards == 0) {
                  offset = -offset;
                }
                offset += 12;
                upwards = (offset >= 0);
                imm8 = (uint32_t)abs(offset);
                assert(imm8 <= 0xFF);

                thumb_push16(&write_p, (1 << r4) | (1 << r5) | (1 << r6));
                write_p++;

                thumb_ldri32(&write_p, rdn, rn, imm8, pre_index, upwards, writeback);
                write_p += 2;

                while(1);
              }
            } else { // rn != sp
              while(1);
            }

            thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                                   true, IHL_FSPACE, basic_block);
            thumb_inline_hash_lookup(thread_data, &write_p, basic_block, -1);
#else
            scratch_reg = (rn == r0) ? 1 : 0;
            branch_save_context(thread_data, &write_p, false);
            assert(rn != r3);

            if (rn == sp) {
              rn = APP_SP;
            }
            thumb_ldri32(&write_p, r0, rn, imm8, pre_index, upwards, writeback);
            write_p+=2;

            branch_jump(thread_data, &write_p, basic_block, target, SETUP|INSERT_BRANCH);
#endif
            stop = true;
          }
        }
        break;

      case THUMB_LDRWI32:
      case THUMB_LDRHWI32:
      case THUMB_LDRSHWI32:
      case THUMB_LDRBWI32:
      case THUMB_LDRSBWI32:
      case THUMB_STRWI32:
      case THUMB_STRBWI32:
      case THUMB_STRHWI32:
        thumb_strwi32_decode_fields(read_address, &rdn, &rn, &imm1);
        assert(rdn != pc && rn != pc);
        copy_thumb_32();
        it_cond_handled = true;
        break;

      case THUMB_LDRBL32:
      case THUMB_LDRHL32:
      case THUMB_LDRL32:
      case THUMB_LDRSBL32:
      case THUMB_LDRSHL32:
        thumb_load_store_single_reg_imm12_32_decode_fields(read_address, &sign_ext, &upwards,
                                                           &size, &loadstore, &rn, &rdn, &imm1);
        assert(rdn != pc);

        modify_in_it_pre(5);
        copy_to_reg_32bit(&write_p, rdn, get_original_pc() + (upwards ? imm1 : -imm1));
        thumb_load_store_single_reg_imm12_32(&write_p, sign_ext, upwards, size,
                                             loadstore, rdn, rdn, 0);
        write_p += 2;
        modify_in_it_post();

        it_cond_handled = true;
        break;

      case THUMB_PLDI32:
        thumb_load_store_single_reg_imm12_32_decode_fields(read_address, &sign_ext, &upwards, &datasize, &loadstore, &rn, &rdn, &imm1);
        
        assert(rn != pc);
        
        copy_thumb_32();
        
        break;
        
      case THUMB_STRI32:
      case THUMB_STRHI32:
      case THUMB_STRBI32:
      case THUMB_STRT32:
      case THUMB_STRBT32:
      case THUMB_STRHT32:
        // check if src or address is pc
        thumb_load_store_single_reg_imm12_32_decode_fields(read_address, &sign_ext, &upwards, &datasize, &loadstore, &rn, &rdn, &imm1);
        
        debug("STR(B/H)32 sign_ext: %d, upwards: %d, rn: %d, rt: %d, imm: %d\n", sign_ext, upwards, rn, rdn, imm1);
        if (rn != pc && rdn != pc) {      
          copy_thumb_32();
          it_cond_handled = true;
        } else {
          fprintf(stderr, "PC involved\n");
          while(1);
        }

        break;

      case THUMB_LDR32:
      case THUMB_LDRH32:
      case THUMB_LDRSH32:
      case THUMB_LDRB32:
      case THUMB_LDRSB32:
        thumb_load_store_single_reg_off_32_decode_fields(read_address, &sign_ext, &datasize, &loadstore, &rn, &rt, &shift, &rm);
        
        assert(rn != pc && rm != pc);
        
        if (rt == pc) {
          if (inst != THUMB_LDR32) {
            fprintf(stderr, "LDR(S)H/B into PC at %p\n", read_address);
            while(1);
          }

          thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_thumb;
          thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;

          assert(rn != sp && rm != sp);
          uint32_t r_target = r0;
#ifdef DBM_INLINE_HASH
          thumb_push16(&write_p, (1 << r4) | (1 << r5) | (1 << r6));
          write_p++;
          r_target = r5;
#else
          branch_save_context(thread_data, &write_p, true);
#endif
          thumb_ldr32 (&write_p, rn, r_target, shift, rm);
          write_p += 2;

#ifdef DBM_INLINE_HASH
        thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                               true, IHL_FSPACE, basic_block);
          thumb_inline_hash_lookup(thread_data, &write_p, basic_block, -1);
#else
          branch_jump(thread_data, &write_p, basic_block, target, SETUP|INSERT_BRANCH|LATE_APP_SP);
#endif
          stop = true;
        } else {        
          copy_thumb_32();
          it_cond_handled = true;
        }
        
        break;
        
      case THUMB_STR32:
      case THUMB_STRH32:
      case THUMB_STRB32:
        thumb_load_store_single_reg_off_32_decode_fields(read_address, &sign_ext, &datasize, &loadstore, &rn, &rt, &shift, &rm);
        
        assert(rn != pc && rt != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;

        break;
        
      case THUMB_PLD32:
        thumb_load_store_single_reg_off_32_decode_fields(read_address, &sign_ext, &datasize, &loadstore, &rn, &rt, &shift, &rm);
      
        assert(rm != pc && rn != pc);
        copy_thumb_32();
      
        break;
        
      case THUMB_PLDIM32:
        thumb_pld_t2_32_decode_fields(read_address, &sign_ext, &datasize, &load_store, &rn, &rt, &opcode, &imm8);
        
        assert(rn != pc);
        copy_thumb_32();
        
        break;
        
      // data_proc_const_shift instructions that use rn, rd and rm
      case THUMB_ADC32:
      case THUMB_ADD32:
      case THUMB_AND32:
      case THUMB_BIC32:
      case THUMB_EOR32:
      case THUMB_ORN32:
      case THUMB_ORR32:
      case THUMB_PKH32:
      case THUMB_RSB32:
      case THUMB_SBC32:
      case THUMB_SUB32:
        thumb_data_proc_const_shift_decode_fields(read_address, &opcode, &set_flags, &rn, &imm3, &rdn, &imm2, &shift_type, &rm);

        assert(rn != pc && rdn != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;

        break;

      // data_proc_const_shift instructions that use rm and rd
      case THUMB_MOV32:
      case THUMB_LSLI32:
      case THUMB_LSRI32:
      case THUMB_ASRI32:
      case THUMB_RORI32:
        thumb_data_proc_const_shift_decode_fields(read_address, &opcode, &set_flags, &rn, &imm3, &rdn, &imm2, &shift_type, &rm);
        
        assert(rdn != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_RRX32:
        thumb_rrx32_decode_fields(read_address, &set_flags, &rdn, &rm);
        
        assert(rdn != pc && rm != pc);
        copy_thumb_32();
        
        break;
       
      case THUMB_MVN32:
        thumb_mvn32_decode_fields(read_address, &set_flags, &imm3, &rdn, &imm2, &shift_type, &rm);
        
        assert(rdn != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;

      // data_proc_const_shift instructions that use rm and rn
      case THUMB_CMN32:
      case THUMB_CMP32:
      case THUMB_TEQ32:
      case THUMB_TST32:
        thumb_data_proc_const_shift_decode_fields(read_address, &opcode, &set_flags, &rn, &imm3, &rdn, &imm2, &shift_type, &rm);
        
        assert(rn != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_LSL32:
      case THUMB_LSR32:
      case THUMB_ASR32:
      case THUMB_ROR32:
        thumb_data_proc_reg_shift_decode_fields(read_address, &opcode, &set_flags, &rn, &rdn, &opcode2, &rm);
        
        assert(rn != pc && rdn != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_SXTAB32:
      case THUMB_SXTAB1632:
      case THUMB_SXTAH32:
      case THUMB_UXTAB32:
      case THUMB_UXTAB1632:
      case THUMB_UXTAH32:
        thumb_data_proc_sign_zero_ext_decode_fields(read_address, &opcode, &rn, &rdn, &rotate, &rm);
        
        assert(rdn != pc && rm != pc && rn != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_SXTB32:
      case THUMB_SXTB1632:
      case THUMB_SXTH32:
      case THUMB_UXTB32:
      case THUMB_UXTB1632:
      case THUMB_UXTH32:
        thumb_data_proc_sign_zero_ext_decode_fields(read_address, &opcode, &rn, &rdn, &rotate, &rm);
        
        assert(rdn != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;

      case THUMB_SIMD_ADD_SUB32:
        thumb_simd_add_sub32_decode_fields(read_address, &opcode, &rn, &rdn, &opcode2, &rm);
        
        assert(rn != pc && rdn != pc && rm != pc);
        copy_thumb_32();

        break;
        
      case THUMB_CLZ32:
      case THUMB_QADD32:
      case THUMB_QDADD32:
      case THUMB_QDSUB32:
      case THUMB_QSUB32:
      case THUMB_RBIT32:
      case THUMB_REV32:
      case THUMB_REV1632:
      case THUMB_REVSH32:
      case THUMB_SEL32:
        thumb_data_proc_other_3reg_decode_fields(read_address, &opcode, &rn, &rdn, &opcode2, &rm);
        
        assert(rn != pc && rdn != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
      
      case THUMB_MLA32:
      case THUMB_MLS32:
      case THUMB_SMMLA32:
      case THUMB_SMMLS32:
        thumb_data_proc_32_mult_decode_fields(read_address, &opcode, &rn, &racc, &rdn, &opcode2, &rm);
        
        assert(rn != pc && racc != pc && rdn != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_MUL32:
        thumb_mul32_decode_fields(read_address, &rn, &rdn, &rm);
        
        assert(rn != pc && rdn != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;

      case THUMB_SMLAD32:
      case THUMB_SMLSD32:
      case THUMB_USADA832:
      case THUMB_SMLABB32:
        thumb_data_proc_rd_rn_rm_ra_decode_fields(read_address, &rdn, &rn, &rm, &racc);

        assert(rn != pc && rdn != pc && rm != pc && racc != pc);
        copy_thumb_32();
        it_cond_handled = true;

        break;

      // data proc with rd, rn, rm
      case THUMB_SMUSD32:
      case THUMB_USAD832:
      case THUMB_SMMUL32:
      case THUMB_SMUAD32:
      case THUMB_UADD832:
      case THUMB_UQSUB832:
      case THUMB_SMULBB32:
        thumb_data_proc_rd_rn_rm_decode_fields(read_address, &rdn, &rn, &rm);
        
        assert(rdn != pc && rn != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_SMULL32:
        thumb_smull32_decode_fields(read_address, &rn, &rdlo, &rdhi, &rm);
        
        assert(rn != pc && rdlo != pc && rdhi != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_UMULL32:
        thumb_umull32_decode_fields(read_address, &rn, &rdlo, &rdhi, &rm);
        
        assert(rn != pc && rdlo != pc && rdhi != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;

      case THUMB_SDIV32:
      case THUMB_UDIV32:
        thumb_data_proc_64_mult_decode_fields(read_address, &opcode, &rn, &rdlo, &rdhi, &opcode2, &n_high, &m_swap, &rm);
        
        assert(rn != pc && rdhi != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;

        break;

      case THUMB_SMLAL32:
      case THUMB_SMLALD32:
      case THUMB_SMLSLD32:
      case THUMB_UMLAL32:
      case THUMB_UMAAL32:
        thumb_data_proc_64_mult_decode_fields(read_address, &opcode, &rn, &rdlo, &rdhi, &opcode2, &n_high, &m_swap, &rm);
        
        assert(rn != pc && rdlo != pc && rdhi != pc && rm != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;

      case THUMB_B32:
      case THUMB_BL32:
      case THUMB_BL_ARM32:
        thumb_branch32_decode_fields(read_address, &sign_bit, &offset_high, &link, &j1, &thumb_arm, &j2, &offset_low);
        debug("B32/BL32/BL_ARM32 sign_bit: %d, j1: %d, j2: %d, offset_high 0x%x, offset_low 0x%x\n",
              sign_bit, j1, j2, offset_high, offset_low);

        branch_offset = sign_bit ? 0xFF000000 : 0;
        branch_offset |= (j1 ^ sign_bit) ? 0 : 1 << 23;
        branch_offset |= (j2 ^ sign_bit) ? 0: 1 << 22;
        branch_offset |= offset_high << 12;
        branch_offset |= offset_low << 1;

        debug("branch_offset = 0x%x\n", branch_offset);

        if (link_bx_alt(thread_data, &write_p, it_state.cond_inst_after_it, (uint32_t)read_address + 5)) {
          it_cond_handled = true;
        }

        // Seems ok, but keep an eye on this
        target = (uint32_t)read_address + branch_offset + 4 + 1;
        if(inst == THUMB_BL_ARM32) target &= 0xFFFFFFFC;
        debug("branch_target = 0x%x\n", target);

        // Set the link register
        if (inst != THUMB_B32) {
          copy_to_reg_32bit(&write_p, lr, ((uint32_t)read_address) + 4 + 1);
        }

#ifdef DBM_INLINE_UNCOND_IMM
        if (inst != THUMB_BL_ARM32 && (type == mambo_trace || type == mambo_trace_entry)) {
          if ((target - 1) <= (uint32_t)read_address) {
            if (inline_back_count >= MAX_BACK_INLINE) {
              block_address = lookup_or_stub(thread_data, target);
              thumb_cc_branch(thread_data, write_p, block_address);
              write_p += 2;

              thread_data->code_cache_meta[basic_block].exit_branch_type = trace_inline_max;

              stop = true;
              break;
            } else {
              inline_back_count++;
            }
          }

          thumb_scanner_deliver_callbacks(thread_data, POST_BB_C, &it_state, &read_address, -1,
                                          &write_p, &data_p, basic_block, type, false, &stop);
          // set the correct address for the PRE_BB_C event
          read_address = (uint16_t *)(target - 1);
          thumb_scanner_deliver_callbacks(thread_data, PRE_BB_C, &it_state, &read_address, -1,
                                          &write_p, &data_p, basic_block, type, true, &stop);
          read_address -= 2;
        } else {
#endif
          thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                                 true, DISP_CALL_SIZE, basic_block);

          if (inst == THUMB_BL_ARM32) {
            thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_blxi_thumb;
          } else {
            thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_imm_thumb;
          }
          thread_data->code_cache_meta[basic_block].branch_taken_addr = target;
          thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
#ifdef DBM_LINK_UNCOND_IMM
          block_address = cc_lookup(thread_data, target);
          if (type == mambo_bb && block_address != UINT_MAX && (target & 0x1)) {
            debug("Found block for 0x%x at 0x%x\n", target, block_address);
            thumb_cc_branch(thread_data, write_p, block_address);
          } else {
#endif
            thumb_simple_exit(thread_data, &write_p, basic_block, target);
#ifdef DBM_LINK_UNCOND_IMM
          }
#endif
          stop = true;
#ifdef DBM_INLINE_UNCOND_IMM
        }
#endif

        break;
      case THUMB_B_COND32:
        // Warning: at some point we might want to restore the values of any scratch registers here
        thumb_b_cond32_decode_fields(read_address, &sign_bit, &condition, &offset_high, &j1, &j2, &offset_low);
        debug("B_COND32: sign_bit %d, j2: %d, j1: %d, offset_high: %x, offset_low %x\n", sign_bit, j2, j1, offset_high, offset_low);
        branch_offset = sign_bit ? 0xFFF00000 : 0;
        branch_offset |= j2 << 19;
        branch_offset |= j1 << 18;
        branch_offset |= offset_high << 12;
        branch_offset |= offset_low << 1;

        debug("branch_offset = %d\n", branch_offset);

        // Seems ok, but keep an eye on this
        target = (uint32_t)read_address + branch_offset + 4 + 1;
        debug("Computed target: 0x%x\n", target);

        thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                               true, IMM_SIZE, basic_block);

        // Mark this as the beggining of code emulating B
        thread_data->code_cache_meta[basic_block].exit_branch_type = cond_imm_thumb;
        thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
        thread_data->code_cache_meta[basic_block].branch_taken_addr = target;
        thread_data->code_cache_meta[basic_block].branch_skipped_addr = (uint32_t)read_address + 4 + 1;
        thread_data->code_cache_meta[basic_block].branch_condition = condition;

#ifdef DBM_LINK_COND_IMM
        if (type == mambo_bb) {
          if (target & 0x1) {
            branch_taken_address = cc_lookup(thread_data, target);
            branch_taken_cached = (branch_taken_address != UINT_MAX);
          } else {
            branch_taken_cached = false;
          }
          branch_skipped_address = cc_lookup(thread_data, (uint32_t)read_address + 4 + 1);
          branch_skipped_cached = (branch_skipped_address != UINT_MAX);

          thumb_encode_cond_imm_branch(thread_data, &write_p, basic_block,
                                       branch_taken_cached ? branch_taken_address : target,
                                       branch_skipped_cached ? branch_skipped_address : ((uint32_t)read_address + 4 + 1),
                                       condition, (branch_taken_address != UINT_MAX), (branch_skipped_address != UINT_MAX), false);
        } else {
#endif
          thumb_encode_cond_imm_branch(thread_data, &write_p, basic_block,
                                       target,
                                       ((uint32_t)read_address + 4 + 1),
                                       condition, false, false, false);
#ifdef DBM_LINK_COND_IMM
        }
#endif
        
        stop = true;
        
        //while(1);
        break;
        
      case THUMB_DSB32:
      case THUMB_DMB32:
      case THUMB_ISB32:
      case THUMB_CLREX32:
        copy_thumb_32();
        break;

      case THUMB_MSR32:
        thumb_msr32_decode_fields(read_address, &rn, &mask);
        assert(rn != pc);
        copy_thumb_32();
        break;

      case THUMB_MRS32:
        thumb_mrs32_decode_fields(read_address, &rdn);
        assert(rdn != pc);
        copy_thumb_32();
        break;
        
      case THUMB_LDRD32:
        thumb_ldrd32_decode_fields(read_address, &pre_index, &upwards, &writeback, &rn, &rt, &rdn, &imm8);
        assert(rt != pc && rdn != pc);

        if (rn == pc) {
          assert(pre_index == 1 && writeback == 0);
          imm8 <<= 2;
          uint32_t addr = get_original_pc() + (upwards ? imm8 : -imm8);
          modify_in_it_pre(5);
          copy_to_reg_32bit(&write_p, rdn, addr);
          thumb_ldrd32(&write_p, 1, 1, 0, rdn, rt, rdn, 0);
          write_p += 2;
          modify_in_it_post();
        } else {
          copy_thumb_32();
        }
        it_cond_handled = true;
        break;

      case THUMB_STRD32:
        thumb_strd32_decode_fields(read_address, &pre_index, &upwards, &writeback, &rn, &rt, &rdn, &imm8);
        
        assert(rn != pc && rt != pc && rdn != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_LDREX32:
      case THUMB_STREX32:
        switch(inst) {
          case THUMB_LDREX32:
            thumb_ldrex32_decode_fields(read_address, &rn, &rt, &imm8);
            ldrex = true;
            rdn = 0;
            break;
          case THUMB_STREX32:
            thumb_strex32_decode_fields(read_address, &rn, &rt, &rdn, &imm8);
            ldrex = false;
            break;
        }
        
        assert(rn != pc && rt != pc && rdn != pc);
        copy_thumb_32();
        it_cond_handled = true;
        
        break;
        
      case THUMB_LDREXB32:
      case THUMB_LDREXH32:
      case THUMB_STREXB32:
      case THUMB_STREXH32:
        thumb_strexb32_decode_fields(read_address, &rn, &rt, &rdn);
        assert(rn != pc && rt != pc);
        if (inst == THUMB_STREXB32 || inst == THUMB_STREXH32) {
          assert(rdn != pc);
          ldrex = false;
        } else {
          ldrex = true;
        }
        copy_thumb_32();
        it_cond_handled = true;

        break;

      case THUMB_LDREXD32:
      case THUMB_STREXD32:
        thumb_strexd32_decode_fields(read_address, &rn, &rt, &rt2, &rdn);
        assert(rn != pc && rt != pc && rt2 != pc);
        if (inst == THUMB_STREX32) assert(rdn != pc);
        ldrex = (inst == THUMB_STREXD32);
        copy_thumb_32();
        it_cond_handled = true;

        break;

      case THUMB_TBB32:
      case THUMB_TBH32:
        // Branch to PC + [value from rn + rm << 1]
        thumb_tbh32_decode_fields(read_address, &rn, &rm);
        assert(rm != pc);
        assert(rn != sp && rm != sp);
        
        scratch_reg = r0;
        while (rn == scratch_reg || rm == scratch_reg) {
          scratch_reg++;
        }
        scratch_reg2 = scratch_reg+1;
        while (rn == scratch_reg2 || rm == scratch_reg2) {
          scratch_reg2++;
        }
        assert(scratch_reg2 <= 2);

#ifdef DBM_TRACES
        if (type == mambo_trace || type == mambo_trace_entry) {
#endif
          thread_data->code_cache_meta[basic_block].exit_branch_type = (inst == THUMB_TBB32) ? tbb : tbh;
#ifdef DBM_TRACES
        } else {
          thread_data->code_cache_meta[basic_block].exit_branch_type = tb_indirect;
        }
#endif
        thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;

#ifdef DBM_TB_DIRECT
        if (rn == pc) {
          debug("TB: w: %p r: %p, BB: %d\n", write_p, read_address, basic_block);

  #ifndef DBM_TRACES
          // At least two consecutive BBs are needed
          assert(thread_data->free_block == basic_block+1);
          /*basic_block = */thread_data->free_block++;
          data_p += BASIC_BLOCK_SIZE;
          thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                                 true, 472, basic_block);
  #else
          if (type == mambo_trace || type == mambo_trace_entry) {
  #endif
            thread_data->code_cache_meta[basic_block].rn = INT_MAX;
            thread_data->code_cache_meta[basic_block].free_b = 0;

  #ifdef FAST_BT
            thumb_cmpi32 (&write_p, 0, rm, 0, TB_CACHE_SIZE-1);
  #else
            thumb_cmpi32 (&write_p, 0, rm, 0, MAX_TB_INDEX-1);
  #endif
            write_p += 2;
            thumb_it16(&write_p, HI, 8);
            write_p++;
  #if defined(DBM_D_INLINE_HASH) && !defined(TB_STATS)
    #ifdef FAST_BT
            thumb_b32_helper(write_p, (uint32_t)write_p + TB_CACHE_SIZE*4 + 16 + (((uint32_t)write_p & 2) ? 0 : 2));
    #else
            thumb_b32_helper(write_p, (uint32_t)write_p + MAX_TB_INDEX + TB_CACHE_SIZE*4 + 10);
    #endif
  #else
    #ifdef FAST_BT
            thumb_b32_helper(write_p, (uint32_t)write_p + TB_CACHE_SIZE*4 + 14 + (((uint32_t)write_p & 2) ? 0 : 2));
    #else
            thumb_b32_helper(write_p, (uint32_t)write_p + MAX_TB_INDEX + TB_CACHE_SIZE*4 + 8);
    #endif
  #endif
            write_p += 2;

  #ifdef FAST_BT
            thumb_bx16(&write_p, pc);
            write_p++;

            if (((uint32_t)write_p) & 2) {
              write_p++;
            }
            arm_ldr((uint32_t **)&write_p, LDR_REG, pc, pc, (LSL << 5) | (2 << 7) | rm, 1, 1, 0);
            write_p += 2;
  #else
            thumb_tbb32(&write_p, pc, rm);
            write_p += 2;
  #endif

  #ifdef FAST_BT
            *write_p = 0;
            write_p++;
            *write_p = 0;
            write_p++;
            for (int i = 0; i < TB_CACHE_SIZE; i++) {
              *(uint32_t *)write_p = (uint32_t)write_p + ((TB_CACHE_SIZE -i) * 4) + 1;
              write_p += 2;
            }
  #else
            // Initially all indexes go to the slow dispatcher
            for (int i = 0; i < MAX_TB_INDEX/2; i++) {
              *write_p = (MAX_TB_INDEX/2 + TB_CACHE_SIZE*2);
              *write_p |= *write_p << 8;
              write_p++;
            }
            
            for (int i = 0; i < TB_CACHE_SIZE; i++) {
              thumb_b32_helper(write_p, (uint32_t)write_p + (TB_CACHE_SIZE -i) * 4);
              write_p += 2;
            }
  #endif
#endif // DBM_TB_DIRECT
#if defined(DBM_D_INLINE_HASH) && defined(DBM_TB_DIRECT)
            thumb_b16(&write_p, ((uint32_t)write_p) & 2 ? 61 : 60);
            write_p++;
#endif
#if defined(DBM_TB_DIRECT) && defined (DBM_TRACES)
          }
#endif
#ifdef DBM_D_INLINE_HASH
          sr[0] = 3;
          while (sr[0] == rn || sr[0] == rm) {
            sr[0]++;
          }
          
          sr[1] = sr[0] + 1;
          while (sr[1] == rn || sr[1] == rm) {
            sr[1]++;
          }
          
          sr[2] = sr[1] + 1;
          while (sr[2] == rn || sr[2] == rm) {
            sr[2]++;
          }
          
          reglist = (1 << sr[0]) | (1 << sr[1]) | (1 << sr[2]);
          thumb_push16(&write_p, reglist);
          write_p++;

          thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                                 true, 118, basic_block);
   
          if (rn == pc) {
            copy_to_reg_32bit(&write_p, sr[1], (uint32_t)read_address + 4);
            rn = sr[1];
          }
          
          if (inst == THUMB_TBB32) {
            thumb_ldrb32(&write_p, rn, sr[0], 0, rm);
          } else {
            thumb_ldrh32(&write_p, rn, sr[0], 1, rm);
          }
          write_p += 2;
          
          thumb_add32(&write_p, 0, sr[1], 0, sr[1], 1,  LSL, sr[0]);
          write_p+=2;
          thumb_addi32 (&write_p, 0, 0,	sr[1], 0, sr[0], 1);
          write_p+=2;

          thumb_inline_hash_lookup(thread_data, &write_p, basic_block, sr[0], sr[1], sr[2], reglist, false, 4);

          ihl_result_branch(thread_data, IHL_BRANCH_LDR_PC_PC, &write_p, reglist, sr, false, 4);
          
          rn = pc;

  #ifdef DBM_TRACES
          if (type == mambo_bb) {
            stop = true;
            break;
          }
  #endif
#endif // DBM_D_INLINE_HASH
#ifdef DBM_TB_DIRECT
        }
#endif
        assert(rn == pc);

        branch_save_context(thread_data, &write_p, true);

        // Save the index for use by the TB linker
        copy_to_reg_32bit(&write_p, scratch_reg, (uint32_t)&thread_data->code_cache_meta[basic_block].rn);
        thumb_strwi32(&write_p, rm, scratch_reg, 0);
        write_p += 2;
 
        copy_to_reg_32bit(&write_p, scratch_reg, (uint32_t)read_address + 4);
        if (rn == pc) {
          rn = scratch_reg;
        }
        
        // load into R1, from rn + rm << 1
        if (inst == THUMB_TBB32) {
          thumb_ldrb32(&write_p, rn, scratch_reg2, 0, rm);
        } else {
          thumb_ldrh32(&write_p, rn, scratch_reg2, 1, rm);
        }
        write_p += 2;
        
        thumb_add32(&write_p, 0, scratch_reg, 0, scratch_reg, 1,  LSL, scratch_reg2);
        write_p+=2;
        thumb_addi32 (&write_p, 0, 0,	scratch_reg, 0, r0, 1);
        write_p+=2;

        branch_jump(thread_data, &write_p, basic_block, 0, SETUP|INSERT_BRANCH|LATE_APP_SP);

        stop = true;
        
        break;

      case THUMB_STMEA32:        
      case THUMB_STMFD32:
        thumb_load_store_multiple32_decode_fields(read_address, &opcode, &writeback, &load_store, &rn, &reglist);
        assert(rn != pc);
        assert((reglist & (1 << pc)) == 0);
        
        copy_thumb_32();
        it_cond_handled = true;
        break;
        
      case THUMB_LDMFD32:
      case THUMB_LDMEA32:
        thumb_load_store_multiple32_decode_fields(read_address, &opcode, &writeback, &load_store, &rn, &reglist);
        assert(rn != pc && (!writeback || (reglist & (1 << rn)) == 0));

        if (reglist & (1<<pc)) {
          if (link_bx_alt(thread_data, &write_p, it_state.cond_inst_after_it, (uint32_t)read_address + 5)) {
            it_cond_handled = true;
          }

          assert(writeback);
          if (reglist & 0x7FFF) {
            thumb_load_store_multiple32(&write_p, opcode, writeback, load_store, rn, reglist & 0x7FFF);
            write_p += 2;
          }

          thread_data->code_cache_meta[basic_block].exit_branch_type = uncond_reg_thumb;
          thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;

#ifdef DBM_INLINE_HASH
          if (rn == sp) {
            assert(inst == THUMB_LDMFD32);

            thumb_push16(&write_p, (1 << r4) | (1 << r5));
            write_p++;
            thumb_ldr_sp16(&write_p, r5, 2);
            write_p++;
            thumb_str_sp16(&write_p, r6, 2);
            write_p++;
          } else {
            thumb_push16(&write_p, (1 << r4) | (1 << r5) | (1 << r6));
            write_p++;

            thumb_load_store_multiple32(&write_p, opcode, writeback, load_store, r0, reglist);
            write_p += 2;
          }
          thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                                 true, IHL_FSPACE, basic_block);
          thumb_inline_hash_lookup(thread_data, &write_p, basic_block, -1);
#else
          branch_save_context(thread_data, &write_p, false);
          assert(rn != r3);
          if (rn == sp) {
            rn = APP_SP;
          }
          thumb_load_store_multiple32(&write_p, opcode, writeback, load_store, rn, 1 << 0);
          write_p+=2;
          branch_jump(thread_data, &write_p, basic_block, 0, SETUP|INSERT_BRANCH);
#endif
          stop = true;
        } else {
          if (inst == THUMB_LDMFD32 && writeback && rn == sp) {
            set_inst_pop_regs = write_p;
            inst_pop_regs_data = data_p;
            poped_regs = reglist;
          }
          
          copy_thumb_32();
          it_cond_handled = true;
        }

        break;
      
      case THUMB_MCR32:
        thumb_mcr32_decode_fields(read_address, &opc1, &crn, &rt, &coproc, &opc2, &crm);

        assert(rt != pc);
        copy_thumb_32();

        break;
      case THUMB_MRC32:
        thumb_mrc32_decode_fields(read_address, &opc1, &crn, &rt, &coproc, &opc2, &crm);

        if (coproc == 15 && opc1 == 0 && crn == 13 && crm == 0 && opc2 == 3) {
          //fprintf(stderr, "Read TPIDRURO into R%d\n", rt);
          assert(rt != pc);

          modify_in_it_pre(5);
          copy_to_reg_32bit(&write_p, rt, (uint32_t)(&thread_data->tls));
          thumb_ldrwi32(&write_p, rt, rt, 0);
          write_p+=2;
          modify_in_it_post();
        } else if (opc1 == 0b111 && crn == 0b0001 && coproc == 0b1010) {
          // This instruction transfers the FPSCR.{N, Z, C, V} condition flags to the APSR.{N, Z, C, V} condition flags.
          copy_thumb_32();
        } else {
          assert(rt != pc);
          copy_thumb_32();
        }
        it_cond_handled = true;
        
        break;
        
      /* NEON and VFP instructions which might access the PC */
      case THUMB_VFP_VLDM_DP:
      case THUMB_VFP_VLDM_SP:
      case THUMB_VFP_VSTM_DP:
      case THUMB_VFP_VSTM_SP:
        thumb_vfp_ld_st_m_decode_fields(read_address, &p, &upwards, &writeback, &rn, &d, &vd, &imm8);
        assert(rn != pc);
        copy_thumb_32();
        it_cond_handled = true;
        break;
        
      case THUMB_VFP_VLDR_DP:
      case THUMB_VFP_VLDR_SP:
      case THUMB_VFP_VSTR_DP:
      case THUMB_VFP_VSTR_SP:
        thumb_vfp_vldr_vstr_decode_fields(read_address, &upwards, &rn, &d, &vd, &imm8);
        
        if(rn == pc) {
          modify_in_it_pre(7);

          thumb_push16(&write_p, 1 << r0);
          write_p++;

          copy_to_reg_32bit(&write_p, r0, get_original_pc());

          switch(inst) {
            case THUMB_VFP_VLDR_DP:
              thumb_vfp_vldr_dp(&write_p, upwards, r0, d, vd, imm8);
              break;
            case THUMB_VFP_VLDR_SP:
              thumb_vfp_vldr_sp(&write_p, upwards, r0, d, vd, imm8);
              break;
            default:
              fprintf(stderr, "inst: %d unimplemented\n", inst);
              while(1);
          }
          write_p += 2;

          thumb_pop16(&write_p, 1 << r0);
          write_p++;

          modify_in_it_post();
        } else {
          copy_thumb_32();
        }

        it_cond_handled = true;
        break;

      case THUMB_VFP_VMOV_CORE_SP:
        thumb_vfp_vmov_core_sp_decode_fields(read_address, &opcode, &rt, &n, &vn);
        assert(rt != pc);
        copy_thumb_32();
        it_cond_handled = true;
        break;

      case THUMB_VFP_VMOV_2CORE_DP:
        thumb_vfp_vmov_2core_dp_decode_fields(read_address, &to_arm, &rt, &rt2, &m, &vm);
        assert(rt != pc && rt2 != pc);
        copy_thumb_32();
        it_cond_handled = true;
        break;

      case THUMB_VFP_VMSR:
        thumb_vfp_vmsr_decode_fields(read_address, &rt);
        assert(rt != pc);
        copy_thumb_32();
        it_cond_handled = true;
        break;

      case THUMB_NEON_VDUP_CORE: {
        uint32_t b, e, q;
        thumb_neon_vdup_core_decode_fields(read_address, &b, &e, &q, &d, &vd, &rt);
        assert(rt != pc);
        copy_thumb_32();
        it_cond_handled = true;
        break;
      }

      case THUMB_NEON_VLDX_S_O:
      case THUMB_NEON_VSTX_S_O:
      case THUMB_NEON_VLDX_S_A:
      case THUMB_NEON_VLDX_M:
      case THUMB_NEON_VSTX_M: {
        thumb_neon_vstx_m_decode_fields(read_address, &opcode, &size, &d, &vd, &rn, &align, &rm);
        assert(rn != pc); // rm == pc has a special meaning, doesn't actually use the PC
        copy_thumb_32();
        it_cond_handled = true;
        break;
      }

      case THUMB_VFP_VMOV_CORE_SCAL:
        thumb_vfp_vmov_core_scal_decode_fields(read_address, &d, &vd, &opc1, &opc2, &rt);
        assert(rt != pc);
        copy_thumb_32();
        it_cond_handled = true;
        break;

      /* NEON and VFP instructions which can't access the PC */
      case THUMB_NEON_VABD_I:
      case THUMB_NEON_VADD_I:
      case THUMB_NEON_VADDL:
      case THUMB_NEON_VADDW:
      case THUMB_NEON_VAND:
      case THUMB_NEON_VBIC:
      case THUMB_NEON_VBSL:
      case THUMB_NEON_VCEQ_I:
      case THUMB_NEON_VCGT_I:
      case THUMB_NEON_VCLTZ:
      case THUMB_NEON_VDUP_SCAL:
      case THUMB_NEON_VEOR:
      case THUMB_NEON_VEXT:
      case THUMB_NEON_VHADD:
      case THUMB_NEON_VMAX_I:
      case THUMB_NEON_VMIN_I:
      case THUMB_NEON_VMLAL_I:
      case THUMB_NEON_VMLA_SCAL:
      case THUMB_NEON_VMLS_SCAL:
      case THUMB_NEON_VMOVI:
      case THUMB_NEON_VMOVL:
      case THUMB_NEON_VMOVN:
      case THUMB_NEON_VMUL_I:
      case THUMB_NEON_VMULL_I:
      case THUMB_NEON_VMUL_SCAL:
      case THUMB_NEON_VMVN:
      case THUMB_NEON_VNEG:
      case THUMB_NEON_VORN:
      case THUMB_NEON_VORR:
      case THUMB_NEON_VPADD_I:
      case THUMB_NEON_VPADDL:
      case THUMB_NEON_VQADD:
      case THUMB_NEON_VQMOVN:
      case THUMB_NEON_VQMOVUN:
      case THUMB_NEON_VQRSHRUN:
      case THUMB_NEON_VQSHRUN:
      case THUMB_NEON_VQSUB:
      case THUMB_NEON_VREV32:
      case THUMB_NEON_VREV64:
      case THUMB_NEON_VRHADD:
      case THUMB_NEON_VRSHR:
      case THUMB_NEON_VRSHRN:
      case THUMB_NEON_VSHL:
      case THUMB_NEON_VSHLI:
      case THUMB_NEON_VSHLL:
      case THUMB_NEON_VSHR:
      case THUMB_NEON_VSHRN:
      case THUMB_NEON_VSLI:
      case THUMB_NEON_VSUB_I:
      case THUMB_NEON_VSUBL:
      case THUMB_NEON_VSUBW:
      case THUMB_NEON_VSWP:
      case THUMB_NEON_VTRN:
      case THUMB_NEON_VTST:
      case THUMB_VFP_VABS:
      case THUMB_VFP_VADD:
      case THUMB_VFP_VCMP:
      case THUMB_VFP_VCMPE:
      case THUMB_VFP_VCMPEZ:
      case THUMB_VFP_VCMPZ:
      case THUMB_VFP_VCVT_DP_SP:
      case THUMB_VFP_VCVT_F_FP:
      case THUMB_VFP_VCVT_F_I:
      case THUMB_VFP_VDIV:
      case THUMB_VFP_VMLA_F:
      case THUMB_VFP_VMLS_F:
      case THUMB_VFP_VMOV:
      case THUMB_VFP_VMOVI:
      case THUMB_VFP_VMRS: // rt=0xF is CPSR
      case THUMB_VFP_VMUL:
      case THUMB_VFP_VNEG:
      case THUMB_VFP_VNMLA:
      case THUMB_VFP_VNMLS:
      case THUMB_VFP_VNMUL:
      case THUMB_VFP_VPOP:
      case THUMB_VFP_VPUSH:
      case THUMB_VFP_VSQRT:
      case THUMB_VFP_VSUB:
        copy_thumb_32();
        it_cond_handled = true;
        break;

      case THUMB_INVALID:
      default:
        if (read_address != start_scan) {
          thumb_b32_helper(write_p, lookup_or_stub(thread_data, (uint32_t)read_address + 1));
          stop = true;
          it_cond_handled = true; // If execution actually reached this inst, something is broken anyway
          fprintf(stderr, "WARN: deferred scanning because of unknown instruction at: %p\n", read_address);
          break;
        } else {
          fprintf(stderr, "Unknown thumb instruction: %d at %p\n", inst, read_address);
          while(1);
          exit(EXIT_FAILURE);
       }
    }
    
    if (it_state.cond_inst_after_it > 0) {
      if(!it_cond_handled) {
        fprintf(stderr, "Didn't handle instruction-after IT at %p, inst: %d\n", read_address, inst);
        while(1);
        //exit(EXIT_FAILURE);
      }
      do_it_iter(&it_state);
    }
#ifdef PLUGINS_NEW
    } // if(!skip_inst)
#endif
    
    if ((uint16_t *)data_p <= write_p) {
      fprintf(stderr, "%d, inst: %p, :write: %p\n", inst, data_p, write_p);
      while(1);
    }
    
    if (!stop) {
      thumb_check_free_space(thread_data, &write_p, &data_p, &it_state,
                             true, MIN_FSPACE, basic_block);
    }
    debug("\n");
#ifdef PLUGINS_NEW
    thumb_scanner_deliver_callbacks(thread_data, POST_INST_C, &it_state, &read_address, inst, &write_p,
                                    &data_p, basic_block, type, !stop, &stop);
#endif

    if (inst < THUMB_ADC32) {
      read_address++;
    } else {
      read_address+= 2;
    }
  }

  if (ldrex) {
    if (thread_data->code_cache_meta[basic_block].exit_branch_type != uncond_imm_thumb
        && thread_data->code_cache_meta[basic_block].exit_branch_type != cond_imm_thumb
        && thread_data->code_cache_meta[basic_block].exit_branch_type != cbz_thumb) {
      fprintf(stderr, "WARN: Basic block containing LDREX and no matching STREX "
                      "ends with branch type that can not be directly linked\n");
    }
  }
  
  // We haven't strictly enforced updating write_p after the last instruction
  return ((uint32_t)write_p - start_address + 4);
}

void thumb_encode_stub_bb(dbm_thread *thread_data, int basic_block, uint32_t target) {
  uint16_t *write_p = (uint16_t *)&thread_data->code_cache->blocks[basic_block];
  uint32_t *data_p = (uint32_t *)write_p;
  data_p += BASIC_BLOCK_SIZE;

  thumb_pop16(&write_p, (1 << r5) | (1 << r6));
  write_p++;

  thumb_simple_exit(thread_data, &write_p, basic_block, target);
}

#endif // __arm__
