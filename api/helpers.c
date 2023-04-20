/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2017-2023 The University of Manchester

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
#include <stdarg.h>
#include "../plugins.h"
#ifdef __arm__
#include "../pie/pie-thumb-encoder.h"
#elif __aarch64__
#include "../pie/pie-a64-encoder.h"
#include "../api/emit_a64.h"
#elif __riscv
#include "../pie/pie-riscv-encoder.h"
#include "../api/emit_riscv.h"
#endif

#define not_implemented() \
  fprintf(stderr, "%s: Implement me\n", __PRETTY_FUNCTION__); \
  while(1);

#ifdef __arm__
void emit_thumb_push_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  uint16_t *write_p = ctx->code.write_p;

  // MRS tmp_reg, CPSR
  thumb_mrs32(&write_p, tmp_reg);
  write_p += 2;

  // PUSH {tmp_reg}
  thumb_push_regs(&write_p, 1 << tmp_reg);

  ctx->code.write_p = write_p;
}

void emit_arm_push_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  emit_arm_mrs(ctx, tmp_reg);
  emit_arm_push(ctx, 1 << tmp_reg);
}

void emit_thumb_pop_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  uint16_t *write_p = ctx->code.write_p;

  // POP {tmp_reg}
  thumb_pop_regs(&write_p, 1 << tmp_reg);

  // MSR tmp_reg, CPSR_fs
  thumb_msr32(&write_p, tmp_reg, 3);
  write_p += 2;

  ctx->code.write_p = write_p;
}

void emit_arm_pop_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  emit_arm_pop(ctx, 1 << tmp_reg);
  emit_arm_msr(ctx, tmp_reg, 3);
}

void emit_thumb_copy_to_reg_32bit(mambo_context *ctx, enum reg reg, uint32_t value) {
  if (value <= 0xFFFF) {
    copy_to_reg_16bit((uint16_t **)&ctx->code.write_p, reg, value);
  } else {
    copy_to_reg_32bit((uint16_t **)&ctx->code.write_p, reg, value);
  }
}

void emit_arm_copy_to_reg_32bit(mambo_context *ctx, enum reg reg, uint32_t value) {
  if (value <= 0xFFFF) {
    arm_copy_to_reg_16bit((uint32_t **)&ctx->code.write_p, reg, value);
  } else {
    arm_copy_to_reg_32bit((uint32_t **)&ctx->code.write_p, reg, value);
  }
}

void emit_thumb_b16_cond(void *write_p, void *target, mambo_cond cond) {
  thumb_b16_cond_helper((uint16_t *)write_p, (uint32_t)target, cond);
}

void emit_thumb_push(mambo_context *ctx, uint32_t regs) {
  ctx->code.plugin_pushed_reg_count += count_bits(regs);

  uint16_t *write_p = ctx->code.write_p;
  thumb_push_regs(&write_p, regs);
  ctx->code.write_p = write_p;
}

void emit_arm_push(mambo_context *ctx, uint32_t regs) {
  ctx->code.plugin_pushed_reg_count += count_bits(regs);

  uint32_t *write_p = ctx->code.write_p;
  arm_push_regs(regs);
  ctx->code.write_p = write_p;
}

void emit_thumb_pop(mambo_context *ctx, uint32_t regs) {
  ctx->code.plugin_pushed_reg_count -= count_bits(regs);
  assert(ctx->code.plugin_pushed_reg_count >= 0);

  uint16_t *write_p = ctx->code.write_p;
  thumb_pop_regs(&write_p, regs);
  ctx->code.write_p = write_p;
}

void emit_arm_pop(mambo_context *ctx, uint32_t regs) {
  ctx->code.plugin_pushed_reg_count -= count_bits(regs);
  assert(ctx->code.plugin_pushed_reg_count >= 0);

  uint32_t *write_p = ctx->code.write_p;
  arm_pop_regs(regs);
  ctx->code.write_p = write_p;
}

void emit_arm_fcall(mambo_context *ctx, void *function_ptr) {
  emit_arm_copy_to_reg_32bit(ctx, lr, (uint32_t)function_ptr);
  emit_arm_blx(ctx, lr);
}

void emit_thumb_fcall(mambo_context *ctx, void *function_ptr) {
  emit_thumb_copy_to_reg_32bit(ctx, lr, (uint32_t)function_ptr);
  emit_thumb_blx16(ctx, lr);
}

static inline int emit_arm_add_sub_shift(mambo_context *ctx, int rd, int rn, int rm,
                                         unsigned int shift_type, unsigned int shift) {
  if (shift < 0 || shift > 31 || shift_type > ROR) {
    return -1;
  }

  if (rm < 0) {
    rm = -rm;
    emit_arm_sub(ctx, REG_PROC, 0, rd, rn, rm | (shift_type << 5) | (shift << 7));
  } else {
    emit_arm_add(ctx, REG_PROC, 0, rd, rn, rm | (shift_type << 5) | (shift << 7));
  }
  return 0;
}

static inline int emit_arm_add_sub(mambo_context *ctx, int rd, int rn, int rm) {
  return emit_arm_add_sub_shift(ctx, rd, rn, rm, LSL, 0);
}

static inline int emit_thumb_add_sub_shift(mambo_context *ctx, int rd, int rn, int rm,
                                           unsigned int shift_type, unsigned int shift) {
  if (shift < 0 || shift > 31 || shift_type > ROR) {
    return -1;
  }
  if (rm < 0) {
    rm = -rm;
    emit_thumb_sub32(ctx, 0, rn, shift >> 2, rd, shift, shift_type, rm);
  } else {
    emit_thumb_add32(ctx, 0, rn, shift >> 2, rd, shift, shift_type, rm);
  }
  return 0;
}

static inline int emit_thumb_add_sub(mambo_context *ctx, int rd, int rn, int rm) {
  return emit_thumb_add_sub_shift(ctx, rd, rn, rm, LSL, 0);
}
#endif // __arm__

#ifdef __aarch64__
void emit_a64_push(mambo_context *ctx, uint32_t regs) {
  int reg_no = count_bits(regs);
  ctx->code.plugin_pushed_reg_count += reg_no;

  uint32_t *write_p = ctx->code.write_p;
  uint32_t to_push[2];

  if (reg_no & 1) {
    reg_no = get_highest_n_regs(regs, to_push, 1);
    assert(reg_no == 1);
    a64_push_reg(to_push[0]);
    regs &= ~(1 << to_push[0]);
  }

  while (regs != 0) {
    reg_no = get_highest_n_regs(regs, to_push, 2);
    assert(reg_no == 2);
    a64_push_pair_reg(to_push[1], to_push[0]);
    regs &= ~((1 << to_push[0]) | (1 << to_push[1]));
  }

  ctx->code.write_p = write_p;
}

void emit_a64_pop(mambo_context *ctx, uint32_t regs) {
  ctx->code.plugin_pushed_reg_count -= count_bits(regs);
  assert(ctx->code.plugin_pushed_reg_count >= 0);

  uint32_t *write_p = ctx->code.write_p;
  uint32_t to_pop[2];
  int reg_no;

  while (regs != 0) {
    reg_no = get_lowest_n_regs(regs, to_pop, 2);
    assert(reg_no == 1 || reg_no == 2);
    if (reg_no == 2) {
      a64_pop_pair_reg(to_pop[0], to_pop[1]);
      regs &= ~((1 << to_pop[0]) | (1 << to_pop[1]));
    } else if (reg_no == 1) {
      a64_pop_reg(to_pop[0]);
      regs &= ~(1 << to_pop[0]);
    }
  }

  ctx->code.write_p = write_p;
}

static inline int emit_a64_add_sub_shift(mambo_context *ctx, int rd, int rn, int rm,
                                         unsigned int shift_type, unsigned int shift) {
  if (shift < 0 || shift > 63 || shift_type > ASR) return -1;
  int op = (rm < 0);
  rm = abs(rm);
  emit_a64_ADD_SUB_shift_reg(ctx, 1, op, 0, shift_type, rm, shift, rn, rd);
  return 0;
}

static inline int emit_a64_add_sub(mambo_context *ctx, int rd, int rn, int rm) {
  return emit_a64_add_sub_shift(ctx, rd, rn, rm, LSL, 0);
}

int emit_a64_add_sub_ext(mambo_context *ctx, int rd, int rn, int rm, int ext_option, int shift) {
  int op = (rm < 0);
  rm = abs(rm);
  if (shift > 4 || shift < 0) return -1;
  emit_a64_ADD_SUB_ext_reg(ctx, 1, op, 0, rm, ext_option, shift, rn, rd);
  return 0;
}
#endif

#ifdef __riscv
  void emit_riscv_push(mambo_context *ctx, uint32_t regs) {
    int reg_no = count_bits(regs);
    ctx->code.plugin_pushed_reg_count += reg_no;

    uint16_t *write_p = ctx->code.write_p;
    riscv_push(&write_p, regs);
    ctx->code.write_p = write_p;
  }

  void emit_riscv_pop(mambo_context *ctx, uint32_t regs) {
    ctx->code.plugin_pushed_reg_count -= count_bits(regs);
    assert(ctx->code.plugin_pushed_reg_count >= 0);

    uint16_t *write_p = ctx->code.write_p;
    riscv_pop(&write_p, regs);
    ctx->code.write_p = write_p;
  }

  uint32_t __riscv_find_next_free_reg(uint32_t current_regs) {
    uint32_t new_reg_temp = 1;
    while((new_reg_temp & current_regs) != 0)
            new_reg_temp++;

    return new_reg_temp;
  }
#endif

void emit_push(mambo_context *ctx, uint32_t regs) {
#ifdef __arm__
  inst_set isa = mambo_get_inst_type(ctx);
  if (isa == ARM_INST) {
    emit_arm_push(ctx, regs);
  } else {
    emit_thumb_push(ctx, regs);
  }
#elif __aarch64__
  emit_a64_push(ctx, regs);
#elif __riscv
  emit_riscv_push(ctx, regs);
#endif
}

void emit_pop(mambo_context *ctx, uint32_t regs) {
  assert(ctx->code.plugin_pushed_reg_count >= 0);
#ifdef __arm__
  inst_set isa = mambo_get_inst_type(ctx);
  if (isa == ARM_INST) {
    emit_arm_pop(ctx, regs);
  } else {
    emit_thumb_pop(ctx, regs);
  }
#elif __aarch64__
  emit_a64_pop(ctx, regs);
#elif __riscv
  emit_riscv_pop(ctx, regs);
#endif
}

void emit_set_reg(mambo_context *ctx, enum reg reg, uintptr_t value) {
#ifdef __arm__
  inst_set isa = mambo_get_inst_type(ctx);
  if (isa == ARM_INST) {
    emit_arm_copy_to_reg_32bit(ctx, reg, value);
  } else {
    emit_thumb_copy_to_reg_32bit(ctx, reg, value);
  }
#elif __aarch64__
  a64_copy_to_reg_64bits((uint32_t **)&ctx->code.write_p, reg, value);
#elif __riscv
  riscv_copy_to_reg((uint16_t **)&ctx->code.write_p, reg, value);
#endif
}

int __emit_branch_cond(inst_set inst_type, void *write, uintptr_t target, mambo_cond cond, bool link) {
  intptr_t diff;
  #ifdef __arm__
    diff = (target & (~THUMB)) - (uintptr_t)write;
  #else
    diff = target - (uintptr_t)write;
  #endif
  if (cond != AL && link) return -1;
#ifdef __arm__
  switch (inst_type) {
    case THUMB_INST:
      diff -= 4;
      if (cond == AL) {
        bool to_arm = link && !(target & THUMB);
        target &= ~THUMB;
        if (diff < -16777216 || diff > 16777214) return -1;
        thumb_b_bl_helper(write, target, link, to_arm);
      } else {
        if (diff < -1048576 || diff > 1048574) return -1;
        void *write_c = write;
        thumb_b32_cond_helper((uint16_t **)&write, target, cond);
        assert((write_c + 4) == write);
      }
      break;
    case ARM_INST:
      if (target & THUMB) return -1;
      diff -= 8;
      if (diff < -33554432 || diff > 33554428) return -1;
      arm_branch_helper(write, target, link, cond);
      break;
    default:
      return -1;
  }
#endif
#ifdef __aarch64__
  if (cond == AL) {
    if (diff < -134217728 || diff > 134217724) return -1;
    a64_branch_helper(write, target, link);
    //a64_b_helper(write, target);
  } else {
    if (diff < -1048576 || diff > 1048572) return -1;
    a64_b_cond_helper(write, target, cond);
  }
#endif
#ifdef __riscv
  //TODO: refactor to support RISC-V conditional branches
  if (cond == AL) {
    if (diff < -1048576 || diff > 1048574) return -1;
    riscv_jal_helper((uint16_t **)&write, target, ra);
  } else {
    return -1;
  }
#endif
  return 0;
}





void emit_fcall(mambo_context *ctx, void *function_ptr) {
  // First try an immediate call, and if that is out of range then generate an indirect call
  int ret = __emit_branch_cond(ctx->code.inst_type, ctx->code.write_p, (uintptr_t)function_ptr, AL, true);
  if (ret == 0) return;
  emit_set_reg(ctx, lr, (uintptr_t)function_ptr);
#ifdef __arm__
  inst_set type = mambo_get_inst_type(ctx);
  if (type == ARM_INST) {
    emit_arm_blx(ctx, lr);
  } else {
    emit_thumb_blx16(ctx, lr);
  }
#elif __aarch64__
  emit_a64_BLR(ctx, lr);
#elif __riscv
  emit_riscv_jalr(ctx, ra, ra, 0);
#endif
}

int emit_safe_fcall(mambo_context *ctx, void *function_ptr, int argno) {
  uintptr_t to_push = (1 << lr);
#ifdef __arm__
  to_push |= (1 << r0) | (1 << r1) | (1 << r2) | (1 << r3) | (1 << r4);
#elif __aarch64__
  to_push |= 0x1FF;
#elif __riscv
  to_push |= 0x3FC00;
#endif

  if (argno > MAX_FCALL_ARGS) return -1;
#if defined __arm__ || __aarch64__
  to_push &= ~(((1 << MAX_FCALL_ARGS)-1) >> (MAX_FCALL_ARGS - argno));
#elif __riscv
  to_push &= ~(((1 << 18)-1) >> (MAX_FCALL_ARGS - argno));
  to_push |= (1 << lr);
#endif

  emit_push(ctx, to_push);
#if defined __arm__ || __aarch64__
  emit_set_reg_ptr(ctx, MAX_FCALL_ARGS, function_ptr);
#else
  emit_set_reg_ptr(ctx, a7, function_ptr);
#endif
  emit_fcall(ctx, safe_fcall_trampoline);
  emit_pop(ctx, to_push);

  return 0;
}

int emit_safe_fcall_static_args(mambo_context *ctx, void *fptr, int argno, ...) {
  va_list args;
  uint32_t reglist = 0;

  if (argno > MAX_FCALL_ARGS || argno < 0) return -1;
  if (argno > 0) {
    reglist = 0xFF >> (8-argno);
    emit_push(ctx, reglist);

    va_start(args, argno);
    for (int a = 0; a < argno; a++) {
      emit_set_reg(ctx, a, va_arg(args, uintptr_t));
    }
    va_end(args);
  }

  emit_safe_fcall(ctx, fptr, argno);

  if (argno > 0) {
    emit_pop(ctx, reglist);
  }

  return 0;
}

void emit_mov(mambo_context *ctx, enum reg rd, enum reg rn) {
#ifdef __arm__
  assert(rd >= 0 && rd < pc && rn >= 0 && rn < pc);
  if (mambo_get_inst_type(ctx) == THUMB_INST) {
    emit_thumb_movh16(ctx, rd >> 3, rn, rd);
  } else {
    emit_arm_mov(ctx, REG_PROC, 0, rd, rn);
  }
#elif __aarch64__
  if (rn == sp) {
    emit_a64_ADD_SUB_immed(ctx, 1, 0, 0, 0, 0, rn, rd);
  } else {
    emit_a64_logical_reg(ctx, 1, 1, 0, 0, rn, 0, 0x1F, rd);
  }
#elif __riscv
  emit_riscv_addi(ctx, rd, rn, 0);
#endif
}

#ifdef __arm__
  #define SHIFTED_ADD_SUB_I_BITS 8
  #define _emit_add_shift_imm(rd, rn, offset, shift) \
           assert((shift & 1) == 0); \
           emit_arm_add(ctx, IMM_PROC, 0, rd, rn, ((16 - (shift / 2)) << 8) | offset);
  #define _emit_sub_shift_imm(rd, rn, offset, shift) \
           assert((shift & 1) == 0); \
           emit_arm_sub(ctx, IMM_PROC, 0, rd, rn, ((16 - (shift / 2)) << 8) | offset);
#elif __aarch64__
  #define SHIFTED_ADD_SUB_I_BITS 12
  #define _emit_add_shift_imm(rd, rn, offset, shift) \
           assert((shift) == 0 || (shift) == 12); \
           emit_a64_ADD_SUB_immed(ctx, 1, 0, 0, (shift == 12), (offset), (rn), (rd));
  #define _emit_sub_shift_imm(rd, rn, offset, shift) \
           assert((shift) == 0 || (shift) == 12); \
           emit_a64_ADD_SUB_immed(ctx, 1, 1, 0, (shift == 12), (offset), (rn), (rd));
#endif
#if defined __arm__ || defined __aarch64__
#define SHIFTED_ADD_SUB_I_MASK ((1 << SHIFTED_ADD_SUB_I_BITS) - 1)
#define SHIFTED_ADD_SUB_MAX (SHIFTED_ADD_SUB_I_MASK | (SHIFTED_ADD_SUB_I_MASK << SHIFTED_ADD_SUB_I_BITS))
#endif

int emit_add_sub_i(mambo_context *ctx, int rd, int rn, int offset) {
  if (offset == 0) {
    if (rd != rn) {
      emit_mov(ctx, rd, rn);
      return 0;
    }
  } else {
#if defined __arm__
    inst_set isa = mambo_get_inst_type(ctx);
    if (isa == THUMB_INST) {
      if (offset > 0xFFF || offset < -0xFFF) return -1;

      if (offset < 0) {
        offset = -offset;
        emit_thumb_subwi32(ctx, offset >> 11, rn, offset >> 8, rd, offset);
      } else {
        emit_thumb_addwi32(ctx, offset >> 11, rn, offset >> 8, rd, offset);
      }
      return 0;
    }
#endif
#if defined __aarch64__ || __arm__
    if (offset < -SHIFTED_ADD_SUB_MAX || offset > SHIFTED_ADD_SUB_MAX) return -1;

    if (offset < 0) {
      offset = -offset;
      if (offset & SHIFTED_ADD_SUB_I_MASK) {
        _emit_sub_shift_imm(rd, rn, offset & SHIFTED_ADD_SUB_I_MASK, 0);
        rn = rd;
      }
      if (offset & (SHIFTED_ADD_SUB_I_MASK << SHIFTED_ADD_SUB_I_BITS)) {
        _emit_sub_shift_imm(rd, rn, offset >> SHIFTED_ADD_SUB_I_BITS, SHIFTED_ADD_SUB_I_BITS);
      }
    } else {
      if (offset & SHIFTED_ADD_SUB_I_MASK) {
        _emit_add_shift_imm(rd, rn, offset & SHIFTED_ADD_SUB_I_MASK, 0);
        rn = rd;
      }
      if (offset & (SHIFTED_ADD_SUB_I_MASK << SHIFTED_ADD_SUB_I_BITS)) {
        _emit_add_shift_imm(rd, rn, offset >> SHIFTED_ADD_SUB_I_BITS, SHIFTED_ADD_SUB_I_BITS);
      }
    }
  #elif  defined __riscv
    if (offset > 0x7FF || offset < -0xFFF) return -1;
    emit_riscv_addi(ctx, rd, rn, offset);
  #endif
  }
  return 0;
}

inline int emit_add_sub_shift(mambo_context *ctx, int rd, int rn, int rm,
                       unsigned int shift_type, unsigned int shift) {
#ifdef __arm__
  if (mambo_get_inst_type(ctx) == THUMB_INST) {
    return emit_thumb_add_sub_shift(ctx, rd, rn, rm, shift_type, shift);
  } else {
    return emit_arm_add_sub_shift(ctx, rd, rn, rm, shift_type, shift);
  }
#elif __aarch64__
  return emit_a64_add_sub_shift(ctx, rd, rn, rm, shift_type, shift);
#elif __riscv
  if (shift > 0) {
    int rm_new = rm;
    if (rn == rm) {
      //need to save register
      //get next free register
      uint32_t current_regs = rd;
      current_regs |= rn;
      current_regs |= rm;
    
      rm_new = __riscv_find_next_free_reg(current_regs);
      emit_riscv_push(ctx, (1 << rm_new));
      emit_riscv_addi(ctx, rm_new, rm, 0);
    }
    switch (shift_type) {
      case LSL:
        emit_riscv_slli(ctx, rm_new, rm_new, shift); 
        break;
      case LSR:
        emit_riscv_srli(ctx, rm_new, rm_new, shift);
        break;
      case ASR:
        emit_riscv_srai(ctx, rm_new, rm_new, shift);
        break;
      case ROR: {
        /* 
         * A little more complex here
         * RISC-V currently has a draft B extension for bitwise operations such as rotate
         * For now we need to construct this using shift instructions
         */
        uint32_t current_regs = rd;
        current_regs |= rn;
        current_regs |= rm;
        current_regs |= rm_new;

        uint32_t temp1 = __riscv_find_next_free_reg(current_regs);
        current_regs |= temp1;
        uint32_t temp2 = __riscv_find_next_free_reg(current_regs);
        emit_riscv_push(ctx, (1 << temp1) | (1 << temp2));
        emit_riscv_srli(ctx, temp1, rm_new, shift);
        emit_riscv_slli(ctx, temp2, rm_new, (-shift & 63));
        emit_riscv_or(ctx, rm_new, temp1, temp2);
        emit_riscv_pop(ctx, (1 << temp1) | (1 << temp2));
        break;

        if (rn == rm) {
          //need to restore register
          emit_riscv_addi(ctx, rm, rm_new, 0);
          emit_riscv_pop(ctx, (1 << rm_new));
        }
      }

    }
  }
  emit_riscv_add(ctx, rd, rn, rm);
#endif
}

inline int emit_add_sub(mambo_context *ctx, int rd, int rn, int rm) {
  return emit_add_sub_shift(ctx, rd, rn, rm, LSL, 0);
}

int emit_branch_cond(mambo_context *ctx, void *target, mambo_cond cond) {
  void *write_p = mambo_get_cc_addr(ctx);
  int ret = __emit_branch_cond(mambo_get_inst_type(ctx), write_p, (uintptr_t)target, cond, false);
  if (ret == 0) {
    mambo_set_cc_addr(ctx, write_p + 4);
  }
  return ret;
}

int emit_branch(mambo_context *ctx, void *target) {
  return emit_branch_cond(ctx, target, AL);
}

#ifdef __riscv
int emit_riscv_cond_branch(mambo_context *ctx, void *target, int rs1, int rs2, int branch_condition) {
  return riscv_branch_helper((uint16_t **)&ctx->code.write_p, target, rs1, rs2, branch_condition);
}
#endif

int __emit_branch_cbz_cbnz(mambo_context *ctx, void *write_p, void *target, enum reg reg, bool is_cbz) {
  int ret = -1;
#ifdef __aarch64__
  ret = a64_cbz_cbnz_helper((uint32_t *)write_p, !is_cbz, (uint64_t)target, 1, reg);
#elif __arm__
  if (mambo_get_inst_type(ctx) == THUMB_INST) {
    ret = thumb_cbz_cbnz_helper((uint16_t *)write_p, (uint32_t)target, reg, is_cbz);
  }
#elif __riscv
  if (is_cbz) {
    ret = riscv_c_beqz_helper((uint16_t **)write_p, (uintptr_t)target, reg);
  } else {
    ret = riscv_c_bnez_helper((uint16_t **)write_p, (uintptr_t)target, reg);
  }
#endif
  return ret;
}

int emit_branch_cbz_cbnz(mambo_context *ctx, void *target, enum reg reg, bool is_cbz) {
  void *write_p = mambo_get_cc_addr(ctx);

  int ret = __emit_branch_cbz_cbnz(ctx, write_p, target, reg, is_cbz);
  if (ret == 0) {
#ifdef __aarch64__
    mambo_set_cc_addr(ctx, write_p + 4);
#elif __arm__
    mambo_set_cc_addr(ctx, write_p + 2);
#elif __riscv
    mambo_set_cc_addr(ctx, write_p + 2);
#endif
  }
  return ret;
}

int emit_branch_cbz(mambo_context *ctx, void *target, enum reg reg) {
  return emit_branch_cbz_cbnz(ctx, target, reg, true);
}

int emit_branch_cbnz(mambo_context *ctx, void *target, enum reg reg) {
  return emit_branch_cbz_cbnz(ctx, target, reg, false);
}

int __mambo_reserve(mambo_context *ctx, mambo_branch *br, size_t incr) {
  if (ctx->code.write_p) {
    br->loc = ctx->code.write_p;
    ctx->code.write_p += incr;
    return 0;
  }
  return -1;
}

int mambo_reserve_branch(mambo_context *ctx, mambo_branch *br) {
  return __mambo_reserve(ctx, br, 4);
}

int mambo_reserve_branch_cbz(mambo_context *ctx, mambo_branch *br) {
#ifdef __arm__
  if (mambo_get_inst_type(ctx) == THUMB_INST) {
    return __mambo_reserve(ctx, br, 2);
  }
  return -1;
#elif __riscv
  return __mambo_reserve(ctx, br, 2);
#endif
  return __mambo_reserve(ctx, br, 4);
}

int __emit_local_branch(mambo_context *ctx, mambo_branch *br, mambo_cond cond, bool link) {
  uintptr_t target = (uintptr_t)mambo_get_cc_addr(ctx);
#ifdef __arm__
  if (ctx->code.inst_type == THUMB_INST) {
    target |= THUMB;
  }
#endif
  return __emit_branch_cond(mambo_get_inst_type(ctx), br->loc, target, cond, link);
}

int emit_local_branch_cond(mambo_context *ctx, mambo_branch *br, mambo_cond cond) {
  return __emit_local_branch(ctx, br, cond, false);
}

int emit_local_branch(mambo_context *ctx, mambo_branch *br) {
  return __emit_local_branch(ctx, br, AL, false);
}

int emit_local_fcall(mambo_context *ctx, mambo_branch *br) {
  return __emit_local_branch(ctx, br, AL, true);
}

int emit_local_branch_cbz_cbnz(mambo_context *ctx, mambo_branch *br, enum reg reg, bool is_cbz) {
  return __emit_branch_cbz_cbnz(ctx, br->loc, mambo_get_cc_addr(ctx), reg, is_cbz);
}

int emit_local_branch_cbz(mambo_context *ctx, mambo_branch *br, enum reg reg) {
  return emit_local_branch_cbz_cbnz(ctx, br, reg, true);
}

int emit_local_branch_cbnz(mambo_context *ctx, mambo_branch *br, enum reg reg) {
  return emit_local_branch_cbz_cbnz(ctx, br, reg, false);
}

void emit_counter64_incr(mambo_context *ctx, void *counter, unsigned incr) {
#ifdef __arm__
  /* On AArch32 we use NEON rather than ADD and ADC to avoid having to save
     and restore the PSR register, which is slow.

     VPUSH {D0, D1}
     PUSH {R0}

     MOV{W,T} R0, counter
     VLDR D1, [R0]
     VMOV.I32 D0, #incr
     VSHR.U64 D0, D0, #32
     VADD.I64 D0, D1, D0
     VSTR D0, [R0]

     POP {R0}
     VPOP {D0, D1}
  */
  assert(incr <= 255);

  switch(mambo_get_inst_type(ctx)) {
    case THUMB_INST: {
      emit_thumb_vfp_vpush(ctx, 1, 0, 0, 4);
      emit_thumb_push(ctx, 1 << r0);

      emit_thumb_copy_to_reg_32bit(ctx, r0, (uintptr_t)counter);
      emit_thumb_vfp_vldr_dp(ctx, 1, r0, 0, 1, 0);
      emit_thumb_neon_vmovi(ctx, 0, 0, 0, 0, 0, incr >> 7, incr >> 4, incr);
      emit_thumb_neon_vshr(ctx, 1, 0, 0, 0, 0, 0, 1, 32);
      emit_thumb_neon_vadd_i(ctx, 3, 0, 0, 0, 0, 1, 0, 0);
      emit_thumb_vfp_vstr_dp(ctx, 1, 0, r0, 0, 0);

      emit_thumb_pop(ctx, 1 << r0);
      emit_thumb_vfp_vpop(ctx, 1, 0, 0, 4);
      break;
    }

    case ARM_INST:
      emit_arm_vfp_vpush_dp(ctx, 0, 0, 4);
      emit_arm_push(ctx, (1 << r0));

      emit_arm_copy_to_reg_32bit(ctx, r0, (uintptr_t)counter);
      emit_arm_vfp_vldr_dp(ctx, 1, 0, r0, 1, 0);
      emit_arm_neon_vmovi(ctx, 0, 0, 0, 0, 0, incr >> 7, incr >> 4, incr);
      emit_arm_neon_vshr(ctx, 1, 0, 0, 0, 0, 0, 1, 32);
      emit_arm_neon_vadd_i(ctx, 3, 0, 0, 0, 0, 1, 0, 0);
      emit_arm_vfp_vstr_dp(ctx, 1, 0, r0, 0, 0);

      emit_arm_pop(ctx, (1 << r0));
      emit_arm_vfp_vpop_dp(ctx, 0, 0, 4);
      break;
  }
#endif
#ifdef __aarch64__
  assert(incr <= 0xFFF);
  emit_a64_push(ctx, (1 << x0) | (1 << x1));
  a64_copy_to_reg_64bits((uint32_t **)&ctx->code.write_p, x0, (uintptr_t)counter);
  emit_a64_LDR_STR_unsigned_immed(ctx, 3, 0, 1, 0, x0, x1);
  emit_a64_ADD_SUB_immed(ctx, 1, 0, 0, 0, incr, x1, x1);
  emit_a64_LDR_STR_unsigned_immed(ctx, 3, 0, 0, 0, x0, x1);
  emit_a64_pop(ctx, (1 << x0) | (1 << x1));
#endif

#ifdef __riscv
  #if __riscv_xlen == 32
    #error increment 64 not implemented on 32 bit yet
  #elif __riscv_xlen == 64
    assert(incr <= 0x7FF);
    emit_riscv_push(ctx, (1 << x6 | (1 << x7)));
    riscv_copy_to_reg((uint16_t **)&ctx->code.write_p, x6, (uintptr_t)counter);
    emit_riscv_ld(ctx, x7, x6, 0);
    emit_riscv_addi(ctx, x7, x7, incr);
    emit_riscv_sd(ctx, x7, x6, 0, 0);
    emit_riscv_pop(ctx, (1 << x6 | (1 << x7)));
  #else
    #error increment 64 not implemented
  #endif
#endif
}

int emit_indirect_branch_by_spc(mambo_context *ctx, enum reg reg) {
#ifdef __aarch64__
  // Uses fragment id 0 to prevent the dispatcher from attempting linking on an IHL miss
  a64_inline_hash_lookup(current_thread, 0, (uint32_t **)&ctx->code.write_p, ctx->code.read_address, reg, false, false);
#elif __arm__
  switch(ctx->code.inst_type) {
    case ARM_INST:
      emit_push(ctx, (1 << r4) | (1 << 5) | (1 << 6));
      arm_inline_hash_lookup(current_thread, (uint32_t **)&ctx->code.write_p, 0, reg);
      break;
    case THUMB_INST: {
      uint16_t *write_p = (uint16_t *)ctx->code.write_p;
      if (reg != r5 && reg != r6) {
        thumb_push16(&write_p, (1 << r5) | (1 << r6));
      } else {
        thumb_push16(&write_p, (1 << r4) | (1 << r5) | (1 << r6));
        write_p++;
        thumb_movh16(&write_p, 0, reg, r5);
        reg = -1;
      }
      write_p++;

      thumb_inline_hash_lookup(current_thread, &write_p, 0, reg);
      ctx->code.write_p = write_p;
      break;
    }
    default:
      assert(0);
  }
#elif __riscv
  riscv_inline_hash_lookup(current_thread, 0, (uint16_t **)&ctx->code.write_p, (uint16_t *)ctx->code.read_address, reg, 0, false, false, false);
#endif
}
#endif
