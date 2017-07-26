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

#ifdef PLUGINS_NEW

#include <stdio.h>
#include <assert.h>
#include "../plugins.h"
#ifdef __arm__
#include "../pie/pie-thumb-encoder.h"
#elif __aarch64__
#include "../pie/pie-a64-encoder.h"
#include "../api/emit_a64.h"
#endif

#define not_implemented() \
  fprintf(stderr, "%s: Implement me\n", __PRETTY_FUNCTION__); \
  while(1);

#ifdef __arm__
void emit_thumb_push_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  uint16_t *write_p = ctx->write_p;

  // MRS tmp_reg, CPSR
  thumb_mrs32(&write_p, tmp_reg);
  write_p += 2;

  // PUSH {tmp_reg}
  thumb_push_regs(&write_p, 1 << tmp_reg);

  ctx->write_p = write_p;
}

void emit_arm_push_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  emit_arm_mrs(ctx, tmp_reg);
  emit_arm_push(ctx, 1 << tmp_reg);
}

void emit_thumb_pop_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  uint16_t *write_p = ctx->write_p;

  // POP {tmp_reg}
  thumb_pop_regs(&write_p, 1 << tmp_reg);

  // MSR tmp_reg, CPSR_fs
  thumb_msr32(&write_p, tmp_reg, 3);
  write_p += 2;

  ctx->write_p = write_p;
}

void emit_arm_pop_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  emit_arm_pop(ctx, 1 << tmp_reg);
  emit_arm_msr(ctx, tmp_reg, 3);
}

void emit_thumb_copy_to_reg_32bit(mambo_context *ctx, enum reg reg, uint32_t value) {
  if (value <= 0xFFFF) {
    copy_to_reg_16bit((uint16_t **)&ctx->write_p, reg, value);
  } else {
    copy_to_reg_32bit((uint16_t **)&ctx->write_p, reg, value);
  }
}

void emit_arm_copy_to_reg_32bit(mambo_context *ctx, enum reg reg, uint32_t value) {
  if (value <= 0xFFFF) {
    arm_copy_to_reg_16bit((uint32_t **)&ctx->write_p, reg, value);
  } else {
    arm_copy_to_reg_32bit((uint32_t **)&ctx->write_p, reg, value);
  }
}

void emit_thumb_b16_cond(void *write_p, void *target, mambo_cond cond) {
  thumb_b16_cond_helper((uint16_t *)write_p, (uint32_t)target, cond);
}

void emit_thumb_push(mambo_context *ctx, uint32_t regs) {
  ctx->plugin_pushed_reg_count += count_bits(regs);

  uint16_t *write_p = ctx->write_p;
  thumb_push_regs(&write_p, regs);
  ctx->write_p = write_p;
}

void emit_arm_push(mambo_context *ctx, uint32_t regs) {
  ctx->plugin_pushed_reg_count += count_bits(regs);

  uint32_t *write_p = ctx->write_p;
  arm_push_regs(regs);
  ctx->write_p = write_p;
}

void emit_thumb_pop(mambo_context *ctx, uint32_t regs) {
  ctx->plugin_pushed_reg_count -= count_bits(regs);
  assert(ctx->plugin_pushed_reg_count >= 0);

  uint16_t *write_p = ctx->write_p;
  thumb_pop_regs(&write_p, regs);
  ctx->write_p = write_p;
}

void emit_arm_pop(mambo_context *ctx, uint32_t regs) {
  ctx->plugin_pushed_reg_count -= count_bits(regs);
  assert(ctx->plugin_pushed_reg_count >= 0);

  uint32_t *write_p = ctx->write_p;
  arm_pop_regs(regs);
  ctx->write_p = write_p;
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
  ctx->plugin_pushed_reg_count += count_bits(regs);

  uint32_t *write_p = ctx->write_p;
  uint32_t to_push[2];
  int reg_no;

  while (regs != 0) {
    reg_no = get_highest_n_regs(regs, to_push, 2);
    assert(reg_no == 1 || reg_no == 2);
    if (reg_no == 2) {
      a64_push_pair_reg(to_push[1], to_push[0]);
      regs &= ~((1 << to_push[0]) | (1 << to_push[1]));
    } else if (reg_no == 1) {
      a64_push_reg(to_push[0]);
      regs &= ~(1 << to_push[0]);
    }
  }

  ctx->write_p = write_p;
}

void emit_a64_pop(mambo_context *ctx, uint32_t regs) {
  ctx->plugin_pushed_reg_count -= count_bits(regs);
  assert(ctx->plugin_pushed_reg_count >= 0);

  uint32_t *write_p = ctx->write_p;
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

  ctx->write_p = write_p;
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
#endif
}

void emit_pop(mambo_context *ctx, uint32_t regs) {
  assert(ctx->plugin_pushed_reg_count >= 0);
#ifdef __arm__
  inst_set isa = mambo_get_inst_type(ctx);
  if (isa == ARM_INST) {
    emit_arm_pop(ctx, regs);
  } else {
    emit_thumb_pop(ctx, regs);
  }
#elif __aarch64__
  emit_a64_pop(ctx, regs);
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
  a64_copy_to_reg_64bits((uint32_t **)&ctx->write_p, reg, value);
#endif
}

void emit_fcall(mambo_context *ctx, void *function_ptr) {
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
#endif
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
#define SHIFTED_ADD_SUB_I_MASK ((1 << SHIFTED_ADD_SUB_I_BITS) - 1)
#define SHIFTED_ADD_SUB_MAX (SHIFTED_ADD_SUB_I_MASK | (SHIFTED_ADD_SUB_I_MASK << SHIFTED_ADD_SUB_I_BITS))

int emit_add_sub_i(mambo_context *ctx, int rd, int rn, int offset) {
  if (offset == 0) {
    if (rd != rn) {
      emit_mov(ctx, rd, rn);
      return 0;
    }
  } else {
#ifdef __arm__
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
  } // offset != 0
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
#endif
}

inline int emit_add_sub(mambo_context *ctx, int rd, int rn, int rm) {
  return emit_add_sub_shift(ctx, rd, rn, rm, LSL, 0);
}

int __emit_branch_cond(inst_set inst_type, void *write, uintptr_t target, mambo_cond cond) {
  intptr_t diff = target - (uintptr_t)write;
#ifdef __arm__
  switch (inst_type) {
    case THUMB_INST:
      diff -= 4;
      if (cond == AL) {
        if (diff < -16777216 || diff > 16777214) return -1;
        thumb_b32_helper(write, target);
      } else {
        if (diff < -1048576 || diff > 1048574) return -1;
        void *write_c = write;
        thumb_b32_cond_helper((uint16_t **)&write, target, cond);
        assert((write_c + 4) == write);
      }
      break;
    case ARM_INST:
      diff -= 8;
      if (diff < -33554432 || diff > 33554428) return -1;
      arm_b32_helper(write, target, cond);
      break;
    default:
      return -1;
  }
#endif
#ifdef __aarch64__
  if (cond == AL) {
    if (diff < -134217728 || diff > 134217724) return -1;
    a64_b_helper(write, target);
  } else {
    if (diff < -1048576 || diff > 1048572) return -1;
    a64_b_cond_helper(write, target, cond);
  }
#endif
  return 0;
}

int emit_branch_cond(mambo_context *ctx, void *target, mambo_cond cond) {
  void *write_p = mambo_get_cc_addr(ctx);
  int ret = __emit_branch_cond(mambo_get_inst_type(ctx), write_p, (uintptr_t)target, cond);
  if (ret == 0) {
    mambo_set_cc_addr(ctx, write_p + 4);
  }
  return ret;
}

int emit_branch(mambo_context *ctx, void *target) {
  return emit_branch_cond(ctx, target, AL);
}

int mambo_reserve_branch(mambo_context *ctx, mambo_branch *br) {
  if (ctx->write_p) {
    br->loc = ctx->write_p;
    ctx->write_p += 4;
    return 0;
  }
  return -1;
}

int emit_local_branch_cond(mambo_context *ctx, mambo_branch *br, mambo_cond cond) {
  uintptr_t target = (uintptr_t)mambo_get_cc_addr(ctx);
  return __emit_branch_cond(mambo_get_inst_type(ctx), br->loc, target, cond);
}

int emit_local_branch(mambo_context *ctx, mambo_branch *br) {
  return emit_local_branch_cond(ctx, br, AL);
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
  a64_copy_to_reg_64bits((uint32_t **)&ctx->write_p, x0, (uintptr_t)counter);
  emit_a64_LDR_STR_unsigned_immed(ctx, 3, 0, 1, 0, x0, x1);
  emit_a64_ADD_SUB_immed(ctx, 1, 0, 0, 0, incr, x1, x1);
  emit_a64_LDR_STR_unsigned_immed(ctx, 3, 0, 0, 0, x0, x1);
  emit_a64_pop(ctx, (1 << x0) | (1 << x1));
#endif
}
#endif
