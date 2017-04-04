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
  uint16_t *write_p = ctx->write_p;

  thumb_push_regs(&write_p, regs);

  ctx->write_p = write_p;
}

void emit_arm_push(mambo_context *ctx, uint32_t regs) {
  uint32_t *write_p = ctx->write_p;

  arm_push_regs(regs);

  ctx->write_p = write_p;
}

void emit_thumb_pop(mambo_context *ctx, uint32_t regs) {
  uint16_t *write_p = ctx->write_p;

  thumb_pop_regs(&write_p, regs);

  ctx->write_p = write_p;
}

void emit_arm_pop(mambo_context *ctx, uint32_t regs) {
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
#endif // __arm__

#ifdef __aarch64__
void emit_a64_push(mambo_context *ctx, uint32_t regs) {
  uint32_t *write_p = ctx->write_p;
  uint32_t to_push[2];
  int reg_no;

  while (regs != 0) {
    reg_no = get_n_regs(regs, to_push, 2);
    assert(reg_no == 1 || reg_no == 2);
    if (reg_no == 2) {
      a64_push_pair_reg(to_push[0], to_push[1]);
      regs &= ~((1 << to_push[0]) | (1 << to_push[1]));
    } else if (reg_no == 1) {
      a64_push_reg(to_push[0]);
      regs &= ~(1 << to_push[0]);
    }
  }

  ctx->write_p = write_p;
}

void emit_a64_pop(mambo_context *ctx, uint32_t regs) {
  uint32_t *write_p = ctx->write_p;
  uint32_t to_pop[2];
  int reg_no;

  while (regs != 0) {
    reg_no = get_n_regs(regs, to_pop, 2);
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
#endif

void emit_counter64_incr(mambo_context *ctx, void *counter, uint64_t incr) {
#ifdef __arm__
  fprintf(stderr, "emit_counter64_incr()make not yet implemented for ARM\n");
  exit(EXIT_FAILURE);
#endif
#ifdef __aarch64__
  emit_a64_push(ctx, (1 << x0) | (1 << x1));
  a64_copy_to_reg_64bits((uint32_t **)&ctx->write_p, x0, (uintptr_t)counter);
  emit_a64_LDR_STR_immed(ctx, 3, 0, 1, 0, 3, x0, x1);
  emit_a64_LDR_STR_unsigned_immed(ctx, 3, 0, 1, 0, x0, x1);
  assert(incr <= 0xFFF);
  emit_a64_ADD_SUB_immed(ctx, 1, 0, 0, 0, incr, x1, x1);
  emit_a64_LDR_STR_unsigned_immed(ctx, 3, 0, 0, 0, x0, x1);
  emit_a64_pop(ctx, (1 << x0) | (1 << x1));
#endif
}
#endif
