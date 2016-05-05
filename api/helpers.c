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

#include <stdio.h>
#include "../plugins.h"
#include "../pie/pie-thumb-encoder.h"

#define not_implemented() \
  fprintf(stderr, "%s: Implement me\n", __PRETTY_FUNCTION__); \
  while(1);

void emit_thumb_push_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  uint16_t *write_p = ctx->write_p;

  // MRS tmp_reg, CPSR
  thumb_mrs32(&write_p, 0, tmp_reg);
  write_p += 2;

  // PUSH {tmp_reg}
  thumb_push_regs(&write_p, 1 << tmp_reg);

  ctx->write_p = write_p;
}

void emit_arm_push_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  not_implemented();
}

void emit_thumb_pop_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  uint16_t *write_p = ctx->write_p;

  // POP {tmp_reg}
  thumb_pop_regs(&write_p, 1 << tmp_reg);

  // MSR tmp_reg, CPSR_fs
  thumb_msr32(&write_p, 0, tmp_reg, 3 << 2);
  write_p += 2;

  ctx->write_p = write_p;
}

void emit_arm_pop_cpsr(mambo_context *ctx, enum reg tmp_reg) {
  not_implemented();
}

void emit_thumb_copy_to_reg_32bit(mambo_context *ctx, enum reg reg, uint32_t value) {
  if (value <= 0xFFFF) {
    copy_to_reg_16bit((uint16_t **)&ctx->write_p, reg, value);
  } else {
    copy_to_reg_32bit((uint16_t **)&ctx->write_p, reg, value);
  }
}

void emit_arm_copy_to_reg_32bit(mambo_context *ctx, enum reg reg, uint32_t value) {
  not_implemented();
}

void emit_thumb_b16_cond(void *write_p, void *target, mambo_cond cond) {
  thumb_b16_cond_helper((uint16_t *)write_p, (uint32_t)target, cond);
}
