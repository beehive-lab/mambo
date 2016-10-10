/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2016 Cosmin Gorgovan <cosmin at linux-geek dot org>

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

/*
   This plugin replaces the SDIV and UDIV instructions with calls to the 
   __aeabi_idiv / __aeabi_uidiv ABI functions. This allows code compiled
   for cores with support for these optional instructions to be executed
   on machines which don't implement them.
*/

#ifdef PLUGINS_NEW
#include <stdio.h>
#include <assert.h>
#include "../plugins.h"
#include "../pie/pie-arm-field-decoder.h"
#include "../pie/pie-thumb-field-decoder.h"

#define DEBUG

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

extern int __aeabi_idiv(int numerator, int denominator); 
extern unsigned __aeabi_uidiv(unsigned numerator, unsigned denominator);

int get_scratch_reg(uint32_t reglist, uint32_t exclude_list) {
  reglist &= ~exclude_list;
  return (int)next_reg_in_list(reglist, 0);
}

int soft_div_pre_inst(mambo_context *ctx) {
  uint32_t opcode, rd, rn, rm, reglist, sr_reglist;
  int inst_set = mambo_get_inst_type(ctx);
  int inst = mambo_get_inst(ctx);
  int sr;
  void *tr_start;
  mambo_cond cond;

  sr_reglist = (1 << r4) | (1 << r5) | (1 <<r6) | (1 << r7);
  reglist = (1 << r0) | (1 << r1) | (1 << r2) | (1 << r3) | (1 << lr);

  if (inst_set == ARM_INST) {
    if (inst == ARM_SDIV || inst == ARM_UDIV) {
      if (mambo_is_cond(ctx)) {
        tr_start = mambo_get_cc_addr(ctx);
        mambo_set_cc_addr(ctx, tr_start + 4);
      }

      arm_divide_decode_fields(ctx->read_address, &opcode, &rd, &rn, &rm);
      assert(rd != sp && rn != sp && rm != sp);

      debug("Replacing A32 %sdiv from %p at: %p\n", (inst == ARM_SDIV) ? "s" : "u",
            mambo_get_source_addr(ctx), mambo_get_cc_addr(ctx));

      sr = get_scratch_reg(sr_reglist, (1 << rn) | (1 << rm) | (1 << rd));
      assert(sr != reg_invalid);

      reglist |= 1 << sr;
      reglist &= ~(1 << rd);
      emit_arm_push(ctx, reglist);
      emit_arm_mrs(ctx, sr);

      if (rn != r0) {
        emit_arm_mov(ctx, REG_PROC, 0, r0, rn);
      }
      if (rm != r1) {
        emit_arm_mov(ctx, REG_PROC, 0, r1, rm);
      }
      emit_arm_fcall(ctx, (inst == ARM_SDIV) ? (void *)__aeabi_idiv : (void *)__aeabi_uidiv);
      if (rd != r0) {
        emit_arm_mov(ctx, REG_PROC, 0, rd, r0);
      }
      sr = get_scratch_reg(reglist, (1 << rd));
      emit_arm_msr(ctx, sr, 3);
      emit_arm_pop(ctx, reglist);

      mambo_replace_inst(ctx);

      if (mambo_is_cond(ctx)) {
        cond = mambo_get_inverted_cond(ctx, mambo_get_cond(ctx));
        arm_b32_helper(tr_start, (uint32_t)mambo_get_cc_addr(ctx), cond);
      }
    }
  } else if(inst_set == THUMB_INST) {
    if (inst == THUMB_SDIV32 || inst == THUMB_UDIV32) {
      if (mambo_is_cond(ctx)) {
        tr_start = mambo_get_cc_addr(ctx);
        mambo_set_cc_addr(ctx, tr_start + 2);
      }

      thumb_sdiv32_decode_fields(ctx->read_address, &rn, &rd, &rm);
      assert(rd != sp && rn != sp && rm != sp);

      debug("Replacing T32 %sdiv from %p at: %p\n", (inst == THUMB_SDIV32) ? "s" : "u",
            mambo_get_source_addr(ctx), mambo_get_cc_addr(ctx));

      sr = get_scratch_reg(sr_reglist, (1 << rn) | (1 << rm) | (1 << rd));
      assert(sr != reg_invalid);

      reglist |= 1 << sr;
      reglist &= ~(1 << rd);
      emit_thumb_push(ctx, reglist);
      emit_thumb_mrs32(ctx, sr);

      if (rn != r0) {
        emit_thumb_movh16(ctx, r0 >> 3, rn, r0 & 7);
      }
      if (rm != r1) {
        emit_thumb_movh16(ctx, r1 >> 3, rm, r1 & 7);
      }
      emit_thumb_fcall(ctx, (inst == THUMB_SDIV32) ? (void *)__aeabi_idiv : (void *)__aeabi_uidiv);
      if (rd != r0) {
        emit_thumb_movh16(ctx, rd >> 3, r0, rd & 7);
      }
      emit_thumb_msr32(ctx, sr, 3);
      emit_thumb_pop(ctx, reglist);

      mambo_replace_inst(ctx);

      if (mambo_is_cond(ctx)) {
        cond = mambo_get_inverted_cond(ctx, mambo_get_cond(ctx));
        emit_thumb_b16_cond(tr_start, mambo_get_cc_addr(ctx), cond);
      }
    }
  }
}

__attribute__((constructor)) void init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);
  mambo_register_pre_inst_cb(ctx, &soft_div_pre_inst);
}

#endif
