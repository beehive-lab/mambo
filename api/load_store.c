/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2014-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
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

#ifdef PLUGINS_NEW

#include <stdio.h>
#include <assert.h>

#include "../plugins.h"
#ifdef __arm__
  #include "../pie/pie-thumb-field-decoder.h"
  #include "../pie/pie-arm-field-decoder.h"
#elif __aarch64__
  #include "../pie/pie-a64-field-decoder.h"
  #include "../pie/pie-a64-decoder.h"
#endif

#ifdef __arm__
  #define read_addr_to_pc(addr) (((uint32_t)addr + 4) & 0xFFFFFFFC)
#endif

#ifdef __aarch64__
#define IS_LOAD (1 << 22)

void _a64_is_load_or_store(mambo_context *ctx, bool *is_load, bool *is_store) {
  *is_load = false;
  *is_store = false;

  uint32_t *inst = (uint32_t *)ctx->code.read_address;

  switch (ctx->code.inst) {
    case A64_LDR_LIT: {
      uint32_t opc, v, imm19, rt;
      a64_LDR_lit_decode_fields(ctx->code.read_address, &opc, &v, &imm19, &rt);
      // !PRFM
      if (opc == 3 && v == 0) break;

      *is_load = true;
      break;
    }
    case A64_LDX_STX:
    case A64_LDP_STP:
    case A64_LDX_STX_MULTIPLE:
    case A64_LDX_STX_MULTIPLE_POST:
    case A64_LDX_STX_SINGLE:
    case A64_LDX_STX_SINGLE_POST:
      if (*inst & IS_LOAD) {
        *is_load = true;
      } else {
        *is_store = true;
      }
      break;
    case A64_LDR_STR_IMMED:
    case A64_LDR_STR_REG:
    case A64_LDR_STR_UNSIGNED_IMMED: {
      uint32_t sz, v, opc, imm12, rn, rt;
      a64_LDR_STR_unsigned_immed_decode_fields(ctx->code.read_address, &sz, &v, &opc, &imm12, &rn, &rt);
      // !PRFM - the sz, v, and opc fields are identical between the three encodings
      if (sz == 3 && v == 0 && opc == 2) break;

      if ((*inst >> 22) & 3) {
        *is_load = true;
      } else {
        *is_store = true;
      }
      break;
    }
  }
}
#endif

bool mambo_is_load(mambo_context *ctx) {
  if (ctx->code.inst == -1) return false;
#ifdef __arm__
  if (ctx->code.inst_type == THUMB_INST) {
    switch(ctx->code.inst) {
      case THUMB_LDMFD16:
      case THUMB_LDR16:
      case THUMB_LDRB16:
      case THUMB_LDRBI16:
      case THUMB_LDRH16:
      case THUMB_LDRHI16:
      case THUMB_LDRI16:
      case THUMB_LDR_PC_16:
      case THUMB_LDRSB16:
      case THUMB_LDRSH16:
      case THUMB_LDR_SP16:
      case THUMB_POP16:
      case THUMB_LDC232:
      case THUMB_LDC32:
      case THUMB_LDMEA32:
      case THUMB_LDMFD32:
      case THUMB_LDR32:
      case THUMB_LDRB32:
      case THUMB_LDRBI32:
      case THUMB_LDRBL32:
      case THUMB_LDRBT32:
      case THUMB_LDRBWI32:
      case THUMB_LDRD32:
      case THUMB_LDREX32:
      case THUMB_LDREXB32:
      case THUMB_LDREXD32:
      case THUMB_LDREXH32:
      case THUMB_LDRH32:
      case THUMB_LDRHI32:
      case THUMB_LDRHL32:
      case THUMB_LDRHT32:
      case THUMB_LDRHWI32:
      case THUMB_LDRI32:
      case THUMB_LDRL32:
      case THUMB_LDRSB32:
      case THUMB_LDRSBI32:
      case THUMB_LDRSBL32:
      case THUMB_LDRSBT32:
      case THUMB_LDRSBWI32:
      case THUMB_LDRSH32:
      case THUMB_LDRSHI32:
      case THUMB_LDRSHL32:
      case THUMB_LDRSHT32:
      case THUMB_LDRSHWI32:
      case THUMB_LDRT32:
      case THUMB_LDRWI32:
      case THUMB_NEON_VLDX_M:
      case THUMB_NEON_VLDX_S_O:
      case THUMB_NEON_VLDX_S_A:
      case THUMB_VFP_VLDM_DP:
      case THUMB_VFP_VLDM_SP:
      case THUMB_VFP_VLDR_DP:
      case THUMB_VFP_VLDR_SP:
      case THUMB_VFP_VPOP:
        return true;
    }
  } else if (ctx->code.inst_type == ARM_INST) {
    switch(ctx->code.inst) {
      case ARM_LDC:
      case ARM_LDM:
      case ARM_LDR:
      case ARM_LDRB:
      case ARM_LDRBT:
      case ARM_LDRD:
      case ARM_LDREX:
      case ARM_LDREXB:
      case ARM_LDREXD:
      case ARM_LDREXH:
      case ARM_LDRH:
      case ARM_LDRHT:
      case ARM_LDRSB:
      case ARM_LDRSBT:
      case ARM_LDRSH:
      case ARM_LDRSHT:
      case ARM_LDRT:
      case ARM_NEON_VLDX_M:
      case ARM_NEON_VLDX_S_O:
      case ARM_NEON_VLDX_S_A:
      case ARM_VFP_VLDM_DP:
      case ARM_VFP_VLDM_SP:
      case ARM_VFP_VLDR_DP:
      case ARM_VFP_VLDR_SP:
      case ARM_VFP_VPOP_DP:
      case ARM_VFP_VPOP_SP:
        return true;
    }
  }
#elif __aarch64__
  bool is_load, is_store;
  _a64_is_load_or_store(ctx, &is_load, &is_store);
  return is_load;
#endif
  return false;
}

bool mambo_is_store(mambo_context *ctx) {
  if (ctx->code.inst == -1) return false;
#ifdef __arm__
  if (ctx->code.inst_type == THUMB_INST) {
    switch(ctx->code.inst) {
      case THUMB_STMEA16:
      case THUMB_STR16:
      case THUMB_STRB16:
      case THUMB_STRBI16:
      case THUMB_STRH16:
      case THUMB_STRHI16:
      case THUMB_STRI16:
      case THUMB_STR_SP16:
      case THUMB_PUSH16:
      case THUMB_STC32:
      case THUMB_STC232:
      case THUMB_STMEA32:
      case THUMB_STMFD32:
      case THUMB_STR32:
      case THUMB_STRB32:
      case THUMB_STRBI32:
      case THUMB_STRBT32:
      case THUMB_STRBWI32:
      case THUMB_STRD32:
      case THUMB_STREX32:
      case THUMB_STREXB32:
      case THUMB_STREXD32:
      case THUMB_STREXH32:
      case THUMB_STRH32:
      case THUMB_STRHI32:
      case THUMB_STRHT32:
      case THUMB_STRHWI32:
      case THUMB_STRI32:
      case THUMB_STRT32:
      case THUMB_STRWI32:
      case THUMB_NEON_VSTX_M:
      case THUMB_NEON_VSTX_S_O:
      case THUMB_VFP_VSTM_DP:
      case THUMB_VFP_VSTM_SP:
      case THUMB_VFP_VSTR_DP:
      case THUMB_VFP_VSTR_SP:
      case THUMB_VFP_VPUSH:
        return true;
    }
  } else if (ctx->code.inst_type == ARM_INST) {
    switch(ctx->code.inst) {
      case ARM_STC:
      case ARM_STM:
      case ARM_STR:
      case ARM_STRB:
      case ARM_STRBT:
      case ARM_STRD:
      case ARM_STREX:
      case ARM_STREXB:
      case ARM_STREXD:
      case ARM_STREXH:
      case ARM_STRH:
      case ARM_STRHT:
      case ARM_STRT:
      case ARM_NEON_VSTX_M:
      case ARM_NEON_VSTX_S_O:
      case ARM_VFP_VSTM_DP:
      case ARM_VFP_VSTM_SP:
      case ARM_VFP_VSTR_DP:
      case ARM_VFP_VSTR_SP:
      case ARM_VFP_VPUSH_DP:
      case ARM_VFP_VPUSH_SP:
        return true;
    }
  }
#elif __aarch64__
  bool is_load, is_store;
  _a64_is_load_or_store(ctx, &is_load, &is_store);
  return is_store;
#endif
  return false;
}

bool mambo_is_load_or_store(mambo_context *ctx) {
#ifdef __arm__
  return mambo_is_load(ctx) || mambo_is_store(ctx);
#elif __aarch64__
  bool is_load, is_store;
  _a64_is_load_or_store(ctx, &is_load, &is_store);
  return is_load || is_store;
#endif
}

void _generate_addr(mambo_context *ctx, int reg, int rn, int rm, int offset) {
#ifdef __arm__
  enum reg rtmp = reg_invalid;

  assert(rm != pc && rm != sp);
#elif __aarch64__
  assert(rm != sp);
#endif
  int apply_offset = 0;
  if (rn == sp) {
    apply_offset = ctx->code.plugin_pushed_reg_count;
    apply_offset *= sizeof(uintptr_t);
  }

#ifdef __arm__
  if (rn == pc) {
    uint32_t addr = read_addr_to_pc(ctx->code.read_address);
    if (rm <= -reg_invalid || rm >= reg_invalid) {
      addr += offset;
      offset = 0;
    }
    int rtpc = reg;
    if (reg == rm) {
      rtmp = (reg == 0) ? 1 : 0;
      emit_push(ctx, 1 << rtmp);
      rtpc = rtmp;
    }
    emit_set_reg(ctx, rtpc, addr);
    rn = rtpc;
  }
#endif

  if (rm <= -reg_invalid || rm >= reg_invalid) {
    offset += apply_offset;
    emit_add_sub_i(ctx, reg, rn, offset);
  } else {
#ifdef __arm__
    emit_add_sub_shift(ctx, reg, rn, rm, offset & 3, offset >> 2);
#elif __aarch64__
    emit_a64_add_sub_ext(ctx, reg, rn, rm, offset & 7, offset >> 3);
#endif
    if (apply_offset != 0) {
      assert(apply_offset <= 0xFFF && apply_offset > 0);
      emit_add_sub_i(ctx, reg, reg, apply_offset);
    }
  }

#ifdef __arm__
  if (rtmp != reg_invalid) {
    emit_pop(ctx, 1 << rtmp);
  }
#endif
}

#ifdef __arm__
int _thumb_calc_ld_st_addr(mambo_context *ctx, enum reg reg) {
  switch(ctx->code.inst) {
    case THUMB_LDMFD16:
    case THUMB_STMEA16: {
      uint32_t rn, reglist;
      thumb_stmea16_decode_fields(ctx->code.read_address, &rn, &reglist);
      _generate_addr(ctx, reg, rn, reg_invalid, 0);
      return 0;
    }

    case THUMB_LDR16:
    case THUMB_LDRB16:
    case THUMB_LDRH16:
    case THUMB_LDRSB16:
    case THUMB_LDRSH16:
    case THUMB_STR16:
    case THUMB_STRB16:
    case THUMB_STRH16: {
      uint32_t rm, rn, rt;
      thumb_ldr16_decode_fields(ctx->code.read_address, &rm, &rn, &rt);
      _generate_addr(ctx, reg, rn, rm, 0);
      return 0;
    }

    case THUMB_LDRI16:
    case THUMB_LDRBI16:
    case THUMB_LDRHI16:
    case THUMB_STRI16:
    case THUMB_STRBI16:
    case THUMB_STRHI16: {
      uint32_t imm5, rn, rd;
      thumb_ldri16_decode_fields(ctx->code.read_address, &imm5, &rn, &rd);
      if (ctx->code.inst == THUMB_LDRI16 || ctx->code.inst == THUMB_STRI16) {
        imm5 <<= 2;
      } else if (ctx->code.inst == THUMB_LDRHI16 || ctx->code.inst == THUMB_STRHI16) {
        imm5 <<= 1;
      }
      _generate_addr(ctx, reg, rn, reg_invalid, imm5);
      return 0;
    }

    case THUMB_LDR_PC_16: {
      uint32_t rd, imm8, addr;
      thumb_ldr_pc_16_decode_fields(ctx->code.read_address, &rd, &imm8);
      addr = (uint32_t)ctx->code.read_address + 4;
      addr &= ~3;
      addr += imm8 << 2;
      emit_thumb_copy_to_reg_32bit(ctx, reg, addr);
      return 0;
    }

    case THUMB_LDR_SP16:
    case THUMB_STR_SP16: {
      uint32_t rd, imm8;
      thumb_ldr_sp16_decode_fields(ctx->code.read_address, &rd, &imm8);
      imm8 <<= 2;
      _generate_addr(ctx, reg, sp, reg_invalid, imm8);
      return 0;
    }

    case THUMB_POP16:
    case THUMB_VFP_VPOP: {
      _generate_addr(ctx, reg, sp, reg_invalid, 0);
      return 0;
    }

    case THUMB_PUSH16: {
      uint32_t regs, offset;
      thumb_push16_decode_fields(ctx->code.read_address, &regs);
      offset = count_bits(regs) << 2;
      _generate_addr(ctx, reg, sp, reg_invalid, -offset);
      return 0;
    }

    case THUMB_LDMEA32:
    case THUMB_LDMFD32:
    case THUMB_STMEA32:
    case THUMB_STMFD32: {
      uint32_t w, rn, regs, offset = 0;
      thumb_ldmea32_decode_fields(ctx->code.read_address, &w, &rn, &regs);
      if (ctx->code.inst == THUMB_LDMEA32 || ctx->code.inst == THUMB_STMFD32) {
        offset = count_bits(regs) << 2;
      }
      _generate_addr(ctx, reg, rn, reg_invalid, -offset);
      return 0;
    }

    case THUMB_LDR32:
    case THUMB_LDRB32:
    case THUMB_LDRH32:
    case THUMB_LDRSB32:
    case THUMB_LDRSH32:
    case THUMB_STR32:
    case THUMB_STRB32:
    case THUMB_STRH32: {
      uint32_t rn, rd, shift, rm;
      thumb_ldr32_decode_fields(ctx->code.read_address, &rn, &rd, &shift, &rm);
      _generate_addr(ctx, reg, rn, rm, LSL | (shift << 2));
      return 0;
    }

    case THUMB_LDRI32:
    case THUMB_LDRBI32:
    case THUMB_LDRHI32:
    case THUMB_LDRSBI32:
    case THUMB_LDRSHI32:
    case THUMB_LDRT32:
    case THUMB_LDRBT32:
    case THUMB_LDRHT32:
    case THUMB_LDRSBT32:
    case THUMB_LDRSHT32:
    case THUMB_STRI32:
    case THUMB_STRBI32:
    case THUMB_STRHI32:
    case THUMB_STRT32:
    case THUMB_STRBT32:
    case THUMB_STRHT32: {
      uint32_t rn, rd, imm8, p, u, w;
      thumb_ldri32_decode_fields(ctx->code.read_address, &rd, &rn, &imm8, &p, &u, &w);
      if (u == 0) {
        imm8 = -imm8;
      }
      _generate_addr(ctx, reg, rn, reg_invalid, p ? imm8 : 0);
      return 0;
    }

    case THUMB_LDRWI32:
    case THUMB_LDRBWI32:
    case THUMB_LDRHWI32:
    case THUMB_LDRSBWI32:
    case THUMB_LDRSHWI32:
    case THUMB_STRWI32:
    case THUMB_STRBWI32:
    case THUMB_STRHWI32: {
      uint32_t rd, rn, imm12;
      thumb_ldrwi32_decode_fields(ctx->code.read_address, &rd, &rn, &imm12);
      _generate_addr(ctx, reg, rn, reg_invalid, imm12);
      return 0;
    }

    case THUMB_LDRD32:
    case THUMB_STRD32: {
      uint32_t p, u, w, rn, rt, rt2, imm8;
      thumb_ldrd32_decode_fields(ctx->code.read_address, &p, &u, &w, &rn, &rt, &rt2, &imm8);
      imm8 <<= 2;
      if (u == 0) {
        imm8 = -imm8;
      }
      _generate_addr(ctx, reg, rn, reg_invalid, p ? imm8 : 0);
      return 0;
    }

    case THUMB_LDRBL32:
    case THUMB_LDRHL32:
    case THUMB_LDRL32:
    case THUMB_LDRSBL32:
    case THUMB_LDRSHL32: {
      uint32_t rt, imm12, u, addr;
      thumb_ldrl32_decode_fields(ctx->code.read_address, &rt, &imm12, &u);
      addr = read_addr_to_pc(ctx->code.read_address) + (u ? imm12 : -imm12);
      emit_thumb_copy_to_reg_32bit(ctx, reg, addr);
      return 0;
    }

    case THUMB_VFP_VPUSH: {
      uint32_t size, d, vd, regs;
      thumb_vfp_vpush_decode_fields(ctx->code.read_address, &size, &d, &vd, &regs);
      _generate_addr(ctx, reg, sp, reg_invalid, -4 * regs);
      return 0;
    }

    case THUMB_STREX32:
    case THUMB_LDREX32: {
      uint32_t rn, rt, rd, imm8;
      thumb_strex32_decode_fields(ctx->code.read_address, &rn, &rt, &rd, &imm8);
      _generate_addr(ctx, reg, rn, reg_invalid, imm8 << 2);
      return 0;
    }

    case THUMB_VFP_VLDM_SP:
    case THUMB_VFP_VLDM_DP:
    case THUMB_VFP_VSTM_SP:
    case THUMB_VFP_VSTM_DP: {
      uint32_t p, u, w, rn, d, vd, imm8;
      thumb_vfp_vstm_dp_decode_fields(ctx->code.read_address, &p, &u, &w, &rn, &d, &vd, &imm8);
      assert(p != u);
      int offset = 0;
	    if (u == 0) {
	      offset = -count_bits(imm8) * 4;
	    }
	    _generate_addr(ctx, reg, rn, reg_invalid, offset);
      return 0;
    }

    case THUMB_VFP_VLDR_SP:
    case THUMB_VFP_VLDR_DP:
    case THUMB_VFP_VSTR_SP:
    case THUMB_VFP_VSTR_DP: {
      uint32_t u, rn, d, vd, imm8;
      thumb_vfp_vstr_sp_decode_fields(ctx->code.read_address, &u, &rn, &d, &vd, &imm8);
      if (u == 0) {
        imm8 = -imm8;
      }
      _generate_addr(ctx, reg, rn, reg_invalid, imm8 << 2);
      return 0;
    }

    case THUMB_LDREXB32:
    case THUMB_LDREXD32:
    case THUMB_LDREXH32:
    case THUMB_STREXB32:
    case THUMB_STREXD32:
    case THUMB_STREXH32: {
      uint32_t rn, rt;
      thumb_ldrexb32_decode_fields(ctx->code.read_address, &rn, &rt);
      _generate_addr(ctx, reg, rn, reg_invalid, 0);
      return 0;
    }

    case THUMB_NEON_VLDX_M:
    case THUMB_NEON_VLDX_S_O:
    case THUMB_NEON_VLDX_S_A:
    case THUMB_NEON_VSTX_M:
    case THUMB_NEON_VSTX_S_O: {
      uint32_t opcode, size, d, vd, rn, align, rm;
      // rm only used for post-incrementing
      thumb_neon_vldx_m_decode_fields(ctx->code.read_address, &opcode, &size, &d, &vd, &rn, &align, &rm);
      _generate_addr(ctx, reg, rn, reg_invalid, 0);
      return 0;
    }

    case THUMB_LDC32:
    case THUMB_LDC232:
    case THUMB_STC32:
    case THUMB_STC232:
      fprintf(stderr, "Address decoding for T32 instruction %d not implemented yet\n", ctx->code.inst);
      assert(0);
      break;
  }
  return -1;
}

void _decode_arm(bool is_imm, uint32_t p, uint32_t u, uint32_t op2, uint32_t *rm, int *imm) {
  *rm = reg_invalid;

  if (p) {
    if (is_imm) {
      if (u) {
        *imm = op2;
      } else {
        *imm = -op2;
      }
    } else {
      *rm = op2 & 0xF;
      *imm = op2 >> 5;
      if (u == 0) {
        *rm = -(*rm);
      }
    }
  } else {
    *imm = 0;
  }
}

int _arm_calc_ld_st_addr(mambo_context *ctx, enum reg reg) {
  switch(ctx->code.inst) {
    case ARM_LDR:
    case ARM_STR:
    case ARM_LDRB:
    case ARM_STRB:
    case ARM_LDRT:
    case ARM_STRT:
    case ARM_LDRBT:
    case ARM_STRBT: {
      uint32_t i, rd, rn, operand2, p, u, w;
      int rm, imm;
      arm_str_decode_fields(ctx->code.read_address, &i, &rd, &rn, &operand2, &p, &u, &w);
      _decode_arm(i == IMM_LDR, p, u, operand2, &rm, &imm);
      _generate_addr(ctx, reg, rn, rm, imm);
      return 0;
    }

    case ARM_LDRD:
    case ARM_STRD:
    case ARM_LDRH:
    case ARM_STRH:
    case ARM_LDRSB:
    case ARM_LDRSH:
    case ARM_LDRHT:
    case ARM_STRHT:
    case ARM_LDRSBT:
    case ARM_LDRSHT: {
      uint32_t i, rd, rn, rm_imm4l, imm4h, p, u, w;
      int rm, imm;
      arm_ldrd_decode_fields(ctx->code.read_address, &i, &rd, &rn, &rm_imm4l, &imm4h, &p, &u, &w);
      _decode_arm(i, p, u, (imm4h << 4) | rm_imm4l, &rm, &imm);
      if (i == 0) imm = 0;
      _generate_addr(ctx, reg, rn, rm, imm);
      return 0;
    }

    case ARM_LDM:
    case ARM_STM: {
      uint32_t rn, regs, p, u, w, s;
      arm_stm_decode_fields(ctx->code.read_address, &rn, &regs, &p, &u, &w, &s);
      int offset = u ? 0 : -4 *(count_bits(regs) -1);
      if (p) {
        offset += u ? 4 : -4;
      }
      _generate_addr(ctx, reg, rn, reg_invalid, offset);
      return 0;
    }

    case ARM_NEON_VLDX_M:
    case ARM_NEON_VLDX_S_O:
    case ARM_NEON_VLDX_S_A:
    case ARM_NEON_VSTX_M:
    case ARM_NEON_VSTX_S_O: {
      uint32_t op, sz, d, vd, rn, align, rm;
      arm_neon_vldx_m_decode_fields(ctx->code.read_address, &op, &sz, &d, &vd, &rn, &align, &rm);
      // rm only used for post-incrementing
      _generate_addr(ctx, reg, rn, reg_invalid, 0);
	    return 0;
    }

    case ARM_LDREX:
    case ARM_LDREXB:
    case ARM_LDREXD:
    case ARM_LDREXH:
    case ARM_STREX:
    case ARM_STREXB:
    case ARM_STREXD:
    case ARM_STREXH: {
      uint32_t rd, rn;
      arm_ldrex_decode_fields(ctx->code.read_address, &rd, &rn);
      _generate_addr(ctx, reg, rn, reg_invalid, 0);
      return 0;
    }

    case ARM_VFP_VLDM_DP:
    case ARM_VFP_VLDM_SP:
    case ARM_VFP_VSTM_DP:
    case ARM_VFP_VSTM_SP:
    case ARM_VFP_VPOP_DP:
    case ARM_VFP_VPOP_SP:
    case ARM_VFP_VPUSH_DP:
    case ARM_VFP_VPUSH_SP: {
      uint32_t p, u, d, w, rn, vd, imm8;
      arm_vfp_vldm_dp_decode_fields(ctx->code.read_address, &p, &u, &d, &w, &rn, &vd, &imm8);
      assert(p != u);
      _generate_addr(ctx, reg, rn, reg_invalid, u ? 0 : -(imm8 << 2));
      return 0;
    }

    case ARM_VFP_VLDR_DP:
    case ARM_VFP_VLDR_SP:
    case ARM_VFP_VSTR_DP:
    case ARM_VFP_VSTR_SP: {
      uint32_t u, d, rn, vd, imm8;
      arm_vfp_vldr_dp_decode_fields(ctx->code.read_address, &u, &d, &rn, &vd, &imm8);
      if (u == 0) {
        imm8 = -imm8;
      }
	    _generate_addr(ctx, reg, rn, reg_invalid, imm8 << 2);
      return 0;
    }

    case ARM_LDC:
    case ARM_STC:
      fprintf(stderr, "Address decoding for A32 instruction %d not implemented yet\n", ctx->code.inst);
      assert(0);
      break;
  }
  return -1;
}
#endif

#ifdef __aarch64__
int _a64_calc_ld_st_addr(mambo_context *ctx, enum reg reg) {
  switch (ctx->code.inst) {
    case A64_LDP_STP: {
      uint32_t opc, v, type, l, imm7, rt2, rn, rt;
      a64_LDP_STP_decode_fields(ctx->code.read_address, &opc, &v, &type, &l, &imm7, &rt2, &rn, &rt);
      int offset = sign_extend32(7, imm7) << (2 + (opc >> (1 - v)));
      _generate_addr(ctx, reg, rn, reg_invalid, (type != 1) ? offset : 0);
      return 0;
    }
    case A64_LDR_STR_UNSIGNED_IMMED: {
      uint32_t size, v, opc, imm12, rn, rt;
      a64_LDR_STR_unsigned_immed_decode_fields(ctx->code.read_address, &size, &v, &opc, &imm12, &rn, &rt);
      int offset = imm12 << (((v & (opc >> 1)) << 2) + size);
      _generate_addr(ctx, reg, rn, reg_invalid, offset);
      return 0;
    }
    case A64_LDR_STR_IMMED: {
      uint32_t size, v, opc, imm9, type, rn, rt;
      a64_LDR_STR_immed_decode_fields(ctx->code.read_address, &size, &v, &opc, &imm9, &type, &rn, &rt);
      int offset = sign_extend32(9, imm9);
      _generate_addr(ctx, reg, rn, reg_invalid, (type != 1) ? offset : 0);
      return 0;
    }
    case A64_LDR_LIT: {
      uint32_t opc, v, imm19, rt;
      a64_LDR_lit_decode_fields(ctx->code.read_address, &opc, &v, &imm19, &rt);
      uintptr_t offset = sign_extend64(19, imm19) << 2;
      uintptr_t addr = (uintptr_t)ctx->code.read_address + offset;
      emit_set_reg(ctx, reg, addr);
      return 0;
    }
    case A64_LDR_STR_REG: {
      uint32_t size, v, opc, rm, opt, s, rn, rt;
      a64_LDR_STR_reg_decode_fields(ctx->code.read_address, &size, &v, &opc, &rm, &opt, &s, &rn, &rt);
      if (rm == x31) {
        _generate_addr(ctx, reg, rn, reg_invalid, 0);
      } else {
        int shift = s ? (((v & (opc >> 1)) << 2) + size) : 0;
        _generate_addr(ctx, reg, rn, rm, (shift << 3) | opt);
      }
      return 0;
    }
    case A64_LDX_STX: {
      uint32_t size, o2, l, o1, rs, o0, rt2, rn, rt;
      a64_LDX_STX_decode_fields(ctx->code.read_address, &size, &o2, &l, &o1, &rs, &o0, &rt2, &rn, &rt);
      _generate_addr(ctx, reg, rn, reg_invalid, 0);
      return 0;
    }
    case A64_LDX_STX_MULTIPLE: {
      uint32_t q, l, op, size, rn, rt;
      a64_LDx_STx_multiple_decode_fields(ctx->code.read_address, &q, &l, &op, &size, &rn, &rt);
      _generate_addr(ctx, reg, rn, reg_invalid, 0);
      return 0;
    }
    case A64_LDX_STX_MULTIPLE_POST: {
      uint32_t q, l, rm, op, sz, rn, rt;
      a64_LDx_STx_multiple_post_decode_fields(ctx->code.read_address, &q, &l, &rm, &op, &sz, &rn, &rt);
      _generate_addr(ctx, reg, rn, reg_invalid, 0);
      return 0;
    }
    case A64_LDX_STX_SINGLE: {
      uint32_t q, l, r, op, s, size, rn, rt;
      a64_LDx_STx_single_decode_fields(ctx->code.read_address, &q, &l, &r, &op, &s, &size, &rn, &rt);
      _generate_addr(ctx, reg, rn, reg_invalid, 0);
      return 0;
    }
    case A64_LDX_STX_SINGLE_POST: {
      uint32_t q, l, r, rm, op, s, size, rn, rt;
      a64_LDx_STx_single_post_decode_fields(ctx->code.read_address, &q, &l, &r, &rm, &op, &s, &size, &rn, &rt);
      _generate_addr(ctx, reg, rn, reg_invalid, 0);
      return 0;
    }
  }

  return -1;
}
#endif


int mambo_calc_ld_st_addr(mambo_context *ctx, enum reg reg) {
#ifdef __arm__
  if (ctx->code.inst_type == THUMB_INST) {
    return _thumb_calc_ld_st_addr(ctx, reg);
  } else if (ctx->code.inst_type == ARM_INST) {
    return _arm_calc_ld_st_addr(ctx, reg);
  }
  return -1;
#elif __aarch64__
  return _a64_calc_ld_st_addr(ctx, reg);
#endif
}

#ifdef __aarch64__
int _a64_get_ld_st_size(mambo_context *ctx) {
  int size = -1;

  switch (ctx->code.inst) {
    case A64_LDR_LIT: {
      uint32_t opc, v, imm19, rt;
      a64_LDR_lit_decode_fields(ctx->code.read_address, &opc, &v, &imm19, &rt);
      if (v) {
        size = 4 << opc;
      } else {
        size = 4 << (opc & 1);
      }
      break;
    }
    case A64_LDP_STP: {
      uint32_t opc, v, type, l, imm7, rt2, rn, rt;
      a64_LDP_STP_decode_fields(ctx->code.read_address, &opc, &v, &type, &l, &imm7, &rt2, &rn, &rt);
      if (v) {
        size = (8 << opc);
      } else {
        size = 8 << (opc >> 1);
      }
      break;
    }
    case A64_LDR_STR_REG:
    case A64_LDR_STR_IMMED:
    case A64_LDR_STR_UNSIGNED_IMMED: {
      uint32_t sz, v, opc, imm12, rn, rt;
      a64_LDR_STR_unsigned_immed_decode_fields(ctx->code.read_address, &sz, &v, &opc, &imm12, &rn, &rt);
      if (v) {
        size = (1 << (sz + ((opc >> 1) << 2)));
      } else {
        size = 1 << sz;
      }
      break;
    }
    case A64_LDX_STX: {
      uint32_t sz, o2, l, o1, rs, o0, rt2, rn, rt;
      a64_LDX_STX_decode_fields(ctx->code.read_address, &sz, &o2, &l, &o1, &rs, &o0, &rt2, &rn, &rt);
      size = 1 << (sz + o1);
      break;
    }
    case A64_LDX_STX_MULTIPLE:
    case A64_LDX_STX_MULTIPLE_POST: {
      uint32_t q, l, op, sz, rn, rt;
      a64_LDx_STx_multiple_decode_fields(ctx->code.read_address, &q, &l, &op, &sz, &rn, &rt);
      int regs = 0;
      switch (op) {
        case 0x0: // LD/ST4
        case 0x2: // LD/ST1
          regs = 4;
          break;
        case 0x4: // LD/ST3
        case 0x6: // LD/ST1
          regs = 3;
          break;
        case 0x8: // LD/ST2
        case 0xA: // LD/ST1
          regs = 2;
          break;
        case 0x7: // LD/ST1
          regs = 1;
          break;
        default:
          fprintf(stderr, "Unsupported LDx/STx opcode %x at %p\n", op, ctx->code.read_address);
          exit(EXIT_FAILURE);
      }
      size = regs * (8 << q);
      break;
    }
    case A64_LDX_STX_SINGLE:
    case A64_LDX_STX_SINGLE_POST: {
      uint32_t q, l, r, op, s, sz, rn, rt;
      a64_LDx_STx_single_decode_fields(ctx->code.read_address, &q, &l, &r, &op, &s, &sz, &rn, &rt);
      int regs = (((op & 1) << 1) | r) + 1;
      int scale = (op >> 1);
      switch (scale) {
        case 3:
          scale = sz;
          break;
        case 2:
          if (sz & 1) {
            scale = 3;
          }
          break;
      }
      size = (1 << scale) * regs;
      break;
    }
  } // switch

  return size;
}
#endif

#ifdef __arm__
// Same decoding logic on A32 and T32
int _get_size_vldx_vstx_m(void *read_addr, bool is_thumb) {
  uint32_t op, sz, d, vd, rn, align, rm;
  if (is_thumb) {
    thumb_neon_vldx_m_decode_fields(read_addr, &op, &sz, &d, &vd, &rn, &align, &rm);
  } else {
    arm_neon_vldx_m_decode_fields(read_addr, &op, &sz, &d, &vd, &rn, &align, &rm);
  }
  int regs = 0;

  switch (op) {
    case 0x7:
      regs = 1;
      break;
    case 0x8:
    case 0x9:
    case 0xA:
      regs = 2;
      break;
    case 0x4:
    case 0x5:
    case 0x6:
      regs = 3;
      break;
    case 0x0:
    case 0x1:
    case 0x2:
    case 0x3:
      regs = 4;
      break;
    default:
      fprintf(stderr, "Unsupported VLDx (multiple) opcode %x at %p\n", op, read_addr);
      exit(EXIT_FAILURE);
  }
  return regs * 8;
}

int _thumb_get_ld_st_size(mambo_context *ctx) {
  int size = -1;

  switch(ctx->code.inst) {
    // Fixed-size loads / stores
    case THUMB_LDRB16:
    case THUMB_LDRBI16:
    case THUMB_LDRSB16:
    case THUMB_STRB16:
    case THUMB_STRBI16:
    case THUMB_LDRB32:
    case THUMB_LDRBI32:
    case THUMB_LDRBL32:
    case THUMB_LDRBT32:
    case THUMB_LDRBWI32:
    case THUMB_LDRSB32:
    case THUMB_LDRSBI32:
    case THUMB_LDRSBL32:
    case THUMB_LDRSBT32:
    case THUMB_LDRSBWI32:
    case THUMB_STRB32:
    case THUMB_STRBI32:
    case THUMB_STRBT32:
    case THUMB_STRBWI32:
    case THUMB_LDREXB32:
    case THUMB_STREXB32:
      size = 1;
      break;

    case THUMB_LDRH16:
    case THUMB_LDRHI16:
    case THUMB_LDRSH16:
    case THUMB_STRH16:
    case THUMB_STRHI16:
    case THUMB_LDRH32:
    case THUMB_LDRHI32:
    case THUMB_LDRHL32:
    case THUMB_LDRHT32:
    case THUMB_LDRHWI32:
    case THUMB_LDRSH32:
    case THUMB_LDRSHI32:
    case THUMB_LDRSHL32:
    case THUMB_LDRSHT32:
    case THUMB_LDRSHWI32:
    case THUMB_STRH32:
    case THUMB_STRHI32:
    case THUMB_STRHT32:
    case THUMB_STRHWI32:
    case THUMB_LDREXH32:
    case THUMB_STREXH32:
      size = 2;
      break;

    case THUMB_LDR16:
    case THUMB_LDRI16:
    case THUMB_LDR_PC_16:
    case THUMB_LDR_SP16:
    case THUMB_STR16:
    case THUMB_STRI16:
    case THUMB_STR_SP16:
    case THUMB_LDR32:
    case THUMB_LDRI32:
    case THUMB_LDRL32:
    case THUMB_LDRT32:
    case THUMB_LDRWI32:
    case THUMB_STR32:
    case THUMB_STRI32:
    case THUMB_STRT32:
    case THUMB_STRWI32:
    case THUMB_LDREX32:
    case THUMB_STREX32:
    case THUMB_VFP_VLDR_SP:
    case THUMB_VFP_VSTR_SP:
      size = 4;
      break;

    case THUMB_LDRD32:
    case THUMB_STRD32:
    case THUMB_LDREXD32:
    case THUMB_STREXD32:
    case THUMB_VFP_VLDR_DP:
    case THUMB_VFP_VSTR_DP:
      size = 8;
      break;

    // Variable-sized loads / stores
    case THUMB_LDMFD32:
    case THUMB_STMFD32:
    case THUMB_LDMEA32:
    case THUMB_STMEA32: {
      uint32_t w, rn, reglist;
      thumb_stmfd32_decode_fields(ctx->code.read_address, &w, &rn, &reglist);
      size = count_bits(reglist) * 4;
      break;
    }

    case THUMB_LDMFD16:
    case THUMB_STMEA16: {
      uint32_t rn, reglist;
      thumb_ldmfd16_decode_fields(ctx->code.read_address, &rn, &reglist);
      size = count_bits(reglist) * 4;
      break;
    }

    case THUMB_PUSH16:
    case THUMB_POP16: {
      uint32_t reglist;
      thumb_push16_decode_fields(ctx->code.read_address, &reglist);
      size = count_bits(reglist) * 4;
      break;
    }

    case THUMB_VFP_VPUSH:
    case THUMB_VFP_VPOP:
    case THUMB_VFP_VLDM_DP:
    case THUMB_VFP_VLDM_SP:
    case THUMB_VFP_VSTM_DP:
    case THUMB_VFP_VSTM_SP: {
      uint32_t sz, d, vd, regs;
      thumb_vfp_vpush_decode_fields(ctx->code.read_address, &sz, &d, &vd, &regs);
      size = regs * 4;
      break;
    }

    case THUMB_NEON_VLDX_S_O:
    case THUMB_NEON_VSTX_S_O: {
      uint32_t op, sz, d, vd, rn, align, rm;
      thumb_neon_vldx_s_o_decode_fields(ctx->code.read_address, &op, &sz, &d, &vd, &rn, &align, &rm);
      size = (1 << sz) * (op + 1);
      break;
    }

    case THUMB_NEON_VLDX_S_A: {
      uint32_t op, sz, d, vd, inc, rn, align, rm;
      thumb_neon_vldx_s_a_decode_fields(ctx->code.read_address, &op, &sz, &d, &vd, &inc, &rn, &align, &rm);
      size = (1 << sz) * (op + 1);
	    break;
    }

    case THUMB_NEON_VLDX_M:
    case THUMB_NEON_VSTX_M:
      size = _get_size_vldx_vstx_m(ctx->code.read_address, true);
      break;

    case THUMB_LDC232:
    case THUMB_LDC32:
    case THUMB_STC32:
    case THUMB_STC232:
      fprintf(stderr, "Size decoding for T32 instruction %d not implemented yet\n", ctx->code.inst);
      assert(0);
      break;
  }

  return size;
}

int _arm_get_ld_st_size(mambo_context *ctx) {
  int size = -1;

  switch(ctx->code.inst) {
    // Fixed-size loads / stores
    case ARM_LDRB:
    case ARM_LDRBT:
    case ARM_LDRSB:
    case ARM_LDRSBT:
    case ARM_STRB:
    case ARM_STRBT:
    case ARM_LDREXB:
    case ARM_STREXB:
      size = 1;
      break;

    case ARM_LDRH:
    case ARM_LDRHT:
    case ARM_LDRSH:
    case ARM_LDRSHT:
    case ARM_STRH:
    case ARM_STRHT:
    case ARM_LDREXH:
    case ARM_STREXH:
      size = 2;
      break;

    case ARM_LDR:
    case ARM_LDRT:
    case ARM_STR:
    case ARM_STRT:
    case ARM_LDREX:
    case ARM_STREX:
    case ARM_VFP_VLDR_SP:
    case ARM_VFP_VSTR_SP:
      size = 4;
      break;

    case ARM_LDRD:
    case ARM_STRD:
    case ARM_LDREXD:
    case ARM_STREXD:
    case ARM_VFP_VLDR_DP:
    case ARM_VFP_VSTR_DP:
      size = 8;
      break;

    // Variable-sized loads / stores
    case ARM_LDM:
    case ARM_STM: {
      uint32_t rn, reglist, p, u, w, s;
      arm_ldm_decode_fields(ctx->code.read_address, &rn, &reglist, &p, &u, &w, &s);
      size = count_bits(reglist) * 4;
      break;
    }

    case ARM_VFP_VLDM_DP:
    case ARM_VFP_VLDM_SP:
    case ARM_VFP_VSTM_DP:
    case ARM_VFP_VSTM_SP:
    case ARM_VFP_VPUSH_DP:
    case ARM_VFP_VPUSH_SP:
    case ARM_VFP_VPOP_DP:
    case ARM_VFP_VPOP_SP: {
      uint32_t p, u, d, w, rn, vd, imm8;
      arm_vfp_vldm_sp_decode_fields(ctx->code.read_address, &p, &u, &d, &w, &rn, &vd, &imm8);
      size = imm8 * 4;
      break;
    }

    case ARM_NEON_VLDX_S_O:
    case ARM_NEON_VSTX_S_O: {
      uint32_t op, sz, d, vd, rn, align, rm;
      arm_neon_vldx_s_o_decode_fields(ctx->code.read_address, &op, &sz, &d, &vd, &rn, &align, &rm);
      size = (1 << sz) * (op + 1);
      break;
    }

    case ARM_NEON_VLDX_S_A: {
      uint32_t op, sz, d, vd, inc, rn, align, rm;
      arm_neon_vldx_s_a_decode_fields(ctx->code.read_address, &op, &sz, &d, &vd, &inc, &rn, &align, &rm);
      size = (1 << sz) * (op + 1);
      break;
    }

    case ARM_NEON_VLDX_M:
    case ARM_NEON_VSTX_M:
      size = _get_size_vldx_vstx_m(ctx->code.read_address, false);
      break;

    case ARM_LDC:
    case ARM_STC:
      fprintf(stderr, "Size decoding for A32 instruction %d not implemented yet\n", ctx->code.inst);
      assert(0);
  }

  return size;
}
#endif

int mambo_get_ld_st_size(mambo_context *ctx) {
#ifdef __arm__
  if (ctx->code.inst_type == THUMB_INST) {
    return _thumb_get_ld_st_size(ctx);
  } else if (ctx->code.inst_type == ARM_INST) {
    return _arm_get_ld_st_size(ctx);
  }
#elif __aarch64__
  return _a64_get_ld_st_size(ctx);
#endif
  return -1;
}


#endif
