/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2017-2019 The University of Manchester

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
#include <assert.h>

#include "../dbm.h"
#include "../common.h"
#include "../plugins.h"

#ifdef __arm__
  #include "../pie/pie-thumb-decoder.h"
  #include "../pie/pie-thumb-field-decoder.h"
  #include "../pie/pie-arm-decoder.h"
  #include "../pie/pie-arm-field-decoder.h"
#endif
#ifdef __aarch64__
  #include "../pie/pie-a64-decoder.h"
  #include "../pie/pie-a64-field-decoder.h"
#endif

#ifdef PLUGINS_NEW

#ifdef __arm__
mambo_branch_type __get_thumb_branch_type(mambo_context *ctx) {
  mambo_branch_type type = BRANCH_NONE;

  switch (ctx->code.inst) {
    case THUMB_MOVH16: {
      uint32_t dn, rm, rdn;
      thumb_movh16_decode_fields(ctx->code.read_address, &dn, &rm, &rdn);
      rdn |= dn << 3;
      if (rdn == pc) {
        type =  BRANCH_INDIRECT;
        if (rm == lr) {
          type |= BRANCH_RETURN;
        }
      }
      break;
    }
    case THUMB_POP16: {
      uint32_t reglist;
      thumb_pop16_decode_fields(ctx->code.read_address, &reglist);
      if (reglist & (1 << 8)) {
        type =  BRANCH_INDIRECT | BRANCH_RETURN | BRANCH_INTERWORKING;
      }
      break;
    }
    case THUMB_LDRI32: {
      uint32_t rn, rt, imm8, p, u, w;
      thumb_ldri32_decode_fields(ctx->code.read_address, &rt, &rn, &imm8, &p, &u, &w);
      if (rt == pc) {
        type =  BRANCH_INDIRECT | BRANCH_INTERWORKING;
        if (rn == sp) {
          type |= BRANCH_RETURN;
        }
      }
      break;
    }
    case THUMB_LDR32: {
      uint32_t rn, rt, shift, rm;
      thumb_ldr32_decode_fields(ctx->code.read_address, &rn, &rt, &shift, &rm);
      if (rt == pc) {
        type =  BRANCH_INDIRECT | BRANCH_INTERWORKING;
        if (rn == sp) {
          type |= BRANCH_RETURN;
        }
      }
      break;
    }
    case THUMB_LDMFD32:
    case THUMB_LDMEA32: {
      uint32_t w, rn, reglist;
      thumb_ldmfd32_decode_fields(ctx->code.read_address, &w, &rn, &reglist);
	    if (reglist & (1 << pc)) {
	      type =  BRANCH_INDIRECT | BRANCH_INTERWORKING;
        if (rn == sp) {
          type |= BRANCH_RETURN;
        }
	    }
	    break;
    }
    case THUMB_BX16: {
      uint32_t rm;
      thumb_bx16_decode_fields(ctx->code.read_address, &rm);
      type =  BRANCH_INDIRECT | BRANCH_INTERWORKING;
      if (rm == lr) {
        type |= BRANCH_RETURN;
      }
      break;
    }
    case THUMB_BLX16:
      type =  BRANCH_INDIRECT | BRANCH_CALL | BRANCH_INTERWORKING;
      break;
    case THUMB_BL32:
      type =  BRANCH_DIRECT | BRANCH_CALL;
      break;
    case THUMB_BL_ARM32:
      type =  BRANCH_DIRECT | BRANCH_CALL | BRANCH_INTERWORKING;
      break;
    case THUMB_B16:
    case THUMB_B32:
      type =  BRANCH_DIRECT;
      break;
    case THUMB_CBZ16:
    case THUMB_CBNZ16:
      type =  BRANCH_DIRECT | BRANCH_COND | BRANCH_COND_CBZ;
      break;
    case THUMB_B_COND16:
    case THUMB_B_COND32:
      type =  BRANCH_DIRECT | BRANCH_COND | BRANCH_COND_PSR;
      break;
    case THUMB_TBB32:
    case THUMB_TBH32:
      type =  BRANCH_INDIRECT | BRANCH_TABLE;
      break;
  } // switch

  if (type != BRANCH_NONE && (type & BRANCH_COND) == 0 && mambo_get_cond(ctx) != AL) {
    type |= BRANCH_COND | BRANCH_COND_PSR | BRANCH_COND_IT;
  }

  return type;
}

mambo_branch_type __get_arm_branch_type(mambo_context *ctx) {
  mambo_branch_type type = BRANCH_NONE;

  switch (ctx->code.inst) {
    case ARM_ADC:
    case ARM_ADD:
    case ARM_EOR:
    case ARM_MOV:
    case ARM_ORR:
    case ARM_SBC:
    case ARM_SUB:
    case ARM_RSC: {
      uint32_t immediate, opcode, set_flags, rd, rn, operand2, rm = reg_invalid;
      arm_data_proc_decode_fields(ctx->code.read_address, &immediate, &opcode, &set_flags, &rd, &rn, &operand2);
      if (rd == pc) {
        type = BRANCH_INDIRECT | BRANCH_INTERWORKING;
      }
      break;
    }
    case ARM_BX: {
      uint32_t rn;
      arm_bx_decode_fields(ctx->code.read_address, &rn);
      type = BRANCH_INDIRECT | BRANCH_INTERWORKING;
      if (rn == lr) {
        type |= BRANCH_RETURN;
      }
      break;
    }
    case ARM_LDM: {
      uint32_t rn, regs, p, u, w, s;
      arm_ldm_decode_fields(ctx->code.read_address, &rn, &regs, &p, &u, &w, &s);
	    if (regs & (1 << pc)) {
	      type = BRANCH_INDIRECT | BRANCH_INTERWORKING;
	      if (rn == sp) {
	        type |= BRANCH_RETURN;
	      }
	    }
      break;
    }
    case ARM_LDR: {
      uint32_t i, rd, rn, op2, p, u, w;
      arm_ldr_decode_fields(ctx->code.read_address, &i, &rd, &rn, &op2, &p, &u, &w);
      if (rd == pc) {
        type = BRANCH_INDIRECT | BRANCH_INTERWORKING;
	      if (rn == sp) {
	        type |= BRANCH_RETURN;
	      }
      }
      break;
    }
    case ARM_BLX:
      type = BRANCH_INDIRECT | BRANCH_INTERWORKING | BRANCH_CALL;
      break;
    case ARM_B:
      type = BRANCH_DIRECT;
      break;
    case ARM_BL:
      type = BRANCH_DIRECT | BRANCH_CALL;
      break;
    case ARM_BLXI:
      type = BRANCH_DIRECT | BRANCH_CALL | BRANCH_INTERWORKING;
      break;
  }

  if (type != BRANCH_NONE && mambo_get_cond(ctx) != AL) {
    type |= BRANCH_COND | BRANCH_COND_PSR;
  }

  return type;
}
#endif // __arm__

mambo_branch_type mambo_get_branch_type(mambo_context *ctx) {
  mambo_branch_type type;

#ifdef __arm__
  if (mambo_get_inst_type(ctx) == THUMB_INST) {
   type = __get_thumb_branch_type(ctx);
  } else { // ARM
   type = __get_arm_branch_type(ctx);
  }
#endif
#ifdef __aarch64__
  type = BRANCH_NONE;

  switch (ctx->code.inst) {
    case A64_CBZ_CBNZ:
      type = BRANCH_DIRECT | BRANCH_COND | BRANCH_COND_CBZ;
      break;
    case A64_B_COND:
      type = BRANCH_DIRECT | BRANCH_COND | BRANCH_COND_PSR;
      break;
    case A64_TBZ_TBNZ:
      type = BRANCH_DIRECT | BRANCH_COND | BRANCH_COND_TBZ;
      break;
    case A64_BR:
      type = BRANCH_INDIRECT;
      break;
    case A64_BLR:
      type = BRANCH_INDIRECT | BRANCH_CALL;
      break;
    case A64_RET:
      type = BRANCH_INDIRECT | BRANCH_RETURN;
      break;
    case A64_B_BL: {
      uint32_t op, imm26;
      a64_B_BL_decode_fields(ctx->code.read_address, &op, &imm26);

      type = BRANCH_DIRECT;
      if (op == 1) { // BL
        type |= BRANCH_CALL;
      }
      break;
    }
  }
#endif // __aarch64__

  return type;
}

#ifdef __arm__
void _arm_target_load(mambo_context *ctx, uint32_t i, enum reg target, enum reg rn, int op2) {
  if (i == LDR_REG) assert((op2 & 0xF) != sp);
  if (rn == pc) {
    assert(i == IMM_LDR);
    emit_set_reg(ctx, target, (uint32_t)mambo_get_source_addr(ctx) + 8 + op2);
    // LDR target, [target]
    emit_arm_ldr(ctx, i, target, target, 0, 1, 1, 0);
  } else {
    if (rn == sp) {
      // adjust here
      if (i == IMM_LDR) {
        op2 += ctx->code.plugin_pushed_reg_count * sizeof(uintptr_t);
      } else {
        while(1); // unimplemented
      }
    }
    assert(abs(op2) <= 0xFFF);
    emit_arm_ldr(ctx, i, target, rn, abs(op2), 1, (op2 >= 0) ? 1 : 0, 0);
    while(i == LDR_REG); // untested
    while(op2 < 0); // untested
  }
}

int __arm_calc_br_target(mambo_context *ctx, enum reg reg) {
  switch(mambo_get_inst(ctx)) {
    case ARM_ADC:
    case ARM_ADD:
    case ARM_EOR:
    case ARM_MOV:
    case ARM_ORR:
    case ARM_SBC:
    case ARM_SUB:
    case ARM_RSC: {
      uint32_t imm, opcode, set_flags, rd, rn, operand2, rm = reg_invalid, sr = reg_invalid, spilled_r = 0;
      arm_data_proc_decode_fields(mambo_get_source_addr(ctx), &imm, &opcode, &set_flags, &rd, &rn, &operand2);
      if (rd == pc) {
        if (imm == REG_PROC) {
          rm = operand2 & 0xF;
        }
        assert(rm != pc || rn != pc);
        assert(rn != sp && rm != sp);
        assert(rm != pc || operand2 == rm);
        if (rn == pc || rm == pc) {
          /* If the target register is different from the input registers, it can be used to
             temporarily store the SPC
             Otherwise, he have to spill a scratch register to the stack */
          if ((rn == pc && reg != rm) || (rm == pc && reg != rn)) {
            sr = reg;
          } else {
            sr = r0;
            while (sr == reg || sr == rm) {
              sr++;
            }
            spilled_r = 1 << sr;
            emit_push(ctx, spilled_r);
          }
          if (rn == pc) {
            rn = sr;
          } else {
            //rm = sr;
            operand2 = sr;
          }
          emit_set_reg(ctx, sr, (uint32_t)mambo_get_source_addr(ctx) + 8);
        }
        emit_arm_data_proc(ctx, imm, opcode, 0, reg, rn, operand2);
        if (spilled_r) {
          emit_pop(ctx, spilled_r);
        }
        return 0;
      }
      break;
    }
    case ARM_BX:
    case ARM_BLX: {
      uint32_t rn;
      arm_bx_decode_fields(ctx->code.read_address, &rn);
      if (rn != reg) {
        emit_mov(ctx, reg, rn);
      }
      return 0;
    }
    case ARM_LDM: {
      uint32_t rn, regs, p, u, w, s;
      arm_ldm_decode_fields(ctx->code.read_address, &rn, &regs, &p, &u, &w, &s);
	    if (regs & (1 << pc)) {
        int offset = (count_bits(regs)-1) << 2;
        if (!u) offset = -offset;
        _arm_target_load(ctx, IMM_LDR, reg, rn, offset);
        while(p != 0 || u != 1 || s != 0);
        return 0;
	    }
      break;
    }
    case ARM_LDR: {
      uint32_t i, rd, rn, op2, p, u, w;
      arm_ldr_decode_fields(ctx->code.read_address, &i, &rd, &rn, &op2, &p, &u, &w);
      if (rd == pc) {
        if (w == 1) {
          w = 0;
        }
        if (p == 0) {
          //p = 1;
          op2 = 0;
          i = IMM_LDR;
        }
        _arm_target_load(ctx, i, reg, rn, u ? op2 : -op2);
        return 0;
      }
      break;
    }
    case ARM_B:
    case ARM_BL: {
      uint32_t offset;
      int32_t branch_offset;
      arm_b_decode_fields(mambo_get_source_addr(ctx), &offset);
      branch_offset = (offset<<2);
      branch_offset |= (offset & 0x2000000) ? 0xFC000000 : 0;
      uint32_t target = (int32_t)mambo_get_source_addr(ctx) + 8 + branch_offset;
      emit_set_reg(ctx, reg, target);
      return 0;
    }
    case ARM_BLXI: {
      uint32_t h, offset, branch_offset;
      arm_blxi_decode_fields(mambo_get_source_addr(ctx), &h, &offset);
      branch_offset = ((h << 1) | (offset << 2)) + 1;
      branch_offset |= (offset & 0x2000000) ? 0xFC000000 : 0;
      uint32_t target = (uint32_t)mambo_get_source_addr(ctx) + 8 + branch_offset;
      emit_set_reg(ctx, reg, target);
      while(offset & 0x2000000);
      return 0;
    }
  }
  return -1;
}

void _thumb_target_load_i(mambo_context *ctx, enum reg target, enum reg rn, int imm) {
  if (rn == sp) {
    // adjust here
    imm += ctx->code.plugin_pushed_reg_count * sizeof(uintptr_t);
  }

  if (imm >= 0) {
    assert(imm <= 0xFFF);
    emit_thumb_ldrwi32(ctx, target, rn, imm);
  } else {
    assert(abs(imm) <= 0x7FF);
    emit_thumb_ldri32(ctx, target, rn, abs(imm), 1, 0, 0);
    while(1); // untested
  }
}

void _thumb_target_load(mambo_context *ctx, enum reg target, enum reg rn, enum reg rm, uint32_t shift) {
  assert(rn != pc);
  if (rn == sp) {
    int offset = ctx->code.plugin_pushed_reg_count * sizeof(uintptr_t);
    // ADD TARGET, RN, RM, LSL #shift
    // LDR TARGET, [TARGET, #offset]
    assert(offset <= 0xFFF);
    emit_thumb_add32(ctx, 0, rn, shift >> 2, target, shift, 0, rm);
    emit_thumb_ldrwi32(ctx, target, target, offset);
    while(1); // untested
  } else {
    emit_thumb_ldr32(ctx, rn, target, shift, rm);
  }
}

int __thumb_calc_br_target(mambo_context *ctx, enum reg reg) {
  uintptr_t target;
  void *read_address = mambo_get_source_addr(ctx);
  int inst = mambo_get_inst(ctx);
  /* First check if the instruction is a direct branch */
  int ret = _thumb_get_dir_br_target(read_address, inst, &target);
  if (ret == 0) {
    emit_set_reg(ctx, reg, target);
    return 0;
  }

  switch (inst) {
    case THUMB_MOVH16: {
      uint32_t dn, rm, rdn;
      thumb_movh16_decode_fields(read_address, &dn, &rm, &rdn);
      rdn |= dn << 3;
      if (rdn == pc) {
        assert(rm != sp && rm != pc);
        emit_thumb_movh16(ctx, (reg >> 3), rm, reg & 0x7);
        return 0;
      }
      break;
    }
    case THUMB_POP16: {
      uint32_t reglist;
      thumb_pop16_decode_fields(read_address, &reglist);
      if (reglist & (1 << 8)) {
        int offset = (count_bits(reglist)-1) << 2;
        _thumb_target_load_i(ctx, reg, sp, offset);
        return 0;
      }
      break;
    }
    case THUMB_LDRI32: {
      uint32_t rn, rt, imm8, p, u, w;
      thumb_ldri32_decode_fields(read_address, &rt, &rn, &imm8, &p, &u, &w);
      if (rt == pc) {
        int offset = 0;
        if (p) {
          offset = u ? imm8 : -imm8;
        }
        _thumb_target_load_i(ctx, reg, rn, offset);
        while(p); // untested
        return 0;
      }
      break;
    }
    case THUMB_LDR32: {
      uint32_t rn, rt, shift, rm;
      thumb_ldr32_decode_fields(read_address, &rn, &rt, &shift, &rm);
      if (rt == pc) {
        _thumb_target_load(ctx, reg, rn, rm, shift);
        return 0;
      }
      break;
    }
    case THUMB_LDMEA32:
      while(1);
      break;
    case THUMB_LDMFD32: {
      uint32_t w, rn, reglist;
      thumb_ldmfd32_decode_fields(read_address, &w, &rn, &reglist);
      if (reglist & (1 << pc)) {
        int offset = (count_bits(reglist)-1) << 2;
        _thumb_target_load_i(ctx, reg, rn, offset);
        return 0;
      }
      break;
    }
    case THUMB_BX16:
    case THUMB_BLX16: {
      uint32_t rm;
      thumb_bx16_decode_fields(read_address, &rm);
      if (rm == pc) {
        emit_set_reg(ctx, reg, ((uint32_t)read_address + 4) & (~3));
      } else {
        emit_mov(ctx, reg, rm);
      }
      return 0;
    }
    case THUMB_TBB32:
    case THUMB_TBH32: {
      uint32_t rn, rm;
      int sr = r0;
      thumb_tbh32_decode_fields(read_address, &rn, &rm);
      assert(rm != pc);
      while (sr == rn || sr == rm || sr == reg) {
        sr++;
      }
      if (rn == pc) {
        rn = sr;
      }

      emit_push(ctx, 1 << sr);
      emit_set_reg(ctx, sr, (uint32_t)read_address + 4);

      if (inst == THUMB_TBB32) {
        // LDRB reg, [RN, RM]
        emit_thumb_ldrb32(ctx, rn, reg, 0, rm);
      } else {
        // LDRH reg, [RN, RM, LSL #1]
        emit_thumb_ldrh32(ctx, rn, reg, 1, rm);
      }
      // ADD reg, sr, reg, LSL #1
      emit_thumb_add32(ctx, 0, sr, 0, reg, 1, LSL, reg);
      // ADD reg, reg, #1
      emit_thumb_addi32(ctx, 0, 0, reg, 0, reg, 1);

      emit_pop(ctx, 1 << sr);
      return 0;
    }
  } // switch

  return -1;
}
#endif

#ifdef __aarch64__
void __br_set_addr_w_offset(mambo_context *ctx, enum reg reg, uintptr_t offset) {
  offset += (uintptr_t)mambo_get_source_addr(ctx);
  emit_set_reg(ctx, reg, offset);
}

int __aarch64_calc_br_target(mambo_context *ctx, enum reg reg) {
  switch(mambo_get_inst(ctx)) {
    case A64_CBZ_CBNZ: {
      uint32_t sf, op, imm, rt;
      a64_CBZ_CBNZ_decode_fields(mambo_get_source_addr(ctx), &sf, &op, &imm, &rt);
      __br_set_addr_w_offset(ctx, reg, sign_extend64(19, imm) << 2);
      return 0;
    }
    case A64_TBZ_TBNZ: {
      uint32_t b5, op, b40, imm, rt;
      a64_TBZ_TBNZ_decode_fields(mambo_get_source_addr(ctx), &b5, &op, &b40, &imm, &rt);
      __br_set_addr_w_offset(ctx, reg, sign_extend64(14, imm) << 2);
      return 0;
    }
    case A64_B_COND: {
      uint32_t imm19, cond;
      a64_B_cond_decode_fields(mambo_get_source_addr(ctx), &imm19, &cond);
      __br_set_addr_w_offset(ctx, reg, sign_extend64(19, imm19) << 2);
      return 0;
    }
    case A64_B_BL: {
      uint32_t op, imm26;
      a64_B_BL_decode_fields(mambo_get_source_addr(ctx), &op, &imm26);
      __br_set_addr_w_offset(ctx, reg, sign_extend64(26, imm26) << 2);
      return 0;
    }
    case A64_BR:
    case A64_BLR:
    case A64_RET: {
      uint32_t rn;
      a64_BR_decode_fields(mambo_get_source_addr(ctx), &rn);
      if (rn != reg) {
        emit_mov(ctx, reg, rn);
      }
      return 0;
    }
  } // switch
  return -1;
}
#endif

int mambo_calc_br_target(mambo_context *ctx, enum reg reg) {
#ifdef __arm__
  if (mambo_get_inst_type(ctx) == THUMB_INST) {
   return __thumb_calc_br_target(ctx, reg);
  } else { // ARM
   return __arm_calc_br_target(ctx, reg);
  }
#elif __aarch64__
  return __aarch64_calc_br_target(ctx, reg);
#else
  return -1;
#endif
}

#endif // PLUGINS_NEW
