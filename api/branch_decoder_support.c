/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
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

#include <stdio.h>

#include "../dbm.h"
#include "../common.h"
#include "plugin_support.h"

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
      uint32_t immediate, opcode, set_flags, rd, rn, operand2;
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

#endif // PLUGINS_NEW
