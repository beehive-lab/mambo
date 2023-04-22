/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2018 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
  Copyright 2018 The University of Manchester

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

// Uncomment to count prefetch instructions
// #define COUNT_PRFM

#include <stdio.h>
#include <assert.h>
#include <locale.h>
#include <inttypes.h>
#include "../plugins.h"

struct instructions {
  uint64_t integer;
  uint64_t floating;
  uint64_t load;
  uint64_t store;
  uint64_t branch;
#ifdef COUNT_PRFM
  uint64_t prefetch;
#endif
#ifdef __riscv
  uint64_t atomic;
#endif
};

struct instructions global_counters = {0};

// Callback function prototypes
int instruction_count_pre_thread_handler(mambo_context *ctx);
int instruction_count_pre_inst_handler(mambo_context *ctx);
int instruction_count_post_thread_handler(mambo_context *ctx);
int instruction_count_exit_handler(mambo_context *ctx);

// Auxiliary function to print the counters
void print_counters(struct instructions *counters);

// Plugin registration and event callbacks function
__attribute__((constructor)) void branch_count_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_pre_thread_cb(ctx, &instruction_count_pre_thread_handler);
  mambo_register_pre_inst_cb(ctx, &instruction_count_pre_inst_handler);
  mambo_register_post_thread_cb(ctx, &instruction_count_post_thread_handler);
  mambo_register_exit_cb(ctx, &instruction_count_exit_handler);
}

int instruction_count_pre_thread_handler(mambo_context *ctx) {
  // Thread private counters initialisation
  struct instructions *counters = mambo_alloc(ctx, sizeof(struct instructions));
  assert(counters != NULL);
  mambo_set_thread_plugin_data(ctx, counters);

  counters->integer = 0;
  counters->floating = 0;
  counters->load = 0;
  counters->store = 0;
  counters->branch = 0;
#ifdef COUNT_PRFM
  counters->prefetch = 0;
#endif
#ifdef __riscv
  counters->atomic = 0;
#endif
}

int instruction_count_post_thread_handler(mambo_context *ctx) {
  // On thread exit, the counters are added to the global counters
  struct instructions *counters = mambo_get_thread_plugin_data(ctx);

  fprintf(stderr, "Thread: %d\n", mambo_get_thread_id(ctx));

  // Prints thread private counters
  print_counters(counters); // comment this out if not needed

  atomic_increment_u64(&global_counters.integer, counters->integer);
  atomic_increment_u64(&global_counters.floating, counters->floating);
  atomic_increment_u64(&global_counters.load, counters->load);
  atomic_increment_u64(&global_counters.store, counters->store);
  atomic_increment_u64(&global_counters.branch, counters->branch);
#ifdef COUNT_PRFM
  atomic_increment_u64(&global_counters.prefetch, counters->prefetch);
#endif
#ifdef __riscv
  atomic_increment_u64(&global_counters.atomic, counters->atomic);
#endif
  mambo_free(ctx, counters);
}

int instruction_count_pre_inst_handler(mambo_context *ctx) {
  struct instructions *counters = mambo_get_thread_plugin_data(ctx);
  uint64_t *inst_counter = NULL;

#ifdef __aarch64__
  // Variables are used for decoding the fields of intructions
	uint32_t sf, rm, opcode, rn, rd;

  // Selects the appropriate counter according to the instruction type
  switch (ctx->code.inst) {
  // Branches, Exception Generating and System instructions Category
      // * Branches instructions
  case A64_B_BL:
  case A64_B_COND:
  case A64_CBZ_CBNZ:
  case A64_TBZ_TBNZ:
  case A64_BR:
  case A64_BLR:
  case A64_RET:
    inst_counter = &counters->branch;
    break;

      // * Exception Generating
  case A64_SVC:
  case A64_HVC:
  case A64_BRK:
    break;

      // * System instructions
  case A64_SYS:
  case A64_MRS_MSR_REG:
  case A64_HINT:
  case A64_DSB:
  case A64_DMB:
  case A64_ISB:
  case A64_CLREX:
    break;

  // Data Processing -- Immediate
  case A64_ADD_SUB_IMMED:
  case A64_LOGICAL_IMMED:
  case A64_BFM:
  case A64_ADR:
  case A64_EXTR:
  case A64_MOV_WIDE:
    inst_counter = &counters->integer;
    break;

  // Loads and Stores
  case A64_LDR_LIT:
  case A64_LDX_STX:
  case A64_LDP_STP:
  case A64_LDR_STR_IMMED:
  case A64_LDR_STR_REG:
  case A64_LDR_STR_UNSIGNED_IMMED:
  case A64_LDX_STX_MULTIPLE:
  case A64_LDX_STX_MULTIPLE_POST:
  case A64_LDX_STX_SINGLE:
  case A64_LDX_STX_SINGLE_POST:
    if (mambo_is_load(ctx)) {
      inst_counter = &counters->load;
    } else if (mambo_is_store(ctx)) {
      inst_counter = &counters->store;
    } else {
#ifdef COUNT_PRFM
      inst_counter = &counters->prefetch;
#endif
    }
    break;

  // Data Processing -- Register
  case A64_ADD_SUB_EXT_REG:
  case A64_ADD_SUB_SHIFT_REG:
  case A64_ADC_SBC:
    inst_counter = &counters->integer;
    break;

  case A64_DATA_PROC_REG1:
  case A64_CCMP_CCMN_IMMED:
  case A64_CCMP_CCMN_REG:
  case A64_COND_SELECT:
  case A64_LOGICAL_REG:
  case A64_DATA_PROC_REG3:
    inst_counter = &counters->integer;
    break;

  case A64_DATA_PROC_REG2:
    a64_data_proc_reg2_decode_fields(ctx->code.read_address, &sf, &rm, &opcode, &rn, &rd);
    if ((opcode == 2) || (opcode == 3)) { // UDIV or SDIV
      inst_counter = &counters->integer;
    }
    break;


  // Data Processing -- Scalar Floating-Point and Advanced SIMD
    // * Floating point instructions
  case A64_FCMP:
  case A64_FCCMP:
  case A64_FCSEL:
  case A64_FLOAT_REG1:
  case A64_FLOAT_REG2:
  case A64_FLOAT_REG3:
  case A64_FMOV_IMMED:
  case A64_FLOAT_CVT_FIXED:
  case A64_FLOAT_CVT_INT:
    inst_counter = &counters->floating;
    break;

    // *SIMD
  case A64_SIMD_ACROSS_LANE:
  case A64_SIMD_COPY:
  case A64_SIMD_EXTRACT:
  case A64_SIMD_MODIFIED_IMMED:
  case A64_SIMD_PERMUTE:
  case A64_SIMD_SCALAR_COPY:
  case A64_SIMD_SCALAR_PAIRWISE:
  case A64_SIMD_SCALAR_SHIFT_IMMED:
  case A64_SIMD_SCALAR_THREE_DIFF:
  case A64_SIMD_SCALAR_THREE_SAME:
  case A64_SIMD_SHIFT_IMMED:
  case A64_SIMD_TABLE_LOOKUP:
  case A64_SIMD_THREE_DIFF:
  case A64_SIMD_THREE_SAME:
  case A64_SIMD_SCALAR_TWO_REG:
  case A64_SIMD_SCALAR_X_INDEXED:
  case A64_SIMD_TWO_REG:
  case A64_SIMD_X_INDEXED:
  case A64_CRYPTO_AES:
  case A64_CRYPTO_SHA_REG3:
  case A64_CRYPTO_SHA_REG2:
    break;

  default:
    break;
  }

#elif __riscv
  switch (ctx->code.inst) {
    case RISCV_C_ADDI4SPN:
    case RISCV_C_NOP:
    case RISCV_C_ADDI:
    case RISCV_C_ADDIW:
    case RISCV_C_LI:
    case RISCV_C_LUI:
    case RISCV_C_SRLI:
    case RISCV_C_SRAI:
    case RISCV_C_ANDI:
    case RISCV_C_SUB:
    case RISCV_C_XOR:
    case RISCV_C_OR:
    case RISCV_C_AND:
    case RISCV_C_SUBW:
    case RISCV_C_ADDW:
    case RISCV_C_ADDI16SP:
    case RISCV_C_SLLI:
    case RISCV_C_MV:
    case RISCV_C_ADD:
    case RISCV_LUI:
    case RISCV_AUIPC:
    case RISCV_ADDI:
    case RISCV_SLTI:
    case RISCV_SLTIU:
    case RISCV_XORI:
    case RISCV_ORI:
    case RISCV_ANDI:
    case RISCV_SLLI:
    case RISCV_SRLI:
    case RISCV_SRAI:
    case RISCV_ADD:
    case RISCV_SUB:
    case RISCV_SLL:
    case RISCV_SLT:
    case RISCV_SLTU:
    case RISCV_XOR:
    case RISCV_SRL:
    case RISCV_SRA:
    case RISCV_OR:
    case RISCV_AND:
    case RISCV_ADDIW:
    case RISCV_SLLIW:
    case RISCV_SRLIW:
    case RISCV_SRAIW:
    case RISCV_ADDW:
    case RISCV_SUBW:
    case RISCV_SLLW:
    case RISCV_SRLW:
    case RISCV_SRAW:
    case RISCV_MUL:
    case RISCV_MULH:
    case RISCV_MULHSU:
    case RISCV_MULHU:
    case RISCV_DIV:
    case RISCV_DIVU:
    case RISCV_REM:
    case RISCV_REMU:
    case RISCV_MULW:
    case RISCV_DIVW:
    case RISCV_DIVUW:
    case RISCV_REMW:
    case RISCV_REMUW:
      inst_counter = &counters->integer;
      break;

    case RISCV_C_JAL:
    case RISCV_C_J:
    case RISCV_C_BEQZ:
    case RISCV_C_BNEZ:
    case RISCV_JAL:
    case RISCV_JALR:
    case RISCV_BEQ:
    case RISCV_BNE:
    case RISCV_BLT:
    case RISCV_BGE:
    case RISCV_BLTU:
    case RISCV_BGEU:
    case RISCV_C_JR:
    case RISCV_C_JALR:
      inst_counter = &counters->branch;
      break;

    case RISCV_C_FLD:
    case RISCV_C_LW:
    case RISCV_C_LD:
    case RISCV_C_FLDSP:
    case RISCV_C_LWSP:
    case RISCV_C_FLWSP:
    case RISCV_C_LDSP:
    case RISCV_LB:
    case RISCV_LH:
    case RISCV_LW:
    case RISCV_LBU:
    case RISCV_LHU:
    case RISCV_LWU:
    case RISCV_LD:
    case RISCV_LR_D:
    case RISCV_LR_W:
    case RISCV_FLW:
    case RISCV_FLD:
      inst_counter = &counters->load;
      break;

    case RISCV_C_FSD:
    case RISCV_C_SW:
    case RISCV_C_SD:
    case RISCV_C_FSDSP:
    case RISCV_C_SWSP:
    case RISCV_C_SDSP:
    case RISCV_SB:
    case RISCV_SH:
    case RISCV_SW:
    case RISCV_SD:
    case RISCV_SC_W:
    case RISCV_SC_D:
    case RISCV_FSW:
    case RISCV_FSD:
      inst_counter = &counters->store;
      break;

    case RISCV_C_EBREAK:
    case RISCV_FENCE:
    case RISCV_ECALL:
    case RISCV_EBREAK:
    case RISCV_FENCEI:
    case RISCV_CSRRW:
    case RISCV_CSRRS:
    case RISCV_CSRRC:
    case RISCV_CSRRWI:
    case RISCV_CSRRSI:
    case RISCV_CSRRCI:
      break;

    case RISCV_AMOSWAP_W:
    case RISCV_AMOADD_W:
    case RISCV_AMOXOR_W:
    case RISCV_AMOAND_W:
    case RISCV_AMOOR_W:
    case RISCV_AMOMIN_W:
    case RISCV_AMOMAX_W:
    case RISCV_AMOMINU_W:
    case RISCV_AMOMAXU_W:
    case RISCV_AMOSWAP_D:
    case RISCV_AMOADD_D:
    case RISCV_AMOXOR_D:
    case RISCV_AMOAND_D:
    case RISCV_AMOOR_D:
    case RISCV_AMOMIN_D:
    case RISCV_AMOMAX_D:
    case RISCV_AMOMINU_D:
    case RISCV_AMOMAXU_D:
      inst_counter = &counters->atomic;
      break;

    case RISCV_FMADD_S:
    case RISCV_FMSUB_S:
    case RISCV_FNMSUB_S:
    case RISCV_FNMADD_S:
    case RISCV_FADD_S:
    case RISCV_FSUB_S:
    case RISCV_FMUL_S:
    case RISCV_FDIV_S:
    case RISCV_FSQRT_S:
    case RISCV_FSGNJ_S:
    case RISCV_FSGNJN_S:
    case RISCV_FSGNJX_S:
    case RISCV_FMIN_S:
    case RISCV_FMAX_S:
    case RISCV_FCVT_W_S:
    case RISCV_FCVT_WU_S:
    case RISCV_FMV_X_W:
    case RISCV_FEQ_S:
    case RISCV_FLT_S:
    case RISCV_FLE_S:
    case RISCV_FCLASS_S:
    case RISCV_FCVT_S_W:
    case RISCV_FCVT_S_WU:
    case RISCV_FMV_W_X:
    case RISCV_FCVT_L_S:
    case RISCV_FCVT_LU_S:
    case RISCV_FCVT_S_L:
    case RISCV_FCVT_S_LU:
    case RISCV_FMADD_D:
    case RISCV_FMSUB_D:
    case RISCV_FNMSUB_D:
    case RISCV_FNMADD_D:
    case RISCV_FADD_D:
    case RISCV_FSUB_D:
    case RISCV_FMUL_D:
    case RISCV_FDIV_D:
    case RISCV_FSQRT_D:
    case RISCV_FSGNJ_D:
    case RISCV_FSGNJN_D:
    case RISCV_FSGNJX_D:
    case RISCV_FMIN_D:
    case RISCV_FMAX_D:
    case RISCV_FCVT_S_D:
    case RISCV_FCVT_D_S:
    case RISCV_FEQ_D:
    case RISCV_FLT_D:
    case RISCV_FLE_D:
    case RISCV_FCLASS_D:
    case RISCV_FCVT_W_D:
    case RISCV_FCVT_WU_D:
    case RISCV_FCVT_D_W:
    case RISCV_FCVT_D_WU:
    case RISCV_FCVT_L_D:
    case RISCV_FCVT_LU_D:
    case RISCV_FMV_X_D:
    case RISCV_FCVT_D_L:
    case RISCV_FCVT_D_LU:
    case RISCV_FMV_D_X:
      inst_counter = &counters->floating;
      break;
  }
#else
  #error Unsupported architecture
#endif
  if (inst_counter != NULL) {
    emit_counter64_incr(ctx, inst_counter, 1);
  }
}

int instruction_count_exit_handler(mambo_context *ctx) {
  // On application exit prints the global counters
  fprintf(stderr, "Total:\n");
  print_counters(&global_counters);
}

void print_counters(struct instructions *counters) {
  // Auxiliary function to print the counters
  fprintf(stderr, "  integer : %'" PRIu64 "\n", counters->integer);
  fprintf(stderr, "  floating: %'" PRIu64 "\n", counters->floating);
  fprintf(stderr, "  load    : %'" PRIu64 "\n", counters->load);
  fprintf(stderr, "  store   : %'" PRIu64 "\n", counters->store);
  fprintf(stderr, "  branch  : %'" PRIu64 "\n", counters->branch);
#ifdef COUNT_PRFM
  fprintf(stderr, "  prefetch: %'" PRIu64 "\n", counters->prefetch);
#endif
#ifdef __riscv
  fprintf(stderr, "  atomic: %'" PRIu64 "\n", counters->atomic);
#endif
}
#endif
