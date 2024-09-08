/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2020 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
  Copyright 2020-2021 The University of Manchester

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

#ifdef __riscv

#include <assert.h>
#include <stdio.h>

#include "dbm.h"
#include "scanner_common.h"
#include "../../api/helpers.h"

#define MIN_FSPACE 56
#define BRANCH_FSPACE 152
#define REG_JUMP_FSPACE 196

#ifdef DBM_TRIBI
#define PREDICTION_FSPACE 13
#endif

//#define DEBUG
#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

#define copy_riscv_compressed() *(write_p++) = *read_address;
#define copy_riscv()            *(uint32_t *)(write_p) = *(uint32_t *)read_address; \
                                 write_p += 2;

#include "pie/pie-riscv-decoder.h"
#include "pie/pie-riscv-encoder.h"
#include "pie/pie-riscv-field-decoder.h"

#define wordsz ((__riscv_xlen) / 8)

/* These functions could probably be in a helpers file                        */
intptr_t riscv_decode_cj_imm(uint32_t imm) {
  //  10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0
  //  11| 4| 9| 8|10| 6| 7| 3| 2| 1| 5
  intptr_t const offset = (extr(3,  1, imm) <<  1)  +
                          (extr(1,  9, imm) <<  4)  +
                          (extr(1,  0, imm) <<  5)  +
                          (extr(1,  5, imm) <<  6)  +
                          (extr(1,  4, imm) <<  7)  +
                          (extr(2,  7, imm) <<  8)  +
                          (extr(1,  6, imm) << 10)  +
                          (extr(1, 10, imm) << 11);
  return sign_extend(12, offset);
}


intptr_t riscv_decode_cb_offset(uint32_t immhi, uint32_t immlo) {
  intptr_t const offset = (extr(2, 1, immlo) << 1)  + // 2:1
                          (extr(2, 0, immhi) << 3)  + // 4:3
                          (extr(1, 0, immlo) << 5)  + // 5
                          (extr(2, 3, immlo) << 6)  + // 7:6
                          (extr(1, 2, immhi) << 8);   // 8

  return sign_extend(9, offset);
}

intptr_t riscv_decode_b_imm(uint32_t immhi, uint32_t immlo) {
  intptr_t const immediate = (extr(4, 1, immlo) << 1) +  // 4:1
                             (extr(6, 0, immhi) << 5) +  // 10:5
                             (extr(1, 0, immlo) << 11) + // 11
                             (extr(1, 6, immhi) << 12);  // 12

  return sign_extend(13, immediate);
}

intptr_t riscv_decode_j_imm(uint32_t imm) {
  intptr_t const immediate = (extr(10, 9, imm) <<  1) + // 10:1
                             (extr( 1, 8, imm) << 11) + // 11
                             (extr(8,  0, imm) << 12) + // 19:12
                             (extr( 1, 19, imm) << 20);  // 20

  return sign_extend(21, immediate);
}

int riscv_create_cb_imm_pair(riscv_imm_pair_t *pair, int const offset) {
  if ((offset & 1) || offset < -256 || offset >= 256) return -1;

  // immlo[7:6|2:1|5]
  pair->immlo = (extr(2, 6, offset) << 4) + // 7:6
                (extr(2, 1, offset) << 1) + // 2:1
                extr(1, 5, offset);         // 5

  // immhi[8|4:3]
  pair->immhi = (extr(1, 8, offset) << 2) + // 8
                extr(2, 3, offset);         // 4:3

  return 0;
}

int riscv_create_b_imm_pair(riscv_imm_pair_t *pair, int const offset) {
  if ((offset & 1) || offset < -4096 || offset >= 4096) return -1;

  // immlo[4:1|11]
  pair->immlo = extr(1, 11, offset)  +      // 11
                (extr(4,  1, offset) << 1); // 4:1

  // immhi[12|10:5]
  pair->immhi = extr(6,  5, offset) +       // 10:5
                (extr(1, 12, offset) << 6); // 12

  return 0;
}

int riscv_create_clwsp_imm_pair(riscv_imm_pair_t *pair, const unsigned int offset) {
  if ((offset & 3) || offset > 0xFF) return -1;

  pair->immhi = extr(1, 5, offset);
  pair->immlo = extr(2, 6, offset) + (extr(3, 2, offset) << 2);

  return 0;
}

int riscv_create_cldsp_imm_pair(riscv_imm_pair_t *pair, const unsigned int offset) {
  if ((offset & 7) || offset > 0x1FF) return -1;

  pair->immhi = extr(1, 5, offset);
  pair->immlo = extr(3, 6, offset) + (extr(2, 3, offset) << 3);

  return 0;
}

int riscv_create_c_addi16sp_pair(riscv_imm_pair_t *pair, const int offset) {
  if ((offset & 0xF) || offset < -512 || offset >= 512) return -1;

  pair->immhi = extr(1, 9, offset);
  pair->immlo = (extr(1, 4, offset) << 4) +
               (extr(1, 6, offset) << 3) +
               (extr(2, 7, offset) << 1) +
               extr(1, 5, offset);

  return 0;
}

void riscv_push_offset(uint16_t **o_write_p, uint32_t regs, unsigned int off) {
  uint16_t *write_p = *o_write_p;

  int offset = (count_bits(regs) + off) * wordsz;
  assert(offset <= 0x7FF);
  riscv_addi(&write_p, sp, sp, -offset);
  write_p += 2;
  for (int o = 0; regs; o += wordsz) {
    uint32_t reg = 0;
    get_lowest_n_regs(regs, &reg, 1);
    regs &= ~(1 << reg);
#if __riscv_xlen == 32
    riscv_sw(&write_p, reg, sp, o >> 5, o);
#elif __riscv_xlen == 64
    riscv_sd(&write_p, reg, sp, o >> 5, o);
#else
  #error riscv_push not implemented
#endif
    write_p += 2;
  }

  *o_write_p = write_p;
}

void riscv_push(uint16_t **o_write_p, uint32_t regs) {
  return riscv_push_offset(o_write_p, regs, 0);
}

void riscv_pop(uint16_t **o_write_p, uint32_t regs) {
  uint16_t *write_p = *o_write_p;

  int o = 0;
  for (; regs; o += wordsz) {
    uint32_t reg = 0;
    get_lowest_n_regs(regs, &reg, 1);
    regs &= ~(1 << reg);
#ifdef __riscv_compressed
    riscv_imm_pair_t imm;
  #if __riscv_xlen == 32
    int ret = riscv_create_clwsp_imm_pair(&imm, o);
    assert(ret == 0);
    riscv_c_lwsp(&write_p, reg, imm.immhi, imm.immlo);
  #elif __riscv_xlen == 64
    int ret = riscv_create_cldsp_imm_pair(&imm, o);
    assert(ret == 0);
    riscv_c_ldsp(&write_p, reg, imm.immhi, imm.immlo);
  #else
    #error riscv_pop with compressed instructions not available
  #endif
    write_p++;
    continue;
#endif

#if __riscv_xlen == 32
    riscv_lw(&write_p, reg, sp, o);
#elif __riscv_xlen == 64
    riscv_ld(&write_p, reg, sp, o);
#else
  #error riscv_pop not implemented
#endif
    write_p += 2;
  }

#ifdef __riscv_compressed
  riscv_imm_pair_t imm;
  int ret = riscv_create_c_addi16sp_pair(&imm, o);
  if (ret == 0) {
    riscv_c_addi16sp(&write_p, imm.immhi, imm.immlo);
    write_p++;
  } else {
#endif
  assert(o <= 0x7FF);
  riscv_addi(&write_p, sp, sp, o);
  write_p += 2;
#ifdef __riscv_compressed
  }
#endif

  *o_write_p = write_p;
}

void riscv_restore_context(uint16_t **o_write_p) {
  uint16_t *write_p = *o_write_p;

  riscv_pop(&write_p, (1 << a0) | (1 << a1));

  *o_write_p = write_p;
}

void riscv_save_context(uint16_t **o_write_p) {
  uint16_t *write_p = *o_write_p;

  riscv_push(&write_p, (1 << s1) | (1 << a0) | (1 << a1));

  *o_write_p = write_p;
}

// LLVM (https://github.com/llvm/llvm-project/blob/master/llvm/lib/Target/RISCV/Utils/RISCVMatInt.cpp#L19)
//       (https://github.com/llvm/llvm-project/blob/master/llvm/lib/Target/RISCV/Disassembler/RISCVDisassembler.cpp)
void riscv_copy_to_reg_32bits(uint16_t **write_p, const enum reg reg,
                              uint32_t const value) {
  int32_t const low12 = (int32_t)sign_extend32(12, value & 0xFFF);
  int32_t const hi20 = ((value + 0x800) >> 12) & 0xFFFFF;

  // if the top 20 bits are not zero LUI reg, imm
  if (hi20 != 0) {
    riscv_lui(write_p, reg, hi20);
    *write_p += 2;
  }

  // if the low 12 bits is not 0, (or if the higher bits is 0 this is to catch if the val is 0)
  if ((low12 != 0) || (hi20 == 0)) {
#if __riscv_xlen == 32
    riscv_addi(write_p, reg, (hi20 != 0) ? reg : x0, low12);
#elif __riscv_xlen == 64
    riscv_addiw(write_p, reg, (hi20 != 0) ? reg : x0, low12);
#elif __riscv_xlen == 128
    error "Risc-V 128 not implemented"
#endif
    *write_p += 2;
  }

  // v == 0                  : ADDI
  // low12 != 0 && hi20 == 0 : ADDI
  // low12 == 0 && hi20 != 0 : LUI
  // hi20  != 0              : LUI + ADDI(W) The W is for riscv 64bits
}

/*
  LUI + ADDIW set the 32 MSB - via riscv_copy_to_reg_32bits()
  Followed by a variable length sequence of SLLI + ADDI to fill in the bottom bits
  See the LLVM links above
*/
void riscv_copy_to_reg_64bits(uint16_t **write_p, const enum reg reg,
                              uint64_t const value) {
  if ((int64_t)value >= INT_MIN && (int64_t)value <= INT_MAX) {
    return riscv_copy_to_reg_32bits(write_p, reg, (uint32_t)(value & 0xFFFFFFFF));
  }

  int64_t lo12 = sign_extend64(12, value & 0xFFF);
  int64_t hi52 = (value + 0x800) >> 12;
  int shift = 12 + __builtin_ffsll(hi52) - 1;
  hi52 = hi52 >> (shift-12);

  riscv_copy_to_reg_64bits(write_p, reg, hi52);

  riscv_c_slli(write_p, reg, shift >> 5, shift & 0x1F);
  (*write_p)++;
  if (lo12) {
    riscv_addi(write_p, reg, reg, lo12);
    (*write_p) += 2;
  }
}

void riscv_copy_to_reg(uint16_t **write_p, const enum reg reg, uintptr_t const value) {
#if __riscv_xlen == 32
  riscv_copy_to_reg_32bits(write_p, reg, value);
#elif __riscv_xlen == 64
  riscv_copy_to_reg_64bits(write_p, reg, value);
#elif __riscv_xlen == 128
  error "Risc-V 128 not implemented"
#endif
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////// Helper Functions/////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
static inline int riscv_c_bcond_helper(uint16_t **o_write_p, uintptr_t const target,
                                       int const rs1, bool eq) {
  intptr_t const offset = target - (uintptr_t)*o_write_p;
  riscv_imm_pair_t imm_pair;
  int ret = riscv_create_cb_imm_pair(&imm_pair, offset);
  if (ret != 0) return -1;

  if (eq) {
    riscv_c_beqz(o_write_p, rs1, imm_pair.immhi, imm_pair.immlo);
  } else {
    riscv_c_bnez(o_write_p, rs1, imm_pair.immhi, imm_pair.immlo);
  }
  *o_write_p++;

  return 0;
}

int riscv_c_beqz_helper(uint16_t **o_write_p, uintptr_t const target, int const rs1) {
  return riscv_c_bcond_helper(o_write_p, target, rs1, true);
}

int riscv_c_bnez_helper(uint16_t **o_write_p, uintptr_t const target, int const rs1) {
  return riscv_c_bcond_helper(o_write_p, target, rs1, false);
}

int riscv_branch_helper(uint16_t **o_write_p, uintptr_t target, int const rs1,
                         int const rs2, enum branch_condition const condition) {
  intptr_t const offset = target - (uintptr_t)*o_write_p;
  riscv_imm_pair_t imm_pair;
  int ret = riscv_create_b_imm_pair(&imm_pair, offset);
  if (ret != 0) return -1;

  riscv_branch(o_write_p, condition, rs1, rs2, imm_pair.immhi, imm_pair.immlo);
  *o_write_p += 2;

  return 0;
}

int riscv_jalr_helper(uint16_t **o_write_p, uintptr_t target, enum reg rd, enum reg rs1) {
  intptr_t offset = target - (uintptr_t)*o_write_p;
  if (offset < INT_MIN || offset > INT_MAX) return -1;

  riscv_auipc(o_write_p, rs1, (offset + 0x800) >> 12);
  *o_write_p += 2;

  riscv_jalr(o_write_p, rd, rs1, offset & 0xFFF);
  *o_write_p += 2;

  return 0;
}

int riscv_jal_helper(uint16_t **o_write_p, uintptr_t target, enum reg rd) {
  intptr_t offset = target - (intptr_t)*o_write_p;
  if ((offset & 1) || offset < (-1024 * 1024) || offset >= (1024 * 1024)) {
    return -1;
  }
  uint32_t imm = (extr(10, 1, offset) << 9) +
                 (extr(1,  11, offset) << 8) +
                 (extr(8,  12, offset) << 0) +
                 (extr(1,  20, offset) << 19);
  riscv_jal(o_write_p, rd, imm);
  *o_write_p += 2;
  return 0;
}

void riscv_go_to_dispatcher(dbm_thread *thread_data, uint16_t **o_write_p) {
  int ret = riscv_jalr_helper(o_write_p, thread_data->dispatcher_addr, zero, s1);
  assert(ret == 0);
}

void riscv_jump(dbm_thread *thread_data, uint16_t *read_address,
               riscv_instruction const inst, int const basic_block,
               uint16_t **o_write_p, uint32_t rd, uintptr_t target) {
  uint16_t *write_p = *o_write_p;

  if (rd != zero) {
    assert(rd != s1 && rd != a0 && rd != a1);
    riscv_copy_to_reg(&write_p, rd, (uintptr_t)read_address + ((inst >= RISCV_LUI) ? 4 : 2));
  }

  thread_data->code_cache_meta[basic_block].exit_branch_type = jal_riscv;
  thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;

  riscv_save_context(&write_p);
  riscv_copy_to_reg(&write_p, a0, target);
  riscv_copy_to_reg(&write_p, a1, basic_block);
  riscv_go_to_dispatcher(thread_data, &write_p);

  *o_write_p = write_p;
}

#define CALC_RET_ADDR() ((uintptr_t)read_address + ((thread_data->code_cache_meta[basic_block].inst >= RISCV_LUI) ? 4 : 2))
#define IS_CONTEXT_REG(reg) ((reg) == s1 || (reg) == a0 || (reg) == a1)


/*
* First, push a0 and a1
* addi    sp,sp,-8/-16
* sw/sd   a0,0(sp)
* sw/sd   a1,8(sp)
*
* If rs1 is one of a0, a1 or ra and we're linking, then:
*   reg_spc = a1
*   reg_tmp = a2
* Otherwise:
*   reg_spc = rs1
*   reg_tmp = a1
*
*
* If a2 is used:
*   addi   sp,sp,-4/-8
*   sw/sd  a2,0(sp)
*   If rs1 != reg_spc:
*     addi reg_spc,rs1,imm
* Else:
*   addi reg_spc,reg_spc,imm
*
* LOAD CODE_CACHE_HASH_SIZE into a0
*
* srli  reg_tmp,reg_spc,HT_SHIFT
* and   reg_tmp,reg_tmp,a0
*
* LOAD hash table base address into a0
*
* slli  reg_tmp,reg_tmp,3/4(32-bit/64-bit)
*
* add   a0,a0,reg_tmp
*
* START OF LOOP
* LOAD  value from address in a0 into reg_tmp
* addi  a0,a0,8/16
* beqz  NOT_FOUND
* sub   reg_tmp,reg_tmp,reg_spc
* bne   START_OF_LOOP
*
*
* ########### Once an entry has been found and we are out of the loop:
*
* lw/ld  a0,-4/-8(a0)
* If a2 was used:
*   lw/ld   a2,0(a2)
*   addi    sp,sp,4/8
* If rd is not zero:
*   copy return address to rd
* jr  a0
*
*
* ########### If no entry is found:
*
* NOT_FOUND:
* mv  a0,reg_spc
* copy bb_id to a1
* If a2 was used:
*   lw/ld   a2,0(a2)
*   addi    sp,sp,4/8
* If rd is not zero:
*   copy return address to rd
*
* addi   sp,sp,-4/-8
* sw/sd  s1,0(sp)
* GO TO DISPATCHER using s1
*
*
*
*/
void riscv_inline_hash_lookup(dbm_thread *thread_data, int basic_block, uint16_t **o_write_p,
                              uint16_t *read_address, enum reg rs1, uint32_t imm, bool link,
                              bool set_meta, bool tribi) {
  uint16_t *write_p = *o_write_p;
  uint16_t *loop;
  uint16_t *branch_to_not_found;
  uint16_t reg_spc = a1;
  uint16_t reg_tmp = a2;
  bool use_a2 = false;
  if ((rs1 == a0) || (rs1 == a1) || (link && rs1 == ra)) {
    reg_spc = a1;
    reg_tmp = a2;
    use_a2 = true;
  } else {
    reg_spc = rs1;
    reg_tmp = a1;
  }

  if (set_meta)
    thread_data->code_cache_meta[basic_block].rs1 = reg_spc;

#if defined DBM_TRACES && DBM_TRIBI
  if (!tribi) {
#endif
    riscv_push(&write_p, (1 << a0) | (1 << a1));
#if defined DBM_TRACES && DBM_TRIBI
  } else {
    thread_data->code_cache_meta[basic_block].ihlu_address = (uintptr_t *)write_p;
  }
#endif
  if (use_a2) {
    riscv_push(&write_p, 1 << a2);
    if (rs1 != reg_spc) {
      riscv_addi(&write_p, reg_spc, rs1, imm);
      write_p += 2;
    }
  } else {
    riscv_addi(&write_p, reg_spc, reg_spc, imm);
    write_p += 2;
  }
  riscv_copy_to_reg(&write_p, a0, CODE_CACHE_HASH_SIZE);
  riscv_srli(&write_p, reg_tmp, reg_spc, HT_SHIFT);
  write_p += 2;
  riscv_and(&write_p, reg_tmp, reg_tmp, a0);
  write_p += 2;
  riscv_copy_to_reg(&write_p, a0,(uintptr_t)&thread_data->entry_address.entries);
#if __riscv_xlen == 32
  riscv_slli(&write_p, reg_tmp, reg_tmp, 3);
#elif __riscv_xlen == 64
  riscv_slli(&write_p, reg_tmp, reg_tmp, 4);
#endif
  write_p += 2;
  riscv_add(&write_p, a0, a0, reg_tmp);
  write_p += 2;
  loop = write_p;
#if __riscv_xlen == 32
  riscv_lw(&write_p, reg_tmp, a0, 0);
  write_p += 2;
  riscv_addi(&write_p, a0, a0, 8);
#elif __riscv_xlen == 64
  riscv_ld(&write_p, reg_tmp, a0, 0);
  write_p += 2;
  riscv_addi(&write_p, a0, a0, 16);
#else
  #error inline hash lookup not implemented
#endif
  write_p += 2;
  branch_to_not_found = write_p;
  write_p++;
  riscv_sub(&write_p, reg_tmp, reg_tmp, reg_spc);
  write_p += 2;
  riscv_branch_helper(&write_p, (uintptr_t)loop, zero, reg_tmp, BNE);
#if __riscv_xlen == 32
  riscv_lw(&write_p, a0, a0, -4);
#elif __riscv_xlen == 64
  riscv_ld(&write_p, a0, a0, -8);
#endif
  write_p += 2;

#if defined DBM_TRACES && DBM_TRIBI
  uint16_t *tribi_branch = NULL;
  if (tribi) {
    thread_data->code_cache_meta[basic_block].rs1 = rs1;
    thread_data->code_cache_meta[basic_block].imm = imm;
    riscv_copy_to_reg(&write_p, reg_tmp, (uintptr_t)thread_data->code_cache->traces);
    tribi_branch = write_p;
    write_p += 2;
  }
#endif

  if (use_a2)
    riscv_pop(&write_p, 1 << a2);

  if (thread_data->code_cache_meta[basic_block].rd != zero) {
    riscv_copy_to_reg(&write_p, thread_data->code_cache_meta[basic_block].rd, CALC_RET_ADDR());
  }

  riscv_c_jr(&write_p, a0);
  write_p++;

  riscv_c_beqz_helper(&branch_to_not_found, (uintptr_t)write_p, reg_tmp);

#if defined DBM_TRACES && DBM_TRIBI
  if (tribi) {
    riscv_branch_helper(&tribi_branch, (uintptr_t)write_p, a0, reg_tmp, BGE);
  }
#endif

  riscv_add(&write_p, a0, reg_spc, zero);
  write_p += 2;
  if (thread_data->code_cache_meta[basic_block].rd != zero) {
    riscv_copy_to_reg(&write_p, thread_data->code_cache_meta[basic_block].rd, CALC_RET_ADDR());
  }

  riscv_copy_to_reg(&write_p, a1, basic_block);

  if (use_a2) {
    riscv_pop(&write_p, 1 << a2);
  }
  if (thread_data->code_cache_meta[basic_block].rd != zero) {
    riscv_copy_to_reg(&write_p, thread_data->code_cache_meta[basic_block].rd, CALC_RET_ADDR());
  }
  riscv_push(&write_p, (1 << s1));
  riscv_go_to_dispatcher(thread_data, &write_p);
  *o_write_p = write_p;
}

#ifdef DBM_TRIBI
void insert_tribi_header(dbm_thread *thread_data, const int basic_block, uint16_t *read_address,
uint16_t **o_write_p, enum reg rs1, uint32_t imm, bool link) {
  uint16_t *write_p = *o_write_p;
  dbm_code_cache_meta *bb_meta = &thread_data->code_cache_meta[basic_block];
  bb_meta->link = link;

  if (link) {
    bb_meta->branch_skipped_addr = (uintptr_t)read_address;
  }

  riscv_push(&write_p, 1 << a0 | 1 << a1);
  bb_meta->next_prediction_slot = (uintptr_t *)write_p;

  uint16_t *ihl_jal = write_p;
  write_p += 2;


  write_p += PREDICTION_FSPACE* 2 * TRIBI_SLOTS;

  riscv_inline_hash_lookup(thread_data, basic_block, &write_p, read_address, rs1, imm, false, false, true);

  riscv_jal_helper(&ihl_jal, (uintptr_t)bb_meta->ihlu_address, zero);
  *o_write_p = write_p;
}
#endif

void riscv_jump_register(dbm_thread *thread_data, uint16_t *read_address,
                         riscv_instruction inst, const int basic_block, uint16_t **o_write_p,
                         uint32_t rd, uint32_t rs1, uint32_t imm) {
  uint16_t *write_p = *o_write_p;

  thread_data->code_cache_meta[basic_block].exit_branch_type = jalr_riscv;
  thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
  thread_data->code_cache_meta[basic_block].rd = rd;
  thread_data->code_cache_meta[basic_block].read_addr = read_address;
  thread_data->code_cache_meta[basic_block].inst = inst;

#ifdef DBM_INLINE_HASH

  /*
  * If the return register is set, we need to ensure that it will not correspond to a0, a1 or s1
  * This should not be the case as per the RISC-V spec, the only registers we should see are
  * ra or t0.
  */
  if (rd != zero) {
    assert(rd != s1 && rd != a0 && rd != a1);
  }
#if defined DBM_TRACES && DBM_TRIBI
  if (basic_block >= CODE_CACHE_SIZE) {
    insert_tribi_header(thread_data, basic_block, read_address, &write_p, rs1, imm, rd == ra);
    *o_write_p = write_p;
    return;
  }
#endif
  riscv_inline_hash_lookup(thread_data, basic_block, &write_p, read_address, rs1, imm, rd == ra, true, false);
#else

  if (rd != zero && rd != rs1) {
    riscv_copy_to_reg(&write_p, rd, CALC_RET_ADDR());
  }

  riscv_save_context(&write_p);

  /* Use a temporary register to generate the return address and
     overwrite the value on the stack */
  if (rd != zero && rd == rs1 && IS_CONTEXT_REG(rd)) {
    int tmp = s1;
    while(tmp == rd) tmp++;
    riscv_copy_to_reg(&write_p, tmp, CALC_RET_ADDR());
#if __riscv_xlen == 32
    riscv_sw(&write_p, tmp, sp, 0, sizeof(uintptr_t) * (rd - s1));
#elif __riscv_xlen == 64
    riscv_sd(&write_p, tmp, sp, 0, sizeof(uintptr_t) * (rd - s1));
#else
    #error TODO: port riscv_jump_register()
#endif
    write_p += 2;
    printf("Untested riscv_jump_register() case, attach GDB and check the output\n");
    while(1);
  }

  riscv_addi(&write_p, a0, rs1, imm);
  write_p += 2;

  /* Safe to overwrite rs, we've already read rs1 */
  if (rd != zero && rd == rs1 && !IS_CONTEXT_REG(rd)) {
    riscv_copy_to_reg(&write_p, rd, CALC_RET_ADDR());
  }

  riscv_copy_to_reg(&write_p, a1, basic_block);
  riscv_go_to_dispatcher(thread_data, &write_p);

#endif

  *o_write_p = write_p;
}

void riscv_cond_branch(dbm_thread *thread_data, uint16_t *read_address,
                       riscv_instruction inst, const int basic_block, uint16_t **o_write_p,
                       uint32_t cond, uint32_t rs1, uint32_t rs2, uintptr_t target) {
  uint16_t *write_p = *o_write_p;

  uintptr_t const fallthrough_addr = (uintptr_t)read_address + ((inst >= RISCV_LUI) ? 4 : 2);

  thread_data->code_cache_meta[basic_block].exit_branch_type = branch_riscv;
  thread_data->code_cache_meta[basic_block].exit_branch_addr = write_p;
  thread_data->code_cache_meta[basic_block].branch_taken_addr = target;
  thread_data->code_cache_meta[basic_block].branch_skipped_addr = fallthrough_addr;
  thread_data->code_cache_meta[basic_block].branch_condition = cond;
  thread_data->code_cache_meta[basic_block].rs1 = rs1;
  thread_data->code_cache_meta[basic_block].rs2 = rs2;

  for (int i = 0; i < 6; i++) {
    riscv_addi(&write_p, zero, zero, 0); // NOP
    write_p += 2;
  }

  riscv_save_context(&write_p);
  if (rs1 != a1 && rs2 != a1) {
    riscv_copy_to_reg(&write_p, a1, basic_block);
  }

  uint16_t *rv_cond_branch = write_p;
  write_p += 2;

  if (rs1 == a1 || rs2 == a1) {
    riscv_copy_to_reg(&write_p, a1, basic_block);
  }
  riscv_copy_to_reg(&write_p, a0, fallthrough_addr);
  riscv_go_to_dispatcher(thread_data, &write_p);

  uintptr_t skip_addr = (uintptr_t)write_p;
  if (rs1 == a1 || rs2 == a1) {
    riscv_copy_to_reg(&write_p, a1, basic_block);
  }
  riscv_copy_to_reg(&write_p, a0, target);
  riscv_go_to_dispatcher(thread_data, &write_p);

  riscv_branch_helper(&rv_cond_branch, skip_addr, rs1, rs2, cond);

  *o_write_p = write_p;
}

void riscv_check_free_space(dbm_thread *thread_data, uint16_t **write_p,
                          uint32_t **data_p, uint32_t size, int cur_block) {
  int basic_block;

  if ((((uint64_t)*write_p) + size) >= (uint64_t)*data_p) {
    basic_block = allocate_bb(thread_data);
    thread_data->code_cache_meta[basic_block].actual_id = cur_block;
    if ((uint32_t *)&thread_data->code_cache->blocks[basic_block] != *data_p) {
      uintptr_t target = (uintptr_t)&thread_data->code_cache->blocks[basic_block];
      int ret = riscv_jal_helper(write_p, target, zero);
      assert(ret == 0);
      *write_p = (uint16_t *)&thread_data->code_cache->blocks[basic_block];
    }
    *data_p = (uint32_t *)&thread_data->code_cache->blocks[basic_block];
    *data_p += BASIC_BLOCK_SIZE;
  }
}

bool riscv_scanner_deliver_callbacks(dbm_thread *thread_data, mambo_cb_idx cb_id,
                                     uint16_t **o_read_address, riscv_instruction inst,
                                     uint16_t **o_write_p, uint32_t **o_data_p,
                                     int const basic_block, cc_type type,
                                     bool allow_write, bool *stop) {

  bool replaced = false;
#ifdef PLUGINS_NEW
  if (global_data.free_plugin > 0) {
    uint16_t *write_p = *o_write_p;
    uint32_t *data_p = *o_data_p;
    uint16_t *read_address = *o_read_address;

    mambo_cond cond = AL;

    mambo_context ctx;
    set_mambo_context_code(&ctx, thread_data, cb_id, type, basic_block, RISCV_INST, inst, cond, read_address, write_p, data_p, stop);

    for (int i = 0; i < global_data.free_plugin; i++) {
      if (global_data.plugins[i].cbs[cb_id] != NULL) {
        ctx.code.write_p = write_p;
        ctx.code.data_p = data_p;
        ctx.plugin_id = i;
        ctx.code.replace = false;
        ctx.code.available_regs = ctx.code.pushed_regs;
        global_data.plugins[i].cbs[cb_id](&ctx);
        if (allow_write) {
          if (replaced && (write_p != ctx.code.write_p || ctx.code.replace)) {
            fprintf(stderr, "MAMBO API WARNING: plugin %d added code for overridden"
                            "instruction (%p).\n", i, read_address);
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
            emit_pop(&ctx, ctx.code.pushed_regs);
          }
          write_p = ctx.code.write_p;
          data_p = ctx.code.data_p;
          riscv_check_free_space(thread_data, &write_p, &data_p, MIN_FSPACE, basic_block);
        } else {
          assert(ctx.code.write_p == write_p);
          assert(ctx.code.data_p == data_p);
        }
      }
    }

    if (cb_id == PRE_BB_C) {
      watched_functions_t *wf = &global_data.watched_functions;
      for (int i = 0; i < wf->funcp_count; i++) {
        if (read_address == wf->funcps[i].addr) {
          _function_callback_wrapper(&ctx, wf->funcps[i].func);
          if (ctx.code.replace) {
            read_address = ctx.code.read_address;
          }
          write_p = ctx.code.write_p;
          data_p = ctx.code.data_p;
          riscv_check_free_space(thread_data, &write_p, &data_p, MIN_FSPACE, basic_block);
        }
      }
    }

    *o_write_p = write_p;
    *o_data_p = data_p;
    *o_read_address = read_address;
  }
#endif
  return replaced;
}

inline void next_instruction(riscv_instruction instruction,
                             uint16_t **o_read_address) {
  uint16_t *read_address = *o_read_address;
  if (instruction < RISCV_LUI)
    read_address++;
  else
    read_address += 2;

  *o_read_address = read_address;
}

void pass1_riscv(uint16_t *read_address, branch_type *bb_type) {
  *bb_type = unknown;

  while(*bb_type == unknown) {
    riscv_instruction instruction = riscv_decode(read_address);

    switch(instruction) {
      case RISCV_C_JAL:
      case RISCV_C_J:
      case RISCV_JAL:
        *bb_type = jal_riscv;
        break;
      case RISCV_C_JR:
      case RISCV_C_JALR:
      case RISCV_JALR:
        *bb_type = jalr_riscv;
        break;
      case RISCV_C_BEQZ:
      case RISCV_C_BNEZ:
      case RISCV_BEQ:
      case RISCV_BNE:
      case RISCV_BLT:
      case RISCV_BGE:
      case RISCV_BLTU:
      case RISCV_BGEU:
        *bb_type = branch_riscv;
        break;
      case RISCV_LR_W:
      case RISCV_SC_W:
      case RISCV_LR_D:
      case RISCV_SC_D:
        *bb_type = atomic_memory_riscv;
        break;
      case RISCV_INVALID:
        return;
    }

    next_instruction(instruction, &read_address);
  }
}

size_t scan_riscv(dbm_thread *thread_data, uint16_t *read_address,
                  int basic_block, cc_type type, uint16_t *write_p) {

  bool stop = false;
  uint16_t *start_scan = read_address;
  uint16_t *bb_entry = read_address;

  if (write_p == NULL) {
    write_p = (uint16_t *)&thread_data->code_cache->blocks[basic_block];
  }

  uint16_t const *start_address = write_p;

  uint32_t *data_p;
  if (type == mambo_bb) {
    data_p = (uint32_t *)write_p + BASIC_BLOCK_SIZE;
  } else { // mambo_trace
    data_p = (uint32_t *)&thread_data->code_cache->traces + (TRACE_CACHE_SIZE / 4);
  }

  debug("write_p: %p\n", write_p);

  if (type != mambo_trace) {
    riscv_restore_context(&write_p);
    assert(write_p == start_address + 3);
  }

  branch_type bb_type;
  pass1_riscv(read_address, &bb_type);

#ifdef DBM_TRACES
  if (type == mambo_bb && bb_type != jalr_riscv && bb_type != atomic_memory_riscv && bb_type != unknown) {
    riscv_push(&write_p, 1 << a0 | 1 << a1);
    riscv_push(&write_p, 1 << ra);
    riscv_copy_to_reg(&write_p, a1, (int)basic_block);
    if (riscv_jal_helper(&write_p, thread_data->trace_head_incr_addr, ra) !=0) {
      riscv_jalr_helper(&write_p, thread_data->trace_head_incr_addr, ra, a0);
    }
    riscv_pop(&write_p, 1 << ra);
    riscv_pop(&write_p, 1 << a0 | 1 << a1);

  }
#endif

    riscv_scanner_deliver_callbacks(thread_data, PRE_FRAGMENT_C, &read_address, -1,
                                &write_p, &data_p, basic_block, type, true, &stop);

    riscv_scanner_deliver_callbacks(thread_data, PRE_BB_C, &read_address, -1,
                                &write_p, &data_p, basic_block, type, true, &stop);

  while (!stop) {
    debug("Risc-V scan read_address: %p, w: : %p, bb: %d\n", read_address, write_p, basic_block);
    riscv_instruction const inst = riscv_decode(read_address);
    debug("  instruction enum: %d\n", (inst == RISCV_INVALID) ? -1 : inst);
    debug("  instruction word: 0x%x\n", *read_address);

#ifdef PLUGINS_NEW
    bool skip_inst = false;
    if (bb_type != atomic_memory_riscv) {
      skip_inst = riscv_scanner_deliver_callbacks(thread_data, PRE_INST_C, &read_address, inst,
                                                   &write_p, &data_p, basic_block, type, true, &stop);
    }
    if (!skip_inst) {
#endif
      switch (inst) {
#ifdef __riscv_compressed // (“C” Standard Extension for Compressed Instructions)
        case RISCV_C_J: {           // Expands to: jal     x0,  offset[11:1]
          uint32_t imm;
          riscv_c_j_decode_fields(read_address, &imm);
          const intptr_t offset = riscv_decode_cj_imm(imm);
          const uintptr_t target = (uintptr_t)read_address + offset;
          riscv_jump(thread_data, read_address, inst, basic_block, &write_p, zero, target);

          stop = true;
          break;
        }
        case RISCV_C_BEQZ:        // Expands to: beq rs1', x0, offset[8:1]
        case RISCV_C_BNEZ: {      // Expands to: bne rs1', x0, offset[8:1]
          uint32_t rs1, immhi, immlo;
          riscv_c_beqz_decode_fields(read_address, &rs1, &immhi, &immlo);
          intptr_t offset = riscv_decode_cb_offset(immhi, immlo);
          uintptr_t target = (uintptr_t)read_address + offset;
          rs1 += s0; // a value of 0 is s0 for these C instructions

          riscv_check_free_space(thread_data, &write_p, &data_p, BRANCH_FSPACE, basic_block);
          riscv_cond_branch(thread_data, read_address, inst, basic_block, &write_p,
                            (inst == RISCV_C_BEQZ) ? BEQ : BNE, rs1, zero, target);
          stop = true;
          break;
        }
        case RISCV_C_JR: {          // Expands to: jalr    x0,  0(rs1)
          uint32_t rs1;
          riscv_c_jr_decode_fields(read_address, &rs1);
          riscv_check_free_space(thread_data, &write_p, &data_p, REG_JUMP_FSPACE, basic_block);
          riscv_jump_register(thread_data, read_address, inst, basic_block,
                              &write_p, zero, rs1, 0);
          stop = true;
          break;
        }
        case RISCV_C_JALR: {       // Expands to: jalr    x1,  0(rs1)
          uint32_t rs1;
          riscv_c_jalr_decode_fields(read_address, &rs1);
          riscv_check_free_space(thread_data, &write_p, &data_p, REG_JUMP_FSPACE, basic_block);
          riscv_jump_register(thread_data, read_address, inst, basic_block,
                              &write_p, ra, rs1, 0);
          stop = true;
          break;
        }
        case RISCV_C_ILLEGAL:
        case RISCV_C_ADDI4SPN:    // Expands to: addi   rd′,  x2, nzuimm[9:2].
        case RISCV_C_FLD:         // Expands to: fld    rd′,  offset[7:3](rs1′)
        case RISCV_C_LW:          // Expands to: lw     rd′,  offset[6:2](rs1′)
        case RISCV_C_LD:          // Expands to: ld     rd′,  offset[7:3](rs1′)
        case RISCV_C_FSD:         // Expands to: fsd   rs2′,  offset[7:3](rs1′)
        case RISCV_C_SW:          // Expands to: sw    rs2′,  offset[6:2](rs1′)
        case RISCV_C_SD:          // Expands to: sd    rs2′,  offset[7:3](rs1′)
        case RISCV_C_NOP:         // Expands to: addi    x0,  x0, #0
        case RISCV_C_ADDI:        // Expands to: addi    rd,  rd, nzimm[5:0]
        case RISCV_C_ADDIW:       // Expands to: addiw   rd,  rd, imm[5:0]
        case RISCV_C_LI:          // Expands to: addi    rd,  x0, imm[5:0]
        case RISCV_C_ADDI16SP:    // Expands to: addi    x2,  x2, nzimm[9:4]
        case RISCV_C_LUI:         // Expands to: lui     rd,  nzimm[17:12].
        case RISCV_C_SRLI:        // Expands to: srli   rd′,  rd′, shamt[5:0],
        case RISCV_C_SRAI:        // Expands to: srai   rd′,  rd′, shamt[5:0]
        case RISCV_C_ANDI:        // Expands to: andi   rd′,  rd,  imm[5:0].
        case RISCV_C_SUB:         // Expands to: sub    rd′,  rd′, rs2′
        case RISCV_C_XOR:         // Expands to: xor    rd′,  rd′, rs2′
        case RISCV_C_OR:          // Expands to: or     rd′,  rd′, rs2′
        case RISCV_C_AND:         // Expands to: and    rd′,  rd′, rs2′
        case RISCV_C_SUBW:        // Expands to: subw   rd′,  rd′, rs2′
        case RISCV_C_ADDW:        // Expands to: addw   rd′,  rd′, rs2′
        case RISCV_C_SLLI:        // Expands to: slli    rd,  rd, shamt[5:0]
        case RISCV_C_FLDSP:       // Expands to: fld     rd,  offset[8:3](x2)
        case RISCV_C_LWSP:        // Expands to: lw      rd,  offset[7:2](x2)
        case RISCV_C_LDSP:        // Expands to: ld      rd,  offset[8:3](x2).
        case RISCV_C_ADD:         // Expands to: add     rd,  rd, rs2.
        case RISCV_C_FSDSP:       // Expands to: fsd    rs2,  offset[8:3](x2).
        case RISCV_C_SWSP:        // Expands to: sw     rs2,  offset[7:2](x2)
        case RISCV_C_SDSP:        // Expands to: sd     rs2,  offset[8:3](x2).
        case RISCV_C_MV:          // Expands to: add     rd,  x0, rs2.
        case RISCV_C_EBREAK:      // Expands to: ebreak
          copy_riscv_compressed();
          break;
#endif
        case RISCV_AUIPC: {  // Add Upper Immediate to PC
          uint32_t rd, imm;
          riscv_auipc_decode_fields(read_address, &rd, &imm);
          intptr_t offset = sign_extend(32, imm << 12);
          riscv_copy_to_reg(&write_p, rd, (intptr_t)read_address + offset);
          break;
        }
        case RISCV_JAL: {    // Jump and Link
          uint32_t rd, imm;
          riscv_jal_decode_fields(read_address, &rd, &imm);
          const intptr_t offset = riscv_decode_j_imm(imm);
          const uintptr_t target = (uintptr_t)read_address + offset;
          riscv_check_free_space(thread_data, &write_p, &data_p, BRANCH_FSPACE, basic_block);
          riscv_jump(thread_data, read_address, inst, basic_block, &write_p, rd, target);

          stop = true;
          break;
        }
        case RISCV_JALR: {   // Jump and Link Register
          uint32_t rd, rs1, imm;
          riscv_jalr_decode_fields(read_address, &rd, &rs1, &imm);
          riscv_check_free_space(thread_data, &write_p, &data_p, REG_JUMP_FSPACE, basic_block);
          riscv_jump_register(thread_data, read_address, inst, basic_block,
                              &write_p, rd, rs1, imm);

          stop = true;
          break;
        }
        // All branch instructions use the B-type instruction format.
        case RISCV_BEQ:
        case RISCV_BNE:
        case RISCV_BLT:
        case RISCV_BGE:
        case RISCV_BLTU:
        case RISCV_BGEU: {
          uint32_t cond, rs1, rs2, immhi, immlo;
          riscv_branch_decode_fields(read_address, &cond, &rs1, &rs2, &immhi, &immlo);
          intptr_t offset = riscv_decode_b_imm(immhi, immlo);
          uintptr_t target = (uintptr_t)read_address + offset;

          riscv_check_free_space(thread_data, &write_p, &data_p, BRANCH_FSPACE, basic_block);
          riscv_cond_branch(thread_data, read_address, inst, basic_block, &write_p,
                            cond, rs1, rs2, target);
          stop = true;
          break;
        }
        // End of branches

        // Other translated instructions
        case RISCV_ECALL: {// Environment Call (System call)
          //copy_riscv();
          riscv_push_offset(&write_p, (1 << s0) | (1 << s1) | (1 << ra), 2);
          riscv_copy_to_reg(&write_p, s0, (uintptr_t)read_address + 4);
          int ret = riscv_jalr_helper(&write_p, thread_data->syscall_wrapper_addr, ra, s1);
          assert(ret == 0);
          riscv_restore_context(&write_p);
          break;
        }

        // Instructions which we may have to translate, but which we copy at the moment
        case RISCV_FENCE: // TODO CHECK: should the fence be copied or needs to be modified
          // CHECK this for FENCE and FENCEI
          // https://github.com/llvm/llvm-project/blob/master/llvm/lib/Target/RISCV/Utils/RISCVBaseInfo.h#L91
          copy_riscv();
          break;
        case RISCV_FENCEI: // CHECK: (riscv)
          copy_riscv();
          break;
        case RISCV_CSRRW:   // CSR Read and Write
        case RISCV_CSRRS:   // CSR Read and Set Bits
        case RISCV_CSRRC:   // CSR Read and Clear Bits
        case RISCV_CSRRWI:  // CSR Read and Write immediate
        case RISCV_CSRRSI:  // CSR Read and Set Bits immediate
        case RISCV_CSRRCI:  // CSR Read and Clear Bits immediate
          debug("csr %p\n", read_address);
          copy_riscv();
          break;

        // Instructions which are safe to copy unmodified
        case RISCV_LUI:     // Load Upper Immediate
        case RISCV_LB:
        case RISCV_LH:
        case RISCV_LW:
        case RISCV_LBU:
        case RISCV_LHU:
        case RISCV_SB:
        case RISCV_SH:
        case RISCV_SW:
        case RISCV_ADDI:    // MOV -> ADDI rd, rs1, 0
        case RISCV_SLTI:    // set less than immediate
        case RISCV_SLTIU:   // set less than immediate unsigned (but immediate is sign extended)
        case RISCV_XORI:
        case RISCV_ORI:
        case RISCV_ANDI:
        case RISCV_SLLI:
        case RISCV_SRLI:
        case RISCV_SRAI:
        case RISCV_ADD:
        case RISCV_SUB:
        case RISCV_SLL:
        case RISCV_SLT:   // set less than register
        case RISCV_SLTU:  // set less than unsigned register (but value is sign extended)
        case RISCV_XOR:
        case RISCV_SRL:
        case RISCV_SRA:
        case RISCV_OR:
        case RISCV_AND:
        case RISCV_EBREAK:
        case RISCV_LWU:
        case RISCV_LD:
        case RISCV_SD:
        case RISCV_ADDIW:
        case RISCV_SLLIW:
        case RISCV_SRLIW:
        case RISCV_SRAIW:
        case RISCV_ADDW:
        case RISCV_SUBW:
        case RISCV_SLLW:
        case RISCV_SRLW:
        case RISCV_SRAW:
          copy_riscv();
          break;
        // RV32/RV64 Zifencei Standard Extension

        // RV32/RV64 "Zicsr", Control and Status Register (CSR) Instructions
        // All use the I-type instruction format

#ifdef __riscv_muldiv // ("M" Standard Extension for Integer Multiplication and Division)
        // RV32M
        case RISCV_MUL:
        case RISCV_MULH:
        case RISCV_MULHSU:
        case RISCV_MULHU:
        case RISCV_DIV:
        case RISCV_DIVU:
        case RISCV_REM:
        case RISCV_REMU:
  #if __riscv_xlen == 64 // RV64M
        case RISCV_MULW:
        case RISCV_DIVW:
        case RISCV_DIVUW:
        case RISCV_REMW:
        case RISCV_REMUW:
  #endif
#endif
#ifdef __riscv_atomic // (“A” Standard Extension for Atomic Instructions)
        // RV32A
        case RISCV_LR_W: // LR.W -> load-reserved word
        case RISCV_SC_W: // SC.W -> store-conditional word
        case RISCV_AMOSWAP_W:
        case RISCV_AMOADD_W:
        case RISCV_AMOXOR_W:
        case RISCV_AMOAND_W:
        case RISCV_AMOOR_W:
        case RISCV_AMOMIN_W:
        case RISCV_AMOMAX_W:
        case RISCV_AMOMINU_W:
        case RISCV_AMOMAXU_W:
  #if __riscv_xlen == 64 // RV64A
        case RISCV_LR_D: // LR.D -> load-reserved double word
        case RISCV_SC_D: // SC.D -> store-conditional double word
        case RISCV_AMOSWAP_D:
        case RISCV_AMOADD_D:
        case RISCV_AMOXOR_D:
        case RISCV_AMOAND_D:
        case RISCV_AMOOR_D:
        case RISCV_AMOMIN_D:
        case RISCV_AMOMAX_D:
        case RISCV_AMOMINU_D:
        case RISCV_AMOMAXU_D:
  #endif
#endif
#ifdef __riscv_fdiv // (“F” Standard Extension for Single-Precision Floating-Point)
        // RV32F
        case RISCV_FLW:
        case RISCV_FSW:
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
  #if __riscv_xlen == 64 // RV64F
        case RISCV_FCVT_L_S:
        case RISCV_FCVT_LU_S:
        case RISCV_FCVT_S_L:
        case RISCV_FCVT_S_LU:
  #endif
#endif
#if __riscv_flen == 64 // (“D” Standard Extension for Double-Precision Floating-Point)
        // RV32D
        case RISCV_FLD:
        case RISCV_FSD:
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
        // RV64D
        case RISCV_FCVT_L_D:
        case RISCV_FCVT_LU_D:
        case RISCV_FMV_X_D:
        case RISCV_FCVT_D_L:
        case RISCV_FCVT_D_LU:
        case RISCV_FMV_D_X:
	// RV64B Zba
	case RISCV_ADD_UW:
	case RISCV_SH1ADD:
	case RISCV_SH1ADD_UW:
	case RISCV_SH2ADD:
	case RISCV_SH2ADD_UW:
	case RISCV_SH3ADD:
	case RISCV_SH3ADD_UW:
	case RISCV_SLLI_UW:
	// RV64B Zbb
	case RISCV_ANDN:
	case RISCV_ORRN:
	case RISCV_XNOR:
	case RISCV_CLZ:
	case RISCV_CLZ_W:
	case RISCV_CTZ:
	case RISCV_CTZ_W:
	case RISCV_CPOP:
	case RISCV_CPOP_W:
	case RISCV_MAX:
	case RISCV_MAX_U:
	case RISCV_MIN:
	case RISCV_MIN_U:
	case RISCV_SEXT_B:
	case RISCV_SEXT_H:
	case RISCV_ZEXT_H:
	case RISCV_ROL:
	case RISCV_ROL_W:
	case RISCV_ROR:
	case RISCV_RORI:
	case RISCV_RORI_W:
	case RISCV_ROR_W:
	case RISCV_ORC_B:
	case RISCV_REV8:
	// RV64B Zbc
	case RISCV_CLMUL:
	case RISCV_CLMUL_H:
	case RISCV_CLMULR:
	// RV64B Zbs
	case RISCV_BCLR:
	case RISCV_BCLRI:
	case RISCV_BEXT:
	case RISCV_BEXTI:
	case RISCV_BINV:
	case RISCV_BINVI:
	case RISCV_BSET:
	case RISCV_BSETI:
	// RV64B Zbkb
	case RISCV_PACK:
	case RISCV_PACK_H:
	case RISCV_PACK_W:
	case RISCV_REV_B:
	// RV64B Zbkx
	case RISCV_XPERM_B:
	case RISCV_XPERM_N:
          copy_riscv();
          break;
#endif
        case RISCV_INVALID:
          if (read_address != start_scan) {
            riscv_jump(thread_data, read_address, inst, basic_block, &write_p, zero, (uintptr_t)read_address);

            stop = true;
            debug("WARN: deferred scanning because of unknown instruction at: %p\n", read_address);
          } else {
            fprintf(stderr, "Unknown RISC-V instruction: %d at %p\n", inst, read_address);
            while(1);
            exit(EXIT_FAILURE);
          }
          break;
        default:
         fprintf(stderr, "Unhandled RISC-V instruction: %d at %p\n", inst, read_address);
         while(1);
         exit(EXIT_FAILURE);
         break;
        }
#ifdef PLUGINS_NEW
    } // if(!skip_inst)
#endif

    if ((void *)data_p <= (void *)write_p) {
      fprintf(stderr, "%d, inst: %p, :write: %p\n", inst, data_p, write_p);
      while(1);
    }

    if (!stop) {
      riscv_check_free_space(thread_data, &write_p, &data_p, MIN_FSPACE, basic_block);
    }
    if (bb_type != atomic_memory_riscv) {
      riscv_scanner_deliver_callbacks(thread_data, POST_INST_C, &read_address, inst, &write_p, &data_p, basic_block, type, !stop, &stop);
    }

    next_instruction(inst, &read_address);
  } // while (!stop)

  riscv_scanner_deliver_callbacks(thread_data, POST_BB_C, &bb_entry, -1,
                                &write_p, &data_p, basic_block, type, false, &stop);
  riscv_scanner_deliver_callbacks(thread_data, POST_FRAGMENT_C, &start_scan, -1,
                                &write_p, &data_p, basic_block, type, false, &stop);

  return write_p - start_address;
}
#endif // __riscv
