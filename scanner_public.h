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

#ifndef __SCANNER_PUBLIC_H__
#define __SCANNER_PUBLIC_H__

#define IMM_LDR 0
#define LDR_REG 1
#define IMM_PROC 1
#define REG_PROC 0

enum reg {
  r0 = 0,
  r1 = 1,
  r2 = 2,
  r3 = 3,
  r4 = 4,
  r5 = 5,
  r6 = 6,
  r7 = 7,
  r8 = 8, 
  r9 = 9,
  r10 = 10,
  r11 = 11,
  r12 = 12,
  r13 = 13,
  r14 = 14,
  r15 = 15,
  reg_invalid = 16
};

typedef enum arm_cond_codes {
  EQ = 0,
  NE = 1,
  CS = 2,
  CC = 3,
  MI = 4,
  PL = 5,
  VS = 6,
  VC = 7,
  HI = 8,
  LS = 9,
  GE = 10,
  LT = 11,
  GT = 12,
  LE = 13,
  AL = 14,
  ALT = 15
} mambo_cond;

enum shift_type {
  LSL = 0,
  LSR = 1,
  ASR = 2,
  ROR = 3
};

extern enum arm_cond_codes arm_inverse_cond_code[];

enum reg_alt {
  sp = r13,
  lr = r14,
  pc = r15
};

#define arm_cond_push_reg(cond, reg) \
  arm_str_cond(&write_p, cond, IMM_LDR, reg, sp, 4, 1, 0, 1); \
  write_p++;

#define arm_cond_pop_reg(cond, reg) \
  arm_ldr_cond(&write_p, cond, IMM_LDR, reg, sp, 4, 0, 1, 0); \
  write_p++;

#define arm_push_reg(reg) \
  arm_str(&write_p, IMM_LDR, reg, sp, 4, 1, 0, 1); \
  write_p++;

#define arm_pop_reg(reg) \
  arm_ldr(&write_p, IMM_LDR, reg, sp, 4, 0, 1, 0); \
  write_p++;

#define arm_push_regs(regs) \
  arm_stm(&write_p, sp, regs, 1, 0, 1, 0); \
  write_p++;

#define arm_pop_regs(regs) \
  if (regs & (1 << sp)) { \
    arm_ldm(&write_p, sp, regs, 0, 1, 0, 0); \
  } else { \
    arm_ldm(&write_p, sp, regs, 0, 1, 1, 0); \
  } \
  write_p++;

void copy_to_reg_16bit(uint16_t **write_p, enum reg reg, uint32_t value);
void copy_to_reg_32bit(uint16_t **write_p, enum reg reg, uint32_t value);
void thumb_push_regs(uint16_t **write_p, uint32_t regs);
void thumb_pop_regs(uint16_t **write_p, uint32_t regs);
void arm_copy_to_reg_16bit(uint32_t **write_p, enum reg reg, uint32_t value);
void arm_cond_copy_to_reg_16bit(uint32_t **write_p, enum arm_cond_codes cond, enum reg reg, uint32_t value);
void arm_copy_to_reg_32bit(uint32_t **write_p, enum reg reg, uint32_t value);
void arm_cond_copy_to_reg_32bit(uint32_t **write_p, enum arm_cond_codes cond, enum reg reg, uint32_t value);
void arm_add_sub_32_bit(uint32_t **write_p, enum reg rd, enum reg rn, int value);

void init_plugin();

void mambo_memcpy(void *dst, void *src, ssize_t l);
#endif

