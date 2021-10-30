/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2015-2020 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
  Copyright 2017-2021 The University of Manchester

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

#include <stdint.h>

#define IMM_LDR 0
#define LDR_REG 1
#define IMM_PROC 1
#define REG_PROC 0

#ifdef __arm__
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

enum reg_alt {
  es = r4, // the first calleE-Saved register - not a standard alias
  sp = r13,
  lr = r14,
  pc = r15
};

#define m_r0 (1 << r0)
#define m_r1 (1 << r1)
#define m_r2 (1 << r2)
#define m_r3 (1 << r3)
#define m_r4 (1 << r4)
#define m_r5 (1 << r5)
#define m_r6 (1 << r6)
#define m_r7 (1 << r7)
#define m_r8 (1 << r8)
#define m_r9 (1 << r9)
#define m_r10 (1 << r10)
#define m_r11 (1 << r11)
#define m_r12 (1 << r12)
#define m_r13 (1 << r13)
#define m_r14 (1 << r14)
#define m_r15 (1 << r15)
#endif // __arm__

#if defined(__aarch64__) || defined(__riscv)
                    // +--------------+--------------+
                    // |   AArch64    |    RISC-V    |
enum reg {          // +--------------+--------------+
  x0   =   0,       // | X0           |  x0  (zero)  |
  x1   =   1,       // | X1           |  x1  (ra)    |
  x2   =   2,       // | X2           |  x2  (sp)    |
  x3   =   3,       // | X3           |  x3  (gp)    |
  x4   =   4,       // | X4           |  x4  (tp)    |
  x5   =   5,       // | X5           |  x5  (t0)    |
  x6   =   6,       // | X6           |  x6  (t1)    |
  x7   =   7,       // | X7           |  x7  (t2)    |
  x8   =   8,       // | X8 (XR)      |  x8  (s0/fp) |
  x9   =   9,       // | X9           |  x9  (s1)    |
  x10  =  10,       // | X10          |  x10 (a0)    |
  x11  =  11,       // | X11          |  x11 (a1)    |
  x12  =  12,       // | X12          |  x12 (a2)    |
  x13  =  13,       // | X13          |  x13 (a3)    |
  x14  =  14,       // | X14          |  x14 (a4)    |
  x15  =  15,       // | X15          |  x15 (a5)    |
  x16  =  16,       // | X16 (IP0)    |  x16 (a6)    |
  x17  =  17,       // | X17 (IP1)    |  x17 (a7)    |
  x18  =  18,       // | X18 (PR)     |  x18 (s2)    |
  x19  =  19,       // | X19          |  x19 (s3)    |
  x20  =  20,       // | X20          |  x20 (s4)    |
  x21  =  21,       // | X21          |  x21 (s5)    |
  x22  =  22,       // | X22          |  x22 (s6)    |
  x23  =  23,       // | X23          |  x23 (s7)    |
  x24  =  24,       // | X24          |  x24 (s8)    |
  x25  =  25,       // | X25          |  x25 (s9)    |
  x26  =  26,       // | X26          |  x26 (s10)   |
  x27  =  27,       // | X27          |  x27 (s11)   |
  x28  =  28,       // | X28          |  x28 (t3)    |
  x29  =  29,       // | X29 (FP)     |  x29 (t4)    |
  x30  =  30,       // | X30 (LR)     |  x30 (t5)    |
  x31  =  31,       // | X31 (SP/XZR) |  x31 (t6)    |
  reg_invalid = 32  // +--------------+--------------+
};
#endif

#ifdef __aarch64__
enum reg_alt {
  xr   =  x8,   // Designated Indirect Result Location Parameter
  ip0  =  x16,  // Intra-Procedure Call temporary registers
  ip1  =  x17,  // Intra-Procedure Call temporary registers
  pr   =  x18,  // Platform Register
  es   =  x19,  // the first calleE-Saved register - not a standard alias
  fp   =  x29,  // Frame Pointer
  lr   =  x30,  // Link register
  sp   =  x31,  // Stack Pointer
  xzr  =  x31,  // Zero Register
};
#endif

#if defined(__aarch64__) || defined(__riscv)
#define m_x0 (1 << x0)
#define m_x1 (1 << x1)
#define m_x2 (1 << x2)
#define m_x3 (1 << x3)
#define m_x4 (1 << x4)
#define m_x5 (1 << x5)
#define m_x6 (1 << x6)
#define m_x7 (1 << x7)
#define m_x8 (1 << x8)
#define m_x9 (1 << x9)
#define m_x10 (1 << x10)
#define m_x11 (1 << x11)
#define m_x12 (1 << x12)
#define m_x13 (1 << x13)
#define m_x14 (1 << x14)
#define m_x15 (1 << x15)
#define m_x16 (1 << x16)
#define m_x17 (1 << x17)
#define m_x18 (1 << x18)
#define m_x19 (1 << x19)
#define m_x20 (1 << x20)
#define m_x21 (1 << x21)
#define m_x22 (1 << x22)
#define m_x23 (1 << x23)
#define m_x24 (1 << x24)
#define m_x25 (1 << x25)
#define m_x26 (1 << x26)
#define m_x27 (1 << x27)
#define m_x28 (1 << x28)
#define m_x29 (1 << x29)
#define m_x30 (1 << x30)
#define m_x31 (1 << x31)
#endif

#ifdef __aarch64__
#define m_xr  (1 << xr)
#define m_ip0 (1 << ip0)
#define m_ip1 (1 << ip1)
#define m_pr  (1 << pr)
#define m_xzr (1 << xzr)
#endif

#ifdef __riscv
enum gp_reg_abi_name {
  zero =   x0,   // Hard-wired Zero
  ra   =   x1,   // Return Address (link register)
  sp   =   x2,   // Stack Pointer
  gp   =   x3,   // Global Pointer
  tp   =   x4,   // Thread Pointer

  t0   =   x5,   // Temporary 0/Alternate Link Register
  t1   =   x6,   // Temporary 1
  t2   =   x7,   // Temporary 2
  t3   =  x28,   // Temporary 3
  t4   =  x29,   // Temporary 4
  t5   =  x30,   // Temporary 5
  t6   =  x31,   // Temporary 6

  a0   =  x10,   // Function Argument/Return Value 0
  a1   =  x11,   // Function Argument/Return Value 1
  a2   =  x12,   // Function Argument 2
  a3   =  x13,   // Function Argument 3
  a4   =  x14,   // Function Argument 4
  a5   =  x15,   // Function Argument 5
  a6   =  x16,   // Function Argument 6
  a7   =  x17,   // Function Argument 7

  s0   =   x8,   // Saved Register  0
  s1   =   x9,   // Saved Register  1
  s2   =  x18,   // Saved Register  2
  s3   =  x19,   // Saved Register  3
  s4   =  x20,   // Saved Register  4
  s5   =  x21,   // Saved Register  5
  s6   =  x22,   // Saved Register  6
  s7   =  x23,   // Saved Register  7
  s8   =  x24,   // Saved Register  8
  s9   =  x25,   // Saved Register  9
  s10  =  x26,   // Saved Register 10
  s11  =  x27,   // Saved Register 11
};

enum gp_reg_abi_name_alt {
  fp   =   x8    // Frame Pointer
};

#ifdef __riscv_fdiv
enum fp_reg {
  f0   =   0,    //  f0 (ft0)
  f1   =   1,    //  f1 (ft1)
  f2   =   2,    //  f2 (ft2)
  f3   =   3,    //  f3 (ft3)
  f4   =   4,    //  f4 (ft4)
  f5   =   5,    //  f5 (ft5)
  f6   =   6,    //  f6 (ft6)
  f7   =   7,    //  f7 (ft7)
  f8   =   8,    //  f8 (fs0)
  f9   =   9,    //  f9 (fs1)
  f10  =  10,    // f10 (fa0)
  f11  =  11,    // f11 (fa1)
  f12  =  12,    // f12 (fa2)
  f13  =  13,    // f13 (fa3)
  f14  =  14,    // f14 (fa4)
  f15  =  15,    // f15 (fa5)
  f16  =  16,    // f16 (fa6)
  f17  =  17,    // f17 (fa7)
  f18  =  18,    // f18 (fs2)
  f19  =  19,    // f19 (fs3)
  f20  =  20,    // f20 (fs4)
  f21  =  21,    // f21 (fs5)
  f22  =  22,    // f22 (fs6)
  f23  =  23,    // f23 (fs7)
  f24  =  24,    // f24 (fs8)
  f25  =  25,    // f25 (fs9)
  f26  =  26,    // f26 (fs10)
  f27  =  27,    // f27 (fs11)
  f28  =  28,    // f28 (ft8)
  f29  =  29,    // f29 (ft9)
  f30  =  30,    // f30 (ft10)
  f31  =  31     // f31 (f11)
};

enum fp_reg_abi_name {
  ft0  =   f0,   // FP Temporary  0
  ft1  =   f1,   // FP Temporary  1
  ft2  =   f2,   // FP Temporary  2
  ft3  =   f3,   // FP Temporary  3
  ft4  =   f4,   // FP Temporary  4
  ft5  =   f5,   // FP Temporary  5
  ft6  =   f6,   // FP Temporary  6
  ft7  =   f7,   // FP Temporary  7
  ft8  =  f28,   // FP Temporary  8
  ft9  =  f29,   // FP Temporary  9
  ft10 =  f30,   // FP Temporary 10
  ft11 =  f31,   // FP Temporary 11

  fa0  =  f10,   // FP Function Argument/Return Value 0
  fa1  =  f11,   // FP Function Argument/Return Value 1
  fa2  =  f12,   // FP Function Argument 2
  fa3  =  f13,   // FP Function Argument 3
  fa4  =  f14,   // FP Function Argument 4
  fa5  =  f15,   // FP Function Argument 5
  fa6  =  f16,   // FP Function Argument 6
  fa7  =  f17,   // FP Function Argument 7

  fs0  =   f8,   // FP Saved Register  0
  fs1  =   f9,   // FP Saved Register  1
  fs2  =  f18,   // FP Saved Register  2
  fs3  =  f19,   // FP Saved Register  3
  fs4  =  f20,   // FP Saved Register  4
  fs5  =  f21,   // FP Saved Register  5
  fs6  =  f22,   // FP Saved Register  6
  fs7  =  f23,   // FP Saved Register  7
  fs8  =  f24,   // FP Saved Register  8
  fs9  =  f25,   // FP Saved Register  9
  fs10 =  f26,   // FP Saved Register 10
  fs11 =  f27,   // FP Saved Register 11
};
#endif

enum csr_addresses {
  // User Trap Setup
  csr_ustatus       = 0x000,  // (RW)   User status register.
  csr_uie           = 0x004,  // (RW)   User interrupt-enable register.
  csr_utvec         = 0x005,  // (RW)   User trap handler base address.

  // User Trap Handling
  csr_uscratch      = 0x040,  // (RW)   Scratch register for user trap handlers.
  csr_uepc          = 0x041,  // (RW)   User exception program counter.
  csr_ucause        = 0x042,  // (RW)   User trap cause.
  csr_utval         = 0x043,  // (RW)   User bad address or instruction.
  csr_uip           = 0x044,  // (RW)   User interrupt pending.

  // User Floating-Point CSRs
  csr_fflags        = 0x001,  // (RW)   Floating-Point Accrued Exceptions.
  csr_frm           = 0x002,  // (RW)   Floating-Point Dynamic Rounding Mode.
  csr_fcsr          = 0x003,  // (RW)   Floating-Point Control and Status Register (frm + fflags).

  // User Counter/Timers
  csr_cycle         = 0xC00,  // (RO)   Cycle counter for RDCYCLE instruction.
  csr_time          = 0xC01,  // (RO)   Timer for RDTIME instruction.
  csr_instret       = 0xC02,  // (RO)   Instructions-retired counter for RDINSTRET instruction.
  csr_hpmcounter3   = 0xC03,  // (RO)   Performance-monitoring counter.
  csr_hpmcounter4   = 0xC04,  // (RO)   Performance-monitoring counter.
  // ...
  csr_hpmcounter31  = 0xC1F,  // (RO)   Performance-monitoring counter.
  csr_cycleh        = 0xC80,  // (RO)   Upper 32 bits of cycle, RV32I only.
  csr_timeh         = 0xC81,  // (RO)   Upper 32 bits of time, RV32I only.
  csr_instreth      = 0xC82,  // (RO)   Upper 32 bits of instret, RV32I only.
  csr_hpmcounter3h  = 0xC83,  // (RO)   Upper 32 bits of hpmcounter3, RV32I only.
  csr_hpmcounter4h  = 0xC84,  // (RO)   Upper 32 bits of hpmcounter4, RV32I only.
  // ...
  csr_hpmcounter31h = 0xC9F   // (RO) Upper 32 bits of hpmcounter31, RV32I only.
};

enum branch_condition {
  BEQ  = 0, // Branch equal
  BNE  = 1, // Branch NOT equal
  BLT  = 4, // Branch lower than
  BGE  = 5, // Branch greater or equal
  BLTU = 6, // Branch lower than unsigned
  BGEU = 7  // Branch greater or equal unsinged
};
#endif

enum reg_portable { // TODO:(riscv) see how these would map to riscv
  reg0 = 0,
  reg1 = 1,
  reg2 = 2,
  reg3 = 3,
  reg4 = 4,
  reg5 = 5,
  reg6 = 6,
  reg7 = 7,
  reg8 = 8,
  reg9 = 9,
  reg10 = 10,
  reg11 = 11,
  reg12 = 12
};

#if defined(__arm__) || defined(__aarch64__)
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
#endif

#define invert_cond(cond) ((cond) ^ 1)

#if defined(__riscv)
typedef enum riscv_cond_codes {
  AL = 0,
} mambo_cond;
#endif

#ifdef __arm__
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
  if ((regs) & (1 << sp)) { \
    arm_ldm(&write_p, sp, regs, 0, 1, 0, 0); \
  } else { \
    arm_ldm(&write_p, sp, regs, 0, 1, 1, 0); \
  } \
  write_p++;
#endif

#ifdef __aarch64__
/*
 * PUSH PAIR
 * STP Xt1, Xt2, [SP]!
 */
#define a64_push_pair_reg(Xt1, Xt2) \
  a64_LDP_STP(&write_p, 2, 0, 3, 0, -2, Xt2, sp, Xt1); \
  write_p++;

/*
 * POP PAIR
 * LDP Xt1, Xt2, [SP], #16
 */
#define a64_pop_pair_reg(Xt1, Xt2) \
  a64_LDP_STP(&write_p, 2, 0, 1, 1, 2, Xt2, sp, Xt1); \
  write_p++;

/*
 * PUSH REGISTER
 * STR reg, [SP, #-16]!
 */
#define a64_push_reg(reg) \
  a64_LDR_STR_immed(&write_p, 3, 0, 0, -16, 3, sp, reg); \
  write_p++;

/*
 * POP REGISTER
 * LDR reg, [SP], #16
 */
#define a64_pop_reg(reg) \
  a64_LDR_STR_immed(&write_p, 3, 0, 1, 16, 1, sp, reg); \
  write_p++;

void a64_copy_to_reg_64bits(uint32_t **write_p, enum reg reg, uint64_t value);
#endif

#ifdef __arm__
void thumb_push_regs(uint16_t **write_p, uint32_t regs);
void thumb_pop_regs(uint16_t **write_p, uint32_t regs);
void arm_copy_to_reg_16bit(uint32_t **write_p, enum reg reg, uint32_t value);
void arm_cond_copy_to_reg_16bit(uint32_t **write_p, enum arm_cond_codes cond, enum reg reg, uint32_t value);
void arm_copy_to_reg_32bit(uint32_t **write_p, enum reg reg, uint32_t value);
void arm_cond_copy_to_reg_32bit(uint32_t **write_p, enum arm_cond_codes cond, enum reg reg, uint32_t value);
void arm_add_sub_32_bit(uint32_t **write_p, enum reg rd, enum reg rn, int value);
void copy_to_reg_16bit(uint16_t **write_p, enum reg reg, uint32_t value);
void copy_to_reg_32bit(uint16_t **write_p, enum reg reg, uint32_t value);
#endif
#ifdef __riscv
void riscv_push(uint16_t **o_write_p, uint32_t regs);
void riscv_pop(uint16_t **o_write_p, uint32_t regs);
void riscv_copy_to_reg(uint16_t **write_p, const enum reg reg, uintptr_t const value);
#endif

void init_plugin();

void mambo_memcpy(void *dst, void *src, size_t l);

static inline uint64_t sign_extend64(unsigned int bits, uint64_t value)
{
    uint64_t C = (-1) << (bits - (uint64_t) 1);
    return (value + C) ^ C;
}

static inline int32_t sign_extend32(unsigned int bits, uint32_t value)
{
  uint32_t C = (-1) << (bits - 1);
  return (int32_t)((value + C) ^ C);
}

static inline intptr_t sign_extend(unsigned int bits, intptr_t value)
{
    intptr_t C = (-1) << (bits - (intptr_t)1);
    return (value + C) ^ C;
}

static inline uintptr_t extr(int const bits, int const pos, uintptr_t const from) {
    uintptr_t const mask = (((uintptr_t)1 << bits) - 1);
    return (from >> pos) & mask;
}
#endif

