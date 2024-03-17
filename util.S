/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
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

#include <asm/unistd.h>

# These helpers are executed from .text and are not copied to the code cache

#ifdef __arm__
.syntax unified
#endif

.global dbm_client_entry
.func dbm_client_entry
.type dbm_client_entry, %function

#ifdef __arm__
.code 32
dbm_client_entry:
  MOV SP, R1
  MOV LR, R0
  MOV R0, #0
  MOV R1, #0
  MOV R2, #0
  MOV R3, #0
  BLX LR
  BX LR
#endif // __arm__

#ifdef __aarch64__
dbm_client_entry:
  MOV SP, X1
  STP XZR, XZR, [SP, #-16]!
  BR X0
#endif

#ifdef __riscv
dbm_client_entry:
  /*
   * Called from elf_loader.c (elf_run function)
   * dbm_client_entry(entry_address,  a0
   *                 &stack->e[0]);   a1
   */
  addi sp, a1, -16
  jr a0
#endif
.endfunc

# R0 - new SP
.global th_enter
.func   th_enter
.type   th_enter, %function

#ifdef __arm__
.thumb_func
th_enter:
  MOV SP, R0
  STR R1, [SP, #56]
  POP {R0-R12, R14}
  POP {PC}
#endif

#ifdef __aarch64__
th_enter:
  MOV SP, X0
  LDP  X4,  X5, [SP,  #16]
  LDP  X6,  X7, [SP,  #32]
  LDP  X8,  X9, [SP,  #48]
  LDP X10, X11, [SP,  #64]
  LDP X12, X13, [SP,  #80]
  LDP X14, X15, [SP,  #96]
  LDP X16, X17, [SP, #112]
  LDP X18, X19, [SP, #128]
  LDP X20, X21, [SP, #144]
  LDP X22, X23, [SP, #160]
  LDP X24, X25, [SP, #176]
  LDP X26, X27, [SP, #192]
  LDR X28,      [SP, #208]
  LDP X29, X30, [SP, #224]
  LDP  X2,  X3, [SP], #240
  BR X1
#endif

#ifdef __riscv
th_enter:
  mv sp, a0
  mv tp, a2 // contains the pointer to tls which is needed by tp
  ld a2,  0(sp)
  ld a3,  8(sp)
  ld a4,  16(sp)
  ld a5,  24(sp)
  ld a6,  32(sp)
  ld a7,  40(sp)
  ld t0,  48(sp)
  ld t1,  56(sp)
  ld t2,  64(sp)
  ld t3,  72(sp)
  ld t4,  80(sp)
  ld t5,  88(sp)
  ld t6,  96(sp)
  ld s2,  104(sp)
  ld s3,  112(sp)
  ld s4,  120(sp)
  ld gp,  136(sp)
  ld s5,  144(sp)
  ld s6,  152(sp)
  ld s7,  160(sp)
  ld s8,  168(sp)
  ld s9,  176(sp)
  ld s10, 184(sp)
  ld s11, 192(sp)
  ld ra,  200(sp)
  ld s0,  208(sp)
  ld s1,  216(sp)
  addi sp, sp, 224
  jr a1
#endif
.endfunc

.global new_thread_trampoline
.func
.type   new_thread_trampoline, %function
new_thread_trampoline:
#ifdef __arm__
  PUSH {R4-R12, LR}
  MOV R1, SP
#elif __aarch64__
  STP X19, X20, [SP, #-96]!
  STP X21, X22, [SP, #16]
  STP X23, X24, [SP, #32]
  STP X25, X26, [SP, #48]
  STP X27, X28, [SP, #64]
  STP X29, X30, [SP, #80]
  MOV X1, SP
#elif __riscv
  mv a1,  sp
#endif
#if defined(__arm__) || defined(__aarch64__)
  B dbm_start_thread_pth
#elif defined(__riscv)
  j dbm_start_thread_pth
#endif
.endfunc

.global return_with_sp
.func
.type   return_with_sp, %function
return_with_sp:
#ifdef __arm__
  MOV SP, R0
  POP {R4-R12, PC}
#elif __aarch64__
  MOV SP, X0
  LDP X21, X22, [SP, #16]
  LDP X23, X24, [SP, #32]
  LDP X25, X26, [SP, #48]
  LDP X27, X28, [SP, #64]
  LDP X29, X30, [SP, #80]
  LDP X19, X20, [SP], #96
  RET
#endif
.endfunc

.global raw_syscall
.func   raw_syscall
.type   raw_syscall, %function

raw_syscall:
#ifdef __arm__
  MOV R12, SP
  PUSH {R4 - R7}
  MOV R7, R0
  MOV R0, R1
  MOV R1, R2
  MOV R2, R3
  LDM R12, {R3 - R6}
  SVC 0
  POP {R4 - R7}
  BX LR
#endif
#ifdef __aarch64__
  MOV W8, W0
  MOV X0, X1
  MOV X1, X2
  MOV X2, X3
  MOV X3, X4
  MOV X4, X5
  MOV X5, X6
  MOV X6, X7
  SVC 0
  RET
#endif
#ifdef __riscv
  mv a7, a0
  mv a0, a1
  mv a1, a2
  mv a2, a3
  mv a3, a4
  mv a4, a5
  mv a5, a6
  mv a6, a7
  ecall
  ret
#endif
.endfunc

.global signal_trampoline
.func signal_trampoline
.type signal_trampoline, %function

signal_trampoline:
#ifdef __arm__
  SUB SP, SP, #4
  PUSH {r0-r3, r9, r12, lr}
  BL signal_dispatcher
  CBZ R0, sigret
  STR R0, [SP, #28]
  POP {r0-r3, r9, r12, lr}
  POP {PC}
sigret:
  ADD SP, SP, #32
  MOV R7, #__NR_rt_sigreturn
  SVC 0
#endif
#ifdef __aarch64__
  STP  X2,  X3, [SP, #-176]!
  STP  X4,  X5, [SP, #16]
  STP  X6,  X7, [SP, #32]
  STP  X8,  X9, [SP, #48]
  STP X10, X11, [SP, #64]
  STP X12, X13, [SP, #80]
  STP X14, X15, [SP, #96]
  STP X16, X17, [SP, #112]
  STP X18, X29, [SP, #128]
  STR X30,      [SP, #144]
  STP  X0,  X1, [SP, #160]

  BL signal_dispatcher

  LDP  X4,  X5, [SP, #16]
  LDP  X6,  X7, [SP, #32]
  LDP  X8,  X9, [SP, #48]
  LDP X10, X11, [SP, #64]
  LDP X12, X13, [SP, #80]
  LDP X14, X15, [SP, #96]
  LDP X16, X17, [SP, #112]
  LDP X18, X29, [SP, #128]
  LDR X30,      [SP, #144]
  LDP  X2,  X3, [SP], #160

  CBZ X0, sigret

  BR X0
sigret:
  ADD SP, SP, #16
  MOV X8, #__NR_rt_sigreturn
  SVC 0
#endif
.endfunc

.global atomic_increment_u64
.func atomic_increment_u64
.type atomic_increment_u64, %function

atomic_increment_u64:
#ifdef __arm__
  // R0 - ptr, R2 inc (low), R3, inc (high)
  PUSH {R4, R5}

retry:
  LDREXD R4, R5, [R0]
  ADDS R4, R2
  ADC R5, R3
  STREXD R1, R4, R5, [R0]
  CMP R1, #0
  BNE retry

  MOV R0, R4
  MOV R1, R5
  POP {R4, R5}
  BX LR

#elif __aarch64__
  LDXR X2, [X0]
  ADD X2, X2, X1
  STXR W3, X2, [X0]
  CBNZ W3, atomic_increment_u64
  MOV X0, X2
  RET
#elif __riscv
  #ifdef __riscv_atomic
    amoadd.d a2, a1, (a0)
    jr ra
  #endif
#endif
.endfunc

.global atomic_increment_u32
.func atomic_increment_u32
.type atomic_increment_u32, %function

atomic_increment_u32:
#ifdef __arm__
  LDREX R2, [R0]
  ADD R2, R1
  STREX R3, R2, [R0]
  CMP R3, #0
  BNE atomic_increment_u32
  MOV R0, R2
  BX LR

#elif __aarch64__
  LDXR W2, [X0]
  ADD W2, W2, W1
  STXR W3, W2, [X0]
  CBNZ W3, atomic_increment_u32
  MOV W0, W2
  RET

#endif
.endfunc

.global atomic_decrement_if_positive_i32
.func atomic_decrement_if_positive_i32
.type atomic_decrement_if_positive_i32, %function

atomic_decrement_if_positive_i32:
#ifdef __arm__
  LDREX R2, [R0]
  CMP R2, R1
  BLT abort
  SUB R2, R2, R1
  STREX R3, R2, [R0]
  CMP R3, #0
  BNE atomic_decrement_if_positive_i32
  MOV R0, R2
  BX LR
abort:
  CLREX
  MOV R0, #-1
  BX LR

#elif __aarch64__
  LDXR W2, [X0]
  CMP W2, W1
  BLT abort
  SUB W2, W2, W1
  STXR W3, W2, [X0]
  CBNZ W3, atomic_decrement_if_positive_i32
  MOV W0, W2
  RET
abort:
  CLREX
  MOV W0, #-1
  RET

#endif
.endfunc


.global safe_fcall_trampoline
.func safe_fcall_trampoline
.type safe_fcall_trampoline, %function

safe_fcall_trampoline:
#ifdef __arm__
  PUSH {R5-R7, R9, R12, LR}
  VPUSH {d16-d31}
  VPUSH {d0-d7}

  MOV R7, SP
  BIC R6, R7, #7
  MOV SP, R6

  MRS R5, CPSR
  VMRS R6, FPSCR

  BLX R4

  MOV SP, R7

  MSR CPSR, R5
  VMSR FPSCR, R6

  VPOP {d0-d7}
  VPOP {d16-d31}
  POP {R5-R7, R9, R12, PC}

#elif __aarch64__
  STP X8,  X9,  [SP, #-128]!
  STP X10, X11, [SP, #16]
  STP X12, X13, [SP, #32]
  STP X14, X15, [SP, #48]
  STP X16, X17, [SP, #64]
  STP X18, X19, [SP, #80]
  STP X20, X21, [SP, #96]
  STP X29, X30, [SP, #112]

  MRS X19, NZCV
  MRS X20, FPCR
  MRS X21, FPSR

  BL push_neon

  BLR X8

  BL pop_neon

  MSR NZCV, X19
  MSR FPCR, X20
  MSR FPSR, X21

  LDP X10, X11, [SP, #16]
  LDP X12, X13, [SP, #32]
  LDP X14, X15, [SP, #48]
  LDP X16, X17, [SP, #64]
  LDP X18, X19, [SP, #80]
  LDP X20, X21, [SP, #96]
  LDP X29, X30, [SP, #112]
  LDP X8,  X9,  [SP], #128

  RET

#elif __riscv

#if __riscv_xlen == 32
  addi sp, sp, -92
  sw x1, 0(sp)
  sw x2, 4(sp)
  sw x3, 8(sp)
  sw x4, 12(sp)
  sw x5, 16(sp)
  sw x6, 20(sp)
  sw x7, 24(sp)
  sw x8, 28(sp)
  sw x9, 32(sp)
  sw x18, 36(sp)
  sw x19, 40(sp)
  sw x20, 44(sp)
  sw x21, 48(sp)
  sw x22, 52(sp)
  sw x23, 56(sp)
  sw x24, 60(sp)
  sw x25, 64(sp)
  sw x25, 68(sp)
  sw x27, 72(sp)
  sw x28, 76(sp)
  sw x29, 80(sp)
  sw x30, 84(sp)
  sw x31, 88(sp)
#elif __riscv_xlen == 64
  addi sp, sp, -184
  sd x1, 0(sp)
  sd x2, 8(sp)
  sd x3, 16(sp)
  sd x4, 24(sp)
  sd x5, 32(sp)
  sd x6, 40(sp)
  sd x7, 48(sp)
  sd x8, 56(sp)
  sd x9, 64(sp)
  sd x18, 72(sp)
  sd x19, 80(sp)
  sd x20, 88(sp)
  sd x21, 96(sp)
  sd x22, 104(sp)
  sd x23, 112(sp)
  sd x24, 120(sp)
  sd x25, 128(sp)
  sd x25, 136(sp)
  sd x27, 144(sp)
  sd x28, 152(sp)
  sd x29, 160(sp)
  sd x30, 168(sp)
  sd x31, 176(sp)
#endif

#if __riscv_flen
  jal ra, push_fp
#endif

  frcsr s0
  frflags s1
  frrm s2

  jalr ra, a7

  fscsr s0
  fsflags s1
  fsrm s2

#if __riscv_flen
  jal ra, pop_fp
#endif

#if __riscv_xlen == 32
  lw x1, 0(sp)
  lw x2, 4(sp)
  lw x3, 8(sp)
  lw x4, 12(sp)
  lw x5, 16(sp)
  lw x6, 20(sp)
  lw x7, 24(sp)
  lw x8, 28(sp)
  lw x9, 32(sp)
  lw x18, 36(sp)
  lw x19, 40(sp)
  lw x20, 44(sp)
  lw x21, 48(sp)
  lw x22, 52(sp)
  lw x23, 56(sp)
  lw x24, 60(sp)
  lw x25, 64(sp)
  lw x25, 68(sp)
  lw x27, 72(sp)
  lw x28, 76(sp)
  lw x29, 80(sp)
  lw x30, 84(sp)
  lw x31, 88(sp)
  addi sp, sp, 92
#elif __riscv_xlen == 64
  ld x1, 0(sp)
  ld x2, 8(sp)
  ld x3, 16(sp)
  ld x4, 24(sp)
  ld x5, 32(sp)
  ld x6, 40(sp)
  ld x7, 48(sp)
  ld x8, 56(sp)
  ld x9, 64(sp)
  ld x18, 72(sp)
  ld x19, 80(sp)
  ld x20, 88(sp)
  ld x21, 96(sp)
  ld x22, 104(sp)
  ld x23, 112(sp)
  ld x24, 120(sp)
  ld x25, 128(sp)
  ld x25, 136(sp)
  ld x27, 144(sp)
  ld x28, 152(sp)
  ld x29, 160(sp)
  ld x30, 168(sp)
  ld x31, 176(sp)
  addi sp, sp, 184
#endif
  ret
#endif

.endfunc

.global __try_memcpy_error
.type __try_memcpy_error, %function
.global __try_memcpy
.type __try_memcpy, %function

__try_memcpy:
#ifdef __arm__
  LDRB R3, [R1], #1
  STRB R3, [R0], #1
  SUB R2, #1
  CBZ R2, __try_memcpy_ret
  B __try_memcpy
__try_memcpy_ret:
  MOV R0, #0
  BX LR

__try_memcpy_error:
  MOV R0, #-1
  BX LR
#elif __aarch64__
  LDRB W3, [X1], #1
  STRB W3, [X0], #1
  SUB X2, X2, #1
  CBNZ X2, __try_memcpy
  MOV X0, #0
  RET

__try_memcpy_error:
  MOV X0, #-1
  RET
#endif
