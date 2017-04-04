/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2017 Cosmin Gorgovan <cosmin at linux-geek dot org>

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
  MOV R7, #173
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
  MOV X8, #139
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
