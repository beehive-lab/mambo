/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

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

#include "mtrace.h"

#ifdef __arm__
.syntax unified
#endif

.global mtrace_buf_write // (value, info, &buf_ptr.entries[0])
.func
.type mtrace_buf_write, %function

#ifdef __arm__
.thumb_func
mtrace_buf_write:
  PUSH {R3, R4}
  LDR R3, [R2, #-4]
  ADD R4, R2, R3, LSL #3
  STRD R0, R1, [R4]
  ADD R3, R3, #1
  STR R3, [R2, #-4]
  SUB R3, R3, #BUFLEN
  CBZ R3, call
  POP {R3, R4}
  BX LR

call:
  PUSH {R0-R2, R5-R6, R9, R12, LR}
  VPUSH {D16-D31}
  VPUSH {D0-D7}
  MRS R4, CPSR
  VMRS R5, FPSCR

  SUB R0, R2, #4

  MOV R6, SP
  BIC R2, R6, #7
  MOV SP, R2
  LDR R1, =mtrace_print_buf
  BLX R1
  MOV SP, R6

  MSR CPSR, R4
  VMSR FPSCR, R5
  VPOP {D0-D7}
  VPOP {D16-D31}
  POP {R0-R2, R5-R6, R9, R12, LR}
  POP {R3 - R4}
  BX LR
#endif

#ifdef __aarch64__
mtrace_buf_write:
  STP X3, X4, [SP, #-16]!
  LDR W3, [X2, #-8]
  ADD X4, X2, W3, UXTW #4
  STP X0, X1, [X4]

  ADD W3, W3, #1
  STR W3, [X2, #-8]
  SUB W3, W3, #BUFLEN
  CBZ W3, call
  LDP X3, X4, [SP], #16
  RET

call:
  STP X29, X30, [SP, #-16]!

  BL push_x4_x21
  MRS X19, NZCV
  MRS X20, FPCR
  MRS X21, FPSR
  BL push_neon

  SUB X0, X2, #8
  LDR X1, =mtrace_print_buf
  BLR X1

  BL pop_neon
  MSR NZCV, X19
  MSR FPCR, X20
  MSR FPSR, X21
  BL pop_x4_x21

  LDP X3, X4, [SP, #16]
  LDP X29, X30, [SP], #32
  RET
#endif

.endfunc
