/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2017 Cosmin Gorgovan <cosmin at linux-geek dot org>

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

.global mtrace_buf_write // (value, &buf_ptr.entries[0])
.func
.type mtrace_buf_write, %function

#ifdef __arm__
.thumb_func
mtrace_buf_write:
  LDR R2, [R1, #-4]
  STR R0, [R1, R2, LSL #2]
  ADD R2, R2, #1
  STR R2, [R1, #-4]
  SUB R2, R2, #BUFLEN
  CBZ R2, call
  BX LR

call:
  PUSH {R0-R5, R9, R12, LR}
  VPUSH {D16-D31}
  VPUSH {D0-D7}
  MRS R4, CPSR
  VMRS R5, FPSCR
  SUB R0, R1, #4
  LDR R1, =mtrace_print_buf
  BLX R1
  MSR CPSR, R4
  VMSR FPSCR, R5
  VPOP {D0-D7}
  VPOP {D16-D31}
  POP {R0-R5, R9, R12, LR}
  BX LR
#endif

#ifdef __aarch64__
mtrace_buf_write:
  LDR W2, [X1, #-8]
  STR X0, [X1, W2, UXTW #3]
  ADD W2, W2, #1
  STR W2, [X1, #-8]
  SUB W2, W2, #BUFLEN
  CBZ X2, call
  RET

call:
  STP X29, X30, [SP, #-32]!
  STR X3, [SP, #16]
  BL push_x4_x21
  MRS X19, NZCV
  MRS X20, FPCR
  MRS X21, FPSR
  BL push_neon

  SUB X0, X1, #8
  LDR X1, =mtrace_print_buf
  BLR X1

  BL pop_neon
  MSR NZCV, X19
  MSR FPCR, X20
  MSR FPSR, X21
  BL pop_x4_x21
  LDR X3, [SP, #16]
  LDP X29, X30, [SP], #32
  RET
#endif

.endfunc
