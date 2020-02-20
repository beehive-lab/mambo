/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2017-2020 The University of Manchester

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

#include "memcheck.h"

#ifdef __arm__
.syntax unified
#endif

// 1 to 3 arguments need to be preserved
// (es-1) (X18/R3) is a pointer to <in_malloc>
.global memcheck_malloc_pre
.func
memcheck_malloc_pre:
#ifdef __aarch64__
  LDR X4, [X18]
  ADD X4, X4, #1
  STR X4, [X18]
  RET
#elif __arm__
  LDR R12, [R3]
  ADD R12, R12, #1
  STR R12, [R3]
  BX LR
#endif
.endfunc


// X0/R0 - address
// (es-1) (X18/R3) is a pointer to <in_malloc>
// (es) (X19/R4) - size
.global memcheck_malloc_post
.func
memcheck_malloc_post:
#ifdef __aarch64__
  LDR X2, [X18]
  SUB X2, X2, #1
  STR X2, [X18]

  CBZ X0, mmp_ret

  #ifdef COMPACT_SHADOW
  STP X0, X30, [SP, #-16]!
  MOV X1, X19
  BL memcheck_alloc_hook
  LDP X0, X30, [SP], #16
  #else
  MOV X1, #0x200000000
  STR X19, [X1, X0]
  STR X19, [X0]

  MOV W4, #1
  MOV X2, #0x100000000
  MOV X3, X19
  ADD X2, X0, X2

mmp_loop:
  CBZ X3, mmp_ret
  STRB W4, [X2], #1
  SUB X3, X3, #1
  B mmp_loop
#endif

mmp_ret:
  RET

#elif __arm__
  LDR R2, [R3]
  SUB R2, R2, #1
  STR R2, [R3]

  CMP R0, #0
  BEQ mmp_ret

  PUSH {R0, LR}
  MOV R1, R4
  BL memcheck_alloc_hook
  POP {R0, LR}

mmp_ret:
  BX LR
#endif
.endfunc


// X0/R0 - address
// (es-1) (X18/R3) is a pointer to <in_malloc>
.global memcheck_free_pre
.func
memcheck_free_pre:
#ifdef __aarch64__
  LDR X3, [X18]
  ADD X3, X3, #1
  STR X3, [X18]

  #ifdef COMPACT_SHADOW
  STR X0, [SP, #-32]!
  STP X1, X30, [SP, #16]
  BL memcheck_free_hook
  LDP X1, X30, [SP, #16]
  LDR X0, [SP], #32
  #else
  MOV X2, #0x200000000
  LDR X2, [X2, X0]

  MOV X3, #0x100000000
  ADD X3, X3, X0

mfp_l:
  CBZ X2, mfp_l_exit
  STRB WZR, [X3], #1
  SUB X2, X2, #1
  B mfp_l

mfp_l_exit:
  #endif
  RET

#elif __arm__
  LDR R2, [R3]
  ADD R2, R2, #1
  STR R2, [R3]

  /* We don't really need to preserve the value of R2 here,
     but by pushing it we maintain stack alignment */
  PUSH {R0-R2, LR}
  BL memcheck_free_hook
  POP {R0-R2, PC}
#endif
.endfunc


// (es-1) (X18/R3) is a pointer to <in_malloc>
.global memcheck_free_post
.func
memcheck_free_post:
#ifdef __aarch64__
  LDR X2, [X18]
  SUB X2, X2, #1
  STR X2, [X18]
  RET
#elif __arm__
  LDR R2, [R3]
  SUB R2, R2, #1
  STR R2, [R3]
  BX LR
#endif
.endfunc


// X0/R0 - access address
// X1/R1 - access size | IS_STORE
// X2/R2 - SPC
// X3/R3 is a pointer to <in_malloc>
// X4/R4 and LR are also pushed
.global memcheck_unalloc
.func
#ifdef __arm__
.thumb_func
#endif
memcheck_unalloc:
#ifdef __aarch64__
  LDR X3, [X3]
  CBNZ X3, skip_err

  STR X30, [SP, #-16]!

  BL push_x4_x21
  MRS X19, NZCV
  MRS X20, FPCR
  MRS X21, FPSR
  BL push_neon

  MOV X3, X29 // frame pointer
  BL memcheck_print_error

  BL pop_neon
  MSR NZCV, X19
  MSR FPCR, X20
  MSR FPSR, X21
  BL pop_x4_x21

  LDR X30, [SP], #16

skip_err:
  RET

#elif __arm__
  LDR R3, [R3]
  CBNZ R3, skip_err

  PUSH {R5-R6, R9, R12, LR}
  VPUSH {d16-d31}
  VPUSH {d0-d7}

  MRS r4, CPSR
  VMRS r5, FPSCR

  // align the SP
  MOV R6, SP
  BIC R3, R6, #7
  MOV SP, R3

  MOV R3, R11 // frame pointer
  BL memcheck_print_error

  MOV SP, R6

  VMSR FPSCR, r5
  MSR CPSR, r4

  VPOP {d0-d7}
  VPOP {d16-d31}
  POP {R5-R6, R9, R12, LR}

skip_err:
  BX LR
#endif
.endfunc


.global memcheck_ret
.func
memcheck_ret:
#ifdef __aarch64__
  RET
#elif __arm__
  BX LR
#endif
