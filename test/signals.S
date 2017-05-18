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

#ifdef __arm__
.syntax unified
#endif

.global test_cbz
.func

#ifdef __aarch64__
test_cbz:
  MOV W1, #0
cbz_loop:
  SUB W0, W0, #1
  AND W2, W0, #1
  CBZ W2, cbz_skip
  AND W2, W0, #2
  CBNZ W2, cbz_skip
  ADD W1, W1, #1
cbz_skip:
  CBNZ W0, cbz_loop

  MOV W0, W1
  RET
#endif

#ifdef __arm__
.type test_cbz, %function
.thumb_func
test_cbz:
  MOV R1, #0
cbz_loop:
  SUB R0, R0, #1
  AND R2, R0, #1
  CBZ R2, cbz_skip
  AND R2, R0, #2
  CBNZ R2, cbz_skip
  ADD R1, R1, #1
cbz_skip:
  CMP R0, #0
  BNE cbz_loop

  MOV R0, R1
  BX LR
#endif

.endfunc

#ifdef __arm__
.global test_a32_direct
.func
.type test_a32_direct, %function
.code 32
test_a32_direct:
  MOV R1, #0
a32d_loop:
  SUB R0, R0, #1
  ANDS R2, R0, #1
  BEQ a32d_skip
  ANDS R2, R0, #2
  BNE a32d_skip
  ADD R1, R1, #1
a32d_skip:
  CMP R0, #0
  BNE a32d_loop
  MOV R0, R1
  BX LR
.endfunc

.global test_a32_indirect
.func
.type test_a32_indirect, %function
.code 32
test_a32_indirect:
  MOV R1, #0
a32i_loop:
  SUB R0, R0, #1
  ANDS R2, R0, #1
  ADREQ R2, a32i_skip
  ADRNE R2, a32i_cont
  BX R2
a32i_cont:
  ADD R1, R1, #1
a32i_skip:
  CMP R0, #0
  ADREQ R2, a32i_ret
  ADRNE R2, a32i_loop
  BX R2
a32i_ret:
  MOV R0, R1
  BX LR
.endfunc
#endif


#ifdef __aarch64__

.global test_tbz
.func
test_tbz:
  MOV W1, #0
tbz_loop:
  SUB W0, W0, #1
  TBZ W0, #0, tbz_skip
  TBNZ W0, #1, tbz_skip
  ADD W1, W1, #1
tbz_skip: 
  CBNZ W0, tbz_loop

  MOV W0, W1
  RET
.endfunc

#endif
