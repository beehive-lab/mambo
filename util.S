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
