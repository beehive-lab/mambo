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

# These helpers are executed from .text and are not copied to the code cache

.syntax unified

.global dbm_client_entry
.func dbm_client_entry
.code 32
.type dbm_client_entry, %function
dbm_client_entry:
  MOV SP, R1
  MOV LR, R0
  MOV R0, #0
  MOV R1, #0
  MOV R2, #0
  MOV R3, #0
  BLX LR
  BX LR
.endfunc

# R0 - pointer to saved registers
# This is executed from .text, not required in the code cache
.global dbm_thread_exit
.func dbm_thread_exit
.code 32
.type dbm_thread_exit, %function
dbm_thread_exit:
  LDM r0, {r0-r12, r14}
  MOV R7, #1
  SVC 0
  BKPT @ if this syscall returns, something went horribly wrong
  B .
.endfunc

.global dbm_aquire_lock
.func dbm_aquire_lock
.type dbm_aquire_lock, %function
dbm_aquire_lock:
  MOV R2, #1
retry:
  LDREX r1, [r0]
  CMP r1, #0
  BNE retry
  STREXEQ r1, r2, [r0]
  CMP r1, #0
  BNE retry
  DMB
  BX LR
.endfunc

.global dbm_release_lock
.func dbm_release_lock
.type dbm_release_lock, %function
dbm_release_lock:
  DMB
  MOV R1, #0
  STR R1, [R0]
  BX LR
.endfunc

# R0 - ptr to {R0-R12, R14} saved by the dispatcher
# R1 - ptr to {R8, R9, R14} saved by the application
# R2 - new SP
# R3 - CC address to branch to
.global th_enter
.func   th_enter
.type   th_enter, %function
.thumb_func
th_enter:
  MOV SP, R2
  PUSH {R1, R3}
  LDM R0, {R0-R12, R14}
  POP {R0}
  LDM R0, {R8, R9, R14}
  MOV R0, #0
  POP {PC}
.endfunc
