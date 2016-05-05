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

.global inline_hash_lookup
.global inline_hash_lookup_get_addr
.global inline_hash_lookup_data
.global end_of_inline_hash_lookup
.func inline_hash_lookup
#.thumb_func
inline_hash_lookup:
  # R0 is target
  PUSH {R3}
  LDR R3, scratch_reg_ptr
  STM R3, {R0-R2}
  POP {R3}
  
# hash lookup
inline_hash_lookup_get_addr:
  POP {R0}
  LDR R1, hash_table
  LDR R2, hash_mask
  AND R2, R0, R2
  ADD R1, R1, R2, LSL #3
asm_hash_lookup_loop:
  LDR R2, [R1], #8
  CMP R2, R0
  BEQ arm_hash_lookup_ret
  CMP R2, #0
  BEQ arm_hash_lookup_fail
  B asm_hash_lookup_loop
arm_hash_lookup_ret:
  LDR R0, [R1, #-4]
  STR R0, spc
  LDR R0, scratch_reg_ptr
  LDM R0, {R0-R2}
  LDR PC, spc
arm_hash_lookup_fail:
# full dispatcher
  LDR R1, bb_id
  LDR R2, dis
  BX R2
  
inline_hash_lookup_data:
spc: .word 0
#slr: .word 0
dis: .word 0
scratch_reg_ptr: .word 0
hash_table: .word 0
hash_mask: .word 0x7FFFF
bb_id: .word 0

.endfunc
end_of_inline_hash_lookup:

