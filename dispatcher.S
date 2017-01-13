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
.global start_of_dispatcher_s
start_of_dispatcher_s:

.syntax unified

.global th_to_arm
.func th_to_arm
.thumb_func
th_to_arm:
  bx pc
.endfunc

.code 32
.global dispatcher_trampoline
.func   dispatcher_trampoline
dispatcher_trampoline:
  #R2 is available at this point
  #TODO: INSTALL our own stack

#A subroutine must preserve the contents of the registers r4-r8, r10, r11 and SP (and r9 in PCS variants that designate r9 as v6).
  SUB SP, SP, #4
  PUSH {r3, r4, r9, r12, lr}
  MOV R2, R1
  # PUSH CPSR
  MRS r1, CPSR
  PUSH {R1}
  # R0 is target, R1 where to put address
  ADD R1, SP, #24
  LDR R3, disp_thread_data
  LDR R9, dispatcher_addr

  # provide 8-byte alignment of the SP
  MOV R4, SP
  BIC SP, #0x7
  BLX R9
  MOV SP, R4

  # RESTORE CPSR
  POP {R1}
  MSR CPSR, r1
  LDR R0, scratch_space
  LDM R0, {R0-R2}
  POP {r3, r4, r9, r12, lr, pc}
ret_addr: .word 0
dispatcher_addr: .word dispatcher
scratch_space: .word 0
.endfunc

  SUB PC, PC, #3
.global trace_head_incr
.func   trace_head_incr
.thumb_func
trace_head_incr:
  NOP
  PUSH {LR}
  NOP // MOVW R1, #counter_base & 0xFFFF    
  NOP
  NOP // MOVT R1, #counter_base >> 16
  NOP
  //NOP // ADD R1, R1, R0
  LDRB R2, [R1, R0]
  SUBW  R2, R2, #1
  STRB R2, [R1, R0]
  CBZ  R2, create_trace_trampoline
  ADD R2, SP, #4
  LDM R2, {R0-R2, LR}
  LDR PC, [SP], #20
create_trace_trampoline:
  BX PC
  NOP
.code 32
  MRS r2, CPSR
  PUSH {R2, R3, R4, R9, R12}

  ADD R2, SP, #20
  MOV R1, R0
  LDR R0, disp_thread_data
  LDR R3, =create_trace

  MOV R4, SP
  BIC SP, #0x7
  BLX R3
  MOV SP, R4
  
  POP {R2, R3, R4, R9, R12}
  MSR CPSR, r2
  
  ADD R2, SP, #4
  LDM R2, {R0-R2, LR}
  LDR PC, [SP], #20
.endfunc

.global syscall_wrapper
.func   syscall_wrapper
.code 32
syscall_wrapper:
  # R8 is the SPC of the following instruction
  # R14 is the address where to return in the code cache
  STR LR, [SP, #56]

  MOV R0, R7 // syscall id
  MOV R1, SP // pointer to saved regs
  MOV R2, R8 // SPC of the next instr.
  LDR R3, disp_thread_data

  LDR R4, syscall_handler_pre_addr
  // provide 8-byte alignment of the SP
  MOV R5, SP
  BIC SP, #0x7
  BLX R4
  MOV SP, R5

  // don't execute the syscall if pre handler returns 0
  CMP R0, #0
  BEQ s_w_r

  // only allow overriding R0-R7
  // the value of R8 must be preserved
  LDM SP, {R0-R7}

  // Balance the stack on sigreturn, which doesn't return here
  CMP R7, #119
  ADDEQ SP, SP, #60

  SVC 0
  STM SP, {R0-R7}

  MOV R0, R7
  MOV R1, SP
  MOV R2, R8
  LDR R3, disp_thread_data

  LDR R4, syscall_handler_post_addr
  // provide 8-byte alignment of the SP
  MOV R5, SP
  BIC SP, #0x7
  BLX R4
  MOV SP, R5
s_w_r: POP {R0-R12, R14, PC}

syscall_handler_pre_addr: .word syscall_handler_pre
syscall_handler_post_addr: .word syscall_handler_post
.endfunc

.global disp_thread_data
disp_thread_data:
.word 0

# place the literal pool before the end_of_dispatcher_s symbol
.ltorg

.global end_of_dispatcher_s
end_of_dispatcher_s:

