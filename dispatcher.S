/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2017 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2015-2017 Guillermo Callaghan <guillermocallaghan at hotmail dot com>

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

#ifdef __arm__
.syntax unified

.global th_to_arm
.func th_to_arm
.thumb_func
th_to_arm:
  bx pc
.endfunc
#endif // __arm__

.global dispatcher_trampoline
.func   dispatcher_trampoline

#ifdef __arm__
.code 32
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
#endif

#ifdef __aarch64__
dispatcher_trampoline:
  // Push SIMD and floating point registers.
  STP  Q0,  Q1, [SP, #-512]!
  STP  Q2,  Q3, [SP,   #32]
  STP  Q4,  Q5, [SP,   #64]
  STP  Q6,  Q7, [SP,   #96]
  STP  Q8,  Q9, [SP,  #128]
  STP Q10, Q11, [SP,  #160]
  STP Q12, Q13, [SP,  #192]
  STP Q14, Q15, [SP,  #224]
  STP Q16, Q17, [SP,  #256]
  STP Q18, Q19, [SP,  #288]
  STP Q20, Q21, [SP,  #320]
  STP Q22, Q23, [SP,  #352]
  STP Q24, Q25, [SP,  #384]
  STP Q26, Q27, [SP,  #416]
  STP Q28, Q29, [SP,  #448]
  STP Q30, Q31, [SP,  #480]

  // PUSH all general purpose registers but X0, X1
  // X0 and X1 are pushed by the exit stub
  STP  X2,  X3, [SP,  #-240]!
  STP  X4,  X5, [SP,  #16]
  STP  X6,  X7, [SP,  #32]
  STP  X8,  X9, [SP,  #48]
  STP X10, X11, [SP,  #64]
  STP X12, X13, [SP,  #80]
  STP X14, X15, [SP,  #96]
  STP X16, X17, [SP,   #112]
  STP X18, X19, [SP,   #128]
  STP X20, X21, [SP,   #144]
  STP X22, X23, [SP,   #160]
  STP X24, X25, [SP,   #176]
  STP X26, X27, [SP,   #192]
  STP X28, X29, [SP,   #208]
  MRS  X3 , NZCV
  STP X30,  X3, [SP,  #224]

  MOV X2, X1
  ADR X1, ret_addr
  LDR X3, disp_thread_data
  LDR X9, dispatcher_addr
  BLR X9

  # POP from the stack
  LDP  X4,  X5, [SP, #16]
  LDP  X6,  X7, [SP, #32]
  LDP  X8,  X9, [SP, #48]
  LDP X10, X11, [SP, #64]
  LDP X12, X13, [SP, #80]
  LDP X14, X15, [SP, #96]
  LDP X16, X17, [SP, #112]
  LDP X18, X19, [SP, #128]
  LDP X20, X21, [SP, #144]
  LDP X22, X23, [SP, #160]
  LDP X24, X25, [SP, #176]
  LDP X26, X27, [SP, #192]
  LDP X28, X29, [SP, #208]
  LDP X30,  X3, [SP, #224]
  MSR NZCV, X3
  LDP  X2,  X3, [SP], #240

  // POP SIMD and floating point registers.
  LDP  Q2,  Q3, [SP, #32]
  LDP  Q4,  Q5, [SP, #64]
  LDP  Q6,  Q7, [SP, #96]
  LDP  Q8,  Q9, [SP, #128]
  LDP Q10, Q11, [SP, #160]
  LDP Q12, Q13, [SP, #192]
  LDP Q14, Q15, [SP, #224]
  LDP Q16, Q17, [SP, #256]
  LDP Q18, Q19, [SP, #288]
  LDP Q20, Q21, [SP, #320]
  LDP Q22, Q23, [SP, #352]
  LDP Q24, Q25, [SP, #384]
  LDP Q26, Q27, [SP, #416]
  LDP Q28, Q29, [SP, #448]
  LDP Q30, Q31, [SP, #480]
  LDP  Q0,  Q1, [SP], #512

  LDR X0, ret_addr
  BR X0

ret_addr:        .quad 0
dispatcher_addr: .quad dispatcher
#endif
.endfunc

#ifdef __arm__
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
#endif // __arm__

.global syscall_wrapper
.func   syscall_wrapper

#ifdef __arm__
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

  // Balance the stack on sigreturn and rt_sigreturn, which don't return here
  CMP R7, #119
  ADDEQ SP, SP, #60
  CMP R7, #173
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
#endif // __arm__

#ifdef __aarch64__
syscall_wrapper:
  STP      X0,  X1, [SP, #-240]!
  STP      X2,  X3, [SP,   #16]
  STP      X4,  X5, [SP,   #32]
  STP      X6,  X7, [SP,   #48]
  STP      X8,  X9, [SP,   #64]
  STP     X10, X11, [SP,   #80]
  STP     X12, X13, [SP,   #96]
  STP     X14, X15, [SP,  #112]
  STP     X16, X17, [SP,  #128]
  STP     X18, X19, [SP,  #144]
  STP     X20, X21, [SP,  #160]
  STP     X22, X23, [SP,  #176]
  STP     X24, X25, [SP,  #192]
  STP     X26, X27, [SP,  #208]
  STR     X28,      [SP,  #224]
  MRS X19, NZCV
  MOV X20, X30

  MOV X0, X8
  MOV X1, SP
  MOV X2, X29
  LDR X3, disp_thread_data

  LDR X4, syscall_handler_pre_addr
  BLR X4

  CBZ X0, s_w_r

  LDP X0, X1, [SP, #0]
  LDP X2, X3, [SP, #16]
  LDP X4, X5, [SP, #32]
  LDP X6, X7, [SP, #48]
  LDP X8, X9, [SP, #64]

  // Balance the stack on rt_sigreturn, which doesn't return here
  CMP X8, #0x8b
  BNE svc
  ADD SP, SP, #256

svc: SVC 0

  STP X0, X1, [SP, #0]

  MOV X0, X8
  MOV X1, SP
  MOV X2, X29
  LDR X3, disp_thread_data

  LDR X4, syscall_handler_post_addr
  BLR X4

s_w_r: MSR NZCV, X19
  MOV X30, X20
  LDP  X2,  X3, [SP,  #16]
  LDP  X4,  X5, [SP,  #32]
  LDP  X6,  X7, [SP,  #48]
  LDP  X8,  X9, [SP,  #64]
  LDP X10, X11, [SP,  #80]
  LDP X12, X13, [SP,  #96]
  LDP X14, X15, [SP, #112]
  LDP X16, X17, [SP, #128]
  LDP X18, X19, [SP, #144]
  LDP X20, X21, [SP, #160]
  LDP X22, X23, [SP, #176]
  LDP X24, X25, [SP, #192]
  LDP X26, X27, [SP, #208]
  LDR X28,      [SP, #224]
  LDP X0,  X1,  [SP], #240
  RET X30

syscall_handler_pre_addr: .quad syscall_handler_pre
syscall_handler_post_addr: .quad syscall_handler_post
#endif // __aarch64__
.endfunc

.global disp_thread_data
disp_thread_data:
#ifdef __arm__
  .word 0
#endif
#ifdef __aarch64__
  .quad 0
#endif

# place the literal pool before the end_of_dispatcher_s symbol
.ltorg

.global end_of_dispatcher_s
end_of_dispatcher_s:

