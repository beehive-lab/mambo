/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2015-2017 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
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
.syntax unified

.global start_of_dispatcher_s
start_of_dispatcher_s:

.global th_to_arm
.thumb_func
th_to_arm:
  bx pc

.global dispatcher_trampoline
.code 32
dispatcher_trampoline:
  #R2 is available at this point
  #TODO: INSTALL our own stack

#A subroutine must preserve the contents of the registers r4-r8, r10, r11 and SP (and r9 in PCS variants that designate r9 as v6).
  PUSH {r3 - r6, r9, r12, lr}
  STR R0, [R3, #-4] // save the SPC
  SUB R2, R3, #8    // set up the TPC pointer
  VPUSH {d16-d31}
  VPUSH {d0-d7}

  MRS r5, CPSR
  VMRS r6, FPSCR

  LDR R3, disp_thread_data
  LDR R9, dispatcher_addr

  # provide 8-byte alignment of the SP
  MOV R4, SP
  BIC SP, #0x7
  BLX R9
  MOV SP, R4

  MSR CPSR, r5
  VMSR FPSCR, r6

  VPOP {d0-d7}
  VPOP {d16-d31}
  POP {r3 - r6, r9, r12, lr}

/*  SP ->  R0
           R1
           R2
           R3
       <0 or more words>
           EMPTY
           TPC
           SPC
    R3 ->
  */

  LDR R1, [SP, #12]
  STR R1, [R3, #-12]
  POP {R0, R1, R2}
  SUB SP, R3, #12
  POP {R3}
  B checked_cc_return

dispatcher_addr: .word dispatcher

.global trace_head_incr
.code 32
  SUB PC, PC, #3
.thumb_func
trace_head_incr:
  STR LR, [SP, #16]
  NOP // MOVW R1, #counter_base & 0xFFFF    
  NOP
  NOP // MOVT R1, #counter_base >> 16
  NOP
  LDRB R2, [R1, R0]
  SUBW  R2, R2, #1
  STRB R2, [R1, R0]
  CBZ  R2, create_trace_trampoline
  POP {R0-R2, LR}
  LDR PC, [SP], #8

.align 2
create_trace_trampoline:
  BX PC
  NOP
.code 32
  ADD R2, SP, #16
  PUSH {R3 - R6, R9, R12}
  VPUSH {D16-D31}
  VPUSH {D0-D7}

  MRS R5, CPSR
  VMRS R6, FPSCR

  MOV R1, R0
  LDR R0, disp_thread_data
  LDR R3, =create_trace

  MOV R4, SP
  BIC SP, #0x7
  BLX R3
  MOV SP, R4

  MSR CPSR, R5
  VMSR FPSCR, R6

  VPOP {D0-D7}
  VPOP {D16-D31}
  POP {R3 - R6, R9, R12}

  POP {R0-R2, LR}
  B checked_cc_return

.global syscall_wrapper
.global syscall_wrapper_svc
.code 32
syscall_wrapper:
  # R8 is the SPC of the following instruction
  # R14 is the address where to return in the code cache
  STR LR, [SP, #56] // save the TPC
  STR R8, [SP, #60] // save the SPC

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
  ADDEQ SP, SP, #64
  CMP R7, #173
  ADDEQ SP, SP, #64

  SVC 0
syscall_wrapper_svc:
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
s_w_r: POP {R0-R12, R14}
  B checked_cc_return

syscall_handler_pre_addr: .word syscall_handler_pre
syscall_handler_post_addr: .word syscall_handler_post


.global disp_thread_data
disp_thread_data: .word 0

.global send_self_signal

.global checked_cc_return
checked_cc_return:
.code 32
  SUB PC, PC, #3
.thumb_func
  PUSH {R0}
  LDR R0, th_is_pending_ptr
  LDR R0, [R0]
  CBZ R0, gotocc
  B deliver_signals_trampoline
gotocc:
  POP {R0}
  LDR PC, [SP], #8
deliver_signals_trampoline:
  LDR R0, [SP, #8] // load SPC
  SUB SP, SP, #12
  PUSH {r1 - r2}
  PUSH {r3 - r6, r9, r12, lr}
  ADD R1, SP, #36
  VPUSH {d16-d31}
  VPUSH {d0-d7}

  MRS r5, CPSR
  VMRS r6, FPSCR

  LDR R9, =deliver_signals

  # provide 8-byte alignment of the SP
  MOV R4, SP
  BIC R2, r4, #0x7
  MOV SP, R2
  BLX R9
  MOV SP, R4

  MSR CPSR, r5
  VMSR FPSCR, r6

  VPOP {d0-d7}
  VPOP {d16-d31}
  POP {r3 - r6, r9, r12, lr}

  /*  SP-> r1
           r2
           PID
           TID
           SIGNO
           R0
           TPC
           SPC
  */

  CBZ R0, abort_self_signal

  PUSH {R7}

  ADD R2, SP, #12
  LDM R2, {R0-R2}
  MOV R7, #268
  SVC 0
send_self_signal:
  POP {r7}
abort_self_signal:
  POP {r1-r2}
  ADD SP, SP, #12
  POP {r0}
  LDR PC, [SP], #8

.global th_is_pending_ptr
th_is_pending_ptr: .word 0

# place the literal pool before the end_of_dispatcher_s symbol
.ltorg

.global end_of_dispatcher_s
end_of_dispatcher_s:

