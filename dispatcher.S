/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2015-2017 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
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
#endif

#ifdef __aarch64__
.global push_neon
push_neon:
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
  RET

.global pop_neon
pop_neon:
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
  RET

.global push_x4_x21
push_x4_x21:
  STP  X4,  X5, [SP, #-144]!
  STP  X6,  X7, [SP, #16]
  STP  X8,  X9, [SP, #32]
  STP X10, X11, [SP, #48]
  STP X12, X13, [SP, #64]
  STP X14, X15, [SP, #80]
  STP X16, X17, [SP, #96]
  STP X18, X19, [SP, #112]
  STP X20, X21, [SP, #128]
  RET

.global pop_x4_x21
pop_x4_x21:
  LDP  X6,  X7, [SP, #16]
  LDP  X8,  X9, [SP, #32]
  LDP X10, X11, [SP, #48]
  LDP X12, X13, [SP, #64]
  LDP X14, X15, [SP, #80]
  LDP X16, X17, [SP, #96]
  LDP X18, X19, [SP, #112]
  LDP X20, X21, [SP, #128]
  LDP  X4,  X5, [SP], #144
  RET
#endif

#ifdef __aarch64__
dispatcher_trampoline:
  // PUSH all general purpose registers but X0, X1
  // X0 and X1 are pushed by the exit stub
  STP  X2,  X3, [SP, #-48]!
  STP X29, X30, [SP, #16]
  STR  X0,      [SP, #40]
  BL push_x4_x21

  MRS X19, NZCV
  MRS X20, FPCR
  MRS X21, FPSR

  ADD X2, SP, #176
  LDR X3, disp_thread_data
  LDR X9, dispatcher_addr
  BL push_neon

  BLR X9

  BL pop_neon
  MSR NZCV, X19
  MSR FPCR, X20
  MSR FPSR, X21

  BL pop_x4_x21
  LDP X29, X30, [SP, #16]
  LDP  X0,  X1, [SP, #32]
  LDP  X2,  X3, [SP], #48

  B checked_cc_return

dispatcher_addr: .quad dispatcher
#endif
.endfunc

.global trace_head_incr
.func   trace_head_incr
#ifdef __arm__
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
#endif // __arm__
#ifdef __aarch64__
trace_head_incr:
  /*
   * X1 = Basic Block number
   * X30 = Address to return on the code cache.
   * X2 = address of the counter
   */
  STP      X2,  X3, [SP, #-16]!
  // Leave space for storing the address of the counter to X2
  NOP  // MOVZ X2, #address_first_half_word
  NOP  // MOVK X2, #address_second_half_word, lsl #16
  NOP  // MOVK X2, #address_third_half_word,  lsl #32
  NOP  // MOVK X2, #address_fourth_half_word, lsl #48
  LDRB W3, [X2, X1]
  SUB  W3,  W3, #1
  STRB W3, [X2, X1]
  CBZ  W3,  create_trace_trampoline
  LDP  X2,  X3, [SP], #16
  RET

create_trace_trampoline:
  LDP X2, X30, [SP, #16]
  STP X0,  X2, [SP, #16]

  STP X29, X30, [SP, #-32]!
  BL push_x4_x21

  MRS X19, NZCV
  MRS X20, FPCR
  MRS X21, FPSR

  /*
   * create_trace (dbm_thread *thread_data,   X0
   *               uint32_t    bb_source,     X1
   *               uint32_t   *trace_addr)    X2
   */
  ADD X2, SP, #160
  LDR X0, disp_thread_data
  LDR X3, =create_trace
  BL push_neon

  BLR X3

  BL pop_neon
  MSR NZCV, X19
  MSR FPCR, X20
  MSR FPSR, X21

  BL pop_x4_x21
  /* Stack layout:
     X29, X30
     TPC  SPC
     X2, X3 */
  LDP  X0,  X1, [SP, #16]
  LDP  X2,  X3, [SP, #32]
  LDP X29, X30, [SP], #48

  B checked_cc_return

#endif // __aarch64__
.endfunc

.global syscall_wrapper
.global syscall_wrapper_svc
.func   syscall_wrapper
#ifdef __arm__
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
#endif // __arm__

#ifdef __aarch64__
syscall_wrapper:
  STP X30, X29, [SP, #-16]!
  BL push_x4_x21
  STP X0, X1, [SP, #-32]!
  STP X2, X3, [SP, #16]
  BL push_neon

  MRS X19, NZCV
  MRS X20, FPCR
  MRS X21, FPSR

  MOV X0, X8
  ADD X1, SP, #512
  MOV X2, X29
  LDR X3, disp_thread_data
  LDR X4, syscall_handler_pre_addr

  BLR X4

  CBZ X0, s_w_r

  ADD X9, SP, #512
  LDP X0, X1, [X9, #0]
  LDP X2, X3, [X9, #16]
  LDP X4, X5, [X9, #32]
  LDP X6, X7, [X9, #48]
  LDR X8,     [X9, #64]

  // Balance the stack on rt_sigreturn, which doesn't return here
  CMP X8, #0x8b
  BNE svc
  ADD SP, SP, #(64 + 144 + 512)

svc: SVC 0
syscall_wrapper_svc:
  ADD X1, SP, #512
  STR X0, [X1, #0]
  MOV X0, X8
  MOV X2, X29
  LDR X3, disp_thread_data
  LDR X4, syscall_handler_post_addr
  BLR X4

s_w_r:
  BL pop_neon
  MSR NZCV, X19
  MSR FPCR, X20
  MSR FPSR, X21

  LDP X2, X3, [SP, #16]
  LDP X0, X1, [SP], #32
  BL pop_x4_x21
  LDP X29, X30, [SP, #16]
  STP X0, X1, [SP, #16]
  LDP X0, X1, [SP], #16

  B checked_cc_return

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

.global send_self_signal

.global checked_cc_return
.func   checked_cc_return
checked_cc_return:
#ifdef __arm__
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

#elif __aarch64__
  STR X2, [SP, #-16]!
  LDR X2, th_is_pending_ptr
  LDR W2, [X2]
  CBNZ W2, deliver_signals_trampoline
  LDR X2, [SP], #16
  BR X0
deliver_signals_trampoline:
  STP X0, X1, [SP, #-16]!
  MOV X0, X1 // set the SPC argument

  STR X3, [SP, #-64]!
  STP X29, X30, [SP, #16]
  ADD X1, SP, #32
  BL push_x4_x21
  BL push_neon

  MRS X19, NZCV
  MRS X20, FPCR
  MRS X21, FPSR

  MOV X2, #0xd6db
  CMP X0, X2
  BEQ .

  LDR X3, =deliver_signals
  BLR X3

  MSR NZCV, X19
  MSR FPCR, X20
  MSR FPSR, X21

  BL pop_neon
  BL pop_x4_x21
  LDP X29, X30, [SP, #16]
  LDR X3, [SP], #32

  CBZ X0, abort_self_signal

  LDR X2, [SP, #16]
  LDP X0, X1, [SP], #32

  STR X8, [SP, #24]

  /*
    TPC, SPC
    X2, X8
    X0, X1
  */
r:
  MOV X8, #131
  SVC 0
send_self_signal:
  LDP X2, X8, [SP, #16]
  LDR X0, [SP], #32
  BR X0
abort_self_signal:
  ADD SP, SP, #32
  LDR X2, [SP, #16]
  LDR X0, [SP], #32
  BR X0
#endif
.endfunc

.global th_is_pending_ptr
#ifdef __arm__
th_is_pending_ptr: .word 0
#elif __aarch64__
th_is_pending_ptr: .quad 0
#endif

# place the literal pool before the end_of_dispatcher_s symbol
.ltorg

.global end_of_dispatcher_s
end_of_dispatcher_s:

