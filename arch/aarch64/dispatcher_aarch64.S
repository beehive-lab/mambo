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
.global start_of_dispatcher_s
start_of_dispatcher_s:

.global push_simd
push_simd:
#if defined(__ARM_FEATURE_SVE) || defined(__ARM_FEATURE_SVE2)
  ADDVL SP, SP, #-32
  STR Z0, [SP]
  STR Z1, [SP, #1, MUL VL]
  STR Z2, [SP, #2, MUL VL]
  STR Z3, [SP, #3, MUL VL]
  STR Z4, [SP, #4, MUL VL]
  STR Z5, [SP, #5, MUL VL]
  STR Z6, [SP, #6, MUL VL]
  STR Z7, [SP, #7, MUL VL]
  STR Z8, [SP, #8, MUL VL]
  STR Z9, [SP, #9, MUL VL]
  STR Z10, [SP, #10, MUL VL]
  STR Z11, [SP, #11, MUL VL]
  STR Z12, [SP, #12, MUL VL]
  STR Z13, [SP, #13, MUL VL]
  STR Z14, [SP, #14, MUL VL]
  STR Z15, [SP, #15, MUL VL]
  STR Z16, [SP, #16, MUL VL]
  STR Z17, [SP, #17, MUL VL]
  STR Z18, [SP, #18, MUL VL]
  STR Z19, [SP, #19, MUL VL]
  STR Z20, [SP, #20, MUL VL]
  STR Z21, [SP, #21, MUL VL]
  STR Z22, [SP, #22, MUL VL]
  STR Z23, [SP, #23, MUL VL]
  STR Z24, [SP, #24, MUL VL]
  STR Z25, [SP, #25, MUL VL]
  STR Z26, [SP, #26, MUL VL]
  STR Z27, [SP, #27, MUL VL]
  STR Z28, [SP, #28, MUL VL]
  STR Z29, [SP, #29, MUL VL]
  STR Z30, [SP, #30, MUL VL]
  STR Z31, [SP, #31, MUL VL]

  ADDPL SP, SP, #-16
  STR P0, [SP]
  STR P1, [SP, #1, MUL VL]
  STR P2, [SP, #2, MUL VL]
  STR P3, [SP, #3, MUL VL]
  STR P4, [SP, #4, MUL VL]
  STR P5, [SP, #5, MUL VL]
  STR P6, [SP, #6, MUL VL]
  STR P7, [SP, #7, MUL VL]
  STR P8, [SP, #8, MUL VL]
  STR P9, [SP, #9, MUL VL]
  STR P10, [SP, #10, MUL VL]
  STR P11, [SP, #11, MUL VL]
  STR P12, [SP, #12, MUL VL]
  STR P13, [SP, #13, MUL VL]
  STR P14, [SP, #14, MUL VL]
  STR P15, [SP, #15, MUL VL]
#else
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
#endif
  RET

.global pop_simd
pop_simd:
#if defined(__ARM_FEATURE_SVE) || defined(__ARM_FEATURE_SVE2)
  LDR P0, [SP]
  LDR P1, [SP, #1, MUL VL]
  LDR P2, [SP, #2, MUL VL]
  LDR P3, [SP, #3, MUL VL]
  LDR P4, [SP, #4, MUL VL]
  LDR P5, [SP, #5, MUL VL]
  LDR P6, [SP, #6, MUL VL]
  LDR P7, [SP, #7, MUL VL]
  LDR P8, [SP, #8, MUL VL]
  LDR P9, [SP, #9, MUL VL]
  LDR P10, [SP, #10, MUL VL]
  LDR P11, [SP, #11, MUL VL]
  LDR P12, [SP, #12, MUL VL]
  LDR P13, [SP, #13, MUL VL]
  LDR P14, [SP, #14, MUL VL]
  LDR P15, [SP, #15, MUL VL]
  ADDPL SP, SP, #16

  LDR Z31, [SP, #31, MUL VL]
  LDR Z30, [SP, #30, MUL VL]
  LDR Z29, [SP, #29, MUL VL]
  LDR Z28, [SP, #28, MUL VL]
  LDR Z27, [SP, #27, MUL VL]
  LDR Z26, [SP, #26, MUL VL]
  LDR Z25, [SP, #25, MUL VL]
  LDR Z24, [SP, #24, MUL VL]
  LDR Z23, [SP, #23, MUL VL]
  LDR Z22, [SP, #22, MUL VL]
  LDR Z21, [SP, #21, MUL VL]
  LDR Z20, [SP, #20, MUL VL]
  LDR Z19, [SP, #19, MUL VL]
  LDR Z18, [SP, #18, MUL VL]
  LDR Z17, [SP, #17, MUL VL]
  LDR Z16, [SP, #16, MUL VL]
  LDR Z15, [SP, #15, MUL VL]
  LDR Z14, [SP, #14, MUL VL]
  LDR Z13, [SP, #13, MUL VL]
  LDR Z12, [SP, #12, MUL VL]
  LDR Z11, [SP, #11, MUL VL]
  LDR Z10, [SP, #10, MUL VL]
  LDR Z9, [SP,  #9 , MUL VL]
  LDR Z8, [SP,  #8 , MUL VL]
  LDR Z7, [SP,  #7 , MUL VL]
  LDR Z6, [SP,  #6 , MUL VL]
  LDR Z5, [SP,  #5 , MUL VL]
  LDR Z4, [SP,  #4 , MUL VL]
  LDR Z3, [SP,  #3 , MUL VL]
  LDR Z2, [SP,  #2 , MUL VL]
  LDR Z1, [SP,  #1 , MUL VL]
  LDR Z0, [SP]
  ADDVL SP, SP, #31
  ADDVL SP, SP, #1
#else
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
#endif
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

.global dispatcher_trampoline
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
  BL push_simd

  BLR X9

  BL pop_simd
  MSR NZCV, X19
  MSR FPCR, X20
  MSR FPSR, X21

  BL pop_x4_x21
  LDP X29, X30, [SP, #16]
  LDP  X0,  X1, [SP, #32]
  LDP  X2,  X3, [SP], #48

  B checked_cc_return

dispatcher_addr: .quad dispatcher


.global trace_head_incr
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
   * create_trace(dbm_thread   *thread_data,   X0
   *              uint32_t      bb_source,     X1
   *              cc_addr_pair *trace_addr)    X2
   */
  ADD X2, SP, #160
  LDR X0, disp_thread_data
  LDR X3, =create_trace
  BL push_simd

  BLR X3

  BL pop_simd
  MSR NZCV, X19
  MSR FPCR, X20
  MSR FPSR, X21

  BL pop_x4_x21
  /* Stack layout:
   * SP ->| X29 | X30 | SP + 0
   *      | TPC | SPC | SP + 16
   *      | X2  | X3  | SP + 32
   *      ---------------------
   *      | X0  | X1  | SP + 48 (Pushed by the basic block
   *                             and popped in the newly created trace)
   */
  LDP  X0,  X1, [SP, #16]
  LDP  X2,  X3, [SP, #32]
  LDP X29, X30, [SP], #48

  B checked_cc_return


.global syscall_wrapper
.global syscall_wrapper_svc
syscall_wrapper:
  STP X30, X29, [SP, #-16]!
  BL push_x4_x21
  STP X0, X1, [SP, #-32]!
  STP X2, X3, [SP, #16]
  BL push_simd

  MRS X19, NZCV
  MRS X20, FPCR
  MRS X21, FPSR

  MOV X0, X8
#if defined(__ARM_FEATURE_SVE) || defined(__ARM_FEATURE_SVE2)
  MOV X1, #0
  ADDVL X1, X1, #31
  ADDVL X1, X1, #1
  ADDPL X1, X1, #16
#else // defined(__ARM_NEON)
  MOV X1, #512
#endif
  ADD X1, SP, X1
  MOV X2, X29
  LDR X3, disp_thread_data
  LDR X4, syscall_handler_pre_addr

  BLR X4

  CBZ X0, s_w_r

#if defined(__ARM_FEATURE_SVE) || defined(__ARM_FEATURE_SVE2)
  MOV X9, #0
  ADDVL X9, X9, #31
  ADDVL X9, X9, #1
  ADDPL X9, X9, #16
#else // defined(__ARM_NEON)
  MOV X9, #512
#endif
  ADD X9, SP, X9
  LDP X0, X1, [X9, #0]
  LDP X2, X3, [X9, #16]
  LDP X4, X5, [X9, #32]
  LDP X6, X7, [X9, #48]
  LDR X8,     [X9, #64]

  // Balance the stack on rt_sigreturn, which doesn't return here
  CMP X8, #0x8b
  BNE svc

#if defined(__ARM_FEATURE_SVE) || defined(__ARM_FEATURE_SVE2)
  ADD SP, SP, #(64 + 144)
  ADDVL SP, SP, #31
  ADDVL SP, SP, #1
  ADDPL SP, SP, #16
#else // defined(__ARM_NEON)
  ADD SP, SP, #(64 + 144 + 512)
#endif

svc: SVC 0
syscall_wrapper_svc:
#if defined(__ARM_FEATURE_SVE) || defined(__ARM_FEATURE_SVE2)
  MOV X1, #0
  ADDVL X1, X1, #31
  ADDVL X1, X1, #1
  ADDPL X1, X1, #16
#else // defined(__ARM_NEON)
  MOV X1, #512
#endif
  ADD X1, SP, X1
  STR X0, [X1, #0]
  MOV X0, X8
  MOV X2, X29
  LDR X3, disp_thread_data
  LDR X4, syscall_handler_post_addr
  BLR X4

s_w_r:
  BL pop_simd
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

.global disp_thread_data
disp_thread_data: .quad 0

.global send_self_signal

.global checked_cc_return
checked_cc_return:
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
  BL push_simd

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

  BL pop_simd
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

.global th_is_pending_ptr
th_is_pending_ptr: .quad 0

# place the literal pool before the end_of_dispatcher_s symbol
.ltorg

.global end_of_dispatcher_s
end_of_dispatcher_s:

