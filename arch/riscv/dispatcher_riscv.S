/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2020 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
  Copyright 2020 The University of Manchester

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

#if   __riscv_xlen == 32
  #define GP_REG_SIZE 4
  #define STR      sw
  #define LDR      lw
#elif __riscv_xlen == 64
  #define GP_REG_SIZE 8
  #define STR      sd
  #define LDR      ld
#elif __riscv_xlen == 128
   #error "Risc-V 128-bit no implemented"
#endif

push_caller_saved_registers:
  addi    sp, sp, -(12 * GP_REG_SIZE)
  STR     a3,  0 * GP_REG_SIZE(sp)
  STR     a4,  1 * GP_REG_SIZE(sp)
  STR     a5,  2 * GP_REG_SIZE(sp)
  STR     a6,  3 * GP_REG_SIZE(sp)
  STR     a7,  4 * GP_REG_SIZE(sp)
  STR     t0,  5 * GP_REG_SIZE(sp)
  STR     t1,  6 * GP_REG_SIZE(sp)
  STR     t2,  7 * GP_REG_SIZE(sp)
  STR     t3,  8 * GP_REG_SIZE(sp)
  STR     t4,  9 * GP_REG_SIZE(sp)
  STR     t5, 10 * GP_REG_SIZE(sp)
  STR     t6, 11 * GP_REG_SIZE(sp)
  ret

pop_caller_saved_registers:
  LDR     a3,  0 * GP_REG_SIZE(sp)
  LDR     a4,  1 * GP_REG_SIZE(sp)
  LDR     a5,  2 * GP_REG_SIZE(sp)
  LDR     a6,  3 * GP_REG_SIZE(sp)
  LDR     a7,  4 * GP_REG_SIZE(sp)
  LDR     t0,  5 * GP_REG_SIZE(sp)
  LDR     t1,  6 * GP_REG_SIZE(sp)
  LDR     t2,  7 * GP_REG_SIZE(sp)
  LDR     t3,  8 * GP_REG_SIZE(sp)
  LDR     t4,  9 * GP_REG_SIZE(sp)
  LDR     t5, 10 * GP_REG_SIZE(sp)
  LDR     t6, 11 * GP_REG_SIZE(sp)
  addi    sp, sp, (12 * GP_REG_SIZE)
  ret

#if __riscv_flen

#if   __riscv_flen == 32
  #define FSTR        fsw
  #define FLDR        flw
  #define FP_REG_SIZE 4
#elif __riscv_flen == 64
  #define FSTR        fsd
  #define FLDR        fld
  #define FP_REG_SIZE 8
#endif
#define FP_FRAME_SZ (FP_REG_SIZE * 32)

.global push_fp
push_fp:
  addi    sp,  sp, -FP_FRAME_SZ
  FSTR    f0,  0  * FP_REG_SIZE(sp)
  FSTR    f1,  1  * FP_REG_SIZE(sp)
  FSTR    f2,  2  * FP_REG_SIZE(sp)
  FSTR    f3,  3  * FP_REG_SIZE(sp)
  FSTR    f4,  4  * FP_REG_SIZE(sp)
  FSTR    f5,  5  * FP_REG_SIZE(sp)
  FSTR    f6,  6  * FP_REG_SIZE(sp)
  FSTR    f7,  7  * FP_REG_SIZE(sp)
  FSTR    f8,  8  * FP_REG_SIZE(sp)
  FSTR    f9,  9  * FP_REG_SIZE(sp)
  FSTR   f10, 10  * FP_REG_SIZE(sp)
  FSTR   f11, 11  * FP_REG_SIZE(sp)
  FSTR   f12, 12  * FP_REG_SIZE(sp)
  FSTR   f13, 13  * FP_REG_SIZE(sp)
  FSTR   f14, 14  * FP_REG_SIZE(sp)
  FSTR   f15, 15  * FP_REG_SIZE(sp)
  FSTR   f16, 16  * FP_REG_SIZE(sp)
  FSTR   f17, 17  * FP_REG_SIZE(sp)
  FSTR   f18, 18  * FP_REG_SIZE(sp)
  FSTR   f19, 19  * FP_REG_SIZE(sp)
  FSTR   f20, 20  * FP_REG_SIZE(sp)
  FSTR   f21, 21  * FP_REG_SIZE(sp)
  FSTR   f22, 22  * FP_REG_SIZE(sp)
  FSTR   f23, 23  * FP_REG_SIZE(sp)
  FSTR   f24, 24  * FP_REG_SIZE(sp)
  FSTR   f25, 25  * FP_REG_SIZE(sp)
  FSTR   f26, 26  * FP_REG_SIZE(sp)
  FSTR   f27, 27  * FP_REG_SIZE(sp)
  FSTR   f28, 28  * FP_REG_SIZE(sp)
  FSTR   f29, 29  * FP_REG_SIZE(sp)
  FSTR   f30, 30  * FP_REG_SIZE(sp)
  FSTR   f31, 31  * FP_REG_SIZE(sp)
  ret

.global pop_fp
pop_fp:
  FLDR    f0,  0  * FP_REG_SIZE(sp)
  FLDR    f1,  1  * FP_REG_SIZE(sp)
  FLDR    f2,  2  * FP_REG_SIZE(sp)
  FLDR    f3,  3  * FP_REG_SIZE(sp)
  FLDR    f4,  4  * FP_REG_SIZE(sp)
  FLDR    f5,  5  * FP_REG_SIZE(sp)
  FLDR    f6,  6  * FP_REG_SIZE(sp)
  FLDR    f7,  7  * FP_REG_SIZE(sp)
  FLDR    f8,  8  * FP_REG_SIZE(sp)
  FLDR    f9,  9  * FP_REG_SIZE(sp)
  FLDR   f10, 10  * FP_REG_SIZE(sp)
  FLDR   f11, 11  * FP_REG_SIZE(sp)
  FLDR   f12, 12  * FP_REG_SIZE(sp)
  FLDR   f13, 13  * FP_REG_SIZE(sp)
  FLDR   f14, 14  * FP_REG_SIZE(sp)
  FLDR   f15, 15  * FP_REG_SIZE(sp)
  FLDR   f16, 16  * FP_REG_SIZE(sp)
  FLDR   f17, 17  * FP_REG_SIZE(sp)
  FLDR   f18, 18  * FP_REG_SIZE(sp)
  FLDR   f19, 19  * FP_REG_SIZE(sp)
  FLDR   f20, 20  * FP_REG_SIZE(sp)
  FLDR   f21, 21  * FP_REG_SIZE(sp)
  FLDR   f22, 22  * FP_REG_SIZE(sp)
  FLDR   f23, 23  * FP_REG_SIZE(sp)
  FLDR   f24, 24  * FP_REG_SIZE(sp)
  FLDR   f25, 25  * FP_REG_SIZE(sp)
  FLDR   f26, 26  * FP_REG_SIZE(sp)
  FLDR   f27, 27  * FP_REG_SIZE(sp)
  FLDR   f28, 28  * FP_REG_SIZE(sp)
  FLDR   f29, 29  * FP_REG_SIZE(sp)
  FLDR   f30, 30  * FP_REG_SIZE(sp)
  FLDR   f31, 31  * FP_REG_SIZE(sp)
  addi   sp,  sp, FP_FRAME_SZ
  ret
#endif


.global dispatcher_trampoline
dispatcher_trampoline:
  /* s1, a0 and a1 are pushed to the stack by the basic block exit, and then
   * the following values are set:
   *      a0 -> target
   *      a1 -> basic block number
   *
   *     +--------+
   *     | Stack  |
   * sp->+--------+
   *   0 |  a2    |
   *   8 |  ra    |
   *  16 |  s0    |  used to store fcsr
   *  24 |  s2    |  used to store frm
   *  32 |  tp    |
   *  40 |  gp    |
   *  48 |  SPC   |  target SPC, not used for now - needed for signal handling
   *  56 |  TPC   |  target TPC, will jump here on return
   *     +--------+ <-Registers below pushed in the code cache
   *  64 |  s1    |  used to store fflags
   *  72 |  a0    |
   *  80 |  a1    |
   *     +--------+
   */
  addi    sp, sp, -64
  sd      a2,  0(sp)
  sd      ra,  8(sp)
  sd      s0, 16(sp)
  sd      s2, 24(sp)
  sd      tp, 32(sp)
  sd      gp, 40(sp)
  sd      a0, 48(sp)
  add     a2, sp, 56 // set a2 to address of next_addr

  jal     ra,  push_caller_saved_registers
  jal     ra,  push_fp

  // Save the status registers
  frcsr s0
  frflags s1
  frrm s2

  /* Set the arguments to call the dispatcher:
   *
   * dispatcher(uintptr_t   target,           a0 -> Set by the Basic Block
   *            uint32_t    source_index,     a1 -> Set by the Basic Block
   *            uintptr_t  *next_addr,        a2 -> Unused uintptr_t space in the stack
   *            dbm_thread *thread_data)      a3 -> thread_data
   */
  lla a3, disp_thread_data
  ld  a3, (a3)

  lla a4, dispatcher_addr
  ld  a4, (a4)

  // load MAMBO's thread pointer
  ld  tp, 0(a3)
  // load MAMBO's global pointer
  lla gp, mambo_gp_addr
  ld  gp, (gp)
  ld  gp, (gp)

  jalr    ra, a4          // Branch to the dispatcher

  // Restore the status registers
  fscsr s0
  fsflags s1
  fsrm s2

  jal     ra, pop_fp
  jal     ra, pop_caller_saved_registers

  ld      a2,  0(sp)
  ld      ra,  8(sp)
  ld      s0, 16(sp)
  ld      s2, 24(sp)
  ld      tp, 32(sp)
  ld      gp, 40(sp)
  ld      a0, 56(sp) // TPC (Translated target)
  ld      s1, 64(sp)
  addi    sp, sp, 72

  // Once the signal handler is ported this will change to check for signals
  // pending firts (checked_cc_return)
  jr a0

dispatcher_addr: .quad dispatcher
mambo_gp_addr: .quad mambo_gp

#ifdef DBM_TRACES

  /* ra, a0 and a1 are pushed to the stack by the basic block.
   *
   *     +--------+
   *     | Stack  |
   * sp->+--------+ <- pushed by create_trace_trampoline
   *     | s0     |
   *     | s1     |
   *     | s2     |
   *     | FP     | <- FP registers saved by push_fp
   *     | CALLER | <- caller saved registers pushed by push_caller_saved_registers
   *     | RET_ADR| <- Address of the new fragment
   *     +--------+ <- Registers below this line are pushed by trace_head_incr
   *     |  a2    |
   *     |  a3    |
   *     +--------+ <-Registers below pushed in the code cache
   *     |  ra    |
   *     |  a0    |
   *     |  a1    |
   *     +--------+
   */
.global trace_head_incr
trace_head_incr:
  addi    sp, sp, -(2 * GP_REG_SIZE)
  STR     a2, 0 * GP_REG_SIZE(sp)
  STR     a3, 1 * GP_REG_SIZE(sp)

  nop
  nop
  nop
  nop
  nop
  nop
  nop

  add     a2, a2, a1
  lbu     a3, 0(a2)
  addi    a3, a3, 1
  sb      a3, 0(a2)
  addi    a3, a3, -256
  beqz    a3, create_trace_trampoline

return_to_cc:
  LDR     a2, 0 * GP_REG_SIZE(sp)
  LDR     a3, 1 * GP_REG_SIZE(sp)
  addi    sp, sp, (2 * GP_REG_SIZE)
  ret     #TO-DO need checked-cc-return

create_trace_trampoline:

  addi    sp, sp, -(1 * GP_REG_SIZE)
  addi    a2, sp, 0 * GP_REG_SIZE

  jal     ra, push_caller_saved_registers
  jal     ra, push_fp

  addi    sp, sp, -3 * GP_REG_SIZE
  STR     s0, 0 * GP_REG_SIZE(sp)
  STR     s1, 1 * GP_REG_SIZE(sp)
  STR     s2, 2 * GP_REG_SIZE(sp)

  lla a4, create_trace_addr
  ld  a4, (a4)

  lla a0, disp_thread_data
  ld  a0, (a0)

  frcsr s0
  frflags s1
  frrm s2

  jalr    ra, a4

  fscsr s0
  fsflags s1
  fsrm s2

  LDR     s0, 0 * GP_REG_SIZE(sp)
  LDR     s1, 1 * GP_REG_SIZE(sp)
  LDR     s2, 2 * GP_REG_SIZE(sp)
  addi    sp, sp, (3 * GP_REG_SIZE)

  jal     ra, pop_fp
  jal     ra, pop_caller_saved_registers

  LDR     a0, 0 * GP_REG_SIZE(sp)
  addi    sp, sp, (1 * GP_REG_SIZE)


  LDR     ra, 2 * GP_REG_SIZE(sp)
  LDR     a2, 0  * GP_REG_SIZE(sp)
  LDR     a3, 1 * GP_REG_SIZE(sp)
  addi    sp, sp, (3 * GP_REG_SIZE)

  jr a0

create_trace_addr: .quad create_trace

#endif


.global syscall_wrapper
syscall_wrapper:
  /* On entry:
   *     s0 -> return SPC
   *     ra -> return TPC
   *
   *     +--------+
   *     | Stack  |
   * sp->+--------+
   *   0 |  ra    |
   *   8 |  s0    |
   *  16 |  s1    |
   *  24 | empty  |
   *  32 | empty  |
   *     +--------+
   *
   * Note: at the TPC we always have a pop {a0, a1}, regardless of whether it's
   * at the location passed from the CC or a newly scanned fragment.
   *
   * We'll push additional registers to end up with this stack structure:
   *
            +--------+
   *        | Stack  |
   *        +--------+
        sp->+--------+
            |FP regs]|
            +--------+
   *      0 |  a0    |
   *      8 |  a1    |
   *     16 |  a2    |
   *     24 |  a3    |
   *     32 |  a4    |
   *     40 |  a5    |
   *     48 |  a6    |
   *     56 |  a7    |
   *     64 |  t0    |
   *     72 |  t1    |
   *     80 |  t2    |
   *     88 |  t3    |
   *     96 |  t4    |
   *    104 |  t5    |
   *    112 |  t6    |
   *  0/120 |  s2    |   stores fcsr
   *  8/128 |  s3    |   stores frm
   * 16/136 |  s4    |   stores fflags
   * 24/144 |  tp    |
   * 32/152 |  gp    |
   * 40/160 |  s5    |
   * 48/168 |  s6    |
   * 56/176 |  s7    |
   * 64/184 |  s8    |
   * 72/192 |  s9    |
   * 80/200 |  s10   |
   * 88/208 |  s11   |
   *        +--------+   <-- saved by the CC code below this
   * 96/216 |  ra    |   TPC on entry, overwritten
   * 104/224|  s0    |   used for SPC
   * 112/232|  s1    |   copied TPC from ra
   * 120/240| empty  |
   * 128/248| empty  |
   *        +--------+
   */


// Spill values of callee-saved registers which will store some temporary values
  addi sp, sp, -96
  sd s2,  0(sp)
  sd s3,  8(sp)
  sd s4, 16(sp)
  sd tp, 24(sp)
  sd gp, 32(sp)
  sd s5, 40(sp)
  sd s6, 48(sp)
  sd s7, 56(sp)
  sd s8, 64(sp)
  sd s9, 72(sp)
  sd s10, 80(sp)
  sd s11, 88(sp)


  frcsr   s2
  frrm    s3
  frflags s4
  mv s1,  ra // ra has the TPC and we'll need it later, but we have to call other functions

  // Spill all the a and t caller-saved registers
  jal     ra,  push_caller_saved_registers
  addi sp, sp, -24
  sd a0,  0(sp)
  sd a1,  8(sp)
  sd a2, 16(sp)

  // int syscall_handler_pre(uintptr_t syscall_no, uintptr_t *args, uint16_t *next_inst (return SPC), dbm_thread *thread_data)
  // ret 0 -> skip the syscall
  mv a0, a7
  mv a1, sp
  mv a2, s0
  lla a3, disp_thread_data
  ld  a3, (a3)
  lla a4, syscall_handler_pre_addr
  ld  a4, (a4)

  // Load the MAMBO runtime tp and gp
  ld  tp, (a3) // mambo_tp is the first value in a dbm_thread
  lla gp, mambo_gp_addr
  ld  gp, (gp)
  ld  gp, (gp)

  // Spill the floating point registers
  jal     ra,  push_fp

  jalr a4
  beqz a0, skip_syscall // if ret == 0, MAMBO has emulated the syscall and we can return directly

  // load the syscall arguments
  ld a0,  0+FP_FRAME_SZ(sp)
  ld a1,  8+FP_FRAME_SZ(sp)
  ld a2, 16+FP_FRAME_SZ(sp)
  ld a3, 24+FP_FRAME_SZ(sp)
  ld a4, 32+FP_FRAME_SZ(sp)
  ld a5, 40+FP_FRAME_SZ(sp)
  ld a6, 48+FP_FRAME_SZ(sp)
  ld a7, 56+FP_FRAME_SZ(sp)

  ecall

  // store the returned value(s)
  sd a0, 0+FP_FRAME_SZ(sp)
  sd a1, 8+FP_FRAME_SZ(sp)

  // void syscall_handler_post(uintptr_t syscall_no, uintptr_t *args, uint16_t *next_inst, dbm_thread *thread_data)
  mv a0, a7
  mv a1, sp
  mv a2, s0
  lla a3, disp_thread_data
  ld  a3, (a3)
  lla a4, syscall_handler_post_addr
  ld  a4, (a4)

  jalr a4

skip_syscall:
  jal     ra,  pop_fp

  // store a0 and a1 at the bottom of the stack frame
  ld a0, 0(sp)
  ld a1, 8(sp)
  sd a0, 240(sp)
  sd a1, 248(sp)

  // restore the remaining general purpose registers
  ld a2, 16(sp)
  addi sp, sp, 24
  jal ra, pop_caller_saved_registers

  // restore the status registers
  fscsr   s2
  fsrm    s3
  fsflags s4

  // prepare the TPC
  mv a0, s1

  // restore the other values stored at the bottom of the stack frame
  ld s2,  0(sp)
  ld s3,  8(sp)
  ld s4, 16(sp)
  ld tp, 24(sp)
  ld gp, 32(sp)
  ld s5, 40(sp)
  ld s6, 48(sp)
  ld s7, 56(sp)
  ld s8, 64(sp)
  ld s9, 72(sp)
  ld s10, 80(sp)
  ld s11, 88(sp)
  ld ra, 96(sp)
  ld s0, 104(sp)
  ld s1, 112(sp)
  addi sp, sp, 120
  jr a0
syscall_handler_pre_addr: .quad syscall_handler_pre
syscall_handler_post_addr: .quad syscall_handler_post

.global disp_thread_data
.global th_is_pending_ptr
#if   __riscv_xlen == 32
disp_thread_data:  .word 0
th_is_pending_ptr: .word 0
#elif __riscv_xlen == 64
disp_thread_data:  .quad 0
th_is_pending_ptr: .quad 0
#endif

.global end_of_dispatcher_s
end_of_dispatcher_s:
