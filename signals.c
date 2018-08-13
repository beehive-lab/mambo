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

#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <string.h>

#include "dbm.h"
#include "scanner_common.h"
#ifdef __arm__
#include "pie/pie-thumb-encoder.h"
#include "pie/pie-thumb-decoder.h"
#include "pie/pie-thumb-field-decoder.h"
#include "pie/pie-arm-encoder.h"
#include "pie/pie-arm-decoder.h"
#include "pie/pie-arm-field-decoder.h"
#endif
#ifdef __aarch64__
#include "pie/pie-a64-encoder.h"
#include "pie/pie-a64-decoder.h"
#include "pie/pie-a64-field-decoder.h"
#endif

#define self_send_signal_offset        ((uintptr_t)send_self_signal - (uintptr_t)&start_of_dispatcher_s)
#define syscall_wrapper_svc_offset     ((uintptr_t)syscall_wrapper_svc - (uintptr_t)&start_of_dispatcher_s)

#define SIGNAL_TRAP_IB (0x94)
#define SIGNAL_TRAP_DB (0x95)

#ifdef __arm__
  #define pc_field uc_mcontext.arm_pc
  #define sp_field uc_mcontext.arm_sp
#elif __aarch64__
  #define pc_field uc_mcontext.pc
  #define sp_field uc_mcontext.sp
#endif

typedef struct {
  uintptr_t pid;
  uintptr_t tid;
  uintptr_t signo;
} self_signal;

void install_system_sig_handlers() {
  struct sigaction act;
  act.sa_sigaction = signal_trampoline;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO;
  int ret = sigaction(UNLINK_SIGNAL, &act, NULL);
  assert(ret == 0);
}

int deliver_signals(uintptr_t spc, self_signal *s) {
  uint64_t sigmask;

  if (global_data.exit_group) {
    thread_abort(current_thread);
  }

  int ret = syscall(__NR_rt_sigprocmask, 0, NULL, &sigmask, sizeof(sigmask));
  assert (ret == 0);

  for (int i = 0; i < _NSIG; i++) {
    if ((sigmask & (1 << i)) == 0
        && atomic_decrement_if_positive_i32(&current_thread->pending_signals[i], 1) >= 0) {
      s->pid = syscall(__NR_getpid);
      s->tid = syscall(__NR_gettid);
      s->signo = i;
      atomic_increment_u32(&current_thread->is_signal_pending, -1);
      return 1;
    }
  }

  return 0;
}

typedef int (*inst_decoder)(void *);
#ifdef __arm__
  #define inst_size(inst, is_thumb) (((is_thumb) && ((inst) < THUMB_ADC32)) ? 2 : 4)
  #define write_trap(code)  if (is_thumb) { \
                              thumb_udf16((uint16_t **)&write_p, (code)); \
                              write_p += 2; \
                            } else { \
                              arm_udf((uint32_t **)&write_p, (code) >> 4, (code) & 0xF); \
                              write_p += 4; \
                            }
  #define TRAP_INST_TYPE ((is_thumb) ? THUMB_UDF16 : ARM_UDF)
#elif __aarch64__
  #define inst_size(inst, is_thumb) (4)
  #define write_trap(code) a64_HVC((uint32_t **)&write_p, (code)); write_p += 4;
  #define TRAP_INST_TYPE (A64_HVC)
#endif

bool unlink_indirect_branch(dbm_code_cache_meta *bb_meta, void **o_write_p) {
  int br_inst_type, trap_inst_type;
  inst_decoder decoder;
  void *write_p = *o_write_p;
  bool is_thumb = false;
#ifdef __arm__
  if (bb_meta->exit_branch_type == uncond_reg_thumb) {
    is_thumb = true;
    br_inst_type = THUMB_BX16;
    decoder = (inst_decoder)thumb_decode;
  } else if (bb_meta->exit_branch_type == uncond_reg_arm) {
    br_inst_type = ARM_BX;
    decoder = (inst_decoder)arm_decode;
  }
#elif __aarch64__
  br_inst_type = A64_BR;
  decoder = (inst_decoder)a64_decode;
#endif
  trap_inst_type = TRAP_INST_TYPE;

  int inst = decoder(write_p);
  while(inst != br_inst_type && inst != trap_inst_type) {
    write_p += inst_size(inst, is_thumb);
    inst = decoder(write_p);
  }

  if (inst == trap_inst_type) {
    return false;
  }

  write_trap(SIGNAL_TRAP_IB);
  *o_write_p = write_p;
  return true;
}

bool unlink_direct_branch(dbm_code_cache_meta *bb_meta, void **o_write_p, int fragment_id, uintptr_t pc) {
  int offset = 0;
  bool is_thumb = false;
  void *write_p = *o_write_p;

  switch(bb_meta->exit_branch_type) {
#ifdef __arm__
    case cond_imm_thumb:
    case cbz_thumb:
      offset = (bb_meta->branch_cache_status & BOTH_LINKED) ? 10 : 6;
      is_thumb = true;
      break;
    case cond_imm_arm:
      offset = (bb_meta->branch_cache_status & BOTH_LINKED) ? 8 : 4;
      break;
#elif __aarch64__
    case uncond_imm_a64:
      offset = 4;
      break;
    case cond_imm_a64:
    case cbz_a64:
    case tbz_a64:
      offset = (bb_meta->branch_cache_status & BOTH_LINKED) ? 12 : 8;
      break;
#endif
    default:
      while(1);
  }

  if (pc < ((uintptr_t)bb_meta->exit_branch_addr + offset)) {
    if (bb_meta->branch_cache_status != 0) {
    inst_decoder decoder;

#ifdef __arm__
      if (is_thumb) {
        decoder = (inst_decoder)thumb_decode;
      } else {
        decoder = (inst_decoder)arm_decode;
      }
#elif __aarch64__
      decoder = (inst_decoder)a64_decode;
#endif
      int inst = decoder(write_p);
      if (inst == TRAP_INST_TYPE) {
        return false;
      }
      for (int i = 0; i < offset; i += inst_size(TRAP_INST_TYPE, is_thumb)) {
        write_trap(SIGNAL_TRAP_DB);
      }
    } // if (bb_meta->branch_cache_status != 0)
  } else {
    /* It's already setting up a call to the dispatcher. Ensure that the
       fragment is not supposed to be linked */
    assert((bb_meta->branch_cache_status & BOTH_LINKED) == 0);
    return false;
  }

  *o_write_p = write_p;
  return true;
}

void unlink_fragment(int fragment_id, uintptr_t pc) {
  dbm_code_cache_meta *bb_meta;

#ifdef DBM_TRACES
  // Skip over trace fragments with elided unconditional branches
  branch_type type;

  do {
    bb_meta = &current_thread->code_cache_meta[fragment_id];
    type = bb_meta->exit_branch_type;
    fragment_id++;
  }
  #ifdef __arm__
  while ((type == uncond_imm_arm || type == uncond_imm_thumb ||
          type == uncond_blxi_thumb || type == uncond_blxi_arm) &&
  #elif __aarch64__
  while (type == uncond_imm_a64 &&
  #endif
         (bb_meta->branch_cache_status & BOTH_LINKED) == 0 &&
         fragment_id >= CODE_CACHE_SIZE &&
         fragment_id < current_thread->active_trace.id);

  fragment_id--;
  // If the fragment isn't installed, make sure it's active
  if (fragment_id >= current_thread->trace_id) {
    assert(current_thread->active_trace.active);
  }
#else
  bb_meta = &current_thread->code_cache_meta[fragment_id];
#endif

  void *write_p = bb_meta->exit_branch_addr;
  void *start_addr = write_p;

#ifdef __arm__
  if (bb_meta->exit_branch_type == uncond_reg_thumb ||
      bb_meta->exit_branch_type == uncond_reg_arm) {
#elif __aarch64__
  if (bb_meta->exit_branch_type == uncond_branch_reg) {
#endif
    if (!unlink_indirect_branch(bb_meta, &write_p)) {
      return;
    }
  } else if (bb_meta->branch_cache_status != 0) {
    if (!unlink_direct_branch(bb_meta, &write_p, fragment_id, pc)) {
      return;
    }
  }

  __clear_cache(start_addr, write_p);
}

void translate_delayed_signal_frame(ucontext_t *cont) {
  uintptr_t *sp = (uintptr_t *)cont->sp_field;
#ifdef __arm__
  /*
         r7
         r1
         r2
         PID
         TID
         SIGNO
         R0
         TPC
         SPC
  */
  cont->uc_mcontext.arm_r7 = sp[0];
  cont->uc_mcontext.arm_r1 = sp[1];
  cont->uc_mcontext.arm_r2 = sp[2];
  cont->uc_mcontext.arm_r0 = sp[6];
  cont->uc_mcontext.arm_pc = sp[8];

  sp += 9;
#elif __aarch64__
  /*
    TPC, SPC
    X2, X8
    X0, X1
  */
  cont->uc_mcontext.regs[x8] = sp[3];
  cont->uc_mcontext.regs[x2] = sp[2];
  cont->uc_mcontext.pc = sp[1];
  cont->uc_mcontext.regs[x0] = sp[4];
  cont->uc_mcontext.regs[x1] = sp[5];
  sp += 6;
#endif

  cont->sp_field = (uintptr_t)sp;
}

void translate_svc_frame(ucontext_t *cont) {
  uintptr_t *sp = (uintptr_t *)cont->sp_field;
#ifdef __arm__
  cont->uc_mcontext.arm_r8  = sp[8];
  cont->uc_mcontext.arm_r9  = sp[9];
  cont->uc_mcontext.arm_r10 = sp[10];
  cont->uc_mcontext.arm_fp  = sp[11];
  cont->uc_mcontext.arm_ip  = sp[12];
  cont->uc_mcontext.arm_lr  = sp[13];
  cont->uc_mcontext.arm_pc  = sp[15];
  sp += 16;
#elif __aarch64__
  #define FPSIMD_SIZE  (0x210)

  assert(cont->uc_mcontext.regs[x8] != __NR_rt_sigreturn);
  struct fpsimd_context *fpstate = (struct fpsimd_context *)&cont->uc_mcontext.__reserved;

  // Set up the FP state first
  assert(fpstate->head.magic == FPSIMD_MAGIC && fpstate->head.size == FPSIMD_SIZE);
  memcpy(fpstate->vregs, sp, sizeof(fpstate->vregs));
  fpstate->fpsr = cont->uc_mcontext.regs[x21];
  fpstate->fpcr = cont->uc_mcontext.regs[x20];
  sp += 512 / sizeof(sp[0]);

  // Now set the general purpose registers  & PSTATE
  cont->uc_mcontext.pstate = cont->uc_mcontext.regs[x19];
  for (int r = 9; r <= 21; r++) {
    cont->uc_mcontext.regs[r] = sp[r];
  }
  cont->uc_mcontext.pc = sp[23];
  cont->uc_mcontext.regs[x29] = sp[24];
  cont->uc_mcontext.regs[x30] = sp[25];
  sp += 26;
#endif
  cont->sp_field = (uintptr_t)sp;
}

#define PSTATE_N (1 << 31)
#define PSTATE_Z (1 << 30)
#define PSTATE_C (1 << 29)
#define PSTATE_V (1 << 28)
bool interpret_condition(uint32_t pstate, mambo_cond cond) {
  assert(cond >= 0 && cond <= 0xF);
  bool state = true;
  switch (cond >> 1) {
    case 0:
      state = pstate & PSTATE_Z;
      break;
    case 1:
      state = pstate & PSTATE_C;
      break;
    case 2:
      state = pstate & PSTATE_N;
      break;
    case 3:
      state = pstate & PSTATE_V;
      break;
    case 4:
      state = (pstate & PSTATE_C) && ((pstate & PSTATE_Z) == 0);
      break;
    case 5:
      state = ((pstate & PSTATE_N) ? true : false) == ((pstate & PSTATE_V) ? true : false);
      break;
    case 6:
      state = ((pstate & PSTATE_N) ? true : false) == ((pstate & PSTATE_V) ? true : false);
      state = state && ((pstate & PSTATE_Z) == 0);
      break;
    case 7:
      state = true;
      break;
  }

  state = state ? true : false;

  if (cond < 14 && (cond & 1)) {
    state = !state;
  }

  return state;
}

#ifdef __aarch64__
bool interpret_cbz(ucontext_t *cont, dbm_code_cache_meta *bb_meta) {
  int reg = (bb_meta->rn) & 0x1F;
  uint64_t val = cont->uc_mcontext.regs[reg];
  if (bb_meta->rn & (1 << 5)) {
    val &= 0xFFFFFFFF;
  }

  return (val == 0) ^ (bb_meta->branch_condition);
}

bool interpret_tbz(ucontext_t *cont, dbm_code_cache_meta *bb_meta) {
  int reg = (bb_meta->rn) & 0x1F;
  int bit = (bb_meta->rn) >> 5;
  bool is_taken = (cont->uc_mcontext.regs[reg] & (1 << bit)) == 0;

  return is_taken ^ bb_meta->branch_condition;
}
#endif

#ifdef __arm__
  #define direct_branch(write_p, target, cond)  if (is_thumb) { \
                                                  thumb_b32_helper((write_p), (target)); \
                                                } else { \
                                                  arm_b32_helper((write_p), (target), cond); \
                                                }
#elif __aarch64__
  #define direct_branch(write_p, target, cond)  a64_b_helper((write_p), (target) + 4);
#endif

#ifdef __arm__
void restore_exit(dbm_thread *thread_data, int fragment_id, void **o_write_p, bool is_thumb) {
#elif __aarch64__
void restore_exit(dbm_thread *thread_data, int fragment_id, void **o_write_p) {
#endif
  uintptr_t target;
  uintptr_t other_target;
  void *write_p = *o_write_p;
  dbm_code_cache_meta *bb_meta = &thread_data->code_cache_meta[fragment_id];
  int cond = bb_meta->branch_condition;

#ifdef __arm__
  if (bb_meta->branch_cache_status & FALLTHROUGH_LINKED) {
#elif __aarch64__
  if (bb_meta->branch_cache_status & BRANCH_LINKED) {
#endif
    cond = invert_cond(cond);
  }
  insert_cond_exit_branch(bb_meta, &write_p, cond);

  if (bb_meta->branch_cache_status & BRANCH_LINKED) {
    target = bb_meta->branch_taken_addr;
    other_target = bb_meta->branch_skipped_addr;
  } else {
    assert((bb_meta->branch_cache_status & 3) == FALLTHROUGH_LINKED);
    target = bb_meta->branch_skipped_addr;
    other_target = bb_meta->branch_taken_addr;
  }
  target = cc_lookup(thread_data, target);
  assert(target != UINT_MAX);
  direct_branch(write_p, target, cond);
  write_p += 4;

  if ((bb_meta->branch_cache_status & BOTH_LINKED) &&
#ifdef __arm__
      bb_meta->exit_branch_type != uncond_imm_thumb &&
      bb_meta->exit_branch_type != uncond_b_to_bl_thumb &&
      bb_meta->exit_branch_type != uncond_imm_arm
#elif __aarch64__
      bb_meta->exit_branch_type != uncond_imm_a64
#endif
  ) {
    target = cc_lookup(thread_data, other_target);
    assert(target != UINT_MAX);
    direct_branch(write_p, target, AL);
    write_p += 4;
  }

  *o_write_p = write_p;
}

void restore_ihl_regs(ucontext_t *cont) {
  uintptr_t *sp = (uintptr_t *)cont->sp_field;

#ifdef __arm__
  cont->context_reg(5) = sp[0];
  cont->context_reg(6) = sp[1];
#elif __aarch64__
  cont->context_reg(0) = sp[0];
  cont->context_reg(1) = sp[1];
#endif
  sp += 2;

  cont->sp_field = (uintptr_t)sp;
}

void sigret_dispatcher_call(dbm_thread *thread_data, ucontext_t *cont, uintptr_t target) {
  uintptr_t *sp = (uintptr_t *)cont->context_sp;

#ifdef __arm__
  sp -= DISP_SP_OFFSET / 4;
#elif __aarch64__
  sp -= 2;
#endif
  sp[0] = cont->context_reg(0);
  sp[1] = cont->context_reg(1);
#ifdef __arm__
  sp[2] = cont->context_reg(2);
  sp[3] = cont->context_reg(3);
#endif
  cont->context_reg(0) = target;
  cont->context_reg(1) = 0;
  cont->context_pc = thread_data->dispatcher_addr;
#ifdef __arm__
  cont->context_reg(3) = cont->context_sp;
  cont->uc_mcontext.arm_cpsr &= ~CPSR_T;
#endif

  cont->context_sp = (uintptr_t)sp;
}

#ifdef __arm__
  #define restore_ihl_inst(addr)  if (is_thumb) { \
                                    thumb_bx16((uint16_t **)&addr, r6); \
                                    __clear_cache((void *)addr, (void *)addr + 2); \
                                  } else { \
                                    arm_bx((uint32_t **)&addr, r6); \
                                    __clear_cache((void *)addr, (void *)addr + 4); \
                                  }

#elif __aarch64__
  #define restore_ihl_inst(addr) a64_BR((uint32_t **)&addr, x0); \
                                __clear_cache((void *)addr, (void *)addr + 4);
#endif

/* If type == indirect && pc >= exit, read the pc and deliver the signal */
/* If pc < <type specific>, unlink the fragment and resume execution */
uintptr_t signal_dispatcher(int i, siginfo_t *info, void *context) {
  uintptr_t handler = 0;
  bool deliver_now = false;

  assert(i >= 0 && i < _NSIG);
  ucontext_t *cont = (ucontext_t *)context;

  uintptr_t pc = (uintptr_t)cont->pc_field;
  uintptr_t cc_start = (uintptr_t)&current_thread->code_cache->blocks[trampolines_size_bbs];
  uintptr_t cc_end = cc_start + MAX_BRANCH_RANGE;

  if (global_data.exit_group > 0) {
    if (pc >= cc_start && pc < cc_end) {
      int fragment_id = addr_to_fragment_id(current_thread, (uintptr_t)pc);
      dbm_code_cache_meta *bb_meta = &current_thread->code_cache_meta[fragment_id];
      if (pc >= (uintptr_t)bb_meta->exit_branch_addr) {
        thread_abort(current_thread);
      }
      unlink_fragment(fragment_id, pc);
    }
    atomic_increment_u32(&current_thread->is_signal_pending, 1);
    return 0;
  }

  if (pc == ((uintptr_t)current_thread->code_cache + self_send_signal_offset)) {
    translate_delayed_signal_frame(cont);
    deliver_now = true;
  } else if (pc == ((uintptr_t)current_thread->code_cache + syscall_wrapper_svc_offset)) {
    translate_svc_frame(cont);
    deliver_now = true;
  }

  if (deliver_now) {
    handler = lookup_or_scan(current_thread, global_data.signal_handlers[i], NULL);
    return handler;
  }

  if (pc >= cc_start && pc < cc_end) {
    int fragment_id = addr_to_fragment_id(current_thread, (uintptr_t)pc);
    dbm_code_cache_meta *bb_meta = &current_thread->code_cache_meta[fragment_id];

    if (pc >= (uintptr_t)bb_meta->exit_branch_addr) {
      void *write_p;

      if (i == UNLINK_SIGNAL) {
        uint32_t imm;
#ifdef __arm__
        bool is_thumb = cont->uc_mcontext.arm_cpsr & CPSR_T;
        if (is_thumb) {
          thumb_udf16_decode_fields((uint16_t *)pc, &imm);
        } else {
          uint32_t imm12, imm4;
          arm_udf_decode_fields((uint32_t *)pc, &imm12, &imm4);
          imm = (imm12 << 4) | imm4;
        }
#elif __aarch64__
        a64_HVC_decode_fields((uint32_t *)pc, &imm);
#endif
        if (imm == SIGNAL_TRAP_IB) {
          restore_ihl_inst(pc);

          int rn = current_thread->code_cache_meta[fragment_id].rn;
          uintptr_t target;
#ifdef __arm__
          unsigned long *regs = &cont->uc_mcontext.arm_r0;
          target = regs[rn];
#elif __aarch64__
          target = cont->uc_mcontext.regs[rn];
#endif
          restore_ihl_regs(cont);
          sigret_dispatcher_call(current_thread, cont, target);
          return 0;
        } else if (imm == SIGNAL_TRAP_DB) {
          write_p = bb_meta->exit_branch_addr;
          void *start_addr = write_p;
#ifdef __arm__
          restore_exit(current_thread, fragment_id, &write_p, is_thumb);
#elif __aarch64__
          restore_exit(current_thread, fragment_id, &write_p);
#endif
          __clear_cache(start_addr, write_p);

          bool is_taken;
          switch(bb_meta->exit_branch_type) {
#ifdef __arm__
            case cond_imm_thumb:
            case cond_imm_arm:
              is_taken = interpret_condition(cont->uc_mcontext.arm_cpsr, bb_meta->branch_condition);
              break;
            case cbz_thumb: {
              unsigned long *regs = &cont->uc_mcontext.arm_r0;
              is_taken = regs[bb_meta->rn] == 0;
              break;
            }
#elif __aarch64__
            case uncond_imm_a64:
              is_taken = true;
              break;
            case cond_imm_a64:
              is_taken = interpret_condition(cont->uc_mcontext.pstate, bb_meta->branch_condition);
              break;
            case cbz_a64:
              is_taken = interpret_cbz(cont, bb_meta);
              break;
            case tbz_a64:
              is_taken = interpret_tbz(cont, bb_meta);
              break;
#endif
            default:
              fprintf(stderr, "Signal: interpreting of %d fragments not implemented\n", bb_meta->exit_branch_type);
              while(1);
          }

          // Set up *sigreturn* to the dispatcher
          sigret_dispatcher_call(current_thread, cont,
                                 is_taken ? bb_meta->branch_taken_addr : bb_meta->branch_skipped_addr);
          return 0;
        } else {
          fprintf(stderr, "Error: unknown MAMBO trap code\n");
          while(1);
        }
      } // i == UNLINK_SIGNAL
    } // if (pc >= (uintptr_t)bb_meta->exit_branch_addr)
    unlink_fragment(fragment_id, pc);
  }

  /* Call the handlers of synchronous signals immediately
     The SPC of the instruction is unknown, so sigreturning to addresses derived
     from the PC value in the signal frame is not supported.
     We mangle the PC in the context to hopefully trap such attempts.
  */
  if (i == SIGSEGV || i == SIGBUS || i == SIGFPE || i == SIGTRAP || i == SIGILL || i == SIGSYS) {
    handler = global_data.signal_handlers[i];

    if (pc < cc_start || pc >= cc_end) {
      fprintf(stderr, "Synchronous signal outside the code cache\n");
      while(1);
    }

    // Check if the application actually has a handler installed for the signal used by MAMBO
    if (handler == (uintptr_t)SIG_IGN || handler == (uintptr_t)SIG_DFL) {
      assert(i == UNLINK_SIGNAL);

      // Remove this handler
      struct sigaction act;
      act.sa_sigaction = (void *)handler;
      sigemptyset(&act.sa_mask);
      int ret = sigaction(i, &act, NULL);
      assert(ret == 0);

      // sigreturn so the same signal is raised again without an installed signal handler
      return 0;
    }

    cont->pc_field = 0;
    handler = lookup_or_scan(current_thread, handler, NULL);
    return handler;
  }

  atomic_increment_int(&current_thread->pending_signals[i], 1);
  atomic_increment_u32(&current_thread->is_signal_pending, 1);

  return handler;
}
