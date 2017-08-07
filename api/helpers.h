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

#ifndef __API_HELPERS_H__
#define __API_HELPERS_H__

typedef struct {
  void *loc;
} mambo_branch;

#define LSL 0
#define LSR 1
#define ASR 2

#ifdef __arm__
  #define MAX_FCALL_ARGS 4
#elif __aarch64__
  #define MAX_FCALL_ARGS 8
#endif

void emit_counter64_incr(mambo_context *ctx, void *counter, unsigned incr);
void emit_push(mambo_context *ctx, uint32_t regs);
void emit_pop(mambo_context *ctx, uint32_t regs);
void emit_set_reg(mambo_context *ctx, enum reg reg, uintptr_t value);
void emit_fcall(mambo_context *ctx, void *function_ptr);
int emit_safe_fcall(mambo_context *ctx, void *function_ptr, int argno);
int emit_safe_fcall_static_args(mambo_context *ctx, void *fptr, int argno, ...);
int emit_indirect_branch_by_spc(mambo_context *ctx, enum reg reg);

void emit_mov(mambo_context *ctx, enum reg rd, enum reg rn);
int emit_add_sub_i(mambo_context *ctx, int rd, int rn, int offset);
int emit_add_sub_shift(mambo_context *ctx, int rd, int rn, int rm,
                       unsigned int shift_type, unsigned int shift);
int emit_add_sub(mambo_context *ctx, int rd, int rn, int rm);
int mambo_calc_ld_st_addr(mambo_context *ctx, enum reg reg);

int emit_branch(mambo_context *ctx, void *target);
int emit_branch_cond(mambo_context *ctx, void *target, mambo_cond cond);
int emit_branch_cbz_cbnz(mambo_context *ctx, void *target, enum reg reg, bool is_cbz);
int emit_branch_cbz(mambo_context *ctx, void *target, enum reg reg);
int emit_branch_cbnz(mambo_context *ctx, void *target, enum reg reg);

int mambo_reserve_branch(mambo_context *ctx, mambo_branch *br);
int mambo_reserve_branch_cbz(mambo_context *ctx, mambo_branch *br);

int emit_local_branch_cond(mambo_context *ctx, mambo_branch *br, mambo_cond cond);
int emit_local_branch(mambo_context *ctx, mambo_branch *br);
int emit_local_fcall(mambo_context *ctx, mambo_branch *br);
int emit_local_branch_cbz_cbnz(mambo_context *ctx, mambo_branch *br, enum reg reg, bool is_cbz);
int emit_local_branch_cbz(mambo_context *ctx, mambo_branch *br, enum reg reg);
int emit_local_branch_cbnz(mambo_context *ctx, mambo_branch *br, enum reg reg);

static inline void emit_set_reg_ptr(mambo_context *ctx, enum reg reg, void *ptr) {
  emit_set_reg(ctx, reg, (uintptr_t)ptr);
}

#ifdef __arm__
#define ROR 3
void emit_thumb_push_cpsr(mambo_context *ctx, enum reg reg);
void emit_arm_push_cpsr(mambo_context *ctx, enum reg reg);
void emit_thumb_pop_cpsr(mambo_context *ctx, enum reg reg);
void emit_arm_pop_cpsr(mambo_context *ctx, enum reg reg);
void emit_thumb_copy_to_reg_32bit(mambo_context *ctx, enum reg reg, uint32_t value);
void emit_arm_copy_to_reg_32bit(mambo_context *ctx, enum reg reg, uint32_t value);
void emit_thumb_b16_cond(void *write_p, void *target, mambo_cond cond);
void emit_thumb_push(mambo_context *ctx, uint32_t regs);
void emit_arm_push(mambo_context *ctx, uint32_t regs);
void emit_thumb_pop(mambo_context *ctx, uint32_t regs);
void emit_arm_pop(mambo_context *ctx, uint32_t regs);
void emit_thumb_fcall(mambo_context *ctx, void *function_ptr);
void emit_arm_fcall(mambo_context *ctx, void *function_ptr);
static inline int emit_arm_add_sub_shift(mambo_context *ctx, int rd, int rn, int rm,
                                         unsigned int shift_type, unsigned int shift);
static inline int emit_thumb_add_sub_shift(mambo_context *ctx, int rd, int rn, int rm,
                                           unsigned int shift_type, unsigned int shift);
static inline int emit_arm_add_sub(mambo_context *ctx, int rd, int rn, int rm);
static inline int emit_thumb_add_sub(mambo_context *ctx, int rd, int rn, int rm);
#endif

#ifdef __aarch64__
void emit_a64_push(mambo_context *ctx, uint32_t regs);
void emit_a64_pop(mambo_context *ctx, uint32_t regs);
static inline int emit_a64_add_sub_shift(mambo_context *ctx, int rd, int rn, int rm,
                                   unsigned int shift_type, unsigned int shift);
static inline int emit_a64_add_sub(mambo_context *ctx, int rd, int rn, int rm);
int emit_a64_add_sub_ext(mambo_context *ctx, int rd, int rn, int rm, int ext_option, int shift);
#endif

#endif
