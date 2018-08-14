/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
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

#ifndef __DBM_UTIL_H__
#define __DBM_UTIL_H__

extern void dbm_client_entry(uintptr_t addr, uintptr_t *stack_top);
extern uint32_t atomic_increment_u32(uint32_t *loc, uint32_t inc);
extern uint64_t atomic_increment_u64(uint64_t *loc, uint64_t inc);
extern int32_t atomic_decrement_if_positive_i32(int32_t *loc, int32_t inc);

static inline int32_t atomic_increment_i32(int32_t *loc, int32_t inc) {
  return (int32_t)atomic_increment_u32((uint32_t *)loc, (uint32_t)inc);
}
static inline int64_t atomic_increment_i64(int64_t *loc, int64_t inc) {
  return (int64_t)atomic_increment_u64((uint64_t *)loc, (uint64_t)inc);
}
#ifdef __arm__
  #define atomic_increment_uptr(loc, inc) atomic_increment_u32(loc, inc);
#elif __aarch64__
  #define atomic_increment_uptr(loc, inc) atomic_increment_u64(loc, inc);
#endif
#define atomic_increment_int(loc, inc) atomic_increment_i32(loc, inc);
#define atomic_increment_uint(loc, inc) atomic_increment_u32(loc, inc);

// syscall() without errno handling
extern uintptr_t raw_syscall(long number, ...);
void signal_trampoline(int i, siginfo_t *, void *);

void safe_fcall_trampoline();
void *new_thread_trampoline();
void return_with_sp(void *sp);
#endif

