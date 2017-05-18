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
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>
#include <asm/unistd.h>

#ifdef __arm__
#include "../pie/pie-arm-encoder.h"
#elif __aarch64__
#include "../pie/pie-a64-encoder.h"
#endif
#include "../scanner_public.h"

#define PAGESZ   4096

#ifdef __arm__
  #define push(reg) arm_push_reg(reg);
  #define pop(reg) arm_pop_reg(reg);
  #define reg_svc_no r7
  #define mov(wptr, rd, rn) arm_mov(&wptr, 0, 0, rd, rn);
  #define movi(wptr, rd, imm) arm_mov(&wptr, 1, 0, rd, imm);
  #define svc(wptr) arm_svc(&wptr, 0);
  #define return_inst(wptr) arm_bx(&wptr, lr);
#elif __aarch64__
  #define push(reg)
  #define pop(reg)
  #define r0 x0
  #define r1 x1
  #define r2 x2
  #define reg_svc_no x8
  #define mov(wptr, rd, rn) a64_logical_reg(&write_p, 1, 1, 0, 0, rn, 0, xzr, rd);
  #define movi(wptr, rd, imm) a64_MOV_wide(&wptr, 1, 2, 0, imm, rd);
  #define svc(wptr) a64_SVC (&wptr, 0);
  #define return_inst(wptr) a64_RET(&wptr, lr);
#else
  #error Unknown architecture
#endif

typedef void (*jit_f)(char *, size_t);
jit_f our_f;
int ready = 0;

void generate_print(uint32_t *write_p) {
  push(reg_svc_no);
  mov(write_p, r2, r1);
  write_p++;
  mov(write_p, r1, r0);
  write_p++;
  movi(write_p, r0, 1);
  write_p++;
  movi(write_p, reg_svc_no, __NR_write);
  write_p++;
  svc(write_p);
  write_p++;
  pop(reg_svc_no);
  return_inst(write_p);
}

void generate_empty(uint32_t *write_p) {
  return_inst(write_p);
}

void dispatcher(char *string) {
  our_f(string, strlen(string));
}

void *compiler_thread(void *alloc) {
  generate_print(alloc);
  __clear_cache(alloc, alloc + PAGESZ);
  ready = 1;
}

int main() {
  void *alloc = mmap(NULL, PAGESZ, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(alloc != MAP_FAILED);
  our_f = (jit_f)alloc;

  generate_print(alloc);
  __clear_cache(alloc, alloc + PAGESZ);
  dispatcher("This should be printed\n");

  generate_empty(alloc);
  __clear_cache(alloc, alloc + PAGESZ);
  dispatcher("This shouldn't be printed\n");

  pthread_t thread;
  pthread_create(&thread, NULL, compiler_thread, alloc);

  while(!ready);
  asm volatile("isb");
  dispatcher("This should also be printed\n");
}
