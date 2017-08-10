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
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>

#ifdef __arm__
#include "../pie/pie-thumb-encoder.h"
#include "../pie/pie-thumb-decoder.h"
#include "../pie/pie-arm-encoder.h"
#include "../pie/pie-arm-decoder.h"
#elif __aarch64__
#include "../pie/pie-a64-encoder.h"
#endif

#define CODE_SIZE  (1024*1024)
#define HEAP_SIZE  (1024*1024)
#define STACK_SIZE (1024*1024)
#define CODE_BASE  ((void *)0x50000000)
#define HEAP_BASE  ((void *)0x60000000)
#define STACK_BASE ((void *)0x70000000)

#define CPSR_T (0x20)

typedef void (*ld_st_test)(void *heap, void *stack);
void *heap, *stack, *code;
uint32_t orig_inst = 0;

#ifdef __arm__
extern void test_thumb16(void *, void *);
extern void *end_test_thumb16;
extern void test_thumb32(void *, void *);
extern void *end_test_thumb32;
extern void test_a32(void *, void *);
extern void *end_test_a32;
#define ucontext_pc uc_mcontext.arm_pc

#elif __aarch64__
extern void test_a64(void *, void *);
extern void *end_test_a64;

#define ucontext_pc uc_mcontext.pc
#endif

void test_wrapper(char *name, ld_st_test test, void* test_end, void *heap, void *stack) {
  uintptr_t test_addr = (uintptr_t)test;
  ld_st_test test_rw = code;
  size_t test_size = test_end - (void *)test + 1;
  assert(test_size <= CODE_SIZE);

#ifdef __arm__
  uintptr_t is_thumb = test_addr & 1;
  test_addr &= ~1;
  test_rw = code + is_thumb;
#endif
  memcpy(code, (void *)test_addr, test_size);
  __clear_cache(code, code + test_size);

  printf("start: %s\n", name);
  test_rw(heap, stack);
  printf("end: %s\n", name);
}

void print_addr_and_retry(int sig, siginfo_t *info, void *c) {
  assert(sig == SIGSEGV);
  ucontext_t *cont = (ucontext_t *)c;
  int ret = mprotect(heap,  HEAP_SIZE, PROT_READ | PROT_WRITE);
  assert(ret == 0);
  ret = mprotect(stack, STACK_SIZE, PROT_READ | PROT_WRITE);
  assert(ret == 0);
#ifdef __arm__
  if (cont->uc_mcontext.arm_cpsr & CPSR_T) {
    uint16_t *bkpt = (uint16_t *)cont->uc_mcontext.arm_pc;
    thumb_instruction inst = thumb_decode(bkpt);
    bkpt += (inst < THUMB_ADC32) ? 1 : 2;
    orig_inst = *(uint32_t *)bkpt;
    thumb_bkpt16(&bkpt, 0);
    __clear_cache(bkpt, bkpt+1);
  } else {
    uint32_t *bkpt = (uint32_t *)cont->uc_mcontext.arm_pc;
    bkpt++;
    orig_inst = *bkpt;
    arm_bkpt(&bkpt, 0, 0);
    __clear_cache(bkpt, bkpt+1);
  }
#elif __aarch64__
  uint32_t *bkpt = (uint32_t *)cont->ucontext_pc;
  bkpt++;
  orig_inst = *bkpt;
  a64_BRK(&bkpt, 0);
  __clear_cache(bkpt, bkpt+1);
#endif
  printf("%p\n", info->si_addr);
}

void remove_breakpoint(int sig, siginfo_t *info, void *c) {
  int ret = mprotect(heap, HEAP_SIZE, PROT_NONE);
  assert(ret == 0);
  ret = mprotect(stack, STACK_SIZE, PROT_NONE);
  assert(ret == 0);

  ucontext_t *cont = (ucontext_t *)c;
  uint32_t *bkpt = (uint32_t *)cont->ucontext_pc;
  *bkpt = orig_inst;
  __clear_cache(bkpt, bkpt+1);

}

int main(int argc, char **argv) {
  bool print_trace = false;
  if (argc >= 2 && strcmp(argv[1], "-t") == 0) {
    print_trace = true;

    // Set up a signal stack
    void *sigstack = mmap(NULL, SIGSTKSZ, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(sigstack != MAP_FAILED);
    
    stack_t ss;
    ss.ss_sp = sigstack;
    ss.ss_flags = 0;
    ss.ss_size = SIGSTKSZ;
    int ret = sigaltstack(&ss, NULL);
    
    // Register the signal handler
    struct sigaction act;
    act.sa_sigaction = print_addr_and_retry;
    act.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&act.sa_mask);
    ret = sigaction(SIGSEGV, &act, NULL);
    assert(ret == 0);
    
    act.sa_sigaction = remove_breakpoint;
    ret = sigaction(SIGTRAP, &act, NULL);
    assert(ret == 0);
  }

  code = mmap(CODE_BASE, CODE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  assert(code != MAP_FAILED);

  heap = mmap(HEAP_BASE, HEAP_SIZE, print_trace ? 0 : (PROT_READ | PROT_WRITE),
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  assert(heap != MAP_FAILED);

  stack = mmap(STACK_BASE, STACK_SIZE, print_trace ? 0 : (PROT_READ | PROT_WRITE),
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  assert(stack != MAP_FAILED);

#ifdef __arm__
  test_wrapper("thumb16", test_thumb16, (void *)&end_test_thumb16,
               heap, stack+STACK_SIZE);
  test_wrapper("thumb32", test_thumb32, (void *)&end_test_thumb32,
               heap, stack+STACK_SIZE);
  test_wrapper("a32", test_a32, (void *)&end_test_a32, heap, stack+STACK_SIZE);
#elif __aarch64__
  test_wrapper("a64", test_a64, (void *)&end_test_a64, heap, stack+STACK_SIZE);
#endif
}
