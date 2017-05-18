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
#include <stdint.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/time.h>
#include <setjmp.h>
#include <errno.h>
#ifdef __arm__
#include "../pie/pie-arm-encoder.h"
#elif __aarch64__
#include "../pie/pie-a64-encoder.h"
#endif
#include "../scanner_public.h"

FILE *nulldev;
int count = 0;
sigjmp_buf main_env;
volatile int sig_received = 0;

#define SIGNAL_CNT (100*1000)
#define AS_TEST_ITER (100*1000*1000)

int test_cbz(int count);
int test_tbz(int count);
int test_a32_direct(int count);
int test_a32_indirect(int count);

void sigusr_handler(int i, siginfo_t *info, void *ptr) {
  sig_received++;
  printf("success\n");
}

void alarm_handler(int i, siginfo_t *info, void *ptr) {
  // Here we need a relatively slow function which uses a high number of registers.
  // We call fprintf for convenience.
  fprintf(nulldev, "alarm\n");
  count++;
}

void handle_sync(int i, siginfo_t *info, void *ptr) {
  sig_received++;
  siglongjmp(main_env, 1);
}

#ifdef __arm__
  #define add_inst(wptr) arm_add(&wptr, 1, 0, r0, r0, 1);
  #define return_inst(wptr) arm_bx(&wptr, lr);
#elif __aarch64__
  #define add_inst(wptr) a64_ADD_SUB_immed(&wptr, 1, 0, 0, 0, 1, x0, x0);
  #define return_inst(wptr) a64_RET(&wptr, lr);
#else
  #error Unknown architecture
#endif

// Fill the CC
#define JUNK_CODE_SIZE (8*1024*1024)
void fill_cc() {
  int i;
  uint32_t *code = mmap(NULL, JUNK_CODE_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  assert(code != MAP_FAILED);
  uint32_t *iptr = code;
  for (i = 0; i < ((JUNK_CODE_SIZE / 4) - 1); i++) {
    add_inst(iptr);
    iptr++;
  }
  return_inst(iptr);
  iptr++;
  __clear_cache(code, iptr);

  ((void (*)())code)();

  munmap(code, JUNK_CODE_SIZE);
}

void *signal_parent(void *data) {
  int tid = *(int *)data;
  int pid = syscall(__NR_getpid);
  int ret;

  for (int i = 0; i < SIGNAL_CNT; i++) {
    do {
      ret = syscall(__NR_tgkill, pid, tid, SIGRTMIN);
      usleep((ret == 0) ? 10 : 1000);
    } while (ret != 0 && errno == EAGAIN);

    assert(ret == 0);
  }
}

int main (int argc, char **argv) {
  int ret;

  struct sigaction act;
  act.sa_sigaction = sigusr_handler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO;
  ret = sigaction(SIGUSR1, &act, NULL);
  assert(ret == 0);

  printf("Simple signal handler: ");
  fflush(stdout);
  ret = kill(getpid(), SIGUSR1);
  assert(ret == 0);

  printf("Signal after flushing the code cache: ");
  fflush(stdout);
  fill_cc();
  ret = kill(getpid(), SIGUSR1);
  assert(ret == 0);

  printf("Test sigsuspend: ");
  fflush(stdout);
  sig_received = 0;
  sigset_t blocked_sigs;
  ret = sigfillset(&blocked_sigs);
  assert(ret == 0);
  ret = sigprocmask(SIG_SETMASK, &blocked_sigs, NULL);
  assert(ret == 0);
  ret = sigemptyset(&blocked_sigs);
  assert(ret == 0);
  ret = kill(getpid(), SIGUSR1);
  assert(ret == 0);
  while(sig_received == 0) {
    sigsuspend(&blocked_sigs);
    assert(errno == EINTR);
  }
  ret = sigprocmask(SIG_SETMASK, &blocked_sigs, NULL);
  assert(ret == 0);
  sig_received = 0;

  printf("Test against race conditions between code generation and signals: ");
  fflush(stdout);
  nulldev = fopen("/dev/null", "r+");
  assert(nulldev != NULL);

  act.sa_sigaction = alarm_handler;
  ret = sigaction(SIGALRM, &act, NULL);
  assert(ret == 0);

  struct itimerval it;
  it.it_interval.tv_sec = 0;
  it.it_interval.tv_usec = 100;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 100;

  ret = setitimer(ITIMER_REAL, &it, NULL);
  assert(ret == 0);

  for (int i = 0; i < 40; i++) {
    fill_cc();
  }

  it.it_value.tv_usec = 0;
  ret = setitimer(ITIMER_REAL, &it, NULL);
  assert(ret == 0);
  printf("success\n");

  printf("Test for missed signals: ");
  fflush(stdout);
  count = 0;
  int tid = syscall(__NR_gettid);

  ret = sigaction(SIGRTMIN, &act, NULL);
  assert(ret == 0);

  pthread_t thread;
  pthread_create(&thread, NULL, signal_parent, &tid);
  pthread_join(thread, NULL);
  assert(count == SIGNAL_CNT);
  printf("success\n");

  printf("Test signal handling in fragments containing CB(N)Z: ");
  fflush(stdout);
  pthread_create(&thread, NULL, signal_parent, &tid);
  int64_t count = test_cbz(AS_TEST_ITER);
  pthread_join(thread, NULL);
  assert(count == AS_TEST_ITER/4);
  printf("success\n");

#ifdef __aarch64__
  printf("Test signal handling in fragments containing TB(N)Z: ");
  fflush(stdout);
  pthread_create(&thread, NULL, signal_parent, &tid);
  count = test_tbz(AS_TEST_ITER);
  pthread_join(thread, NULL);
  assert(count == AS_TEST_ITER/4);
  printf("success\n");
#endif

#ifdef __arm__
  printf("Test signal handling in fragments containing A32 conditional branches: ");
  fflush(stdout);
  pthread_create(&thread, NULL, signal_parent, &tid);
  count = test_a32_direct(AS_TEST_ITER);
  pthread_join(thread, NULL);
  assert(count == AS_TEST_ITER/4);
  printf("success\n");

  printf("Test signal handling in fragments containing A32 indirect branches: ");
  fflush(stdout);
  pthread_create(&thread, NULL, signal_parent, &tid);
  count = test_a32_indirect(AS_TEST_ITER);
  pthread_join(thread, NULL);
  assert(count == AS_TEST_ITER/2);
  printf("success\n");
#endif

  printf("Test handling of a synchronous SIGTRAP signal: ");
  fflush(stdout);
  act.sa_sigaction = handle_sync;
  ret = sigaction(SIGTRAP, &act, NULL);
  assert(ret == 0);

  ret = sigsetjmp(main_env, 1);
  if (ret == 0) {
#ifdef __arm__
    asm volatile ("bkpt 0");
#elif __aarch64__
    asm volatile ("brk 0");
#else
    #error Unsupported architecture
#endif
  }
  assert(sig_received == 1);
  printf("success\n");

  printf("Test handling of a synchronous SIGILL signal: ");
  fflush(stdout);
  ret = sigaction(SIGILL, &act, NULL);
  assert(ret == 0);

  ret = sigsetjmp(main_env, 1);
  if (ret == 0) {
#ifdef __arm__
    asm volatile ("udf");
#elif __aarch64__
    asm volatile ("hvc 0");
#else
    #error Unsupported architecture
#endif
  }
  assert(sig_received == 2);
  printf("success\n");

  printf("Test receiving SIGILL when no handler is installed\n");
  act.sa_handler = SIG_DFL;
  ret = sigaction(SIGILL, &act, NULL);
#ifdef __arm__
    asm volatile ("udf");
#elif __aarch64__
    asm volatile ("hvc 0");
#else
    #error Unsupported architecture
#endif
}
