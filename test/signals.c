#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#ifdef __arm__
#include "../pie/pie-arm-encoder.h"
#elif __aarch64__
#include "../pie/pie-a64-encoder.h"
#endif
#include "../scanner_public.h"

FILE *nulldev;
int count = 0;

void sigusr_handler(int i, siginfo_t *info, void *ptr) {
  printf("success\n");
}

void alarm_handler(int i, siginfo_t *info, void *ptr) {
  // Here we need a relatively slow function which uses a high number of registers.
  // We call fprintf for convenience.
  fprintf(nulldev, "alarm\n");
  count++;
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
#define JUNK_CODE_SIZE (10*1024*1024)
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

int main (int argc, char **argv) {
  int ret;

  struct sigaction act;
  act.sa_sigaction = sigusr_handler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO;
  ret = sigaction(SIGUSR1, &act, NULL);
  assert(ret == 0);

  printf("Simple signal handler: ");
  ret = kill(getpid(), SIGUSR1);
  assert(ret == 0);
  printf("Back to main()\n");

  printf("Signal after flushing the code cache: ");
  fill_cc();
  ret = kill(getpid(), SIGUSR1);
  assert(ret == 0);
  printf("Back to main()\n");

  printf("Test against race conditions between code generation and signals:\n");
  nulldev = fopen("/dev/null", "r+");
  assert(nulldev != NULL);

  act.sa_sigaction = alarm_handler;
  ret = sigaction(SIGALRM, &act, NULL);
  assert(ret == 0);

  struct itimerval it;
  it.it_interval.tv_sec = 0;
  it.it_interval.tv_usec = 10;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 10;

  ret = setitimer(ITIMER_REAL, &it, NULL);
  assert(ret == 0);

  for (int i = 0; i < 40; i++) {
    fill_cc();
  }

  it.it_value.tv_usec = 0;
  ret = setitimer(ITIMER_REAL, &it, NULL);
  assert(ret == 0);
  printf("Test completed succesfully\n");
  printf("Sig handler count: %d\n", count);
}
