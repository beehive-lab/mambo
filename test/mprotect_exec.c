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

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <sys/mman.h>
#include <errno.h>

#define PAGESZ   4096
#define BASEADDR 0x80000

int main() {
  int ret;

  printf("main()\n");

  // One page allocation
  void *alloc = mmap((void *)BASEADDR, PAGESZ, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  assert(alloc != MAP_FAILED);

  // No actual change
  ret = mprotect(alloc, PAGESZ, PROT_READ);
  assert(ret == 0);

  // Make executable
  ret = mprotect(alloc, PAGESZ, PROT_READ | PROT_EXEC);
  assert(ret == 0);

  // Not executable
  ret = mprotect(alloc, PAGESZ, PROT_NONE);
  assert(ret == 0);

  void *large_alloc = mmap((void *)BASEADDR + PAGESZ, PAGESZ*10, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  assert(large_alloc != MAP_FAILED);

  // Make the first page executable
  ret = mprotect(alloc, PAGESZ, PROT_READ | PROT_EXEC);
  assert(ret == 0);

  // Make the third page executable
  ret = mprotect(alloc + PAGESZ*2, PAGESZ, PROT_READ | PROT_EXEC);
  assert(ret == 0);

  // Make the fifth page executable
  ret = mprotect(alloc + PAGESZ*4, PAGESZ, PROT_READ | PROT_EXEC);
  assert(ret == 0);

  // Make the first six pages executable
  ret = mprotect(alloc, PAGESZ*6, PROT_READ | PROT_EXEC);
  assert(ret == 0);

  // Execute-only - should fail
  ret = mprotect(alloc, PAGESZ, PROT_EXEC);
  assert(ret == 0);
}
