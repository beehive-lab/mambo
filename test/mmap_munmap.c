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
#include <assert.h>
#include <sys/mman.h>
#include <errno.h>

#define PAGESZ   4096
#define BASEADDR 0x80000

int main() {
  int ret;

  // Failing allocation
  void *alloc = mmap(NULL, 0, PROT_EXEC | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(alloc == MAP_FAILED);

  // One page allocation
  alloc = mmap(NULL, PAGESZ, PROT_EXEC | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(alloc != MAP_FAILED);

  ret = munmap(alloc, PAGESZ);
  assert (ret == 0);

  // Multiple page allocation, for testing partial unmapping
  alloc = mmap(NULL, PAGESZ*10, PROT_EXEC | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(alloc != MAP_FAILED);

  // Unmap the first page
  ret = munmap(alloc, PAGESZ);
  assert (ret == 0);
  alloc += PAGESZ;

  // Unmap the last page
  ret = munmap(alloc + PAGESZ*8, PAGESZ);
  assert (ret == 0);

  // Unmap the second remaining page
  ret = munmap(alloc + PAGESZ, PAGESZ);
  assert(ret == 0);

  // Map back the second page
  void *alloc2 = mmap(alloc + PAGESZ, PAGESZ, PROT_EXEC | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(alloc2 != MAP_FAILED);
  
  // Unmap the whole region
  ret = munmap(alloc, PAGESZ*8);
  assert(ret == 0);

  return 0;
}
