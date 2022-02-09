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

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <ucontext.h>

#include "dbm.h"
#include "common.h"
#include "scanner_public.h"

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

/* Hash table */

// Breaks linear probing, don't use
void hash_delete(hash_table *table, uintptr_t key) {
  assert(false);
  int index = GET_INDEX(key);
  int end = index - 1;
  bool found = false;
  uintptr_t c_key;
  
  do {
    c_key = table->entries[index].key;
    if (c_key == key) {
      table->entries[index].key = 0;
      found = true;
    } else {
      index = (index + 1) & table->size;
    }
  } while(!found && index != end && c_key != 0);
}

/* To simplify the inline hash lookup code, we avoid looping around for linear probing.
   A few slots are overprovisioned at the end of the table and the last one is reserved
   empty to mark the end of the structure. */
uintptr_t hash_lookup(hash_table *table, uintptr_t key) {
  int index = GET_INDEX(key);
  bool found = false;
  uintptr_t entry = UINT_MAX;
  uintptr_t c_key;
  
  do {
    c_key = table->entries[index].key;
    if (c_key == key) {
      entry = table->entries[index].value;
      found = true;
    } else {
      index++;
    }
  } while(!found && index < (table->size - 1) && c_key != 0);
  
  return entry;
}

bool hash_add(hash_table *table, uintptr_t key, uintptr_t value) {
  int index = GET_INDEX(key);
  bool done = false;
  
  do {
    if (table->entries[index].key == 0 || table->entries[index].key == key) {
      if (table->entries[index].key == 0) {
        table->count++;
      }
      table->entries[index].key = key;
      table->entries[index].value = value;
      done = true;
    } else {
      index++;
      if (index >= table->size -1) {
        fprintf(stderr, "Hash table index overflow\n");
        while(1);
      }
      table->collisions++;
    }
  } while(!done && index < (table->size - 1));
  
  return done;
}

void hash_init(hash_table *table, int size) {
  table->size = size;
  table->collisions = 0;
  table->count = 0;
  for (int i = size-1; i >= 0; i--) {
    table->entries[i].key = 0;
  }
}


/* Linked list */
void linked_list_init(ll *list, int size) {
  assert(size >= 1);
  list->size = size;
  list->free_list = &list->pool[0];
  
  for (int i = 0; i < size-1; i++) {
    list->pool[i].next = &list->pool[i+1];
  }
  
  list->pool[size-1].next = NULL;
}

ll_entry *linked_list_alloc(ll *list) {
  if (list->free_list == NULL) return NULL;
  
  ll_entry *entry = list->free_list;
  list->free_list = entry->next;
  entry->next = NULL;
  
  return entry;
}

/* Interval map */
/* Private interval_map functions; obtain lock before calling */
void interval_map_print(interval_map *imap) {
  fprintf(stderr, "imap %p:\n", imap);
  for (ssize_t i = 0; i < imap->entry_count; i++) {
    fprintf(stderr, "  %"PRIxPTR" - %"PRIxPTR"\n",
            imap->entries[i].start, imap->entries[i].end);
  }
}

int interval_map_delete_entry(interval_map *imap, ssize_t index) {
  if (index < 0 || index >= imap->entry_count) {
    return -1;
  }

  if (imap->entries[index].fd >= 0) {
    close(imap->entries[index].fd);
  }
  if (imap->entry_count >= 2) {
    imap->entries[index] = imap->entries[imap->entry_count - 1];
  }
  imap->entry_count--;
  return 0;
}

int interval_map_add_entry(interval_map *imap, uintptr_t start, uintptr_t end, int fd) {
  if (imap->entry_count >= imap->mem_size || start >= end) {
    return -1;
  }
  ssize_t index = imap->entry_count++;

  imap->entries[index].start = start;
  imap->entries[index].end = end;
  imap->entries[index].fd = fd;

  return 0;
}

/* Public interval_map functions */
int interval_map_init(interval_map *imap, ssize_t size) {
  assert(size > 0);
  interval_map_entry *entries = malloc(sizeof(interval_map_entry) * size);
  if (entries == NULL) return -1;

  imap->mem_size = size;
  imap->entry_count = 0;
  imap->entries = entries;
  int ret = pthread_mutex_init(&imap->mutex, NULL);
  if (ret != 0 && ret != EBUSY) {
    return -1;
  }

  return 0;
}

int interval_map_add(interval_map *imap, uintptr_t start, uintptr_t end, int fd) {
  int ret;
  ssize_t overlap_ind = -1;

  if (start >= end) return -1;

  if (fd >= 0) {
    fd = dup(fd);
    assert(fd >= 0);
  }

  ret = pthread_mutex_lock(&imap->mutex);
  if (ret != 0) return -1;

  // Check for overlapping regions
  for (ssize_t i = imap->entry_count -1; i >= 0; i--) {
    if ((start < imap->entries[i].end) && (end > imap->entries[i].start)) {
      assert(fd < 0 && imap->entries[i].fd < 0);
      if (overlap_ind == -1) {
        overlap_ind = i;
      } else {
        start = min(imap->entries[i].start, start);
        end = max(imap->entries[i].end, end);
        ret = interval_map_delete_entry(imap, i);
        assert(ret == 0);
      }
      imap->entries[overlap_ind].start = min(imap->entries[overlap_ind].start, start);
      imap->entries[overlap_ind].end = max(imap->entries[overlap_ind].end, end);
    }
  }

  // No overlapping region found
  if (overlap_ind == -1) {
    ret = interval_map_add_entry(imap, start, end, fd);
    assert(ret == 0);
  }

#ifdef DEBUG
  fprintf(stderr, "imap added: %"PRIxPTR" %"PRIxPTR"\n", start, end);
  interval_map_print(imap);
#endif

  ret = pthread_mutex_unlock(&imap->mutex);
  if (ret != 0) return -1;

  return 0;
}

ssize_t interval_map_search(interval_map *imap, uintptr_t start, uintptr_t end) {
  int ret;
  ssize_t status = 0;

  if (start >= end) return -1;

  ret = pthread_mutex_lock(&imap->mutex);
  if (ret != 0) return -1;

  for (ssize_t i = imap->entry_count - 1; i >= 0; i--) {
    if ((start < imap->entries[i].end) && (end > imap->entries[i].start)) {
      status++;
    }
  }

  ret = pthread_mutex_unlock(&imap->mutex);
  if (ret != 0) return -1;

  return status;
}

int interval_map_search_by_addr(interval_map *imap, uintptr_t addr, interval_map_entry *entry) {
  bool found = false;

  if (entry == NULL) return -1;

  int ret = pthread_mutex_lock(&imap->mutex);
  if (ret != 0) return -1;

  for (ssize_t i = imap->entry_count - 1; i >= 0 && !found; i--) {
    if ((addr >= imap->entries[i].start) && (addr < imap->entries[i].end)) {
      memcpy(entry, &imap->entries[i], sizeof(*entry));
      found = true;
    }
  }

  ret = pthread_mutex_unlock(&imap->mutex);
  assert(ret == 0);

  return found ? 1 : 0;
}

ssize_t interval_map_delete(interval_map *imap, uintptr_t start, uintptr_t end) {
  ssize_t status = 0;

  if (start >= end) return -1;

  int ret = pthread_mutex_lock(&imap->mutex);
  if (ret != 0) return -1;

  for (ssize_t i = imap->entry_count - 1; i >= 0; i--) {
    if ((start < imap->entries[i].end) && (end > imap->entries[i].start)) {
      status++;

      if (start <= imap->entries[i].start && end >= imap->entries[i].end) {
        ret = interval_map_delete_entry(imap, i);
        assert(ret == 0);
      } else if (start == imap->entries[i].start && end < imap->entries[i].end) {
        imap->entries[i].start = end;
      } else if (end == imap->entries[i].end && start > imap->entries[i].start) {
        imap->entries[i].end = start;
      } else {
        uintptr_t tmp = imap->entries[i].end;
        imap->entries[i].end = start;
        int fd = imap->entries[i].fd;
        if (fd >= 0) {
          fd = dup(fd);
          assert(fd >= 0);
        }
        ret = interval_map_add_entry(imap, end, tmp, fd);
        assert(ret == 0);
      }
    } // if hit
  } // for

#ifdef DEBUG
  if (status > 0) {
    fprintf(stderr, "imap deleted: %"PRIxPTR" %"PRIxPTR"\n", start, end);
    interval_map_print(imap);
  }
#endif

  ret = pthread_mutex_unlock(&imap->mutex);
  if (ret != 0) return -1;

  return status;
}

/* Other useful functions*/
#ifdef __arm__
  #define first_reg r0
  #define last_reg pc
#endif
#ifdef __aarch64__
  #define first_reg x0
  #define last_reg sp
#endif

uint32_t next_reg_in_list(uint32_t reglist, uint32_t start) {
  for (; start <= last_reg; start++) {
    if (reglist & (1 << start)) {
      return start;
     }
   }
   
   return reg_invalid;
}

uint32_t last_reg_in_list(uint32_t reglist, uint32_t start) {
  for (; start >= first_reg; start--) {
    if (reglist & (1 << start)) {
      return start;
     }
   }

   return reg_invalid;
}

int get_lowest_n_regs(uint32_t reglist, uint32_t *regs, int n) {
  int count = 0, prev = -1;
  if (n < 1) return count;

  for (int i = 0; i < n; i++) {
    regs[i] = next_reg_in_list(reglist, prev + 1);
    if (regs[i] < reg_invalid) {
      count++;
    }
    prev = regs[i];
  }

  return count;
}

int get_highest_n_regs(uint32_t reglist, uint32_t *regs, int n) {
  int count = 0, prev = reg_invalid;
  if (n < 1) return count;

  for (int i = 0; i < n; i++) {
    regs[i] = last_reg_in_list(reglist, prev - 1);
    if (regs[i] < reg_invalid) {
      count++;
    }
    prev = regs[i];
  }

  return count;
}

int count_bits(uint32_t n) {
  int c;
  for (c = 0; n; c++) 
    n &= n - 1;
  return c;
}

// Used to avoid calling stdlib's memcpy implementation which overwrites NEON regs
void mambo_memcpy(void *dst, void *src, size_t l) {
  char *d = (char *)dst;
  char *s = (char *)src;
  for (int i = 0; i < l; i++) {
    d[i] = s[i];
  }
}

extern int __try_memcpy(void *dst, const void *src, size_t n);
extern void __try_memcpy_error();

#ifdef __arm__
  #define pc_reg uc_mcontext.arm_pc
#elif __aarch64__
  #define pc_reg uc_mcontext.pc
#endif
void memcpy_fault(int i, siginfo_t *info, void *ctx_ptr) {
  ucontext_t *ctx = (ucontext_t *)ctx_ptr;
  ctx->pc_reg = (uintptr_t)__try_memcpy_error;
}
#undef pc_reg

int try_memcpy(void *dst, void *src, size_t n) {
  struct sigaction act, oldact;
  act.sa_sigaction = memcpy_fault;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO;
  int ret = sigaction(SIGSEGV, &act, &oldact);
  assert(ret == 0);

  int status = __try_memcpy(dst, src, n);

  ret = sigaction(SIGSEGV, &oldact, NULL);
  assert(ret == 0);

  return status;
}
