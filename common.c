/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2017 Cosmin Gorgovan <cosmin at linux-geek dot org>

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

#include "common.h"
#include "scanner_public.h"

#define DEBUG 1
//#undef DEBUG
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
  int prev_index;
  bool done = false;
  
  do {
    if (table->entries[index].key == 0 || table->entries[index].key == key) {
      table->entries[index].key = key;
      table->entries[index].value = value;
      table->count++;
      done = true;
    } else {
      prev_index = index;
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


/* Other useful functions*/
#define first_reg r0
#define last_reg pc

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

int get_n_regs(uint32_t reglist, uint32_t *regs, int n) {
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

int count_bits(uint32_t n) {
  int c;
  for (c = 0; n; c++) 
    n &= n - 1;
  return c;
}

// Used to avoid calling stdlib's memcpy implementation which overwrites NEON regs
void mambo_memcpy(void *dst, void *src, ssize_t l) {
  char *d = (char *)dst;
  char *s = (char *)src;
  for (int i = 0; i < l; i++) {
    d[i] = s[i];
  }
}

