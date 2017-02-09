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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdlib.h>

#define CODE_CACHE_HASH_SIZE 0x7FFFF//14071
#define CODE_CACHE_HASH_OVERP 10

/* Warning, size MUST be (a power of 2) */
#define GET_INDEX(key) ((key) & (table->size - CODE_CACHE_HASH_OVERP))
typedef struct {
  uintptr_t key;
  uintptr_t value;
} hash_entry;

typedef struct {
  int size;
  int collisions;
  int count;
  hash_entry entries[CODE_CACHE_HASH_SIZE + CODE_CACHE_HASH_OVERP];
} hash_table;

struct ll_entry_s {
  struct ll_entry_s *next;
  uint32_t data;
};
typedef struct ll_entry_s ll_entry;

typedef struct {
  ll_entry *free_list;
  int size;
  ll_entry pool[];
} ll;

bool hash_add(hash_table *table, uintptr_t key, uintptr_t value);
void hash_delete(hash_table *table, uintptr_t key);
uintptr_t hash_lookup(hash_table *table, uintptr_t key);
void hash_init(hash_table *table, int size);

void linked_list_init(ll *list, int size);
ll_entry *linked_list_alloc(ll *list);

uint32_t next_reg_in_list(uint32_t reglist, uint32_t start);
uint32_t last_reg_in_list(uint32_t reglist, uint32_t start);
int get_n_regs(uint32_t reglist, uint32_t *regs, int n);
int count_bits(uint32_t n);
#endif

