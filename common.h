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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdlib.h>

#define CODE_CACHE_HASH_SIZE 0x7FFFF//14071
#define CODE_CACHE_HASH_OVERP 10

/* Warning, size MUST be (a power of 2) */
#ifdef __arm__
#define GET_INDEX(key) ((key) & (table->size - CODE_CACHE_HASH_OVERP))
#endif
#ifdef __aarch64__
#define GET_INDEX(key) ((key >> 2) & (table->size - CODE_CACHE_HASH_OVERP))
#endif
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
  uintptr_t data;
};
typedef struct ll_entry_s ll_entry;

typedef struct {
  ll_entry *free_list;
  int size;
  ll_entry pool[];
} ll;

typedef struct {
  uintptr_t start;
  uintptr_t end;
  int fd;
} interval_map_entry;

typedef struct {
  ssize_t mem_size;
  ssize_t entry_count;
  pthread_mutex_t mutex;
  interval_map_entry *entries;
} interval_map;

bool hash_add(hash_table *table, uintptr_t key, uintptr_t value);
void hash_delete(hash_table *table, uintptr_t key);
uintptr_t hash_lookup(hash_table *table, uintptr_t key);
void hash_init(hash_table *table, int size);

void linked_list_init(ll *list, int size);
ll_entry *linked_list_alloc(ll *list);

int interval_map_init(interval_map *imap, ssize_t size);
int interval_map_add(interval_map *imap, uintptr_t start, size_t len, int fd);
ssize_t interval_map_search(interval_map *imap, uintptr_t start, size_t len);
int interval_map_search_by_addr(interval_map *imap, uintptr_t addr, interval_map_entry *entry);
ssize_t interval_map_delete(interval_map *imap, uintptr_t start, size_t len);

uint32_t next_reg_in_list(uint32_t reglist, uint32_t start);
uint32_t last_reg_in_list(uint32_t reglist, uint32_t start);
int get_lowest_n_regs(uint32_t reglist, uint32_t *regs, int n);
int get_highest_n_regs(uint32_t reglist, uint32_t *regs, int n);
int count_bits(uint32_t n);
int try_memcpy(void *dst, void *src, size_t n);

static inline uintptr_t align_lower(uintptr_t address, uintptr_t alignment) {
  uintptr_t aligned_address = address / alignment * alignment;

  return aligned_address;
}

static inline uintptr_t align_higher(uintptr_t address, uintptr_t alignment) {
  uintptr_t aligned_address = align_lower(address, alignment);
  if (aligned_address != address) {
    aligned_address += alignment;
  }

  return aligned_address;
}

static inline bool is_offset_within_range(intptr_t const offset, intptr_t const range) {
  return ((offset <= (range - 4)) && (offset >= (- range)));
}
#endif
