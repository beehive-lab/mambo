/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2017-2020 The University of Manchester

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

#include <pthread.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "hash_table.h"

int mambo_ht_init(mambo_ht_t *ht, size_t initial_size, int index_shift, int fill_factor, bool allow_resize) {
  if (fill_factor < 10 || fill_factor > 90) return -1;
  if (index_shift < 0 || index_shift > 20) return -1;

  // Round up the size to a power of 2
  size_t size = 1;
  while (size < initial_size) size <<= 1;

  int ret = pthread_mutex_init(&ht->lock, NULL);
  if (ret != 0) return -1;

  ht->entries = calloc(size, sizeof(mambo_ht_entry_t));
  if (ht->entries == NULL) return -1;

  ht->entry_count = 0;
  ht->size = size;
  ht->allow_resize = allow_resize;
  ht->fill_factor = fill_factor;
  ht->index_shift = index_shift;
  ht->resize_threshold = (ht->size * ht->fill_factor) / 100;

  return 0;
}

void __mambo_ht_lock(mambo_ht_t *ht) {
  int ret = pthread_mutex_lock(&ht->lock);
  assert(ret == 0);
}

void __mambo_ht_unlock(mambo_ht_t *ht) {
  int ret = pthread_mutex_unlock(&ht->lock);
  assert(ret == 0);
}

int __mambo_ht_resize(mambo_ht_t *ht) {
  mambo_ht_entry_t *prev_entries = ht->entries;
  size_t prev_size = ht->size;

  size_t new_size = ht->size << 1;
  mambo_ht_entry_t *new_entries = calloc(new_size, sizeof(mambo_ht_entry_t));
  if (new_entries == NULL) return -1;
 
  ht->entries = new_entries;
  ht->entry_count = 0;
  ht->size = new_size;
  ht->resize_threshold = ht->size * ht->fill_factor / 100;

  for (size_t i = 0; i < prev_size; i++) {
    if (prev_entries[i].key != 0) {
      int ret = mambo_ht_add_nolock(ht, prev_entries[i].key, prev_entries[i].value);
      assert(ret == 0);
    }
  }
}

int mambo_ht_add_nolock(mambo_ht_t *ht, uintptr_t key, uintptr_t value) {
  if (key == 0) return -1;

  if (ht->entry_count >= ht->resize_threshold) {
    if (ht->allow_resize) {
      __mambo_ht_resize(ht);
    } else {
      return -1;
    }
  }

  size_t index_max = (ht->size - 1);
  size_t index = (key >> ht->index_shift) & index_max;

  while (ht->entries[index].key != 0 && ht->entries[index].key != key) {
    index = (index + 1) & index_max;
  }
  if (ht->entries[index].key == 0) {
    ht->entry_count++;
  }
  ht->entries[index].key = key;
  ht->entries[index].value = value;

  return 0;
}

int mambo_ht_add(mambo_ht_t *ht, uintptr_t key, uintptr_t value) {
  __mambo_ht_lock(ht);
  int ret = mambo_ht_add_nolock(ht, key, value);
  __mambo_ht_unlock(ht);
  return ret;
}

int mambo_ht_get_nolock(mambo_ht_t *ht, uintptr_t key, uintptr_t *value) {
  if (key == 0) return -1;

  size_t index_max = (ht->size - 1);
  size_t index = (key >> ht->index_shift) & index_max;
  while (ht->entries[index].key != 0 && ht->entries[index].key != key) {
    index = (index + 1) & index_max;
  }
  if (ht->entries[index].key == key) {
    *value = ht->entries[index].value;
    return 0;
  }
  return -1;
}

int mambo_ht_get(mambo_ht_t *ht, uintptr_t key, uintptr_t *value) {
  __mambo_ht_lock(ht);
  int ret = mambo_ht_get_nolock(ht, key, value);
  __mambo_ht_unlock(ht);
  return ret;
}

int mambo_ht_delete_nolock(mambo_ht_t *ht, uintptr_t key) {
  
}
