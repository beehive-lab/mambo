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

/**
 * @file hash_table.h
 */

#ifndef __MAMBO_HASH_TABLE_H__
#define __MAMBO_HASH_TABLE_H__

#include <stdbool.h>

typedef struct {
  uintptr_t key;
  uintptr_t value;
} mambo_ht_entry_t;

typedef struct {
  size_t size;
  size_t entry_count;

  int index_shift;

  bool allow_resize;
  int fill_factor;
  size_t resize_threshold;

  pthread_mutex_t lock;

  mambo_ht_entry_t *entries; 
} mambo_ht_t;

/**
 * @brief Initialises a pre-allocated hash-table.
 *
 * @pre @c index_shift must be within the range [0, 20].
 * @pre @c fill_factor must be within the range [10, 90].
 *
 * @param ht The hash-table to be initialised.
 * @param initial_size The initial size of the hash-table. Will be round up to a
 * power of 2.
 * @param index_shift The number of bits a key is shifted to determine the index in
 * the hash-table where the value belongs.
 * @param fill_factor The percentage of elements relative to the hash-table's
 * size that must be filled, to trigger a hash-table resize.
 * @param allow_resize If true, the hash-table will automatically resize when
 * resize threshold is reached.
 * @return Error code of the hash-table initialisation ( @c 0 for success ).
 */
int mambo_ht_init(mambo_ht_t *ht, size_t initial_size, int index_shift, int fill_factor, bool allow_resize);
int mambo_ht_add_nolock(mambo_ht_t *ht, uintptr_t key, uintptr_t value);

/**
 * @brief Atomically adds a key-value pair to a hash-table.
 *
 * @pre @c key must be greater than 0.
 *
 * @param ht The hash-table to add the key-value pair.
 * @param key The key of the key-value pair. The key can often be an address in
 * the hosted application that can be associated with data stored in @c value.
 * @param value The value of the key-value pair. Could be also used to store a
 * pointer to a more complex data structure.
 * @return 0 on success or -1 on error.
 */
int mambo_ht_add(mambo_ht_t *ht, uintptr_t key, uintptr_t value);
int mambo_ht_get_nolock(mambo_ht_t *ht, uintptr_t key, uintptr_t *value);

/**
 * @brief Atomically returns a value from a key-value pair stored in a
 * hash-table.
 *
 * @pre @c key must be greater than 0.
 * @pre @c value must not be NULL.
 *
 * @param ht The hash-table to retrieve the value from.
 * @param key The key used to locate the value within the hash-table.
 * @param value Pointer where the address of the retrieved value will be stored
 * after this call. Unchanged on error.
 * @return 0 on success or -1 on error.
 */
int mambo_ht_get(mambo_ht_t *ht, uintptr_t key, uintptr_t *value);

#endif