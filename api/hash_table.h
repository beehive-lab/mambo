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

int mambo_ht_init(mambo_ht_t *ht, size_t initial_size, int index_shift, int fill_factor, bool allow_resize);
int mambo_ht_add_nolock(mambo_ht_t *ht, uintptr_t key, uintptr_t value);
int mambo_ht_add(mambo_ht_t *ht, uintptr_t key, uintptr_t value);
int mambo_ht_get_nolock(mambo_ht_t *ht, uintptr_t key, uintptr_t *value);
int mambo_ht_get(mambo_ht_t *ht, uintptr_t key, uintptr_t *value);
