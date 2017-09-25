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
#include <inttypes.h>
#include <string.h>
#include <locale.h>
#include <assert.h>
#include <pthread.h>

#include "cachesim_model.h"

#define READ_INDEX 0
#define WRITE_INDEX 1

#define IS_DIRTY 1

static inline bool is_pow2(unsigned int val) {
  return (val & (val -1)) == 0;
}

__attribute__((always_inline))
static inline int cachesim_get_set(cachesim_model_t *cache, addr_t addr) {
  addr_t set = addr >> cache->set_shift;
  return (int)(set & cache->set_mask);
}

__attribute__((always_inline))
static inline addr_t cachesim_get_tag(cachesim_model_t *cache, addr_t addr) {
  return addr >> cache->tag_shift;
}

int cachesim_model_init(cachesim_model_t *cache, char *name, unsigned size,
                        unsigned line_size, unsigned max_fetch, unsigned assoc,
                        cachesim_policy repl_policy) {
  if (size == 0 || line_size == 0 || assoc == 0 ||
      !is_pow2(line_size) || !is_pow2(max_fetch) ||
      (assoc * line_size) > size ||
      (size % (line_size * assoc)) != 0) {
    return -1;
  }

  unsigned sets = cache->sets = size / (line_size * assoc);
  if (!is_pow2(sets)) {
    return -1;
  }

  int ret = pthread_mutex_init(&cache->mutex, NULL);
  if (ret != 0) {
    return -1;
  }

  cache->lines = calloc(sets * assoc, sizeof(cachesim_model_line_t));
  if (cache->lines == NULL) {
    return -1;
  }

  cache->max_fetch = (max_fetch != 0) ? max_fetch : line_size;

  strncpy(cache->name, name, CACHESIM_NAME_LEN);
  cache->name[CACHESIM_NAME_LEN - 1] = '\0';

  cache->size = size;
  cache->line_size = line_size;
  cache->assoc = assoc;
  cache->replacement_policy = repl_policy;

  cache->sets = sets;
  cache->set_shift = __builtin_ctz(line_size);
  cache->set_mask = cache->sets - 1;
  cache->tag_shift = __builtin_ctz(cache->sets) + cache->set_shift;
  cache->max_fetch_shift = __builtin_ctz(cache->max_fetch);

  memset(&cache->stats, 0, sizeof(cache->stats));

  return 0;
}

void cachesim_model_free(cachesim_model_t *cache) {
  if (cache->lines) {
    free(cache->lines);
  }

  pthread_mutex_destroy(&cache->mutex);
}

int cachesim_lock(cachesim_model_t *cache) {
  return pthread_mutex_lock(&cache->mutex);
}

int cachesim_unlock(cachesim_model_t *cache) {
  return pthread_mutex_unlock(&cache->mutex);
}

__attribute__((always_inline))
static inline void cachesim_load_line(cachesim_model_t *cache, int line_index, addr_t addr, bool is_write) {
  if (cache->lines[line_index].tag & 1) {
    int counter_index = is_write ? 1 : 0;
    cache->stats.writebacks[counter_index]++;
  }
  cache->lines[line_index].tag = cachesim_get_tag(cache, addr) << 1;
}

__attribute__((always_inline))
static inline
int cachesim_evict_line(cachesim_model_t *cache, int line_index) {
  int line = -1;

  switch (cache->replacement_policy) {
    case REPLACE_RANDOM:
      line = random() % cache->assoc;
      break;
    case REPLACE_LRU: {
      uint64_t min_timestamp = -1;
      for (int i = 0; i < cache->assoc; i++) {
        if (cache->lines[line_index + i].timestamp < min_timestamp) {
          min_timestamp = cache->lines[line_index + i].timestamp;
          line = i;
        }
      }
      break;
    }
    default:
      printf("Unimplemented cache replacement policy %d\n", cache->replacement_policy);
      exit(EXIT_FAILURE);
  }

  return line;
}

__attribute__((always_inline))
static inline void update_dirty_bit(cachesim_model_t *cache, int line, bool is_write) {
  if (is_write) {
    cache->lines[line].tag |= IS_DIRTY;
  }
}

__attribute__((always_inline))
static inline void update_line(cachesim_model_t *cache, int line, bool is_write) {
  update_dirty_bit(cache, line, is_write);
  cache->lines[line].timestamp = cache->stats.references[0] + cache->stats.references[1];
}

int cachesim_ref(cachesim_model_t *cache, addr_t addr, unsigned size, bool is_write) {
  int counter_index = is_write ? 1 : 0;
  addr_t end = addr + size;

  unsigned mask = cache->max_fetch - 1;
  unsigned offset = (unsigned)addr & mask;
  unsigned t_size = size + offset;
  cache->stats.references[counter_index] += t_size >> cache->max_fetch_shift;
  cache->stats.references[counter_index] += (t_size & mask) ? 1 : 0;

  addr = (addr >> cache->set_shift) << cache->set_shift;
  int line;

  for (; addr < end; addr += cache->line_size) {
    /* If it's the same as the previously used address, we have its cache line cached.
       Also, we don't have to update the timestamp since it's already the highest one
       in the cache. */
    if (addr == cache->last_addr) {
      line = cache->last_line;
      update_dirty_bit(cache, line, is_write);
      continue;
    }

    line = cachesim_get_set(cache, addr) * cache->assoc;
    addr_t tag = cachesim_get_tag(cache, addr);
    bool hit = false;

    /* We keep the MRU tag in the first position of the line.
       We can also avoid updating its timestamp because it's the highest one in this line */
    if ((cache->lines[line].tag >> 1) == tag) {
      update_dirty_bit(cache, line, is_write);
      continue;
    }

    for (int i = 1; i < cache->assoc && !hit; i++) {
      if ((cache->lines[line + i].tag >> 1) == tag) {
        // Move the tag to the first position on the line
        cachesim_model_line_t tmp = cache->lines[line];
        cache->lines[line] = cache->lines[line+i];
        cache->lines[line+i] = tmp;

        hit = true;
      }
    }

    // Miss
    if (!hit) {
      cache->stats.misses[counter_index]++;

      if (cache->parent) {
        int ret = cachesim_lock(cache->parent);
        assert(ret == 0);
        cachesim_ref(cache->parent, addr, cache->line_size, is_write);
        ret = cachesim_unlock(cache->parent);
        assert(ret == 0);
      }

      line += cachesim_evict_line(cache, line);
      cachesim_load_line(cache, line, addr, is_write);
    }

    update_line(cache, line, is_write);
  }

  cache->last_addr = addr;
  cache->last_line = line;

  return 0;
}

void cachesim_print_stats(cachesim_model_t *cache) {
  uint64_t references = cache->stats.references[READ_INDEX] + cache->stats.references[WRITE_INDEX];
  uint64_t misses = cache->stats.misses[READ_INDEX] + cache->stats.misses[WRITE_INDEX];
  uint64_t writebacks = cache->stats.writebacks[READ_INDEX] + cache->stats.writebacks[WRITE_INDEX];
  float rate;
  char *repl;

  switch (cache->replacement_policy) {
    case REPLACE_RANDOM:
      repl = "random";
      break;
    case REPLACE_LRU:
      repl = "LRU";
      break;
  }

  setlocale(LC_NUMERIC, "");

  printf("Cache %s: %'d bytes, %d byte lines, %d-way set-associative, %s replacement policy\n\n",
         cache->name, cache->size, cache->line_size, cache->assoc, repl);
  printf("%'16" PRIu64 " references\n", references);
  printf("%'16" PRIu64 " reads\n", cache->stats.references[READ_INDEX]);
  printf("%'16" PRIu64 " writes\n", cache->stats.references[WRITE_INDEX]);

  rate = (float)misses / (float)references;
  printf("%'16" PRIu64 " misses total       (%.2f%% of references)\n",
         misses, rate * 100.0);
  rate = (float)cache->stats.misses[READ_INDEX] / (float)references;
  printf("%'16" PRIu64 " misses reads       (%.2f%% of references)\n",
         cache->stats.misses[READ_INDEX], rate * 100.0);
  rate = (float)cache->stats.misses[WRITE_INDEX] / (float)references;
  printf("%'16" PRIu64 " misses writes      (%.2f%% of references)\n",
         cache->stats.misses[WRITE_INDEX], rate * 100.0);

  rate = (float)writebacks / (float)references;
  printf("%'16" PRIu64 " writebacks total   (%.2f%% of references)\n",
         writebacks, rate * 100.0);
  rate = (float)cache->stats.writebacks[READ_INDEX] / (float)references;
  printf("%'16" PRIu64 " writebacks reads   (%.2f%% of references)\n",
         cache->stats.writebacks[READ_INDEX], rate * 100.0);
  rate = (float)cache->stats.writebacks[WRITE_INDEX] / (float)references;
  printf("%'16" PRIu64 " writebacks writes  (%.2f%% of references)\n\n",
         cache->stats.writebacks[WRITE_INDEX], rate * 100.0);
}
