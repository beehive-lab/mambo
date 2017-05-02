/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2017 Cosmin Gorgovan <cosmin at linux-geek dot org>

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

#include <stdint.h>
#include <stdbool.h>

typedef uint64_t addr_t;

typedef enum {
  REPLACE_RANDOM,
  REPLACE_LRU,
} cachesim_policy;

typedef struct {
  addr_t tag;
  uint64_t timestamp;
} cachesim_model_line_t;

typedef struct {
  uint64_t references[2];
  uint64_t misses[2];
  uint64_t writebacks[2];
} cachesim_stats_t;

typedef struct cachesim_model cachesim_model_t;
#define CACHESIM_NAME_LEN 20
struct cachesim_model {
  char name[CACHESIM_NAME_LEN];
  unsigned size;
  unsigned line_size;
  unsigned assoc;
  cachesim_policy replacement_policy;

  unsigned sets;
  unsigned set_shift;
  unsigned set_mask;
  unsigned tag_shift;

  pthread_mutex_t mutex;

  cachesim_model_t *parent;
  cachesim_stats_t stats;
  cachesim_model_line_t *lines;
};

int cachesim_model_init(cachesim_model_t *cache, char *name, unsigned size, 
                        unsigned line_size, unsigned assoc, cachesim_policy repl_policy);
void cachesim_model_free(cachesim_model_t *cache);
int cachesim_ref(cachesim_model_t *cache, addr_t addr, unsigned size, bool is_write);
void cachesim_print_stats(cachesim_model_t *cache);
