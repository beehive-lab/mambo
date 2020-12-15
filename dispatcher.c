/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
  Copyright 2015-2017 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
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

#include <stdio.h>
#include <limits.h>

#include "dbm.h"
#include "scanner_common.h"
#ifdef __arm__
#include "pie/pie-thumb-encoder.h"
#include "pie/pie-arm-encoder.h"
#elif __aarch64__
#include "pie/pie-a64-encoder.h"
#endif

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

void dispatcher_aarch32(dbm_thread *thread_data, uint32_t source_index, branch_type exit_type,
                        uintptr_t target, uintptr_t block_address);
void dispatcher_aarch64(dbm_thread *thread_data, uint32_t source_index, branch_type exit_type,
                        uintptr_t target, uintptr_t block_address);

void dispatcher(uintptr_t target, uint32_t source_index, uintptr_t *next_addr, dbm_thread *thread_data) {
  uintptr_t   block_address;
  bool        cached;
  branch_type source_branch_type;

#ifdef __aarch64__
  uint32_t *branch_addr;
#endif // __arch64__

/* It's essential to copy exit_branch_type before calling lookup_or_scan
     because when scanning a stub basic block the source block and its
     meta-information get overwritten */
  debug("Source block index: %d\n", source_index);
  source_branch_type = thread_data->code_cache_meta[source_index].exit_branch_type;

#ifdef DBM_TRACES
  // Handle trace exits separately
  if (source_index >= CODE_CACHE_SIZE) {
#ifdef __arm__
    if (source_branch_type != tbb && source_branch_type != tbh)
#endif
      return trace_dispatcher(target, next_addr, source_index, thread_data);
  }
#endif

  debug("Reached the dispatcher, target: 0x%x, ret: %p, src: %d thr: %p\n", target, next_addr, source_index, thread_data);
  thread_data->was_flushed = false;
  block_address = lookup_or_scan(thread_data, target, &cached);
  if (cached) {
    debug("Found block from %d for 0x%x in cache at 0x%x\n", source_index, target, block_address);
  } else {
    debug("Scanned at 0x%x for 0x%x\n", block_address, target);
  }

  *next_addr = block_address;

  // Bypass any linking
  if (source_index == 0 || thread_data->was_flushed) {
    return;
  }

#ifdef __arm__
  dispatcher_aarch32(thread_data, source_index, source_branch_type, target, block_address);
#endif
#ifdef __aarch64__
  dispatcher_aarch64(thread_data, source_index, source_branch_type, target, block_address);
#endif
}
