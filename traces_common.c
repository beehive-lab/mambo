/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo
  Copyright 2022 The University of Manchester
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

#include "traces_common.h"

#ifdef DBM_TRACES

uintptr_t get_active_trace_spc(dbm_thread *thread_data) {
  int bb_id = thread_data->active_trace.source_bb;
  return (uintptr_t)thread_data->code_cache_meta[bb_id].source_addr;
}

uintptr_t active_trace_lookup_or_scan(dbm_thread *thread_data, uintptr_t target) {
  uintptr_t spc = get_active_trace_spc(thread_data);
  if (target == spc) {
    return adjust_cc_entry(thread_data->active_trace.entry_addr);
  }
  return lookup_or_scan(thread_data, target);
}

uintptr_t active_trace_lookup(dbm_thread *thread_data, uintptr_t target) {
  uintptr_t spc = get_active_trace_spc(thread_data);
  if (target == spc) {
    return adjust_cc_entry(thread_data->active_trace.entry_addr);
  }
  uintptr_t return_tpc = hash_lookup(&thread_data->entry_address, target);
  if (return_tpc >= (uintptr_t)thread_data->code_cache->traces)
    return adjust_cc_entry(return_tpc);
  return UINT_MAX;
}

int allocate_trace_fragment(dbm_thread *thread_data) {
  int id = thread_data->active_trace.id++;
  assert(id < (CODE_CACHE_SIZE + TRACE_FRAGMENT_NO));
  return id;
}

#endif
