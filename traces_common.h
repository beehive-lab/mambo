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

#ifndef __TRACES_COMMON_H__
#define __TRACES_COMMON_H__

#include <stdint.h>
#include <assert.h>
#include "dbm.h"

#ifdef DBM_TRACES
uintptr_t get_active_trace_spc(dbm_thread *thread_data);
uintptr_t active_trace_lookup_or_scan(dbm_thread *thread_data, uintptr_t target);
uintptr_t active_trace_lookup(dbm_thread *thread_data, uintptr_t target);
int allocate_trace_fragment(dbm_thread *thread_data);

#endif
#endif

