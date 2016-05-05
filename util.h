/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>

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

#ifndef __DBM_UTIL_H__
#define __DBM_UTIL_H__

extern void dbm_client_entry(uint32_t addr, uint32_t *stack_top);
extern void dbm_thread_exit(uint32_t *args);
extern void dbm_aquire_lock(uint32_t *lock);
extern void dbm_release_lock(uint32_t *lock);

#endif

