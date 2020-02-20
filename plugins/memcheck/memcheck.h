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

#define COMPACT_SHADOW 1

/* ignore invalid accesses from a whitelist of instructions found in glibc functions
   known to perform safe (aligned) out-of-bounds reads for performance optimisation
   may lead to false negatives */
//#define MC_IGNORE_LIST 1

/* replace the standard library functions known to have glibc implementations that
   perform safe (aligned) out-of-bounds reads for performance reasons
   the replacement implementations are naive - may affect application performance */
#define MC_REPLACE_FNS 1

/* ignore errors in the dynamic loader
   some distributions seem to ship stripped linker executables, which means that we
   can't hook their embedded stdlib functions, so we'll get some false positive errors
   as the dynamic loader sets up
   this options will cause memcheck to ignore all invalid accesses in the loader */
#define MC_IGNORE_INTERP 1

#ifdef COMPACT_SHADOW
  #define SHADOW_SIZE (RESERVED_BASE/8)
#else
  #define SHADOW_SIZE (RESERVED_BASE*2)
  #ifdef __arm__
    #error Uncompacted shadow memory not supported on AArch32
  #endif
#endif

#define VDSO_SIZE     (PAGE_SIZE*2)
#ifdef __aarch64__
  #define RESERVED_BASE 0x4000000000 // 256 GiB
  #define RESERVED_TOP  (vdso_base - PAGE_SIZE)
  #define INITIAL_RES_SIZE (0x1000000000) // 64 GiB
#elif __arm__
  #define RESERVED_BASE 0x80000000
  #define INITIAL_RES_SIZE (128*1024*1024)
#endif

