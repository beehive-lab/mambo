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

/* Defined as a multiple of <native register width> (i.e. 4 bytes on AArch32
   and 8 bytes on AArch64), not bytes
*/
#ifdef __arm__
  /* SP decremented twice +
     14 regs pushed by the SVC translation
  */
  #define SYSCALL_WRAPPER_STACK_OFFSET (2 + 14)
  #define SYSCALL_WRAPPER_FRAME_SIZE   (SYSCALL_WRAPPER_STACK_OFFSET)
#elif __aarch64__
  /* 2  regs(x29, x30) pushed by the SVC translation
     2  (TPC, SVC) +
     22 (X0-X21) +
     (32*2) NEON/FP registers saved in the wrapper
  */
  #define SYSCALL_WRAPPER_STACK_OFFSET (2 + 2 + 22)
  #define SYSCALL_WRAPPER_FRAME_SIZE   (SYSCALL_WRAPPER_STACK_OFFSET + 2*32)
#endif
