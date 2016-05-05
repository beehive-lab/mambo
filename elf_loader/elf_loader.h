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

#define DYN_OBJ_OFFSET 0xa0000000

int load_elf(char *filename, Elf **ret_elf, int *has_interp, uint32_t *auxv_phdr, uint32_t *phnum);
void elf_run(uint32_t entry_address, uint32_t orig_entry_addr, char *filename, uint32_t auxv_phdr, uint32_t phnum, int argc, char **argv, char **envp);

