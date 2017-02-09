/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2017 Cosmin Gorgovan <cosmin at linux-geek dot org>

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

#define ELF_CLASS  ELFCLASS32
#define EM_MACHINE EM_ARM
#define ELF_EHDR   Elf32_Ehdr
#define ELF_PHDR   Elf32_Phdr
#define ELF_GETEHDR(...) elf32_getehdr(__VA_ARGS__)
#define ELF_GETPHDR(...) elf32_getphdr(__VA_ARGS__)
#define ELF_AUXV_T Elf32_auxv_t

int load_elf(char *filename, Elf **ret_elf, int *has_interp, uintptr_t *auxv_phdr, size_t *phnum);
void elf_run(uintptr_t entry_address, uintptr_t orig_entry_addr, char *filename, uintptr_t auxv_phdr, size_t phnum, int argc, char **argv, char **envp);

