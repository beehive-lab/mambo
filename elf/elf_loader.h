/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
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

#include <stdbool.h>

#ifdef __arm__
  #define ELF_CLASS  ELFCLASS32
  #define EM_MACHINE EM_ARM
  #define ELF_EHDR   Elf32_Ehdr
  #define ELF_PHDR   Elf32_Phdr
  #define ELF_GETEHDR(...) elf32_getehdr(__VA_ARGS__)
  #define ELF_GETPHDR(...) elf32_getphdr(__VA_ARGS__)
  #define ELF_AUXV_T Elf32_auxv_t
#endif
#ifdef __aarch64__
  #define ELF_CLASS  ELFCLASS64
  #define EM_MACHINE EM_AARCH64
  #define ELF_EHDR   Elf64_Ehdr
  #define ELF_PHDR   Elf64_Phdr
  #define ELF_GETEHDR(...) elf64_getehdr(__VA_ARGS__)
  #define ELF_GETPHDR(...) elf64_getphdr(__VA_ARGS__)
  #define ELF_AUXV_T Elf64_auxv_t
#endif

struct elf_loader_auxv {
  uintptr_t at_base;
  uintptr_t at_entry;
  uintptr_t at_phdr;
  uintptr_t at_phnum;
};

void load_elf(char *filename, Elf **ret_elf, struct elf_loader_auxv *auxv, uintptr_t *entry_addr, bool is_interp);
void elf_run(uintptr_t entry_address, char *filename, int argc, char **argv, char **envp, struct elf_loader_auxv *auxv);

