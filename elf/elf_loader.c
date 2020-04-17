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

#include <stdlib.h>
#include <stdio.h>
#include <libelf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>

#include "elf_loader.h"
#include "../dbm.h"
#include "../common.h"

#ifndef AT_MINSIGSTKSZ
  #define AT_MINSIGSTKSZ 51
#endif

#define DEBUG 1
#undef DEBUG
#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

extern void *__ehdr_start;

void load_segment(uintptr_t base_addr, ELF_PHDR *phdr, int fd, Elf32_Half type, bool is_interp) {
  uint32_t *mem;
  int prot = 0;
  unsigned long pos;
  uintptr_t aligned_vaddr, aligned_fsize, aligned_msize, page_offset, map_file_end;

  /*if (phdr->p_flags & PF_X) {
    prot |= PROT_EXEC;
  }*/

  if (phdr->p_flags & PF_W) {
    prot |= PROT_WRITE;
  }

  if (phdr->p_flags & PF_R) {
    prot |= PROT_READ;
  }

  if (type == ET_DYN) {
    assert(base_addr != 0);
    phdr->p_vaddr += base_addr;
  }

  aligned_vaddr = align_lower(phdr->p_vaddr, PAGE_SIZE);
  page_offset = phdr->p_vaddr - aligned_vaddr;
  aligned_fsize = align_higher(phdr->p_filesz + page_offset, PAGE_SIZE);
  map_file_end = phdr->p_vaddr + phdr->p_filesz;
  aligned_msize = align_higher(phdr->p_memsz + page_offset, PAGE_SIZE);

  // Map a page-aligned file-backed segment including the (vaddr, vaddr + filesize) area
  #define MAP_EL_FILE (MAP_PRIVATE|MAP_FIXED)
  off_t offset = phdr->p_offset - page_offset;
  mem = mmap((void *)aligned_vaddr, aligned_fsize, prot,
             MAP_EL_FILE, fd, offset);
  assert(mem != MAP_FAILED);
  int flags = MAP_EL_FILE|(is_interp ? MAP_INTERP : MAP_APP);
  notify_vm_op(VM_MAP, aligned_vaddr, aligned_fsize,
               prot | ((phdr->p_flags & PF_X) ? PROT_EXEC : 0), flags, fd, offset);

  // Zero the area from (vaddr + filesize) to the end of the page
  if (phdr->p_flags & PF_W) {
    memset((void *)map_file_end, 0, (aligned_vaddr + aligned_fsize) - map_file_end);
  }

  // Allocate anonymous pages if aligned memsize > filesize
  #define MAP_EL_ANON (MAP_ANONYMOUS|MAP_EL_FILE)
  if (aligned_msize > aligned_fsize) {
    mem = mmap((void *)(aligned_vaddr + aligned_fsize), aligned_msize-aligned_fsize, prot,
               MAP_EL_ANON, -1, 0);
    assert(mem != MAP_FAILED);
    notify_vm_op(VM_MAP, aligned_vaddr + aligned_fsize, aligned_msize-aligned_fsize,
                 prot | ((phdr->p_flags & PF_X) ? PROT_EXEC : 0), MAP_EL_ANON, -1, 0);
  }

  /*
  if (phdr->p_flags & PF_X) {
    __clear_cache((char *)phdr->p_vaddr, (char *)phdr->p_vaddr + (char *)phdr->p_memsz);
  }
  */

  if (!is_interp && (aligned_vaddr + aligned_msize) > global_data.brk) {
    global_data.brk = aligned_vaddr + aligned_msize;
  }
}

int load_elf(char *filename, Elf **ret_elf, struct elf_loader_auxv *auxv, uintptr_t *entry_addr, bool is_interp) {
  int fd;
  FILE *file;
  Elf *elf;
  Elf_Kind kind;
  ELF_EHDR *ehdr;
  ELF_PHDR *phdr;
  char interp[256];
  errno = 0;
  char *tmpmem;
  size_t phnum;

  fd = open(filename, O_RDONLY);
  if (fd < 0) {
    printf("Couldn't open file %s\n", filename);
    exit(EXIT_FAILURE);
  }
  
  if (elf_version(EV_CURRENT) == EV_NONE) {
    printf("Error setting ELF version\n");
    exit(EXIT_FAILURE);
  }
  
  elf = elf_begin(fd, ELF_C_READ, NULL);
  *ret_elf = elf;
  if (elf == NULL) {
    printf("Error opening ELF file: %s: %s\n", filename, elf_errmsg(-1));
    exit(EXIT_FAILURE);
  }
  
  kind = elf_kind(elf);
  if (kind != ELF_K_ELF) {
    printf("File %s isn't an ELF file\n", filename);
    exit(EXIT_FAILURE);
  }
  
  ehdr = ELF_GETEHDR(elf);
  if (ehdr == NULL) {
    printf("Error reading the ELF executable header: %s\n", elf_errmsg(-1));
    exit(EXIT_FAILURE);
  }
  
  if (ehdr->e_ident[EI_CLASS] != ELF_CLASS) {
    printf("Not a 32-bit ELF file\n");
    exit(EXIT_FAILURE);
  }

  if (ehdr->e_machine != EM_MACHINE) {
    printf("Not compiled for ARM\n");
    exit(EXIT_FAILURE);
  }

  file = fdopen(fd, "r");

  elf_getphdrnum(elf, &phnum);
  phdr = ELF_GETPHDR(elf);

  /* Allocate the whole memory region, using ASLR if enabled in the kernel */
  void *base_addr = NULL;
  uintptr_t min_addr = UINTPTR_MAX;
  uintptr_t max_addr = 0;

  for (int i = 0; i < phnum; i++) {
    if (phdr[i].p_type == PT_LOAD) {
      uintptr_t end = phdr[i].p_vaddr + phdr[i].p_memsz;
      if (end > max_addr) {
        max_addr = end;
      }
      if (phdr[i].p_vaddr < min_addr) {
        min_addr = phdr[i].p_vaddr;
      }
    }
  }

  if (ehdr->e_type == ET_DYN) {
    assert(min_addr == 0);
  } else {
    assert(min_addr != 0);
  }

  base_addr = mmap((void *)min_addr, max_addr - min_addr, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  if (ehdr->e_type == ET_DYN) {
    assert(base_addr != MAP_FAILED);
    ehdr->e_entry += (uintptr_t)base_addr;
  } else {
    assert(base_addr == (void*)min_addr);
  }

  /* entry address is the actual execution entry point, either in the interpreter
     (if one is used), or in the executable */
  *entry_addr = ehdr->e_entry;

  // AT_ENTRY in the AUXV points to the original executable
  if (!is_interp) {
    auxv->at_entry = ehdr->e_entry;
  }

  // Look for an INTERP header
  for (int i = 0; i < phnum; i++) {
    if (phdr[i].p_type == PT_INTERP) {
      debug("INTERP field found\n");
      assert(!is_interp);
      
      if (phdr[i].p_filesz > 255) {
        printf("INTERP filename longer than the buffer\n");
        while(1);
      }
      
      if (fseek(file, phdr[i].p_offset, SEEK_SET) != 0) {
        printf("Seek to INTERP field failed");
        while(1);
      }
      
      if(fread(interp, sizeof(char), phdr[i].p_filesz, file) != phdr[i].p_filesz) {
        printf("Failed reading INTERP string\n");
        while(1);
      }
      interp[phdr[i].p_filesz] = '\0';
      
      load_elf(interp, ret_elf, auxv, entry_addr, true);
    }
  }

  if (is_interp) {
    auxv->at_base = 0;
  } else {
    auxv->at_phdr = 0;
    auxv->at_phnum = phnum;
  }

  for (int i = 0; i < phnum; i++) {
    debug("\np_type: 0x%x\n", phdr[i].p_type);
    debug("p_offset: 0x%x\n", phdr[i].p_offset);
    debug("p_vaddr: 0x%x\n", phdr[i].p_vaddr);
    debug("p_paddr: 0x%x\n", phdr[i].p_paddr);
    debug("p_filesz: 0x%x\n", phdr[i].p_filesz);
    debug("p_memsz: 0x%x\n", phdr[i].p_memsz);
    debug("p_flags: 0x%x\n", phdr[i].p_flags);
    debug("p_align: 0x%x\n", phdr[i].p_align);
    
    switch(phdr[i].p_type) {
      case PT_LOAD:
        load_segment((uintptr_t)base_addr, &phdr[i], fd, ehdr->e_type, is_interp);
        if (is_interp) {
          if (phdr[i].p_offset == 0) {
            auxv->at_base = phdr[i].p_vaddr;
          }
        } else { // !is_interp
          if (phdr[i].p_offset == 0) {
            auxv->at_phdr = phdr[i].p_vaddr + ehdr->e_phoff;
          }
        }
        break;
      default:
        debug("Unhandled program header table entry type\n");
        break;
    }
  }

  if (is_interp) {
    assert(auxv->at_base);
  } else { // !is_interp
    assert(auxv->at_phdr);
  }
}

size_t find_stack_data_size(char *filename, int argc, char **argv, char **envp) {
  size_t size = (4 + argc) * sizeof(uintptr_t); // ARGC, ARGV[0], NULL after ARGs and ENVP
  size += 16; // AT_RANDOM
  size += strlen(filename) + 1;

  for (int i = 0; i < argc; i++) {
    size += strlen(argv[i]) + 1;
  }

  for (; *envp != NULL; envp++) {
    size += sizeof(uintptr_t) + strlen(*envp) + 1;
  }

  ELF_AUXV_T *s_aux = (ELF_AUXV_T *)(envp + 1);
  while(s_aux->a_type != AT_NULL) {
    switch(s_aux->a_type) {
      case AT_PLATFORM:
      case AT_EXECFN: {
        char *s = (char *)s_aux->a_un.a_val;
        size += strlen(s) + 1;
      }
    } // switch
    size += sizeof(*s_aux);
    s_aux++;
  } // while
  size += sizeof(*s_aux);

  return size;
}

char *copy_string_to_stack(char *string, char **stack_strings) {
  size_t len = strlen(string) + 1;
  *stack_strings -= len;
  strncpy(*stack_strings, string, len);
  return *stack_strings;
}

#define INITIAL_STACK_SIZE (2*1024*1024)
#define STACK_PROT  (PROT_READ | PROT_WRITE)
#define STACK_FLAGS (MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN|MAP_STACK)
#define stack_push(val) stack[stack_i++] = (val);

void elf_run(uintptr_t entry_address, char *filename, int argc, char **argv, char **envp, struct elf_loader_auxv *auxv) {
  // Allocate a new stack for the execution of the application
  void *stack_space = mmap(NULL, INITIAL_STACK_SIZE, STACK_PROT, STACK_FLAGS, -1, 0);
  assert(stack_space != MAP_FAILED);
  notify_vm_op(VM_MAP, (uintptr_t)stack_space, INITIAL_STACK_SIZE, STACK_PROT, STACK_FLAGS, -1, 0);

  // Grows up (towards lower addresses)
  char *stack_strings = stack_space + INITIAL_STACK_SIZE;

  // Grows down (towards higher addresses)
  size_t data_size = find_stack_data_size(filename, argc, argv, envp);
  uintptr_t *stack = (uintptr_t *)align_lower((uintptr_t)(stack_space + INITIAL_STACK_SIZE - data_size), 16);
  int stack_i = 0;

  // Copy args
  stack_push(argc + 1);
  stack_push((uintptr_t)copy_string_to_stack(filename, &stack_strings));
  for (int i = 0; i < argc; i++) {
    stack_push((uintptr_t)copy_string_to_stack(argv[i], &stack_strings));
  }
  stack_push((uintptr_t)NULL);
  
  // Copy env
  while (*envp != NULL) {
    stack_push((uintptr_t)copy_string_to_stack(*envp, &stack_strings));
    envp++;
  }
  stack_push((uintptr_t)NULL);
  
  // Copy the Auxiliary Vector
  ELF_AUXV_T *s_aux = (ELF_AUXV_T *)(envp + 1);
  ELF_AUXV_T *d_aux = (ELF_AUXV_T *)&stack[stack_i];
  while(s_aux->a_type != AT_NULL) {
    d_aux->a_type = s_aux->a_type;

    switch(s_aux->a_type) {
      case AT_PAGESZ:
      case AT_HWCAP:
      case AT_HWCAP2:
      case AT_CLKTCK:
      case AT_FLAGS:
      case AT_UID:
      case AT_EUID:
      case AT_GID:
      case AT_EGID:
      case AT_SECURE:
      case AT_SYSINFO_EHDR:
      case AT_MINSIGSTKSZ:
      case AT_PHENT:
        d_aux->a_un.a_val = s_aux->a_un.a_val;
        break;

      case AT_RANDOM: {
        stack_strings -= 15;
        memcpy(stack_strings, (void *)s_aux->a_un.a_val, 16);
        d_aux->a_un.a_val = (uintptr_t)stack_strings;
        stack_strings--;
        break;
      }

      case AT_PLATFORM:
      case AT_EXECFN:
        d_aux->a_un.a_val = (uintptr_t)copy_string_to_stack((char *)s_aux->a_un.a_val, &stack_strings);
        break;

      case AT_BASE:
        d_aux->a_un.a_val = auxv->at_base;
        break;

      case AT_PHDR:
        d_aux->a_un.a_val = auxv->at_phdr;
        break;

      case AT_PHNUM:
        d_aux->a_un.a_val = auxv->at_phnum;
        break;

      case AT_ENTRY:
        d_aux->a_un.a_val = auxv->at_entry;
        break;  

      default:
        #ifdef __arm__
          #define auxv_type "%d"
        #elif __aarch64__
          #define auxv_type "%ld"
        #endif
        printf("Unhandled auxv entry type: " auxv_type "\n", s_aux->a_type);
        exit(EXIT_FAILURE);
        break;
    }
    
    s_aux++;
    d_aux++;

    stack_i += 2;
  }
  // End of list
  d_aux->a_type = AT_NULL;
  d_aux->a_un.a_val = 0;
  stack_i += 2;

  /* Stack:
  sp->argc     [LOW]
      argv[0]
      argv[1]
      ...
      argv[x]
      NULL
      envp[0]
      envp[1]
      ...
      envp[y]
      NULL
      auxv[0]
      auxv[1]
      ...
      auxv[z]  [HIGH]
  */
  assert((char *)&stack[stack_i] <= stack_strings);

  dbm_client_entry(entry_address, &stack[0]);
  
  // If we return here, something is horribly wrong
  while(1);
}
