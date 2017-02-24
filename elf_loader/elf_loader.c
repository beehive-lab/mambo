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

#define DEBUG 1
#undef DEBUG
#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

extern void *_start;

#define STARTUP_STACK_LEN 200

struct startup_stack {
  uintptr_t e[STARTUP_STACK_LEN];
};

void load_segment(ELF_PHDR *phdr, int fd, Elf32_Half type, uintptr_t *auxv_phdr) {
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

  // Warning: no ASLR here
  if (type == ET_DYN) {
    phdr->p_vaddr += DYN_OBJ_OFFSET;
  }

  aligned_vaddr = align_lower(phdr->p_vaddr, PAGE_SIZE);
  page_offset = phdr->p_vaddr - aligned_vaddr;
  aligned_fsize = align_higher(phdr->p_filesz + page_offset, PAGE_SIZE);
  map_file_end = phdr->p_vaddr + phdr->p_filesz;
  aligned_msize = align_higher(phdr->p_memsz + page_offset, PAGE_SIZE);

  // Map a page-aligned file-backed segment including the (vaddr, vaddr + filesize) area
  mem = mmap((void *)aligned_vaddr, aligned_fsize, prot,
             MAP_PRIVATE|MAP_FIXED, fd, phdr->p_offset - page_offset);
  assert(mem != MAP_FAILED);

  // Zero the area from (vaddr + filesize) to the end of the page
  if (phdr->p_flags & PF_W) {
    memset((void *)map_file_end, 0, (aligned_vaddr + aligned_fsize) - map_file_end);
  }

  // Allocate anonymous pages if aligned memsize > filesize
  if (aligned_msize > aligned_fsize) {
    mem = mmap((void *)(aligned_vaddr + aligned_fsize), aligned_msize-aligned_fsize, prot,
               MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    assert(mem != MAP_FAILED);
  }
  /*
  if (phdr->p_flags & PF_X) {
    __clear_cache((char *)phdr->p_vaddr, (char *)phdr->p_vaddr + (char *)phdr->p_memsz);
  }
  */

  if (phdr->p_offset == 0) {
    *auxv_phdr = (uint32_t)phdr->p_vaddr;
  }
}

//void main(int argc, char **argv, char **envp) {
int load_elf(char *filename, Elf **ret_elf, int *has_interp, uintptr_t *auxv_phdr, size_t *phnum) {
  int fd;
  FILE *file;
  Elf *elf;
  Elf_Kind kind;
  ELF_EHDR *ehdr;
  ELF_PHDR *phdr;
  char interp[256];
  *auxv_phdr = 0;
  errno = 0;
  char *tmpmem;
  
  // Reserve the area below MAMBO's image for the application. libelf uses the heap.
  tmpmem = mmap((void *)0x8000, ((uintptr_t)&_start-0x8000) & (~0x7FFF), PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
  assert(tmpmem !=  MAP_FAILED);

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
  
  debug("Entry address: 0x%x\n", ehdr->e_entry);
  
  file = fdopen(fd, "r");
  
  elf_getphdrnum(elf, phnum);
  phdr = ELF_GETPHDR(elf);

  munmap(tmpmem, ((uintptr_t)&_start-0x8000) & (~0x7FFF));
  
  // Look for an INTERP header
  for (int i = 0; i < *phnum; i++) {
    if (phdr[i].p_type == PT_INTERP) {
      debug("INTERP field found\n");
      
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
      *has_interp = 1;
      
      return load_elf(interp, ret_elf, has_interp, auxv_phdr, phnum);
    }
  }
  
  for (int i = 0; i < *phnum; i++) {
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
        load_segment(&phdr[i], fd, ehdr->e_type, auxv_phdr);
        break;
      default:
        debug("Unhandled program header table entry type\n");
        break;
    }
  }
  
  if (*auxv_phdr == 0) {
    fprintf(stderr, "PHDR not loaded in memory?\n");
    while(1);
  }
  *auxv_phdr += ehdr->e_phoff;
}

#define stack_push(val) \
  stack->e[stack_i++] = (val); \
  assert(stack_i < STARTUP_STACK_LEN) \

void elf_run(uintptr_t entry_address, uintptr_t orig_entry_addr, char *filename, uintptr_t auxv_phdr, size_t phnum, int argc, char **argv, char **envp) {
  // alloca is required, otherwise our translated stack can get optimised away
  struct startup_stack *stack = alloca(sizeof(struct startup_stack));
  int stack_i = 0;

  // Copy args
  stack_push(argc + 1);
  stack_push((uintptr_t)filename);
  for (int i = 0; i < argc; i++) {
    stack_push((uintptr_t)argv[i]);
  }
  stack_push((uintptr_t)NULL);
  
  // Copy env
  while (*envp != NULL) {
    stack_push((uintptr_t)*envp);
    envp++;
  }
  stack_push((uintptr_t)NULL);
  
  // Copy the Auxiliary Vector
  ELF_AUXV_T *s_aux = (ELF_AUXV_T *)(envp + 1);
  ELF_AUXV_T *d_aux = (ELF_AUXV_T *)&stack->e[stack_i];
  while(s_aux->a_type != AT_NULL) {
    switch(s_aux->a_type) {
      case AT_PAGESZ:
      case AT_HWCAP:
      case AT_HWCAP2:
      case AT_CLKTCK:
      case AT_BASE:
      case AT_FLAGS:
      case AT_UID:
      case AT_EUID:
      case AT_GID:
      case AT_EGID:
      case AT_SECURE:
      case AT_RANDOM:
      case AT_PLATFORM:
      case AT_SYSINFO_EHDR:
        d_aux->a_type = s_aux->a_type;
        d_aux->a_un.a_val = s_aux->a_un.a_val;
        break;

      case AT_PHDR:
        d_aux->a_type = s_aux->a_type;
        d_aux->a_un.a_val = auxv_phdr;
        break;
        
      case AT_PHNUM:
        d_aux->a_type = s_aux->a_type;
        d_aux->a_un.a_val = phnum;
        break;

      case AT_PHENT:
        d_aux->a_type = s_aux->a_type;
        d_aux->a_un.a_val = s_aux->a_un.a_val;
        break;

      case AT_ENTRY:
        d_aux->a_type = s_aux->a_type;
        d_aux->a_un.a_val = orig_entry_addr;
        break;  
  
      case AT_EXECFN:
        d_aux->a_type = s_aux->a_type;
        d_aux->a_un.a_val = (uintptr_t)filename;
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
    assert(stack_i < STARTUP_STACK_LEN);
  }
  // End of list
  d_aux->a_type = AT_NULL;
  d_aux->a_un.a_val = 0;
  
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
  
  dbm_client_entry(entry_address, &stack->e[0]);
  
  // If we return here, something is horribly wrong
  while(1);
}
