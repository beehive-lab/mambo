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

#ifdef PLUGINS_NEW

#ifdef __aarch64__

#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <locale.h>
#include <inttypes.h>
#include "../plugins.h"
#include "../dbm.h"
#include "../elf/elf_loader.h"
#include <libelf.h>
#include <gelf.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include  <sysexits.h>
#include "../pie/pie-a64-decoder.h"

#ifdef DEBUG
#define debug(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug(...)
#endif

#define NUM_HASH_BUCKETS           16U

typedef struct plt_hash_entry plt_hash_entry;
struct plt_hash_entry {
  struct plt_hash_entry * next;
  Elf64_Addr addr;
  uint64_t call_count;
  char * name;
};

typedef struct plt_list_item plt_list_item;
struct plt_list_item {
  Elf64_Addr plt_addr;
  void* translated_addr;
  uint32_t call_count;
  char * plt_string;
};

typedef struct lct_priv {
  plt_hash_entry ** plt_hash_table;
  plt_list_item ** plt_list;
  char ** plt_string_list;
  Elf64_Addr plt_address_min;
  Elf64_Addr plt_address_max;
  Elf64_Addr plt_size;
  Elf64_Addr text_address;
  Elf64_Addr text_size;
  Elf64_Addr main_address;
} lct_priv_t;

int plt_list_add_entry(mambo_context* ctx, plt_list_item ** list, Elf64_Addr plt_addr, char* str, int str_idx) {
  plt_list_item * list_item = (plt_list_item*) mambo_alloc(ctx, sizeof(plt_list_item));
  if(list_item == NULL) {
    return -1;
  }
  char * str_alloc = (char*) mambo_alloc(ctx, strlen(str)*sizeof(char));
  strcpy(str_alloc, str);
  if(str_alloc == NULL) {
    return -1;
  } else {
    debug("New PLT list entry is %s, it's address is %llx at index %d.\n", str, plt_addr, str_idx);
    list[str_idx] = list_item;
    list_item->plt_addr = plt_addr;
    list_item->call_count = 0;
    list_item->translated_addr = 0;
    list_item->plt_string = str_alloc;
    return 0;
  }
}

uint32_t list_search_by_translated_addr(plt_list_item ** list, Elf64_Addr addr) {
  uint32_t returner = -1;
  uint32_t idx = 0;
  while(list[idx] != 0) {
    if(((Elf64_Addr) list[idx]->translated_addr) == addr) {
      returner = idx;
      break;
    }
    idx++;
  }
  return returner;
}

int plt_string_list_add_entry(mambo_context* ctx, char ** list, char* str, int str_idx) {
  char * str_alloc = (char*) mambo_alloc(ctx, strlen(str)*sizeof(char));
  strcpy(str_alloc, str);
  printf("%s %d string is\n", str, str_idx);
  if(str_alloc == NULL) {
    return -1;
  } else {
    list[str_idx] = str_alloc;
    return 0;
  }
}

void print_plt_string_list(char** list) {
  uint32_t idx = 0;
  while(list[idx] != 0) {
    printf("%s\n", list[idx]);
    idx ++;
  }
}

void print_plt_list_counts(plt_list_item ** list) {
  int idx = 0;
  while(list[idx] != 0) {
    printf("%s was called %x times.\n", list[idx]->plt_string, list[idx]->call_count);
    idx ++;
  }
}

/* This function is needed as PLT structure is architecture dependent, 
so offset may be different if implemented for separate archs. */
uint32_t get_plt_string_index(lct_priv_t* priv, Elf64_Addr plt_address) {
  uint32_t returner = (plt_address - priv->plt_address_min);
  assert(returner);
  returner = (returner/0x10) - 2;
  return returner;
}

uint32_t get_plt_list_index(lct_priv_t* priv, Elf64_Addr plt_address) {
  uint32_t returner = (plt_address - priv->plt_address_min);
  assert(returner);
  returner = (returner/0x10) - 2;
  return returner;
}

plt_hash_entry ** plt_hash_create_table(mambo_context* ctx) {
  plt_hash_entry ** tbl = (plt_hash_entry**) mambo_calloc(ctx, NUM_HASH_BUCKETS, sizeof(plt_hash_entry*));
  if(tbl == NULL) {
    return NULL;
  } else {
    return tbl;
  }
}

int plt_hash_add_entry(mambo_context* ctx, plt_hash_entry** plt_hash_table, Elf64_Addr plt_address, char* name) {
  plt_hash_entry * tbl = (plt_hash_entry*) mambo_alloc(ctx, sizeof(plt_hash_entry));
  char * name_alloc = mambo_alloc(ctx, sizeof(char)*strlen(name));
  strcpy(name_alloc, name);
  tbl->next = 0;
  tbl->addr = plt_address;
  tbl->call_count = 0;
  tbl->name = name_alloc;

  uint32_t key = (plt_address >> 4)%NUM_HASH_BUCKETS;

  plt_hash_entry * curr_entry = plt_hash_table[key];

  if(curr_entry == 0) {
    plt_hash_table[key] = tbl;
  } else {
    while(curr_entry->next != 0) {
      curr_entry = curr_entry->next;
    }
    curr_entry->next = tbl;
  }
}

void print_hash_table(plt_hash_entry** plt_hash_table) {
  int i = 0;
  plt_hash_entry* curr_entry;
  for(i = 0; i < NUM_HASH_BUCKETS; i++) {
    curr_entry = plt_hash_table[i];
    while(curr_entry != 0) {
      printf("%s was called %d times.\n", curr_entry->name, curr_entry->call_count);
      curr_entry = curr_entry->next;
    }
  }
}

int parse_process_mappings(mambo_context *ctx) {
  char          *line = NULL;
  size_t         size = 0;
  FILE          *maps = NULL;

  maps = fopen("/proc/self/maps", "r");
  if(maps == NULL) {
    printf("Couldn't open file /proc/self/maps\n");
    exit(EXIT_FAILURE);
  }

  while (getline(&line, &size, maps) > 0) {
    /* Placeholder for actual parsing of the file. Parsing is needed in order to 
    recursively find the VA of library calls within library calls, in order to trace 
    deeper than the top level calls of the application. The PLTs of all the 
    libraries themelves must be parsed, and we must find when our process 
    calls into them, and count these calls also. */
    printf("%s", line);
  }
  fclose(maps);
  return 0;
}

void increment_call(plt_list_item * list_item) {
  (list_item->call_count)++;
}

int lct_pre_bb_handler(mambo_context *ctx) {
  lct_priv_t* lct_priv = (lct_priv_t*) mambo_get_thread_plugin_data(ctx);

  // 1. If the address relates to main, then we have the full process mappings
  // for the application at this point. parse and print these.
  if(((Elf64_Addr) ctx->code.read_address) == lct_priv->main_address) {
    printf("****************************************************************\n");
    printf("Entering main function, parse process mappings file...\n");
    printf("****************************************************************\n");
    parse_process_mappings(ctx);
  }

  // 2. If the address relates to the PLT entries, inrememnt the revelent count.
  // base address is greater than minimum of plt, as the base address of the plt 
  // is not actually an entry but is the lookup for the GOT.
  if(((Elf64_Addr)ctx->code.read_address) > lct_priv->plt_address_min && ((Elf64_Addr)ctx->code.read_address) < lct_priv->plt_address_max) {
    debug("DEBUG: address of Basic block is %llx\n", ctx->code.read_address);
    uint32_t idx = get_plt_list_index(lct_priv, ((Elf64_Addr)ctx->code.read_address));
    emit_push(ctx, (1 << 0));
    emit_set_reg(ctx, reg0, ((uintptr_t) (plt_list_item *) lct_priv->plt_list[idx]));
    emit_safe_fcall(ctx, &increment_call, 1);
    emit_pop(ctx, (1 << 0));
  }

  return 0;
}

int lct_pre_thread_handler(mambo_context *ctx) {
  Elf *elf = NULL;
  int fd;
  char* filename = global_data.argv[1];
  Elf* ret_elf = NULL;
  Elf_Kind kind;
  ELF_EHDR *ehdr;
  Elf_Scn     *scn = NULL;
  GElf_Shdr   shdr;
  scn = NULL;
  size_t shstrndx;

  lct_priv_t * lct_priv = (lct_priv_t *) mambo_alloc(ctx, sizeof(lct_priv_t));
  assert(lct_priv != NULL);

  lct_priv->plt_string_list = (char**) mambo_calloc(ctx, 1000, sizeof(char *));
  lct_priv->plt_list = (plt_list_item **) mambo_calloc(ctx, 1000, sizeof(plt_list_item *));

  lct_priv->plt_hash_table = plt_hash_create_table(ctx);

  if(lct_priv->plt_hash_table == NULL) {
    printf("Couldn't create the hash table\n");
    exit(EXIT_FAILURE);
  }

  // Open the ELF file and check the symbol table to find the address of the PLT table.
  // Should be safe to delete all of these checks since this happens in main before 
  // the plugin callback is called. Here for absolute safety...
  fd = open(filename, O_RDONLY);
  if(fd < 0) {
    printf("Couldn't open file %s\n", filename);
    exit(EXIT_FAILURE);
  }

  if(elf_version(EV_CURRENT) == EV_NONE) {
    printf("Error setting ELF version\n");
    exit(EXIT_FAILURE);
  }

  elf = elf_begin(fd, ELF_C_READ, NULL);
  ret_elf = elf;
  if(elf == NULL) {
    printf("Error opening ELF file: %s: %s\n", filename, elf_errmsg(-1));
    exit(EXIT_FAILURE);
  }

  kind = elf_kind(elf);
  if(kind != ELF_K_ELF) {
    printf("File %s isn't an ELF file\n", filename);
    exit(EXIT_FAILURE);
  }

  ehdr = ELF_GETEHDR(elf);
  if(ehdr == NULL) {
    printf("Error reading the ELF executable header: %s\n", elf_errmsg(-1));
    exit(EXIT_FAILURE);
  }

  if(ehdr->e_ident[EI_CLASS] != ELF_CLASS) {
    printf("Not a 32-bit ELF file\n");
    exit(EXIT_FAILURE);
  }

  if(ehdr->e_machine != EM_MACHINE) {
    printf("Not compiled for ARM\n");
    exit(EXIT_FAILURE);
  }

  if(elf_getshdrstrndx(elf, &shstrndx) != 0) {
    printf("elf_getshdrstrndx failed...\n");
    exit(EXIT_FAILURE);
  }

  int ii, count;
  Elf_Data    *symtab;

  // FIRST PASS, 
  // 1. extract the base address of the PLT, and calculate the location of the 
  // first PLT entry. All others are calculated from here, as indexing in the 
  // ELF dynsym is in order of location in the PLT itself.
  // 2. Calculate the address of main(). We use main in order to identify when 
  // the user written program begins which libraries are mapped into memory. 
  // Using this we can see the memory space of the given mappings at runtime.
  // 3. Find the relocation section, extract the rela symbols and retrieve 
  // their information. The information relates to an index in the .dynsym table.
  // we extract these indexes for use in the second pass. 
  int * rela_indexes;
  rela_indexes = mambo_calloc(ctx,1000,sizeof(int));
  uint32_t use_zero_index = 0;

  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    if(gelf_getshdr(scn , &shdr) != &shdr) {
      printf("Could not find section header in ELF...\n");
      exit(EXIT_FAILURE);
    }
    // 1.
    if(!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name) , ".plt")) {
      lct_priv->plt_address_min = shdr.sh_addr;
      lct_priv->plt_address_max = shdr.sh_addr + shdr.sh_size;
      lct_priv->plt_size = shdr.sh_size;
      symtab = elf_getdata(scn, NULL);
      count = shdr.sh_size / shdr.sh_entsize;
      debug("DEBUG: PLT MIN = %llx, PLT MAX = %llx, PLT SIZE = %llx.\n", lct_priv->plt_address_min, lct_priv->plt_address_max, lct_priv->plt_size);
    }
    // 2.
    if(shdr.sh_type == SHT_SYMTAB) {
      symtab = elf_getdata(scn, NULL);
      count = shdr.sh_size / shdr.sh_entsize;
      debug("DEBUG: symbol table count is %d\n", count);

      for (ii = 0; ii < count; ++ii) {
        GElf_Sym sym;
        gelf_getsym(symtab, ii, &sym);
        if(!strcmp(elf_strptr(elf, shdr.sh_link, sym.st_name), "main")) {
          debug("DEBUG: Found main at address: %llx\n", sym.st_value);
          lct_priv->main_address = sym.st_value;
        }
      }
    }
    // 3. 
    if(!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name) , ".rela.plt")) {
      GElf_Xword relplt_count = shdr.sh_size / shdr.sh_entsize;
      GElf_Xword i;
      Elf_Data    *relaplt;
      relaplt = elf_getdata(scn, NULL);

      for (i = 0; i < relplt_count; ++i) {
        GElf_Rela rela;
        if(gelf_getrela(relaplt, i, &rela) == NULL) {
          return -1;
        }

        Elf64_Word relaword = ELF64_R_SYM(rela.r_info);
        if(relaword == 0) {
          use_zero_index = 1;
        }
        rela_indexes[i] = relaword;
      }
    }
  }

  scn = NULL;

  // SECOND PASS.
  // 1. Now we have the indexes into the dynsym table which correspond to the 
  // relocations, we can extract the string values of the symbols, and create 
  // list entries for each of the components of the PLT. In our instance we 
  // will use a simple list, with each new entry an additional offset from the 
  // base of the PLT. On AARCH64, the PLT is written such that the first 0x20 
  // is not an actual entry, but is the calculation of the index in the GOT, so
  // the first function call PLT entry starts at offset 0x20 from the base of the PLT.
  int str_idx = 0;
  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    if(gelf_getshdr(scn , &shdr) != &shdr) {
      printf("Could not find section header in ELF...\n");
      exit(EXIT_FAILURE);
    }
    // 1.
    if(!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name) , ".dynsym")) {
      symtab = elf_getdata(scn, NULL);
      count = shdr.sh_size / shdr.sh_entsize;
      int index = 0;
      Elf64_Addr plt_addr_curr = lct_priv->plt_address_min + 0x20;

      // First we handle entry 0, because if index 0 is used we do not want to accidentally reach break condition.
      if(use_zero_index) {
        GElf_Sym sym;
        gelf_getsym(symtab, 0, &sym);
        index = 1;
        plt_list_add_entry(ctx, lct_priv->plt_list, plt_addr_curr, elf_strptr(elf, shdr.sh_link, sym.st_name), str_idx);
        str_idx++;
        plt_addr_curr = plt_addr_curr + 0x10;
      } 
      while(rela_indexes[index] != 0) {
        GElf_Sym sym;
        sym = * gelf_getsym(symtab, rela_indexes[index], &sym);
        plt_list_add_entry(ctx, lct_priv->plt_list, plt_addr_curr, elf_strptr(elf, shdr.sh_link, sym.st_name), str_idx);
        plt_addr_curr = plt_addr_curr + 0x10;
        index++;
        str_idx++;
      }
    }
  }

  elf_end(elf);
  close(fd);
  mambo_free(ctx, rela_indexes);

  mambo_set_thread_plugin_data(ctx, lct_priv);
}

int lct_post_thread_handler(mambo_context *ctx) {
  lct_priv_t* lct_priv = (lct_priv_t*) mambo_get_thread_plugin_data(ctx);
  printf("****************************************************************\n");
  printf("Exited application. Total top-level library call counts are as follows...\n");
  printf("****************************************************************\n");
  print_plt_list_counts(lct_priv->plt_list);
}

int lct_exit_handler(mambo_context *ctx) {
  lct_priv_t* lct_priv = (lct_priv_t*) mambo_get_thread_plugin_data(ctx);
  assert(lct_priv != NULL);
  mambo_free(ctx, lct_priv);
  fprintf(stderr, "Exit called:\n");
}

__attribute__((constructor)) void library_call_trace_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);
  mambo_register_pre_thread_cb(ctx, &lct_pre_thread_handler);
  mambo_register_pre_basic_block_cb(ctx, &lct_pre_bb_handler);
  mambo_register_post_thread_cb(ctx, &lct_post_thread_handler);
  mambo_register_exit_cb(ctx, &lct_exit_handler);
  setlocale(LC_NUMERIC, "");
}

#else // __aarch64__
#error The library call trace plugin is currently only implemented for AArch64... sorry.
#endif
#endif // PLUGINS_NEW
