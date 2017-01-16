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
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <asm/unistd.h>

#include <sys/mman.h>
#include <unistd.h>

#include <libelf.h>

#include "dbm.h"
#include "common.h"
#include "scanner_common.h"

#include "elf_loader/elf_loader.h"

#include "pie/pie-thumb-decoder.h"
#include "pie/pie-thumb-encoder.h"

#include "pie/pie-arm-encoder.h"

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
  #ifndef VERBOSE
    #define VERBOSE
  #endif
#else
  #define debug(...)
#endif

#ifdef VERBOSE
  #define info(...) fprintf(stderr, __VA_ARGS__)
#else
  #define info(...)
#endif

dbm_global global_data;
__thread dbm_thread *current_thread;

void flush_code_cache(dbm_thread *thread_data) {
  thread_data->free_block = 2;
  hash_init(&thread_data->entry_address, CODE_CACHE_HASH_SIZE + CODE_CACHE_HASH_OVERP);
#ifdef DBM_TRACES
  thread_data->trace_cache_next = thread_data->code_cache->traces;
  thread_data->trace_id = CODE_CACHE_SIZE;

  hash_init(&thread_data->trace_entry_address, CODE_CACHE_HASH_SIZE + CODE_CACHE_HASH_OVERP);
#endif

  for (int i = 0; i < CODE_CACHE_SIZE; i++) {
    thread_data->code_cache_meta[i].exit_branch_type = unknown;
    thread_data->code_cache_meta[i].linked_from = NULL;
    thread_data->code_cache_meta[i].branch_cache_status = 0;
#ifdef DBM_TRACES
    thread_data->exec_count[i] = 0;
#endif
  }

  linked_list_init(thread_data->cc_links, MAX_CC_LINKS);
}

void mambo_deliver_callbacks(unsigned cb_id, dbm_thread *thread_data, inst_set inst_type,
                             cc_type fragment_type, int fragment_id, int inst, mambo_cond cond,
                             void *read_address, void *write_p, unsigned long *regs) {
#ifdef PLUGINS_NEW
  mambo_context ctx;

  assert(cb_id < CALLBACK_MAX_IDX);

  if (global_data.free_plugin > 0) {
    set_mambo_context(&ctx, thread_data, inst_type, fragment_type,
                      fragment_id, inst, cond, read_address, write_p, regs);
    for (int i = 0; i < global_data.free_plugin; i++) {
      if (global_data.plugins[i].cbs[cb_id] != NULL) {
        ctx.plugin_id = i;
        global_data.plugins[i].cbs[cb_id](&ctx);
      } // if
    } // for
  }
#endif
}

uint32_t lookup_or_scan(dbm_thread *thread_data, uint32_t target, bool *cached) {
  uint32_t block_address;
  bool from_cache = true;
  uint32_t basic_block;
  
  debug("Thread_data: %p\n", thread_data);
  
  block_address = hash_lookup(&thread_data->entry_address, target);

  if (block_address == UINT_MAX) {
    from_cache = false;
    block_address = scan(thread_data, (uint16_t *)target, ALLOCATE_BB);
  } else {
    basic_block = ((uint32_t)block_address - (uint32_t)(thread_data->code_cache)) >> 8;
    if (thread_data->code_cache_meta[basic_block].exit_branch_type == stub) {
      block_address = scan(thread_data, (uint16_t *)target, basic_block);
    }
  }
  
  if (cached != NULL) {
    *cached = from_cache;
  }
  
  return block_address;
}

int allocate_bb(dbm_thread *thread_data) {
  unsigned int basic_block;

  // Reserve CODE_CACHE_OVERP basic blocks to be able to scan large blocks
  if(thread_data->free_block >= (CODE_CACHE_SIZE - CODE_CACHE_OVERP)) {
    fprintf(stderr, "code cache full, flushing it\n");
    flush_code_cache(thread_data);
  }
  
  basic_block = thread_data->free_block++;
  return basic_block;
}

/* Stub BBs only contain a call to the dispatcher
   Stub BBs are used when a basic block can be optimised by directly linking
   to a target, but it's not clear if the target will ever be reached, e.g.:
   branch-not-taken path for conditional branches, RAS prediction */
uint32_t stub_bb(dbm_thread *thread_data, uint32_t target) {
  unsigned int basic_block;
  uint32_t block_address;
  uint32_t thumb = target & THUMB;
  
  basic_block = allocate_bb(thread_data);
  block_address = (uint32_t)&thread_data->code_cache->blocks[basic_block];
  
  debug("Stub BB: 0x%x\n", block_address + thumb);
  
  thread_data->code_cache_meta[basic_block].exit_branch_type = stub;
  if (!hash_add(&thread_data->entry_address, target, block_address + thumb)) {
    fprintf(stderr, "Failed to add hash table entry for newly created stub basic block\n");
    while(1);
  }
  
  if (thumb) {
    thumb_encode_stub_bb(thread_data, basic_block, target);
  } else {
    arm_encode_stub_bb(thread_data, basic_block, target);
  }
  
  return block_address + thumb;
}

uint32_t lookup_or_stub(dbm_thread *thread_data, uint32_t target) {
  uint32_t block_address;
  
  debug("Stub(0x%x)\n", target);
  debug("Thread_data: %p\n", thread_data);
  
  block_address = hash_lookup(&thread_data->entry_address, target);
  if (block_address == UINT_MAX) {
    block_address = stub_bb(thread_data, target);
    __clear_cache((char *)block_address, (char *)(block_address + BASIC_BLOCK_SIZE * 4 + 1));
  }
 
  return block_address;
}

#ifdef PLUGINS_NEW
void set_mambo_context(mambo_context *ctx, dbm_thread *thread_data, inst_set inst_type,
                       cc_type fragment_type, int fragment_id, int inst, mambo_cond cond,
                       void *read_address, void *write_p, unsigned long *regs) {
  ctx->thread_data = thread_data;
  ctx->inst_type = inst_type;
  ctx->fragment_type = fragment_type;
  ctx->fragment_id = fragment_id;
  ctx->inst = inst;
  ctx->cond = cond;
  ctx->read_address = read_address;
  ctx->write_p = write_p;
  ctx->regs = regs;
  ctx->replace = false;
}
#endif

uint32_t scan(dbm_thread *thread_data, uint16_t *address, int basic_block) {
  uint32_t thumb = (uint32_t)address & THUMB;
  uint32_t block_address;
  size_t block_size;
  bool stub = false;

  debug("scan(%p)\n", address);

  // Alocate a basic block
  if (basic_block == ALLOCATE_BB) {
    basic_block = allocate_bb(thread_data);
  } else {
    stub = true;
  }
  thread_data->code_cache_meta[basic_block].source_addr = address;
  block_address = (uint32_t)&thread_data->code_cache->blocks[basic_block];
  //fprintf(stderr, "scan(%p): 0x%x (bb %d)\n", address, block_address, basic_block);

  // Add entry into the code cache hash table
  // It must be added before scan_ is called, otherwise a call for scan
  // from scan_x could result in duplicate BBS or an infinite recursive call
  block_address |= thumb;
  if (!stub) {
    if (!hash_add(&thread_data->entry_address, (uint32_t)address, block_address)) {
      fprintf(stderr, "Failed to add hash table entry for newly created basic block\n");
      while(1);
    }
  }

  mambo_deliver_callbacks(PRE_FRAGMENT_C, thread_data, thumb ? THUMB_INST : ARM_INST, mambo_bb,
                          basic_block, -1, -1, address, (void *)(block_address & (~THUMB)), NULL);

  // Build a basic block
  // Scan functions return size of the generated basic block, in bytes
  if (thumb) {
    debug("scan address: %p\n", address);
    block_size = scan_thumb(thread_data, (uint16_t *)((uint32_t)address & 0xFFFFFFFE), basic_block, mambo_bb, NULL);
  } else {
    block_size = scan_arm(thread_data, (uint32_t *)address, basic_block, mambo_bb, NULL);
  }

  mambo_deliver_callbacks(POST_FRAGMENT_C, thread_data, thumb ? THUMB_INST : ARM_INST, mambo_bb,
                          basic_block, -1, -1, address, (void *)(block_address & (~THUMB)), NULL);

  // Flush modified instructions from caches
  // End address is exclusive
  __clear_cache((char *)block_address, (char *)(block_address + block_size + 1));

  return block_address;
}

void dbm_exit(dbm_thread *thread_data, uint32_t code) {
  int bb_count = thread_data->entry_address.count;
  int collision_rate = thread_data->entry_address.collisions * 1000 / bb_count;

  fprintf(stderr, "We're done; exiting with status: %d\n", code);

  mambo_deliver_callbacks(POST_THREAD_C, thread_data, -1, -1, -1, -1, -1, NULL, NULL, NULL);
  mambo_deliver_callbacks(EXIT_C, thread_data, -1, -1, -1, -1, -1, NULL, NULL, NULL);

  info("MAMBO exit\n");

  exit(code);
}

bool allocate_thread_data(dbm_thread **thread_data) {
  dbm_thread *data = mmap(NULL, sizeof(dbm_thread), PROT_READ | PROT_WRITE, METADATA_MMAP_OPTS, -1, 0);
  if (data != MAP_FAILED) {
    *thread_data = data;
    return true;
  }
  return false;
}

void init_thread(dbm_thread *thread_data) {
  dbm_thread **dispatcher_thread_data;
  uint16_t *write_p;

  // Initialize code cache
  thread_data->code_cache = mmap(NULL, sizeof(dbm_code_cache), PROT_EXEC | PROT_READ | PROT_WRITE, CC_MMAP_OPTS, -1, 0);
  if (thread_data->code_cache == MAP_FAILED) {
    fprintf(stderr, "Allocating code cache space failed\n");
    while(1);
  }
  info("Code cache: %p\n", thread_data->code_cache);

  thread_data->cc_links = mmap(NULL, sizeof(ll) + sizeof(ll_entry) * MAX_CC_LINKS, PROT_READ | PROT_WRITE, METADATA_MMAP_OPTS, -1, 0);
  assert(thread_data->cc_links != MAP_FAILED);

  // Initialize the hash table and basic block allocator, mark all BBs as unknown type
  flush_code_cache(thread_data);
 
  // Check that the thread private functions fit in the first basic block
  assert((uint32_t)&end_of_dispatcher_s - (uint32_t)th_to_arm < sizeof(dbm_block)*2);
  // Copy trampolines to the code cache
  /* GCC BUG?: if -O3 is enabled when doing arithmetic on a pointer
     to Thumb function (so addr[0] == 1), it seems the result is
     always a odd address. Use dispatcher_trampoline (ARM) instead
     of th_to_arm (Thumb). */
  memcpy(&thread_data->code_cache->blocks[0], (uint8_t *)dispatcher_trampoline-4, sizeof(dbm_block)*2);
  dispatcher_thread_data = (dbm_thread **)((uint32_t)&thread_data->code_cache->blocks[0] + global_data.disp_thread_data_off);
  *dispatcher_thread_data = thread_data;
  thread_data->code_cache->blocks[0].words[20] = (uint32_t)thread_data->scratch_regs;
  debug("*thread_data in dispatcher at: %p\n", dispatcher_thread_data);

#ifdef DBM_TRACES
  write_p = (uint16_t *)&thread_data->code_cache->blocks[0].words[23];
  thread_data->trace_head_incr_addr = ((uint32_t)write_p) + 1 - 4;
  copy_to_reg_32bit(&write_p, r1, (uint32_t)thread_data->exec_count);

  info("Traces start at: %p\n", &thread_data->code_cache->traces);
#endif

  __clear_cache((char *)&thread_data->code_cache->blocks[0], (char *)&thread_data->code_cache->blocks[thread_data->free_block]);
 
  thread_data->dispatcher_addr = (uint32_t)&thread_data->code_cache[0] + 4;
  thread_data->syscall_wrapper_addr = thread_data->dispatcher_addr
                                      + ((uint32_t)syscall_wrapper - (uint32_t)dispatcher_trampoline);

  thread_data->is_vfork_child = false;
                        
  debug("Syscall wrapper addr: 0x%x\n", thread_data->syscall_wrapper_addr);

  mambo_deliver_callbacks(PRE_THREAD_C, thread_data, -1, -1, -1, -1, -1, NULL, NULL, NULL);
}

bool is_bb(dbm_thread *thread_data, uint32_t addr) {
  uint32_t min = (uint32_t)thread_data->code_cache->blocks;
  uint32_t max = (uint32_t)thread_data->code_cache->traces;

  return addr >= min && addr < max;
}

int addr_to_bb_id(dbm_thread *thread_data, uint32_t addr) {
  uint32_t min = (uint32_t)thread_data->code_cache->blocks;
  uint32_t max = (uint32_t)thread_data->code_cache->traces;

  if (addr < min || addr > max) {
    return -1;
  }

  return (addr - (uint32_t)thread_data->code_cache->blocks) / sizeof(dbm_block);
}

// TODO: handle links to traces
void record_cc_link(dbm_thread *thread_data, uint32_t linked_from, uint32_t linked_to_addr) {
  int linked_to = addr_to_bb_id(thread_data, linked_to_addr);

  debug("Linked 0x%x (%d) from 0x%x\n", linked_to_addr, linked_to, linked_from);

  if (linked_to < 0) return;

  ll_entry *entry = linked_list_alloc(thread_data->cc_links);

  entry->data = linked_from;
  entry->next = thread_data->code_cache_meta[linked_to].linked_from;
  thread_data->code_cache_meta[linked_to].linked_from = entry;
}

void main(int argc, char **argv, char **envp) {
  Elf *elf = NULL;
  int has_interp = 0;
  int arg_diff;
  uint32_t phdr, phnum;
  
  if (argc < 2) {
    printf("Syntax: dbm elf_file arguments\n");
    exit(EXIT_FAILURE);
  }
  
  load_elf(argv[1], &elf, &has_interp, &phdr, &phnum);

  Elf32_Ehdr *ehdr = elf32_getehdr(elf);

  uint32_t entry_address = ehdr->e_entry;
  if (ehdr->e_type == ET_DYN) entry_address += DYN_OBJ_OFFSET;
  uint32_t block_address;
  debug("entry address: 0x%x\n", entry_address);
  
  global_data.disp_thread_data_off = (uint32_t)&disp_thread_data - (uint32_t)th_to_arm+1;
  
  dbm_thread *thread_data;
  if (!allocate_thread_data(&thread_data)) {
    fprintf(stderr, "Failed to allocate initial thread data\n");
    while(1);
  }
  current_thread = thread_data;
  init_thread(thread_data);
  thread_data->tid = syscall(__NR_gettid);

  block_address = scan(thread_data, (uint16_t *)entry_address, ALLOCATE_BB);
  debug("Address of first basic block is: 0x%x\n", block_address);
  
  arg_diff = has_interp ? 1 : 2;
  
  elf_run(block_address, entry_address, (has_interp ? "" : argv[1]), phdr, phnum, argc-arg_diff, &argv[arg_diff], envp);
}

