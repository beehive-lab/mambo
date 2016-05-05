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
#include <signal.h>
#include <asm/unistd.h>
#include <linux/sched.h>
#include <pthread.h>

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

#ifdef CC_HUGETLB
  #define CC_PAGE_SIZE (2*1024*1024)
  #define CC_MMAP_OPTS (MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB)
#else
  #define CC_PAGE_SIZE 4096
  #define CC_MMAP_OPTS (MAP_PRIVATE|MAP_ANONYMOUS)
#endif

#ifdef METADATA_HUGETLB
  #define METADATA_PAGE_SIZE (2*1024*1024)
  #define METADATA_MMAP_OPTS (MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB)
#else
  #define METADATA_PAGE_SIZE 4096
  #define METADATA_MMAP_OPTS (MAP_PRIVATE|MAP_ANONYMOUS)
#endif

#define ROUND_UP(input, multiple_of) \
  (((input / multiple_of) * multiple_of) + (input % multiple_of) ? multiple_of : 0)

#define CC_SZ_ROUND(input) ROUND_UP(input, CC_PAGE_SIZE)
#define METADATA_SZ_ROUND(input) ROUND_UP(input, CC_PAGE_SIZE)

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

void *dbm_start_thread_pth(void *ptr) {
  dbm_thread *thread_data = (dbm_thread *)ptr;
  assert(thread_data->clone_args->child_stack);

  current_thread = thread_data;
  uint32_t addr = scan(thread_data, thread_data->clone_ret_addr, ALLOCATE_BB);
  uint32_t tid = syscall(__NR_gettid);

  if (thread_data->clone_args->flags & CLONE_PARENT_SETTID) {
    *thread_data->clone_args->ptid = tid;
  }
  if (thread_data->clone_args->flags & CLONE_CHILD_SETTID) {
    *thread_data->clone_args->ctid = tid;
  }
  if (thread_data->clone_args->flags & CLONE_CHILD_CLEARTID) {
		syscall(__NR_set_tid_address, thread_data->clone_args->ctid);
  }
  thread_data->tls = thread_data->clone_args->tls;
  __asm__ volatile("dmb");

  thread_data->tid = tid;

  th_enter((uint32_t *)thread_data->clone_args, thread_data->scratch_regs,
           thread_data->clone_args->child_stack, addr);
  return NULL;
}

dbm_thread *dbm_create_thread(dbm_thread *thread_data, void *next_inst, sys_clone_args *args) {
  pthread_t thread;
  dbm_thread *new_thread_data;

  if (!allocate_thread_data(&new_thread_data)) {
    fprintf(stderr, "Failed to allocate thread data\n");
    while(1);
  }
  init_thread(new_thread_data);
  new_thread_data->clone_ret_addr = next_inst;
  new_thread_data->tid = 0;
  new_thread_data->clone_args = args;
  for (int i = 0; i < 3; i++) {
    new_thread_data->scratch_regs[i] = thread_data->scratch_regs[i];
  }

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED);
  /* We're switching to the stack allocated by the application immediately, so make this
     as small as possible. Our glibc stores data here, so we can't unmap it.
     Also see man pthread_attr_setguardsize BUGS. */
  pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN + 4096);
  pthread_attr_setguardsize(&attr, 4096);
  pthread_create(&thread, &attr, dbm_start_thread_pth, new_thread_data);

  return new_thread_data;
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

// return 0 to skip the syscall
int syscall_handler_pre(uint32_t syscall_no, uint32_t *args, uint16_t *next_inst, dbm_thread *thread_data) {
  struct sigaction *sig_action;
  sys_clone_args *clone_args;
  debug("syscall pre %d\n", syscall_no);

#ifdef PLUGINS_NEW
  mambo_context ctx;
  int cont;

  if (global_data.free_plugin > 0) {
    set_mambo_context(&ctx, thread_data, -1, -1, -1, -1, -1, NULL, NULL, (unsigned long *)args);
    for (int i = 0; i < global_data.free_plugin; i++) {
      if (global_data.plugins[i].cbs[PRE_SYSCALL_C] != NULL) {
        ctx.plugin_id = i;
        cont = global_data.plugins[i].cbs[PRE_SYSCALL_C](&ctx);
        if (!cont) return 0;
      } // if
    } // for
  }
#endif

  switch(syscall_no) {
    case SYSCALL_CLONE:
      clone_args = (sys_clone_args *)args;

      if (clone_args->flags & CLONE_VM) {
        if (!(clone_args->flags & CLONE_SETTLS)) {
          clone_args->tls = thread_data->tls;
        }
        thread_data->clone_vm = true;

        dbm_thread *child_data = dbm_create_thread(thread_data, next_inst, clone_args);
        while(child_data->tid == 0);
        args[0] = child_data->tid;

        return 0;
      } else {
        thread_data->child_tls = (clone_args->flags & CLONE_SETTLS) ? clone_args->tls : thread_data->tls;
        clone_args->flags &= ~CLONE_SETTLS;

        thread_data->clone_vm = false;
      }
      break;
    case SYSCALL_EXIT:
      debug("thread exit\n");
      mambo_deliver_callbacks(POST_THREAD_C, thread_data, -1, -1, -1, -1, -1, NULL, NULL, NULL);

      if (munmap(thread_data->code_cache, CC_SZ_ROUND(sizeof(dbm_code_cache))) != 0) {
        fprintf(stderr, "Error freeing code cache on exit()\n");
        while(1);
      }
      if (munmap(thread_data, METADATA_SZ_ROUND(sizeof(dbm_thread))) != 0) {
        fprintf(stderr, "Error freeing thread private structure on exit()\n");
        while(1);
      }
      pthread_exit(NULL); // this should never return
      while(1); 
      break;
    case SYSCALL_RT_SIGACTION:
      debug("sigaction %d\n", args[0]);
      debug("struct sigaction at 0x%x\n", args[1]);
      sig_action = (struct sigaction *)args[1];
      // If act is non-NULL, the new action for signal signum is installed from act. If oldact is non-NULL, the previous action is saved in oldact.
      debug("handler at %p\n", sig_action->sa_handler);
      if (sig_action
          && sig_action->sa_handler != SIG_IGN
          && sig_action->sa_handler != SIG_DFL) {
        sig_action->sa_handler = (void *)lookup_or_scan(thread_data, (uint32_t)sig_action->sa_handler, NULL);
      }
      break;
    case SYSCALL_EXIT_GROUP:
      dbm_exit(thread_data, args[0]);
      break;
    case SYSCALL_CLOSE:
      if (args[0] <= 2) { // stdin, stdout, stderr
        args[0] = 0;
        return 0;
      }
      break;
    case __ARM_NR_cacheflush:
      /* Returning to the calling BB is potentially unsafe because the remaining
         contents of the BB or other basic blocks it is linked against could be stale */
      flush_code_cache(thread_data);
      break;
    case __ARM_NR_set_tls:
      debug("set tls to %x\n", args[0]);
      thread_data->tls = args[0];
      args[0] = 0;
      return 0;
      break;
    /* Remove the execute permission from application mappings. At this point, this mostly acts
       as a safeguard in case a translation bug causes a branch to unmodified application code.
       Page permissions happen to be passed in the third argument both for mmap and mprotect. */
    case __NR_mmap2:
    case __NR_mprotect:
      /* Ensure that code pages are readable by the code scanner. */
      if (args[2] & PROT_EXEC) {
        assert(args[2] & PROT_READ);
      }
      args[2] &= ~PROT_EXEC;
      break;

    case __NR_munmap:
      flush_code_cache(thread_data);
      break;

    case __NR_vfork:
      assert(thread_data->is_vfork_child == false);
      thread_data->is_vfork_child = true;
      for (int i = 0; i < 3; i++) {
        thread_data->parent_scratch_regs[i] = thread_data->scratch_regs[i];
      }
      break;
  }
  
  return 1;
}

uint32_t syscall_handler_post(uint32_t syscall_no, uint32_t *args, uint16_t *next_inst, dbm_thread *thread_data) {
  dbm_thread *new_thread_data;
  uint32_t addr = 0;
  
  debug("syscall post %d\n", syscall_no);

  switch(syscall_no) {
    case SYSCALL_CLONE:
      debug("r0 (tid): %d\n", args[0]);
      if (args[0] == 0) { // the child
        if (thread_data->clone_vm) {
          debug("target: %p\n", next_inst);
          if (!allocate_thread_data(&new_thread_data)) {
            fprintf(stderr, "Failed to allocate thread data\n");
            while(1);
          }
          init_thread(new_thread_data);
          addr = scan(new_thread_data, next_inst, ALLOCATE_BB);
          new_thread_data->tls = thread_data->child_tls;
          /* There are a few race conditions in this implementation, which should be addressed.
             However, this code path is not used at the moment. We are using ptrace_create.
             TODO:
             * block the parent
             * copy all shared state to the child's private data (sr_regs, next_inst, th->child_tls)
               * args should be safe, they're pushed on the thread's stack
             * unblock the parent
          */
          assert(0);
        } else {
          /* Without CLONE_VM, the child runs in a separate memory space,
             no synchronisation is needed.*/
          thread_data->tls = thread_data->child_tls;
        }
      }
      break;

    case __NR_vfork:
      if (args[0] != 0) { // in the parent
        for (int i = 0; i < 3; i++) {
          thread_data->scratch_regs[i] = thread_data->parent_scratch_regs[i];
        }
        thread_data->is_vfork_child = false;
      }
      break;
  }

  mambo_deliver_callbacks(POST_SYSCALL_C, thread_data, -1, -1, -1, -1, -1, NULL, NULL, (unsigned long *)args);

  return addr;
}

void dispatcher(uint32_t target, uint32_t *next_addr, uint32_t source_index, dbm_thread *thread_data) {
  uint32_t block_address;
  uint32_t other_target;
  uint32_t pred_target;
  uint16_t *branch_addr; 
  uint32_t *branch_table;
  bool     cached;
  bool     other_target_in_cache;
  int      cache_index;
  uint8_t  *table;
  branch_type source_branch_type;
  uint8_t  sr[2];
  uint32_t reglist;
  uint32_t *ras;
  bool use_bx_lr;
  int unwind_len;
  bool is_taken;

/* It's essential to copy exit_branch_type before calling lookup_or_scan
     because when scanning a stub basic block the source block and its
     meta-information get overwritten */
  debug("Source block index: %d\n", source_index);
  source_branch_type = thread_data->code_cache_meta[source_index].exit_branch_type;

#ifdef DBM_TRACES
  // Handle trace exits separately
  if (source_index >= CODE_CACHE_SIZE && source_branch_type != tbb && source_branch_type != tbh) {
    return trace_dispatcher(target, next_addr, source_index, thread_data);
  }
#endif
  
  debug("Reached the dispatcher, target: 0x%x, ret: %p, src: %d thr: %p\n", target, next_addr, source_index, thread_data);
  block_address = lookup_or_scan(thread_data, target, &cached);
  if (cached) {
    debug("Found block from %d for 0x%x in cache at 0x%x\n", source_index, target, block_address);
  } else {
    debug("Scanned at 0x%x for 0x%x\n", block_address, target);
  }
  
  switch (source_branch_type) {
#ifdef DBM_TB_DIRECT
    case tbb:
    case tbh:
      /* the index is invalid only when the inline hash lookup is called for a new BB,
         no linking is required */
#ifdef FAST_BT
      if (thread_data->code_cache_meta[source_index].rn >= TB_CACHE_SIZE) {
        break;
      }
#else
      if (thread_data->code_cache_meta[source_index].rn >= MAX_TB_INDEX) {
        break;
      }
#endif
      //thread_data->code_cache_meta[source_index].count++;
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
#ifdef FAST_BT
      branch_table = (uint32_t *)(((uint32_t)branch_addr + 20 + 2) & 0xFFFFFFFC);
      branch_table[thread_data->code_cache_meta[source_index].rn] = block_address;
#else
      branch_addr += 7;
      table = (uint8_t *)branch_addr;
      if (thread_data->code_cache_meta[source_index].free_b == TB_CACHE_SIZE) {
        // if the list of linked blocks is full, link this index to the inline hash lookup
  #ifdef DBM_D_INLINE_HASH
        table[thread_data->code_cache_meta[source_index].rn] = MAX_TB_INDEX / 2 + TB_CACHE_SIZE * 2 + 1;
  #else
        table[thread_data->code_cache_meta[source_index].rn] = MAX_TB_INDEX / 2 + TB_CACHE_SIZE * 2;
  #endif
      } else {
        // allocate a branch slot and link it
        cache_index = thread_data->code_cache_meta[source_index].free_b++;
        table[thread_data->code_cache_meta[source_index].rn] = MAX_TB_INDEX / 2 + cache_index * 2;
        
        // insert the branch to the target BB
        branch_addr += MAX_TB_INDEX / 2 + cache_index * 2;
        thumb_cc_branch(thread_data, branch_addr, (uint32_t)block_address);
        __clear_cache(branch_addr, branch_addr + 5);
      }
  #endif
      
      // invalidate the saved rm value - required to detect calls from the inline hash lookup
      thread_data->code_cache_meta[source_index].rn = INT_MAX;

      break;
#endif
#ifdef DBM_LINK_UNCOND_IMM
    case uncond_imm_thumb:
    case uncond_b_to_bl_thumb:
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
      if (block_address & 0x1) {
        if (source_branch_type == uncond_b_to_bl_thumb) {
          thumb_b32_helper(branch_addr, (uint32_t)block_address);
        } else {
          thumb_cc_branch(thread_data, branch_addr, (uint32_t)block_address);
        }
        __clear_cache((char *)branch_addr-1, (char *)(branch_addr) + 8);
      } else {
        // The data word used for the address is word-aligned
        if (((uint32_t)branch_addr) & 2) {
          thumb_ldrl32(&branch_addr, pc, 4, 1);
          branch_addr += 3;
        } else {
          thumb_ldrl32(&branch_addr, pc, 0, 1);
          branch_addr += 2;
        }
        *(uint32_t *)branch_addr = block_address;
        __clear_cache((char *)branch_addr-7, (char *)branch_addr);
      }
      break;
#endif
#ifdef DBM_LINK_COND_IMM
    case cond_imm_arm:
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
      is_taken = target == thread_data->code_cache_meta[source_index].branch_taken_addr;
      if (is_taken) {
        other_target = hash_lookup(&thread_data->entry_address, thread_data->code_cache_meta[source_index].branch_skipped_addr);
        other_target_in_cache = (other_target != UINT_MAX);

        if (thread_data->code_cache_meta[source_index].branch_cache_status & 1) {
          branch_addr += 2;
        }

        arm_cc_branch(thread_data, (uint32_t *)branch_addr, (uint32_t)block_address,
                      thread_data->code_cache_meta[source_index].branch_condition);
      } else {
        other_target = hash_lookup(&thread_data->entry_address, thread_data->code_cache_meta[source_index].branch_taken_addr);
        other_target_in_cache = (other_target != UINT_MAX);

        if (thread_data->code_cache_meta[source_index].branch_cache_status & 2) {
          branch_addr += 2;
        }

        arm_cc_branch(thread_data, (uint32_t *)branch_addr, (uint32_t)block_address,
                       arm_inverse_cond_code[thread_data->code_cache_meta[source_index].branch_condition]);
      }
      thread_data->code_cache_meta[source_index].branch_cache_status |= is_taken ? 2 : 1;

      if (other_target_in_cache &&
          (thread_data->code_cache_meta[source_index].branch_cache_status & (is_taken ? 1 : 2)) == 0) {
        branch_addr += 2;
        arm_cc_branch(thread_data, (uint32_t *)branch_addr, (uint32_t)other_target, AL);

        thread_data->code_cache_meta[source_index].branch_cache_status |= is_taken ? 1 : 2;
      }

      __clear_cache((char *)branch_addr-4, (char *)branch_addr+8);
      break;

    case cond_imm_thumb:
      if (block_address & 0x1) {
        branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
        debug("Target is: 0x%x, b taken addr: 0x%x, b skipped addr: 0x%x\n",
               target, thread_data->code_cache_meta[source_index].branch_taken_addr,
               thread_data->code_cache_meta[source_index].branch_skipped_addr);
        debug("Overwriting branches at %p\n", branch_addr);
        if (target == thread_data->code_cache_meta[source_index].branch_taken_addr) {
          other_target = hash_lookup(&thread_data->entry_address, thread_data->code_cache_meta[source_index].branch_skipped_addr);
          other_target_in_cache = (other_target != UINT_MAX);
          thumb_encode_cond_imm_branch(thread_data, &branch_addr, 
                                      source_index,
                                      block_address,
                                      (other_target_in_cache ? other_target : thread_data->code_cache_meta[source_index].branch_skipped_addr),
                                      thread_data->code_cache_meta[source_index].branch_condition,
                                      true,
                                      other_target_in_cache, true);
        } else {
          other_target = hash_lookup(&thread_data->entry_address, thread_data->code_cache_meta[source_index].branch_taken_addr);
          other_target_in_cache = (other_target != UINT_MAX);
          thumb_encode_cond_imm_branch(thread_data, &branch_addr, 
                                      source_index,
                                      (other_target_in_cache ? other_target : thread_data->code_cache_meta[source_index].branch_taken_addr),
                                      block_address,
                                      thread_data->code_cache_meta[source_index].branch_condition,
                                      other_target_in_cache,
                                      true, true);
        }
        debug("Target at 0x%x, other target at 0x%x\n", block_address, other_target);
        // thumb_encode_cond_imm_branch updates branch_addr to point to the next free word
        __clear_cache((char *)(branch_addr)-100, (char *)branch_addr);
      } else {
        fprintf(stderr, "WARN: cond_imm_thumb to arm\n");
        while(1);
      }
      break;
#endif
#ifdef DBM_LINK_CBZ
    case cbz_thumb:
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;
      debug("Target is: 0x%x, b taken addr: 0x%x, b skipped addr: 0x%x\n",
             target, thread_data->code_cache_meta[source_index].branch_taken_addr,
             thread_data->code_cache_meta[source_index].branch_skipped_addr);
      debug("Overwriting branches at %p\n", branch_addr);
      if (target == thread_data->code_cache_meta[source_index].branch_taken_addr) {
        other_target = hash_lookup(&thread_data->entry_address, thread_data->code_cache_meta[source_index].branch_skipped_addr);
        other_target_in_cache = (other_target != UINT_MAX);
        thumb_encode_cbz_branch(thread_data,
                                thread_data->code_cache_meta[source_index].rn,
                                &branch_addr,
                                source_index,
                                block_address,
                                (other_target_in_cache ? other_target : thread_data->code_cache_meta[source_index].branch_skipped_addr),
                                true,
                                other_target_in_cache, true);
      } else {
        other_target = hash_lookup(&thread_data->entry_address, thread_data->code_cache_meta[source_index].branch_taken_addr);
        other_target_in_cache = (other_target != UINT_MAX);
        thumb_encode_cbz_branch(thread_data,
                                thread_data->code_cache_meta[source_index].rn,
                                &branch_addr,
                                source_index,
                                (other_target_in_cache ? other_target : thread_data->code_cache_meta[source_index].branch_taken_addr),
                                block_address,
                                other_target_in_cache,
                                true, true);
      }
      debug("Target at 0x%x, other target at 0x%x\n", block_address, other_target);
      // tthumb_encode_cbz_branch updates branch_addr to point to the next free word
      __clear_cache((char *)(branch_addr)-100, (char *)branch_addr);
      break;
#endif

    case uncond_blxi_thumb:
      branch_addr = thread_data->code_cache_meta[source_index].exit_branch_addr;

      thumb_ldrl32(&branch_addr, pc, ((uint32_t)branch_addr & 2) ? 4 : 0, 1);
	    branch_addr += 2;
	    // The target is word-aligned
	    if ((uint32_t)branch_addr & 2) { branch_addr++; }
	    *(uint32_t *)branch_addr = block_address;
	    __clear_cache((char *)(branch_addr)-6, (char *)branch_addr);

	    record_cc_link(thread_data, (uint32_t)branch_addr|FULLADDR, block_address);

      break;
  }
  
  *next_addr = block_address;
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

