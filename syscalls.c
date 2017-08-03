/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
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

#include <stdio.h>
#include <asm/unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/sched.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/shm.h>

#include "dbm.h"
#include "kernel_sigaction.h"
#include "scanner_common.h"
#include "syscalls.h"

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

#ifdef __aarch64__
  #define SIG_FRAG_OFFSET 4
#else
  #define SIG_FRAG_OFFSET 0
#endif

void *dbm_start_thread_pth(void *ptr, void *mambo_sp) {
  dbm_thread *thread_data = (dbm_thread *)ptr;
  assert(thread_data->clone_args->child_stack);
  current_thread = thread_data;
  current_thread->mambo_sp = mambo_sp;

  pid_t tid = syscall(__NR_gettid);
  thread_data->tid = tid;
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

  // Copy the parent's saved register values to the child's stack
#ifdef __arm__
  uint32_t *child_stack = thread_data->clone_args->child_stack;
  child_stack -= 15; // reserve 15 words on the child's stack
  mambo_memcpy(child_stack, thread_data->clone_args, sizeof(uintptr_t) * 14);
  child_stack[r0] = 0; // return 0
#endif
#ifdef __aarch64__
  uint64_t *child_stack = thread_data->clone_args->child_stack;
  child_stack -= 34;
  mambo_memcpy(child_stack, (void *)thread_data->clone_args, sizeof(uintptr_t) * 32);
  // move the values for X0 and X1 to the bottom of the stack
  child_stack[32] = 0; // X0
  child_stack[33] = child_stack[1]; // X1
  child_stack += 2;
#endif

  // Release the lock
  asm volatile("DMB SY" ::: "memory");
  *(thread_data->set_tid) = tid;

  assert(register_thread(thread_data, false) == 0);

  uintptr_t addr = scan(thread_data, thread_data->clone_ret_addr, ALLOCATE_BB);
  th_enter(child_stack, addr);

  return NULL;
}

dbm_thread *dbm_create_thread(dbm_thread *thread_data, void *next_inst, sys_clone_args *args, volatile pid_t *set_tid) {
  pthread_t thread;
  dbm_thread *new_thread_data;

  if (!allocate_thread_data(&new_thread_data)) {
    fprintf(stderr, "Failed to allocate thread data\n");
    while(1);
  }
  init_thread(new_thread_data);
  new_thread_data->clone_ret_addr = next_inst;
  new_thread_data->set_tid = set_tid;
  new_thread_data->clone_args = args;

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED);
  /* We're switching to the stack allocated by the application immediately, so make this
     as small as possible. Our glibc stores data here, so we can't unmap it.
     Also see man pthread_attr_setguardsize BUGS. */
  pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN + 4096);
  pthread_attr_setguardsize(&attr, 4096);
  pthread_create(&thread, &attr, new_thread_trampoline, new_thread_data);

  return new_thread_data;
}

uintptr_t emulate_brk(uintptr_t addr) {
  int ret;

  // Fast path
  if (addr == 0 || addr == global_data.brk) {
    return global_data.brk;
  }

  ret = pthread_mutex_lock(&global_data.brk_mutex);
  assert(ret == 0);

  /* We use mremap for non-overlapping re-allocation, therefore
     we must always always keep at least one allocated page. */
  if (addr >= (global_data.initial_brk + PAGE_SIZE)) {
    void *map = mremap((void *)global_data.initial_brk,
                       global_data.brk - global_data.initial_brk,
                       addr - global_data.initial_brk, 0);
    if (map != MAP_FAILED) {
      vm_op_t op = VM_MAP;
      size_t size = addr - global_data.brk;
      if (addr < global_data.brk) {
        vm_op_t op = VM_UNMAP;
        size = global_data.brk - addr;
      }
      notify_vm_op(op, min(addr, global_data.brk), size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
      global_data.brk = addr;
    }
  }

  ret = pthread_mutex_unlock(&global_data.brk_mutex);
  assert(ret == 0);

  return global_data.brk;
}

ssize_t readlink_handler(char *sys_path, char *sys_buf, ssize_t bufsize) {
  const int proc_buflen = 100;
  char buf[proc_buflen];
  snprintf(buf, proc_buflen, "/proc/%d/exe", getpid());
  if (strcmp(sys_path, buf) == 0 ||
      strcmp(sys_path, "/proc/self/exe") == 0 ||
      strcmp(sys_path, "/proc/thread-self/exe") == 0) {
    char path[PATH_MAX];
    char *rp = realpath(global_data.argv[1], path);
    assert(rp != NULL);
    size_t path_len = strlen(rp);

    /* realpath() null-terminates strings, while readlinkat shouldn't.
       Therefore, if PATH_MAX has been filled and bufsize == PATH_MAX, then it's possible
       that we've lost a valid last character which realpath set to null. */
    assert((bufsize < PATH_MAX) || (path_len < (PATH_MAX - 1)));

    strncpy(sys_buf, path, bufsize);
    return min(path_len, bufsize);
  }

  return -1;
}

int syscall_handler_pre(uintptr_t syscall_no, uintptr_t *args, uint16_t *next_inst, dbm_thread *thread_data) {
  int do_syscall = 1;
  sys_clone_args *clone_args;
  debug("syscall pre %d\n", syscall_no);

#ifdef PLUGINS_NEW
  mambo_context ctx;
  int cont;

  if (global_data.free_plugin > 0) {
    set_mambo_context_syscall(&ctx, thread_data, PRE_SYSCALL_C, syscall_no, args);
    mambo_deliver_callbacks_for_ctx(&ctx);
  }

  if (ctx.syscall.replace) {
    do_syscall = 0;
    args[0] = ctx.syscall.ret;
  } else {
#endif

  switch(syscall_no) {
    case __NR_brk:
      args[0] = emulate_brk(args[0]);
      do_syscall = 0;
      break;
    case __NR_clone:
      clone_args = (sys_clone_args *)args;

      if (clone_args->flags & CLONE_THREAD) {
        assert(clone_args->flags & CLONE_VM);
        if (!(clone_args->flags & CLONE_SETTLS)) {
          clone_args->tls = thread_data->tls;
        }
        thread_data->clone_vm = true;

        volatile pid_t child_tid = 0;
        dbm_create_thread(thread_data, next_inst, clone_args, &child_tid);
        while(child_tid == 0);
        asm volatile("DMB SY" ::: "memory");
        args[0] = child_tid;

        do_syscall = 0;
        break;
      }

      if (clone_args->flags & CLONE_VFORK) {
        clone_args->flags &= ~CLONE_VM;
      }
      assert((clone_args->flags & CLONE_VM) == 0);
      thread_data->clone_vm = false;

      thread_data->child_tls = (clone_args->flags & CLONE_SETTLS) ? clone_args->tls : thread_data->tls;
      clone_args->flags &= ~CLONE_SETTLS;

      if (clone_args->child_stack != NULL) {
        if (clone_args->child_stack == &args[SYSCALL_WRAPPER_STACK_OFFSET]) {
          clone_args->child_stack = NULL;
        } else {
          const size_t copy_size = SYSCALL_WRAPPER_FRAME_SIZE * sizeof(uintptr_t);
          clone_args->child_stack -= copy_size;
          void *source = args + SYSCALL_WRAPPER_STACK_OFFSET - SYSCALL_WRAPPER_FRAME_SIZE;
          mambo_memcpy(clone_args->child_stack, source, copy_size);
        }
      } // if child_stack != NULL
      break;
    case __NR_exit:
      debug("thread exit\n");
      void *sp = thread_data->mambo_sp;
      assert(unregister_thread(thread_data, false) == 0);
      assert(free_thread_data(thread_data) == 0);

      return_with_sp(sp); // this should never return
      while(1); 
      break;
#ifdef __arm__
    case __NR_sigaction:
      fprintf(stderr, "check sigaction()\n");
      while(1);
#endif
    case __NR_rt_sigaction: {
      uintptr_t handler = 0xdead;
      assert(args[3] == 8 && args[0] >= 0 && args[0] < _NSIG);

      struct kernel_sigaction *act = (struct kernel_sigaction *)args[1];
      if (act != NULL) {
        handler = (uintptr_t)act->k_sa_handler;
        // Never remove the UNLINK_SIGNAL handler, which is used internally by MAMBO
        if (args[0] == UNLINK_SIGNAL || (act->k_sa_handler != SIG_IGN && act->k_sa_handler != SIG_DFL)) {
          act->k_sa_handler = (__sighandler_t)signal_trampoline;
          act->sa_flags |= SA_SIGINFO;
        }
      }

      // A mutex is used to ensure that changes to the handler and all other options appear atomic
      int ret = pthread_mutex_lock(&global_data.signal_handlers_mutex);
      assert(ret == 0);

      uintptr_t syscall_ret = raw_syscall(syscall_no, args[0], args[1], args[2], args[3]);
      if (syscall_ret == 0) {
        struct kernel_sigaction *oldact = (struct kernel_sigaction *)args[2];
        if (oldact != NULL && oldact->k_sa_handler != SIG_IGN && oldact->k_sa_handler != SIG_DFL) {
          oldact->k_sa_handler = (void *)global_data.signal_handlers[args[0]];
        }

        if (act != NULL) {
          global_data.signal_handlers[args[0]] = handler;
        }
      }

      ret = pthread_mutex_unlock(&global_data.signal_handlers_mutex);
      assert(ret == 0);

      args[0] = syscall_ret;

      do_syscall = 0;
      break;
    }
    case __NR_exit_group:
      dbm_exit(thread_data, args[0]);
      break;
    case __NR_close:
      if (args[0] <= 2) { // stdin, stdout, stderr
        args[0] = 0;
        do_syscall = 0;
      }
      break;
    case __NR_readlinkat: {
      ssize_t len = readlink_handler((char *)args[1], (char *)args[2], args[3]);
      if (len >= 0) {
        args[0] = (uintptr_t)len;
        do_syscall = 0;
      }
      break;
    }
    /* Remove the execute permission from application mappings. At this point, this mostly acts
       as a safeguard in case a translation bug causes a branch to unmodified application code.
       Page permissions happen to be passed in the third argument both for mmap and mprotect. */
#ifdef __arm__
    case __NR_mmap2: {
#endif
#ifdef __aarch64__
    case __NR_mmap: {
#endif
      uintptr_t syscall_ret, prot = args[2];

      /* Ensure that code pages are readable by the code scanner. */
      if (args[2] & PROT_EXEC) {
        assert(args[2] & PROT_READ);
        args[2] &= ~PROT_EXEC;
      }
      syscall_ret = raw_syscall(syscall_no, args[0], args[1], args[2], args[3], args[4], args[5]);
      if (syscall_ret <= -ERANGE) {
        uintptr_t start = align_lower(syscall_ret, PAGE_SIZE);
        uintptr_t end = align_higher(syscall_ret + args[1], PAGE_SIZE);
        notify_vm_op(VM_MAP, start, end-start, prot, args[3], args[4], args[5]);
      }

      args[0] = syscall_ret;
      do_syscall = 0;
      break;
    }
    case __NR_mprotect: {
      int ret;
      uintptr_t syscall_ret, prot = args[2];

      if (args[2] & PROT_EXEC) {
        assert(args[2] & PROT_READ);
        args[2] &= ~PROT_EXEC;
      }
      syscall_ret = raw_syscall(syscall_no, args[0], args[1], args[2]);
      if (syscall_ret == 0) {
        uintptr_t start = align_lower(args[0], PAGE_SIZE);
        uintptr_t end = align_higher(args[0] + args[1], PAGE_SIZE);
        notify_vm_op(VM_PROT, start, end-start, args[2], 0, -1, 0);
      }

      args[0] = syscall_ret;
      do_syscall = 0;
      break;
    }
    case __NR_munmap: {
      uintptr_t syscall_ret = raw_syscall(syscall_no, args[0], args[1]);

      if (syscall_ret == 0) {
        uintptr_t start = align_lower(args[0], PAGE_SIZE);
        uintptr_t end = align_higher(args[0] + args[1], PAGE_SIZE);
        notify_vm_op(VM_UNMAP, start, end-start, 0, 0, -1, 0);
      }

      args[0] = syscall_ret;
      do_syscall = 0;
      break;
    }

    case __NR_shmat: {
      uintptr_t syscall_ret = raw_syscall(syscall_no, args[0], args[1], args[2]);
      if (syscall_ret != -1) {
        struct shmid_ds shm;
        int prot = PROT_READ;
        prot |= (args[2] & SHM_EXEC) ? PROT_EXEC : 0;
        prot |= (args[2] & SHM_RDONLY) ? 0 : PROT_WRITE;
        int ret = shmctl(args[0], IPC_STAT, &shm);
        assert(ret == 0);

        notify_vm_op(VM_MAP, syscall_ret, shm.shm_segsz, prot, 0, -1, 0);
      }

      args[0] = syscall_ret;
      do_syscall = 0;
      break;
    }

    case __NR_shmdt: {
      struct shmid_ds shm;
      int ret = shmctl(args[0], IPC_STAT, &shm);
      if (ret == 0) {
        uintptr_t syscall_ret = raw_syscall(syscall_no, args[0]);
        if (syscall_ret == 0) {
          notify_vm_op(VM_UNMAP, args[0], shm.shm_segsz, 0, 0, -1, 0);
        }
        args[0] = syscall_ret;
      } else {
        args[0] = -errno;
      }

      do_syscall = 0;
      break;
    }

#ifdef __arm__
    case __NR_sigreturn:
#endif
    case __NR_rt_sigreturn: {
      void *app_sp = args;
#ifdef __arm__
      /* We force all signal handler to the SA_SIGINFO type, which must return
         with rt_sigreturn() and not sigreturn(). Some applications don't return
         to the rt_sigreturn wrapper set by the kernel in the LR, so we need to
         override it here. See linux/arm/kernel/signal.c for the difference
         between the two types of signal handlers.
      */
      args[7] = __NR_rt_sigreturn;
      app_sp += 64;
#elif __aarch64__
      app_sp += 64 + 144;
#endif
      ucontext_t *cont = (ucontext_t *)(app_sp + sizeof(siginfo_t));
      sigret_dispatcher_call(thread_data, cont, cont->context_pc);

      // Don't mark the thread as executing a syscall
      return 1;
    }

#ifdef __arm__
    case __NR_vfork:
      // vfork without sharing the address space
      args[0] = raw_syscall(__NR_clone, CLONE_VFORK, NULL, NULL, NULL, NULL);
      if (args[0] == 0) {
        reset_process(thread_data);
      }
      do_syscall = 0;
      break;
    case __ARM_NR_cacheflush:
      debug("cache flush\n");
      /* Returning to the calling BB is potentially unsafe because the remaining
         contents of the BB or other basic blocks it is linked against could be stale */
      flush_code_cache(thread_data);
      break;
    case __ARM_NR_set_tls:
      debug("set tls to %x\n", args[0]);
      thread_data->tls = args[0];
      args[0] = 0;
      do_syscall = 0;
      break;
    case __NR_readlink: {
      ssize_t len = readlink_handler((char *)args[0], (char *)args[1], args[2]);
      if (len >= 0) {
        args[0] = (uintptr_t)len;
        do_syscall = 0;
      }
      break;
    }
#endif
  }

#ifdef PLUGINS_NEW
  } // if (!ctx.syscall.replace)
  if (do_syscall == 0 && global_data.free_plugin > 0) {
    set_mambo_context_syscall(&ctx, thread_data, POST_SYSCALL_C, syscall_no, (uintptr_t *)args);
    mambo_deliver_callbacks_for_ctx(&ctx);
  }
#endif

  if (do_syscall) {
    thread_data->status = THREAD_SYSCALL;
  }

  return do_syscall;
}

void syscall_handler_post(uintptr_t syscall_no, uintptr_t *args, uint16_t *next_inst, dbm_thread *thread_data) {
  dbm_thread *new_thread_data;
  
  debug("syscall post %d\n", syscall_no);

  if (global_data.exit_group) {
    thread_abort(thread_data);
  }
  thread_data->status = THREAD_RUNNING;

  switch(syscall_no) {
    case __NR_clone:
      debug("r0 (tid): %d\n", args[0]);
      if (args[0] == 0) { // the child
        assert(!thread_data->clone_vm);
        /* Without CLONE_VM, the child runs in a separate memory space,
           no synchronisation is needed.*/
        thread_data->tls = thread_data->child_tls;
        reset_process(thread_data);
      }
      break;
  }

#ifdef PLUGINS_NEW
  mambo_context ctx;

  set_mambo_context_syscall(&ctx, thread_data, POST_SYSCALL_C, syscall_no, (uintptr_t *)args);
  mambo_deliver_callbacks_for_ctx(&ctx);
#endif
}
