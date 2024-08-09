#ifdef PLUGINS_NEW

#include <asm/unistd.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "../../plugins.h"
#include "datarace.h"


/*
  = DATARACE PLUGIN INFO

  - READ: <TID> <ADDR>
  - WRITE: <TID> <ADDR>
  - LOCK: <TID> <ADDR> - ADDR is to mutex object
  - UNLOCK: <TID> <ADDR> - ADDR is to mutex object
  - FORK(T, U) <tid> <tid> - T is parent tid, U is child tid
  - JOIN(T, U) <tid> <tid> - T is parent tid, U is child tid

Implementations:
  - READ/WRITE: pre_inst - Note: Refer to how libc is ignored - either use -no-pie or dynamically compile
  - LOCK: In pre_lock: Save the address of mutex. Commit lock in post_lock for that mutex
  - UNLOCK: Commit unlock of the mutex in pre_unlock
  - FORK: Commit in pre_thread by retrieving parent's TID
  - JOIN:
    - pre_clone:    Get the pthread_t value of child thread (to be spawned)
    - syscall.c::dbm_create_thread   get pthread_t value from parent's thread data
    - pre_thread:   Get pthread_t of this thread and link it to its tid
    - pre_join:     Use pthread_t to get joining thread's tid
    - post_join:    Commit JOIN using joining tid

TODO:
  - JOIN: __clone() cb registered. Handle clone3 - replace with syscall cb?
*/


/* 
  ## PROCESS EVENTS ## 
  Recorded operations are processed for data race detection.
*/ 
thread_list_t *threads;
variable_list_t *variables;
lock_list_t *locks;

// print symbol info when data race detected
void print_symbol_info(uintptr_t addr) {
  char *sym_name, *filename;
  void *symbol_start_addr;

  get_symbol_info_by_addr(addr, &sym_name, &symbol_start_addr, &filename);

  fprintf(stderr, ">>>> at %p: %s (%p) (%s)\n", (void*)addr, filename, 
  symbol_start_addr, (sym_name == NULL ? "none" : sym_name));

  free(sym_name);
  free(filename);
}


void process_fork(int parent_tid, int child_tid) {
  info("--- FORK: Thread %d created by %d\n", child_tid, parent_tid);

  thread_t *child_thread = thread_list_smart_get(threads, child_tid);
  if (parent_tid != 0) { // initial thread has no parent
    thread_t *parent_thread = thread_list_smart_get(threads, parent_tid);
    thread_fork(parent_thread, child_thread);
  }
}

void process_join(int parent_tid, int child_tid) {
  info("--- JOIN: Thread %d joining %d\n", child_tid, parent_tid);

  thread_t *child_thread = thread_list_smart_get(threads, child_tid);
  thread_t *parent_thread = thread_list_smart_get(threads, parent_tid);
  thread_join(parent_thread, child_thread);
}

void process_lock(int tid, uintptr_t addr) {
  info("--- LOCK: Thread %d locked %p\n", tid, (void*)addr);

  thread_t *thread = thread_list_smart_get(threads, tid);
  lock_t *lock = lock_list_smart_get(locks, addr);
  lock_acquire(lock, thread);
}

void process_unlock(int tid, uintptr_t addr) {
  info("--- UNLOCK: Thread %d unlocked %p\n", tid, (void*)addr);

  thread_t *thread = thread_list_smart_get(threads, tid);
  lock_t *lock = lock_list_smart_get(locks, addr);
  lock_release(lock, thread);
}

void process_read(int tid, uintptr_t ld_addr, uintptr_t inst_addr) {
  debug("Processing: READ(%lx): %u %p\n", inst_addr, tid, ld_addr);
  
  thread_t *thread = thread_list_smart_get(threads, tid);
  variable_t *var = variable_list_smart_get(variables, ld_addr);
  if (!variable_update_read(var, thread)) {
    fprintf(stderr, "!!! READ RACE: Possible read race - %p by thread %d\n", (void*)ld_addr, tid);
    print_symbol_info(inst_addr);
  }
}

void process_write(int tid, uintptr_t st_addr, uintptr_t inst_addr) {
  debug("Processing: WRITE(%lx): %u %p\n", inst_addr, tid, st_addr);

  thread_t *thread = thread_list_smart_get(threads, tid);
  variable_t *var = variable_list_smart_get(variables, st_addr);
  if (!variable_update_write(var, thread)) {
    fprintf(stderr, "!!! WRITE RACE: Possible write race - %p by thread %d\n", (void*)st_addr, tid);
    print_symbol_info(inst_addr);
  }
}


/* 
  ## MAMBO PLUGIN ## 
  Track operations within underlying program.
*/ 

// join: map pthread_t value to tid of the same thread
mambo_ht_t *tid_map = NULL;


// ----------------
// READ/WRITE: TID ADDR
// ----------------
void handle_read_write(bool is_load, int tid, uintptr_t ld_st_addr, uintptr_t inst_addr) {
  if (ld_st_addr == 0) return;
  
  if (is_load) {
    process_read(tid, ld_st_addr, inst_addr);
  } else {
    process_write(tid, ld_st_addr, inst_addr);
  }
}

int ignore_usr_lib(uintptr_t addr) {
  char *sym_name, *filename;
  void *symbol_start_addr;

  get_symbol_info_by_addr(addr, &sym_name, &symbol_start_addr, &filename);
  
  // if filename starts with "/usr" then return true - ignore
  if (filename != NULL && strncmp(filename, "/usr", 4) == 0) {
    free(sym_name);
    free(filename);
    return 1;
  }

  free(sym_name);
  free(filename);
  return 0;
}

// capture load and store instructions
int datarace_pre_inst_handler(mambo_context *ctx) {
  uintptr_t inst_addr = (uintptr_t)mambo_get_source_addr(ctx);


// ignore libc
#ifdef NO_PIE_ENABLE
  // ignore libs. Underlying program must be compiled with -no-pie.
  if (inst_addr >= (uintptr_t) 0x7000000000) {
    return 0;
  }
#else
  // Use symbol data to ignore libc. libc must be located in /usr/.
  if (ignore_usr_lib(inst_addr)) {
    return 0;
  }
#endif // NO_PIE_ENABLE


  bool is_load = mambo_is_load(ctx);
  bool is_store = mambo_is_store(ctx);
  int tid = mambo_get_thread_id(ctx); // thread id

  if (is_load || is_store) {
    emit_push(ctx, (1 << x0) | (1 << x1) | (1 << x2) | (1 << x3));

    // calc address first!
    mambo_calc_ld_st_addr(ctx, reg2); // put load/store address in reg2
    emit_set_reg(ctx, reg3, inst_addr);
    emit_set_reg(ctx, reg1, tid);
    emit_set_reg(ctx, reg0, is_load); // is load or store
    emit_safe_fcall(ctx, handle_read_write, 4);

    emit_pop(ctx, (1 << x0) | (1 << x1) | (1 << x2) | (1 << x3));
  }

  return 0;
}


// ----------------
// LOCK: TID ADDR
// ----------------
void handle_lock(int tid, thread_data_t *thread_data) {
  process_lock(tid, (uintptr_t)thread_data->mutex); // handle function required
}

void lock_save_mutex(pthread_mutex_t *mutex, thread_data_t *thread_data) {
  thread_data->mutex = mutex; // save mutex in pre lock
}

// Capture the address of the lock that is to be acquired
int datarace_pre_pthread_lock(mambo_context *ctx) {
  thread_data_t *thread_data = mambo_get_thread_plugin_data(ctx);

  emit_push(ctx, (1 << x0) | (1 << x1));
  
  // reg0 holds address to mutex - int pthread_mutex_lock(pthread_mutex_t *mutex);
  emit_set_reg(ctx, reg1, (uintptr_t)thread_data);
  emit_safe_fcall(ctx, lock_save_mutex, 2); // Calls lock_save_mutex(*mutex, *thread_data)
  
  emit_pop(ctx, (1 << x0) | (1 << x1));

  return 0;
}

// The lock is successfully acquired after pthread_lock returns
int datarace_post_pthread_lock(mambo_context *ctx) {
  thread_data_t *thread_data = mambo_get_thread_plugin_data(ctx);

  int tid = mambo_get_thread_id(ctx); // thread id

  emit_push(ctx, (1 << x0) | (1 << x1));
  
  emit_set_reg(ctx, reg0, tid);
  emit_set_reg(ctx, reg1, (uintptr_t)thread_data);
  emit_safe_fcall(ctx, handle_lock, 2); // handle_lock(tid, thread_data)

  emit_pop(ctx, (1 << x0) | (1 << x1)); 

  return 0;
}

// ----------------
// UNLOCK: TID ADDR
// ----------------
int datarace_pre_pthread_unlock(mambo_context *ctx) {
  int tid = mambo_get_thread_id(ctx); // thread id

  emit_push(ctx, (1 << x0) | (1 << x1));
  
  emit_mov(ctx, reg1, reg0); // move mutex addr to reg1
  emit_set_reg(ctx, reg0, tid);
  emit_safe_fcall(ctx, process_unlock, 3);

  emit_pop(ctx, (1 << x0) | (1 << x1)); 

  return 0;
}


// ----------------
// PTHREAD JOIN 
// ---------------- 
void save_child_pth(dbm_thread *dbm_thread_data, void *pass_pthread_t) {
  /*  Store child's pthread_t value in parent's dbm thread data.
      The value is passed to the child when it's created.
      The child thread copies this value when it spawns */
  dbm_thread_data->shared_parent_data = pass_pthread_t;
}

int datarace_pre_clone(mambo_context *ctx) {
  emit_push(ctx, (1 << x0) | (1 << x1) | (1 << x2) | (1 << x3));

  // reg3 holds pthread_t value of the child thread to be spawned
  emit_mov(ctx, reg1, reg3);
  emit_set_reg(ctx, reg0, (uintptr_t) ctx->thread_data);
  emit_safe_fcall(ctx, save_child_pth, 2);

  emit_pop(ctx, (1 << x0) | (1 << x1) | (1 << x2) | (1 << x3)); 

  return 0;
}


void get_child_tid(void *joining_pthread_t, thread_data_t *thread_data) {
  // get tid of joining thread using its pthread_t and store in thread_data
  uintptr_t child_tid = 0;
  mambo_ht_get(tid_map, (uintptr_t) joining_pthread_t, &child_tid);
  thread_data->joining_tid = (int)child_tid;
}

int datarace_pre_pthread_join(mambo_context *ctx) {
  thread_data_t *thread_data = mambo_get_thread_plugin_data(ctx);

  emit_push(ctx, (1 << x0) | (1 << x1) | (1 << x2));
  
  // get tid of the thread joining using its pthread_t value passed 
  // as first arg - save this tid to be used in post join
  emit_set_reg(ctx, reg1, (uintptr_t) thread_data);
  emit_safe_fcall(ctx, get_child_tid, 2);

  emit_pop(ctx, (1 << x0) | (1 << x1) | (1 << x2)); 

  return 0;
}

// handle function required
void handle_join(int parent_tid, thread_data_t *thread_data) { 
  // commit join completed
  process_join(parent_tid, thread_data->joining_tid); 
}

// join operation complete when pthread_join returns
int datarace_post_pthread_join(mambo_context *ctx) {
  thread_data_t *thread_data = mambo_get_thread_plugin_data(ctx);
  int tid = mambo_get_thread_id(ctx);

  emit_push(ctx, (1 << x0) | (1 << x1)); 

  emit_set_reg(ctx, reg0, tid);
  emit_set_reg(ctx, reg1, (uintptr_t)thread_data);
  emit_safe_fcall(ctx, handle_join, 2);
		
  emit_pop(ctx, (1 << x0) | (1 << x1)); 
  return 0;
}

// ----------------
// MAMBO THREAD (data + FORK + JOIN data)
// ----------------
int datarace_pre_thread_handler(mambo_context *ctx) {
  thread_data_t *thread_data = mambo_alloc(ctx, sizeof(thread_data_t));
  mambo_set_thread_plugin_data(ctx, thread_data);

  int tid = mambo_get_thread_id(ctx);
  int parent_tid = mambo_get_parent_thread_id(ctx);

  // commit FORK(T, U)
  process_fork(parent_tid, tid);

  // JOIN - get pthread_t value of current thread passed by the parent thread.
  // This is the pthread_t value utilised by the underlying program.
  // Since dbm captures pthread_create, it creates a new pthread_t value which
  // cannot be related to the pthread_t value utilised by the underlying program.
  void *curr_pthread_id = ctx->thread_data->shared_parent_data;
  if (curr_pthread_id != NULL) {
    // map pthread_t value to tid
    int ret = mambo_ht_add(tid_map, (uintptr_t) curr_pthread_id, (uintptr_t) tid);
    assert(ret == 0);
  }

  return 0;
}

int datarace_post_thread_handler(mambo_context *ctx) {
  thread_data_t *thread_data = mambo_get_thread_plugin_data(ctx);
  mambo_free(ctx, thread_data);
  return 0;
}

// ----------------
// EXIT
// ----------------
int datarace_exit_handler(mambo_context *ctx) {
  // free data
  mambo_free(ctx, threads);
  mambo_free(ctx, locks);
  mambo_free(ctx, variables);
  mambo_free(ctx, tid_map);
  return 0;
}

__attribute__((constructor)) void datarace_trace_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  int set_cb = MAMBO_INVALID_CB;

  threads = mambo_alloc(ctx, sizeof(thread_list_t));
  thread_list_init(threads);
  locks = mambo_alloc(ctx, sizeof(lock_list_t));
  lock_list_init(locks);
  variables = mambo_alloc(ctx, sizeof(variable_list_t));
  variable_list_init(variables);

  tid_map = mambo_alloc(ctx, sizeof(mambo_ht_t));
  set_cb = mambo_ht_init(tid_map, 16, 0, 70, true);
  assert(set_cb == MAMBO_SUCCESS);
  

  set_cb = mambo_register_exit_cb(ctx, &datarace_exit_handler);
  assert(set_cb == MAMBO_SUCCESS);

  set_cb = mambo_register_pre_thread_cb(ctx, &datarace_pre_thread_handler);
  assert(set_cb == MAMBO_SUCCESS);

  set_cb = mambo_register_post_thread_cb(ctx, &datarace_post_thread_handler);
  assert(set_cb == MAMBO_SUCCESS);

  set_cb = mambo_register_pre_inst_cb(ctx, &datarace_pre_inst_handler);
  assert(set_cb == MAMBO_SUCCESS);

  set_cb = mambo_register_function_cb(ctx, 
                                      "__clone",
                                      &datarace_pre_clone,
                                      NULL,
                                      4);
  assert(set_cb == MAMBO_SUCCESS);
  

  set_cb = mambo_register_function_cb(ctx, 
                                      "pthread_mutex_lock",
                                      &datarace_pre_pthread_lock,
                                      &datarace_post_pthread_lock,
                                      2);

  assert(set_cb == MAMBO_SUCCESS);
  
  set_cb = mambo_register_function_cb(ctx,
                                      "pthread_mutex_unlock",
                                      &datarace_pre_pthread_unlock,
                                      NULL,
                                      2);
  assert(set_cb == MAMBO_SUCCESS);

  set_cb = mambo_register_function_cb(ctx,
                                      "pthread_join",
                                      &datarace_pre_pthread_join,
                                      &datarace_post_pthread_join,
                                      2);

}


#endif // PLUGINS_NEW
