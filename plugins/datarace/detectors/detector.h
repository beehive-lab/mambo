#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include "../../../api/hash_table.h"

// Currently support up to VC_INITIAL_SZ threads
#define VC_INITIAL_SZ 8

// TODO: Add destructors/free functions

// VECTOR CLOCK //
typedef struct {
  int *clocks;
  size_t size;
  pthread_mutex_t lock;
} vector_clock_t;

// EPOCH //
#ifdef FASTTRACK
typedef struct {
    int clock;
    int thread_idx;
    pthread_mutex_t lock;
} epoch_t;
#endif // EPOCH

int vector_clock_init(vector_clock_t *vc, size_t size);
int vector_clock_get(vector_clock_t *vc, int idx);
void vector_clock_increment(vector_clock_t *vc, int idx);
void vector_clock_set(vector_clock_t *vc, int idx, int clock);
int vector_clock_update(vector_clock_t *vc, vector_clock_t *other_vc);
int vector_clock_happens_before(vector_clock_t *vc, vector_clock_t *other_vc);


// THREAD //
typedef struct {
  size_t idx;
  vector_clock_t *vc;
} thread_t;

int thread_init(thread_t *t, int thread_idx);
int thread_get_clock(thread_t *t);
int thread_get_idx(thread_t *t);
void thread_increment(thread_t *t);
void thread_update_vc(thread_t *t, vector_clock_t *other_clock);
void thread_fork(thread_t *parent_thread, thread_t *child_thread);
void thread_join(thread_t *parent_thread, thread_t *child_thread);


// LOCK //
typedef struct {
  vector_clock_t *vc;
} lock_t;

int lock_init(lock_t *l);
void lock_acquire(lock_t *lock, thread_t *thread);
void lock_release(lock_t *lock, thread_t *thread);


// VARIABLE //
#if defined(FASTTRACK)
typedef struct {
  vector_clock_t *rx_vc;
  epoch_t *rx_epoch;
  epoch_t *wx_epoch;
  bool is_shared;
} variable_t;

#elif defined(DJIT)
typedef struct {
  vector_clock_t *rx;
  vector_clock_t *wx;
} variable_t;

#endif // VARIABLE

int variable_init(variable_t *v);
int variable_read_is_race_free(variable_t *v, vector_clock_t *thread_clock);
int variable_write_is_race_free(variable_t *v, vector_clock_t *thread_clock);
int variable_update_read(variable_t *v, thread_t *thread);
int variable_update_write(variable_t *v, thread_t *thread);


// Lists
// ThreadList
typedef struct {
  thread_t **threads; // array of threads
  size_t size;
  size_t capacity;
  mambo_ht_t *tid_index_ht; // tid -> index ht
  pthread_mutex_t lock;
} thread_list_t;

typedef struct {
  lock_t **locks;
  size_t size;
  size_t capacity;
  mambo_ht_t *addr_index_ht; // address -> index ht
  pthread_mutex_t lock;
} lock_list_t;

typedef struct {
  variable_t **variables;
  size_t size;
  size_t capacity;
  mambo_ht_t *addr_index_ht; // address -> index ht
  pthread_mutex_t lock;
} variable_list_t;

// smart_get: return if item in list, else adds it and returns it

int thread_list_init(thread_list_t *list);
thread_t *thread_list_append(thread_list_t *list, uint64_t tid);
thread_t *thread_list_smart_get(thread_list_t *list, uint64_t tid);

int lock_list_init(lock_list_t *list);
lock_t *lock_list_append(lock_list_t *list, uintptr_t addr);
lock_t *lock_list_smart_get(lock_list_t *list, uintptr_t addr);

int variable_list_init(variable_list_t *list);
variable_t *variable_list_append(variable_list_t *list, uintptr_t addr);
variable_t *variable_list_smart_get(variable_list_t *list, uintptr_t addr);


#endif // DETECTOR_H
