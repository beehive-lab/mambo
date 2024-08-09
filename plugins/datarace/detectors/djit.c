#include "detector.h"

#include <stdio.h>
#include <assert.h>

// VECTOR CLOCK //
int vector_clock_init(vector_clock_t *vc, size_t size) {
  pthread_mutex_init(&vc->lock, NULL);
  vc->size = size;

  vc->clocks = calloc(size, sizeof(int));
  if (vc->clocks == NULL) return -1;

  return 1;
}

int vector_clock_get(vector_clock_t *vc, int idx) {
  if (idx >= 0 && idx < vc->size) {
    return vc->clocks[idx];
  }

  return -1;
}

void vector_clock_increment(vector_clock_t *vc, int idx) {
  pthread_mutex_lock(&vc->lock);
  assert(idx >= 0);
  assert(idx < vc->size);

  ++vc->clocks[idx];
  pthread_mutex_unlock(&vc->lock);
}

void vector_clock_set(vector_clock_t *vc, int idx, int clock) {
  pthread_mutex_lock(&vc->lock);
  
  vc->clocks[idx] = clock;
  pthread_mutex_unlock(&vc->lock);
}

int vector_clock_update(vector_clock_t *vc, vector_clock_t *other_vc) {
  pthread_mutex_lock(&vc->lock);

  // vc[i] = max(vc[i], other_vc[i])
  for (size_t i = 0; i < other_vc->size; ++i) {
    if (vc->clocks[i] < other_vc->clocks[i]) {
      vc->clocks[i] = other_vc->clocks[i];
    }
  }

  pthread_mutex_unlock(&vc->lock);
  return 1;
}

int vector_clock_happens_before(vector_clock_t *vc, vector_clock_t *other_vc) {
  pthread_mutex_lock(&vc->lock);
  pthread_mutex_lock(&other_vc->lock);
  int min_size = (vc->size < other_vc->size) ? vc->size : other_vc->size;
  
  for (int i = 0; i < min_size; ++i) {
    if (vc->clocks[i] > other_vc->clocks[i]) {
      pthread_mutex_unlock(&vc->lock);
      pthread_mutex_unlock(&other_vc->lock);
      return 0; // false
    }
  }

  pthread_mutex_unlock(&vc->lock);
  pthread_mutex_unlock(&other_vc->lock);
  return 1; // true
}


// THREAD //
int thread_init(thread_t *t, int thread_idx) {
  t->idx = thread_idx;

  t->vc = malloc(sizeof(vector_clock_t));
  if (t->vc == NULL)
    return -1;
  if (vector_clock_init(t->vc, VC_INITIAL_SZ) == -1)
    return -1;

  vector_clock_increment(t->vc, t->idx); 

  return 1;
}

int thread_get_clock(thread_t *t) {
  return vector_clock_get(t->vc, t->idx);
}

int thread_get_idx(thread_t *t) {
  return t->idx;
}

void thread_increment(thread_t *t) {
  vector_clock_increment(t->vc, t->idx);
}
void thread_update_vc(thread_t *t, vector_clock_t *other_clock) {
  vector_clock_update(t->vc, other_clock);
}

void thread_fork(thread_t *parent_thread, thread_t *child_thread) {
  // Cu = Cu join Ct
  // Ct += 1
  thread_update_vc(child_thread, parent_thread->vc);
  thread_increment(parent_thread);
}

void thread_join(thread_t *parent_thread, thread_t *child_thread) {
  thread_update_vc(parent_thread, child_thread->vc);
  thread_increment(child_thread);
}

// LOCK //
int lock_init(lock_t *l) {
  l->vc = malloc(sizeof(vector_clock_t));
  if (l->vc == NULL)
    return -1;
  if (vector_clock_init(l->vc, VC_INITIAL_SZ) == -1) {
    free(l->vc);
    return -1;
  }
  
  return 1;
}

void lock_acquire(lock_t *l, thread_t *t) {
  thread_update_vc(t, l->vc);
}
void lock_release(lock_t *l, thread_t *t) {
  vector_clock_update(l->vc, t->vc);
  thread_increment(t);
}


// VARIABLE //
int variable_init(variable_t *v) {
  v->rx = malloc(sizeof(vector_clock_t));
  if (v->rx == NULL)
    return -1;
  if (vector_clock_init(v->rx, VC_INITIAL_SZ) == -1) {
    free(v->rx);
    return -1;
  }

  v->wx = malloc(sizeof(vector_clock_t));
  if (v->wx == NULL) {
    free(v->rx);
    return -1;
  }
  if (vector_clock_init(v->wx, VC_INITIAL_SZ) == -1) {
    free(v->rx);
    free(v->wx);
    return -1;
  }

  return 1;
}

int variable_read_is_race_free(variable_t *v, vector_clock_t *thread_clock) {
  return vector_clock_happens_before(v->wx, thread_clock);
}

int variable_write_is_race_free(variable_t *v, vector_clock_t *thread_clock) {
  return vector_clock_happens_before(v->wx, thread_clock) &&
         vector_clock_happens_before(v->rx, thread_clock);
}

int variable_update_read(variable_t *v, thread_t *t) {
  if (variable_read_is_race_free(v, t->vc)) {
    vector_clock_set(v->rx, t->idx, thread_get_clock(t));
    return 1; // true
  }
  return 0; // false
}

int variable_update_write(variable_t *v, thread_t *t) {
  if (variable_write_is_race_free(v, t->vc)) {
    vector_clock_set(v->wx, t->idx, thread_get_clock(t));
    return 1; // true
  }
  return 0; // false
}


int thread_list_init(thread_list_t *list) {
  pthread_mutex_init(&list->lock, NULL);

  list->size = 0;
  list->capacity = VC_INITIAL_SZ;

  list->threads = malloc(list->capacity * sizeof(thread_t *));
  for (int i = 0; i < list->capacity; ++i) {
    list->threads[i] = NULL;
  }

  list->tid_index_ht = malloc(sizeof(mambo_ht_t));
  mambo_ht_init(list->tid_index_ht, VC_INITIAL_SZ, 0, 90, true);

  return 1;
}

thread_t *thread_list_append(thread_list_t *list, uint64_t tid) {
  if (list->size == list->capacity) {
    list->capacity *= 2;
    list->threads = realloc(list->threads, list->capacity * sizeof(thread_t *));
  }
  
  // create new thread
  thread_t *new_thread = malloc(sizeof(thread_t));
  thread_init(new_thread, list->size);
  
  // link tid to index
  mambo_ht_add(list->tid_index_ht, tid, list->size);
  list->threads[list->size] = new_thread;
  
  ++list->size;
  return new_thread;
}

thread_t *thread_list_smart_get(thread_list_t *list, uint64_t tid) {
  pthread_mutex_lock(&list->lock);

  uint64_t index = -1;
  int ret = mambo_ht_get(list->tid_index_ht, tid, &index);

  if (ret == -1) {
    pthread_mutex_unlock(&list->lock);
    return thread_list_append(list, tid);
  }

  pthread_mutex_unlock(&list->lock);
  return list->threads[index];
}


int lock_list_init(lock_list_t *list) {
  pthread_mutex_init(&list->lock, NULL);

  list->size = 0;
  list->capacity = VC_INITIAL_SZ;

  list->locks = malloc(list->capacity * sizeof(lock_t *));
  for (int i = 0; i < list->capacity; ++i) {
    list->locks[i] = NULL;
  }

  list->addr_index_ht = malloc(sizeof(mambo_ht_t));
  mambo_ht_init(list->addr_index_ht, VC_INITIAL_SZ, 0, 90, true);

  return 1;
}

lock_t *lock_list_append(lock_list_t *list, uint64_t tid) {
  if (list->size == list->capacity) {
    list->capacity *= 2;
    list->locks = realloc(list->locks, list->capacity * sizeof(lock_t *));
  }
  // create new thread
  lock_t *new_lock = malloc(sizeof(lock_t));
  lock_init(new_lock);

  // link tid to index
  mambo_ht_add(list->addr_index_ht, tid, list->size);
  list->locks[list->size] = new_lock;

  ++list->size;
  return new_lock;
}

lock_t *lock_list_smart_get(lock_list_t *list, uint64_t tid) {
  pthread_mutex_lock(&list->lock);

  uint64_t index = -1;
  int ret = mambo_ht_get(list->addr_index_ht, tid, &index);

  if (ret == -1) {
    pthread_mutex_unlock(&list->lock);
    return lock_list_append(list, tid);
  }

  pthread_mutex_unlock(&list->lock);
  return list->locks[index];
}

int variable_list_init(variable_list_t *list) {
  pthread_mutex_init(&list->lock, NULL);

  list->size = 0;
  list->capacity = VC_INITIAL_SZ;

  list->variables = malloc(list->capacity * sizeof(variable_t *));
  for (int i = 0; i < list->capacity; ++i) {
    list->variables[i] = NULL;
  }

  list->addr_index_ht = malloc(sizeof(mambo_ht_t));
  mambo_ht_init(list->addr_index_ht, VC_INITIAL_SZ, 0, 90, true);

  return 1;
}

variable_t *variable_list_append(variable_list_t *list, uint64_t tid) {
  if (list->size == list->capacity) {
    list->capacity *= 2;
    list->variables = realloc(list->variables, list->capacity * sizeof(variable_t *));
  }
  // create new thread
  variable_t *new_variable = malloc(sizeof(variable_t));
  variable_init(new_variable);

  // link tid to index
  mambo_ht_add(list->addr_index_ht, tid, list->size);
  list->variables[list->size] = new_variable;

  ++list->size;
  return new_variable;
}

variable_t *variable_list_smart_get(variable_list_t *list, uint64_t tid) {
  pthread_mutex_lock(&list->lock);

  uint64_t index = -1;
  int ret = mambo_ht_get(list->addr_index_ht, tid, &index);

  if (ret == -1) {
    pthread_mutex_unlock(&list->lock);
    return variable_list_append(list, tid);
  }

  pthread_mutex_unlock(&list->lock);
  return list->variables[index];
}

