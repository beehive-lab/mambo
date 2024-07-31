#ifndef DATARACE_H
#define DATARACE_H

#include "detectors/detector.h"

#include <pthread.h>
#include <stdint.h>

#if !defined(FASTTRACK) && !defined(DJIT)
  #error "Neither DJIT nor FASTTRACK is defined"
#endif


/* 
  Define this if exe run under mambo is compiled with -no-pie. (Recommended)
  Otherwise exe must be dynamically linked with libs at /usr/.
  Required to ignore data race detection in libc.
*/
#define NO_PIE_ENABLE

/*
  Enable for more verbose information. (Recommended)
  Prints fork, join, lock, unlock operations for easier debugging of races.
*/
#define INFO
#ifdef INFO
  #define info(...) fprintf(stderr, __VA_ARGS__)
#else
  #define info(...)
#endif

#ifdef DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define debug(...)
#endif

typedef struct thread_data {
  pthread_mutex_t *mutex;
  uint64_t joining_tid; // tid associated with pthread_t in pre join
} thread_data_t;

#endif // DATARACE_H
