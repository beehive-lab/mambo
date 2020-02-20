/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2017-2020 The University of Manchester

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

#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include "../../plugins.h"

int memcheck_bcmp(const void *s1, const void *s2, size_t n) {
  char *a = (char *)s1, *b = (char *)s2;
  for (size_t i = 0; i < n; i++) {
    if (a[i] != b[i]) return -1;
  }
  return 0;
}

char *memcheck_index(const char *s, int c) {
  char *ptr = (char *)s;
  for (; *ptr != '\0'; ptr++) {
    if (*ptr == c) return ptr;
  }
  if (c == '\0' && *ptr == '\0') return ptr;
  return NULL;
}

void *memcheck_memchr(const void *s, int c, size_t n) {
  unsigned char *p = (unsigned char *)s;
  for (size_t i = 0; i < n; i++) {
    if (p[i] == (unsigned char) c) return &p[i];
  }
  return NULL;
}

void *memcheck_rawmemchr(const void *s, int c) {
  return memcheck_memchr(s, c, SIZE_MAX);
}

char *memcheck_rindex(const char *s, int c) {
  char *ret = NULL;
  char *ptr = (char *)s;
  for (; *ptr != '\0'; ptr++) {
    if (*ptr == c) ret = ptr;
  }
  if (c == '\0' && *ptr == '\0') return ptr;
  return ret;
}

char *memcheck_stpcpy(char *dest, const char *src) {
  do {
    *dest = *src;
  } while(*src != '\0' && src++ && dest++);

  return dest;
}

int memcheck_strcmp(const char *s1, const char *s2) {
  uintptr_t i = 0;

  while(s1[i] == s2[i] && s1[i] != '\0') {
    i++;
  }
  if (s1[i] < s2[i]) return -1;
  if (s1[i] > s2[i]) return 1;
  return 0;
}

char *memcheck_strcpy(char *dest, const char *src) {
  size_t i;
  for (i = 0; src[i] != '\0'; i++) {
    dest[i] = src[i];
  }
  dest[i] = '\0';
  return dest;
}

size_t memcheck_strlen(const char *s) {
  size_t len = 0;
  for (len = 0; s[len] != '\0'; len++);
  return len;
}

int memcheck_strncmp(const char *s1, const char *s2, size_t n) {
  size_t i = 0;

  if (n == 0) return 0;

  while(s1[i] == s2[i] && s1[i] != '\0' && (i+1) < n) {
    i++;
  }
  if (s1[i] < s2[i]) return -1;
  if (s1[i] > s2[i]) return 1;
  return 0;
}

size_t memcheck_strnlen(const char *s, size_t maxlen) {
  size_t len = 0;
  for (len = 0; (len < maxlen) && (s[len] != '\0'); len++);
  return len;
}

char *memcheck_strchrnul(const char *s, int c) {
  char *p = (char *)s;
  for (; *p != (char)c && (*p != '\0') ; p++);
  return p;
}

size_t memcheck_strspn(const char *s, const char *accept) {
  size_t len = 0;
  char *p = (char *)s;
  for (; *p != '\0'; p++) {
    //printf("%c\n", *p);
    bool match = false;
    for (int i = 0; accept[i] != '\0' && !match; i++) {
      //printf(" %c\n", accept[i]);
      if (*p == accept[i]) {
        match = true;
        break;
      }
    }
    if (!match) return len;
    len++;
  } // end of the string
  return len;
}

size_t memcheck_strcspn(const char *s, const char *reject) {
  size_t len = 0;
  char *p = (char *)s;
  for (; *p != '\0'; p++) {
    for (int i = 0; reject[i] != '\0'; i++) {
      if (*p == reject[i]) {
        return len;
      }
    }
    len++;
  } // end of the string
  return len;
}

int memcheck_replace_strlen(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_strlen);
  assert(ret == 0);
}

int memcheck_replace_bcmp(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_bcmp);
  assert(ret == 0);
}

int memcheck_replace_index(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_index);
  assert(ret == 0);
}

int memcheck_replace_memchr(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_memchr);
  assert(ret == 0);
}

int memcheck_replace_rawmemchr(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_rawmemchr);
  assert(ret == 0);
}

int memcheck_replace_rindex(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_rindex);
  assert(ret == 0);
}

int memcheck_replace_stpcpy(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_stpcpy);
  assert(ret == 0);
}

int memcheck_replace_strcmp(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_strcmp);
  assert(ret == 0);
}

int memcheck_replace_strcpy(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_strcpy);
  assert(ret == 0);
}

int memcheck_replace_strncmp(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_strncmp);
  assert(ret == 0);
}

int memcheck_replace_strnlen(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_strnlen);
  assert(ret == 0);
}

int memcheck_replace_strchrnul(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_strchrnul);
  assert(ret == 0);
}

int memcheck_replace_strspn(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_strspn);
  assert(ret == 0);
}

int memcheck_replace_strcspn(mambo_context *ctx) {
  int ret = mambo_set_source_addr(ctx, memcheck_strcspn);
  assert(ret == 0);
}

void memcheck_install_naive_stdlib(mambo_context *ctx) {
  int ret;
  /* Replace the stdlib functions which use hand-optimised assembly with
     deliberate out-of-bounds accesses with naive versions*/ 
  ret = mambo_register_function_cb(ctx, "bcmp", &memcheck_replace_bcmp, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "index", &memcheck_replace_index, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "memchr", &memcheck_replace_memchr, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "rawmemchr", &memcheck_replace_rawmemchr, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "rindex", &memcheck_replace_rindex, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "stpcpy", &memcheck_replace_stpcpy, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "strchrnul", &memcheck_replace_strchrnul, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "strcmp", &memcheck_replace_strcmp, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "strcpy", &memcheck_replace_strcpy, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "strlen", &memcheck_replace_strlen, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "strncmp", &memcheck_replace_strncmp, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "strnlen", &memcheck_replace_strnlen, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "strspn", &memcheck_replace_strspn, NULL, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "strcspn", &memcheck_replace_strcspn, NULL, 1);
  assert(ret == MAMBO_SUCCESS);
}
