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

// On AArch64, compile with TEXT_SEGMENT = 0x7000000000

#include <sys/mman.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

#include "../../plugins.h"

#include "memcheck.h"

extern void memcheck_install_naive_stdlib(mambo_context *ctx);


#define IS_STORE (1 << 15)

#define MAGIC_FREED (UINTPTR_MAX-1)

void *shadow_mem = NULL;
void *loader_base = NULL;

extern void memcheck_malloc_pre();
extern void memcheck_malloc_post();
extern void memcheck_free_pre();
extern void memcheck_free_post();
extern void memcheck_unalloc();

mambo_ht_t allocs;

typedef struct {
  uintptr_t in_malloc;
} memcheck_thread_t;

typedef struct {
  size_t size;
} malloc_header_t;

int print_backtrace(void *data, void *addr, char *sym_name, void *symbol_base, char *filename) {
  fprintf(stderr, "==memcheck==  at [%s]+%p (%p) in %s\n", sym_name, (void *)(addr - symbol_base), addr, filename);
  return 0;
}

void memcheck_print_error(void *addr, uintptr_t meta, void *pc, stack_frame_t *frame) {
  bool is_store = meta & IS_STORE;
  size_t size = meta & (~IS_STORE);

  char *filename;
  char *symbol;
  void *symbol_base;
  int ret = get_symbol_info_by_addr((uintptr_t)pc, &symbol, &symbol_base, &filename);
#ifdef MC_IGNORE_INTERP
  if(symbol_base == loader_base) return;
#endif

  fprintf(stderr, "\n==memcheck== Invalid %s (size %zu) %s %p\n", is_store ? "store" : "load", size, is_store ? "to" : "from", addr);

  if (ret == 0) {
    while(filename == NULL || symbol_base == NULL);
    fprintf(stderr, "==memcheck==  at [%s]+%p (%p) in %s\n", symbol, (void *)(pc - symbol_base), pc, filename);
    free(filename);
    free(symbol);
  } else {
    fprintf(stderr, "==memcheck==  at %p\n", pc);
  }

  fprintf(stderr, "==memcheck==  Backtrace:\n");
  get_backtrace(frame, &print_backtrace, NULL);
  
  fprintf(stderr, "\n");
}

void memcheck_mark(void *start, size_t size, bool valid) {
  assert(start < (void *)RESERVED_BASE
        && (start + size) < (void *)RESERVED_BASE
        && (start + size) >= start);

  if (size == 0) return;

#ifdef COMPACT_SHADOW
  void *shadow_addr = (void *)RESERVED_BASE + (((uintptr_t)start) / 8);
  uintptr_t start_b_offset = (uintptr_t)start & 0x7;

  if (start_b_offset) {
    uint8_t mask = (1 << max(size, 8)) - 1;
    uint8_t *sb = shadow_addr;
    if (valid) {
      *sb |= (mask << start_b_offset);
    } else {
      *sb &= ~(mask << start_b_offset);
    }
    shadow_addr++;
    size -= start_b_offset;
    while(1);
  }

  if (size > 0) {
    uintptr_t end_b_offset = ((uintptr_t)start + size);
    uintptr_t end_b_size = end_b_offset & 0x7;
    if (end_b_size) {
      uint8_t *eb = (void *)RESERVED_BASE + end_b_offset / 8;
      if (valid) {
        *eb |= (0xFF >> (8-end_b_size));
      } else {
        *eb &= ~(0xFF >> (8-end_b_size));
      }
      size -= end_b_size;
    }
  }
  
  if (size) {
    memset(shadow_addr, valid ? 0xFF : 0, size/8);
  }

#else
  memset(start + RESERVED_BASE, valid ? 1 : 0, size);
#endif
}

void memcheck_mark_valid(void *start, size_t size) {
  return memcheck_mark(start, size, true);
}

void memcheck_mark_invalid(void *start, size_t size) {
  return memcheck_mark(start, size, false);
}

void memcheck_alloc_hook(void *start, size_t size) {
  int ret = mambo_ht_add(&allocs, (uintptr_t)start, (uintptr_t)size);
  assert(ret == 0);
  memcheck_mark_valid(start, size);
}

void memcheck_free_hook(void *start, size_t size) {
  if (start == NULL) return;

  uintptr_t alloc_size;
  int ret = mambo_ht_get(&allocs, (uintptr_t)start, &alloc_size);
  if (ret != 0) {
    fprintf(stderr, "\n==memcheck== invalid free for %p\n\n", start);
    return;
  }
  size = alloc_size;

  if (size == MAGIC_FREED) {
    fprintf(stderr, "\n==memcheck== double free for %p\n\n", start);
  } else {
    ret = mambo_ht_add(&allocs, (uintptr_t)start, MAGIC_FREED);
    assert(ret == 0);

    memcheck_mark_invalid(start, size);
  }
}

void set_in_malloc_ptr(mambo_context *ctx, enum reg reg) {
  memcheck_thread_t *td = mambo_get_thread_plugin_data(ctx);
  assert(td != NULL);
  emit_set_reg(ctx, reg, (uintptr_t)&td->in_malloc);
}

void __memcheck_inst_aarch32(mambo_context *ctx, int size) {
#ifdef __arm__
  while (size > 24);

  inst_set type = mambo_get_inst_type(ctx);
  if (type == ARM_INST) {
    emit_add_sub_i(ctx, pc, pc, -3);
  }

  /*
    AND R1, R0, #7
    BIC R2, R0, #0x80000000 // mask off high bit
    LSR R2, R2, #3
    ORR R2, R2, RESERVED_BASE
    MOV R3, MASK (based on access size)
    LSL R3, R3, R1
    LDR R1, [R2]
    AND R1, R1, R3
    EOR R1, R1, R3
  */
  emit_thumb_andi32(ctx, 0, 0, r0, 0, r1, 7);
  uint32_t imm12 = 0x400;
  emit_thumb_bici32(ctx, imm12 >> 11, 0, r0, imm12 >> 8, r2, imm12);
  emit_thumb_lsri32(ctx, 0, 0, r2, 3, r2);
  emit_thumb_orri32(ctx, imm12 >> 11, 0, r2, imm12 >> 8, r2, imm12);

  ctx->code.inst_type = THUMB_INST;
  emit_set_reg(ctx, r3, (1 << size) -1);
  ctx->code.inst_type = type;

  emit_thumb_lsl32(ctx, 0, r3, r3, r1);
  emit_thumb_ldri16(ctx, 0, r2, r1);
  emit_thumb_and32(ctx, 0, r1, 0, r1, 0, 0, r3);
  emit_thumb_eor32(ctx, 0, r1, 0, r1, 0, 0, r3);
#endif
}

void __memcheck_inst_aarch64(mambo_context *ctx, int size) {
#ifdef __aarch64__
  // AND X1, X0, #7
  emit_a64_logical_immed(ctx, 1, 0, 1, 0, 2, x0, x1);
  // AND X2, X0, #(RESERVED_BASE -1) 0x3F_FFFF_FFFF
  emit_a64_logical_immed(ctx, 1, 0, 1, 0, 37, x0, x2);
  // LSR X2, X2, #3
  emit_a64_BFM(ctx, 1, 2, 1, 3, 0x3F, x2, x2);
  // ORR X2, X2, RESERVED_BASE (0x40_0000_0000)
  emit_a64_logical_immed(ctx, 1, 1, 1, 26, 0, x2, x2);
  // MOV X3, #mask
  emit_a64_logical_immed(ctx, 1, 1, 1, 0, size-1, 0x1F, x3);
  // LSL X3, X3, X1
  emit_a64_data_proc_reg2(ctx, 1, x1, 0x8, x3, x3);
  // LDR X1, [X2]
  emit_a64_LDR_STR_unsigned_immed(ctx, 3, 0, 1, 0, x2, x1);
  // AND X1, X1, X3
  emit_a64_logical_reg(ctx, 1, 0, 0, 0, x3, 0, x1, x1);
  // EOR X1, X1, X3
  emit_a64_logical_reg(ctx, 1, 2, 0, 0, x3, 0, x1, x1);
#endif
}

// Pattern matching accesses which cause false positives
bool memcheck_should_ignore(mambo_context *ctx) {
  uint32_t iw = *(uint32_t *)mambo_get_source_addr(ctx);
#ifdef __aarch64__
  #ifdef MC_IGNORE_LIST
  if (iw == 0x4cdfa041 ||  // strchr
      iw == 0x4cdfa061 ||  // memchr
      iw == 0xa9410c22 ||  // strlen + 0x70
      iw == 0xa9400c02 ||  // strlen + 0x10
      iw == 0xf8408402 ||  // strcmp + 0x18
      iw == 0xf8408423 ||  // strcmp + 0x1c
      iw == 0xa9401424 ||  // __stpcpy + 0x18
      iw == 0xa9c20c22 ||  // strlen + 0x58
      iw == 0xf8408403 ||  // strncmp + 0x24
      iw == 0xa8c11043 ||  // strnlen + 0x94
      iw == 0xa9c10c22 ||  // strlen + 0xc4
      iw == 0xa9400c22 ||  // strlen + 0x114
      iw == 0xa8c11444 ||  // strcpy + 0xd8
      iw == 0xf8408424 ||  // bcmp + 0x24
      iw == 0x39400820 ||  // strcspn + 0xdc
      iw == 0x39400c22 ||  // strcspn + 0xe0
      iw == 0x39400424 ||  // strcspn + +0xe4
      iw == 0x39400c43     // strspn + 0xe4
  ) return true;
  #endif

  if (mambo_get_inst(ctx) == A64_LDX_STX) {
    uint32_t size, o2, l, o1, rs, o0, rt2, rn, rt;
    a64_LDX_STX_decode_fields(mambo_get_source_addr(ctx), &size, &o2, &l, &o1, &rs, &o0, &rt2, &rn, &rt);
    // don't instrument store exclusive
    if (o2 == 0 && l == 0 && o1 == 0) {
      return true;
    }
  }
#elif __arm__ && MC_IGNORE_LIST
  inst_set inst_type = mambo_get_inst_type(ctx);
  if (inst_type == THUMB_INST) {
    if (iw == 0x2300e9d1 || // strlen + 0x23
        iw == 0x2302e9d1 || // strlen + 0x41
        iw == 0x2304e9d1 || // strlen + 0x5b
        iw == 0x2306e9d1 || // strlen + 0x75
        iw == 0x2304e8f0 || // strlen + 0x6f
        iw == 0x6704e8f1 || // strcmp + 0x73
        iw == 0x2302e950 || // strcmp + 0x93
        iw == 0x6702e951 || // strcmp + 0x97
        iw == 0x2b08f850 || // strcmp + 0x115
        iw == 0x3b08f851 || // strcmp + 0x119
        iw == 0x2c04f850 || // strcmp + 0x12b
        iw == 0x3c04f851 || // strcmp + 0x12f
        iw == 0x3b04f851 || // strcmp + 0x1eb
        iw == 0x2b04f850 || // strcmp + 0x291
        iw == 0xea4f680b || // strcmp + 0x2a3
        iw == 0x4b04f853 || // strnlen + 0x2d
        iw == 0x2302e8f0    // rawmemchr + 0x57
    ) return true;
  } else if (inst_type == ARM_INST) {
    if (iw == 0x00c020d8 || // index + 0x84
        iw == 0xe491e004 || // memcpy + 0x1b4
        iw == 0xe0c340d8 || // rindex + 0x48
        iw == 0xe493c004    // strnlen + 0x68
    ) return true;
  }
#endif
  return false;
}

int memcheck_pre_inst_handler(mambo_context *ctx) {
  int ret;
  if (mambo_is_load_or_store(ctx)) {
    if (memcheck_should_ignore(ctx)) return 0;

    mambo_cond cond = mambo_get_cond(ctx);
    mambo_branch cond_br;
    mambo_branch zbr;

    if (cond != AL) {
      ret = mambo_reserve_branch(ctx, &cond_br);
      assert(ret == 0);
    }

#ifdef __arm__
    ret = mambo_reserve_cc_space(ctx, 88);
    assert(ret == 0);
#endif

#ifdef COMPACT_SHADOW
    int access_size = mambo_get_ld_st_size(ctx);
    bool is_store = mambo_is_store(ctx);
    
    emit_push(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3));

    mambo_calc_ld_st_addr(ctx, 0);
    __memcheck_inst_aarch64(ctx, min(access_size, 56));
    __memcheck_inst_aarch32(ctx, min(access_size, 24));
  #ifdef __arm__
    inst_set type = mambo_get_inst_type(ctx);
    ctx->code.inst_type = THUMB_INST;
  #endif
    mambo_reserve_branch_cbz(ctx, &zbr);

    emit_push(ctx, (1 << 4) | (1 << lr));

    emit_set_reg(ctx, 1, access_size | (is_store ? IS_STORE : 0));
    emit_set_reg(ctx, 2, (uintptr_t)mambo_get_source_addr(ctx));
    set_in_malloc_ptr(ctx, 3);
    emit_fcall(ctx, memcheck_unalloc);

    emit_pop(ctx, (1 << 4) | (1 << lr));

    emit_local_branch_cbz(ctx, &zbr, 1);
  #ifdef __arm__
    if (type == ARM_INST) {
      if ((uintptr_t)ctx->code.write_p & 2) {
        emit_thumb_nop16(ctx);
      }
      emit_thumb_bx16(ctx, pc);
      emit_thumb_nop16(ctx);
    }
    ctx->code.inst_type = type;
  #endif

    emit_pop(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3));
    if (cond != AL) {
      ret = emit_local_branch_cond(ctx, &cond_br, invert_cond(cond));
      assert(ret == 0);
    }

#else
    int regs[2];
    ret = mambo_get_scratch_regs(ctx, 2, &regs[0], &regs[1]);
    assert(ret == 2);

    mambo_calc_ld_st_addr(ctx, regs[0]);

    emit_set_reg(ctx, regs[1], RESERVED_BASE);
    emit_a64_LDR_STR_reg(ctx, 0, 0, 1, regs[0], 2, 0, regs[1], regs[1]);

    mambo_reserve_branch_cbz(ctx, &cbz);

    emit_push(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << lr));
    emit_mov(ctx, 0, regs[0]);
    emit_set_reg(ctx, 1, mambo_get_ld_st_size(ctx) | (mambo_is_store(ctx) ? IS_STORE : 0));
    emit_set_reg(ctx, 2, (uintptr_t)mambo_get_source_addr(ctx));
    set_in_malloc_ptr(ctx, 3);
    emit_fcall(ctx, memcheck_unalloc);
    emit_pop(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << lr));

    emit_local_branch_cbz(ctx, &zbr, regs[1]);

    ret = mambo_free_scratch_regs(ctx, (1 << regs[0]) | (1 << regs[1]));
    assert(ret == 0);
#endif
  }

  return 0;
}

int _memcheck_inst_alloc_reg(mambo_context *ctx, enum reg reg) {
  emit_mov(ctx, es, reg);
  set_in_malloc_ptr(ctx, es-1);
  emit_fcall(ctx, memcheck_malloc_pre);
  return 0;
}

int memcheck_inst_alloc0(mambo_context *ctx) {
  return _memcheck_inst_alloc_reg(ctx, 0);
}

int memcheck_inst_alloc1(mambo_context *ctx) {
  return _memcheck_inst_alloc_reg(ctx, 1);
}

int memcheck_inst_alloc_post(mambo_context *ctx) {
  set_in_malloc_ptr(ctx, es-1);
  emit_fcall(ctx, memcheck_malloc_post);
  return 0;
}

const enum reg sr1 = es + 1, sr2 = es + 2;

int memcheck_inst_posix_memalign(mambo_context *ctx) {
  emit_push(ctx, (1 << sr1) | (1 << sr2));
  emit_mov(ctx, es, 2);
  emit_mov(ctx, sr1, 0);
  set_in_malloc_ptr(ctx, es-1);

  // BL memcheck_malloc_pre
  emit_fcall(ctx, memcheck_malloc_pre);
}

int memcheck_inst_posix_memalign_post(mambo_context *ctx) {
  emit_mov(ctx, sr2, 0); // keep the return value in SR2

#ifdef __aarch64__
  // LDR X0, [sr1]
  emit_a64_LDR_STR_unsigned_immed(ctx, 3, 0, 1, 0, sr1, 0);
#elif __arm__
  // LDR R0, [sr1]
  switch(mambo_get_inst_type(ctx)) {
    case ARM_INST:
      emit_arm_ldr(ctx, IMM_LDR, r0, sr1, 0, 1, 1, 0);
      break;
    case THUMB_INST:
      emit_thumb_ldri16(ctx, 0, sr1, r0);
      break;
    default:
      assert(0);
  }
#endif

  set_in_malloc_ptr(ctx, es-1);

  // BL memcheck_malloc_post
  emit_fcall(ctx, memcheck_malloc_post);

  emit_mov(ctx, 0, sr2); // restore the return value

  emit_pop(ctx, (1 << sr1) | (1 << sr2));
}

int memcheck_inst_calloc(mambo_context *ctx) {
#ifdef __aarch64__
  // MUL X19, X0, X1
  emit_a64_data_proc_reg3(ctx, 1, 0, x0, 0, 0x1F, x1, x19);
#elif __arm__
  switch (mambo_get_inst_type(ctx)) {
    case ARM_INST:
      emit_arm_mul(ctx, es, r0, r1);
      break;
    case THUMB_INST:
      emit_thumb_mul32(ctx, r0, es, r1);
      break;
    default:
      assert(0);
  }
#endif
  set_in_malloc_ptr(ctx, es-1);
  emit_fcall(ctx, memcheck_malloc_pre);
}

int memcheck_inst_realloc(mambo_context *ctx) {
  emit_mov(ctx, es, 1);
  set_in_malloc_ptr(ctx, es-1);
  emit_fcall(ctx, memcheck_free_pre);
}

int memcheck_inst_free(mambo_context *ctx) {
  memcheck_thread_t *td = mambo_get_thread_plugin_data(ctx);
  assert(td != NULL);

  emit_set_reg(ctx, es-1, (uintptr_t)&td->in_malloc);

  // BL memcheck_free_pre
  emit_fcall(ctx, memcheck_free_pre);
}

int memcheck_inst_free_post(mambo_context *ctx) {
  memcheck_thread_t *td = mambo_get_thread_plugin_data(ctx);
  assert(td != NULL);

  emit_set_reg(ctx, es-1, (uintptr_t)&td->in_malloc);
  emit_fcall(ctx, memcheck_free_post);
}

int memcheck_inst_ignored_fn(mambo_context *ctx) {
  set_in_malloc_ptr(ctx, es-1);
  emit_fcall(ctx, memcheck_malloc_pre);
}

int memcheck_inst_ignored_fn_post(mambo_context *ctx) {
  set_in_malloc_ptr(ctx, es-1);
  emit_fcall(ctx, memcheck_free_post);
}

int memcheck_vm_op_handler(mambo_context *ctx) {
  memcheck_thread_t *td = mambo_get_thread_plugin_data(ctx);

  if (td == NULL || !td->in_malloc) {
    vm_op_t op = mambo_get_vm_op(ctx);
    switch(op) {
      case VM_MAP:
        memcheck_mark_valid(mambo_get_vm_addr(ctx), mambo_get_vm_size(ctx));
        if (loader_base == NULL && (mambo_get_vm_flags(ctx) & MAP_INTERP)) {
          loader_base = mambo_get_vm_addr(ctx);
        }
        break;
      case VM_UNMAP:
        memcheck_mark_invalid(mambo_get_vm_addr(ctx), mambo_get_vm_size(ctx));
        break;
    }
  }
}

void extend_stack() {
  // First, increase our stack allocation
  uint8_t *stack = alloca(1024*1024);
  stack[0] = 1;
}

int memcheck_pre_thread_handler(mambo_context *ctx) {
  memcheck_thread_t *td = mambo_alloc(ctx, sizeof(*td));
  assert(td != NULL);
  int ret = mambo_set_thread_plugin_data(ctx, td);
  assert(ret == MAMBO_SUCCESS);

  td->in_malloc = 0;
}

void __memcheck_mark_valid(uintptr_t addr, size_t size) {
  void *alias = (void*)(addr & (RESERVED_BASE-1));
  if ((uintptr_t)alias != addr) {
    void *shadow = mmap(alias, size, PROT_NONE,
                        MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
    assert(shadow == alias);
  }
  memcheck_mark_valid(alias, size);
}

size_t memcheck_malloc_usable_size(uintptr_t ptr) {
  uintptr_t alloc_size = 0;
  int ret = mambo_ht_get(&allocs, ptr, &alloc_size);
  return alloc_size;
}

extern void memcheck_ret();
int memcheck_replace_malloc_usable_size(mambo_context *ctx) {
  int ret = emit_safe_fcall(ctx, memcheck_malloc_usable_size, MAX_FCALL_ARGS);
  assert(ret == 0);
  ret = mambo_set_source_addr(ctx, memcheck_ret);
  assert(ret == 0);
}

__attribute__((constructor)) void memcheck_init_plugin() {
  int ret;

  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  printf("\n-- MAMBO memcheck " GIT_VERSION " --\n\n");

  /* Reserve the highest page of the application's memory range */
  void *guard_page = mmap((void *)RESERVED_BASE - PAGE_SIZE, PAGE_SIZE, PROT_NONE,
                          MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
  assert(guard_page == (void *)RESERVED_BASE - PAGE_SIZE);

  /* Reserve shadow memory */
  shadow_mem = mmap((void *)RESERVED_BASE, SHADOW_SIZE, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
  assert(shadow_mem == (void *)RESERVED_BASE);

  /* The MAMBO image and its stack and heap can be within the reserved region.
     Rather than attempting to identify their boundaries, we'll reserve the
     range below RESERVED_BASE for the application and then fill the address space. */
  // First, increase our stack allocation
  extend_stack();

  uintptr_t app_base = max(0x8000, PAGE_SIZE);
  size_t app_size = (size_t)guard_page - app_base;
  void *app_range = mmap((void *)app_base, app_size, PROT_NONE,
                         MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
  assert(app_range == (void *)app_base);

  for (size_t size = INITIAL_RES_SIZE; size >= PAGE_SIZE; size /= 2) {
    while(mmap(NULL, size, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0) != MAP_FAILED);
  }

  ret = munmap(app_range, app_size);
  assert(ret == 0);

  // VDSO and VVAR
  /* We can't move them below RESERVED_BASE, so instead we reserve their alias and rely on the load / store
     instrumentation to mask the addresses of accesses to the VDSO region.
  */
  // AT_SYSINFO_EHDR points to the base of the VDSO. The adjacent lower page is VVAR
  uintptr_t vdso_base = getauxval(AT_SYSINFO_EHDR);
  if (vdso_base != 0) {
    __memcheck_mark_valid(vdso_base - PAGE_SIZE, VDSO_SIZE);
  }

  // Kernel helpers page
#ifdef __arm__
  __memcheck_mark_valid(0xffff0000, PAGE_SIZE);
#endif

  ret = mambo_ht_init(&allocs, 10000, 2, 70, true);
  assert(ret == 0);

  ret = mambo_register_pre_thread_cb(ctx, &memcheck_pre_thread_handler);
  assert(ret == MAMBO_SUCCESS);
  ret = mambo_register_pre_inst_cb(ctx, &memcheck_pre_inst_handler);
  assert(ret == MAMBO_SUCCESS);
  ret = mambo_register_vm_op_cb(ctx, &memcheck_vm_op_handler);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "malloc", &memcheck_inst_alloc0,
                                                  &memcheck_inst_alloc_post, 1);
  assert(ret == MAMBO_SUCCESS);
  ret = mambo_register_function_cb(ctx, "valloc", &memcheck_inst_alloc0, &memcheck_inst_alloc_post, 1);
  assert(ret == MAMBO_SUCCESS);
  ret = mambo_register_function_cb(ctx, "pvalloc", &memcheck_inst_alloc0, &memcheck_inst_alloc_post, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "alligned_alloc", &memcheck_inst_alloc1, &memcheck_inst_alloc_post, 2);
  assert(ret == MAMBO_SUCCESS);
  ret = mambo_register_function_cb(ctx, "memalign", &memcheck_inst_alloc1, &memcheck_inst_alloc_post, 2);
  assert(ret == MAMBO_SUCCESS);
  ret = mambo_register_function_cb(ctx, "__libc_memalign", &memcheck_inst_alloc1, &memcheck_inst_alloc_post, 2);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "posix_memalign", &memcheck_inst_posix_memalign, &memcheck_inst_posix_memalign_post, 3);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "calloc", &memcheck_inst_calloc, &memcheck_inst_alloc_post, 2);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "realloc", &memcheck_inst_realloc, &memcheck_inst_alloc_post, 2);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "free", &memcheck_inst_free, &memcheck_inst_free_post, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "__malloc_arena_thread_freeres", &memcheck_inst_ignored_fn, &memcheck_inst_ignored_fn_post, 1);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_function_cb(ctx, "malloc_usable_size", &memcheck_replace_malloc_usable_size, NULL, 1);
  assert(ret == MAMBO_SUCCESS);
#ifdef MC_REPLACE_FNS
  memcheck_install_naive_stdlib(ctx);
#endif
}
