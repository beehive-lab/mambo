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

#ifndef __DBM_H__
#define __DBM_H__

#include <stdbool.h>
#include <signal.h>
#include <limits.h>
#include <stdint.h>
#include <sys/auxv.h>
#include <libelf.h>

#ifdef __arm__
#include "pie/pie-arm-decoder.h"
#include "pie/pie-thumb-decoder.h"
#endif

#include "common.h"
#include "util.h"

/* Various parameters which can be tuned */

// BASIC_BLOCK_SIZE should be a power of 2
#define BASIC_BLOCK_SIZE 64
#ifdef DBM_TRACES
  #define CODE_CACHE_SIZE 55000
#else
  #define CODE_CACHE_SIZE 65000
#endif
#define TRACE_FRAGMENT_NO 60000
#define CODE_CACHE_OVERP 30
#define MAX_BRANCH_RANGE (16*1024*1024)
#define TRACE_CACHE_SIZE (MAX_BRANCH_RANGE - (CODE_CACHE_SIZE*BASIC_BLOCK_SIZE * 4))
#define TRACE_LIMIT_OFFSET (2*1024)

#define TRACE_ALIGN 4 // must be a power of 2
#define TRACE_ALIGN_MASK (TRACE_ALIGN-1)

#define INST_CNT 400

#define MAX_TB_INDEX  152
#define TB_CACHE_SIZE 32

#define MAX_BACK_INLINE 5
#define MAX_TRACE_FRAGMENTS 20

#define RAS_SIZE (4096*5)
#define TBB_TARGET_REACHED_SIZE 30

#define MAX_CC_LINKS 100000

#define THUMB 0x1
#define FULLADDR 0x2

#define MAX_PLUGIN_NO (10)

typedef enum {
  mambo_bb = 0,
  mambo_trace,
  mambo_trace_entry
} cc_type;

typedef enum {
  unknown,
  stub,
  trace_inline_max,
#ifdef __arm__
  uncond_b_to_bl_thumb,
  uncond_imm_thumb,
  uncond_reg_thumb,
  cond_imm_thumb,
  cond_reg_thumb,
  cbz_thumb,
  uncond_blxi_thumb,
  cond_blxi_thumb,
  cond_imm_arm,
  uncond_imm_arm,
  cond_reg_arm,
  uncond_reg_arm,
  uncond_blxi_arm,
  cond_blxi_arm,
  tbb,
  tbh,
  tb_indirect,
  pred_bxlr,
  pred_pop16pc,
  pred_ldmfd32pc,
  pred_armbxlr,
  pred_ldrpcsp,
  pred_armldmpc,
  pred_bad,
#endif //__arm__
#ifdef __aarch64__
  uncond_imm_a64,
  uncond_branch_reg,
  cond_imm_a64,
  cbz_a64,
  tbz_a64,
#endif // __aarch64__
} branch_type;

typedef struct {
  uint32_t words[BASIC_BLOCK_SIZE];
} dbm_block;

typedef struct {
  dbm_block blocks[CODE_CACHE_SIZE];
  uint8_t  traces[TRACE_CACHE_SIZE];
} dbm_code_cache;

#define FALLTHROUGH_LINKED (1 << 0)
#define BRANCH_LINKED (1 << 1)
#define BOTH_LINKED (1 << 2)

typedef struct {
  uint16_t *source_addr;
  uintptr_t tpc;
  branch_type exit_branch_type;
  int actual_id;
#ifdef __arm__
  uint16_t *exit_branch_addr;
#endif // __arm__
#ifdef __aarch64__
  uint32_t *exit_branch_addr;
#endif // __arch64__
  uintptr_t branch_taken_addr;
  uintptr_t branch_skipped_addr;
  uintptr_t branch_condition;
  uintptr_t branch_cache_status;
  uint32_t rn;
  uint32_t free_b;
  ll_entry *linked_from;
} dbm_code_cache_meta;

typedef struct {
  unsigned long flags;
  void *child_stack;
  pid_t *ptid;
  uintptr_t tls;
  pid_t *ctid;
} sys_clone_args;

struct trace_exits {
  uintptr_t from;
  uintptr_t to;
};

#define MAX_TRACE_REC_EXITS (MAX_TRACE_FRAGMENTS+1)
typedef struct {
  int id;
  int source_bb;
  void *write_p;
  uintptr_t entry_addr;
  bool active;
  int free_exit_rec;
  struct trace_exits exits[MAX_TRACE_REC_EXITS];
} trace_in_prog;

enum dbm_thread_status {
  THREAD_RUNNING = 0,
  THREAD_SYSCALL,
  THREAD_EXIT
};

typedef struct dbm_thread_s dbm_thread;
struct dbm_thread_s {
  dbm_thread *next_thread;
  enum dbm_thread_status status;

  int free_block;
  bool was_flushed;
  uintptr_t dispatcher_addr;
  uintptr_t syscall_wrapper_addr;

  dbm_code_cache *code_cache;
  dbm_code_cache_meta code_cache_meta[CODE_CACHE_SIZE + TRACE_FRAGMENT_NO];
  hash_table entry_address;
#ifdef DBM_TRACES
  uint8_t   exec_count[CODE_CACHE_SIZE];
  uintptr_t trace_head_incr_addr;
  uint8_t  *trace_cache_next;
  int       trace_id;
  int       trace_fragment_count;
  trace_in_prog active_trace;
#endif

  ll *cc_links;

  uintptr_t tls;
  uintptr_t child_tls;

#ifdef PLUGINS_NEW
  void *plugin_priv[MAX_PLUGIN_NO];
#endif
  void *clone_ret_addr;
  pid_t tid;
  volatile pid_t *set_tid;
  sys_clone_args *clone_args;
  bool clone_vm;
  int pending_signals[_NSIG];
  uint32_t is_signal_pending;
  void *mambo_sp;
};

typedef enum {
  ARM_INST,
  THUMB_INST,
  A64_INST,
} inst_set;

typedef enum {
  VM_MAP,
  VM_UNMAP,
  VM_PROT
} vm_op_t;

#include "api/plugin_support.h"

typedef struct {
  char *name;
  int plugin_id;
  mambo_callback pre_callback;
  mambo_callback post_callback;
} watched_func_t;

typedef struct {
  void *addr;
  watched_func_t *func;
} watched_funcp_t;

#define MAX_WATCHED_FUNCS 40
#define MAX_WATCHED_FUNC_PTRS 80
typedef struct {
  int func_count;
  pthread_mutex_t funcs_lock;
  watched_func_t  funcs[MAX_WATCHED_FUNCS];

  int funcp_count;
  pthread_mutex_t funcps_lock;
  watched_funcp_t funcps[MAX_WATCHED_FUNC_PTRS];
} watched_functions_t;

typedef struct {
  int argc;
  char **argv;
  interval_map exec_allocs;

  uintptr_t signal_handlers[_NSIG];
  pthread_mutex_t signal_handlers_mutex;

  uintptr_t brk;
  uintptr_t initial_brk;
  pthread_mutex_t brk_mutex;

  dbm_thread *threads;
  pthread_mutex_t thread_list_mutex;

  volatile int exit_group;

#ifdef PLUGINS_NEW
  int free_plugin;
  mambo_plugin plugins[MAX_PLUGIN_NO];
  watched_functions_t watched_functions;
#endif
} dbm_global;

typedef struct {
  uintptr_t tpc;
  uintptr_t spc;
} cc_addr_pair;

void dbm_exit(dbm_thread *thread_data, uint32_t code);
void thread_abort(dbm_thread *thread_data);

extern void dispatcher_trampoline();
extern void syscall_wrapper();
extern void trace_head_incr();
extern void* start_of_dispatcher_s;
extern void* end_of_dispatcher_s;
extern void th_to_arm();
extern void th_enter(void *stack, uintptr_t cc_addr);
extern void send_self_signal();
extern void syscall_wrapper_svc();

int lock_thread_list(void);
int unlock_thread_list(void);
int register_thread(dbm_thread *thread_data, bool caller_has_lock);
int unregister_thread(dbm_thread *thread_data, bool caller_has_lock);
bool allocate_thread_data(dbm_thread **thread_data);
int free_thread_data(dbm_thread *thread_data);
void init_thread(dbm_thread *thread_data);
void reset_process(dbm_thread *thread_data);

uintptr_t cc_lookup(dbm_thread *thread_data, uintptr_t target);
uintptr_t lookup_or_scan(dbm_thread *thread_data, uintptr_t target, bool *cached);
uintptr_t lookup_or_stub(dbm_thread *thread_data, uintptr_t target);
uintptr_t scan(dbm_thread *thread_data, uint16_t *address, int basic_block);
uint32_t scan_arm(dbm_thread *thread_data, uint32_t *read_address, int basic_block, cc_type type, uint32_t *write_p);
uint32_t scan_thumb(dbm_thread *thread_data, uint16_t *read_address, int basic_block, cc_type type, uint16_t *write_p);
size_t   scan_a64(dbm_thread *thread_data, uint32_t *read_address, int basic_block, cc_type type, uint32_t *write_p);
int allocate_bb(dbm_thread *thread_data);
void trace_dispatcher(uintptr_t target, uintptr_t *next_addr, uint32_t source_index, dbm_thread *thread_data);
void flush_code_cache(dbm_thread *thread_data);
#ifdef __aarch64__
void generate_trace_exit(dbm_thread *thread_data, uint32_t **o_write_p, int fragment_id, bool is_taken);
#endif
void insert_cond_exit_branch(dbm_code_cache_meta *bb_meta, void **o_write_p, int cond);
void sigret_dispatcher_call(dbm_thread *thread_data, ucontext_t *cont, uintptr_t target);

void thumb_encode_stub_bb(dbm_thread *thread_data, int basic_block, uint32_t target);
void arm_encode_stub_bb(dbm_thread *thread_data, int basic_block, uint32_t target);

int addr_to_bb_id(dbm_thread *thread_data, uintptr_t addr);
int addr_to_fragment_id(dbm_thread *thread_data, uintptr_t addr);
void record_cc_link(dbm_thread *thread_data, uintptr_t linked_from, uintptr_t linked_to_addr);
bool is_bb(dbm_thread *thread_data, uintptr_t addr);
void install_system_sig_handlers();


#define MAP_INTERP (0x40000000)
#define MAP_APP (0x20000000)
void notify_vm_op(vm_op_t op, uintptr_t addr, size_t size, int prot, int flags, int fd, off_t off);

#ifdef __arm__
void thumb_simple_exit(dbm_thread *thread_data, uint16_t **o_write_p, int bb_index, uint32_t target);
void arm_simple_exit(dbm_thread *thread_data, uint32_t **o_write_p, int bb_index,
                     uint32_t offset, uint32_t *read_address, uint32_t cond);
#endif

inline static uintptr_t adjust_cc_entry(uintptr_t addr) {
#ifdef __arm__
  if (addr != UINT_MAX) {
    addr += 4 - ((addr & 1) << 1); // +4 for ARM, +2 for Thumb
  }
#endif
  return addr;
}

extern dbm_global global_data;
extern uintptr_t page_size;
extern dbm_thread *disp_thread_data;
extern uint32_t *th_is_pending_ptr;
extern __thread dbm_thread *current_thread;

/* API-related functions */
#ifdef PLUGINS_NEW
void set_mambo_context(mambo_context *ctx, dbm_thread *thread_data, mambo_cb_idx event_type);
void set_mambo_context_code(mambo_context *ctx, dbm_thread *thread_data, mambo_cb_idx event_type,
                            cc_type fragment_type, int fragment_id, inst_set inst_type, int inst,
                            mambo_cond cond, void *read_address, void *write_p, void *data_p, bool *stop);
void set_mambo_context_syscall(mambo_context *ctx, dbm_thread *thread_data, mambo_cb_idx event_type,
                               uintptr_t number, uintptr_t *regs);
#endif
void mambo_deliver_callbacks_for_ctx(mambo_context *ctx);
void mambo_deliver_callbacks(unsigned cb_id, dbm_thread *thread_data);
void mambo_deliver_callbacks_code(unsigned cb_id, dbm_thread *thread_data, cc_type fragment_type,
                                  int fragment_id, inst_set inst_type, int inst, mambo_cond cond,
                                  void *read_address, void *write_p, void *data_p, bool *stop);
void _function_callback_wrapper(mambo_context *ctx, watched_func_t *func);
int function_watch_parse_elf(watched_functions_t *self, Elf *elf, void *base_addr);
int function_watch_add(watched_functions_t *self, char *name, int plugin_id,
                       mambo_callback pre_callback, mambo_callback post_callback);

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

/* Constants */

#define ALLOCATE_BB 0

#ifdef CC_HUGETLB
  #define CC_PAGE_SIZE (2*1024*1024)
  #define CC_MMAP_OPTS (MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB)
#else
  #define CC_PAGE_SIZE (page_size)
  #define CC_MMAP_OPTS (MAP_PRIVATE|MAP_ANONYMOUS)
#endif

#ifdef METADATA_HUGETLB
  #define METADATA_PAGE_SIZE (2*1024*1024)
  #define METADATA_MMAP_OPTS (MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB)
#else
  #define METADATA_PAGE_SIZE (page_size)
  #define METADATA_MMAP_OPTS (MAP_PRIVATE|MAP_ANONYMOUS)
#endif

#define ROUND_UP(input, multiple_of) \
  ((((input) / (multiple_of)) * (multiple_of)) + (((input) % (multiple_of)) ? (multiple_of) : 0))

#define CC_SZ_ROUND(input) ROUND_UP(input, CC_PAGE_SIZE)
#define METADATA_SZ_ROUND(input) ROUND_UP(input, CC_PAGE_SIZE)

#define PAGE_SIZE (page_size != 0 ? page_size : (page_size = getauxval(AT_PAGESZ)))

#define trampolines_size_bytes         ((uintptr_t)&end_of_dispatcher_s - (uintptr_t)&start_of_dispatcher_s)
#define trampolines_size_bbs           ((trampolines_size_bytes / sizeof(dbm_block)) \
                                      + ((trampolines_size_bytes % sizeof(dbm_block)) ? 1 : 0))

#define UNLINK_SIGNAL (SIGILL)
#define CPSR_T (0x20)

#ifdef __arm__
  #define context_pc uc_mcontext.arm_pc
  #define context_sp uc_mcontext.arm_sp
  #define context_reg(reg) uc_mcontext.arm_r##reg
#elif __aarch64__
  #define context_pc uc_mcontext.pc
  #define context_sp uc_mcontext.sp
  #define context_reg(reg) uc_mcontext.regs[reg]
#endif

#endif

