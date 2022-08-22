#ifndef __RISCV_TRACES_H__
#define __RISCV_TRACES_H__

void create_trace(dbm_thread *thread_data, uint16_t bb_source, uintptr_t *ret_addr);
void trace_dispatcher(uintptr_t target, uintptr_t *next_addr, uint32_t source_index, dbm_thread *thread_data);

#endif
