ARCH=$(shell $(CC) -dumpmachine | awk -F '-' '{print $$1}')
ifeq ($(ARCH),arm)
	PIE = ../pie/pie-arm-encoder.o
endif
ifeq ($(ARCH),aarch64)
	PIE = ../pie/pie-a64-encoder.o
endif

portable: mmap_munmap mprotect_exec self_modifying signals

aarch32: portable hw_div

aarch64: portable

hw_div: hw_div.S
	$(CC) -mcpu=cortex-a15 $< -o $@

self_modifying: $(PIE) self_modifying.c
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

signals: $(PIE) signals.c
