portable: mmap_munmap mprotect_exec self_modifying signals

aarch32: portable hw_div

aarch64: portable

hw_div: hw_div.S
	$(CC) -mcpu=cortex-a15 $< -o $@

self_modifying: ../pie/pie-arm-encoder.o ../pie/pie-a64-encoder.o self_modifying.c
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

signals: ../pie/pie-arm-encoder.o ../pie/pie-a64-encoder.o signals.c
