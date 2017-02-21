portable: mmap_munmap mprotect_exec

hw_div: hw_div.S
	$(CC) -mcpu=cortex-a15 $< -o $@

aarch32: portable hw_div

aarch64: portable
