portable: mmap_munmap

hw_div: hw_div.S
	$(CC) -mcpu=cortex-a15 $< -o $@

aarch32: portable hw_div

aarch64: portable
