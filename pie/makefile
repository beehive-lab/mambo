CFLAGS= -Os -Wall -g -std=c99 #-DPIE_AUTOINC

C_ARCH = $(shell $(CC) -dumpmachine | awk -F '-' '{print $$1}')
ifeq ($(findstring arm, $(C_ARCH)), arm)
	NATIVE_TARGETS = arm thumb
endif
ifeq ($(C_ARCH),aarch64)
	NATIVE_TARGETS = a64
endif
ifeq ($(C_ARCH),riscv64)
	NATIVE_TARGETS = riscv
endif

ifeq ($(ARCH),riscv)
  OPTS=swaphw
endif

.SECONDARY:
.PHONY: native print_arch all pie clean

native: print_arch $(NATIVE_TARGETS)
	
print_arch:
	$(info PIE: detected architecture "$(C_ARCH)")

all: thumb arm a64 riscv

%:
	$(MAKE) --no-print-directory ARCH=$@ pie

pie: pie-$(ARCH)-decoder.o pie-$(ARCH)-encoder.o pie-$(ARCH)-field-decoder.o

pie-$(ARCH)-%.o: pie-$(ARCH)-%.c pie-$(ARCH)-%.h
	$(CC) -c $(CFLAGS) $< -o $@

pie-$(ARCH)-%.h: generate_%.rb $(ARCH).txt
	ruby $< $(ARCH) header $(OPTS) > $@

pie-$(ARCH)-%.c: generate_%.rb $(ARCH).txt
	ruby $< $(ARCH) $(OPTS) > $@

clean:
	rm -f *.o pie-arm-*.h pie-thumb-*.h pie-a64-*.h pie-riscv-*.h pie-*.c

