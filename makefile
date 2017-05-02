#PLUGINS+=plugins/branch_count.c
#PLUGINS+=plugins/soft_div.c
#PLUGINS+=plugins/tb_count.c
#PLUGINS+=plugins/mtrace.c plugins/mtrace.S
#PLUGINS+=plugins/cachesim/cachesim.c plugins/cachesim/cachesim.S plugins/cachesim/cachesim_model.c

OPTS= -DDBM_LINK_UNCOND_IMM
OPTS+=-DDBM_INLINE_UNCOND_IMM
OPTS+=-DDBM_LINK_COND_IMM
OPTS+=-DDBM_LINK_CBZ
OPTS+=-DDBM_LINK_TBZ
OPTS+=-DDBM_TB_DIRECT #-DFAST_BT
OPTS+=-DLINK_BX_ALT
OPTS+=-DDBM_INLINE_HASH
OPTS+=-DDBM_TRACES #-DTB_AS_TRACE_HEAD #-DBLXI_AS_TRACE_HEAD
#OPTS+=-DCC_HUGETLB -DMETADATA_HUGETLB

CFLAGS=-D_GNU_SOURCE -g -std=gnu99 -O2
#CFLAGS+=-mcpu=native

LDFLAGS=-static -ldl -Wl,-Ttext-segment=0xa8000000
LIBS=-lelf -lpthread
HEADERS=*.h makefile
INCLUDES=-I/usr/include/libelf
SOURCES= dispatcher.S common.c dbm.c traces.c syscalls.c dispatcher.c signals.c util.S
SOURCES+=api/helpers.c api/plugin_support.c api/branch_decoder_support.c api/load_store.c
SOURCES+=elf_loader/elf_loader.o

ARCH=$(shell $(CROSS_COMPILE)$(CC) -dumpmachine | awk -F '-' '{print $$1}')
ifeq ($(findstring arm, $(ARCH)), arm)
	CFLAGS += -mfpu=neon
	HEADERS += api/emit_arm.h api/emit_thumb.h
	PIE = pie/pie-arm-encoder.o pie/pie-arm-decoder.o pie/pie-arm-field-decoder.o
	PIE += pie/pie-thumb-encoder.o pie/pie-thumb-decoder.o pie/pie-thumb-field-decoder.o
	SOURCES += scanner_thumb.c scanner_arm.c
	SOURCES += api/emit_arm.c api/emit_thumb.c
endif
ifeq ($(ARCH),aarch64)
	HEADERS += api/emit_a64.h
	PIE += pie/pie-a64-field-decoder.o pie/pie-a64-encoder.o pie/pie-a64-decoder.o
	SOURCES += scanner_a64.c
	SOURCES += api/emit_a64.c
endif

ifdef PLUGINS
	CFLAGS += -DPLUGINS_NEW
endif

.PHONY: pie clean cleanall

all:
	$(info MAMBO: detected architecture "$(ARCH)")
	@$(MAKE) --no-print-directory pie && $(MAKE) --no-print-directory dbm

pie:
	@$(MAKE) --no-print-directory -C pie/ native

%.o: %.c %.h
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $<

dbm: $(HEADERS) $(SOURCES) $(PLUGINS)
	$(CROSS_COMPILE)$(CC) $(CFLAGS) $(LDFLAGS) $(OPTS) $(INCLUDES) -o $@ $(SOURCES) $(PLUGINS) $(PIE) $(LIBS)

clean:
	rm -f dbm elf_loader/elf_loader.o

cleanall: clean
	$(MAKE) -C pie/ clean

api/emit_%.c: pie/pie-%-encoder.c api/generate_emit_wrapper.rb
	ruby api/generate_emit_wrapper.rb $< > $@

api/emit_%.h: pie/pie-%-encoder.c api/generate_emit_wrapper.rb
	ruby api/generate_emit_wrapper.rb $< header > $@
