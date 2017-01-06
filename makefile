CC=gcc
CFLAGS=-g -std=gnu99 -mcpu=native #-DPLUGINS_NEW #-DDEBUG -DVERBOSE
OPTS=-O2 -DDBM_LINK_UNCOND_IMM  -DDBM_INLINE_UNCOND_IMM -DDBM_LINK_COND_IMM -DLINK_BX_ALT -DDBM_LINK_CBZ -DDBM_INLINE_HASH -DDBM_D_INLINE_HASH -DDBM_TB_DIRECT -DDBM_TRACES #-DTB_AS_TRACE_HEAD #-DBLXI_AS_TRACE_HEAD #-DCC_HUGETLB #-DMETADATA_HUGETLB #-DFAST_BT
LDFLAGS=-static -ldl -Wl,-Ttext-segment=0xa8000000
LIBS=-lelf -lpthread
HEADERS=dbm.h common.h api/plugin_support.h api/emit_arm.h api/emit_thumb.h api/helpers.h makefile
INCLUDES=-I/usr/include/libelf
SOURCES=elf_loader/elf_loader.o pie/pie-arm-encoder.o pie/pie-arm-decoder.o pie/pie-arm-field-decoder.o pie/pie-thumb-encoder.o pie/pie-thumb-decoder.o pie/pie-thumb-field-decoder.o dispatcher.s scanner_thumb.c scanner_arm.c common.c dbm.c traces.c api/emit_arm.c api/emit_thumb.c api/helpers.c api/plugin_support.c util.s
PLUGINS=plugins/soft_div.c plugins/tb_count.c

all: pie dbm

.PHONY: pie
pie:
	make --no-print-directory -C pie/ all

%.o: %.c %.h
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $<

dbm: $(HEADERS) $(SOURCES) $(PLUGINS)
	$(CROSS_COMPILE)$(CC) -o $@ $(INCLUDES) $(SOURCES) $(PLUGINS) $(CFLAGS) $(OPTS) $(LDFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm dbm elf_loader/elf_loader.o

api/emit_%.c: pie/pie-%-encoder.c api/generate_emit_wrapper.rb
	ruby api/generate_emit_wrapper.rb $< > $@

api/emit_%.h: pie/pie-%-encoder.c api/generate_emit_wrapper.rb
	ruby api/generate_emit_wrapper.rb $< header > $@
