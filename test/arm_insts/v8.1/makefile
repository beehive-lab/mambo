CFLAGS=-march=armv8.2-a
ARCH=$(shell $(CC) -dumpmachine | awk -F '-' '{print $$1}')

ifeq ($(ARCH),aarch64)
aarch64: CASPx CASx LDADDx LDCLRx LDEORx LDLARx LDSETx LDSMAXx LDSMINx LDUMAXx LDUMINx SQRDMLxH STADDx STCLRx STEORx STLLRx STSETx STSMAXx STSMINx STUMAXx STUMINx SWPx
else ifeq ($(findstring arm, $(ARCH)), arm)
CFLAGS+=-mthumb -mfpu=neon-fp-armv8
aarch32: VQRDMLAH
else
fallback: $(error $(ARCH) isn't supported)
endif

clean:
	rm -f CASPx CASx LDADDx LDCLRx LDEORx LDLARx LDSETx LDSMAXx LDSMINx LDUMAXx LDUMINx SQRDMLxH STADDx STCLRx STEORx STLLRx STSETx STSMAXx STSMINx STUMAXx STUMINx SWPx VQRDMLAH
