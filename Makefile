ifndef KP_DIR
	KP_DIR = KPM-Headers
endif

ifndef TARGET_COMPILE
	TARGET_COMPILE = aarch64-none-elf-
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

CFLAGS += -Wall -Werror=implicit-function-declaration -Wundef -O2 -std=gnu11
CFLAGS += -fno-builtin -fno-builtin-memset -fno-pic -fno-PIC -fno-pie -fno-PIE
CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
CFLAGS += -fno-stack-protector -fno-common -mgeneral-regs-only -mcmodel=small $(EXTRA_CFLAGS)

KP_INCLUDE_DIRS := include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := -Iinclude -Isrc -isystem $(KP_DIR) $(foreach dir,$(KP_INCLUDE_DIRS),-isystem $(KP_DIR)/$(dir))

HEADERS := include/hmkpm_uapi.h src/hmkpm_internal.h
objs := src/main.o src/sw_pan.o src/mmu.o src/io.o src/scan.o src/fsnotify_filter.o src/disasm_legacy.o

all: hmkpm.kpm

hmkpm.kpm: ${objs}
	${LD} -r -o $@ $^

%.o: %.c $(HEADERS)
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f hmkpm.kpm *.kpm *.o src/*.o
