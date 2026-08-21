ifndef KP_DIR
	KP_DIR = KPM-Headers
endif

ifndef TARGET_COMPILE
	TARGET_COMPILE = aarch64-none-elf-
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

CFLAGS += -Wall -O2 -std=gnu11 -fno-builtin -fno-builtin-memset -fno-pic -fno-PIC -fno-pie -fno-PIE -fno-asynchronous-unwind-tables -fno-unwind-tables
CFLAGS += -fno-stack-protector -fno-common -mgeneral-regs-only -mcmodel=small

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/$(dir))

objs := hmkpm.o

all: hmkpm.kpm

hmkpm.kpm: ${objs}
	${LD} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm *.o
