
ifndef KP_DIR
	KP_DIR = KPM-Headers
endif

ifndef TARGET_COMPILE
	TARGET_COMPILE = aarch64-none-elf-
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

CFLAGS += -fno-builtin-memset -fno-builtin -mgeneral-regs-only

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/$(dir))

objs := hmkpm.o

all: hmkpm.kpm

hmkpm.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm *.o
