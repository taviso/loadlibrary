CFLAGS    = -march=native -ggdb3 -std=gnu99 -fshort-wchar -Wno-multichar -Iinclude -mstackrealign
CPPFLAGS  = -D_GNU_SOURCE -I.
LDFLAGS   = $(CFLAGS) -lm
LDLIBS	  = libpeloader.a
TST_LIBS  = -lcheck -lm -lpthread -lrt -lsubunit
TST_DIR   = ./tests
TST_FILES = $(addprefix $(TST_DIR)/, *.c)
ARCH	  = x86

ifeq ($(ARCH),x86)
	CFLAGS  += -m32
	LDFLAGS += -m32
else ifneq ($(ARCH),x64)
$(error Supported target architectures: x86 or x64)
endif

RELEASE_CFLAGS 	 = -O3
RELEASE_CPPFLAGS = -DNDEBUG
DEBUG_CFLAGS 	 = -O0 -g

.PHONY: clean

# This glob matches all the winapi exports we provide.
WINAPI  = $(patsubst %.c,%.o,$(wildcard winapi/*.c))

TARGETS=libpeloader.a

all: CFLAGS += $(RELEASE_CFLAGS)
all: CPPFLAGS += $(RELEASE_CPPFLAGS)
all: $(TARGETS)

debug: CFLAGS += $(DEBUG_CFLAGS)
debug: $(TARGETS)

libpeloader.a: $(WINAPI) winstrings.o pe_linker.o crt.o log.o util.o extra.o
	$(AR) $(ARFLAGS) $@ $^

check_peloader.o: $(TST_FILES)
	$(CC) -O0 -g -c -o tests/check_peloader.o $(TST_FILES) $(LDLIBS)

check_peloader: $(TARGETS) check_peloader.o
	$(CC) -O0 -g tests/check_peloader.o $(TST_LIBS) -o tests/check_peloader_tests $(LDLIBS)

test: clean check_peloader
	./tests/check_peloader_tests

clean:
	rm -f a.out core *.o core.* vgcore.* gmon.out winapi/*.o tests/*.o $(TARGETS)
