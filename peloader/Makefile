CFLAGS  = -march=native -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -Iinclude -mstackrealign
CPPFLAGS= -D_GNU_SOURCE -I.
LDFLAGS = $(CFLAGS) -m32 -lm

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

clean:
	rm -f a.out core *.o core.* vgcore.* gmon.out winapi/*.o $(TARGETS)
