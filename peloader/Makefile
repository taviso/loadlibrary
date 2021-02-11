CFLAGS  = -O3 -march=native -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -Iinclude -mstackrealign
CPPFLAGS= -DNDEBUG -D_GNU_SOURCE -I. -Iwinapi/ -I../intercept -I../intercept/subhook
LDFLAGS = $(CFLAGS) -m32 -lm

.PHONY: clean

# This glob matches all the winapi exports we provide.
WINAPI  = $(patsubst %.c,%.o,$(wildcard winapi/*.c))
# This glob matches all the winapi custom hooks we provide.
WINAPI_HOOKS  = $(patsubst %.c,%.o,$(wildcard winapi_hooks/*.c))

TARGETS=libpeloader.a

all: $(TARGETS)

libpeloader.a: $(WINAPI) $(WINAPI_HOOKS) winstrings.o pe_linker.o crt.o log.o util.o extra.o
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f a.out core *.o core.* vgcore.* gmon.out winapi/*.o winapi_hooks/*.o $(TARGETS)
