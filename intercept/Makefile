CFLAGS	= -O0 -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -w
CPPFLAGS=
LDFLAGS	= $(CFLAGS) -m32

RELEASE_CPPFLAGS = -DNDEBUG
DEBUG_CFLAGS 	 = -g

all: CPPFLAGS += $(RELEASE_CPPFLAGS)
all: hook.o
	make -C libdisasm all
	cp libdisasm/libdisasm.a .

debug: CFLAGS += $(DEBUG_CFLAGS)
debug: hook.o
	make -C libdisasm debug
	cp libdisasm/libdisasm.a .

clean:
	rm -f *.o *.a
	make -C libdisasm clean
