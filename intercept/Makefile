CFLAGS	= -O0 -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -w
CPPFLAGS= -DNDEBUG -D_GNU_SOURCE -Isubhook -I.
LDFLAGS	= $(CFLAGS) -m32

all: hook.o subhook/subhook.o winapi_hook.o
	make -C libdisasm all
	cp libdisasm/libdisasm.a .

clean:
	rm -f *.o *.a subhook/*.o
	make -C libdisasm clean
