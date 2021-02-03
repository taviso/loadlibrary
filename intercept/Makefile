CFLAGS	= -O0 -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -w
CPPFLAGS= -DNDEBUG
LDFLAGS	= $(CFLAGS) -m32

all: hook.o subhook
	make -C libdisasm all
	cp libdisasm/libdisasm.a .

subhook: subhook/subhook.o

clean:
	rm -f *.o *.a subhook/*.o
	make -C libdisasm clean
