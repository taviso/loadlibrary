CFLAGS  = -O3 -march=native -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -Iinclude -mstackrealign
CPPFLAGS=-DNDEBUG -D_GNU_SOURCE -I. -Iintercept -Ipeloader
LDFLAGS = $(CFLAGS) -m32 -lm -Wl,--dynamic-list=exports.lst
LDLIBS  = intercept/libdisasm.a -Wl,--whole-archive,peloader/libpeloader.a,--no-whole-archive

.PHONY: clean peloader intercept

TARGETS=mpclient

all: $(TARGETS)
	-mkdir -p faketemp

intercept:
	make -C intercept all

peloader:
	make -C peloader all

script.h: javascript.txt
	hexdump -v -e '8/1 "%#02x," "\n"' < $^ > $@

mpscript.o: script.h

intercept/hook.o: intercept

mpclient: mpclient.o intercept/hook.o | peloader
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(LDFLAGS)

# mpscript requires libreadline-dev:i386
mpscript: mpscript.o intercept/hook.o | peloader
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(LDFLAGS) -lreadline

clean:
	rm -f a.out core *.o core.* vgcore.* gmon.out script.h mpclient mpscript
	make -C intercept clean
	make -C peloader clean
	rm -rf faketemp
