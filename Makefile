CFLAGS  = -O3 -march=native -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -Iinclude -mstackrealign
CPPFLAGS=-DNDEBUG -D_GNU_SOURCE -I. -Iintercept -Ipeloader
LDFLAGS = $(CFLAGS) -m32 -lm -Wl,--dynamic-list=exports.lst
LDLIBS  = intercept/libdisasm.a -Wl,--whole-archive,peloader/libpeloader.a,--no-whole-archive

.PHONY: clean peloader intercept

TARGETS=mpclient | peloader

all: $(TARGETS)
	-mkdir -p faketemp
	
get:
	cd engine && wget "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86" --user-agent="Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" -O mpam-fe.exe && cabextract mpam-fe.exe

intercept:
	make -C intercept all

peloader:
	make -C peloader all

intercept/hook.o: intercept

mpclient: mpclient.o intercept/hook.o | peloader
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(LDFLAGS)

clean:
	rm -f a.out core *.o core.* vgcore.* gmon.out mpclient
	make -C intercept clean
	make -C peloader clean
	rm -rf faketemp
