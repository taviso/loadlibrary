CFLAGS  = -march=native -ggdb3 -std=gnu99 -fshort-wchar -Wno-multichar -Iinclude -mstackrealign
CPPFLAGS= -D_GNU_SOURCE -I. -Iintercept -Ipeloader
LDFLAGS = $(CFLAGS) -lm -Wl,--dynamic-list=exports.lst
LDLIBS  = -Wl,intercept/libhook.a -Wl,intercept/libZydis.a,--whole-archive -Wl,peloader/libpeloader.a,--no-whole-archive

.PHONY: clean peloader intercept

RELEASE_CFLAGS 	 = -O3
RELEASE_CPPFLAGS = -DNDEBUG
DEBUG_CFLAGS 	 = -O0 -g

TARGETS=mpclient | peloader

all: CFLAGS += $(RELEASE_CFLAGS)
all: CPPFLAGS += $(RELEASE_CPPFLAGS)
all: BUILD_TARGET = "all"
all: $(TARGETS)
	-mkdir -p faketemp

debug: CFLAGS += $(DEBUG_CFLAGS)
debug: BUILD_TARGET = "debug"
debug: $(TARGETS)
	-mkdir -p faketemp

intercept:
	cd intercept; mkdir build; cd build; cmake -DCMAKE_BUILD_TYPE=Debug ..; make
	cp intercept/build/libhook.a intercept/libhook.a
	cp intercept/build/zydis/libZydis.a intercept/libZydis.a

peloader:
	make -C peloader $(BUILD_TARGET)

peloader_x64:
	make -C peloader debug ARCH=x64

intercept/libhook.a: intercept

mpclient: CFLAGS += -m32
mpclient: LDFLAGS += -m32
mpclient: mpclient.o | peloader intercept
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(LDFLAGS)

mpclient_x64: CFLAGS += -g -O0
mpclient_x64: mpclient_x64.o | peloader_x64 intercept
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(LDFLAGS)

clean:
	rm -rf a.out core *.o core.* vgcore.* gmon.out mpclient intercept/build intercept/libhook.a intercept/libZydis.a
	make -C peloader clean
	rm -rf faketemp
