CFLAGS  = -march=native -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -Iinclude -mstackrealign
CPPFLAGS= -D_GNU_SOURCE -I. -Iintercept -Ipeloader
LDFLAGS = $(CFLAGS) -m32 -lm -Wl,--dynamic-list=exports.lst
LDLIBS  = intercept/libdisasm.a -Wl,--whole-archive,peloader/libpeloader.a,--no-whole-archive

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
	make -C intercept $(BUILD_TARGET)

peloader:
	make -C peloader $(BUILD_TARGET)

intercept/hook.o: intercept

mpclient: mpclient.o intercept/hook.o | peloader
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(LDFLAGS)

clean:
	rm -f a.out core *.o core.* vgcore.* gmon.out mpclient
	make -C intercept clean
	make -C peloader clean
	rm -rf faketemp
