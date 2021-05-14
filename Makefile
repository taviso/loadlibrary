CFLAGS  = -march=native -ggdb3 -std=gnu99 -fshort-wchar -Wno-multichar -Iinclude -Iintercept/include -Ipeloader -mstackrealign -mno-red-zone
CPPFLAGS= -D_GNU_SOURCE -I.
LDFLAGS = $(CFLAGS) -lm -Wl,--dynamic-list=exports.lst
LDLIBS  = -Wl,--whole-archive peloader/libpeloader.a -Wl,intercept/libhook.a -Wl,intercept/libx64_dispatcher.a -Wl,intercept/libZydis.a -Wl,intercept/libsubhook.a -Wl,--no-whole-archive

.PHONY: clean peloader intercept

RELEASE_CFLAGS 	 = -O3
RELEASE_CPPFLAGS = -DNDEBUG
DEBUG_CFLAGS 	 = -O0 -g

TARGETS=mpclient | peloader

all: CFLAGS += $(RELEASE_CFLAGS)
all: CPPFLAGS += $(RELEASE_CPPFLAGS)
all: BUILD_TARGET = "all"
all: $(TARGETS) $(MY_TARGETS)
	-mkdir -p faketemp

debug: CFLAGS += $(DEBUG_CFLAGS)
debug: BUILD_TARGET = "debug"
debug: CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=Debug
debug: $(TARGETS)
	-mkdir -p faketemp

intercept:
	cd intercept; mkdir build; cd build; cmake $(CMAKE_FLAGS) ..; make
	cp intercept/build/libhook.a intercept/libhook.a
	cp intercept/build/zydis/libZydis.a intercept/libZydis.a
	cp intercept/build/subhook/libsubhook.a intercept/libsubhook.a
	cp intercept/build/libx64_dispatcher.a intercept/libx64_dispatcher.a

peloader:
	make -C peloader $(BUILD_TARGET)

peloader_x64:
	make -C peloader debug ARCH=x64

mpclient: CFLAGS += -m32
mpclient: LDFLAGS += -m32
mpclient: CMAKE_FLAGS += -DARCH:STRING=x86
mpclient: mpclient.o | peloader intercept
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(LDFLAGS)

mpclient_x64: CFLAGS += -g -O0  -fPIC
mpclient_x64: CMAKE_FLAGS = -DARCH:STRING=x64 -DCMAKE_BUILD_TYPE=Debug
mpclient_x64: mpclient_x64.o | peloader_x64 intercept
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(LDFLAGS)

clean:
	rm -rf a.out core *.o core.* vgcore.* gmon.out mpclient intercept/build intercept/*.a tests/build
	make -C peloader clean
	rm -rf faketemp
