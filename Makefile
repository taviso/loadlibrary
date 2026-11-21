.DEFAULT_GOAL := all

CC ?= cc
AR ?= ar
CMAKE ?= cmake
BUILD_DIR ?= build
BUILD_MODE ?= release

ifeq ($(BUILD_MODE),debug)
MODE_OPT := -O0
CMAKE_BUILD_TYPE := Debug
else ifeq ($(BUILD_MODE),release)
MODE_OPT := -O2
MODE_CPPFLAGS := -DNDEBUG
CMAKE_BUILD_TYPE := RelWithDebInfo
else
$(error Supported BUILD_MODE values: release or debug)
endif

CPPFLAGS += -D_GNU_SOURCE $(MODE_CPPFLAGS) -I. -Iinclude -Iintercept/include -Ilog -Ipeloader
CFLAGS += -march=native -ggdb3 -std=gnu99 -fshort-wchar -fno-omit-frame-pointer \
          -Wno-multichar -mstackrealign -maccumulate-outgoing-args
LDFLAGS += -Wl,--dynamic-list=exports.lst
LDLIBS += -lm -ldl

LOADER_SOURCES := $(wildcard peloader/*.c) $(filter-out peloader/winapi/Exception_x86.c peloader/winapi/Exception_x64.c,$(wildcard peloader/winapi/*.c))
LOADER_x86 := $(patsubst %.c,$(BUILD_DIR)/x86/%.o,$(LOADER_SOURCES) peloader/winapi/Exception_x86.c)
LOADER_x64 := $(patsubst %.c,$(BUILD_DIR)/x64/%.o,$(LOADER_SOURCES) peloader/winapi/Exception_x64.c)
DISASM_SOURCES := $(wildcard intercept/libdisasm/*.c)
DISASM_OBJECTS := $(patsubst %.c,$(BUILD_DIR)/x86/%.o,$(DISASM_SOURCES))
X86_LIBS := $(BUILD_DIR)/x86/libpeloader.a $(BUILD_DIR)/x86/libhook.a $(BUILD_DIR)/x86/libdisasm.a
X64_INTERCEPT := $(BUILD_DIR)/x64/intercept
X64_LIBS := $(BUILD_DIR)/x64/libpeloader.a $(X64_INTERCEPT)/libhook.a $(X64_INTERCEPT)/zydis/libZydis.a $(X64_INTERCEPT)/subhook/libsubhook.a

.PHONY: all debug check clean mpclient mpclient_x64 peloader peloader_x64 x64-intercept x64-relink-check
all: mpclient mpclient_x64
debug:
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/debug BUILD_MODE=debug all
check: $(BUILD_DIR)/x86/tests/mpengine_layout $(BUILD_DIR)/x64/tests/mpengine_layout
	$(BUILD_DIR)/x86/tests/mpengine_layout
	$(BUILD_DIR)/x64/tests/mpengine_layout
mpclient: $(BUILD_DIR)/x86/mpclient
mpclient_x64: $(BUILD_DIR)/x64/mpclient_x64
peloader: $(BUILD_DIR)/x86/libpeloader.a
peloader_x64: $(BUILD_DIR)/x64/libpeloader.a

$(BUILD_DIR)/x86/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -m32 $(MODE_OPT) -MMD -MP -c $< -o $@

$(BUILD_DIR)/x64/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -m64 $(MODE_OPT) -fPIC -MMD -MP -c $< -o $@

# Rebuild existing objects when build flags in this Makefile change.
$(LOADER_x86) $(LOADER_x64) $(DISASM_OBJECTS) \
$(BUILD_DIR)/x86/intercept/src/hook_x86.o \
$(BUILD_DIR)/x86/mpclient.o $(BUILD_DIR)/x86/log/log.o \
$(BUILD_DIR)/x64/mpclient.o $(BUILD_DIR)/x64/log/log.o \
$(BUILD_DIR)/x86/tests/mpengine_layout.o $(BUILD_DIR)/x64/tests/mpengine_layout.o: Makefile

$(BUILD_DIR)/x86/tests/mpengine_layout: $(BUILD_DIR)/x86/tests/mpengine_layout.o
	$(CC) -m32 -o $@ $^

$(BUILD_DIR)/x64/tests/mpengine_layout: $(BUILD_DIR)/x64/tests/mpengine_layout.o
	$(CC) -m64 -o $@ $^

$(DISASM_OBJECTS): CPPFLAGS += -DHAVE_CONFIG_H -Iintercept/libdisasm
$(DISASM_OBJECTS): CFLAGS += -w
$(BUILD_DIR)/x86/intercept/src/hook_x86.o: CPPFLAGS += -Iintercept/libdisasm

$(BUILD_DIR)/x86/libpeloader.a: $(LOADER_x86)
	@mkdir -p $(@D)
	rm -f $@
	$(AR) rcs $@ $^

$(BUILD_DIR)/x64/libpeloader.a: $(LOADER_x64)
	@mkdir -p $(@D)
	rm -f $@
	$(AR) rcs $@ $^

$(BUILD_DIR)/x86/libhook.a: $(BUILD_DIR)/x86/intercept/src/hook_x86.o
	$(AR) rcs $@ $^

$(BUILD_DIR)/x86/libdisasm.a: $(DISASM_OBJECTS)
	$(AR) rcs $@ $^

# CMake tracks its own sources and headers. Run its incremental build before
# checking the library timestamps used by the client link rule.
x64-intercept:
	$(CMAKE) -S intercept -B $(X64_INTERCEPT) -DARCH:STRING=x64 -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) -DCMAKE_POLICY_VERSION_MINIMUM=3.5
	+$(CMAKE) --build $(X64_INTERCEPT)

$(filter-out $(BUILD_DIR)/x64/libpeloader.a,$(X64_LIBS)): | x64-intercept
	@test -f $@

$(BUILD_DIR)/x86/mpclient: $(BUILD_DIR)/x86/mpclient.o $(BUILD_DIR)/x86/log/log.o $(X86_LIBS) exports.lst
	$(CC) -m32 $(LDFLAGS) -o $@ $(filter %.o,$^) -Wl,--whole-archive $(X86_LIBS) -Wl,--no-whole-archive $(LDLIBS)

# CMake may update its archives while make is considering order-only
# prerequisites. Check their actual timestamps after the CMake build finishes.
x64-relink-check:

$(BUILD_DIR)/x64/mpclient_x64: $(BUILD_DIR)/x64/mpclient.o $(BUILD_DIR)/x64/log/log.o $(X64_LIBS) exports.lst x64-relink-check
	@relink=; if [ ! -f $@ ]; then relink=1; fi; \
	for input in $(filter %.o,$^) $(X64_LIBS) exports.lst; do \
		if [ "$$input" -nt "$@" ]; then relink=1; fi; \
	done; \
	if [ -n "$$relink" ]; then \
		set -x; $(CC) -m64 $(LDFLAGS) -o $@ $(filter %.o,$^) -Wl,--whole-archive $(X64_LIBS) -Wl,--no-whole-archive $(LDLIBS); \
	fi

clean:
	rm -rf $(BUILD_DIR)

-include $(LOADER_x86:.o=.d) $(LOADER_x64:.o=.d) $(DISASM_OBJECTS:.o=.d) \
         $(BUILD_DIR)/x86/intercept/src/hook_x86.d \
         $(BUILD_DIR)/x86/mpclient.d $(BUILD_DIR)/x86/log/log.d \
         $(BUILD_DIR)/x64/mpclient.d $(BUILD_DIR)/x64/log/log.d \
         $(BUILD_DIR)/x86/tests/mpengine_layout.d $(BUILD_DIR)/x64/tests/mpengine_layout.d
