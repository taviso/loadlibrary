.DEFAULT_GOAL := all

BUILD_DIR ?= ../build
BUILD_DIR := $(abspath $(BUILD_DIR))
PIN_ROOT ?= $(firstword $(wildcard $(CURDIR)/pin-*-gcc-linux))

CFLAGS = -O3 -fomit-frame-pointer -Wall -DNDEBUG -fno-stack-protector -fPIC -march=native
CXXFLAGS = -Wall -O3 -fno-stack-protector -fpermissive -march=native
LDFLAGS = -Wl,-O1 -Wl,--as-needed

.PHONY: all x86 x64 tool clean
all: x86 x64 $(BUILD_DIR)/coverage/coverage_parse_min

x86:
	+$(MAKE) COVERAGE_ARCH=x86 tool

x64:
	+$(MAKE) COVERAGE_ARCH=x64 tool

$(BUILD_DIR)/coverage/coverage_parse_min: coverage_parse_min.c Makefile
	@mkdir -p $(@D)
	$(CC) -std=gnu99 $(CFLAGS) $(LDFLAGS) $(shell pkg-config glib-2.0 --cflags) -o $@ $< $(shell pkg-config glib-2.0 --libs)

clean:
	rm -rf $(BUILD_DIR)/x86/coverage $(BUILD_DIR)/x64/coverage $(BUILD_DIR)/coverage

ifneq ($(COVERAGE_ARCH),)
ifeq ($(COVERAGE_ARCH),x86)
override TARGET := ia32
else ifeq ($(COVERAGE_ARCH),x64)
override TARGET := intel64
else
$(error Supported COVERAGE_ARCH values: x86 or x64)
endif

ifeq ($(PIN_ROOT),)
$(error No Pin kit found under coverage/; set PIN_ROOT to its directory)
endif

CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
KIT := 1
include $(CONFIG_ROOT)/makefile.config

# Pin's configuration provides the compiler, linker, and architecture flags.
# Its default targets are not needed by this small standalone pintool.
dir:
libs:
objects:
dlls:
apps:

OUT := $(BUILD_DIR)/$(COVERAGE_ARCH)/coverage
OBJS := $(OUT)/tree.o $(OUT)/deepcover.o $(OUT)/instrument.o

tool: $(OUT)/deepcover.so $(OUT)/pin

$(OUT):
	@mkdir -p $@

$(OUT)/%.o: %.cpp Makefile | $(OUT)
	$(TOOL_CXX) $(COMP_OBJ) $@ $(CXXFLAGS) $(TOOL_CXXFLAGS) $<

$(OUT)/%.o: %.c Makefile | $(OUT)
	$(TOOL_CC) $(COMP_OBJ) $@ $(CFLAGS) $(TOOL_CFLAGS) $<

$(OUT)/tree.o: tree.h
$(OUT)/instrument.o: instrument.h tree.h
$(OUT)/deepcover.o: instrument.h tree.h blacklist.h

$(OUT)/deepcover.so: $(OBJS)
	$(TOOL_LINKER) $(LINK_EXE) $@ $(LDFLAGS) $(TOOL_LDFLAGS) $(OBJS) $(TOOL_LPATHS) $(TOOL_LIBS) -static-libgcc -static-libstdc++

$(OUT)/pin: Makefile | $(OUT)
	@printf '#!/bin/sh\nexec "$(PIN_ROOT)/pin" "$$@"\n' > $@
	@chmod +x $@
endif
