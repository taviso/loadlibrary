PIN_ROOT = $(CURDIR)/$(wildcard pin-*-gcc-linux)
CONFIG_ROOT = $(PIN_ROOT)/source/tools/Config
PIN = $(PIN_ROOT)/pin
TARGET = ia32
KIT = 1

include $(PIN_ROOT)/source/tools/Config/makefile.config

CXXFLAGS = -Wall -O3 -fno-stack-protector -fpermissive -march=native
CFLAGS = -O3 -fomit-frame-pointer -Wall -DNDEBUG -fno-stack-protector -fPIC -march=native
LDFLAGS = -Wl,-O1 -Wl,--as-needed

# I dont need these default targets
dir:
libs:
objects:
dlls:
apps:
libs:

tools: deepcover.so
	@echo \#!/bin/sh > pin
	@echo exec $(PIN_ROOT)/pin \$$\@ >> pin
	@chmod +x pin

OBJS = tree.o deepcover.o instrument.o

%.o : %.cpp
	$(CXX) $(COMP_OBJ) $@ $(CXXFLAGS) $(TOOL_CXXFLAGS) $<

%.o : %.c
	$(CC) $(COMP_OBJ) $@ $(CFLAGS) $(TOOL_CFLAGS) $<

deepcover.so : $(OBJS)
	$(CXX) $(LINK_EXE) $@ $(LDFLAGS) $(TOOL_LDFLAGS) $(OBJS) $(TOOL_LPATHS) $(TOOL_LIBS) -static-libgcc -static-libstdc++

coverage_parse_min: coverage_parse_min.c
	gcc -std=gnu99 $(CFLAGS) $(LDFLAGS) $(shell pkg-config glib-2.0 --cflags) -o $@ $<  $(shell pkg-config glib-2.0 --libs)

clean:
	rm -f *.o deepcover.so core *.core pin *.log blocks.txt coverage.txt summary.txt
	rm -f coverage_parse_min
