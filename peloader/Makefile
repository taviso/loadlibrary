# Compatibility entry points; the top-level Makefile owns all build artifacts.
ARCH ?= x64
ifeq ($(ARCH),x86)
LOADER_TARGET := peloader
else ifeq ($(ARCH),x64)
LOADER_TARGET := peloader_x64
else
$(error Supported target architectures: x86 or x64)
endif

.PHONY: all debug clean
all:
	$(MAKE) -C .. $(LOADER_TARGET)

debug:
	$(MAKE) -C .. BUILD_DIR=build/debug BUILD_MODE=debug $(LOADER_TARGET)

clean:
	$(MAKE) -C .. clean
