CFLAGS    	 = -march=native -ggdb3 -std=gnu99 -fshort-wchar -fno-omit-frame-pointer -Wno-multichar -I../include -I../log -mstackrealign -maccumulate-outgoing-args
CPPFLAGS  	 = -D_GNU_SOURCE -I. -I../intercept/include
LDFLAGS   	 = $(CFLAGS) -lm
ARCH	  	 = x64
OBJECT_FILES = winstrings.o pe_linker.o crt.o util.o extra.o file_mapping.o

ifeq ($(ARCH),x86)
	CFLAGS  += -m32
	LDFLAGS += -m32
else ifneq ($(ARCH),x64)
$(error Supported target architectures: x86 or x64)
endif

RELEASE_CFLAGS 	 = -O3
RELEASE_CPPFLAGS = -DNDEBUG
DEBUG_CFLAGS 	 = -O0 -g

.PHONY: clean

# Compile the exception implementation for the selected architecture only.
WINAPI_SOURCES = $(filter-out winapi/Exception_x86.c winapi/Exception_x64.c,$(wildcard winapi/*.c))
WINAPI_SOURCES += winapi/Exception_$(ARCH).c
WINAPI = $(patsubst %.c,%.o,$(WINAPI_SOURCES))

TARGETS=libpeloader.a

all: CFLAGS += $(RELEASE_CFLAGS)
all: CPPFLAGS += $(RELEASE_CPPFLAGS)
all: $(TARGETS)

debug: CFLAGS += $(DEBUG_CFLAGS)
debug: $(TARGETS)

libpeloader.a: $(WINAPI) $(OBJECT_FILES)
	rm -f $@
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f a.out core *.o core.* vgcore.* gmon.out winapi/*.o $(TARGETS)