/*
 * Copyright (c) 2012-2018 Zeex
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>

#define SUBHOOK_CODE_PROTECT_FLAGS (PROT_READ | PROT_WRITE | PROT_EXEC)

int subhook_unprotect(void *address, size_t size) {
  long pagesize;

  pagesize = sysconf(_SC_PAGESIZE);
  address = (void *)((long)address & ~(pagesize - 1));

  return mprotect(address, size, SUBHOOK_CODE_PROTECT_FLAGS);
}

void *subhook_alloc_code(size_t size) {
  void *address;

  address = mmap(NULL,
                 size,
                 SUBHOOK_CODE_PROTECT_FLAGS,
                 #if defined MAP_32BIT && !defined __APPLE__
                   MAP_32BIT |
                 #endif
                 MAP_PRIVATE | MAP_ANONYMOUS,
                 -1,
                 0);
  return address == MAP_FAILED ? NULL : address;
}

int subhook_free_code(void *address, size_t size) {
  if (address == NULL) {
    return 0;
  }
  return munmap(address, size);
}
