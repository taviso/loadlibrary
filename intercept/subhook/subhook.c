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

#include "subhook.h"
#include "subhook_private.h"

subhook_disasm_handler_t subhook_disasm_handler = NULL;

SUBHOOK_EXPORT void *SUBHOOK_API subhook_get_src(subhook_t hook) {
  if (hook == NULL) {
    return NULL;
  }
  return hook->src;
}

SUBHOOK_EXPORT void *SUBHOOK_API subhook_get_dst(subhook_t hook) {
  if (hook == NULL) {
    return NULL;
  }
  return hook->dst;
}

SUBHOOK_EXPORT void *SUBHOOK_API subhook_get_trampoline(subhook_t hook) {
  if (hook == NULL) {
    return NULL;
  }
  return hook->trampoline;
}

SUBHOOK_EXPORT int SUBHOOK_API subhook_is_installed(subhook_t hook) {
  if (hook == NULL) {
    return false;
  }
  return hook->installed;
}

SUBHOOK_EXPORT void SUBHOOK_API subhook_set_disasm_handler(
  subhook_disasm_handler_t handler) {
  subhook_disasm_handler = handler;
}

#ifndef SUBHOOK_SEPARATE_SOURCE_FILES

#if defined SUBHOOK_WINDOWS
  #include "subhook_windows.c"
#elif defined SUBHOOK_UNIX
  #include "subhook_unix.c"
#endif

#if defined SUBHOOK_X86 || defined SUBHOOK_X86_64
  #include "subhook_x86.c"
#endif

#endif
