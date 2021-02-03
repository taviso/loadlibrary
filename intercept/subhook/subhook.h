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

#ifndef SUBHOOK_H
#define SUBHOOK_H

#include <stddef.h>

#if defined _M_IX86 || defined __i386__
  #define SUBHOOK_X86
  #define SUBHOOK_BITS 32
#elif defined _M_AMD64 || __amd64__
  #define SUBHOOK_X86_64
  #define SUBHOOK_BITS 64
#else
  #error Unsupported architecture
#endif

#if defined _WIN32 || defined __CYGWIN__
  #define SUBHOOK_WINDOWS
#elif defined __linux__ || defined __APPLE__ \
   || defined __FreeBSD__ || defined __OpenBSD__ || defined __NetBSD__
  #define SUBHOOK_UNIX
#else
  #error Unsupported operating system
#endif

#if !defined SUBHOOK_EXTERN
  #if defined __cplusplus
    #define SUBHOOK_EXTERN extern "C"
  #else
    #define SUBHOOK_EXTERN extern
  #endif
#endif

#if defined SUBHOOK_STATIC
  #define SUBHOOK_API
  #define SUBHOOK_EXPORT SUBHOOK_EXTERN
#endif

#if !defined SUBHOOK_API
  #if defined SUBHOOK_X86
    #if defined SUBHOOK_WINDOWS
      #define SUBHOOK_API __cdecl
    #elif defined SUBHOOK_UNIX
      #define SUBHOOK_API __attribute__((cdecl))
    #endif
  #else
    #define SUBHOOK_API
  #endif
#endif

#if !defined SUBHOOK_EXPORT
  #if defined SUBHOOK_WINDOWS
    #if defined SUBHOOK_IMPLEMENTATION
      #define SUBHOOK_EXPORT SUBHOOK_EXTERN __declspec(dllexport)
    #else
      #define SUBHOOK_EXPORT SUBHOOK_EXTERN __declspec(dllimport)
    #endif
  #elif defined SUBHOOK_UNIX
    #if defined SUBHOOK_IMPLEMENTATION
      #define SUBHOOK_EXPORT SUBHOOK_EXTERN __attribute__((visibility("default")))
    #else
      #define SUBHOOK_EXPORT SUBHOOK_EXTERN
    #endif
  #endif
#endif

typedef enum subhook_flags {
  /* Use the 64-bit jump method on x86-64 (requires more space). */
  SUBHOOK_64BIT_OFFSET = 1
} subhook_flags_t;

struct subhook_struct;
typedef struct subhook_struct *subhook_t;

typedef int (SUBHOOK_API *subhook_disasm_handler_t)(
  void *src,
  int *reloc_op_offset);

SUBHOOK_EXPORT subhook_t SUBHOOK_API subhook_new(
  void *src,
  void *dst,
  subhook_flags_t flags);
SUBHOOK_EXPORT void SUBHOOK_API subhook_free(subhook_t hook);

SUBHOOK_EXPORT void *SUBHOOK_API subhook_get_src(subhook_t hook);
SUBHOOK_EXPORT void *SUBHOOK_API subhook_get_dst(subhook_t hook);
SUBHOOK_EXPORT void *SUBHOOK_API subhook_get_trampoline(subhook_t hook);

SUBHOOK_EXPORT int SUBHOOK_API subhook_install(subhook_t hook);
SUBHOOK_EXPORT int SUBHOOK_API subhook_is_installed(subhook_t hook);
SUBHOOK_EXPORT int SUBHOOK_API subhook_remove(subhook_t hook);

/*
 * Reads hook destination address from code.
 *
 * This function may be useful when you don't know the address or want to
 * check whether src is already hooked.
 */
SUBHOOK_EXPORT void *SUBHOOK_API subhook_read_dst(void *src);

/*
 * Returns the length of the first instruction in src. You can replace it with
 * a custom function via subhook_set_disasm_handler.
 */
SUBHOOK_EXPORT int SUBHOOK_API subhook_disasm(void *src, int *reloc_op_offset);

/*
 * Sets a custom disassmbler function to use in place of the default one
 * (subhook_disasm).
 *
 * The default function can recognize only a small subset of x86 instructions
 * commonly used in prologues. If it fails in your situation, you might want
 * to use a more advanced disassembler library.
 */
SUBHOOK_EXPORT void SUBHOOK_API subhook_set_disasm_handler(
  subhook_disasm_handler_t handler);

#ifdef __cplusplus

namespace subhook {

enum HookFlags {
  HookNoFlags = 0,
  HookFlag64BitOffset = SUBHOOK_64BIT_OFFSET
};

inline HookFlags operator|(HookFlags o1, HookFlags o2) {
  return static_cast<HookFlags>(
      static_cast<unsigned int>(o1) | static_cast<unsigned int>(o2));
}

inline HookFlags operator&(HookFlags o1, HookFlags o2) {
  return static_cast<HookFlags>(
      static_cast<unsigned int>(o1) & static_cast<unsigned int>(o2));
}

inline void *ReadHookDst(void *src) {
  return subhook_read_dst(src);
}

inline void SetDisasmHandler(subhook_disasm_handler_t handler) {
  subhook_set_disasm_handler(handler);
}

class Hook {
 public:
  Hook() : hook_(NULL) {}
  Hook(void *src, void *dst, HookFlags flags = HookNoFlags)
    : hook_(subhook_new(src, dst, (subhook_flags_t)flags))
  {
  }

  ~Hook() {
    subhook_remove(hook_);
    subhook_free(hook_);
  }

  void *GetSrc() const { return subhook_get_src(hook_); }
  void *GetDst() const { return subhook_get_dst(hook_); }
  void *GetTrampoline() const { return subhook_get_trampoline(hook_); }

  bool Install() {
    return subhook_install(hook_) == 0;
  }

  bool Install(void *src,
               void *dst,
               HookFlags flags = HookNoFlags) {
    if (hook_ != NULL) {
      subhook_remove(hook_);
      subhook_free(hook_);
    }
    hook_ = subhook_new(src, dst, (subhook_flags_t)flags);
    if (hook_ == NULL) {
      return false;
    }
    return Install();
  }

  bool Remove() {
    return subhook_remove(hook_) == 0;
  }

  bool IsInstalled() const {
    return !!subhook_is_installed(hook_);
  }

 private:
  Hook(const Hook &);
  void operator=(const Hook &);

 private:
  subhook_t hook_;
};

class ScopedHookRemove {
 public:
  ScopedHookRemove(Hook *hook)
    : hook_(hook),
      removed_(hook_->Remove())
  {
  }

  ~ScopedHookRemove() {
    if (removed_) {
      hook_->Install();
    }
  }

 private:
  ScopedHookRemove(const ScopedHookRemove &);
  void operator=(const ScopedHookRemove &);

 private:
  Hook *hook_;
  bool removed_;
};

class ScopedHookInstall {
 public:
  ScopedHookInstall(Hook *hook)
    : hook_(hook),
      installed_(hook_->Install())
  {
  }

  ScopedHookInstall(Hook *hook,
                    void *src,
                    void *dst,
                    HookFlags flags = HookNoFlags)
    : hook_(hook),
      installed_(hook_->Install(src, dst, flags))
  {
  }

  ~ScopedHookInstall() {
    if (installed_) {
      hook_->Remove();
    }
  }

 private:
  ScopedHookInstall(const ScopedHookInstall &);
  void operator=(const ScopedHookInstall &);

 private:
  Hook *hook_;
  bool installed_;
};

} // namespace subhook

#endif /* __cplusplus */

#endif /* SUBHOOK_H */
