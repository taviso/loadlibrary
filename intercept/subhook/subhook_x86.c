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

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "subhook.h"
#include "subhook_private.h"

#ifdef SUBHOOK_WINDOWS
  #define INT32_MAX 0x7fffffff
  #define INT32_MIN (-INT32_MAX - 1)
  typedef unsigned __int8 uint8_t;
  typedef __int32 int32_t;
  typedef unsigned __int32 uint32_t;
  typedef __int64 int64_t;
  #ifdef SUBHOOK_X86_64
    typedef __int64 intptr_t;
    typedef unsigned __int64 uintptr_t;
  #else
    typedef __int32 intptr_t;
    typedef unsigned __int32 uintptr_t;
  #endif
#else
  #include <stdint.h>
#endif

#define ABS(x) ((x) >= 0 ? (x) : -(x))
#define MAX_INSN_LEN 15 /* maximum length of x86 instruction */

#define JMP_OPCODE  0xE9
#define PUSH_OPCODE 0x68
#define MOV_OPCODE  0xC7
#define RET_OPCODE  0xC3

#define JMP64_MOV_MODRM  0x44 /* write to address + 1 byte displacement */
#define JMP64_MOV_SIB    0x24 /* write to [rsp] */
#define JMP64_MOV_OFFSET 0x04

#define CHECK_INT32_OVERFLOW(x) \
  ((int64_t)(x) < INT32_MIN || ((int64_t)(x)) > INT32_MAX)

#pragma pack(push, 1)

struct subhook_jmp32 {
  uint8_t opcode;
  int32_t offset;
};

/* Since AMD64 doesn't support 64-bit direct jumps, we'll push the address
 * onto the stack, then call RET.
 */
struct subhook_jmp64 {
  uint8_t  push_opcode;
  uint32_t push_addr; /* lower 32-bits of the address to jump to */
  uint8_t  mov_opcode;
  uint8_t  mov_modrm;
  uint8_t  mov_sib;
  uint8_t  mov_offset;
  uint32_t mov_addr;  /* upper 32-bits of the address to jump to */
  uint8_t  ret_opcode;
};

#pragma pack(pop)

extern subhook_disasm_handler_t subhook_disasm_handler;

SUBHOOK_EXPORT int SUBHOOK_API subhook_disasm(void *src, int *reloc_op_offset) {
  enum flags {
    MODRM      = 1,
    PLUS_R     = 1 << 1,
    REG_OPCODE = 1 << 2,
    IMM8       = 1 << 3,
    IMM16      = 1 << 4,
    IMM32      = 1 << 5,
    RELOC      = 1 << 6
  };

  static uint8_t prefixes[] = {
    0xF0, 0xF2, 0xF3,
    0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65,
    0x66, /* operand size override */
    0x67  /* address size override */
  };

  struct opcode_info {
    uint8_t opcode;
    uint8_t reg_opcode;
    unsigned int flags;
  };

  /*
   * See the Intel Developer Manual volumes 2a and 2b for more information
   * about instruction format and encoding:
   *
   * https://www-ssl.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html
   */
  static struct opcode_info opcodes[] = {
    /* ADD AL, imm8      */ {0x04, 0, IMM8},
    /* ADD EAX, imm32    */ {0x05, 0, IMM32},
    /* ADD r/m8, imm8    */ {0x80, 0, MODRM | REG_OPCODE | IMM8},
    /* ADD r/m32, imm32  */ {0x81, 0, MODRM | REG_OPCODE | IMM32},
    /* ADD r/m32, imm8   */ {0x83, 0, MODRM | REG_OPCODE | IMM8},
    /* ADD r/m8, r8      */ {0x00, 0, MODRM},
    /* ADD r/m32, r32    */ {0x01, 0, MODRM},
    /* ADD r8, r/m8      */ {0x02, 0, MODRM},
    /* ADD r32, r/m32    */ {0x03, 0, MODRM},
    /* AND AL, imm8      */ {0x24, 0, IMM8},
    /* AND EAX, imm32    */ {0x25, 0, IMM32},
    /* AND r/m8, imm8    */ {0x80, 4, MODRM | REG_OPCODE | IMM8},
    /* AND r/m32, imm32  */ {0x81, 4, MODRM | REG_OPCODE | IMM32},
    /* AND r/m32, imm8   */ {0x83, 4, MODRM | REG_OPCODE | IMM8},
    /* AND r/m8, r8      */ {0x20, 0, MODRM},
    /* AND r/m32, r32    */ {0x21, 0, MODRM},
    /* AND r8, r/m8      */ {0x22, 0, MODRM},
    /* AND r32, r/m32    */ {0x23, 0, MODRM},
    /* CALL rel32        */ {0xE8, 0, IMM32 | RELOC},
    /* CALL r/m32        */ {0xFF, 2, MODRM | REG_OPCODE},
    /* CMP r/m32, imm8   */ {0x83, 7, MODRM | REG_OPCODE | IMM8},
    /* CMP r/m32, r32    */ {0x39, 0, MODRM},
    /* DEC r/m32         */ {0xFF, 1, MODRM | REG_OPCODE},
    /* DEC r32           */ {0x48, 0, PLUS_R},
    /* ENTER imm16, imm8 */ {0xC8, 0, IMM16 | IMM8},
    /* FLD m32fp         */ {0xD9, 0, MODRM | REG_OPCODE},
    /* FLD m64fp         */ {0xDD, 0, MODRM | REG_OPCODE},
    /* FLD m80fp         */ {0xDB, 5, MODRM | REG_OPCODE},
    /* INT 3             */ {0xCC, 0, 0},
    /* JMP rel32         */ {0xE9, 0, IMM32 | RELOC},
    /* JMP r/m32         */ {0xFF, 4, MODRM | REG_OPCODE},
    /* LEA r32,m         */ {0x8D, 0, MODRM},
    /* LEAVE             */ {0xC9, 0, 0},
    /* MOV r/m8,r8       */ {0x88, 0, MODRM},
    /* MOV r/m32,r32     */ {0x89, 0, MODRM},
    /* MOV r8,r/m8       */ {0x8A, 0, MODRM},
    /* MOV r32,r/m32     */ {0x8B, 0, MODRM},
    /* MOV r/m16,Sreg    */ {0x8C, 0, MODRM},
    /* MOV Sreg,r/m16    */ {0x8E, 0, MODRM},
    /* MOV AL,moffs8     */ {0xA0, 0, IMM8},
    /* MOV EAX,moffs32   */ {0xA1, 0, IMM32},
    /* MOV moffs8,AL     */ {0xA2, 0, IMM8},
    /* MOV moffs32,EAX   */ {0xA3, 0, IMM32},
    /* MOV r8, imm8      */ {0xB0, 0, PLUS_R | IMM8},
    /* MOV r32, imm32    */ {0xB8, 0, PLUS_R | IMM32},
    /* MOV r/m8, imm8    */ {0xC6, 0, MODRM | REG_OPCODE | IMM8},
    /* MOV r/m32, imm32  */ {0xC7, 0, MODRM | REG_OPCODE | IMM32},
    /* NOP               */ {0x90, 0, 0},
    /* OR AL, imm8       */ {0x0C, 0, IMM8},
    /* OR EAX, imm32     */ {0x0D, 0, IMM32},
    /* OR r/m8, imm8     */ {0x80, 1, MODRM | REG_OPCODE | IMM8},
    /* OR r/m32, imm32   */ {0x81, 1, MODRM | REG_OPCODE | IMM32},
    /* OR r/m32, imm8    */ {0x83, 1, MODRM | REG_OPCODE | IMM8},
    /* OR r/m8, r8       */ {0x08, 0, MODRM},
    /* OR r/m32, r32     */ {0x09, 0, MODRM},
    /* OR r8, r/m8       */ {0x0A, 0, MODRM},
    /* OR r32, r/m32     */ {0x0B, 0, MODRM},
    /* POP r/m32         */ {0x8F, 0, MODRM | REG_OPCODE},
    /* POP r32           */ {0x58, 0, PLUS_R},
    /* PUSH r/m32        */ {0xFF, 6, MODRM | REG_OPCODE},
    /* PUSH r32          */ {0x50, 0, PLUS_R},
    /* PUSH imm8         */ {0x6A, 0, IMM8},
    /* PUSH imm32        */ {0x68, 0, IMM32},
    /* RET               */ {0xC3, 0, 0},
    /* RET imm16         */ {0xC2, 0, IMM16},
    /* SUB AL, imm8      */ {0x2C, 0, IMM8},
    /* SUB EAX, imm32    */ {0x2D, 0, IMM32},
    /* SUB r/m8, imm8    */ {0x80, 5, MODRM | REG_OPCODE | IMM8},
    /* SUB r/m32, imm32  */ {0x81, 5, MODRM | REG_OPCODE | IMM32},
    /* SUB r/m32, imm8   */ {0x83, 5, MODRM | REG_OPCODE | IMM8},
    /* SUB r/m8, r8      */ {0x28, 0, MODRM},
    /* SUB r/m32, r32    */ {0x29, 0, MODRM},
    /* SUB r8, r/m8      */ {0x2A, 0, MODRM},
    /* SUB r32, r/m32    */ {0x2B, 0, MODRM},
    /* TEST AL, imm8     */ {0xA8, 0, IMM8},
    /* TEST EAX, imm32   */ {0xA9, 0, IMM32},
    /* TEST r/m8, imm8   */ {0xF6, 0, MODRM | REG_OPCODE | IMM8},
    /* TEST r/m32, imm32 */ {0xF7, 0, MODRM | REG_OPCODE | IMM32},
    /* TEST r/m8, r8     */ {0x84, 0, MODRM},
    /* TEST r/m32, r32   */ {0x85, 0, MODRM},
    /* XOR AL, imm8      */ {0x34, 0, IMM8},
    /* XOR EAX, imm32    */ {0x35, 0, IMM32},
    /* XOR r/m8, imm8    */ {0x80, 6, MODRM | REG_OPCODE | IMM8},
    /* XOR r/m32, imm32  */ {0x81, 6, MODRM | REG_OPCODE | IMM32},
    /* XOR r/m32, imm8   */ {0x83, 6, MODRM | REG_OPCODE | IMM8},
    /* XOR r/m8, r8      */ {0x30, 0, MODRM},
    /* XOR r/m32, r32    */ {0x31, 0, MODRM},
    /* XOR r8, r/m8      */ {0x32, 0, MODRM},
    /* XOR r32, r/m32    */ {0x33, 0, MODRM}
  };

  uint8_t *code = src;
  size_t i;
  int len = 0;
  int operand_size = 4;
  uint8_t opcode = 0;
  int found_opcode = false;

  for (i = 0; i < sizeof(prefixes) / sizeof(*prefixes); i++) {
    if (code[len] == prefixes[i]) {
      len++;
      if (prefixes[i] == 0x66) {
        operand_size = 2;
      }
    }
  }

#ifdef SUBHOOK_X86_64
  if ((code[len] & 0xF0) == 0x40) {
    /* This is a REX prefix (40H - 4FH). REX prefixes are valid only in
     * 64-bit mode.
     */
    uint8_t rex = code[len++];

    if (rex & 8) {
      /* REX.W changes size of immediate operand to 64 bits. */
      operand_size = 8;
    }
  }
#endif

  for (i = 0; i < sizeof(opcodes) / sizeof(*opcodes); i++) {
    if (code[len] == opcodes[i].opcode) {
      if (opcodes[i].flags & REG_OPCODE) {
        found_opcode = ((code[len + 1] >> 3) & 7) == opcodes[i].reg_opcode;
      } else {
        found_opcode = true;
      }
    }

    if ((opcodes[i].flags & PLUS_R)
      && (code[len] & 0xF8) == opcodes[i].opcode) {
      found_opcode = true;
    }

    if (found_opcode) {
      opcode = code[len++];
      break;
    }
  }

  if (!found_opcode) {
    return 0;
  }

  if (reloc_op_offset != NULL && opcodes[i].flags & RELOC) {
    /* Either a call or a jump instruction that uses an absolute or relative
     * 32-bit address.
     *
     * Note: We don't support short (8-bit) offsets at the moment, so the
     * caller can assume the operand will be always 4 bytes.
     */
    *reloc_op_offset = len;
  }

  if (opcodes[i].flags & MODRM) {
    uint8_t modrm = code[len++]; /* +1 for Mod/RM byte */
    uint8_t mod = modrm >> 6;
    uint8_t rm = modrm & 0x07;

    if (mod != 3 && rm == 4) {
      uint8_t sib = code[len++]; /* +1 for SIB byte */
      uint8_t base = sib & 0x07;

      if (base == 5) {
        /* The SIB is followed by a disp32 with no base if the MOD is 00B.
         * Otherwise, disp8 or disp32 + [EBP].
         */
        if (mod == 1) {
          len += 1; /* for disp8 */
        } else {
          len += 4; /* for disp32 */
        }
      }
    }

#ifdef SUBHOOK_X86_64
    if (reloc_op_offset != NULL && mod == 0 && rm == 5) {
      /* RIP-relative addressing: target is at [RIP + disp32]. */
      *reloc_op_offset = (int32_t)len;
    }
#endif

    if (mod == 1) {
      len += 1; /* for disp8 */
    }
    if (mod == 2 || (mod == 0 && rm == 5)) {
      len += 4; /* for disp32 */
    }
  }

  if (opcodes[i].flags & IMM8) {
    len += 1;
  }
  if (opcodes[i].flags & IMM16) {
    len += 2;
  }
  if (opcodes[i].flags & IMM32) {
    len += operand_size;
  }

  return len;
}

static size_t subhook_get_jmp_size(subhook_flags_t flags) {
#ifdef SUBHOOK_X86_64
  if ((flags & SUBHOOK_64BIT_OFFSET) != 0) {
    return sizeof(struct subhook_jmp64);
  }
#else
  (void)flags;
#endif
  return sizeof(struct subhook_jmp32);
}

static int subhook_make_jmp32(void *src, void *dst) {
  struct subhook_jmp32 *jmp = (struct subhook_jmp32 *)src;
  intptr_t src_addr = (intptr_t)src;
  intptr_t dst_addr = (intptr_t)dst;
#ifdef SUBHOOK_X86_64
  int64_t distance = ABS(src_addr - dst_addr);
#endif

#ifdef SUBHOOK_X86_64
  if (CHECK_INT32_OVERFLOW(distance)) {
    return -EOVERFLOW;
  }
#endif

  jmp->opcode = JMP_OPCODE;
  jmp->offset = (int32_t)(dst_addr - (src_addr + sizeof(*jmp)));

  return 0;
}

#ifdef SUBHOOK_X86_64

static int subhook_make_jmp64(void *src, void *dst) {
  struct subhook_jmp64 *jmp = (struct subhook_jmp64 *)src;

  jmp->push_opcode = PUSH_OPCODE;
  jmp->push_addr = (uint32_t)(uintptr_t)dst; /* truncate */
  jmp->mov_opcode = MOV_OPCODE;
  jmp->mov_modrm = JMP64_MOV_MODRM;
  jmp->mov_sib = JMP64_MOV_SIB;
  jmp->mov_offset = JMP64_MOV_OFFSET;
  jmp->mov_addr = (uint32_t)(((uintptr_t)dst) >> 32);
  jmp->ret_opcode = RET_OPCODE;

  return 0;
}

#endif

static int subhook_make_jmp(void *src,
                            void *dst,
                            subhook_flags_t flags) {
#ifdef SUBHOOK_X86_64
  if ((flags & SUBHOOK_64BIT_OFFSET) != 0) {
    return subhook_make_jmp64(src, dst);
  }
#else
  (void)flags;
#endif
  return subhook_make_jmp32(src, dst);
}

static int subhook_make_trampoline(void *trampoline,
                                   void *src,
                                   size_t jmp_size,
                                   size_t *trampoline_len,
                                   subhook_flags_t flags) {
  size_t orig_size = 0;
  size_t insn_len;
  intptr_t trampoline_addr = (intptr_t)trampoline;
  intptr_t src_addr = (intptr_t)src;
  subhook_disasm_handler_t disasm_handler =
    subhook_disasm_handler != NULL ? subhook_disasm_handler : subhook_disasm;

  assert(trampoline_len != NULL);

  /* Determine how many bytes of original code needs to be copied over
   * to the trampoline.
   */
  while (orig_size < jmp_size) {
    int reloc_op_offset = 0;

    insn_len =
      disasm_handler((void *)(src_addr + orig_size), &reloc_op_offset);

    if (insn_len == 0) {
      return -EINVAL;
    }

    /* Copy this instruction to the trampoline.
     */
    memcpy((void *)(trampoline_addr + orig_size),
           (void *)(src_addr + orig_size),
           insn_len);

    /* If the operand is a relative address, such as found in calls or jumps,
     * it needs to be relocated because the original code and the trampoline
     * reside at different locations in memory.
     */
    if (reloc_op_offset > 0) {
      /* Calculate how far our trampoline is from the source and change the
       * address accordingly.
       */
      intptr_t offset = trampoline_addr - src_addr;
#ifdef SUBHOOK_X86_64
      if (CHECK_INT32_OVERFLOW(offset)) {
        /*
         * Oops! It looks like the two locations are too far away from each
         * other! This is not going to work...
         */
        *trampoline_len = 0;
        return -EOVERFLOW;
      }
#endif
      int32_t *op = (int32_t *)(trampoline_addr + orig_size + reloc_op_offset);
      *op -= (int32_t)offset;
    }

    orig_size += insn_len;
  }

  *trampoline_len = orig_size + jmp_size;

  /* Insert the final jump. It goes back to the original code at
   * src + orig_size.
   */
  return subhook_make_jmp((void *)(trampoline_addr + orig_size),
                          (void *)(src_addr + orig_size),
                          flags);
}

SUBHOOK_EXPORT subhook_t SUBHOOK_API subhook_new(void *src,
                                                 void *dst,
                                                 subhook_flags_t flags) {
  subhook_t hook;
  int error;

  hook = calloc(1, sizeof(*hook));
  if (hook == NULL) {
    return NULL;
  }

  hook->src = src;
  hook->dst = dst;
  hook->flags = flags;
  hook->jmp_size = subhook_get_jmp_size(hook->flags);
  hook->trampoline_size = hook->jmp_size * 2 + MAX_INSN_LEN;

  hook->code = malloc(hook->jmp_size);
  if (hook->code == NULL) {
    goto error_exit;
  }

  memcpy(hook->code, hook->src, hook->jmp_size);

  error = subhook_unprotect(hook->src, hook->jmp_size);
  if (error != 0) {
    goto error_exit;
  }

  hook->trampoline = subhook_alloc_code(hook->trampoline_size);
  if (hook->trampoline != NULL) {
    error = subhook_make_trampoline(hook->trampoline,
                                    hook->src,
                                    hook->jmp_size,
                                    &hook->trampoline_len,
                                    hook->flags);
    if (error != 0) {
      subhook_free_code(hook->trampoline, hook->trampoline_size);
      hook->trampoline = NULL;
      hook->trampoline_size = 0;
      hook->trampoline_len = 0;
    }
  }

  return hook;

error_exit:
  subhook_free_code(hook->trampoline, hook->trampoline_size);
  free(hook->code);
  free(hook);

  return NULL;
}

SUBHOOK_EXPORT void SUBHOOK_API subhook_free(subhook_t hook) {
  if (hook == NULL) {
    return;
  }

  subhook_free_code(hook->trampoline, hook->trampoline_size);
  free(hook->code);
  free(hook);
}

SUBHOOK_EXPORT int SUBHOOK_API subhook_install(subhook_t hook) {
  int error;

  if (hook == NULL) {
    return -EINVAL;
  }
  if (hook->installed) {
    return -EINVAL;
  }

  error = subhook_make_jmp(hook->src, hook->dst, hook->flags);
  if (error >= 0) {
    hook->installed = true;
    return 0;
  }

  return error;
}

SUBHOOK_EXPORT int SUBHOOK_API subhook_remove(subhook_t hook) {
  if (hook == NULL) {
    return -EINVAL;
  }
  if (!hook->installed) {
    return -EINVAL;
  }

  memcpy(hook->src, hook->code, hook->jmp_size);
  hook->installed = 0;

  return 0;
}

SUBHOOK_EXPORT void *SUBHOOK_API subhook_read_dst(void *src)  {
  struct subhook_jmp32 *maybe_jmp32 = (struct subhook_jmp32 *)src;
#ifdef SUBHOOK_X86_64
  struct subhook_jmp64 *maybe_jmp64 = (struct subhook_jmp64 *)src;
#endif

  if (maybe_jmp32->opcode == JMP_OPCODE) {
    return (void *)(
      maybe_jmp32->offset + (uintptr_t)src + sizeof(*maybe_jmp32));
  }

#ifdef SUBHOOK_X86_64
  if (maybe_jmp64->push_opcode == PUSH_OPCODE
    && maybe_jmp64->mov_opcode == MOV_OPCODE
    && maybe_jmp64->mov_modrm == JMP64_MOV_MODRM
    && maybe_jmp64->mov_sib == JMP64_MOV_SIB
    && maybe_jmp64->mov_offset == JMP64_MOV_OFFSET
    && maybe_jmp64->ret_opcode == RET_OPCODE) {
    return (void *)(
      maybe_jmp64->push_addr & ((uintptr_t)maybe_jmp64->mov_addr << 32));
  }
#endif

  return NULL;
}
