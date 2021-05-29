#ifndef __HOOK_H
#define __HOOK_H

#include "../subhook/subhook.h"

// Flags recognised by insert_function_redirect.
enum ENUM_REDIRECT_FLAGS{
    HOOK_DEFAULT              = 0,
    HOOK_REPLACE_FUNCTION     = (1 << 0),     // Replace call, don't hook.
    HOOK_FASTCALL             = (1 << 1),     // Try to minimize damage to registers.
};

bool insert_function_redirect(void *function, void *target, uint32_t flags);
bool remove_function_redirect(void *function);
bool redirect_call_within_function(void *function, void *target, void *redirect);

// Convenient representation of an x86 near call. The immediate operand is the
// relative, displaced branch target, thus actual address is something like:
//
//      target = (uintptr_t)(&call) + sizeof(struct call) + call->operand.i;
//

struct __attribute__((packed)) branch {
    uint8_t     opcode;
    union {
        uintptr_t   i;
        void       *p;
    } operand;
    uint8_t     data[0];                // Used to chain instructions together.
};

#ifdef __x86_64__
struct __attribute__((packed)) branch64 {
    uint16_t    opcode;
    uint8_t     reg;
    uint8_t     data[0];                // Used to chain instructions together.
};
// Convenient representation of an x64 MOVABS r64, imm64 instruction.
struct __attribute__((packed)) mov_r64_abs_insn {
    uint8_t     opcode;
    uint8_t      reg;
    union {
        uintptr_t   i;
        void       *p;
    } imm;
    uint8_t     data[0];                // Used to chain instructions together.
};

typedef struct mov_r64_abs_insn mov_r64_abs_insn;
#endif

#define X86_64_OPCODE_MOV_ABS_R32   0x48
#define X86_64_OPCODE_MOV_ABS_R64   0x49

#define X86_OPCODE_CALL_NEAR        0xE8
#define X86_64_OPCODE_CALL_REG      0xFF41
#define X86_OPCODE_JMP_NEAR         0xE9
#define X86_64_OPCODE_JMP_NEAR      0xE9

#define X86_OPCODE_NOP              0x90
#define X86_OPCODE_RET              0xC3
#define X86_OPCODE_MOV_EAX_IMM      0xB8
#define X86_OPCODE_PUSH_EBP         0x55
#define X86_64_OPCODE_PUSH_RBP         0x55

#define X86_PREFIX_DATA16           0x66

// This is used to save an arbitrary 2 byte integer in the instuction stream
// without disrupting disassemblers.
struct __attribute__((packed)) encodedsize {
    uint8_t     prefix;     // 0x66
    uint8_t     opcode;     // 0xB8
    uint16_t    operand;
};

static int __stub_zero() { return  0; }
static int __stub_one()  { return  1; }
static int __stub_false(){ return  false; }
static int __stub_true() { return  true; }
static int __stub_neg()  { return -1; }

// Callee clears stubs, common on Windows.
static int __attribute__((stdcall)) __stub_zero_std_4(int a) { return 0; }
static int __attribute__((stdcall)) __stub_zero_std_8(int a, int b) { return 0; }
static int __attribute__((stdcall)) __stub_zero_std_12(int a, int b, int c) { return 0; }
static int __attribute__((stdcall)) __stub_zero_std_16(int a, int b, int c, int d) { return 0; }

// This allows you to call stubs like __stub_zero_std(4) to specify how many bytes to clear.
#define __stub_zero_std(n) __stub_zero_std_ ## n

#endif
