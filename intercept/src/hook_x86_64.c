#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/user.h>
#include "Zydis/Zydis.h"
#include "subhook.h"
#include "hook.h"
#include "log.h"

// Routines to intercept or redirect routines (x86_64).
// Author: Alessandro De Vito (cube0x8)

// This was chosen arbitrarily, the maximum amount of code we will search to
// find a call when looking for callsites, feel free to adjust as required.
#define MAX_FUNCTION_LENGTH 2048
#define X86_64_MAX_INSTRUCTION_LENGTH 15U
#define X86_64_FXSAVE_AREA_SIZE 0x200U
#define X86_64_STACK_ALIGN_SLACK 0x10U
#define X86_64_FXSAVE_FRAME_SIZE (X86_64_FXSAVE_AREA_SIZE + X86_64_STACK_ALIGN_SLACK + sizeof(uintptr_t))
#define X86_64_FXSAVE_RSP_SLOT X86_64_FXSAVE_AREA_SIZE
#define X64_REL32_REACH ((uintptr_t)INT32_MAX)
#define NEAR_ALLOC_SEARCH_STEP (64U * 1024U)
#define NEAR_ALLOC_MAX_PROBES 32768U

typedef struct __attribute__((packed)) win64_call_stub {
    uint8_t pushfq;
    uint8_t push_rax;
    uint8_t push_rcx;
    uint8_t push_rdx;
    uint8_t push_r8[2];
    uint8_t push_r9[2];
    uint8_t push_r10[2];
    uint8_t push_r11[2];
    uint8_t push_rbx;
    uint8_t push_rbp;
    uint8_t push_rsi;
    uint8_t push_rdi;
    uint8_t push_r12[2];
    uint8_t push_r13[2];
    uint8_t push_r14[2];
    uint8_t push_r15[2];
    uint8_t mov_rax_rsp[3];
    uint8_t sub_rsp[7];
    uint8_t and_rsp[4];
    uint8_t save_rsp[8];
    uint8_t fxsave[5];
    uint16_t call_opcode;
    uint8_t call_reg;
    uint8_t fxrstor[5];
    uint8_t restore_rsp[8];
    uint8_t pop_r15[2];
    uint8_t pop_r14[2];
    uint8_t pop_r13[2];
    uint8_t pop_r12[2];
    uint8_t pop_rdi;
    uint8_t pop_rsi;
    uint8_t pop_rbp;
    uint8_t pop_rbx;
    uint8_t pop_r11[2];
    uint8_t pop_r10[2];
    uint8_t pop_r9[2];
    uint8_t pop_r8[2];
    uint8_t pop_rdx;
    uint8_t pop_rcx;
    uint8_t pop_rax;
    uint8_t popfq;
    uint8_t data[0];
} win64_call_stub;

ZydisDecoder decoder;
ZydisFormatter formatter;

static size_t get_page_size(void) {
    static size_t cached_page_size = 0U;

    if (cached_page_size == 0U) {
        long result = sysconf(_SC_PAGESIZE);
        cached_page_size = result > 0 ? (size_t)result : 4096U;
    }

    return cached_page_size;
}

static uintptr_t align_down_uintptr(uintptr_t value, size_t alignment) {
    return value & ~((uintptr_t)alignment - 1U);
}

static uintptr_t align_up_uintptr(uintptr_t value, size_t alignment) {
    return (value + (uintptr_t)alignment - 1U) & ~((uintptr_t)alignment - 1U);
}

static bool is_within_rel32_range(void *src, void *dst, size_t patch_len) {
    int64_t rel = (int64_t)(uintptr_t)dst - ((int64_t)(uintptr_t)src + (int64_t)patch_len);
    return rel >= INT32_MIN && rel <= INT32_MAX;
}

static int zydis_subhook_disasm(void *src, int *reloc_op_offset) {
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (reloc_op_offset != NULL) {
        *reloc_op_offset = 0;
    }
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
            &decoder, src, X86_64_MAX_INSTRUCTION_LENGTH, &instruction, operands))) {
        return 0;
    }

    if (reloc_op_offset != NULL) {
        for (uint8_t idx = 0; idx < instruction.operand_count_visible; idx++) {
            if (operands[idx].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[idx].mem.base == ZYDIS_REGISTER_RIP) {
                if (instruction.raw.disp.size != 32U) {
                    return 0;
                }
                *reloc_op_offset = instruction.raw.disp.offset;
                break;
            }
            if (operands[idx].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operands[idx].imm.is_relative) {
                bool found_relative_immediate = false;

                for (uint8_t imm_idx = 0; imm_idx < 2U; imm_idx++) {
                    if (!instruction.raw.imm[imm_idx].is_relative) {
                        continue;
                    }
                    if (instruction.raw.imm[imm_idx].size != 32U) {
                        return 0;
                    }
                    *reloc_op_offset = instruction.raw.imm[imm_idx].offset;
                    found_relative_immediate = true;
                    break;
                }
                if (!found_relative_immediate) {
                    return 0;
                }
                break;
            }
        }
    }

    return instruction.length;
}

static void *try_map_near_candidate(uintptr_t candidate, size_t allocation_size) {
    void *mapped = mmap((void *)candidate,
                        allocation_size,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                        -1,
                        0);
    if (mapped == MAP_FAILED) {
        return NULL;
    }

    return mapped;
}

void *alloc_executable_near(void *target, size_t size) {
    size_t page_size;
    size_t allocation_size;
    uintptr_t target_addr;
    uintptr_t min_addr;
    uintptr_t max_addr;
    uintptr_t base_candidate;

    if (target == NULL || size == 0U) {
        errno = EINVAL;
        return NULL;
    }

    page_size = get_page_size();
    allocation_size = align_up_uintptr(size, page_size);
    target_addr = (uintptr_t)target;

    min_addr = target_addr > X64_REL32_REACH ? target_addr - X64_REL32_REACH : page_size;
    max_addr = UINTPTR_MAX - X64_REL32_REACH > target_addr ? target_addr + X64_REL32_REACH : UINTPTR_MAX;

    if (max_addr > UINTPTR_MAX - allocation_size) {
        max_addr = UINTPTR_MAX - allocation_size;
    }
    min_addr = align_down_uintptr(min_addr, page_size);
    max_addr = align_down_uintptr(max_addr, page_size);
    base_candidate = align_down_uintptr(target_addr, page_size);

    for (uint32_t probe = 0; probe < NEAR_ALLOC_MAX_PROBES; probe++) {
        uintptr_t distance = (uintptr_t)probe * NEAR_ALLOC_SEARCH_STEP;
        uintptr_t high_candidate = align_down_uintptr(base_candidate + distance, page_size);
        uintptr_t low_candidate = base_candidate >= distance ? align_down_uintptr(base_candidate - distance, page_size) : 0U;
        void *mapped;

        if (high_candidate >= min_addr && high_candidate <= max_addr) {
            mapped = try_map_near_candidate(high_candidate, allocation_size);
            if (mapped != NULL && is_within_rel32_range(target, mapped, 5U)) {
                l_message("alloc_executable_near(): mapped %zu bytes near %p at %p", allocation_size, target, mapped);
                return mapped;
            }
            if (mapped != NULL) {
                munmap(mapped, allocation_size);
            }
        }

        if (distance == 0U) {
            continue;
        }

        if (low_candidate >= min_addr && low_candidate <= max_addr) {
            mapped = try_map_near_candidate(low_candidate, allocation_size);
            if (mapped != NULL && is_within_rel32_range(target, mapped, 5U)) {
                l_message("alloc_executable_near(): mapped %zu bytes near %p at %p", allocation_size, target, mapped);
                return mapped;
            }
            if (mapped != NULL) {
                munmap(mapped, allocation_size);
            }
        }
    }

    errno = ENOMEM;
    l_warning("alloc_executable_near(): failed to map %zu bytes within rel32 reach of %p after %u probes",
              allocation_size,
              target,
              NEAR_ALLOC_MAX_PROBES);
    return NULL;
}

bool free_executable_near(void *address, size_t size) {
    size_t allocation_size;

    if (address == NULL || size == 0U) {
        return false;
    }

    allocation_size = align_up_uintptr(size, get_page_size());
    return munmap(address, allocation_size) == 0;
}

static void __attribute__((constructor(100))) init(void) {
    // Initialize Zydis disassemble
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    subhook_set_disasm_handler(zydis_subhook_disasm);
}

static bool instruction_has_rip_relative_operand(const ZydisDecodedInstruction *instruction,
                                                 const ZydisDecodedOperand *operands) {
    for (uint8_t operand_idx = 0; operand_idx < instruction->operand_count_visible; operand_idx++) {
        if (operands[operand_idx].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[operand_idx].mem.base == ZYDIS_REGISTER_RIP) {
            return true;
        }
    }

    return false;
}

static void format_instruction_text(const ZydisDecodedInstruction *instruction,
                                    const ZydisDecodedOperand *operands,
                                    ZyanU64 runtime_address,
                                    char *buffer,
                                    size_t buffer_size) {
    if (buffer_size == 0U) {
        return;
    }

    buffer[0] = '\0';
    if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, instruction, operands,
            instruction->operand_count_visible, buffer, buffer_size, runtime_address, ZYAN_NULL))) {
        snprintf(buffer, buffer_size, "%s", ZydisMnemonicGetString(instruction->mnemonic));
    }
}

static void log_stolen_instruction(void *function,
                                   ZyanU64 runtime_address,
                                   uint32_t cumulative_size,
                                   const ZydisDecodedInstruction *instruction,
                                   const ZydisDecodedOperand *operands) {
    char instruction_text[256];

    format_instruction_text(instruction, operands, runtime_address, instruction_text, sizeof(instruction_text));
    l_message("trampoline candidate %p +%uB: %s%s",
              function,
              cumulative_size,
              instruction_text,
              instruction_has_rip_relative_operand(instruction, operands) ? " [rip-relative]" : "");
}

/* Disassemble a buffer until max_size is reached. If no branch instructions have been found
 * returns the total amount of disassembled bytes.
 */
bool disassemble(void *buffer, uint32_t *total_disassembled, ulong max_size, uint32_t flags) {
    ZyanUSize offset = 0;
    unsigned insncount = 0;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    for (*total_disassembled = 0; *total_disassembled < max_size; insncount++) {
        ZydisDecodedInstruction instruction;
        /* Allow enough lookahead to decode the next full instruction even when
         * we only need a couple more bytes to satisfy the patch length. */
        ZyanUSize decode_window = (max_size - offset) + X86_64_MAX_INSTRUCTION_LENGTH;

        // Test if Zydis understood the instruction
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer + offset, decode_window, &instruction, operands))) {
            // Valid, increment size.
            *total_disassembled += instruction.length;
            log_stolen_instruction(buffer,
                                   (ZyanU64)((uintptr_t)buffer + offset),
                                   *total_disassembled,
                                   &instruction,
                                   operands);

            if (instruction_has_rip_relative_operand(&instruction, operands)) {
                l_error("Refusing to redirect function %p due to RIP-relative operand in stolen bytes (total bytes disassembled: +%u)",
                        buffer,
                        *total_disassembled);

                return false;
            }

            // Check for branches just to be safe, as these instructions are
            // relative and cannot be relocated safely (there are others of
            // course, but these are the most likely).
            if ((instruction.meta.category == ZYDIS_CATEGORY_CALL ||
                 instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                 instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                 instruction.meta.category == ZYDIS_CATEGORY_RET) &&
                flags != HOOK_REPLACE_FUNCTION) {
                l_error("Refusing to redirect function %p due to early controlflow manipulation (total bytes disassembled: +%u)",
                        buffer,
                        *total_disassembled);

                return false;
            }

            offset += instruction.length;

            // Next instuction.
            continue;
        }

        // Invalid instruction, abort.
        l_error("%s encountered an invalid instruction @%p+%u, so redirection was aborted",
                __func__,
                buffer,
                *total_disassembled);

        return false;
    }

    return true;
}

// Intercept calls to this function and execute redirect first. Depending on
// flags, you can either replace this function, or simply be inserted into the
// call chain.
//  function    The address of the function you want intercepted.
//  redirect    Your callback function. The prototype should be the same as
//              function, except an additional first parameter which you can
//              ignore (it's the return address for the caller).
//  flags       Options, see header file for flags available. Use HOOK_DEFAULT
//              if you don't need any.
//
// *NOTE*: If you want to redirect (or intercept) a function in a dll,
// remember to declare the target function (*redirect) as WINAPI e.g:
// PVOID WINAPI my_redirect_function(...) {
//      [code]
// }

subhook_t insert_function_redirect(void *function, void *redirect, uint32_t flags) {
    uint32_t redirect_size = 0;
    void *fixup_area;
    mov_r64_abs_insn *movabs;
    win64_call_stub *call_stub;
    uintptr_t clobbered_code_offset;
    size_t branch_size;
    size_t page_size = get_page_size();
    size_t detour_jmp_size;
    size_t restore_jmp_size;
    size_t redirect_jmp_size;
    size_t fixup_allocation_size = page_size;
    subhook_flags_t detour_flags = SUBHOOK_64BIT_OFFSET;
    subhook_flags_t restore_flags = SUBHOOK_64BIT_OFFSET;
    subhook_flags_t redirect_flags = SUBHOOK_64BIT_OFFSET;
    bool near_fixup = false;

    fixup_area = alloc_executable_near(function, fixup_allocation_size);
    if (fixup_area != NULL) {
        near_fixup = true;
        detour_flags = 0;
        restore_flags = 0;
        l_message("insert_function_redirect(): using near rel32 stub for %p via fixup %p", function, fixup_area);
    } else {
        fixup_area = NULL;
        l_message("insert_function_redirect(): no near rel32 stub available for %p, falling back to 64-bit detour", function);
    }

    detour_jmp_size = subhook_get_jmp_size(detour_flags);

    if (!disassemble(function, &redirect_size, detour_jmp_size, flags)) {
        if (near_fixup) {
            free_executable_near(fixup_area, fixup_allocation_size);
        }
        return NULL;
    }

    if (flags == HOOK_REPLACE_FUNCTION && near_fixup &&
        is_within_rel32_range((void *)((uintptr_t)fixup_area + sizeof(mov_r64_abs_insn)), redirect, 5U)) {
        redirect_flags = 0;
        l_message("insert_function_redirect(): replace path can use rel32 jump from near fixup %p to redirect %p",
                  fixup_area,
                  redirect);
    }
    redirect_jmp_size = subhook_get_jmp_size(redirect_flags);
    restore_jmp_size = subhook_get_jmp_size(restore_flags);

    l_message("install trampoline at %p redirect=%p clobbering %u bytes (patch size=%zu, mode=%s)",
              function,
              redirect,
              redirect_size,
              detour_jmp_size,
              flags == HOOK_REPLACE_FUNCTION ? "replace" : "call-through");

    branch_size = flags == HOOK_DEFAULT ? sizeof(win64_call_stub) : redirect_jmp_size;

    // We need to create a fixup, a small chunk of code that repairs the damage
    // we did redirecting the function. This basically handles calling the
    // redirect, then fixes the damage and restores execution. So it's going to be
    // sizeof(mov_r64_abs_insn) + branch_size + redirect_size + jmp64_size bytes,
    // which looks like this:
    //
    // mov r11, your_routine
    // call r11 (or "push, mov, ret" x86_64 jump, based on the flags' value)
    // <code clobbered to get here>             ; redirectsize bytes
    // push, mov, ret (x86_64 jump)
    //
    // the "branch_size" value is determined by the flags argument's value (HOOK_DEFAULT
    // or HOOK_REPLACE_FUNCTION). If HOOK_DEFAULT is selected, the branch to the user-defined
    // routine is implemented as a "call r11" instruction. Instead, when HOOK_REPLACE_FUNCTION
    // is selected, we create a subhook (push, mov, ret) redirect.
    //

    size_t fixup_size = sizeof(mov_r64_abs_insn) +
                        branch_size +
                        redirect_size +
                        restore_jmp_size;
    if (!near_fixup) {
        fixup_area = calloc(fixup_size, 1);
    } else if (fixup_size > fixup_allocation_size) {
        l_message("insert_function_redirect(): near fixup at %p too small for %zu-byte stub, falling back to heap/64-bit detour",
                  fixup_area,
                  fixup_size);
        free_executable_near(fixup_area, fixup_allocation_size);
        fixup_area = calloc(fixup_size, 1);
        near_fixup = false;
        detour_flags = SUBHOOK_64BIT_OFFSET;
        restore_flags = SUBHOOK_64BIT_OFFSET;
        redirect_flags = SUBHOOK_64BIT_OFFSET;
        detour_jmp_size = subhook_get_jmp_size(detour_flags);
        restore_jmp_size = subhook_get_jmp_size(restore_flags);
        redirect_jmp_size = subhook_get_jmp_size(redirect_flags);
        branch_size = flags == HOOK_DEFAULT ? sizeof(win64_call_stub) : redirect_jmp_size;
        fixup_size = sizeof(mov_r64_abs_insn) + branch_size + redirect_size + restore_jmp_size;
    }
    if (fixup_area == NULL) {
        return NULL;
    }

    /* This moves the address of the redirect function in the r11 register
     * [addr+0x0]:      movabs r11, *redirect
     */
    movabs = fixup_area;
    movabs->opcode = X86_64_OPCODE_MOV_ABS_R64;
    movabs->reg = 0xBB; // r11
    movabs->imm.i = (uintptr_t)redirect;

    // Create a call or a subhook jump
    if (flags == HOOK_DEFAULT) {
        call_stub = (win64_call_stub *)&movabs->data;
        call_stub->pushfq = 0x9C;
        call_stub->push_rax = 0x50;
        call_stub->push_rcx = 0x51;
        call_stub->push_rdx = 0x52;
        call_stub->push_r8[0] = 0x41;
        call_stub->push_r8[1] = 0x50;
        call_stub->push_r9[0] = 0x41;
        call_stub->push_r9[1] = 0x51;
        call_stub->push_r10[0] = 0x41;
        call_stub->push_r10[1] = 0x52;
        call_stub->push_r11[0] = 0x41;
        call_stub->push_r11[1] = 0x53;
        call_stub->push_rbx = 0x53;
        call_stub->push_rbp = 0x55;
        call_stub->push_rsi = 0x56;
        call_stub->push_rdi = 0x57;
        call_stub->push_r12[0] = 0x41;
        call_stub->push_r12[1] = 0x54;
        call_stub->push_r13[0] = 0x41;
        call_stub->push_r13[1] = 0x55;
        call_stub->push_r14[0] = 0x41;
        call_stub->push_r14[1] = 0x56;
        call_stub->push_r15[0] = 0x41;
        call_stub->push_r15[1] = 0x57;
        /* Build an explicitly aligned spill area for fxsave/fxrstor and keep
         * the original stack pointer in-frame so we can resume the pop chain. */
        call_stub->mov_rax_rsp[0] = 0x48;
        call_stub->mov_rax_rsp[1] = 0x89;
        call_stub->mov_rax_rsp[2] = 0xE0;
        call_stub->sub_rsp[0] = 0x48;
        call_stub->sub_rsp[1] = 0x81;
        call_stub->sub_rsp[2] = 0xEC;
        call_stub->sub_rsp[3] = (uint8_t)(X86_64_FXSAVE_FRAME_SIZE & 0xFFU);
        call_stub->sub_rsp[4] = (uint8_t)((X86_64_FXSAVE_FRAME_SIZE >> 8) & 0xFFU);
        call_stub->sub_rsp[5] = (uint8_t)((X86_64_FXSAVE_FRAME_SIZE >> 16) & 0xFFU);
        call_stub->sub_rsp[6] = (uint8_t)((X86_64_FXSAVE_FRAME_SIZE >> 24) & 0xFFU);
        call_stub->and_rsp[0] = 0x48;
        call_stub->and_rsp[1] = 0x83;
        call_stub->and_rsp[2] = 0xE4;
        call_stub->and_rsp[3] = 0xF0;
        call_stub->save_rsp[0] = 0x48;
        call_stub->save_rsp[1] = 0x89;
        call_stub->save_rsp[2] = 0x84;
        call_stub->save_rsp[3] = 0x24;
        call_stub->save_rsp[4] = (uint8_t)(X86_64_FXSAVE_RSP_SLOT & 0xFFU);
        call_stub->save_rsp[5] = (uint8_t)((X86_64_FXSAVE_RSP_SLOT >> 8) & 0xFFU);
        call_stub->save_rsp[6] = (uint8_t)((X86_64_FXSAVE_RSP_SLOT >> 16) & 0xFFU);
        call_stub->save_rsp[7] = (uint8_t)((X86_64_FXSAVE_RSP_SLOT >> 24) & 0xFFU);
        call_stub->fxsave[0] = 0x48;
        call_stub->fxsave[1] = 0x0F;
        call_stub->fxsave[2] = 0xAE;
        call_stub->fxsave[3] = 0x04;
        call_stub->fxsave[4] = 0x24;
        call_stub->call_opcode = X86_64_OPCODE_CALL_REG;
        call_stub->call_reg = 0xD3; // r11
        call_stub->fxrstor[0] = 0x48;
        call_stub->fxrstor[1] = 0x0F;
        call_stub->fxrstor[2] = 0xAE;
        call_stub->fxrstor[3] = 0x0C;
        call_stub->fxrstor[4] = 0x24;
        call_stub->restore_rsp[0] = 0x48;
        call_stub->restore_rsp[1] = 0x8B;
        call_stub->restore_rsp[2] = 0xA4;
        call_stub->restore_rsp[3] = 0x24;
        call_stub->restore_rsp[4] = (uint8_t)(X86_64_FXSAVE_RSP_SLOT & 0xFFU);
        call_stub->restore_rsp[5] = (uint8_t)((X86_64_FXSAVE_RSP_SLOT >> 8) & 0xFFU);
        call_stub->restore_rsp[6] = (uint8_t)((X86_64_FXSAVE_RSP_SLOT >> 16) & 0xFFU);
        call_stub->restore_rsp[7] = (uint8_t)((X86_64_FXSAVE_RSP_SLOT >> 24) & 0xFFU);
        call_stub->pop_r15[0] = 0x41;
        call_stub->pop_r15[1] = 0x5F;
        call_stub->pop_r14[0] = 0x41;
        call_stub->pop_r14[1] = 0x5E;
        call_stub->pop_r13[0] = 0x41;
        call_stub->pop_r13[1] = 0x5D;
        call_stub->pop_r12[0] = 0x41;
        call_stub->pop_r12[1] = 0x5C;
        call_stub->pop_rdi = 0x5F;
        call_stub->pop_rsi = 0x5E;
        call_stub->pop_rbp = 0x5D;
        call_stub->pop_rbx = 0x5B;
        call_stub->pop_r11[0] = 0x41;
        call_stub->pop_r11[1] = 0x5B;
        call_stub->pop_r10[0] = 0x41;
        call_stub->pop_r10[1] = 0x5A;
        call_stub->pop_r9[0] = 0x41;
        call_stub->pop_r9[1] = 0x59;
        call_stub->pop_r8[0] = 0x41;
        call_stub->pop_r8[1] = 0x58;
        call_stub->pop_rdx = 0x5A;
        call_stub->pop_rcx = 0x59;
        call_stub->pop_rax = 0x58;
        call_stub->popfq = 0x9D;
        clobbered_code_offset = (uintptr_t)&call_stub->data;
    } else {
        subhook_t hook = subhook_new(&movabs->data, redirect, redirect_flags);
        if (subhook_install(hook) != 0) {
            l_error("Cannot install the jmp to the redirect.");
            if (near_fixup) {
                free_executable_near(fixup_area, fixup_allocation_size);
            } else {
                free(fixup_area);
            }
            return NULL;
        }
        clobbered_code_offset = (uintptr_t) & movabs->data + redirect_jmp_size;
    }

    // Copy over the code we are going to clobber by installing the redirect.
    memcpy((void *) clobbered_code_offset, function, redirect_size);

    // And install a branch to restore execution to the rest of the original routine.
    subhook_t restore_hook = subhook_new((void *)(clobbered_code_offset + redirect_size),
                                         function + redirect_size,
                                         restore_flags);
    if (subhook_install(restore_hook) != 0) {
        l_error("Cannot the jmp to restore the execution.");
        if (near_fixup) {
            free_executable_near(fixup_area, fixup_allocation_size);
        } else {
            free(fixup_area);
        }
        return NULL;
    }

    // Fix permissions on the redirect.
    if (mprotect((void *) ((uintptr_t) fixup_area & PAGE_MASK), PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        printf("mprotect() failed on stub => %p (%m), try `sudo setenforce 0`\n", fixup_area);
        return NULL;
    }

    // Now I need to install the redirect, I also clobber any left over bytes
    // with x86 nops, so as not to disrupt disassemblers while debugging.
    subhook_t hook = subhook_new(function, fixup_area, detour_flags);
    if (subhook_install(hook) != 0) {
        l_error("Cannot install redirect.");
        if (near_fixup) {
            free_executable_near(fixup_area, fixup_allocation_size);
        } else {
            free(fixup_area);
        }
        return NULL;
    }

    // Leave bytes beyond the detour untouched: subhook restores only the
    // bytes occupied by its jump when the hook is removed.
    return hook;
}

subhook_t insert_function_wrapper(void *function, void *wrapper, void **original) {
    subhook_t hook;
    void *trampoline;

    if (function == NULL || wrapper == NULL || original == NULL) {
        errno = EINVAL;
        return NULL;
    }

    *original = NULL;
    hook = subhook_new(function, wrapper, SUBHOOK_64BIT_OFFSET);
    if (hook == NULL) {
        return NULL;
    }

    trampoline = subhook_get_trampoline(hook);
    if (trampoline == NULL) {
        l_error("Cannot create the original-function trampoline for %p.", function);
        subhook_free(hook);
        return NULL;
    }
    if (subhook_install(hook) != 0) {
        l_error("Cannot install function wrapper at %p.", function);
        subhook_free(hook);
        return NULL;
    }

    *original = trampoline;
    return hook;
}

// TODO: implement it
bool redirect_call_within_function(void *function, void *target, void *redirect) {
    l_error("Not implemented.");
    return false;
}

bool remove_function_redirect(subhook_t hook) {
    if (subhook_remove(hook) != 0) {
        l_error("Cannot remove the hook.");
        return false;
    }
    subhook_free(hook);
    return true;
}
