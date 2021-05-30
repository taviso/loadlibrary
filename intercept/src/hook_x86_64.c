#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

ZydisDecoder decoder;

static void __attribute__((constructor(100))) init(void) {
    // Initialize Zydis disassemble
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
}

/* Disassemble a buffer until max_size is reached. If no branch instructions have been found
 * returns the total amount of disassembled bytes.
 */
bool disassemble(void *buffer, uint32_t *total_disassembled, ulong max_size, uint32_t flags) {
    ZyanUSize offset = 0;
    unsigned insncount = 0;

    for (*total_disassembled = 0; *total_disassembled < max_size; insncount++) {
        ZydisDecodedInstruction instruction;

        // Test if Zydis understood the instruction
        if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, buffer + offset, max_size, &instruction))) {
            // Valid, increment size.
            *total_disassembled += instruction.length;

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
    struct branch64 *branch;
    uintptr_t clobbered_code_offset;
    size_t branch_size;
    size_t jmp64_size = subhook_get_jmp_size(SUBHOOK_64BIT_OFFSET);

    if (!disassemble(function, &redirect_size, jmp64_size, flags))
        return NULL;

    branch_size = flags == HOOK_DEFAULT ? sizeof(struct branch64) : jmp64_size;

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

    fixup_area = calloc(sizeof(mov_r64_abs_insn) +
                        branch_size +
                        redirect_size +
                        jmp64_size, 1);

    /* This moves the address of the redirect function in the r11 register
     * [addr+0x0]:      movabs r11, *redirect
     */
    movabs = fixup_area;
    movabs->opcode = X86_64_OPCODE_MOV_ABS_R64;
    movabs->reg = 0xBB; // r11
    movabs->imm.i = redirect;

    // Create a call or a subhook jump
    if (flags == HOOK_DEFAULT) {
        branch = &movabs->data;
        branch->opcode = X86_64_OPCODE_CALL_REG;
        branch->reg = 0xD3; // r11
        clobbered_code_offset = (uintptr_t) & branch->data;
    } else {
        subhook_t hook = subhook_new(&movabs->data, redirect, SUBHOOK_64BIT_OFFSET);
        if (subhook_install(hook) != 0) {
            l_error("Cannot install the jmp to the redirect.");
            return NULL;
        }
        clobbered_code_offset = (uintptr_t) & movabs->data + jmp64_size;
    }

    // Copy over the code we are going to clobber by installing the redirect.
    memcpy((void *) clobbered_code_offset, function, redirect_size);

    // And install a branch to restore execution to the rest of the original routine.
    subhook_t restore_hook = subhook_new(clobbered_code_offset + redirect_size,
                                         function + redirect_size,
                                         SUBHOOK_64BIT_OFFSET);
    if (subhook_install(restore_hook) != 0) {
        l_error("Cannot the jmp to restore the execution.");
        return NULL;
    }

    // Fix permissions on the redirect.
    if (mprotect((void *) ((uintptr_t) fixup_area & PAGE_MASK), PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        printf("mprotect() failed on stub => %p (%m), try `sudo setenforce 0`\n", fixup_area);
        return NULL;
    }

    // Now I need to install the redirect, I also clobber any left over bytes
    // with x86 nops, so as not to disrupt disassemblers while debugging.
    subhook_t hook = subhook_new(function, fixup_area, SUBHOOK_64BIT_OFFSET);
    if (subhook_install(hook) != 0) {
        l_error("Cannot install redirect.");
        return NULL;
    }

    // Clean up the left over slack bytes (not acutally needed, as we're careful to
    // restore execution to the next valid instructions, but intended to make
    // sure we dont desync disassembly when debugging problems in kgdb).
    memset(function + jmp64_size,
           X86_OPCODE_NOP,
           redirect_size - jmp64_size);

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
