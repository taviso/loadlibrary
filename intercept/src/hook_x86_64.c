#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/user.h>
#include "Zydis/Zydis.h"
#include "subhook.h"
#include "hook.h"
#include "x64_dispatcher.h"

// Routines to intercept or redirect routines (x86_64).
// Author: Alessandro De Vito (cube0x8)

// This was chosen arbitrarily, the maximum amount of code we will search to
// find a call when looking for callsites, feel free to adjust as required.
#define MAX_FUNCTION_LENGTH 2048

ZydisDecoder decoder;

static void __attribute__((constructor)) init(void) {
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
                printf("error: refusing to redirect function %p due to early controlflow manipulation (+%u)\n",
                       buffer,
                       *total_disassembled);

                return false;
            }

            offset += instruction.length;

            // Next instuction.
            continue;
        }

        // Invalid instruction, abort.
        printf("error: %s encountered an invalid instruction @%p+%u, so redirection was aborted\n",
               __func__,
               buffer,
               *total_disassembled);

        return false;
    }

    return true;
}

// Setup the call to the dispatcher in the fixup_area
void *setup_call_to_dispatcher(mov_r64_abs_insn *fixup_area, uintptr_t call_to_dispatch, void *dispatcher) {
    struct branch64 *fixup_jmp;

    /* This moves the address of the user-supplied call
     * to dispatch
     * [addr+0x0]:      movabs rax, $call_to_dispatch
     */
    fixup_area->opcode = X86_64_OPCODE_MOV_ABS;
    fixup_area->reg = 0xB8; // rax
    fixup_area->imm.i = call_to_dispatch;

    /* Set a jmp to the dispatcher.
     * [addr+0xb]:      jmp dispatcher
     * WARNING: it seems like we can use a jmp near, relative, immediate here.
     * But is it safe to assume the dispatcher will be *always* in a 4gb range?
     * Or should we use a x64 jmp (push, mov, ret) also here?
     */
    fixup_jmp = (void *) (fixup_area->data);
    fixup_jmp->opcode = X86_64_OPCODE_JMP_NEAR;
    fixup_jmp->i = (uintptr_t)(dispatcher)
                   - (uintptr_t)(fixup_area)
                   - (uintptr_t)(sizeof(mov_r64_abs_insn))
                   - (uintptr_t)(sizeof(struct branch64));
    return &fixup_jmp->data;
}

/* Setup the fixup area.
 * This creates the fixup which repairs the damage done from the function_redirect,
 * calls the dispatcher (if any) and then restores
 * the execution to the user supplied target function.
 *
 */
bool create_fixup_area(P_REDIRECT function_redirect) {
    void *restore;
    uintptr_t call_to_dispatch;
    void *fixup_jmp;

    switch (function_redirect->redirect_type) {
        case CALLING_CONVENTION_SWITCH:
            /* We are performing a simple calling convention switch.
             * We pass, in the RAX register, the address of the first instruction of the
             * clobbered code to the user-supplied dispatcher, using a movabs instruction.
             * After the dispatcher set up the stack and registers,
             * the execution will be restored starting from RAX's value.
             */
            call_to_dispatch =
                    (uintptr_t)(function_redirect->fixup_area) + (uintptr_t)(sizeof(struct mov_r64_abs_insn)) +
                    (uintptr_t)(sizeof(struct branch64));

            // Setup the call to the dispatcher
            fixup_jmp = setup_call_to_dispatcher(function_redirect->fixup_area, call_to_dispatch,
                                                 function_redirect->dispatcher);

            // Store the code clobbered from the hook to the fixup area
            memcpy(fixup_jmp, function_redirect->trampoline_code,
                   function_redirect->redirect_size);

            // Restore the execution to the original function
            subhook_t hook = subhook_new((void *) fixup_jmp + function_redirect->redirect_size,
                                         (void *) function_redirect->func + subhook_get_jmp_size(SUBHOOK_64BIT_OFFSET),
                                         SUBHOOK_64BIT_OFFSET);

            if (subhook_install(hook) != 0) {
                printf("Cannot install the redirect to the original function");
                return false;
            }

            break;
        case HOOK_REPLACE_FUNCTION:
            if (function_redirect->dispatcher_type == NIX2NIX) {
                /* We are most likely redirecting a WINAPI to a custom
                 * user-defined function.
                 * In this case, the fixup area will just perform a jump
                 * to the user-defined target function.
                 */
                subhook_t nix2nix_hook = subhook_new(function_redirect->fixup_area, function_redirect->func,
                                                     SUBHOOK_64BIT_OFFSET);
                if (subhook_install(nix2nix_hook) != 0) {
                    printf("Failed to create the hook from %p win_to_nix %p", function_redirect->func,
                           function_redirect->fixup_area);
                    return false;
                }
            } else if (function_redirect->dispatcher_type == WIN2NIX || function_redirect->dispatcher_type == NIX2WIN) {
                /* We are redirecting a dll function to a user-defined
                 * function/WINAPI or a call to a user-defined (Linux) function
                 * to a dll function.
                 * We call the dispatcher first, which will perform the
                 * WIN <=> NIX/NIX <=> WIN magic and then call the target.
                 */
                call_to_dispatch = (uintptr_t)(function_redirect->target);
                // Setup the call to the dispatcher
                setup_call_to_dispatcher(function_redirect->fixup_area, call_to_dispatch,
                                         function_redirect->dispatcher);
            } else {
                printf("Dispatcher type not implemented. Exit.");
                return false;
            }
            break;
        case HOOK_DEFAULT:
            // TODO:
        default:
            printf("Redirect type not implemented. Exit.");
            return false;
    }

    // Fix permissions on the function_redirect.
    if (mprotect((void *) ((uintptr_t) function_redirect->fixup_area & PAGE_MASK), PAGE_SIZE,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        printf("mprotect() failed on stub => %p (%m), try `sudo setenforce 0`\n", function_redirect->fixup_area);
        return false;
    }

    return true;
}

P_REDIRECT
insert_function_redirect(void *function, int n_args, void *redirect, uint32_t flags, ENUM_DISPATCHERS dispatcher) {
    uint32_t redirect_size = 0;
    size_t fixup_area_size;
    size_t hook_area_size;
    void *selected_dispatcher;
    void *fixup_area;
    void *hook_area;
    void *trampoline_code;
    size_t jmp64_size = subhook_get_jmp_size(SUBHOOK_64BIT_OFFSET);

    // Set the dispatcher and calculate hook_area size
    switch (dispatcher) {
        case NIX2WIN:
            selected_dispatcher = nix_to_win;
            break;
        case WIN2NIX:
            if (n_args <= 4 && n_args >= 0)
                selected_dispatcher = win_to_nix;
            else if (n_args == 5)
                selected_dispatcher = win_to_nix_5;
            else if (n_args > 5)
                selected_dispatcher = win_to_nix_6;
            else {
                printf("Invalid number of arguments.");
                return false;
            }
            break;
        case NIX2NIX:
            selected_dispatcher = NULL;
            break;
        default:
            printf("Unknown dispatcher. Exit");
            return false;
    }

    if (!disassemble(function, &redirect_size, jmp64_size, flags))
        return false;

    /* Copy over the code we are going to clobber by installing the function_redirect.
     * the dispatcher will start executing code from here
     */
    trampoline_code = calloc(redirect_size, 1);
    memcpy(trampoline_code, function, redirect_size);

    // Calculate the size of the fixup area
    if (flags == HOOK_REPLACE_FUNCTION) {
        fixup_area_size = jmp64_size;
    } else if (flags == CALLING_CONVENTION_SWITCH) {
        fixup_area_size = redirect_size + jmp64_size;
    } else {
        printf("Redirect type not implemented. Exit.");
        return false;
    }

    if (dispatcher == WIN2NIX || dispatcher == NIX2WIN) {
        fixup_area_size += sizeof(struct mov_r64_abs_insn) + sizeof(struct branch64);
    }

    // Allocate the fixup_area
    fixup_area = calloc(fixup_area_size, 1);

    // Define the redirect we are going to install
    P_REDIRECT function_redirect = (P_REDIRECT) calloc(sizeof(struct REDIRECT), 1);
    function_redirect->redirect_type = flags;
    function_redirect->target = redirect;
    function_redirect->func = function;
    function_redirect->fixup_area = fixup_area;
    function_redirect->redirect_size = redirect_size;
    function_redirect->trampoline_code = trampoline_code;
    function_redirect->dispatcher_type = dispatcher;
    function_redirect->dispatcher = selected_dispatcher;

    if (!create_fixup_area(function_redirect)) {
        printf("Cannot setup the fixup area. Exit");
        return false;
    }

    // Create a x64 "push mov ret" hook from the function to the fixup_area
    subhook_t hook = subhook_new(function, fixup_area, SUBHOOK_64BIT_OFFSET);
    if (subhook_install(hook) != 0) {
        printf("Cannot install the redirect on the given function (%p).", function);
        return false;
    }

    function_redirect->hook = hook;

    // Clean up the left over slack bytes (not actually needed, as we're careful to
    // restore execution to the next valid instructions, but intended to make
    // sure we dont desync disassembly when debugging problems in kgdb).
    memset((void *) (function + jmp64_size),
           X86_OPCODE_NOP,
           redirect_size - jmp64_size);

    return function_redirect;
}

bool remove_function_redirect(P_REDIRECT function_redirect) {
    free(function_redirect->fixup_area);
    if (subhook_remove(function_redirect->hook) != 0)
        return false;
    return true;
}
