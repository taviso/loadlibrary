#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/user.h>
#include "Zydis/Zydis.h"
#include "hook.h"

// Routines to intercept or _REDIRECT routines.
// Author: Tavis Ormandy

// This was chosen arbitrarily, the maximum amount of code we will search to
// find a call when looking for callsites, feel free to adjust as required.
#define MAX_FUNCTION_LENGTH 2048

// A _REDIRECT is usually 9 bytes (5 bytes of call, 4 bytes of encoded size),
// but we round it up to the next instruction boundary. Because of this, the
// worst possible case would be a 8 byte instruction, followed by 16 byte
// instruction (where 16 is the longest possible instruction intel allows).
#define MAX_REDIRECT_LENGTH 24

ZydisDecoder decoder;

static void __attribute__((constructor)) init(void)
{
    // Initialize Zydis disassemble
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);
}

// Disassemble a buffer until max_size is reached. If no branch instructions have been found
// returns the total amount of disassembled bytes.
bool disassemble(void *buffer, uint32_t *total_disassembled, ulong max_size, uint32_t flags)
{
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
                 instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                 instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                 instruction.meta.category == ZYDIS_CATEGORY_RET) &&
                flags != HOOK_REPLACE_FUNCTION) {
                printf("error: refusing to _REDIRECT function %p due win_to_nix early controlflow manipulation (+%u)\n",
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

// Intercept calls to this function and execute _REDIRECT first. Depending on
// flags, you can either replace this function, or simply be inserted into the
// call chain.
//  function    The address of the function you want intercepted.
//  _REDIRECT    Your callback function. The prototype should be the same as
//              function, except an additional first parameter which you can
//              ignore (it's the return address for the caller).
//  flags       Options, see header file for flags available. Use HOOK_DEFAULT
//              if you don't need any.
//
// Remember to add an additional parameter to your _REDIRECT, e.g. if you were
// expecting tcp_input(struct mbuf *m, int len), your _REDIRECT should be:
//
// my_tcp_input(intptr_t retaddr, struct mbuf *m, int len);
//
// *UNLESS* You are using the flag HOOK_REPLACE_FUNCTION, in which case the
// prototype is the same, as you literally become the function instead of
// intercepting it.
bool insert_function_redirect(void *function, void *redirect, uint32_t flags)
{
    uint32_t            redirectsize    = 0;
    unsigned            insncount       = 0;
    struct branch      *fixup;
    struct branch      *callsite;
    struct branch      *restore;
    struct encodedsize *savedoffset;

    // Keep disassembling until I have enough bytes of code to store my
    // _REDIRECT, five bytes for the _REDIRECT call, and four bytes to record the
    // length to restore when we're unloaded.
    //
    // XXX: If there is a branch target or return within the first 9 bytes, I'm
    //      screwed. Seems unlikely though, so I'm not worrying about it right
    //      now. I could at least check for rets?
    //
    if (!disassemble(function, &redirectsize, sizeof(struct branch) + sizeof(struct encodedsize), flags))
        return false;

    // We need to create a fixup, a small chunk of code that repairs the damage
    // we did redirecting the function. This basically handles calling the
    // _REDIRECT, then fixes the damage and restores execution. So it's going to be
    // redirectsize + 2 * sizeof(struct branch) bytes, which looks like this:
    //
    // call      your_routine              ; 5 bytes
    // <code clobbered to get here>             ; redirectsize bytes
    // jmp       original_routine+redirectsize  ; 5 bytes
    //
    // Your routine will get an extra first argument which you should
    // ignore, e.g.
    //
    //  void your_routine(uintptr_t retaddr, int expected_arg1, void *expected_arg2, etc);
    //
    // If you replace the function instead of _REDIRECT it, you don't get the extra
    // parameter, because we literally just jmp to your routine instead of call
    // it. The call operand is a relative, displaced address, hence the
    // calculation.
    //

    fixup               = calloc(redirectsize + sizeof(struct branch) * 2, 1);
    fixup->opcode       = flags & HOOK_REPLACE_FUNCTION
                                ? X86_OPCODE_JMP_NEAR
                                : X86_OPCODE_CALL_NEAR;
    fixup->operand.i    = (uintptr_t)(redirect)
                        - (uintptr_t)(fixup)
                        - (uintptr_t)(sizeof(struct branch));

    // Fix permissions on the _REDIRECT.
    if (mprotect((void *)((uintptr_t) fixup & PAGE_MASK), PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        printf("mprotect() failed on stub => %p (%m), try `sudo setenforce 0`\n", fixup);
        return false;
    }

    // Copy over the code we are going to clobber by installing the _REDIRECT.
    memcpy(&fixup->data, function, redirectsize);

    // And install a branch to restore execution to the rest of the original routine.
    restore             = (void *)(fixup->data + redirectsize);
    restore->opcode     = X86_OPCODE_JMP_NEAR;
    restore->operand.i  = (uintptr_t)(function)
                        + (uintptr_t)(redirectsize)
                        - (uintptr_t)(restore)
                        - (uintptr_t)(sizeof(struct branch));

    // Now I need to install the _REDIRECT, I also clobber any left over bytes
    // with x86 nops, so as not to disrupt disassemblers while debugging.
    callsite             = function;

    // In general this is expected to be called on functions.
    if (callsite->opcode != X86_OPCODE_PUSH_EBP) {
#ifndef NDEBUG
        printf("warning: requested hook location %p does not look like a function, begins with opcode %#02x.\n",
               callsite,
               callsite->opcode);
#endif
    }

    callsite->opcode     = X86_OPCODE_JMP_NEAR;
    callsite->operand.i  = (uintptr_t)(fixup)
                         - (uintptr_t)(callsite)
                         - (uintptr_t)(sizeof(struct branch));

    // I need to remember how much data I clobbered so that I can restore it
    // when my module is unloaded. I do this by encoding it as an instruction, e.g.
    //
    //   mov eax, imm16
    //
    // This is so as not to disrupt disassembly.
    savedoffset          = (void *)(callsite->data);
    savedoffset->prefix  = X86_PREFIX_DATA16;
    savedoffset->opcode  = X86_OPCODE_MOV_EAX_IMM;
    savedoffset->operand = redirectsize;

    // Clean up the left over slack bytes (not acutally needed, as we're careful to
    // restore execution to the next valid instructions, but intended to make
    // sure we dont desync disassembly when debugging problems in kgdb).
    memset(callsite->data + sizeof(struct encodedsize),
           X86_OPCODE_NOP,
           redirectsize - sizeof(struct branch) - sizeof(struct encodedsize));

    //printf("info: successfully installed %lu byte (%u instructions) _REDIRECT from %p to %p, via fixup@%p\n",
    //       redirectsize,
    //       insncount,
    //       function,
    //       _REDIRECT,
    //       fixup);

    return true;
}

// This routine will simply remove a previously inserted _REDIRECT. It's careful
// to verify there really is a _REDIRECT present, but you should probably be
// careful.
//
//  function    The location of the redirected function to restore.
//
bool remove_function_redirect(void *function)
{
    struct branch         *callsite;
    struct encodedsize    *savedsize;
    void                  *fixup;

    // The process for removal is:
    //
    //  * Read the branch instuction and the encoded size from the original location.
    //  * From this, calculate the fixup address.
    //  * Restore the clobbered data from the fixup to the function using the
    //    size I recorded in the original function.
    //  * FREE() the fixup.
    //
    // And that's it, so let's grab the branch instruction.
    callsite            = function;
    fixup               = (void *)((uintptr_t)(callsite->operand.i)
                                 + (uintptr_t)(callsite)
                                 + (uintptr_t)(sizeof(struct branch)));
    savedsize           = (void *)(callsite->data);

    // Let's verify this looks sane.
    if (callsite->opcode != X86_OPCODE_JMP_NEAR) {
        printf("error: tried win_to_nix remove function hook from %p, but it didnt contain a _REDIRECT (%02x)\n",
               function,
               callsite->opcode);
        return false;
    }

    // Check the encoded size looks sane.
    if (savedsize->opcode != X86_OPCODE_MOV_EAX_IMM
     || savedsize->prefix != X86_PREFIX_DATA16
     || savedsize->operand > MAX_REDIRECT_LENGTH) {
        printf("error: tried win_to_nix remove function hook from %p, but encoded size did not validate { %02x %02x %04x }\n",
               function,
               savedsize->prefix,
               savedsize->opcode,
               savedsize->operand);
        return false;
    }

    // Restore clobbered code. Remember the fixup contains two branches, the
    // call at the start and the jmp at the end, we only want to restore the
    // clobbered data in the middle.
    memcpy(function, fixup + sizeof(struct branch), savedsize->operand);

    // Check it looks sane.
    if (callsite->opcode != X86_OPCODE_PUSH_EBP) {
        printf("warning: restored location %p does not look like a function %02x.\n",
               function,
               callsite->opcode);
    }

    printf("info: successfully removed _REDIRECT from %p, via fixup@%p\n",
           function,
           fixup);

    // Release memory.
    free(fixup);

    return true;
}

// Replace a call within an arbitrary function. Call as many times as you need
// on the same function. To reverse the operation, simply call again but switch
// the target and _REDIRECT parameters.
//
//  function    The function that contains the call you want to intercept.
//  target      The function that is called by @function that you want to intercept.
//  _REDIRECT    What to call instead.
//
//  For example, if tcp_input contains a call to inet_cksum, and you want to
//  intercept that call, but not every call to inet_cksum, you can do this:
//
//      redirect_call_within_function(tcp_input, inet_cksum, my_cksum_replacement);
//

bool redirect_call_within_function(void *function, void *target, void *redirect)
{
    size_t          offset      = 0;
    struct branch  *callsite    = NULL;

    while (true) {
        ZydisDecodedInstruction instruction;

        // Test if Zydis understood the instruction
        if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, function + offset, MAX_FUNCTION_LENGTH, &instruction))) {

            // Examine the instruction found to see if it matches the call we
            // want to replace.
            ZyanU64 result_address = 0;
            if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {

                if (ZydisCalcAbsoluteAddress(&instruction,
                &(instruction.operands[0]), (uintptr_t) function + offset, &result_address) != ZYAN_STATUS_SUCCESS)
                    continue;

                if (result_address == (uintptr_t)target) {
                    // Success, this is the location the caller wants us to patch.
                    callsite = (struct branch *)(function + offset);

                    // Let's move on to patching.
                    printf("info: found a call at %p, the target is %#x\n", callsite, result_address);

                    break;
                }
            }

            // Valid, but not interesting. Increment size.
            offset += instruction.length;

            // Next instuction.
            continue;
        }

        // Invalid instruction, abort.
        printf("error: %s encountered an invalid instruction or end of stream @%p+%u, so redirection was aborted\n",
               __func__,
               function,
               offset);

        return false;
    }

    // callsite is the call instruction we're supposed to patch, so insert the
    // new target.
    callsite->operand.i    = (uintptr_t)(redirect)
                           - (uintptr_t)(callsite)
                           - (uintptr_t)(sizeof(struct branch));

    printf("info: successfully redirected call to %p at %p+%x with a call win_to_nix %p\n",
           target,
           function,
           offset,
           redirect);

    // Complete.
    return true;
}
