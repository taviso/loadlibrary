//
// Copyright (C) 2017 Tavis Ormandy
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include "log.h"
#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"

// Quick check if I'm running under GDB.
bool IsGdbPresent()
{
    char *statusline;
    FILE *status;
    size_t len;
    bool result;

    if (getenv("NO_DEBUGGER_PRESENT")) {
        return false;
    }

    statusline = NULL;
    status     = NULL;
    len        = 0;
    result     = true;

    if ((status = fopen("/proc/self/status", "r")) == NULL) {
        LogMessage("failed to open status file, cannot determine debug status");
        return false;
    }

    while (getline(&statusline, &len, status) != -1) {
        if (strcmp(statusline, "TracerPid:\t0\n") == 0) {
            result = false;
            break;
        }
    }

    free(statusline);
    fclose(status);

    return result;
}

#ifdef __x86_64__
static void swap_fp_register(PM128A MSFpReg, struct _libc_xmmreg *NixFpReg) {
    memcpy(&(MSFpReg->Low), &NixFpReg[0], 4);
    memcpy(((uint32_t *) &MSFpReg->Low) + 1, &NixFpReg[1], 4);
    memcpy(&(MSFpReg->High), &NixFpReg[2], 4);
    memcpy(((uint32_t *) &MSFpReg->High) + 1,&NixFpReg[3], 4);
}

void nix_2_ms_context_swap(ucontext_t *pNixContext, CONTEXT *pMSContext) {
    // General purpose registers
    pMSContext->Rax = pNixContext->uc_mcontext.gregs[REG_RAX];
    pMSContext->Rcx = pNixContext->uc_mcontext.gregs[REG_RCX];
    pMSContext->Rdx = pNixContext->uc_mcontext.gregs[REG_RDX];
    pMSContext->Rbx = pNixContext->uc_mcontext.gregs[REG_RBX];
    pMSContext->Rsp = pNixContext->uc_mcontext.gregs[REG_RSP];
    pMSContext->Rbp = pNixContext->uc_mcontext.gregs[REG_RBP];
    pMSContext->Rsi = pNixContext->uc_mcontext.gregs[REG_RSI];
    pMSContext->Rdi = pNixContext->uc_mcontext.gregs[REG_RDI];
    pMSContext->Rip = pNixContext->uc_mcontext.gregs[REG_RIP];
    pMSContext->R8 = pNixContext->uc_mcontext.gregs[REG_R8];
    pMSContext->R9 = pNixContext->uc_mcontext.gregs[REG_R9];
    pMSContext->R10 = pNixContext->uc_mcontext.gregs[REG_R10];
    pMSContext->R11 = pNixContext->uc_mcontext.gregs[REG_R11];
    pMSContext->R12 = pNixContext->uc_mcontext.gregs[REG_R12];
    pMSContext->R13 = pNixContext->uc_mcontext.gregs[REG_R13];
    pMSContext->R14 = pNixContext->uc_mcontext.gregs[REG_R14];
    pMSContext->R15 = pNixContext->uc_mcontext.gregs[REG_R15];

    // XMM0
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm0),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[0]));

    // XMM1
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm1),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[1]));

    // XMM2
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm2),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[2]));

    // XMM3
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm3),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[3]));

    // XMM4
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm4),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[4]));

    // XMM5
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm5),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[5]));

    // XMM6
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm6),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[6]));

    // XMM7
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm7),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[7]));

    // XMM8
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm8),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[8]));

    // XMM9
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm9),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[9]));

    // XMM10
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm10),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[10]));

    // XMM11
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm11),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[11]));

    // XMM12
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm12),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[12]));

    // XMM13
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm13),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[13]));

    // XMM14
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm14),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[14]));

    // XMM15
    swap_fp_register(&(pMSContext->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm15),
                     &(pNixContext->uc_mcontext.fpregs->_xmm[15]));

}
#endif
