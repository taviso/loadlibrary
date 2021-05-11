// Header file for x64 calling convention switcher.
// Author: Alessandro De Vito (cube0x8)

#ifndef LOADLIBRARY_X64_DISPATCHER_H
#define LOADLIBRARY_X64_DISPATCHER_H

void *x86_64_call_exported_function();
void *nix_to_win();
void *win_to_nix();
void *win_to_nix_5();
void *win_to_nix_6();

#endif //LOADLIBRARY_X64_DISPATCHER_H
