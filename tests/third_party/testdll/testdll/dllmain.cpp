// This dll is only for testing purposes
// Please compile it without any compiler optimization
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) int test_sum(int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, int arg7, int arg8)
{
    int x = arg1 + arg2 + arg3;
    int y = x + arg3 + arg5;
    int z = x + y + arg8;
    int a = x + y + z;
    if (arg1 != 1)
        return -1;
    if (arg2 != 2)
        return -1;
    if (arg3 != 3)
        return -1;
    if (arg4 != 4)
        return -1;
    if (arg5 != 5)
        return -1;
    if (arg6 != 6)
        return -1;
    if (arg7 != 7)
        return -1;
    if (arg8 != 8)
        return -1;
    return arg1 + arg2 + arg3 + arg4 + arg5 + arg6 + arg7 + arg8;
}

extern "C" __declspec(dllexport) int call_test_sum()
{
    int arg1 = 1;
    int arg2 = arg1 + 1;
    int arg3 = arg2 + 1;
    int arg4 = arg3 + 1;
    int arg5 = arg4 + 1;
    int arg6 = arg5 + 1;
    int arg7 = arg6 + 1;
    int arg8 = arg7 + 1;
    int result = test_sum(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    return result;
}
