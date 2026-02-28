#include <windows.h>
#include "TickCountHelper.h"

ULONGLONG SafeGetTickCount64(void)
{
    static ULONGLONG(WINAPI * pGetTickCount64)(void) = NULL;
    if (!pGetTickCount64) {
        HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
        if (hKernel32) {
            pGetTickCount64 = (ULONGLONG(WINAPI*)(void))GetProcAddress(hKernel32, "GetTickCount64");
        }
    }
    return pGetTickCount64 ? pGetTickCount64() : (ULONGLONG)GetTickCount();
}
