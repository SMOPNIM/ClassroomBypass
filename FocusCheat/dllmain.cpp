// dllmain.cpp : DLL entry point. Calls InstallHooks from the implementation file.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "FocusCheat.h"

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        // FALSE refuses the load; the injector surfaces it via LoadLibrary NULL.
        return InstallHooks(hModule);
    case DLL_PROCESS_DETACH:
        // lpReserved != NULL means process termination: the OS is about to
        // tear everything down, so skip Detours/file I/O under loader lock.
        // The module is also pinned in InstallHooks, so FreeLibrary cannot
        // reach the full-cleanup path in normal use.
        if (lpReserved != NULL) {
            return TRUE;
        }
        RemoveHooks();
        break;
    }
    return TRUE;
}