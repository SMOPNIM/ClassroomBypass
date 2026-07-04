// dllmain.cpp : DLL entry point. Calls InstallHooks from the implementation file.
#include "pch.h"
#include "FocusCheat.h"
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InstallHooks();
        break;
    case DLL_PROCESS_DETACH:
        // Cleanup is handled in FocusCheat.cpp if needed
        break;
    }
    return TRUE;
}