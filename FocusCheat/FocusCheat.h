#pragma once
#include <windows.h>

#ifdef FOCUSCHEAT_EXPORTS
#define FOCUSCHEAT_API __declspec(dllexport)
#else
#define FOCUSCHEAT_API __declspec(dllimport)
#endif

// InstallHooks pins the module in the target process, so FreeLibrary cannot
// unmap it. RemoveHooks detaches everything early and may only be called
// outside the loader lock (never from DllMain); normal removal is achieved
// by restarting the target process.
FOCUSCHEAT_API BOOL InstallHooks(HMODULE hModule);
FOCUSCHEAT_API void RemoveHooks();