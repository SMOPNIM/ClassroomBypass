#pragma once
#include <windows.h>

#ifdef FOCUSCHEAT_EXPORTS
#define FOCUSCHEAT_API __declspec(dllexport)
#else
#define FOCUSCHEAT_API __declspec(dllimport)
#endif

FOCUSCHEAT_API BOOL InstallHooks();