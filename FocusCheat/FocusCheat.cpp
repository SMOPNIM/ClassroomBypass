#include "FocusCheat.h"
#include <windows.h>
#include <detours.h>
#include <stdio.h>
#include <winnt.h>

#pragma comment(lib, "detours.lib")

// ---------- Global variables ----------
static HWND g_targetHwnd = NULL;
static HHOOK g_hMsgHook = NULL;

// Original API pointers (for restoration)
HWND(WINAPI* TrueGetForegroundWindow)(void) = GetForegroundWindow;
BOOL(WINAPI* TrueSetWindowDisplayAffinity)(HWND hWnd, DWORD dwAffinity) = SetWindowDisplayAffinity;

// example_module.dll internal function pointers
typedef void (__thiscall* SendExampleEventA_t)(void* thisPtr);
typedef void (__thiscall* SendWindowForegoundInfo_t)(void* thisPtr);
static SendExampleEventA_t TrueSendExampleEventA = NULL;
static SendWindowForegoundInfo_t TrueSendWindowForegoundInfo = NULL;

// ============================================================
// PE Analysis: dynamically locate functions in example_module.dll
// ============================================================
static BYTE* g_pTextBase = NULL;
static DWORD g_dwTextSize = 0;
static DWORD g_dwTextRva = 0;
static BYTE* g_pRdataBase = NULL;
static DWORD g_dwImageBase = 0;

static DWORD FindFuncStart(DWORD textOffset);
static DWORD FindFuncEnd(DWORD textOffset);

static BOOL InitPESections(HMODULE hModule) {
    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    g_dwImageBase = nt->OptionalHeader.ImageBase;
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD numSections = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; i++) {
        char name[9] = {};
        memcpy(name, sections[i].Name, 8);
        if (strcmp(name, ".text") == 0) {
            g_pTextBase = base + sections[i].VirtualAddress;
            g_dwTextSize = sections[i].Misc.VirtualSize;
            g_dwTextRva = sections[i].VirtualAddress;
        }
        else if (strcmp(name, ".rdata") == 0) {
            g_pRdataBase = base + sections[i].VirtualAddress;
        }
    }
    return (g_pTextBase && g_pRdataBase);
}

static DWORD FindStringInRdata(const char* keyword) {
    size_t kwLen = strlen(keyword);
    for (DWORD i = 0; i + kwLen < 0x100000; i++) {
        if (memcmp(g_pRdataBase + i, keyword, kwLen) == 0) {
            return (DWORD)(g_pRdataBase - (BYTE*)GetModuleHandle(L"example_module.dll")) + i;
        }
    }
    return 0;
}

static DWORD FindFuncStart(DWORD textOffset) {
    DWORD searchStart = (textOffset > 0x1000) ? textOffset - 0x1000 : 0;
    for (DWORD i = textOffset; i > searchStart; i--) {
        if (g_pTextBase[i] == 0x55 && g_pTextBase[i + 1] == 0x8B && g_pTextBase[i + 2] == 0xEC) {
            return i;
        }
    }
    return 0;
}

static DWORD FindFuncByStringRef(DWORD strRva) {
    DWORD strVa = g_dwImageBase + strRva;
    for (DWORD i = 0; i + 5 < g_dwTextSize; i++) {
        if (g_pTextBase[i] == 0x68) {
            DWORD imm = *(DWORD*)(g_pTextBase + i + 1);
            if (imm == strVa) return FindFuncStart(i);
        }
        if (g_pTextBase[i] == 0xBE || g_pTextBase[i] == 0xBA ||
            g_pTextBase[i] == 0xBF || g_pTextBase[i] == 0xB8 ||
            g_pTextBase[i] == 0xBB || g_pTextBase[i] == 0xB9) {
            DWORD imm = *(DWORD*)(g_pTextBase + i + 1);
            if (imm == strVa) return FindFuncStart(i);
        }
    }
    return 0;
}

static PVOID FindLibOwcrFunc(const char* funcName) {
    HMODULE hLib = GetModuleHandle(L"example_module.dll");
    if (!hLib || !InitPESections(hLib)) return NULL;

    DWORD strRva = FindStringInRdata(funcName);
    if (!strRva) return NULL;

    DWORD funcOffset = FindFuncByStringRef(strRva);
    if (!funcOffset) return NULL;

    return (PVOID)(g_pTextBase + funcOffset);
}

// ---------- 1. Message hook: intercept focus-loss messages ----------
LRESULT CALLBACK GetMsgProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION) {
        MSG* pMsg = (MSG*)lParam;
        if (pMsg->hwnd == g_targetHwnd) {
            // Discard WM_KILLFOCUS and WM_ACTIVATE messages
            if (pMsg->message == WM_KILLFOCUS || pMsg->message == WM_ACTIVATE) {
                return 1;
            }
        }
    }
    return CallNextHookEx(g_hMsgHook, code, wParam, lParam);
}

// ---------- 2. Fake GetForegroundWindow (spoof foreground ownership) ----------
HWND WINAPI FakeGetForegroundWindow(void) {
    if (g_targetHwnd && IsWindow(g_targetHwnd)) {
        return g_targetHwnd;
    }
    return TrueGetForegroundWindow();
}

// ---------- 3. Fake SetWindowDisplayAffinity (bypass screenshot block) ----------
BOOL WINAPI FakeSetWindowDisplayAffinity(HWND hWnd, DWORD dwAffinity) {
    if (hWnd == g_targetHwnd) {
        return TRUE;
    }
    return TrueSetWindowDisplayAffinity(hWnd, dwAffinity);
}

// ---------- 4. Fake example_module.dll: block minimize notification ----------
void __fastcall FakeSendExampleEventA(void* thisPtr, void* EDX) {
    // Do nothing - prevent "ExampleEventA" event from reaching JS
}

// ---------- 5. Fake example_module.dll: block foreground notification ----------
void __fastcall FakeSendWindowForegoundInfo(void* thisPtr, void* EDX) {
    // Do nothing - prevent "ExampleEventB" event from reaching JS
}

// ---------- Uninstall all hooks ----------
void RemoveHooks() {
    if (g_hMsgHook) {
        UnhookWindowsHookEx(g_hMsgHook);
        g_hMsgHook = NULL;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueGetForegroundWindow, FakeGetForegroundWindow);
    DetourDetach(&(PVOID&)TrueSetWindowDisplayAffinity, FakeSetWindowDisplayAffinity);
    if (TrueSendExampleEventA) {
        DetourDetach(&(PVOID&)TrueSendExampleEventA, FakeSendExampleEventA);
    }
    if (TrueSendWindowForegoundInfo) {
        DetourDetach(&(PVOID&)TrueSendWindowForegoundInfo, FakeSendWindowForegoundInfo);
    }
    DetourTransactionCommit();
}

// ---------- Install all hooks ----------
BOOL InstallHooks() {
    // 1. Find target window by class name "EXAMPLE_WINDOW_CLASS"
    g_targetHwnd = FindWindow(L"EXAMPLE_WINDOW_CLASS", NULL);
    if (!g_targetHwnd) {
        MessageBox(NULL, L"EXAMPLE_WINDOW_CLASS window not found!", L"Error", MB_OK);
        return FALSE;
    }

    // Force allow screenshots: clear any display affinity
    SetWindowDisplayAffinity(g_targetHwnd, WDA_NONE);

    DWORD tid = GetWindowThreadProcessId(g_targetHwnd, NULL);

    // 2. Install message hook
    g_hMsgHook = SetWindowsHookEx(WH_GETMESSAGE, GetMsgProc,
        GetModuleHandle(L"FocusCheat.dll"), tid);
    if (!g_hMsgHook) return FALSE;

    // 3. Install API hooks via Detours
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueGetForegroundWindow, FakeGetForegroundWindow);
    DetourAttach(&(PVOID&)TrueSetWindowDisplayAffinity, FakeSetWindowDisplayAffinity);

    // 4. Hook example_module.dll internal functions (if loaded)
    HMODULE hLibOwcr = GetModuleHandle(L"example_module.dll");
    if (hLibOwcr) {
        PVOID pMinimize = FindLibOwcrFunc("ExampleEventA");
        PVOID pForeground = FindLibOwcrFunc("ExampleEventB");
        if (pMinimize) {
            TrueSendExampleEventA = (SendExampleEventA_t)pMinimize;
            DetourAttach(&(PVOID&)TrueSendExampleEventA, FakeSendExampleEventA);
        }
        if (pForeground) {
            TrueSendWindowForegoundInfo = (SendWindowForegoundInfo_t)pForeground;
            DetourAttach(&(PVOID&)TrueSendWindowForegoundInfo, FakeSendWindowForegoundInfo);
        }
    }

    DetourTransactionCommit();

    return TRUE;
}