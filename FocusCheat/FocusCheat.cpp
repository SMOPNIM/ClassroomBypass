#include "FocusCheat.h"
#include <windows.h>
#include <tlhelp32.h>
#include <detours.h>
#include <stdio.h>
#include <string>
#include <winnt.h>

#pragma comment(lib, "detours.lib")

// Generic foreground / display-affinity research module.
// It only affects windows owned by the process it is injected into.
// No target process name, window class, or third-party module name is
// hardcoded. Optional advanced hooks are loaded from FocusCheat.ini
// located next to this DLL (see FocusCheat.example.ini).

// ---------- Global variables ----------
static HHOOK g_hMsgHooks[64];
static int g_nMsgHooks = 0;

// Original API pointers (for restoration)
HWND(WINAPI* TrueGetForegroundWindow)(void) = GetForegroundWindow;
BOOL(WINAPI* TrueSetWindowDisplayAffinity)(HWND hWnd, DWORD dwAffinity) = SetWindowDisplayAffinity;

// Optional custom-hook function pointers (resolved from config at runtime)
typedef void (__thiscall* CustomNoop_t)(void* thisPtr);
static CustomNoop_t TrueCustomHookA = NULL;
static CustomNoop_t TrueCustomHookB = NULL;

// ============================================================
// PE Analysis: locate functions in a configured module by
// searching for configured marker strings at runtime.
// ============================================================
static BYTE* g_pModuleBase = NULL;
static BYTE* g_pTextBase = NULL;
static DWORD g_dwTextSize = 0;
static BYTE* g_pRdataBase = NULL;
static DWORD g_dwRdataSize = 0;
static DWORD g_dwImageBase = 0;

static DWORD FindFuncStart(DWORD textOffset);

static BOOL InitPESections(HMODULE hModule) {
    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    g_pModuleBase = base;
    g_dwImageBase = nt->OptionalHeader.ImageBase;
    g_pTextBase = NULL;
    g_pRdataBase = NULL;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD numSections = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; i++) {
        char name[9] = {};
        memcpy(name, sections[i].Name, 8);
        if (strcmp(name, ".text") == 0) {
            g_pTextBase = base + sections[i].VirtualAddress;
            g_dwTextSize = sections[i].Misc.VirtualSize;
        }
        else if (strcmp(name, ".rdata") == 0) {
            g_pRdataBase = base + sections[i].VirtualAddress;
            g_dwRdataSize = sections[i].Misc.VirtualSize;
        }
    }
    return (g_pTextBase && g_pRdataBase);
}

static DWORD FindStringInRdata(const char* keyword) {
    size_t kwLen = strlen(keyword);
    if (!g_pRdataBase || kwLen == 0 || g_dwRdataSize < kwLen) return 0;
    for (DWORD i = 0; i + (DWORD)kwLen <= g_dwRdataSize; i++) {
        if (memcmp(g_pRdataBase + i, keyword, kwLen) == 0) {
            return (DWORD)(g_pRdataBase - g_pModuleBase) + i;
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
        // PUSH imm32
        if (g_pTextBase[i] == 0x68) {
            DWORD imm = *(DWORD*)(g_pTextBase + i + 1);
            if (imm == strVa) return FindFuncStart(i);
        }
        // MOV reg, imm32 (BE=ESI, BA=EDX, BF=EDI, B8=EAX, BB=EBX, B9=ECX)
        if (g_pTextBase[i] == 0xBE || g_pTextBase[i] == 0xBA ||
            g_pTextBase[i] == 0xBF || g_pTextBase[i] == 0xB8 ||
            g_pTextBase[i] == 0xBB || g_pTextBase[i] == 0xB9) {
            DWORD imm = *(DWORD*)(g_pTextBase + i + 1);
            if (imm == strVa) return FindFuncStart(i);
        }
    }
    return 0;
}

static PVOID FindModuleFuncByMarker(HMODULE hModule, const char* marker) {
    if (!hModule || !marker || !marker[0]) return NULL;
    if (!InitPESections(hModule)) return NULL;

    DWORD strRva = FindStringInRdata(marker);
    if (!strRva) return NULL;

    DWORD funcOffset = FindFuncByStringRef(strRva);
    if (!funcOffset) return NULL;

    return (PVOID)(g_pTextBase + funcOffset);
}

// ---------- Own-process window helpers ----------
static BOOL IsOwnWindow(HWND hWnd) {
    if (!hWnd) return FALSE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    return pid == GetCurrentProcessId();
}

static BOOL CALLBACK EnumOwnMainWindow(HWND hWnd, LPARAM lParam) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;
    if (!IsWindowVisible(hWnd)) return TRUE;
    if (GetWindow(hWnd, GW_OWNER) != NULL) return TRUE;
    *(HWND*)lParam = hWnd;
    return FALSE;
}

static HWND GetOwnMainWindow() {
    HWND hWnd = NULL;
    EnumWindows(EnumOwnMainWindow, (LPARAM)&hWnd);
    return hWnd;
}

// ---------- 1. Message hook: intercept focus-loss messages ----------
LRESULT CALLBACK GetMsgProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION) {
        MSG* pMsg = (MSG*)lParam;
        if (IsOwnWindow(pMsg->hwnd)) {
            // Discard focus-loss messages so the process keeps
            // behaving as if its window stayed in the foreground.
            if (pMsg->message == WM_KILLFOCUS || pMsg->message == WM_ACTIVATE) {
                return 1;
            }
        }
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

// ---------- 2. Fake GetForegroundWindow (spoof foreground ownership) ----------
HWND WINAPI FakeGetForegroundWindow(void) {
    HWND hOwn = GetOwnMainWindow();
    if (hOwn && IsWindow(hOwn)) {
        return hOwn;
    }
    return TrueGetForegroundWindow();
}

// ---------- 3. Fake SetWindowDisplayAffinity (allow capture) ----------
BOOL WINAPI FakeSetWindowDisplayAffinity(HWND hWnd, DWORD dwAffinity) {
    if (IsOwnWindow(hWnd)) {
        // Report success without applying the restriction.
        return TRUE;
    }
    return TrueSetWindowDisplayAffinity(hWnd, dwAffinity);
}

// ---------- 4-5. Optional custom hooks (configured via ini) ----------
void __fastcall FakeCustomHookA(void* thisPtr, void* EDX) {
    (void)thisPtr;
    (void)EDX;
    // No-op: suppress the configured notification.
}

void __fastcall FakeCustomHookB(void* thisPtr, void* EDX) {
    (void)thisPtr;
    (void)EDX;
    // No-op: suppress the configured notification.
}

static void GetDllDirectory(wchar_t* outDir, DWORD cch) {
    wchar_t path[MAX_PATH];
    GetModuleFileName(GetModuleHandle(L"FocusCheat.dll"), path, MAX_PATH);
    std::wstring p(path);
    size_t pos = p.find_last_of(L"\\/");
    std::wstring dir = (pos == std::wstring::npos) ? L".\\" : p.substr(0, pos + 1);
    wcsncpy_s(outDir, cch, dir.c_str(), _TRUNCATE);
}

static void InstallCustomHooks() {
    wchar_t dir[MAX_PATH];
    GetDllDirectory(dir, MAX_PATH);
    wchar_t iniPath[MAX_PATH];
    _snwprintf_s(iniPath, MAX_PATH, _TRUNCATE, L"%sFocusCheat.ini", dir);

    wchar_t moduleName[256] = {};
    wchar_t sigA[256] = {};
    wchar_t sigB[256] = {};
    GetPrivateProfileString(L"CustomHooks", L"Module", L"", moduleName, 256, iniPath);
    GetPrivateProfileString(L"CustomHooks", L"Signature1", L"", sigA, 256, iniPath);
    GetPrivateProfileString(L"CustomHooks", L"Signature2", L"", sigB, 256, iniPath);

    if (!moduleName[0]) return;

    HMODULE hMod = GetModuleHandle(moduleName);
    if (!hMod) return;

    char sigA8[256] = {};
    char sigB8[256] = {};
    WideCharToMultiByte(CP_UTF8, 0, sigA, -1, sigA8, 256, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, sigB, -1, sigB8, 256, NULL, NULL);

    if (sigA8[0]) {
        PVOID p = FindModuleFuncByMarker(hMod, sigA8);
        if (p) {
            TrueCustomHookA = (CustomNoop_t)p;
            DetourAttach(&(PVOID&)TrueCustomHookA, FakeCustomHookA);
        }
    }
    if (sigB8[0]) {
        PVOID p = FindModuleFuncByMarker(hMod, sigB8);
        if (p) {
            TrueCustomHookB = (CustomNoop_t)p;
            DetourAttach(&(PVOID&)TrueCustomHookB, FakeCustomHookB);
        }
    }
}

// ---------- Uninstall all hooks ----------
void RemoveHooks() {
    for (int i = 0; i < g_nMsgHooks; i++) {
        if (g_hMsgHooks[i]) {
            UnhookWindowsHookEx(g_hMsgHooks[i]);
            g_hMsgHooks[i] = NULL;
        }
    }
    g_nMsgHooks = 0;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueGetForegroundWindow, FakeGetForegroundWindow);
    DetourDetach(&(PVOID&)TrueSetWindowDisplayAffinity, FakeSetWindowDisplayAffinity);
    if (TrueCustomHookA) {
        DetourDetach(&(PVOID&)TrueCustomHookA, FakeCustomHookA);
    }
    if (TrueCustomHookB) {
        DetourDetach(&(PVOID&)TrueCustomHookB, FakeCustomHookB);
    }
    DetourTransactionCommit();
}

// ---------- Install all hooks ----------
BOOL InstallHooks() {
    HMODULE hSelf = GetModuleHandle(L"FocusCheat.dll");

    // 1. Install message hooks on all threads of this process (best effort).
    DWORD selfPid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == selfPid && g_nMsgHooks < (int)(sizeof(g_hMsgHooks) / sizeof(g_hMsgHooks[0]))) {
                    HHOOK h = SetWindowsHookEx(WH_GETMESSAGE, GetMsgProc, hSelf, te.th32ThreadID);
                    if (h) g_hMsgHooks[g_nMsgHooks++] = h;
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    // 2. Allow capture on our own main window if present.
    HWND hOwn = GetOwnMainWindow();
    if (hOwn) {
        SetWindowDisplayAffinity(hOwn, WDA_NONE);
    }

    // 3. Install API hooks via Detours.
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueGetForegroundWindow, FakeGetForegroundWindow);
    DetourAttach(&(PVOID&)TrueSetWindowDisplayAffinity, FakeSetWindowDisplayAffinity);

    // 4. Optional custom hooks from FocusCheat.ini (skipped if absent).
    InstallCustomHooks();

    DetourTransactionCommit();

    return TRUE;
}
