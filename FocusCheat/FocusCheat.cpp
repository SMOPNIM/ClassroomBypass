#include "FocusCheat.h"
#include <windows.h>
#include <tlhelp32.h>
#include <detours.h>
#include <stdio.h>
#include <stdarg.h>
#include <string>
#include <winnt.h>

#pragma comment(lib, "detours.lib")

// Generic foreground / display-affinity research module.
// It only affects windows owned by the process it is injected into.
// No target process name, window class, or third-party module name is
// hardcoded. Optional advanced hooks are loaded from FocusCheat.ini
// located next to this DLL (see FocusCheat.example.ini).

// Append-only diagnostics log next to this DLL.
static void Log(const char* fmt, ...) {
    char dllPath[MAX_PATH] = {};
    GetModuleFileNameA(GetModuleHandleA("FocusCheat.dll"), dllPath, MAX_PATH);
    std::string p(dllPath);
    size_t pos = p.find_last_of("\\/");
    std::string dir = (pos == std::string::npos) ? ".\\" : p.substr(0, pos + 1);
    std::string logPath = dir + "FocusCheat.log";

    FILE* f = NULL;
    if (fopen_s(&f, logPath.c_str(), "a") != 0 || !f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d][pid %lu] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            (unsigned long)GetCurrentProcessId());
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

// ---------- Global variables ----------
static HHOOK g_hMsgHooks[64];
static int g_nMsgHooks = 0;
static DWORD g_hookedTids[256];
static int g_nHookedTids = 0;
static DWORD g_failedTids[64];
static int g_nFailedTids = 0;
static HANDLE g_hWatchThread = NULL;
static volatile BOOL g_bWatching = FALSE;
static BOOL g_attachedCustomA = FALSE;
static BOOL g_attachedCustomB = FALSE;

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

struct CustomConfig {
    wchar_t moduleName[256];
    char sigA[256];
    char sigB[256];
    bool hasModule;
};

static void ReadCustomConfig(CustomConfig& cfg) {
    memset(&cfg, 0, sizeof(cfg));
    wchar_t dir[MAX_PATH];
    GetDllDirectory(dir, MAX_PATH);
    wchar_t iniPath[MAX_PATH];
    _snwprintf_s(iniPath, MAX_PATH, _TRUNCATE, L"%sFocusCheat.ini", dir);

    wchar_t sigAW[256] = {};
    wchar_t sigBW[256] = {};
    GetPrivateProfileString(L"CustomHooks", L"Module", L"", cfg.moduleName, 256, iniPath);
    GetPrivateProfileString(L"CustomHooks", L"Signature1", L"", sigAW, 256, iniPath);
    GetPrivateProfileString(L"CustomHooks", L"Signature2", L"", sigBW, 256, iniPath);
    WideCharToMultiByte(CP_UTF8, 0, sigAW, -1, cfg.sigA, 256, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, sigBW, -1, cfg.sigB, 256, NULL, NULL);
    cfg.hasModule = (cfg.moduleName[0] != 0);
}

static bool ConfigHasModule() {
    CustomConfig cfg;
    ReadCustomConfig(cfg);
    return cfg.hasModule;
}

static bool IsTidHooked(DWORD tid) {
    for (int i = 0; i < g_nHookedTids; i++) {
        if (g_hookedTids[i] == tid) return true;
    }
    return false;
}

// Hooks message handling on all not-yet-hooked threads of this process.
// Returns the number of newly hooked threads.
static int HookNewThreads() {
    int added = 0;
    DWORD selfPid = GetCurrentProcessId();
    HMODULE hSelf = GetModuleHandle(L"FocusCheat.dll");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        Log("thread snapshot failed err=%lu", GetLastError());
        return 0;
    }
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != selfPid) continue;
            if (IsTidHooked(te.th32ThreadID)) continue;
            if (g_nMsgHooks >= 64 || g_nHookedTids >= 256) break;
            HHOOK h = SetWindowsHookEx(WH_GETMESSAGE, GetMsgProc, hSelf, te.th32ThreadID);
            if (h) {
                g_hMsgHooks[g_nMsgHooks++] = h;
                g_hookedTids[g_nHookedTids++] = te.th32ThreadID;
                added++;
            }
            else {
                // Log each failing tid only once to keep the log readable.
                bool logged = false;
                for (int k = 0; k < g_nFailedTids; k++) {
                    if (g_failedTids[k] == te.th32ThreadID) { logged = true; break; }
                }
                if (!logged) {
                    Log("SetWindowsHookEx tid %lu failed err=%lu (best effort, skipped)",
                        (unsigned long)te.th32ThreadID, GetLastError());
                    if (g_nFailedTids < 64) g_failedTids[g_nFailedTids++] = te.th32ThreadID;
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return added;
}

// Resolves not-yet-resolved custom targets. No Detours calls here, so it is
// safe to call outside a transaction. Returns true if anything new resolved.
static bool ResolveCustomTargets(const CustomConfig& cfg) {
    if (!cfg.hasModule) return false;
    HMODULE hMod = GetModuleHandle(cfg.moduleName);
    if (!hMod) return false;
    bool fresh = false;
    if (!TrueCustomHookA && cfg.sigA[0]) {
        PVOID p = FindModuleFuncByMarker(hMod, cfg.sigA);
        if (p) {
            TrueCustomHookA = (CustomNoop_t)p;
            fresh = true;
            Log("custom A resolved at %p", p);
        }
        else {
            Log("custom A: marker not found in module");
        }
    }
    if (!TrueCustomHookB && cfg.sigB[0]) {
        PVOID p = FindModuleFuncByMarker(hMod, cfg.sigB);
        if (p) {
            TrueCustomHookB = (CustomNoop_t)p;
            fresh = true;
            Log("custom B resolved at %p", p);
        }
        else {
            Log("custom B: marker not found in module");
        }
    }
    return fresh;
}

// Attaches resolved-but-unattached custom hooks. Caller must hold an
// active Detours transaction.
static void AttachResolvedCustom() {
    if (TrueCustomHookA && !g_attachedCustomA) {
        LONG err = DetourAttach(&(PVOID&)TrueCustomHookA, FakeCustomHookA);
        Log("attach custom A err=%ld", err);
        if (err == NO_ERROR) g_attachedCustomA = TRUE;
    }
    if (TrueCustomHookB && !g_attachedCustomB) {
        LONG err = DetourAttach(&(PVOID&)TrueCustomHookB, FakeCustomHookB);
        Log("attach custom B err=%ld", err);
        if (err == NO_ERROR) g_attachedCustomB = TRUE;
    }
}

static void InstallCustomHooks() {
    CustomConfig cfg;
    ReadCustomConfig(cfg);
    if (!cfg.hasModule) {
        Log("custom hooks: no Module configured, skipped");
        return;
    }
    Log("custom hooks: module=%S", cfg.moduleName);
    if (!GetModuleHandle(cfg.moduleName)) {
        Log("custom hooks: module not loaded yet, watcher will retry");
        return;
    }
    if (ResolveCustomTargets(cfg)) {
        AttachResolvedCustom();
    }
    else {
        Log("custom hooks: nothing new to attach");
    }
}

// Background watcher: picks up late module loads and late-created threads.
static DWORD WINAPI WatchThreadProc(LPVOID) {
    Log("watcher start");
    for (int i = 0; i < 30 && g_bWatching; i++) {
        // Sleep in small chunks so RemoveHooks never waits out a full cycle.
        for (int s = 0; s < 10 && g_bWatching; s++) {
            Sleep(200);
        }
        if (!g_bWatching) break;
        int added = HookNewThreads();
        if (added > 0) {
            Log("watcher hooked %d new thread(s)", added);
        }
        CustomConfig cfg;
        ReadCustomConfig(cfg);
        if (!cfg.hasModule) break;
        if (!GetModuleHandle(cfg.moduleName)) continue;
        bool fresh = ResolveCustomTargets(cfg);
        bool pending = (TrueCustomHookA && !g_attachedCustomA) ||
                       (TrueCustomHookB && !g_attachedCustomB);
        if (fresh || pending) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            AttachResolvedCustom();
            LONG err = DetourTransactionCommit();
            Log("watcher custom transaction commit err=%ld", err);
        }
    }
    Log("watcher exit");
    return 0;
}

// ---------- Uninstall all hooks ----------
void RemoveHooks() {
    Log("RemoveHooks begin");
    g_bWatching = FALSE;
    if (g_hWatchThread) {
        WaitForSingleObject(g_hWatchThread, 3000);
        CloseHandle(g_hWatchThread);
        g_hWatchThread = NULL;
    }

    for (int i = 0; i < g_nMsgHooks; i++) {
        if (g_hMsgHooks[i]) {
            UnhookWindowsHookEx(g_hMsgHooks[i]);
            g_hMsgHooks[i] = NULL;
        }
    }
    g_nMsgHooks = 0;
    g_nHookedTids = 0;
    g_nFailedTids = 0;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LONG eFg = DetourDetach(&(PVOID&)TrueGetForegroundWindow, FakeGetForegroundWindow);
    LONG eAf = DetourDetach(&(PVOID&)TrueSetWindowDisplayAffinity, FakeSetWindowDisplayAffinity);
    LONG eA = NO_ERROR, eB = NO_ERROR;
    if (g_attachedCustomA) {
        eA = DetourDetach(&(PVOID&)TrueCustomHookA, FakeCustomHookA);
        g_attachedCustomA = FALSE;
    }
    if (g_attachedCustomB) {
        eB = DetourDetach(&(PVOID&)TrueCustomHookB, FakeCustomHookB);
        g_attachedCustomB = FALSE;
    }
    TrueCustomHookA = NULL;
    TrueCustomHookB = NULL;
    LONG eC = DetourTransactionCommit();
    Log("detach fg=%ld affinity=%ld customA=%ld customB=%ld commit=%ld",
        eFg, eAf, eA, eB, eC);
}

// ---------- Install all hooks ----------
BOOL InstallHooks() {
    Log("InstallHooks begin");

    // 1. Install message hooks on all current threads (best effort).
    int hooked = HookNewThreads();
    Log("message hooks installed on %d thread(s)", hooked);

    // 2. Allow capture on our own main window if present.
    HWND hOwn = GetOwnMainWindow();
    if (hOwn) {
        SetWindowDisplayAffinity(hOwn, WDA_NONE);
        Log("cleared display affinity on own main window %p", (void*)hOwn);
    }
    else {
        Log("no own main window found yet");
    }

    // 3. Install API hooks via Detours.
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LONG errFg = DetourAttach(&(PVOID&)TrueGetForegroundWindow, FakeGetForegroundWindow);
    LONG errAf = DetourAttach(&(PVOID&)TrueSetWindowDisplayAffinity, FakeSetWindowDisplayAffinity);
    Log("attach GetForegroundWindow err=%ld, SetWindowDisplayAffinity err=%ld", errFg, errAf);

    // 4. Optional custom hooks from FocusCheat.ini (skipped if absent).
    InstallCustomHooks();

    LONG errCommit = DetourTransactionCommit();
    Log("detour transaction commit err=%ld", errCommit);

    // 5. Watch for late module loads + late-created threads (if configured).
    if (ConfigHasModule()) {
        g_bWatching = TRUE;
        g_hWatchThread = CreateThread(NULL, 0, WatchThreadProc, NULL, 0, NULL);
        if (g_hWatchThread) {
            Log("watcher thread started");
        }
        else {
            g_bWatching = FALSE;
            Log("watcher thread create failed err=%lu", GetLastError());
        }
    }
    else {
        Log("watcher disabled (no Module configured)");
    }

    return TRUE;
}
