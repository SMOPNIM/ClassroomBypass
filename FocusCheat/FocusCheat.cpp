#include "FocusCheat.h"
#include <windows.h>
#include <tlhelp32.h>
#include <detours.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <string>
#include <atomic>
#include <winnt.h>

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "version.lib")

// Generic foreground / display-affinity research module.
// It only affects windows owned by the process it is injected into.
// No target process name, window class, or third-party module name is
// hardcoded. Optional advanced hooks are loaded from FocusCheat.ini
// located next to this DLL (see FocusCheat.example.ini).

static CRITICAL_SECTION g_logCs;
static CRITICAL_SECTION g_scanCs;

// RAII guard for the scan lock. Lock order is always scan -> log
// (Log never takes the scan lock), so no inversion is possible.
struct ScanLock {
    ScanLock() { EnterCriticalSection(&g_scanCs); }
    ~ScanLock() { LeaveCriticalSection(&g_scanCs); }
};

// Append-only diagnostics log next to this DLL. Uses only stack buffers
// (no std::string) so it stays usable during process detach, and is
// serialized with a critical section so concurrent writers can't tear lines.
static void Log(const char* fmt, ...) {
    EnterCriticalSection(&g_logCs);
    char dllPath[MAX_PATH] = {};
    GetModuleFileNameA(GetModuleHandleA("FocusCheat.dll"), dllPath, MAX_PATH);
    char dir[MAX_PATH] = ".\\";
    char* sep = strrchr(dllPath, '\\');
    char* slash = strrchr(dllPath, '/');
    if (slash > sep) sep = slash;
    if (sep) {
        size_t n = (size_t)(sep - dllPath) + 1;
        if (n >= sizeof(dir)) n = sizeof(dir) - 1;
        memcpy(dir, dllPath, n);
        dir[n] = '\0';
    }
    char logPath[MAX_PATH * 2] = {};
    _snprintf_s(logPath, sizeof(logPath), _TRUNCATE, "%sFocusCheat.log", dir);

    FILE* f = NULL;
    if (fopen_s(&f, logPath, "a") == 0 && f) {
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
    LeaveCriticalSection(&g_logCs);
}

// ---------- Global variables ----------
static HHOOK g_hMsgHooks[64];
static int g_nMsgHooks = 0;
static DWORD g_hookedTids[256];
static int g_nHookedTids = 0;
static DWORD g_failedTids[64];
static int g_nFailedTids = 0;
static HANDLE g_hWatchThread = NULL;
static std::atomic<BOOL> g_watching{ FALSE };
static BOOL g_attachedCustomA = FALSE;
static BOOL g_attachedCustomB = FALSE;
static HWND g_cachedMainWnd = NULL;
static ULONGLONG g_cachedMainTick = 0;

// Original API pointers (for restoration)
HWND(WINAPI* TrueGetForegroundWindow)(void) = GetForegroundWindow;
BOOL(WINAPI* TrueSetWindowDisplayAffinity)(HWND hWnd, DWORD dwAffinity) = SetWindowDisplayAffinity;

// Optional custom-hook function pointers (resolved from config at runtime).
// Declared __fastcall to match the fake implementations exactly.
typedef void (__fastcall* CustomNoop_t)(void* thisPtr, void* edxReserved);
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

static DWORD FindFuncStart(DWORD textOffset);

static BOOL InitPESections(HMODULE hModule) {
    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    g_pModuleBase = base;
    g_pTextBase = NULL;
    g_dwTextSize = 0;
    g_pRdataBase = NULL;
    g_dwRdataSize = 0;

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

static DWORD FindStringInRdataFrom(const char* keyword, DWORD start) {
    size_t kwLen = strlen(keyword);
    if (!g_pRdataBase || kwLen == 0 || g_dwRdataSize < kwLen) return 0;
    if (start >= g_dwRdataSize) return 0;
    for (DWORD i = start; i + (DWORD)kwLen <= g_dwRdataSize; i++) {
        if (memcmp(g_pRdataBase + i, keyword, kwLen) == 0) {
            return (DWORD)(g_pRdataBase - g_pModuleBase) + i;
        }
    }
    return 0;
}

// UTF-16LE (wide) variant, e.g. CefString event names.
static DWORD FindWideStringInRdataFrom(const char* keyword, DWORD start) {
    size_t kwLen = strlen(keyword);
    if (!g_pRdataBase || kwLen == 0 || kwLen > 120) return 0;
    if (start >= g_dwRdataSize) return 0;
    for (DWORD i = start; i + (DWORD)kwLen * 2 <= g_dwRdataSize; i++) {
        bool ok = true;
        for (size_t k = 0; k < kwLen; k++) {
            if (g_pRdataBase[i + k * 2] != (BYTE)keyword[k] ||
                g_pRdataBase[i + k * 2 + 1] != 0) {
                ok = false;
                break;
            }
        }
        if (ok) return (DWORD)(g_pRdataBase - g_pModuleBase) + i;
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
    // NOTE: compare against the ACTUAL loaded base, not the PE header's
    // preferred ImageBase (ASLR relocates the module at load time).
    DWORD strVa = (DWORD)g_pModuleBase + strRva;
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

static PVOID FindModuleFuncByMarker(HMODULE hModule, const char* marker, int* pFailStage) {
    if (pFailStage) *pFailStage = 0;
    if (!hModule || !marker || !marker[0]) return NULL;
    if (!InitPESections(hModule)) { if (pFailStage) *pFailStage = 1; return NULL; }

    DWORD rdataRva = (DWORD)(g_pRdataBase - g_pModuleBase);
    bool anyString = false;

    // Pass 1: try every narrow occurrence (code may reference a later copy).
    for (DWORD off = 0; ; ) {
        DWORD strRva = FindStringInRdataFrom(marker, off);
        if (!strRva) break;
        anyString = true;
        DWORD funcOffset = FindFuncByStringRef(strRva);
        if (funcOffset) return (PVOID)(g_pTextBase + funcOffset);
        off = strRva - rdataRva + 1;
    }
    // Pass 2: UTF-16LE occurrences.
    for (DWORD off = 0; ; ) {
        DWORD strRva = FindWideStringInRdataFrom(marker, off);
        if (!strRva) break;
        anyString = true;
        DWORD funcOffset = FindFuncByStringRef(strRva);
        if (funcOffset) {
            Log("marker matched wide string");
            return (PVOID)(g_pTextBase + funcOffset);
        }
        off = strRva - rdataRva + 2;
    }

    if (pFailStage) *pFailStage = anyString ? 2 : 1;
    return NULL;
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

// Cached variant: EnumWindows on every call is too expensive for a hot
// path like GetForegroundWindow. Re-enumerate at most every 5 seconds or
// when the cached handle dies. Benign races (double enumeration) are fine.
static HWND GetCachedMainWindow() {
    if (g_cachedMainWnd && IsWindow(g_cachedMainWnd)) {
        DWORD pid = 0;
        GetWindowThreadProcessId(g_cachedMainWnd, &pid);
        if (pid == GetCurrentProcessId()) return g_cachedMainWnd;
    }
    ULONGLONG now = GetTickCount64();
    if (g_cachedMainWnd && now - g_cachedMainTick < 5000) return g_cachedMainWnd;
    g_cachedMainWnd = GetOwnMainWindow();
    g_cachedMainTick = now;
    return g_cachedMainWnd;
}

// ---------- 1. Message hook: intercept focus-loss messages ----------
// NOTE: WH_GETMESSAGE only observes queued (posted) messages. Focus-loss
// notifications delivered via SendMessage bypass this hook entirely;
// intercepting those requires window subclassing (planned separately),
// so this layer is best-effort only.
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
    HWND hOwn = GetCachedMainWindow();
    if (hOwn && IsWindow(hOwn)) {
        return hOwn;
    }
    return TrueGetForegroundWindow();
}

// ---------- 3. Fake SetWindowDisplayAffinity (allow capture) ----------
BOOL WINAPI FakeSetWindowDisplayAffinity(HWND hWnd, DWORD dwAffinity) {
    if (!IsWindow(hWnd)) {
        return TrueSetWindowDisplayAffinity(hWnd, dwAffinity);
    }
    if (dwAffinity == WDA_NONE) {
        // Genuinely succeeding call: pass through untouched.
        return TrueSetWindowDisplayAffinity(hWnd, dwAffinity);
    }
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
    wchar_t funcARva[32];
    wchar_t funcBRva[32];
    char funcAFp[65];
    char funcBFp[65];
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
    wchar_t fpAW[65] = {};
    wchar_t fpBW[65] = {};
    GetPrivateProfileString(L"CustomHooks", L"FuncA_RVA", L"", cfg.funcARva, 32, iniPath);
    GetPrivateProfileString(L"CustomHooks", L"FuncB_RVA", L"", cfg.funcBRva, 32, iniPath);
    GetPrivateProfileString(L"CustomHooks", L"FuncA_FP", L"", fpAW, 65, iniPath);
    GetPrivateProfileString(L"CustomHooks", L"FuncB_FP", L"", fpBW, 65, iniPath);
    WideCharToMultiByte(CP_UTF8, 0, fpAW, -1, cfg.funcAFp, 65, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, fpBW, -1, cfg.funcBFp, 65, NULL, NULL);
    cfg.hasModule = (cfg.moduleName[0] != 0);
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
    bool exhaustedLogged = false;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != selfPid) continue;
            if (IsTidHooked(te.th32ThreadID)) continue;
            if (g_nMsgHooks >= 64 || g_nHookedTids >= 256) {
                // Slots full: skip this thread but keep enumerating the rest.
                if (!exhaustedLogged) {
                    Log("message hook slots exhausted, skipping rest of this pass");
                    exhaustedLogged = true;
                }
                continue;
            }
            HHOOK h = SetWindowsHookEx(WH_GETMESSAGE, GetMsgProc, hSelf, te.th32ThreadID);
            if (h) {
                g_hMsgHooks[g_nMsgHooks++] = h;
                g_hookedTids[g_nHookedTids++] = te.th32ThreadID;
                added++;
            }
            else {
                // Log each failing tid only once (ring: oldest entries are
                // overwritten once full, so a repeat may re-log rarely).
                bool logged = false;
                int known = g_nFailedTids < 64 ? g_nFailedTids : 64;
                for (int k = 0; k < known; k++) {
                    if (g_failedTids[k] == te.th32ThreadID) { logged = true; break; }
                }
                if (!logged) {
                    Log("SetWindowsHookEx tid %lu failed err=%lu (best effort, skipped)",
                        (unsigned long)te.th32ThreadID, GetLastError());
                    g_failedTids[g_nFailedTids % 64] = te.th32ThreadID;
                    g_nFailedTids++;
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return added;
}

// Resolves not-yet-resolved custom targets. No Detours calls here, so it is
// safe to call outside a transaction. Returns true if anything new resolved.
static HMODULE g_versionLoggedFor = NULL;
static BOOL g_diagDone = FALSE;

static void LogModuleVersion(HMODULE hMod) {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileName(hMod, path, MAX_PATH);
    Log("custom module path=%S", path);
    DWORD handle = 0;
    DWORD verSize = GetFileVersionInfoSize(path, &handle);
    if (!verSize || verSize > 65536) {
        Log("custom module has no version resource");
        return;
    }
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, verSize);
    if (!buf) return;
    if (GetFileVersionInfo(path, handle, verSize, buf)) {
        VS_FIXEDFILEINFO* info = NULL;
        UINT infoLen = 0;
        if (VerQueryValue(buf, L"\\", (LPVOID*)&info, &infoLen) && info) {
            Log("custom module version %u.%u.%u.%u",
                (unsigned)HIWORD(info->dwFileVersionMS), (unsigned)LOWORD(info->dwFileVersionMS),
                (unsigned)HIWORD(info->dwFileVersionLS), (unsigned)LOWORD(info->dwFileVersionLS));
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
}

// Temporary diagnostic: count raw occurrences of the packed string VA in
// .text (opcode-agnostic) and log module geometry. Tells apart "bytes not
// in memory" from "seen but not recognized".
static void LogScanDiag(const char* tag, DWORD strRva) {
    DWORD strVa = (DWORD)g_pModuleBase + strRva;
    BYTE pat[4];
    pat[0] = (BYTE)(strVa & 0xFF);
    pat[1] = (BYTE)((strVa >> 8) & 0xFF);
    pat[2] = (BYTE)((strVa >> 16) & 0xFF);
    pat[3] = (BYTE)((strVa >> 24) & 0xFF);
    DWORD hitOff[8] = {};
    int hits = 0;
    if (g_pTextBase && g_dwTextSize > 4) {
        for (DWORD i = 0; i + 4 <= g_dwTextSize; i++) {
            if (memcmp(g_pTextBase + i, pat, 4) == 0) {
                if (hits < 8) hitOff[hits] = i;
                hits++;
            }
        }
    }
    Log("diag %s: modBase=%p textSize=0x%X strRva=0x%X strVa=0x%08X rawHits=%d",
        tag, (void*)g_pModuleBase, g_dwTextSize, strRva, strVa, hits);
    for (int k = 0; k < hits && k < 8; k++) {
        // Dump 8 bytes before and after the hit: identifies the real opcode.
        DWORD ctxBase = hitOff[k] >= 8 ? hitOff[k] - 8 : 0;
        char hex[49] = {};
        for (int b = 0; b < 16; b++) {
            if (ctxBase + (DWORD)b >= g_dwTextSize) break;
            unsigned v = g_pTextBase[ctxBase + b];
            hex[b * 3] = "0123456789ABCDEF"[(v >> 4) & 0xF];
            hex[b * 3 + 1] = "0123456789ABCDEF"[v & 0xF];
            hex[b * 3 + 2] = ' ';
        }
        Log("diag %s: hit#%d at text+0x%X ctx[%08X]=%s", tag, k, hitOff[k],
            (unsigned)(ctxBase + 0x1000), hex);
    }
}

// Relocation-aware fingerprint check: bytes covered by a HIGHLOW reloc
// entry legitimately differ (preferred base vs loaded base), so they are
// skipped during comparison. Returns true on match.
static bool VerifyFingerprint(HMODULE hMod, DWORD rva, const BYTE* fp, int fpLen) {
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    DWORD relocAddr = 0, relocSize = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {};
        memcpy(name, sections[i].Name, 8);
        if (strcmp(name, ".reloc") == 0) {
            relocAddr = sections[i].VirtualAddress;
            relocSize = sections[i].Misc.VirtualSize;
            break;
        }
    }
    // Collect HIGHLOW reloc RVAs that overlap [rva, rva+fpLen).
    DWORD hits[64];
    int nHits = 0;
    if (relocAddr && relocSize) {
        DWORD end = relocAddr + relocSize;
        for (DWORD blk = relocAddr; blk + 8 <= end && nHits < 64; ) {
            DWORD page = *(DWORD*)(base + blk);
            DWORD blkSize = *(DWORD*)(base + blk + 4);
            if (blkSize < 8) break;
            for (DWORD o = 8; o + 2 <= blkSize && nHits < 64; o += 2) {
                WORD e = *(WORD*)(base + blk + o);
                if ((e >> 12) == 3) { // IMAGE_REL_BASED_HIGHLOW
                    DWORD rr = page + (e & 0x0FFF);
                    if (rr + 4 > rva && rr < rva + (DWORD)fpLen) {
                        hits[nHits++] = rr;
                    }
                }
            }
            blk += blkSize;
        }
    }
    for (int i = 0; i < fpLen; i++) {
        bool relocated = false;
        for (int k = 0; k < nHits; k++) {
            if ((DWORD)i + rva >= hits[k] && (DWORD)i + rva < hits[k] + 4) {
                relocated = true;
                break;
            }
        }
        if (!relocated && base[rva + i] != fp[i]) return false;
    }
    return true;
}
static bool TryResolvePinned(HMODULE hMod, const wchar_t* rvaStr, const char* fpHex,
                             const char* sig, CustomNoop_t& trueFn, char label) {
    if (trueFn) return false; // already resolved
    if (!rvaStr[0]) return false; // not configured
    wchar_t* end = NULL;
    unsigned long rva = wcstoul(rvaStr, &end, 16);
    if (end == rvaStr || rva == 0) {
        Log("custom %c: bad RVA value", label);
        return false;
    }
    BYTE fp[32];
    int fpLen = 0;
    for (const char* p = fpHex; p[0] && p[1] && fpLen < 32; p += 2) {
        int hi = (p[0] >= '0' && p[0] <= '9') ? p[0] - '0'
               : ((p[0] >= 'A' && p[0] <= 'F') ? p[0] - 'A' + 10
               : ((p[0] >= 'a' && p[0] <= 'f') ? p[0] - 'a' + 10 : -1));
        int lo = (p[1] >= '0' && p[1] <= '9') ? p[1] - '0'
               : ((p[1] >= 'A' && p[1] <= 'F') ? p[1] - 'A' + 10
               : ((p[1] >= 'a' && p[1] <= 'f') ? p[1] - 'a' + 10 : -1));
        if (hi < 0 || lo < 0) break;
        fp[fpLen++] = (BYTE)(hi * 16 + lo);
    }
    if (fpLen < 8) {
        Log("custom %c: fingerprint too short (need >=8 hex chars)", label);
        return false;
    }
    if (!InitPESections(hMod)) {
        Log("custom %c: PE parse failed", label);
        return false;
    }
    BYTE* base = (BYTE*)hMod;
    if (!InitPESections(hMod)) {
        Log("custom %c: PE parse failed", label);
        return false;
    }
    DWORD textRva = (DWORD)(g_pTextBase - base);
    if (rva < textRva || rva + (DWORD)fpLen > textRva + g_dwTextSize) {
        Log("custom %c: RVA 0x%X outside .text, refused", label, rva);
        return false;
    }
    if (!VerifyFingerprint(hMod, rva, fp, fpLen)) {
        char actual[65] = {};
        for (int b = 0; b < fpLen && b < 32; b++) {
            unsigned v = *(base + rva + b);
            actual[b * 2] = "0123456789ABCDEF"[(v >> 4) & 0xF];
            actual[b * 2 + 1] = "0123456789ABCDEF"[v & 0xF];
        }
        Log("custom %c: fingerprint mismatch at RVA 0x%X, refused (module updated?)",
            label, rva);
        Log("custom %c: actual bytes: %s", label, actual);
        return false;
    }
    trueFn = (CustomNoop_t)(base + rva);
    Log("custom %c pinned at %p (fingerprint ok)", label, (void*)trueFn);
    // Consistency check: the marker string (narrow or wide) must be
    // referenced within the first 0x400 bytes (matches the analyzed layout).
    // The scan is bounded to the section end. Refuse otherwise.
    if (sig[0] && InitPESections(hMod)) {
        DWORD textRva2 = (DWORD)(g_pTextBase - base);
        DWORD scanLen = 0x400;
        if (rva >= textRva2 && rva - textRva2 < g_dwTextSize) {
            DWORD remain = g_dwTextSize - (rva - textRva2);
            if (remain < scanLen) scanLen = remain;
        }
        else {
            scanLen = 0;
        }
        DWORD vaN = 0, vaW = 0;
        DWORD rN = FindStringInRdataFrom(sig, 0);
        if (rN) vaN = (DWORD)base + rN;
        DWORD rW = FindWideStringInRdataFrom(sig, 0);
        if (rW) vaW = (DWORD)base + rW;
        bool consistent = false;
        for (DWORD i = 0; i + 5 < scanLen && !consistent; i++) {
            BYTE op = *(base + rva + i);
            if (op == 0x68 || op == 0xB8 || op == 0xB9 || op == 0xBA ||
                op == 0xBB || op == 0xBE || op == 0xBF) {
                DWORD imm = *(DWORD*)(base + rva + i + 1);
                if ((vaN && imm == vaN) || (vaW && imm == vaW)) {
                    consistent = true;
                    Log("custom %c: marker ref found +0x%X inside, consistent", label, i);
                }
            }
        }
        if (!consistent) {
            Log("custom %c: pinned target does not reference the marker, refused", label);
            trueFn = NULL;
            return false;
        }
    }
    return true;
}

static bool ResolveCustomTargets(const CustomConfig& cfg) {
    if (!cfg.hasModule) return false;
    HMODULE hMod = GetModuleHandle(cfg.moduleName);
    if (!hMod) return false;
    ScanLock scanLock;
    if (hMod != g_versionLoggedFor) {
        LogModuleVersion(hMod);
        g_versionLoggedFor = hMod;
    }
    if (!g_diagDone && (!TrueCustomHookA || !TrueCustomHookB)) {
        g_diagDone = TRUE;
        // NOTE: sections must be initialized before scanning (FindString*
        // helpers rely on globals set by InitPESections).
        if (InitPESections(hMod)) {
            DWORD rA = FindStringInRdataFrom(cfg.sigA, 0);
            if (rA) LogScanDiag("A", rA);
            DWORD rB = FindStringInRdataFrom(cfg.sigB, 0);
            if (rB) LogScanDiag("B", rB);
        }
    }
    bool fresh = false;
    if (!TrueCustomHookA) {
        // Pinned RVA wins when configured; otherwise fall back to the
        // string heuristic (works for framed functions).
        if (cfg.funcARva[0]) {
            if (TryResolvePinned(hMod, cfg.funcARva, cfg.funcAFp, cfg.sigA, TrueCustomHookA, 'A')) {
                fresh = true;
            }
        }
        else if (cfg.sigA[0]) {
            int stage = 0;
            PVOID p = FindModuleFuncByMarker(hMod, cfg.sigA, &stage);
            if (p) {
                TrueCustomHookA = (CustomNoop_t)p;
                fresh = true;
                Log("custom A resolved at %p", p);
            }
            else {
                Log("custom A: locate failed at stage %d (1=no string, 2=no code ref)", stage);
            }
        }
    }
    if (!TrueCustomHookB) {
        if (cfg.funcBRva[0]) {
            if (TryResolvePinned(hMod, cfg.funcBRva, cfg.funcBFp, cfg.sigB, TrueCustomHookB, 'B')) {
                fresh = true;
            }
        }
        else if (cfg.sigB[0]) {
            int stage = 0;
            PVOID p = FindModuleFuncByMarker(hMod, cfg.sigB, &stage);
            if (p) {
                TrueCustomHookB = (CustomNoop_t)p;
                fresh = true;
                Log("custom B resolved at %p", p);
            }
            else {
                Log("custom B: locate failed at stage %d (1=no string, 2=no code ref)", stage);
            }
        }
    }
    return fresh;
}

// Attaches resolved-but-unattached custom hooks. Caller must hold an
// active Detours transaction.
static void AttachResolvedCustom() {
    ScanLock scanLock;
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

// One resolve+attach round. Quiet unless something happens (or verbose).
static void TryAttachCustomOnce(bool verbose) {
    CustomConfig cfg;
    ReadCustomConfig(cfg);
    if (!cfg.hasModule) {
        if (verbose) Log("custom hooks: no Module configured, skipped");
        return;
    }
    if (verbose) Log("custom hooks: module=%S", cfg.moduleName);
    if (!GetModuleHandle(cfg.moduleName)) {
        if (verbose) Log("custom hooks: module not loaded yet, watcher will retry");
        return;
    }
    bool fresh = ResolveCustomTargets(cfg);
    bool pending = (TrueCustomHookA && !g_attachedCustomA) ||
                   (TrueCustomHookB && !g_attachedCustomB);
    if (!fresh && !pending) {
        if (verbose) Log("custom hooks: nothing new to attach");
        return;
    }
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    AttachResolvedCustom();
    LONG err = DetourTransactionCommit();
    Log("custom transaction commit err=%ld", err);
}

// Background watcher: performs everything too heavy for DllMain (message
// hooks, window enumeration, ini/PE scanning live here, outside the loader
// lock), then keeps watching for late module loads and late-created threads.
static DWORD WINAPI WatchThreadProc(LPVOID) {
    Log("watcher start");

    // First pass runs immediately: message hooks, affinity clear, custom hooks.
    {
        int added = HookNewThreads();
        Log("message hooks installed on %d thread(s)", added);
        HWND hOwn = GetOwnMainWindow();
        if (hOwn) {
            SetWindowDisplayAffinity(hOwn, WDA_NONE);
            Log("cleared display affinity on own main window %p", (void*)hOwn);
        }
        else {
            Log("no own main window found yet");
        }
        TryAttachCustomOnce(true);
    }

    for (int i = 0; i < 30 && g_watching.load(); i++) {
        // Sleep in small chunks so the thread notices shutdown quickly.
        for (int s = 0; s < 10 && g_watching.load(); s++) {
            Sleep(200);
        }
        if (!g_watching.load()) break;
        int added = HookNewThreads();
        if (added > 0) {
            Log("watcher hooked %d new thread(s)", added);
        }
        TryAttachCustomOnce(false);
    }
    Log("watcher exit");
    return 0;
}

// ---------- Uninstall all hooks ----------
void RemoveHooks() {
    Log("RemoveHooks begin");
    g_watching.store(FALSE);
    // NOTE: deliberately no WaitForSingleObject/CloseHandle here. Waiting
    // inside DllMain risks deadlock, and closing the handle while the thread
    // might still run risks use-after-unmap. The thread exits itself within
    // ~200ms (chunked sleep); the leaked handle dies with the process.

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
    g_versionLoggedFor = NULL;
    g_diagDone = FALSE;
    LONG eC = DetourTransactionCommit();
    Log("detach fg=%ld affinity=%ld customA=%ld customB=%ld commit=%ld",
        eFg, eAf, eA, eB, eC);
}

// ---------- Install all hooks ----------
// NOTE: runs inside DllMain (loader lock held), so this only installs the
// two Detours API hooks and spawns the watcher. Everything heavier (thread
// snapshot, window enumeration, ini parsing, PE scanning) happens in the
// watcher thread outside the loader lock. Returns FALSE on API-hook failure,
// in which case the loader unloads us and the injector reports it.
BOOL InstallHooks() {
    InitializeCriticalSection(&g_logCs);
    InitializeCriticalSection(&g_scanCs);
    Log("InstallHooks begin");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LONG errFg = DetourAttach(&(PVOID&)TrueGetForegroundWindow, FakeGetForegroundWindow);
    LONG errAf = DetourAttach(&(PVOID&)TrueSetWindowDisplayAffinity, FakeSetWindowDisplayAffinity);
    LONG errCommit = DetourTransactionCommit();
    Log("attach GetForegroundWindow err=%ld, SetWindowDisplayAffinity err=%ld, commit err=%ld",
        errFg, errAf, errCommit);
    if (errFg != NO_ERROR || errAf != NO_ERROR || errCommit != NO_ERROR) {
        Log("InstallHooks: API hook install FAILED, refusing load");
        return FALSE;
    }

    g_watching.store(TRUE);
    g_hWatchThread = CreateThread(NULL, 0, WatchThreadProc, NULL, 0, NULL);
    if (g_hWatchThread) {
        Log("watcher thread started");
    }
    else {
        g_watching.store(FALSE);
        Log("watcher thread create failed err=%lu (continuing without it)", GetLastError());
    }

    return TRUE;
}
