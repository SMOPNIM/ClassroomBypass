#include "FocusCheat.h"
#include <windows.h>
#include <detours.h>
#include <stdio.h>

#pragma comment(lib, "detours.lib")

// ---------- Global variables ----------
static HWND g_targetHwnd = NULL;
static HHOOK g_hMsgHook = NULL;

// Original API pointers (for restoration)
HWND(WINAPI* TrueGetForegroundWindow)(void) = GetForegroundWindow;
BOOL(WINAPI* TrueSetWindowDisplayAffinity)(HWND hWnd, DWORD dwAffinity) = SetWindowDisplayAffinity;

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
        // For the target window, return success but do nothing (allow capture)
        return TRUE;
    }
    return TrueSetWindowDisplayAffinity(hWnd, dwAffinity);
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
    DetourTransactionCommit();

    return TRUE;
}