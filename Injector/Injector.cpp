#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// Get process ID by executable name
DWORD GetProcessIdByName(const wchar_t* name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// Get the full path of the DLL located in the same directory as this EXE
std::wstring GetDllPath() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        path = path.substr(0, pos + 1);
    }
    path += L"FocusCheat.dll";
    return path;
}

int main() {
    // Target process name (modify if needed)
    const wchar_t* targetProc = L"TARGET_PROCESS";
    DWORD pid = GetProcessIdByName(targetProc);
    if (pid == 0) {
        std::wcout << L"Process not found: " << targetProc << std::endl;
        system("pause");
        return 1;
    }
    std::wcout << L"Found target process PID: " << pid << std::endl;

    // DLL path (auto-located in the same folder as Injector.exe)
    std::wstring dllPath = GetDllPath();
    std::wcout << L"DLL path: " << dllPath << std::endl;

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::wcout << L"Failed to open process. Please run as administrator." << std::endl;
        system("pause");
        return 1;
    }

    // Allocate memory in the target process and write the DLL path
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMem) {
        std::wcout << L"Memory allocation failed!" << std::endl;
        CloseHandle(hProcess);
        system("pause");
        return 1;
    }
    WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, NULL);

    // Create a remote thread to load the DLL (LoadLibraryW)
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        std::wcout << L"DLL injected successfully!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::wcout << L"DLL injection failed. Error code: " << GetLastError() << std::endl;
    }

    // Cleanup
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    system("pause");
    return 0;
}