#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cwctype>

// Generic DLL injector.
// No hardcoded target process: the target is chosen via command-line
// arguments or an interactive prompt at runtime.

struct ProcessEntry {
    DWORD pid = 0;
    std::wstring name;
};

struct Options {
    DWORD pid = 0;
    std::wstring processName;
    std::wstring dllPath;
    bool listOnly = false;
};

static void PrintUsage() {
    std::wcout << L"Usage:\n"
               << L"  Injector.exe [--pid <PID> | --process <name.exe>] [--dll <path>]\n"
               << L"  Injector.exe [--dll <path>] <PID | name.exe>\n"
               << L"  Injector.exe --list\n"
               << L"\n"
               << L"Options:\n"
               << L"  --pid, -p <PID>        Target process ID\n"
               << L"  --process, -n <name>   Target process image name (e.g. TARGET.EXE)\n"
               << L"  --dll, -d <path>       DLL to inject (default: FocusCheat.dll next to this EXE)\n"
               << L"  --list, -l             List running processes and exit\n"
               << L"  --help, -h             Show this help\n"
               << L"\n"
               << L"If no target is given, running processes are listed and you are\n"
               << L"prompted to enter a PID or process image name.\n";
}

static std::wstring Trim(const std::wstring& s) {
    size_t b = 0;
    while (b < s.size() && std::iswspace(s[b])) ++b;
    size_t e = s.size();
    while (e > b && std::iswspace(s[e - 1])) --e;
    return s.substr(b, e - b);
}

static bool IsAllDigits(const std::wstring& s) {
    if (s.empty()) return false;
    for (wchar_t c : s) {
        if (!std::iswdigit(c)) return false;
    }
    return true;
}

// Get the full path of the DLL located in the same directory as this EXE
static std::wstring GetDefaultDllPath() {
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

static std::vector<ProcessEntry> ListAllProcesses() {
    std::vector<ProcessEntry> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            ProcessEntry e;
            e.pid = pe.th32ProcessID;
            e.name = pe.szExeFile;
            out.push_back(e);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    std::sort(out.begin(), out.end(), [](const ProcessEntry& a, const ProcessEntry& b) {
        if (a.name != b.name) return a.name < b.name;
        return a.pid < b.pid;
    });
    return out;
}

static std::vector<DWORD> FindPidsByName(const std::wstring& name) {
    std::vector<DWORD> pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) {
                pids.push_back(pe.th32ProcessID);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pids;
}

static bool ProcessExists(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    CloseHandle(h);
    return true;
}

// Resolve a process image name to a PID. If several instances match,
// the user is asked to pick one.
static DWORD ResolveNameToPid(const std::wstring& name) {
    std::vector<DWORD> pids = FindPidsByName(name);
    if (pids.empty()) return 0;
    if (pids.size() == 1) return pids[0];

    std::wcout << L"Multiple processes named \"" << name << L"\" found:\n";
    for (DWORD pid : pids) {
        std::wcout << L"  PID " << pid << L"\n";
    }
    std::wcout << L"Enter PID: ";
    std::wstring input;
    std::getline(std::wcin, input);
    input = Trim(input);
    if (!IsAllDigits(input)) return 0;
    DWORD pid = static_cast<DWORD>(std::wcstoul(input.c_str(), nullptr, 10));
    if (std::find(pids.begin(), pids.end(), pid) == pids.end()) return 0;
    return pid;
}

// Interactive fallback: list processes and prompt for PID or image name.
static DWORD PromptForTarget() {
    std::vector<ProcessEntry> procs = ListAllProcesses();
    if (procs.empty()) {
        std::wcout << L"Unable to enumerate processes." << std::endl;
        return 0;
    }
    std::wcout << L"Running processes:\n";
    for (const auto& e : procs) {
        std::wcout << L"  " << e.pid << L"  " << e.name << L"\n";
    }
    std::wcout << L"\nEnter target PID or process image name: ";
    std::wstring input;
    std::getline(std::wcin, input);
    input = Trim(input);
    if (input.empty()) return 0;
    if (IsAllDigits(input)) {
        return static_cast<DWORD>(std::wcstoul(input.c_str(), nullptr, 10));
    }
    return ResolveNameToPid(input);
}

static bool ParseArgs(int argc, wchar_t** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--help" || a == L"-h") {
            PrintUsage();
            exit(0);
        }
        else if (a == L"--list" || a == L"-l") {
            opt.listOnly = true;
        }
        else if ((a == L"--pid" || a == L"-p") && i + 1 < argc) {
            std::wstring v = Trim(argv[++i]);
            if (!IsAllDigits(v)) {
                std::wcout << L"Invalid PID value: " << v << std::endl;
                return false;
            }
            opt.pid = static_cast<DWORD>(std::wcstoul(v.c_str(), nullptr, 10));
        }
        else if ((a == L"--process" || a == L"-n") && i + 1 < argc) {
            opt.processName = Trim(argv[++i]);
        }
        else if ((a == L"--dll" || a == L"-d") && i + 1 < argc) {
            opt.dllPath = Trim(argv[++i]);
        }
        else if (!a.empty() && a[0] != L'-') {
            // Positional argument: PID or process image name.
            std::wstring v = Trim(a);
            if (IsAllDigits(v)) {
                opt.pid = static_cast<DWORD>(std::wcstoul(v.c_str(), nullptr, 10));
            }
            else {
                opt.processName = v;
            }
        }
        else {
            std::wcout << L"Unknown argument: " << a << std::endl;
            PrintUsage();
            return false;
        }
    }
    return true;
}

int wmain(int argc, wchar_t** argv) {
    Options opt;
    if (!ParseArgs(argc, argv, opt)) {
        system("pause");
        return 1;
    }

    if (opt.listOnly) {
        std::vector<ProcessEntry> procs = ListAllProcesses();
        for (const auto& e : procs) {
            std::wcout << e.pid << L"  " << e.name << L"\n";
        }
        return 0;
    }

    DWORD pid = 0;
    if (opt.pid != 0) {
        pid = opt.pid;
        if (!ProcessExists(pid)) {
            std::wcout << L"Process not found (PID " << pid << L")." << std::endl;
            system("pause");
            return 1;
        }
    }
    else if (!opt.processName.empty()) {
        pid = ResolveNameToPid(opt.processName);
        if (pid == 0) {
            std::wcout << L"Process not found: " << opt.processName << std::endl;
            system("pause");
            return 1;
        }
    }
    else {
        pid = PromptForTarget();
        if (pid == 0) {
            std::wcout << L"No valid target selected." << std::endl;
            system("pause");
            return 1;
        }
        if (!ProcessExists(pid)) {
            std::wcout << L"Process not found (PID " << pid << L")." << std::endl;
            system("pause");
            return 1;
        }
    }
    std::wcout << L"Target process PID: " << pid << std::endl;

    // DLL path (explicit --dll or auto-located next to Injector.exe)
    std::wstring dllPath = opt.dllPath.empty() ? GetDefaultDllPath() : opt.dllPath;
    if (GetFileAttributes(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"DLL not found: " << dllPath << std::endl;
        system("pause");
        return 1;
    }
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
    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, NULL)) {
        std::wcout << L"WriteProcessMemory failed. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
        return 1;
    }

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
