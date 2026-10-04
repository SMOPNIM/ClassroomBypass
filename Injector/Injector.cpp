#include <windows.h>
#include <tlhelp32.h>
#include <conio.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cwctype>

// Generic DLL injector.
// No hardcoded target process: the target is chosen via command-line
// arguments or an interactive picker at runtime.

struct ProcessEntry {
    DWORD pid = 0;
    std::wstring name;
    std::wstring arch;     // L"x86", L"x64" or L"?" when undetermined
    std::wstring wndTitle; // main window title, may be empty
};

enum ColorMode {
    COLOR_AUTO = 0,
    COLOR_ALWAYS = 1,
    COLOR_NEVER = 2,
};

struct Options {
    DWORD pid = 0;
    std::wstring processName;
    std::wstring dllPath;
    std::wstring verifyTarget; // PID or image name for --verify mode (no injection)
    bool listOnly = false;
    bool quiet = false;
    bool assumeYes = false;
    int pageSize = 20;
    ColorMode colorMode = COLOR_AUTO;
};

// ============================================================
// Console UI helpers (colors auto-disabled when piped)
// ============================================================
namespace ui {

static HANDLE hOut = NULL;
static WORD savedAttr = 0;
static bool colorOn = false;
static bool quiet = false;

static bool IsConsoleHandle(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE) return false;
    DWORD mode = 0;
    return GetConsoleMode(h, &mode) != FALSE;
}

bool StdinIsConsole() { return IsConsoleHandle(GetStdHandle(STD_INPUT_HANDLE)); }
bool StdoutIsConsole() { return IsConsoleHandle(GetStdHandle(STD_OUTPUT_HANDLE)); }

void Init(const Options& opt) {
    quiet = opt.quiet;
    hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (opt.colorMode == COLOR_ALWAYS) {
        colorOn = true;
    }
    else if (opt.colorMode == COLOR_NEVER) {
        colorOn = false;
    }
    else {
        colorOn = StdoutIsConsole();
    }
    if (colorOn && hOut && hOut != INVALID_HANDLE_VALUE) {
        CONSOLE_SCREEN_BUFFER_INFO info;
        if (GetConsoleScreenBufferInfo(hOut, &info)) {
            savedAttr = info.wAttributes;
        }
        else {
            colorOn = false;
        }
    }
}

void SetColor(WORD attr) {
    if (colorOn) SetConsoleTextAttribute(hOut, attr);
}

void ResetColor() {
    if (colorOn) SetConsoleTextAttribute(hOut, savedAttr);
}

void Write(const std::wstring& s) { std::wcout << s; }
void WriteLine(const std::wstring& s) { std::wcout << s << std::endl; }

void Info(const std::wstring& s) { WriteLine(s); }

void Success(const std::wstring& s) {
    SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    WriteLine(s);
    ResetColor();
}

void Warn(const std::wstring& s) {
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    WriteLine(s);
    ResetColor();
}

void Error(const std::wstring& s) {
    SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    WriteLine(s);
    ResetColor();
}

void Dim(const std::wstring& s) {
    SetColor(FOREGROUND_INTENSITY);
    WriteLine(s);
    ResetColor();
}

void Banner() {
    if (quiet) return;
    SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    WriteLine(L"============================================================");
    WriteLine(L"  Injector - generic DLL injector");
    WriteLine(L"============================================================");
    ResetColor();
}

void Step(int index, int total, const std::wstring& label) {
    wchar_t buf[32];
    swprintf_s(buf, L"[%d/%d] ", index, total);
    Write(buf);
    WriteLine(label + L" ...");
}

void StepOk() {
    SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    WriteLine(L"        OK");
    ResetColor();
}

void StepFail(const std::wstring& reason) {
    SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    WriteLine(L"        FAILED: " + reason);
    ResetColor();
}

void HideCursor() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE) return;
    CONSOLE_CURSOR_INFO info;
    if (GetConsoleCursorInfo(h, &info)) {
        info.bVisible = FALSE;
        SetConsoleCursorInfo(h, &info);
    }
}

void ShowCursor() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE) return;
    CONSOLE_CURSOR_INFO info;
    if (GetConsoleCursorInfo(h, &info)) {
        info.bVisible = TRUE;
        SetConsoleCursorInfo(h, &info);
    }
}

} // namespace ui

static std::wstring WinErrorMessage(DWORD code) {
    wchar_t* buf = NULL;
    DWORD n = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                            FORMAT_MESSAGE_IGNORE_INSERTS,
                            NULL, code, 0, (LPWSTR)&buf, 0, NULL);
    std::wstring msg;
    if (n && buf) {
        msg.assign(buf, n);
        LocalFree(buf);
        // Trim trailing whitespace/newlines.
        while (!msg.empty() && std::iswspace(msg.back())) msg.pop_back();
    }
    if (msg.empty()) {
        wchar_t tmp[64];
        swprintf_s(tmp, L"error code %lu", (unsigned long)code);
        msg = tmp;
    }
    return msg;
}

static void PrintUsage() {
    std::wcout << L"Usage:\n"
               << L"  Injector.exe [--pid <PID> | --process <name>] [--dll <path>]\n"
               << L"  Injector.exe [--dll <path>] <PID | name>\n"
               << L"  Injector.exe --list\n"
               << L"  Injector.exe --verify <PID | name> [--dll <path>]\n"
               << L"\n"
               << L"Target selection:\n"
               << L"  --pid, -p <PID>        Target process ID\n"
               << L"  --process, -n <name>   Target process image name\n"
               << L"  --dll, -d <path>       DLL to inject (default: FocusCheat.dll next to this EXE)\n"
               << L"  --list, -l             List running processes and exit\n"
               << L"  --verify, -V <target>  Check whether the DLL is loaded in target(s)\n"
               << L"\n"
               << L"Interface:\n"
               << L"  --color=auto|always|never   Color output (default: auto = TTY only)\n"
               << L"  --quiet, -q            Suppress banner and hints\n"
               << L"  --yes, -y              Skip confirmation prompt\n"
               << L"  --page-size <N>        Rows per page in the picker (default: 20)\n"
               << L"  --help, -h             Show this help\n"
               << L"\n"
               << L"Interactive picker: type to filter (name or PID), Up/Down = move,\n"
               << L"  PgUp/PgDn = page, / = clear filter, Enter = confirm, Esc/Ctrl+C = cancel.\n"
               << L"\n"
               << L"Examples:\n"
               << L"  Injector.exe --list\n"
               << L"  Injector.exe --pid 1234 --yes\n"
               << L"  Injector.exe --process <image-name> --dll C:\\path\\to\\FocusCheat.dll\n";
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

static std::wstring ToLower(const std::wstring& s) {
    std::wstring out = s;
    for (wchar_t& c : out) c = std::towlower(c);
    return out;
}

// Approximate terminal cell width (CJK characters count as 2).
static int CellWidth(wchar_t c) {
    if (c < 0x1100) return 1;
    if (c <= 0x115F) return 2;
    if (c >= 0x2E80 && c <= 0xA4CF) return 2;
    if (c >= 0xAC00 && c <= 0xD7A3) return 2;
    if (c >= 0xF900 && c <= 0xFAFF) return 2;
    if (c >= 0xFE30 && c <= 0xFE4F) return 2;
    if (c >= 0xFF00 && c <= 0xFF60) return 2;
    if (c >= 0xFFE0 && c <= 0xFFE6) return 2;
    return 1;
}

static int DisplayWidth(const std::wstring& s) {
    int w = 0;
    for (wchar_t c : s) w += CellWidth(c);
    return w;
}

static std::wstring PadRight(const std::wstring& s, int width) {
    int w = DisplayWidth(s);
    if (w >= width) return s;
    return s + std::wstring((size_t)(width - w), L' ');
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

static BOOL CALLBACK EnumMainWindowProc(HWND hWnd, LPARAM lParam) {
    auto* titles = (std::map<DWORD, std::wstring>*)lParam;
    if (!IsWindowVisible(hWnd)) return TRUE;
    if (GetWindow(hWnd, GW_OWNER) != NULL) return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid == 0 || titles->find(pid) != titles->end()) return TRUE;
    wchar_t text[256];
    if (GetWindowText(hWnd, text, 256) > 0) {
        (*titles)[pid] = text;
    }
    return TRUE;
}

static bool QueryWow64(HANDLE hProcess, bool& wow64) {
    typedef BOOL(WINAPI * IsWow64ProcessFn)(HANDLE, PBOOL);
    static IsWow64ProcessFn fn = (IsWow64ProcessFn)GetProcAddress(
        GetModuleHandle(L"kernel32.dll"), "IsWow64Process");
    if (!fn) return false;
    BOOL b = FALSE;
    if (!fn(hProcess, &b)) return false;
    wow64 = (b != FALSE);
    return true;
}

static void FillProcessDetails(std::vector<ProcessEntry>& entries) {
    std::map<DWORD, std::wstring> titles;
    EnumWindows(EnumMainWindowProc, (LPARAM)&titles);
    for (auto& e : entries) {
        auto it = titles.find(e.pid);
        if (it != titles.end()) e.wndTitle = it->second;

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, e.pid);
        if (h) {
            bool wow = false;
            if (QueryWow64(h, wow)) {
                e.arch = wow ? L"x86" : L"x64";
            }
            CloseHandle(h);
        }
    }
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
            e.arch = L"?";
            out.push_back(e);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    std::sort(out.begin(), out.end(), [](const ProcessEntry& a, const ProcessEntry& b) {
        if (a.name != b.name) return a.name < b.name;
        return a.pid < b.pid;
    });
    FillProcessDetails(out);
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

static std::wstring ProcessNameByPid(const std::vector<ProcessEntry>& all, DWORD pid) {
    for (const auto& e : all) {
        if (e.pid == pid) return e.name;
    }
    return L"";
}

// The injector is 32-bit, so the target must be 32-bit as well.
// Returns true when compatible (or undeterminable); false with a reason otherwise.
static bool CheckTargetBitness(DWORD pid, std::wstring& reason) {
    bool selfWow = false, targetWow = false;
    if (!QueryWow64(GetCurrentProcess(), selfWow)) return true;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return true; // let the later OpenProcess report the real error
    bool ok = QueryWow64(h, targetWow);
    CloseHandle(h);
    if (!ok) return true;
    if (selfWow != targetWow) {
        // This injector is always built 32-bit, so a mismatch means a 64-bit target.
        reason = L"Bitness mismatch: this injector is 32-bit but the target process is 64-bit. "
                 L"Pick the 32-bit instance (see the Arch column).";
        return false;
    }
    return true;
}

static std::wstring DllFileName(const std::wstring& dllPath) {
    size_t pos = dllPath.find_last_of(L"\\/");
    std::wstring base = (pos == std::wstring::npos) ? dllPath : dllPath.substr(pos + 1);
    if (base.empty()) base = L"FocusCheat.dll";
    return base;
}

// Checks whether a module file name is loaded in the target process.
static bool ModulePresentInProcess(DWORD pid, const std::wstring& moduleFile) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32First(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleFile.c_str()) == 0) {
                found = true;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

// Set while the picker runs; lets Ctrl+C cancel instead of killing.
// (Ctrl+Break keeps its default terminate behavior.)
static volatile BOOL g_pickerCancel = FALSE;

static BOOL WINAPI PickerCtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT) {
        g_pickerCancel = TRUE;
        return TRUE;
    }
    return FALSE;
}

// ============================================================
// Interactive TUI picker
// ============================================================
namespace picker {

// Frame rendering uses absolute buffer coordinates (see Run below),
// so it self-heals even if a line wraps or the console resizes.

// A picker frame: one text + color per line. Blitted to the console in a
// single WriteConsoleOutputW call, so partial frames can never appear.
struct FrameLine {
    std::wstring text;
    WORD attr;
};

static std::vector<FrameLine> BuildFrame(const std::vector<ProcessEntry>& rows,
                                         const std::vector<size_t>& view,
                                         size_t selected, size_t page, size_t pageSize,
                                         const std::wstring& filter, WORD defAttr) {
    const WORD cyan = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    const WORD yellow = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    const WORD dim = FOREGROUND_INTENSITY;

    std::vector<FrameLine> lines;
    auto emit = [&](const std::wstring& s, WORD attr) {
        FrameLine ln;
        ln.text = s;
        ln.attr = attr;
        lines.push_back(ln);
    };

    size_t totalPages = (view.size() + pageSize - 1) / pageSize;
    if (totalPages == 0) totalPages = 1;
    if (page >= totalPages) page = totalPages - 1;

    wchar_t head[128];
    swprintf_s(head, L"Select target process  (page %llu/%llu, %llu match%s)",
               (unsigned long long)(page + 1), (unsigned long long)totalPages,
               (unsigned long long)view.size(), view.size() == 1 ? L"" : L"es");
    emit(head, cyan);

    if (!filter.empty()) {
        emit(L"Filter: " + filter, defAttr);
    }

    emit(L"  #     PID       Arch  Image Name              Window Title", defAttr);
    emit(L"  --    --------  ----  ------------------------  ------------------------------", defAttr);

    const size_t nameWidth = 24;
    const size_t titleWidth = 30;
    auto truncateCell = [](const std::wstring& src, size_t width) {
        if (DisplayWidth(src) <= (int)width) return src;
        std::wstring cut;
        int w = 0;
        for (wchar_t c : src) {
            int cw = CellWidth(c);
            if (w + cw > (int)width - 1) break;
            cut += c;
            w += cw;
        }
        return cut + L"…";
    };
    for (size_t i = page * pageSize; i < view.size() && i < (page + 1) * pageSize; ++i) {
        const ProcessEntry& e = rows[view[i]];
        wchar_t row[160];
        swprintf_s(row, L"%c %-4llu  %-8lu  %-4s  ", (i == selected ? L'>' : L' '),
                   (unsigned long long)(i + 1), (unsigned long)e.pid,
                   e.arch.c_str());
        std::wstring line(row);
        line += PadRight(truncateCell(e.name, nameWidth), (int)nameWidth);
        line += L"  ";
        line += PadRight(truncateCell(e.wndTitle, titleWidth), (int)titleWidth);
        emit(line, (i == selected) ? yellow : defAttr);
    }

    emit(L"Type=filter Up/Down=move PgUp/PgDn=page Enter=OK Esc=cancel", dim);
    return lines;
}

// Writes the frame at absolute buffer position (0, topRow) in one call,
// padding with blank lines up to prevRows so shrunken views leave nothing.
// Returns rows now occupied, or -1 when the console API is unusable.
static int BlitFrame(const std::vector<FrameLine>& in, HANDLE hCon, WORD defAttr,
                     SHORT topRow, int prevRows) {
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (topRow < 0 || !GetConsoleScreenBufferInfo(hCon, &info)) return -1;
    int width = (int)info.dwSize.X;
    int bufH = (int)info.dwSize.Y;
    if (width <= 0 || width > 4096 || bufH <= 0) return -1;

    int frameH = (int)in.size();
    int totalH = frameH > prevRows ? frameH : prevRows;
    if (topRow + totalH > bufH) totalH = bufH - (int)topRow;
    if (totalH <= 0) return -1;

    std::vector<CHAR_INFO> cells((size_t)width * (size_t)totalH);
    for (size_t k = 0; k < cells.size(); ++k) {
        cells[k].Char.UnicodeChar = L' ';
        cells[k].Attributes = defAttr;
    }
    for (int r = 0; r < frameH && r < totalH; ++r) {
        int col = 0;
        for (wchar_t c : in[r].text) {
            int cw = CellWidth(c);
            if (col + cw > width) break;
            size_t idx = (size_t)r * (size_t)width + (size_t)col;
            cells[idx].Char.UnicodeChar = c;
            cells[idx].Attributes = in[r].attr;
            if (cw == 2 && col + 1 < width) {
                cells[idx + 1].Attributes = in[r].attr;
            }
            col += cw;
        }
    }

    COORD bufSize;
    bufSize.X = (SHORT)width;
    bufSize.Y = (SHORT)totalH;
    COORD bufPos;
    bufPos.X = 0;
    bufPos.Y = 0;
    SMALL_RECT dst;
    dst.Left = 0;
    dst.Top = topRow;
    dst.Right = (SHORT)(width - 1);
    dst.Bottom = (SHORT)((int)topRow + totalH - 1);
    if (!WriteConsoleOutputW(hCon, cells.data(), bufSize, bufPos, &dst)) return -1;
    return totalH;
}

// Filter rows by case-insensitive name substring or PID substring.
static std::vector<size_t> ApplyFilter(const std::vector<ProcessEntry>& rows,
                                       const std::wstring& filter) {
    std::vector<size_t> view;
    std::wstring f = ToLower(filter);
    for (size_t i = 0; i < rows.size(); ++i) {
        if (f.empty()) {
            view.push_back(i);
            continue;
        }
        if (ToLower(rows[i].name).find(f) != std::wstring::npos) {
            view.push_back(i);
            continue;
        }
        wchar_t pidBuf[32];
        swprintf_s(pidBuf, L"%lu", (unsigned long)rows[i].pid);
        if (std::wstring(pidBuf).find(f) != std::wstring::npos) {
            view.push_back(i);
        }
    }
    return view;
}

// Line-based fallback when stdin is not a console (piped input).
static DWORD FallbackPick(const std::vector<ProcessEntry>& rows) {
    for (size_t i = 0; i < rows.size(); ++i) {
        wchar_t buf[128];
        swprintf_s(buf, L"  %llu  %lu  %s\n", (unsigned long long)(i + 1),
                   (unsigned long)rows[i].pid, rows[i].name.c_str());
        std::wcout << buf;
    }
    std::wcout << L"Enter row number, PID or image name (empty to cancel): ";
    std::wstring input;
    std::getline(std::wcin, input);
    input = Trim(input);
    if (input.empty()) return 0;
    if (IsAllDigits(input)) {
        unsigned long n = std::wcstoul(input.c_str(), nullptr, 10);
        if (n >= 1 && n <= rows.size()) return rows[n - 1].pid;
        if (ProcessExists((DWORD)n)) return (DWORD)n;
        return 0;
    }
    std::vector<DWORD> pids = FindPidsByName(input);
    if (pids.size() == 1) return pids[0];
    return 0;
}

// Returns selected PID, or 0 on cancel/failure.
DWORD Run(const std::vector<ProcessEntry>& rows, const std::wstring& initialFilter,
          int pageSize) {
    if (rows.empty()) return 0;
    if (pageSize <= 0) pageSize = 20;

    if (!ui::StdinIsConsole() || !ui::StdoutIsConsole()) {
        return FallbackPick(rows);
    }

    std::wstring filter = initialFilter;
    std::vector<size_t> view = ApplyFilter(rows, filter);
    size_t selected = 0;
    DWORD finalPid = 0;
    bool needRender = false;
    bool paintPending = false;

    // Hide the blinking cursor for the whole picker session; it is
    // restored on every exit path by the guard's destructor.
    struct CursorGuard {
        CursorGuard() { ui::HideCursor(); }
        ~CursorGuard() { ui::ShowCursor(); }
    } cursorGuard;

    // Swallow Ctrl+C during the picker so it cancels instead of killing.
    // (Ctrl+Break keeps its default terminate behavior.)
    struct CtrlGuard {
        CtrlGuard() {
            g_pickerCancel = FALSE;
            SetConsoleCtrlHandler(PickerCtrlHandler, TRUE);
        }
        ~CtrlGuard() { SetConsoleCtrlHandler(PickerCtrlHandler, FALSE); }
    } ctrlGuard;

    // Drop stale queued input (pastes, held keys) so the session starts clean.
    while (_kbhit()) _getch();

    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD defAttr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    SHORT topRow = -1;
    {
        CONSOLE_SCREEN_BUFFER_INFO abi;
        if (GetConsoleScreenBufferInfo(hCon, &abi)) {
            defAttr = abi.wAttributes;
            topRow = abi.dwCursorPosition.Y;
        }
    }
    int prevRows = 0;

    // Park the cursor below the frame and report the outcome. Runs on every
    // exit path via the destructor.
    struct ExitEcho {
        HANDLE hCon;
        SHORT& topRow;
        int& prevRows;
        const std::vector<ProcessEntry>& rows;
        DWORD& finalPid;
        ~ExitEcho() {
            CONSOLE_SCREEN_BUFFER_INFO ebi;
            if (GetConsoleScreenBufferInfo(hCon, &ebi)) {
                int endY = (topRow >= 0 ? (int)topRow + prevRows : (int)ebi.dwCursorPosition.Y);
                if (endY >= (int)ebi.dwSize.Y) endY = (int)ebi.dwSize.Y - 1;
                if (endY < 0) endY = 0;
                COORD p;
                p.X = 0;
                p.Y = (SHORT)endY;
                SetConsoleCursorPosition(hCon, p);
            }
            if (finalPid != 0) {
                wchar_t buf[160];
                swprintf_s(buf, L"Selected: %lu  %s", (unsigned long)finalPid,
                           ProcessNameByPid(rows, finalPid).c_str());
                ui::Success(buf);
            }
            else {
                ui::Warn(L"Cancelled.");
            }
        }
    } exitEcho{GetStdHandle(STD_OUTPUT_HANDLE), topRow, prevRows, rows, finalPid};

    // Paint one atomic frame; falls back to scrolling print if the console
    // API is unusable (and re-anchors afterwards).
    auto paintOnce = [&]() {
        size_t totalPages = (view.size() + (size_t)pageSize - 1) / (size_t)pageSize;
        if (totalPages == 0) totalPages = 1;
        if (selected >= view.size()) selected = view.empty() ? 0 : view.size() - 1;
        size_t page = view.empty() ? 0 : selected / (size_t)pageSize;
        if (page >= totalPages) page = totalPages - 1;
        std::vector<FrameLine> frame =
            BuildFrame(rows, view, selected, page, (size_t)pageSize, filter, defAttr);
        int used = BlitFrame(frame, hCon, defAttr, topRow, prevRows);
        if (used < 0) {
            for (const auto& ln : frame) {
                ui::SetColor(ln.attr);
                std::wcout << ln.text << L"\n";
                ui::ResetColor();
            }
            CONSOLE_SCREEN_BUFFER_INFO rbi;
            if (GetConsoleScreenBufferInfo(hCon, &rbi)) topRow = rbi.dwCursorPosition.Y;
            else topRow = -1;
            prevRows = 0;
        }
        else {
            prevRows = used;
        }
    };

    paintOnce();
    ULONGLONG lastPaint = GetTickCount64();
    for (;;) {
        if (g_pickerCancel) { finalPid = 0; break; } // Ctrl+C requested cancel
        if (needRender || paintPending) {
            // Coalesce bursts: while input is queued and we painted recently,
            // skip this frame; it will be painted once the queue drains.
            if (paintPending || (_kbhit() && GetTickCount64() - lastPaint < 50)) {
                paintPending = true;
                needRender = false;
            }
            else {
                paintOnce();
                lastPaint = GetTickCount64();
                needRender = false;
                paintPending = false;
            }
        }

        int ch = _getch();
        if (ch == 3) { // Ctrl+C delivered as a key: cancel
            finalPid = 0;
            break;
        }
        if (ch == 27) { // Esc: clear search first, cancel second
            if (!filter.empty()) {
                filter.clear();
                view = ApplyFilter(rows, filter);
                selected = 0;
                needRender = true;
                continue;
            }
            finalPid = 0;
            break;
        }
        if (ch == 13) { // Enter: confirm highlight (noop on empty view)
            if (!view.empty()) {
                finalPid = rows[view[selected]].pid;
                break;
            }
            continue;
        }
        if (ch == 0 || ch == 224) { // extended key
            int code = _getch();
            size_t old = selected;
            if (code == 72) { // Up
                if (selected > 0) --selected;
            }
            else if (code == 80) { // Down
                if (selected + 1 < view.size()) ++selected;
            }
            else if (code == 73 || code == 75) { // PgUp / Left
                selected = (selected >= (size_t)pageSize) ? selected - (size_t)pageSize : 0;
            }
            else if (code == 81 || code == 77) { // PgDn / Right
                selected = selected + (size_t)pageSize < view.size()
                               ? selected + (size_t)pageSize
                               : (view.empty() ? 0 : view.size() - 1);
            }
            else if (code == 71) { // Home
                selected = 0;
            }
            else if (code == 79) { // End
                selected = view.empty() ? 0 : view.size() - 1;
            }
            if (selected != old) needRender = true;
            continue;
        }
        if (ch == 8) { // Backspace: shrink search
            if (!filter.empty()) {
                filter.pop_back();
                view = ApplyFilter(rows, filter);
                selected = 0;
                needRender = true;
            }
            continue;
        }
        if (ch == '/') { // Clear search
            if (!filter.empty()) {
                filter.clear();
                view = ApplyFilter(rows, filter);
                selected = 0;
                needRender = true;
            }
            continue;
        }
        if (ch >= 32 && ch <= 126) { // Printable ASCII: live filter
            filter += (wchar_t)ch;
            view = ApplyFilter(rows, filter);
            selected = 0;
            needRender = true;
            continue;
        }
        // Ignore other keys (no redraw).
    }
    return finalPid;
}

} // namespace picker

// Resolve a process image name to a PID (interactive narrowing on multiples).
static DWORD ResolveNameToPid(const std::wstring& name, const Options& opt) {
    std::vector<DWORD> pids = FindPidsByName(name);
    if (pids.empty()) return 0;
    if (pids.size() == 1) return pids[0];

    if (!ui::StdinIsConsole()) {
        ui::Error(L"Multiple processes named \"" + name + L"\" found; re-run with --pid:");
        for (DWORD pid : pids) {
            wchar_t buf[64];
            swprintf_s(buf, L"  PID %lu", (unsigned long)pid);
            ui::WriteLine(buf);
        }
        return 0;
    }
    std::vector<ProcessEntry> all = ListAllProcesses();
    std::vector<ProcessEntry> cands;
    for (DWORD pid : pids) {
        ProcessEntry e;
        e.pid = pid;
        e.name = ProcessNameByPid(all, pid);
        if (e.name.empty()) e.name = name;
        cands.push_back(e);
    }
    ui::Info(L"Multiple matches; pick one:");
    return picker::Run(cands, L"", opt.pageSize);
}

// Interactive fallback: pick from the full process list.
static DWORD PromptForTarget(const Options& opt) {
    std::vector<ProcessEntry> procs = ListAllProcesses();
    if (procs.empty()) {
        ui::Error(L"Unable to enumerate processes.");
        return 0;
    }
    return picker::Run(procs, L"", opt.pageSize);
}

static bool ParseColorValue(const std::wstring& v, Options& opt) {
    std::wstring lower = ToLower(Trim(v));
    if (lower == L"auto") {
        opt.colorMode = COLOR_AUTO;
        return true;
    }
    if (lower == L"always") {
        opt.colorMode = COLOR_ALWAYS;
        return true;
    }
    if (lower == L"never") {
        opt.colorMode = COLOR_NEVER;
        return true;
    }
    return false;
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
        else if (a == L"--verify" || a == L"-V") {
            if (i + 1 >= argc) {
                std::wcout << L"Option " << a << L" requires a value." << std::endl;
                return false;
            }
            opt.verifyTarget = Trim(argv[++i]);
        }
        else if (a == L"--quiet" || a == L"-q") {
            opt.quiet = true;
        }
        else if (a == L"--yes" || a == L"-y") {
            opt.assumeYes = true;
        }
        else if (a == L"--pid" || a == L"-p") {
            if (i + 1 >= argc) {
                std::wcout << L"Option " << a << L" requires a value." << std::endl;
                return false;
            }
            std::wstring v = Trim(argv[++i]);
            if (!IsAllDigits(v)) {
                std::wcout << L"Invalid PID value: " << v << std::endl;
                return false;
            }
            opt.pid = static_cast<DWORD>(std::wcstoul(v.c_str(), nullptr, 10));
        }
        else if (a == L"--process" || a == L"-n") {
            if (i + 1 >= argc) {
                std::wcout << L"Option " << a << L" requires a value." << std::endl;
                return false;
            }
            opt.processName = Trim(argv[++i]);
        }
        else if (a == L"--dll" || a == L"-d") {
            if (i + 1 >= argc) {
                std::wcout << L"Option " << a << L" requires a value." << std::endl;
                return false;
            }
            opt.dllPath = Trim(argv[++i]);
        }
        else if (a == L"--page-size") {
            if (i + 1 >= argc) {
                std::wcout << L"Option " << a << L" requires a value." << std::endl;
                return false;
            }
            std::wstring v = Trim(argv[++i]);
            if (!IsAllDigits(v) || v == L"0") {
                std::wcout << L"Invalid page size: " << v << std::endl;
                return false;
            }
            opt.pageSize = (int)std::wcstoul(v.c_str(), nullptr, 10);
        }
        else if (a.rfind(L"--color", 0) == 0) {
            std::wstring v;
            if (a.length() > 7 && a[7] == L'=') {
                v = a.substr(8);
            }
            else if (a == L"--color") {
                if (i + 1 >= argc) {
                    std::wcout << L"Option --color requires a value." << std::endl;
                    return false;
                }
                v = argv[++i];
            }
            else {
                std::wcout << L"Unknown argument: " << a << std::endl;
                PrintUsage();
                return false;
            }
            if (!ParseColorValue(v, opt)) {
                std::wcout << L"Invalid color mode (auto|always|never): " << v << std::endl;
                return false;
            }
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

// Press-any-key pause, interactive consoles only.
static void WaitForExitKey(const Options& opt) {
    if (opt.assumeYes) return;
    if (!ui::StdinIsConsole()) return;
    ui::Dim(L"Press any key to exit...");
    _getch();
}

static int Fail(const Options& opt, const std::wstring& msg) {
    ui::Error(msg);
    WaitForExitKey(opt);
    return 1;
}

int wmain(int argc, wchar_t** argv) {
    Options opt;
    if (!ParseArgs(argc, argv, opt)) {
        WaitForExitKey(opt);
        return 1;
    }
    ui::Init(opt);

    if (opt.listOnly) {
        std::vector<ProcessEntry> procs = ListAllProcesses();
        for (const auto& e : procs) {
            std::wcout << e.pid << L"  " << e.name << L"\n";
        }
        return 0;
    }

    if (!opt.verifyTarget.empty()) {
        std::wstring dllPath = opt.dllPath.empty() ? GetDefaultDllPath() : opt.dllPath;
        std::wstring dllFile = DllFileName(dllPath);
        std::vector<DWORD> targets;
        if (IsAllDigits(opt.verifyTarget)) {
            targets.push_back(static_cast<DWORD>(std::wcstoul(opt.verifyTarget.c_str(), nullptr, 10)));
        }
        else {
            targets = FindPidsByName(opt.verifyTarget);
            if (targets.empty()) {
                ui::Error(L"Process not found: " + opt.verifyTarget);
                return 1;
            }
        }
        bool anyFound = false;
        for (DWORD vpid : targets) {
            wchar_t buf[192];
            if (ModulePresentInProcess(vpid, dllFile)) {
                swprintf_s(buf, L"PID %lu: %s is loaded.", (unsigned long)vpid, dllFile.c_str());
                ui::Success(buf);
                anyFound = true;
            }
            else {
                swprintf_s(buf, L"PID %lu: %s is NOT loaded.", (unsigned long)vpid, dllFile.c_str());
                ui::Warn(buf);
            }
        }
        return anyFound ? 0 : 1;
    }

    bool interactive = ui::StdinIsConsole() && ui::StdoutIsConsole();
    if (interactive) ui::Banner();

    DWORD pid = 0;
    std::wstring targetDesc;
    if (opt.pid != 0) {
        pid = opt.pid;
        if (!ProcessExists(pid)) {
            return Fail(opt, L"Process not found (PID " + std::to_wstring(pid) + L").");
        }
        targetDesc = L"PID " + std::to_wstring(pid);
    }
    else if (!opt.processName.empty()) {
        pid = ResolveNameToPid(opt.processName, opt);
        if (pid == 0) {
            return Fail(opt, L"Process not found: " + opt.processName);
        }
        targetDesc = opt.processName + L" (PID " + std::to_wstring(pid) + L")";
    }
    else {
        if (!interactive) {
            return Fail(opt, L"No target given. Use --pid, --process, or run in a console for the picker.");
        }
        pid = PromptForTarget(opt);
        if (pid == 0) {
            return Fail(opt, L"No valid target selected.");
        }
        if (!ProcessExists(pid)) {
            return Fail(opt, L"Process not found (PID " + std::to_wstring(pid) + L").");
        }
        std::vector<ProcessEntry> all = ListAllProcesses();
        targetDesc = ProcessNameByPid(all, pid) + L" (PID " + std::to_wstring(pid) + L")";
    }
    ui::Success(L"Target: " + targetDesc);

    // The injector is 32-bit: refuse clearly instead of failing silently.
    {
        std::wstring bitReason;
        if (!CheckTargetBitness(pid, bitReason)) {
            return Fail(opt, bitReason);
        }
    }

    // DLL path (explicit --dll or auto-located next to Injector.exe)
    std::wstring dllPath = opt.dllPath.empty() ? GetDefaultDllPath() : opt.dllPath;
    if (GetFileAttributes(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return Fail(opt, L"DLL not found: " + dllPath);
    }
    ui::Info(L"DLL: " + dllPath);

    // Confirmation (interactive only, unless --yes).
    if (interactive && !opt.assumeYes) {
        ui::Write(L"Proceed with injection? [Y/n] ");
        std::wstring answer;
        std::getline(std::wcin, answer);
        answer = ToLower(Trim(answer));
        if (!answer.empty() && answer != L"y" && answer != L"yes") {
            ui::Warn(L"Cancelled.");
            return 1;
        }
    }

    // Open the target process
    ui::Step(1, 4, L"Open process");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        DWORD err = GetLastError();
        ui::StepFail(L"cannot open process (" + WinErrorMessage(err) +
                     L"). Try running as administrator.");
        WaitForExitKey(opt);
        return 1;
    }
    ui::StepOk();

    // Allocate memory in the target process and write the DLL path
    ui::Step(2, 4, L"Allocate remote memory");
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMem) {
        DWORD err = GetLastError();
        ui::StepFail(WinErrorMessage(err));
        CloseHandle(hProcess);
        WaitForExitKey(opt);
        return 1;
    }
    ui::StepOk();

    ui::Step(3, 4, L"Write DLL path");
    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, NULL)) {
        DWORD err = GetLastError();
        ui::StepFail(WinErrorMessage(err));
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        WaitForExitKey(opt);
        return 1;
    }
    ui::StepOk();

    // Create a remote thread to load the DLL (LoadLibraryW)
    ui::Step(4, 4, L"Create remote thread (LoadLibraryW)");
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, NULL);

    if (!hThread) {
        DWORD err = GetLastError();
        ui::StepFail(WinErrorMessage(err));
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        WaitForExitKey(opt);
        return 1;
    }
    ui::StepOk();

    WaitForSingleObject(hThread, INFINITE);
    DWORD threadExit = 0;
    GetExitCodeThread(hThread, &threadExit);
    CloseHandle(hThread);

    // Cleanup
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);

    // Verify truthfully: the thread exit code is the HMODULE returned by
    // LoadLibraryW, and the module must show up in the target's module list.
    std::wstring dllFile = DllFileName(dllPath);
    if (threadExit == 0) {
        CloseHandle(hProcess);
        return Fail(opt, L"LoadLibraryW returned NULL in the target process. "
                         L"The DLL failed to load (often a 32/64-bit mismatch or a missing dependency).");
    }
    if (!ModulePresentInProcess(pid, dllFile)) {
        CloseHandle(hProcess);
        return Fail(opt, L"Remote thread finished but " + dllFile +
                         L" was not found in the target's modules. Injection did not take effect.");
    }
    CloseHandle(hProcess);

    ui::Success(L"DLL injected successfully and verified in target modules!");
    WaitForExitKey(opt);
    return 0;
}
