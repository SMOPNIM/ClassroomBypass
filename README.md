# ClassroomBypass

> Win32 前台状态与截屏限制行为研究工具（仅用于你拥有或已获授权测试的自有程序）。

---

## 📖 项目简介

本项目通过 **DLL 注入** + **API 钩子（Hook）** 技术，在运行时研究目标进程的前台状态查询与窗口截屏限制行为：

- **前台状态研究**（`GetForegroundWindow` / 失焦消息）
- **截屏限制研究**（`SetWindowDisplayAffinity`）

**用途**：仅供技术学习、兼容性测试，且**仅限你拥有或已获得明确授权的软件**。**严禁用于绕过课堂监控、考试监控、或任何未授权软件的行为干预**。

---

## ⚙️ 工作原理

1. **注入器 (`Injector.exe`)**
   - 通过命令行参数或交互式选择确定目标（PID 或进程名，不内置任何默认目标）。
   - 在目标进程内存中分配空间，写入 `FocusCheat.dll` 的路径。
   - 创建远程线程调用 `LoadLibraryW`，将 DLL 加载进目标进程。

2. **焦点欺骗 (`FocusCheat.dll`)**
   - **消息钩子**：拦截本进程窗口的 `WM_KILLFOCUS` / `WM_ACTIVATE` 等失焦消息，直接丢弃。
   - **API 钩子 (Detours)**：
     - `GetForegroundWindow` → 返回本进程主窗口句柄。
     - `SetWindowDisplayAffinity` → 对本进程窗口返回“成功”但不实际施加限制，同时注入时清除已有保护属性。
   - **可选自定义钩子**：如需研究特定模块内部通知函数，可在 DLL 同目录放置 `FocusCheat.ini`（参考 `FocusCheat.example.ini`），填写你自有程序的模块名与特征字符串；缺省则跳过。

---

## 🖥️ 系统要求

- Windows 10 / 11（x64 或 x86）
- Visual Studio 2022（或 Build Tools），安装 **"使用 C++ 的桌面开发"** 工作负载
- Detours 已作为 git submodule 包含在项目中，无需额外下载或设置环境变量

---

## 🔧 编译步骤

### 1. 克隆项目（含 submodule）

```bash
git clone --recurse-submodules https://github.com/SMOPNIM/ClassroomBypass.git
cd ClassroomBypass
```

若已克隆但未拉取 submodule：

```bash
git submodule update --init
```

### 2. 编译 Detours（仅首次）

打开 **Developer Command Prompt for VS**（默认即为 x86 环境），执行：

```cmd
cd Detours\src
nmake /nologo
```

编译完成后会在 `Detours\lib.X86\` 生成 `detours.lib`，`Detours\include\` 生成头文件。

### 3. 编译项目

同一命令行中继续执行：

```cmd
cd ..
msbuild FocusCheat\FocusCheat.vcxproj /p:Configuration=Debug /p:Platform=Win32 /p:PlatformToolset=v143 /p:SolutionDir="%CD%\\" /nologo /verbosity:minimal
msbuild Injector\Injector.vcxproj /p:Configuration=Debug /p:Platform=Win32 /p:PlatformToolset=v143 /p:SolutionDir="%CD%\\" /nologo /verbosity:minimal
```

编译产物在 `Debug\` 目录下：`Injector.exe` 和 `FocusCheat.dll`。

> **注意**：
> - 必须选择 **x86** 平台（目标进程为 32 位）。
> - 若使用 VS 2022 完整版，`PlatformToolset` 改为 `v145`。
> - Release 编译将 `Debug` 替换为 `Release` 即可。

### 也可通过 Visual Studio 编译

用 VS 打开 `ClassroomBypass.slnx`，选择 **x86** 平台，按 `Ctrl+Shift+B` 生成。

---

## 🚀 使用方法

> 仅可用于你拥有或已获明确授权测试的程序。请遵守当地法律法规及相关软件的用户协议。

1. 将 `FocusCheat.dll` 和 `Injector.exe` **放在同一个文件夹**中。
2. 启动你的测试目标程序。
3. **右键** `Injector.exe` → **“以管理员身份运行”**。
4. 选择目标：直接运行时会打开交互式进程选择器（直接敲字过滤、方向键移动、回车确认、ESC/Ctrl+C 取消），或用参数直接指定：
   ```cmd
   Injector.exe --list
   Injector.exe --pid 1234 --yes
   Injector.exe --process <进程映像名>
   ```
   完整选项见 `Injector.exe --help`（`--color`、`--quiet`、`--yes`、`--page-size` 等）。
5. 控制台输出 `DLL injected successfully!` 即表示成功。
6. （可选）如需启用自定义钩子，将 `FocusCheat.example.ini` 复制为 `FocusCheat.ini` 并按注释填写你自有程序的值。

> **提示**：不要对未获授权的第三方软件使用本工具。

---

## ⚙️ FocusCheat.ini 配置（可选）

默认只启用通用钩子（前台欺骗、截屏、失焦消息）。如需额外拦截目标进程内某模块的内部通知函数，可通过配置文件启用自定义钩子。

### 1. 放置文件

将 `FocusCheat.example.ini` 复制为 `FocusCheat.ini`，与 `FocusCheat.dll` **放在同一文件夹**。文件不存在则跳过自定义钩子，不影响通用功能。

### 2. 填写内容

```ini
[CustomHooks]
Module=example_module.dll
Signature1=ExampleEventA
Signature2=ExampleEventB
```

| 字段 | 说明 |
|------|------|
| `Module` | 目标进程中已加载的模块文件名。为空则整个自定义钩子被跳过；若模块尚未加载也会跳过（不报错） |
| `Signature1` / `Signature2` | 该模块 `.rdata` 中的特征字符串（最多 2 个，建议使用纯 ASCII）。为空的项会被跳过 |

### 3. 工作原理

注入时 DLL 会在目标模块内存中搜索特征字符串，找到引用它的代码位置后回溯到函数起始（`push ebp; mov ebp, esp`），用 Detours 挂上空操作钩子，使该函数直接返回、不再向外发送通知。定位失败（字符串不存在、无引用、找不到函数边界）时静默跳过该项。

### 4. 如何找特征字符串

用 x64dbg / IDA 等工具在目标模块中搜索与待拦截行为相关的字符串（如事件名、日志关键字），通过交叉引用确认引用它的函数即为候选目标。填入前请确认该模块属于你拥有或已获明确授权测试的程序。

---

## ⚠️ 注意事项

- **杀毒软件拦截**：由于 DLL 注入技术常被恶意软件利用，Windows Defender 等会报毒。请按以下方式解决：
  - **推荐**：添加文件夹到排除项（`设置 → 安全中心 → 病毒和威胁防护 → 管理设置 → 排除项`）。
  - 或临时禁用实时保护（完成后务必重新开启）。
- **平台匹配**：注入器与 DLL 的位数必须与目标进程一致（本仓库默认 **x86** 32 位配置）。
- **多进程问题**：若有多个同名进程，注入器会列出并请你选择 PID。
- **系统兼容性**：本工具仅在 Windows 10/11 上测试，其他版本未经验证。
- **合规**：严禁用于绕过课堂/考试监控、侵犯版权或违反软件用户协议的场景。

---

## 🛠️ 常见问题

### Q: 注入失败，提示 `Process not found` / `No valid target selected`
- 用 `Injector.exe --list` 确认目标进程名/PID 是否正确（任务管理器查看）。

### Q: 注入成功但截图依然黑屏
- 可能程序使用了更底层的防截屏机制（如 DirectX 层拦截）。本方案已覆盖最常见的 `SetWindowDisplayAffinity`，若无效可尝试其他工具。

### Q: 注入后系统卡顿或程序崩溃
- 确保注入器/DLL 位数与目标进程一致，且 Detours submodule 已正确初始化（`git submodule update --init`）。尝试清理输出目录并重新编译。
- 如启用了 `FocusCheat.ini` 自定义钩子，先移除该文件再测试，确认是否为特征串定位问题。

---

## 📜 许可证

本项目仅用于**教育和研究目的**，且仅限你拥有或已获明确授权的软件，不提供任何明示或暗示的担保。使用者应自行承担一切风险，并确保遵守当地法律法规及相关软件的用户协议。

**严禁将此技术用于任何非法、违规、绕过课堂或考试监控、或侵犯他人权益的行为。**

---

## 🙏 致谢

- [Microsoft Detours](https://github.com/microsoft/Detours) – 提供强大的 API 钩子支持。

---
