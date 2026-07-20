# ClassroomBypass

> 一个用于绕过目标客户端焦点检测与截图限制的技术验证工具。

---

## 📖 项目简介

本项目通过 **DLL 注入** + **API 钩子（Hook）** 技术，在运行时修改 `TARGET_PROCESS`（第三方客户端）的行为，使其：

- **始终认为自己处于前台激活状态**（防止因切换窗口而暂停视频/弹出提示）
- **允许被正常截图/录屏**（解除 `SetWindowDisplayAffinity` 造成的截屏黑屏）

**用途**：仅供技术学习、兼容性测试或个人合法使用场景，**严禁用于破坏课堂秩序、绕过考试监控或侵犯版权**。

---

## ⚙️ 工作原理

1. **注入器 (`Injector.exe`)**  
   - 通过进程名 `TARGET_PROCESS` 找到目标进程。  
   - 在目标进程内存中分配空间，写入 `FocusCheat.dll` 的路径。  
   - 创建远程线程调用 `LoadLibraryW`，将 DLL 加载进目标进程。

2. **焦点欺骗 (`FocusCheat.dll`)**  
   - **消息钩子**：拦截 `WM_KILLFOCUS` / `WM_ACTIVATE` 等失焦消息，直接丢弃，让程序收不到失去焦点的通知。  
   - **API 钩子 (Detours)**：  
     - `GetForegroundWindow` → 永远返回目标窗口句柄，骗过程序的主动查询。  
     - `SetWindowDisplayAffinity` → 拦截防截屏设置，使其失效并返回“成功”，同时注入时强制清除已有保护属性。

---

## 🖥️ 系统要求

- Windows 10 / 11（x64 或 x86）
- Visual Studio 2022（或 2019） 并安装 **“使用 C++ 的桌面开发”** 工作负载
- Microsoft Detours 库（源码版，需手动编译）

---

## 🔧 编译步骤

### 1. 获取并编译 Detours

```bash
git clone https://github.com/microsoft/Detours.git
cd Detours/src
nmake -f Makefile
```

编译后会在上级目录生成 `lib.X86`（32 位）或 `lib.x64`（64 位）文件夹，以及 `include` 文件夹。

设置环境变量 `DETOURS_ROOT` 指向 Detours 根目录（即包含 `include` 和 `lib.X86` 的上级目录），例如：
```bash
set DETOURS_ROOT=C:\path\to\Detours
```
也可以在系统环境变量中永久设置。

> **注意**：本项目目标进程为 32 位，因此只需编译 **x86** 版本（使用 `Developer Command Prompt for VS` 默认即为 x86 环境）。

---

### 2. 打开解决方案

用 Visual Studio 打开 `ClassroomBypass.slnx`。

### 3. 配置项目属性（FocusCheat）

- **平台**：选择 **x86**（必须与目标进程一致）。
- **C/C++ → 附加包含目录**：添加 `Detours\include` 路径。
- **链接器 → 附加库目录**：添加 `Detours\lib.X86` 路径。
- **链接器 → 输入 → 附加依赖项**：追加 `detours.lib`（保留原有默认库）。
- **C/C++ → 预编译头**：选择 **“不使用预编译头”**（对 `FocusCheat.cpp` 和 `dllmain.cpp` 都做此设置）。

### 4. 生成解决方案

按 `Ctrl+Shift+B` 编译，成功后会在 `x86\Debug`（或 `Release`）下生成：
- `FocusCheat.dll`
- `Injector.exe`

---

## 🚀 使用方法

1. 将 `FocusCheat.dll` 和 `Injector.exe` **放在同一个文件夹**中。
2. 启动 `TARGET_PROCESS` 并进入课堂界面。
3. **右键** `Injector.exe` → **“以管理员身份运行”**。
4. 控制台输出 `DLL injected successfully!` 即表示成功。
5. 切换到其他窗口，观察目标是否仍然激活；使用截图工具是否不再黑屏。

> **提示**：如果您的目标进程名不是 `TARGET_PROCESS`，请修改 `Injector.cpp` 中 `targetProc` 的值（目前为 `L"TARGET_PROCESS"`）并重新编译。

---

## ⚠️ 注意事项

- **杀毒软件拦截**：由于 DLL 注入技术常被恶意软件利用，Windows Defender 等会报毒。请按以下方式解决：
  - **推荐**：添加文件夹到排除项（`设置 → 安全中心 → 病毒和威胁防护 → 管理设置 → 排除项`）。
  - 或临时禁用实时保护（完成后务必重新开启）。
- **平台匹配**：必须使用 **x86** 编译版本，因为 `TARGET_PROCESS` 为 32 位进程。
- **多进程问题**：若有多个 `TARGET_PROCESS` 进程，注入器只会找到第一个匹配的。若需精确控制，可改用窗口类名 `EXAMPLE_WINDOW_CLASS` 查找，但这不在本版本中实现。
- **系统兼容性**：本工具仅在 Windows 10/11 上测试，其他版本未经验证。

---

## 🛠️ 常见问题

### Q: 注入失败，提示 `Process not found: TARGET_PROCESS`
- 确认目标进程名是否正确（任务管理器查看）。如果名称不同，修改 `Injector.cpp` 中 `targetProc` 的值并重新编译。

### Q: 注入成功但截图依然黑屏
- 可能程序使用了更底层的防截屏机制（如 DirectX 层拦截）。本方案已覆盖最常见的 `SetWindowDisplayAffinity`，若无效可尝试其他工具。

### Q: 注入后系统卡顿或程序崩溃
- 请确保 Detours 版本与编译器匹配，且项目配置正确。尝试清理解决方案并重新生成。

---

## 📜 许可证

本项目仅用于**教育和研究目的**，不提供任何明示或暗示的担保。使用者应自行承担一切风险，并确保遵守当地法律法规及相关软件的用户协议。

**严禁将此技术用于任何非法、违规或侵犯他人权益的行为。**

---

## 🙏 致谢

- [Microsoft Detours](https://github.com/microsoft/Detours) – 提供强大的 API 钩子支持。

---
