# EagleEye

本地反外挂**只读**查询工具（Windows x64 CLI）。扫描本机进程、文件、数字签名，按外置 JSON 规则匹配，输出带证据链和风险等级的 JSON 报告。

- 不注入、不 Hook、不读目标进程内存、不加载驱动、不改系统配置
- 输出的不是"作弊判定"，而是"检测到某特征 + 证据 + 置信度"，风险分三级：`信息` / `可疑` / `高度可疑`

---

## 1. 环境要求

| 项目 | 要求 |
|---|---|
| 系统 | Windows 10 / 11 x64 |
| 运行时 | .NET 8（框架依赖模式）；或直接用 self-contained 发布包 |
| 构建 | .NET 8 SDK |

本机已安装用户级 SDK：`E:\dotnet8\dotnet.exe`（8.0.427）。

## 2. 构建

```powershell
# 常规构建
cd E:\查挂小程序\src\EagleEye
E:\dotnet8\dotnet.exe build -c Release

# 单文件发布（依赖框架，体积小，目标机需装 .NET 8 运行时）
E:\dotnet8\dotnet.exe publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o E:\查挂小程序\out\publish

# 单文件发布（自带运行时，目标机无需装 .NET）
E:\dotnet8\dotnet.exe publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o E:\查挂小程序\out\publish-standalone
```

产物：`bin\Release\net8.0-windows\EagleEye.exe`（`rules\` 目录会一起复制到输出目录）。

## 3. 运行

```powershell
# 校验规则文件（不扫描）
EagleEye.exe validate --rules rules\rules.json

# 进程 + 文件全量扫描，报告写到默认位置 out\reports\scan-<时间>.json
EagleEye.exe scan

# 只扫进程（快）
EagleEye.exe scan --no-files

# 指定规则与输出，附加扫描目录，只看高危
EagleEye.exe scan --rules rules\rules.json --out D:\r.json --file-root D:\tools --min-level suspicious

# 报告里附带全部进程清单（便于排查"为什么没命中"）
EagleEye.exe scan --all-processes --out D:\r.json
```

| 参数 | 说明 |
|---|---|
| `--rules <路径>` | 规则文件，默认 exe 目录下 `rules\rules.json` |
| `--out <路径>` | JSON 报告路径，默认 `out\reports\scan-<时间>.json` |
| `--no-files` | 跳过文件扫描 |
| `--no-dma` | 跳过 DMA 外设用户态枚举 |
| `--no-device-list` | 报告不附全部 PCI 设备清单（默认附） |
| `--file-root <目录>` | 追加文件扫描目录，可重复 |
| `--all-processes` | 报告附全部进程明细（默认不附，控制体积） |
| `--check-revocation` | 验签时检查证书吊销（需联网，较慢） |
| `--timeout <秒>` | 整体超时，默认 180 |
| `--min-level info\|suspicious\|high` | 控制台只显示 ≥ 该等级的命中 |
| `--quiet` | 只输出一行摘要 |

**退出码**：`0` 未发现可疑 / `2` 存在可疑 / `3` 存在高度可疑 / `1` 错误。便于接 CI 或批处理。

## 4. 规则文件

JSON 顶层两段：`rules` + `whitelist`（另有 `meta`、`options`）。

```json
{
  "meta": { "name": "默认规则集", "version": "1.0.0" },
  "options": {
    "scanRoots": ["%TEMP%", "%USERPROFILE%\\Downloads"],
    "includeExtensions": [".exe", ".dll", ".sys"],
    "maxFiles": 20000, "maxDepth": 5,
    "maxFileSizeBytes": 268435456, "maxHashFiles": 3000
  },
  "rules": [
    {
      "id": "proc.cheatengine",
      "type": "process_name",
      "pattern": "cheatengine*",
      "severity": 4,
      "confidence": 0.9,
      "description": "Cheat Engine 主程序在运行（内存扫描/调试工具）",
      "advice": "单独存在不构成作弊，需结合其他证据人工复核",
      "match": "glob",
      "enabled": true
    }
  ],
  "whitelist": {
    "processes": [{ "pattern": "explorer.exe", "match": "exact", "reason": "Windows 外壳" }],
    "paths":     [{ "pattern": "C:\\Windows\\System32\\*", "reason": "系统目录" }],
    "files":     [{ "pattern": "*.tmp", "reason": "临时文件" }],
    "signers":   [{ "subjectContains": "Microsoft Corporation", "reason": "微软签名" }]
  }
}
```

### 4.1 规则字段

| 字段 | 必填 | 说明 |
|---|---|---|
| `id` | ✅ | 唯一标识，重复会报错 |
| `type` | ✅ | 见下表 |
| `pattern` | ✅（`file_hash` 除外） | 匹配模式 |
| `severity` | ✅ | 1–5：1 提示 / 2 低 / 3 中 / 4 高 / 5 确定 |
| `confidence` | ✅ | 0–1，与该信号的可靠度相乘，避免"名字像就判死" |
| `description` | ✅ | 报告里显示的一句话说明 |
| `match` | 否 | `glob`（默认）/ `exact` / `contains` / `regex`，均忽略大小写 |
| `hash` | `file_hash` 必填 | 64 位 SHA256（小写十六进制） |
| `size` | 否 | `file_hash` 预筛：只有大小匹配才计算哈希，省 IO |
| `advice` | 否 | 给复核人的建议，写入报告 |
| `enabled` | 否 | 默认 `true`，写 `false` 可灰度下线单条规则 |

### 4.2 规则类型

| type | 作用对象 | 说明 |
|---|---|---|
| `process_name` | 进程名 | 例：`cheatengine*` |
| `process_path` | 进程映像路径 | 例：`*\\AppData\\Local\\Temp\\*` |
| `process_command_line` | 命令行 | 例：`--inject`（`match: contains`） |
| `module_name` | 进程已加载模块名 | 例：`aimbot*.dll`，命中后证据里列出全部命中模块 |
| `file_name` | 扫描到的文件名 | 例：`*speedhack*` |
| `file_hash` | 文件 SHA256 | 与 `hash` 字段比对 |
| `signature` | Authenticode 状态 | `pattern` 取 `unsigned` / `bad_digest` / `untrusted_root` / `expired` / `revoked` / `catalog_only` / `any_invalid` |

## 5. 如何新增白名单

白名单的目的是"确认无害后降噪"，命中白名单**不会删除命中项**，只是把该条分值衰减到 20% 并标记 `whitelisted: true` + 原因，保证可追溯。

### 5.1 按进程名/路径放行

```json
"whitelist": {
  "processes": [
    { "pattern": "OBS*.exe", "match": "glob", "reason": "直播软件，覆盖层合法" }
  ],
  "paths": [
    { "pattern": "D:\\Games\\AntiCheatPro\\\\*", "reason": "自家反作弊目录" }
  ]
}
```

- `pattern` 里含 `\` 或 `/` 时按**映像路径**匹配，否则按**进程名**匹配
- 可选 `"hash": "<sha256>"`：要求文件哈希也一致才放行（防止同名伪造，推荐用于高风险放行）
- 可选 `"expires": "2027-01-01"`：到期自动失效，过期条目启动时会打印告警

### 5.2 按签名主体放行

```json
"signers": [
  { "subjectContains": "Microsoft Corporation", "reason": "微软签名" }
]
```

只对**验签通过**的文件生效（`subjectContains` 与证书 Subject 做包含匹配）。

### 5.3 按文件放行

```json
"files": [
  { "pattern": "*.tmp", "reason": "临时文件" },
  { "hash": "<sha256>", "reason": "已确认无害的已知文件" }
]
```

### 5.4 新增白名单的标准流程

1. 先跑一次，看报告里被误报的 `target` / `targetPath`
2. 确认无害（人工核对签名、来源、哈希）
3. 在白名单对应段加条目，**写清 `reason`**，高风险条目务必带 `hash` 和 `expires`
4. `EagleEye.exe validate --rules rules\rules.json` 校验通过后再上线

## 6. 评分与风险等级

```
单条得分 = severity × 20 × confidence            （1–100）
白名单命中 = 单条得分 × 0.2
目标累计 = 该进程/该文件所有命中之和，封顶 100
整体风险 = 各目标累计分中的最高者
```

| 分值 | 等级 | 含义 |
|---|---|---|
| 0–39 | 信息 | 低置信提示，多半是签名/路径类弱信号 |
| 40–69 | 可疑 | 需要人工看一眼 |
| 70–100 | 高度可疑 | 多条强证据叠加，优先复核 |

按目标聚合而不是全局累加，避免"一堆 18 分的弱提示"被累加成高危。

## 7. 报告结构

```jsonc
{
  "tool": "EagleEye", "version": "1.0.0",
  "scanStartedUtc": "...", "durationSeconds": 2.43,
  "machine": "...", "osVersion": "...", "isElevated": false,
  "ruleset": { "name": "...", "version": "...", "ruleCount": 18, "whitelistCount": 11, "warnings": [] },
  "summary": {
    "processesScanned": 293, "filesScanned": 773, "filesHashed": 0,
    "findings": 4, "totalScore": 18.0, "sumScore": 72.0,
    "riskLevel": "信息", "byRiskLevel": { "信息": 4, "可疑": 0, "高度可疑": 0 },
    "notCheckedCount": 191
  },
  "findings": [
    {
      "ruleId": "sig.unsigned", "ruleType": "signature",
      "target": "xxx.exe", "targetPath": "C:\\...\\xxx.exe", "pid": 1234,
      "severity": 2, "confidence": 0.45, "score": 18.0, "riskLevel": "信息",
      "description": "...", "advice": "...",
      "evidence": { "matchedField": "authenticode", "matchedValue": "unsigned", "winTrustStatus": "0x800B0100", "catalogSigned": false },
      "whitelisted": false
    }
  ],
  "notChecked": [
    { "target": "svchost.exe", "pid": 984, "reason": "受保护进程或权限不足：仅完成名称级检查..." }
  ],
  "processes": null
}
```

`notChecked` 是关键字段：**没查到 ≠ 干净**，受保护进程、权限不足、目录不可读都会记在这里。

## 8. 安全边界（代码层面可审计）

只使用以下 API：

- 进程枚举：`CreateToolhelp32Snapshot` + `Process32First/Next`、`Module32First/Next`
- 进程信息：`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`、`QueryFullProcessImageName`、`NtQueryInformationProcess(ProcessCommandLineInformation)`
- 签名：`WinVerifyTrust`、`CryptCATAdmin*`（目录签名）
- 文件：`FileStream` 只读 + `SHA256`

代码中**不存在**：`WriteProcessMemory`、`VirtualAllocEx`、`CreateRemoteThread`、`SetWindowsHookEx`、`ReadProcessMemory`、任何驱动加载/服务创建/注册表写入。

自检命令：

```powershell
Select-String -Path .\*.cs,.\**\*.cs -Pattern "WriteProcessMemory|CreateRemoteThread|SetWindowsHookEx|ReadProcessMemory|VirtualAllocEx|NtWriteVirtualMemory" -SimpleMatch:$false
# 期望：无输出
```

## 9. 已知限制

1. **受保护进程**（PPL / 反作弊进程）：`OpenProcess` 会被拒绝，只能拿到名称；报告 `notChecked` 里注明，绝不降级为强开。
2. **命令行**：走 `ProcessCommandLineInformation` 信息类查询，需要 `PROCESS_QUERY_LIMITED_INFORMATION`；仍拿不到就留空，不做内存读取兜底。
3. **目录签名**：只校验"存在 cat 签名"，不深入验证 cat 内容；如需严格校验可对 cat 路径单独跑 `WinVerifyTrust`。
4. **吊销检查**：默认关闭（离线快）；`--check-revocation` 打开后需联网，且可能明显变慢。
5. **文件扫描**：只覆盖 `options.scanRoots` + `--file-root`；达到 `maxFiles` 会截断并在 `notChecked` 说明。
6. 不是反作弊，不做实时监控；一次扫描是一份快照。

## 10. 目录

```
src\EagleEye\
├─ EagleEye.csproj
├─ Program.cs              CLI 入口、参数、汇总输出
├─ Models\                 Rule / RuleSet / Finding / ProcessRecord / ScanReport
├─ Native\                 Win32 + NT 互操作、Authenticode 验签
├─ Core\                   PatternMatcher / Hashing / Scoring
├─ Rules\                  规则加载与 JSON 校验
├─ Scanning\               ProcessScanner / FileScanner
├─ Reporting\              JSON 报告输出
└─ rules\rules.json        默认规则库
```
---

# 附：DMA 外设用户态初筛（阶段 2 新增）

## A. 做了什么 / 没做什么

| | 内容 |
|---|---|
| ✅ 做 | SetupAPI + CfgMgr32 只读枚举当前存在的设备；筛出 `PCI\` 实例；解析 VID/PID/SUBSYS/REV；读取设备名、设备类、驱动服务名、位置、厂商、问题码；与 DMA 规则比对并输出证据 |
| ❌ 不做 | 不加载驱动、不打开设备写句柄、不改设备状态、不访问 IOMMU 寄存器、不读写 PCIe 配置空间 |
| ⚠️ 关键限制 | **用户态读不到 PCIe 配置空间**：Capability 链表、BAR 大小、MSI/MSI-X、真实 Class Code、Subsystem 都拿不到；`classCode` 只是由"设备类名"近似推导的**猜测值**。因此 DMA 段结果 **不能作为 DMA 检测的唯一依据** |

代码里这段结论写死在两处：`Scanning\DmaScanner.cs` 的类注释、`DmaReport.Note` 字段（每次报告都会带上）。

## B. 输出字段

报告里新增两段：

```jsonc
"dmaUserModeFindings": [
  {
    "ruleId": "dma.xilinx.pid7024",
    "target": "PCI 设备 7024",
    "instanceId": "PCI\\VEN_10EE&DEV_7024&SUBSYS_00000000&REV_01\\4&1b2c3d&0&00E0",
    "vendorId": "10EE", "deviceId": "7024", "revision": "01", "classCodeGuess": "06",
    "severity": 5, "confidence": 0.75, "score": 75.0, "riskLevel": "高度可疑",
    "description": "Xilinx 7024 设备 ID，常见于市售 DMA 板卡",
    "advice": "与设备类、驱动服务名、位置信息一起看，勿单独定性",
    "whitelisted": false,
    "userModeOnly": true,
    "evidence": {
      "instanceId": "...", "hardwareIds": "...", "deviceClass": "System",
      "classCodeSource": "setupapi-derived-guess",
      "service": "xdma", "location": "PCI 总线 1、设备 0、功能 0",
      "manufacturer": "Xilinx", "problemCode": 0, "configSpaceAvailable": false
    }
  }
],
"dma": {
  "enabled": true, "userModeOnly": true,
  "note": "用户态枚举无法读取 PCIe 配置空间……本段结果仅为线索，不能作为 DMA 检测的唯一依据",
  "devicesEnumerated": 218, "pciDevices": 38,
  "findings": 1, "riskLevel": "高度可疑", "topScore": 75.0,
  "devices": [
    { "name": "AMD Radeon(TM) Graphics", "instanceId": "PCI\\VEN_1002&DEV_1681...",
      "vendorId": "1002", "deviceId": "1681", "subsystemId": "..." , "revision": "C7",
      "deviceClass": "Display", "classCodeGuess": "03", "service": "amdwddmg",
      "location": "PCI 总线 6、设备 0、功能 0", "manufacturer": "Advanced Micro Devices, Inc.",
      "problemCode": 0 }
  ]
}
```

`summary` 里同步新增：`dmaDevicesEnumerated`、`dmaPciDevices`、`dmaFindings`、`dmaRiskLevel`。

## C. 规则字段（新增 `dma` 段）

```json
"dma": {
  "enabled": true,
  "includeDeviceList": true,
  "rules": [
    {
      "id": "dma.xilinx.vendor",
      "vid": "10EE",                 // 必填之一：4 位十六进制，可带 0x
      "vendor": "Xilinx",            // 可选，仅用于报告可读性
      "severity": 4,                 // 1-5
      "confidence": 0.55,            // 0-1，用户态建议 ≤0.8
      "description": "Xilinx FPGA 厂商设备，是常见 DMA 采集卡的载板芯片",
      "advice": "单靠 VID 不足以定性……"
    },
    {
      "id": "dma.xilinx.pid7024",
      "vid": "10EE",
      "pid": "7024",                 // 可选，不填=该厂商全部设备
      "severity": 5,
      "confidence": 0.75,
      "description": "Xilinx 7024 设备 ID，常见于市售 DMA 板卡"
    },
    {
      "id": "dma.xilinx.rev01",
      "vid": "10EE", "pid": "7024", "revision": "01",   // 可选，精确匹配 REV
      "severity": 4, "confidence": 0.6,
      "description": "指定修订号的板卡批次"
    },
    {
      "id": "dma.class.system",
      "classCode": "06",             // 可选，近似 PCI 基础类（见下表），慎用
      "severity": 1, "confidence": 0.15, "enabled": false,
      "description": "按近似 Class Code 匹配（06=桥/系统类），默认关闭"
    }
  ],
  "whitelist": [
    { "vid": "8086", "reason": "Intel 芯片组 / 核显 / 网卡" },
    { "vid": "10DE", "pid": "2520", "reason": "已知型号显卡", "expires": "2027-01-01" }
  ]
}
```

**匹配语义**：一条规则里出现的字段（`vid` / `pid` / `revision` / `classCode`）必须**全部**与设备一致才命中；没写的字段不参与比较。校验器会拦下：severity 越界、confidence 越界、重复 id、vid/pid 非 4 位十六进制；并在 `severity>=4 && confidence>0.8` 时告警（用户态证据不该给这么高的置信度）。

**设备类 → 近似 Class Code（启发式，不是配置空间真实值）**

| 设备类 | 近似基础类 | 设备类 | 近似基础类 |
|---|---|---|---|
| Display / HIDClass | 03 | HDC / SCSIAdapter / DiskDrive | 01 |
| Net | 02 | Mouse / Keyboard | 09 |
| Media | 04 | Ports / Modem | 07 |
| System | 06 | USB / SmartCardReader | 0C |
| Memory | 05 | Bluetooth | 0D |
| Processor | 0B | SecurityDevices | 10 |
| 其它 | FF | | |

## D. 测试方法

### D1. 对照设备管理器做正确性验证

```powershell
# 枚举数量与名称对照
EagleEye.exe scan --no-files --out D:\dma.json
# 打开 设备管理器 → 查看 → 按连接排序，显卡/网卡/USB 控制器逐项核对 VID:PID 与位置
```

看 `dma.pciDevices` 是否与设备管理器里"PCI 总线上的设备数"接近（差几个通常是隐藏/未启动设备）。

### D2. 用本机真实设备造规则，验证命中链路

```json
{ "id": "dma.test.vga", "vid": "1002", "pid": "1681", "revision": "C7",
  "severity": 5, "confidence": 0.8, "description": "测试：VID/PID/REV 三段匹配" }
```

期望：`dmaUserModeFindings` 出现 1 条，score = 5×20×0.8 = 80 → `高度可疑`，退出码 3。
（这条规则就是本项目实测用的用例，见 `samples\verify\rules.dma.verify.json`）

### D3. 白名单衰减验证

把 `"whitelist": [{ "vid": "1002", "pid": "1681", "reason": "确认是显卡" }]` 加进去，重跑：

```
dma.test.vga | score=16 | 信息 | wl=true | 确认是显卡
```

分数变成原来的 20%，等级降为 `信息`，退出码回到 0 —— 与进程/文件白名单行为一致（衰减而不是删除，保证可审计）。

### D4. 负向测试（防误报回归）

把规则 `vid` 改成 `FFFF` 这种不存在的值，或把 `classCode` 改成 `FF`：

```powershell
EagleEye.exe scan --rules rules\invalid-vid.json --no-files --quiet
# 期望：dma=0(信息)，退出码 0
```

### D5. 想伪造一张 DMA 卡来测？

需要真板卡，或在虚拟机里挂一个 PCI 直通设备。**注意**：虚拟机里厂商 ID 往往被改写，测试价值有限；真实判定只能上物理机。别指望用软件"假装"出 Xilinx 设备，SetupAPI 读的是总线枚举结果。

### D6. classCode 规则的正确用法

只在"某厂商 + 某近似类"两条一起用时才给中等权重，例如：

```json
{ "id": "dma.fpga.system", "vid": "10EE", "classCode": "06", "severity": 3, "confidence": 0.5 }
```

单靠 `classCode` 会命中一大堆桥片/USB 控制器（本机实测就命中了显卡和网卡），必须配白名单。

## E. 接口清单（可审计）

只用到这些只读接口：`SetupDiGetClassDevsW`、`SetupDiEnumDeviceInfo`、`SetupDiDestroyDeviceInfoList`、`CM_Get_Device_IDW`、`CM_Get_DevNode_Registry_PropertyW`、`CM_Get_DevNode_Status`。

不存在的调用：`CreateFile(\\.\PCI...)`、`DeviceIoControl`、`SetupDiSetDeviceRegistryProperty`、`SetupDiSetClassInstallParams`、`CM_Reenumerate_DevNode`、任何 IOMMU/PCI 配置空间访问。
---

# 附：一次性只读 PCIe 配置空间驱动（阶段 3）

## A. 这是什么 / 风险在哪

一个 **DEMAND_START 的 WDM 驱动**，只在扫描期间存在：`CreateService → StartService → IOCTL → Stop → DeleteService`，读完立刻卸载。

**加载前必读**（详见 `docs\15_内核驱动风险说明.md`）：

1. 这是本工具**风险最高**的部分，默认关闭，不加 `--kernel` 完全不碰驱动。
2. **不要在 Vanguard / EAC / BattlEye / ACE / GameGuard 活跃期间加载**。推荐姿势：**先扫描、后启动游戏**。
3. 未签名驱动在 Secure Boot + HVCI 下无法加载（`StartService` 返回 577）；正式使用需 EV 签名 + Microsoft attestation。
4. 只在授权诊断机上使用，保留加载/卸载审计日志。

## B. 能力范围

| 输出项 | 是否可靠 | 说明 |
|---|---|---|
| VendorId / DeviceId / Revision | ✅ 真值 | 配置空间 0x00–0x0B |
| Class Code（Base/Sub/ProgIf） | ✅ 真值 | 0x09–0x0B，替代用户态的"近似猜测" |
| Subsystem Vendor / Device ID | ✅ 真值 | 0x2C–0x2F |
| Capability 链表 | ✅ 真值 | 从 0x34 起逐级遍历，最多 48 项 |
| MSI / MSI-X 存在性 + MSI Control | ✅ 真值 | Capability ID 0x05 / 0x11 |
| BAR 原始值 + 类型（IO/MEM/64bit/预取） | ✅ 真值 | 0x10–0x27 |
| **BAR 大小** | ❌ 不提供 | 确定大小必须写 `0xFFFFFFFF` 回读，**本驱动禁止写配置空间**，因此 `barSizeDeterminable` 恒为 `false` |

## C. 驱动与用户态的契约

```
设备名   \Device\PcieCfg      符号链接 \DosDevices\PcieCfg
IOCTL    IOCTL_PCIECFG_PING        0x80002001  返回协议版本 ULONG
         IOCTL_PCIECFG_READ_CONFIG 0x80002005  输入 PcieCfgRequest，输出 PcieCfgResult
权限     只允许 Token 已提权的调用方（SeQueryInformationToken），否则 STATUS_ACCESS_DENIED
```

请求结构（528 字节）：

```c
typedef struct _PCIECFG_REQUEST {
    WCHAR PdoPath[260];   // 如 \Device\NTPNP_PCI0007，由用户态 DEVPKEY_Device_PDOName 取得
    ULONG Offset;         // 只允许 0
    ULONG Length;         // 只允许 4..256，且 4 字节对齐
} PCIECFG_REQUEST;
```

响应结构（384 字节，全 4 字节对齐，与 C# `PcieCfgResult` 一一对应）：

```c
typedef struct _PCIECFG_RESULT {
    ULONG Status;            // NTSTATUS 原值
    ULONG Ids;               // VendorId | DeviceId<<16
    ULONG Subsystem;         // SubVendorId | SubsystemId<<16
    ULONG ClassInfo;         // Base<<24 | Sub<<16 | ProgIf<<8 | Revision
    ULONG HeaderType;
    ULONG Bar[6];
    ULONG BarFlags[6];       // bit0 IO / bit1 64bit / bit2 prefetch / bit3 非零
    ULONG CapCount;
    UCHAR CapIds[48];
    UCHAR HasMsi, HasMsix, CapabilityListOffset, Reserved0;
    ULONG MsiControl;
    UCHAR Raw[256];          // 原始配置空间，证据留痕
} PCIECFG_RESULT;
```

## D. 用法

```powershell
# 1) 先编译驱动（需要 WDK，见 native\pciecfg\build.md）
# 2) 把 PcieCfg.sys 放到 exe 同目录，或显式指定
EagleEye.exe scan --no-files --kernel --driver-path E:\path\PcieCfg.sys --out D:\r.json
```

报告新增：

```jsonc
"dma": {
  "kernel": {
    "attempted": true, "loaded": true, "unloaded": true,
    "driverPath": "...\\PcieCfg.sys", "error": null,
    "devicesAttempted": 38, "devicesRead": 37,
    "errors": ["PCI 设备 xxx: 驱动返回 0xC0000001"],
    "note": "驱动只在扫描期间存在……不要在 Vanguard / EAC / BattlEye 活跃期间加载"
  }
}
```

命中的 `dmaUserModeFindings[]` 里会多两个字段：

- `userModeOnly: false` —— 表示这条证据已经过真实配置空间校验
- `evidence.configSpace.{vendorId,classCode,capabilityIds,hasMsi,bars,barKinds,raw64Bytes}` —— 硬件真值

## E. 规则里怎么用配置空间条件

```json
{
  "id": "dma.fpga.no_msi",
  "vid": "10EE",
  "severity": 3,
  "confidence": 0.6,
  "conditions": ["msi_missing"],
  "description": "Xilinx FPGA 设备没有 MSI 能力"
}
```

支持的条件：`msi_missing`、`msix_missing`、`no_capability_list`、`bar0_zero`、`class_ff`、`revision_zero`。

**注意**：带 `conditions` 的规则在没启用 `--kernel` 时**不会触发**（没有配置空间数据就不做猜测），这正是"不拿近似值当证据"的体现。

## F. 卸载保证

```csharp
try {
    host.EnsureLoaded(driver, out err);
    device = host.OpenDevice(out err);
    foreach (var d in devices) PcieCfgIoctl.TryReadConfig(device, d.PdoName, out raw, out err);
} finally {
    device?.Dispose();
    host.TryUnload(out err);   // ControlService(STOP) + DeleteService
}
```

- 启动前先清理同名残留服务
- `finally` 里强制 stop + delete
- 卸载后 `sc query PcieCfg` 应为 1060（服务不存在）

## G. 实测（无 WDK 环境下的失败路径）

本机没有 WDK，驱动未编译，因此只验证了用户态的失败处理：

```
内核配置空间: 加载失败：驱动文件不存在: ...\PcieCfg.sys，读取 0/0 个设备
内核配置空间: 加载失败：OpenSCManager 失败（Win32=5 拒绝访问。），读取 0/0 个设备
sc query PcieCfg → FAILED 1060（未创建任何服务）
```

即：**驱动缺失 / 权限不足都不会影响其余扫描，也不会留下服务残留**。
---

# 附：规则引擎与报告（阶段 4）

## A. 规则文件的元信息与分类

```json
"meta": {
  "name": "EagleEye 默认规则集",
  "version": "1.3.0",          // 规则内容版本
  "updated": "2026-11-10",     // 规则内容更新时间
  "schemaVersion": "2.0",      // 格式版本
  "categories": [
    { "id": "tool.cheat",     "name": "作弊工具", "weight": 1.2 },
    { "id": "tool.injector",  "name": "注入器",   "weight": 1.3 },
    { "id": "path.anomaly",   "name": "路径异常", "weight": 0.8 }
  ]
}
```

每条规则通过 `category` 归属分类，分类的 `weight` 会乘进单条得分：

```
单条得分 = severity × 20 × confidence × categoryWeight
```

报告里会按分类统计，HTML 报告的证据条目也会带上分类标签。

## B. 白名单抑制（不是"降权"，是"抑制 + 留痕"）

```json
"whitelist": {
  "processes": [
    {
      "pattern": "ArmouryCrate.exe",
      "match": "exact",
      "reason": "已知外设厂商软件",
      "suppressRules": ["sig.unsigned"],   // 可选：只压制指定规则
      "expires": "2027-01-01"              // 可选：到期自动失效
    }
  ]
}
```

语义：

| 配置 | 行为 |
|---|---|
| `suppressRules` 省略或空数组 | 抑制该目标上**全部**规则命中 |
| `suppressRules: ["sig.unsigned"]` | 只抑制这一条，其他规则照常命中、照常计分 |

被抑制的命中：

- **不参与风险聚合**，不影响等级与得分；
- 仍完整写入报告 `suppressedFindings[]`，带 `suppressed: true`、`suppressReason`、`suppressedBy`、原始 `score`；
- HTML 报告里单独一节「白名单抑制记录」，方便定期复核白名单是否被滥用。

## C. 风险聚合规则（强/中/弱 + 组合升级）

信号分级：`severity 4-5` = 强，`3` = 中，`1-2` = 弱。

```
1) 同一目标（PID / 文件 / 设备）累加得分，封顶 100
2) 强信号直判：任一条 severity>=4 且单条 score>=70 → 高度可疑
3) 组合升级（分数还不够，但信号够多）：
     弱信号 >= 3                → 可疑
     弱 >= 2 且 中 >= 1         → 可疑
     中 >= 2                    → 可疑
4) 最终等级 = max(分值等级, 组合升级等级)
```

证据链按目标输出，包含每条规则的 id / 分类 / severity / confidence / 得分 / 原始证据，以及"等级是怎么升上去的"。

## D. 报告输出

```powershell
EagleEye.exe scan                                  # 默认同时出 JSON + HTML
EagleEye.exe scan --format json --out D:\r.json
EagleEye.exe scan --format html --html D:\r.html
EagleEye.exe scan --log D:\audit.jsonl
```

HTML 特点：

- 单文件、内联 CSS、**零外部引用**（无 CDN、无脚本、无字体文件），断网双击可看
- 章节：主机信息 → KPI 卡片 → 风险评定与证据链（可展开）→ 白名单抑制记录 → 未检查项 → DMA 设备 → 审计
- 等级色标：高度可疑红 / 可疑橙 / 信息灰

## E. 审计日志（本地 JSONL）

每行一个事件，UTF-8：

```jsonl
{"ts":"...","event":"scan.start","data":{"rulesVersion":"1.3.0","options":{...},"note":"本工具不发起任何网络请求，不上传任何数据"}}
{"ts":"...","event":"process.open","data":{"pid":28800,"name":"msedge.exe","accessMask":"0x1000","accessMeaning":"PROCESS_QUERY_LIMITED_INFORMATION（只读查询）","result":"granted","win32Error":0,"imagePath":"C:\\...\\msedge.exe"}}
{"ts":"...","event":"process.open","data":{"pid":7272,"name":"svchost.exe","accessMask":"0x1000","result":"denied","win32Error":5}}
{"ts":"...","event":"signature.verify","data":{"path":"...","state":"unsigned"}}
{"ts":"...","event":"driver.load","data":{"service":"PcieCfg","result":"failed","detail":"..."}}
{"ts":"...","event":"scan.end","data":{"riskLevel":"可疑","score":54,"activeFindings":86,"suppressed":1,"outputs":[...]}}
{"ts":"...","event":"audit.closed","data":{"processOpenAttempts":295,"processOpenDenied":166,"signatureChecks":129,"driverLoadAttempts":0}}
```

要点：

- **每个进程**都记一条：目标 PID、名字、申请的访问掩码、成功/被拒、Win32 错误码；
- 访问掩码恒为 `0x1000`（`PROCESS_QUERY_LIMITED_INFORMATION`），**从不申请** `PROCESS_VM_READ/WRITE`；
- 驱动加载/卸载各记一条，失败也记；
- 报告里的 `audit` 段是这份日志的摘要。

## F. 无网络

代码中没有任何 HTTP / socket / 上传逻辑；`audit.networkUsed` 恒为 `false`。
报告页脚与审计日志都会写明"本工具不发起任何网络请求，不上传任何数据"。

## G. 实测

```
规则集   : EagleEye 默认规则集 v1.3.0（更新 2026-11-10，schema 2.0）
规则数量 : 通用 18（启用 17），DMA 5，分类 8，白名单 17 条
命中/抑制 : 4 条活跃 / 0 条被白名单抑制
目标分布  : 信息 4  可疑 0  高度可疑 0
审计      : 进程打开 296 次（拒绝 168），权限仅 0x1000，验签 128 次，驱动的未加载，网络访问：无
```

组合升级实测（3 条弱信号，累计仅 36 分）：

```
[可疑]   36.0  WidgetService.exe (PID 22600)
           ↑ 组合升级：3 个弱信号叠加（规则：弱信号≥3 视为可疑）
```

定向抑制实测（`suppressRules: ["test.sig.unsigned"]`）：

```
suppressed: test.sig.unsigned@ArmouryCrate.exe
ArmouryCrate 仍活跃的证据: test.strong.module, test.path.windowsapps
```
---

# 附：合规红线（可执行自检）

红线不写在文档里靠自觉，而是由脚本逐条校验：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\audit-policy.ps1
# 退出码 0 = 全部通过；1 = 存在违规
```

当前 13 项全部 PASS：

| 检查项 | 结果 |
|---|---|
| C# 无注入/内存读写/Hook 实现（21 个文件） | PASS |
| C# 无反反作弊/绕过/提权/关 HVCI 关键词 | PASS |
| 驱动无写配置空间/内存读写/回调/文件操作 | PASS |
| 驱动只发 `IRP_MN_READ_CONFIG` | PASS |
| 驱动服务 `StartType=3`（按需启动，不自启） | PASS |
| `CreateService` 仅存在于 Kernel 装载模块 | PASS |
| 规则均有 description（可解释） | PASS |
| 规则均有 category（可分类） | PASS |
| 规则集有版本号与更新时间 | PASS |
| 白名单段存在 | PASS |
| 支持定向抑制 `suppressRules` | PASS |
| 报告命中均带 ruleId + evidence | PASS |
| 报告含审计段且 `networkUsed=false` | PASS |

脚本会**先剥离 C/C# 注释再匹配关键词**，避免"注释里写了绝不使用 XXX"造成误报；也会校验最新报告里每条命中是否都带证据。

## 被禁止且本工具从未实现的行为

进程注入、`ReadProcessMemory`/`WriteProcessMemory`、`VirtualAllocEx`、`CreateRemoteThread`、
`SetWindowsHookEx`、驱动隐藏、`ObRegisterCallbacks`、反反作弊、绕过 EAC/BattlEye/Vanguard/ACE、
伪造签名、提权（`SeDebugPrivilege`/`AdjustTokenPrivileges`）、关闭 HVCI/VBS、修改游戏文件。

## 若需求触碰红线，只用只读替代

| 需求 | 不做 | 只读替代 |
|---|---|---|
| 判断某 DLL 是否被注入进游戏 | 读游戏内存、扫内存特征 | 枚举已加载模块名 + 签名 + 路径（受保护进程跳过并注明"未检查"） |
| 判断是否有人读写游戏 | Hook / 句柄拦截 | 枚举全系统句柄持有者，看谁以 `PROCESS_VM_READ` 打开游戏（只读枚举，不拦截） |
| 判断 DMA 板卡 | 写配置空间、映射 BAR | `IRP_MN_READ_CONFIG` 读 256 字节 + 用户态资源报告近似 BAR 大小 |
| 判断驱动是否恶意 | 内核回调拦载/隐藏检测 | 枚举已加载驱动 + Authenticode + 哈希黑名单 |
---

# 附：AI 视觉外挂线索（阶段 5）

## A. 这个模块能做什么、不能做什么

| 层 | 数据来源 | 能证明 |
|---|---|---|
| `capture` | 可见窗口（`EnumWindows`）+ 已加载模块（Toolhelp） | 某进程**同时**拥有可见窗口并加载了采集/推理模块 |
| `hardware` | 复用 SetupAPI 设备枚举 | 本机存在采集卡 / HID 开发板 / 输入映射驱动 |
| `behavior` | `GetCursorPos` 轮询 | 输入事件的宏观统计（信息级） |

**不能证明**：双机链路、外接采集卡、KMBox 转发、模型内容、是否在对局中生效。
报告固定声明：*双机+外部采集+硬件注入链路在本机用户态无法独立确证*。

判定上限：单层 → 信息；≥2 层 → 可疑；**永远不超过「可疑」**，`maxLevel` 写高了规则校验会直接报错。

## B. 行为提示为什么**不用**低级钩子

需求允许「风险可控时使用 WH_MOUSE_LL」，但本实现明确**不采用**，理由：

1. `SetWindowsHookEx(WH_MOUSE_LL)` 是系统级全局钩子，属于本项目红线（不 Hook 任何 API），`tools\audit-policy.ps1` 会直接判 FAIL；
2. 全局钩子对反作弊高度可见，且在游戏运行期安装有被判定为可疑行为的风险；
3. Raw Input 的 `RIDEV_INPUTSINK` 需要后台收包，等价于全局输入捕获，同样踩线；
4. Windows 没有暴露"鼠标移动平滑度"这类性能计数器。

因此改为 `GetCursorPos` 定时轮询（默认 16ms / 3s）：

- 无钩子、无注册、无消息循环，对目标进程零侵入
- 采样点只存在于本地 List，函数返回即释放，**不落盘、不记录坐标轨迹**
- 只输出聚合值：直线化比例、匀速比例、静止占比、平均速度、速度标准差
- `severity` 恒为 1，`confidence ≤ 0.15`，输出注明「信息级，不构成判定」

## C. 规则文件（`vision` 段）

```jsonc
"vision": {
  "enabled": true,

  "capture": {
    "enabled": true,
    "moduleRules": [
      { "id": "vision.capture.onnxruntime", "tier": "strong", "pattern": "onnxruntime*.dll",
        "match": "glob", "category": "inference_runtime",
        "severity": 2, "confidence": 0.35,
        "description": "进程拥有可见窗口且加载了 ONNX Runtime（AI 推理运行时）" },
      { "id": "vision.capture.graphics_hook", "tier": "strong", "pattern": "graphics-hook*.dll",
        "match": "glob", "category": "capture_hook", "severity": 3, "confidence": 0.5,
        "description": "进程加载了 OBS Game Capture 的注入模块（画面采集中）" },
      { "id": "vision.context.gdi32", "tier": "context", "pattern": "gdi32*.dll",
        "match": "glob", "category": "capture_context", "severity": 1, "confidence": 0.05,
        "description": "加载了 GDI（BitBlt 等画面捕获能力的载体）" }
    ]
  },

  "hardware": {
    "enabled": true,
    "rules": [
      { "id": "vision.hw.elgato", "category": "video_capture", "vendorId": "0FD9",
        "severity": 2, "confidence": 0.4, "description": "Elgato 视频采集设备" },
      { "id": "vision.hw.arduino_hid", "category": "hid_injector", "vendorId": "2341",
        "deviceClass": "HIDClass", "severity": 3, "confidence": 0.5,
        "description": "Arduino 类开发板以 HID 输入设备形式枚举" },
      { "id": "vision.hw.vigem", "category": "input_mapper", "service": "ViGEmBus",
        "severity": 3, "confidence": 0.5, "description": "ViGEm 虚拟手柄总线" }
    ]
  },

  "behavior": { "enabled": false, "durationMs": 3000, "sampleMs": 16, "minSamples": 50,
                "straightLineRatio": 0.85, "constantVelocityRatio": 0.8, "zeroDeltaRatio": 0.6 },

  "whitelist": [
    { "processPattern": "nvcontainer.exe", "match": "exact", "reason": "NVIDIA 容器进程" },
    { "vendorId": "046D", "reason": "罗技外设" }
  ],

  "aggregation": { "maxLevel": "可疑", "requireIndependentLayers": 2 }
}
```

**tier 语义**：
- `strong`：特异性高（推理运行时 / CV 库 / 采集 hook），单独出现即可成条；
- `context`：通用图形模块（gdi32/dxgi/d3d11），几乎所有 GUI 程序都加载，**只加权不单独成条**——否则一台机器会出几百条噪音。

## D. 报告字段

```jsonc
"visionCheatIndicators": {
  "enabled": true,
  "note": "双机+外部采集+硬件注入链路在本机用户态无法独立确证，以下为可观测线索，不代表最终判定。",
  "softwareCapture": [{
    "id": "vision.capture.onnxruntime", "layer": "capture", "category": "inference_runtime",
    "target": "xxx.exe", "pid": 1234, "path": "...", "signatureState": "valid",
    "commandLineSummary": "...", "matchedModules": ["onnxruntime.dll"],
    "severity": 2, "confidence": 0.45, "score": 18, "riskLevel": "可疑",
    "suppressed": false, "needsTelemetry": true,
    "evidence": { "visibleWindows": 2, "largestWindow": "1920x1080",
                  "memoryRead": false, "screenshotTaken": false }
  }],
  "hardwareIndicators": [{ "id": "vision.hw.elgato", "category": "video_capture",
                           "target": "...", "evidence": { "vendorId": "0FD9", ... } }],
  "behavioralHint": { "collected": true, "straightLineRatio": 0.42, "confidence": 0.08,
                      "note": "信息级提示：仅由 GetCursorPos 轮询得到…" },
  "layerSummary": { "capture": 1, "hardware": 0, "behavior": 0 },
  "independentLayers": 1,
  "highestLevel": "信息",
  "levelCapped": true,
  "notes": ["软件采集线索基于「可见窗口 + 已加载模块」，无法区分正常直播/录屏与作弊采集"]
}
```

## E. 运行

```powershell
EagleEye.exe scan                          # 默认包含视觉线索（模块+窗口+设备）
EagleEye.exe scan --vision-behavior        # 追加输入统计（3s，信息级）
EagleEye.exe scan --no-vision              # 完全跳过
```

## F. 实测

```
---- 视觉外挂线索（等级 可疑，2 层独立线索）----
软件采集 6 条 / 硬件 1 条 / 行为提示 已采集（信息级）
[可疑]   18.0  vision.capture.onnxruntime  xxx.exe (PID 1234)
           模块: onnxruntime.dll, gdi32.dll
           签名: valid   窗口: 1295x823
[可疑]   16.0  vision.hw.elgato  Elgato 4K Capture
           VID:PID 0FD9:0061  Class Camera  Service usbvideo
声明: 双机+外部采集+硬件注入链路在本机用户态无法独立确证，以上为可观测线索，不代表最终判定。
```

干净机器（默认规则）：`0 条软件 / 0 条硬件 / 信息` —— 说明默认规则没有噪音。
---

# 附：深度扫描与可移植性（阶段 6）

## A. 先说实话：无法承诺"90%"

只读、用户态、不 Hook 的工具，命中率取决于**外挂在本机留下的痕迹**：

- 软件类外挂（读内存、注入、读屏 + 推理 + 模拟输入）→ 本机痕迹多，可覆盖大部分
- 双机 + 外部采集 + 硬件转发 → **本机零痕迹**，任何用户态工具都查不到
- 内核态外挂（驱动级隐藏）→ 用户态枚举看不到被摘链的模块

所以本项目的目标是"**把可观测面做到最大 + 误报压到最低**"，而不是报一个假的百分比。

## B. 本轮新增的四个探测器

| 探测器 | 抓什么 | 数据来源 | 风险 |
|---|---|---|---|
| **HandleScanner** | 谁以 `VM_READ` / `VM_WRITE` / `CREATE_THREAD` 打开了某个进程 | `NtQuerySystemInformation(SystemExtendedHandleInformation)` + `DuplicateHandle` + `GetProcessId` | 只读；需管理员 |
| **DriverScanner** | 已加载内核模块里命中黑名单的（dbk64 / winio / winring0 / inpout / kdmapper） | `SystemModuleInformation` + 文件哈希 + Authenticode | 只读枚举 |
| **OverlayScanner** | 透明/置顶窗口覆盖在其它进程窗口之上（ESP 常见形态） | `EnumWindows` + `GetWindowLongPtr(GWL_EXSTYLE)` + `GetWindowRect` | 只读 |
| **FileSignatureScanner** | 文件首部字节特征（无哈希也能识别已知样本） | `FileStream(Read)` + ASCII/HEX 匹配 | 只读 |

全部并入主风险聚合（`handle_access` / `kernel_driver` / `file_signature`），overlay 并入视觉层级。

## C. 误报治理（这几条是实测调出来的）

句柄线索第一版在本机跑出 **71 条命中、直接 100 分**，全是噪音。三层过滤后降到 **1 条 / 25.6 分（信息）**：

1. **父子关系**：`CreateProcess` 会给父进程一个 `0x1FFFFF`（ALL_ACCESS）句柄，属正常 → 按 `ParentPid` 直接跳过
2. **同映像**：同一程序的多进程互相持有句柄 → 跳过
3. **ALL_ACCESS 打折**：`0x1FFFFF` 的置信度 ×0.5
4. **一对 (持有者,目标) 只记一条**：一个 ALL_ACCESS 句柄原本会同时命中 read/write/thread 三条规则被累加成 93 分
5. **持有者白名单** 44 条：杀软、系统组件、启动器（Steam/Epic）、覆盖层（Discord/OBS/NVIDIA）、浏览器

## D. 可移植性

| 项 | 做法 |
|---|---|
| 目标机无 .NET | `--self-contained true` 单文件发布（64.6 MB），零依赖 |
| 规则文件 | `rules\` 随 exe 一起发布，按 exe 目录解析，不写死路径 |
| 扫描目录 | 规则里用 `%TEMP%` `%APPDATA%` 环境变量，换机器自动适配 |
| 非管理员 | 句柄枚举等需管理员的能力失败时降级，报告写"未检查"，不崩溃 |
| 编码 | 控制台强制 UTF-8，中文/英文系统都不乱码 |
| 档位 | `--profile quick / standard / deep` 一键切换扫描深度 |
| 无网络 | 全流程离线，报告与日志都写本地 |

实测（模拟"另一台机器"）：把自包含包复制到 `%TEMP%\acprobe-portable-test` 直接运行：

```
规则文件 : ...\acprobe-portable-test\rules\rules.json
portable run ok: EagleEye 2.0.0 | rules: 1.5.0 | risk: 信息
processes: 297 | handles: 1 | drivers: 0
```

## E. 新增 CLI

```powershell
EagleEye.exe scan                      # 默认：进程+文件+DMA+视觉+句柄+驱动+overlay
EagleEye.exe scan --profile quick      # 快扫：不做句柄与 overlay
EagleEye.exe scan --profile deep       # 深扫：+文件特征码 +行为统计
EagleEye.exe scan --no-handles         # 跳过句柄线索
EagleEye.exe scan --file-signatures    # 启用文件特征码（需规则）
```

## F. 本机实测（全模块）

```
总体风险: 信息 25.6
句柄命中 1 / 驱动命中 0 / 特征码命中 0 / overlay 1
视觉: 软件 1 条 / 硬件 0 条 → 信息
进程 297，句柄表 138601 个，高权限句柄 1802 个
```

`overlay 1` 是本次唯一新增的可疑项：某进程的 layered+topmost 窗口覆盖在另一个窗口上——正常软件（Discord/NVIDIA 覆盖层）也会命中，所以只给「信息」。

## G. 仍然查不到的（写进报告，不装作能查）

- 双机链路：另一台机器采集+识别，本机只有"正常鼠标输入"
- 外接采集卡接在另一台机器：本机 PnP 树里没有这个设备
- KMBox 类硬件转发：设备侧是标准 HID，主机无法区分人手与转发
- 内核态隐藏的外挂：模块被摘链后用户态枚举不到
- 模型内容 / 是否真的用于作弊：不读内存、不解析模型
---

# 附：规则热更新目录 + 哈希库工具链（阶段 7）

## A. 规则目录热加载

```powershell
EagleEye.exe scan --rules-dir rules\        # 加载目录下全部 *.json
EagleEye.exe scan --rules  rules\rules.json # 单个文件（旧行为，保留）
EagleEye.exe validate --rules-dir rules\
```

目录里的 JSON 按**文件名升序**依次合并：

| 段 | 合并语义 |
|---|---|
| `meta` | 非空字段逐个覆盖；`categories` 追加去重 |
| `rules` | 按 `id` 合并，同名**后者覆盖前者**，并打印"规则 id 冲突 N 条" |
| `whitelist` | 追加，按 `(pattern, hash, subjectContains)` 三元组去重 |
| `options` / `dma` / `vision` / `deep` | 文件里出现该键则**整段替换** |

实测：

```
规则数量 : 通用 20（启用 19），DMA 5，分类 8，白名单 17 条
  [警告] 已加载: rules.hash.json（规则 2 条，白名单 0 条）
  [警告] 已加载: rules.json（规则 18 条，白名单 11 条）
  [警告] 已加载: zz-override.json（规则 1 条，白名单 0 条）
  [警告] 规则 id 冲突 1 条，已按文件名顺序后者覆盖前者
规则校验通过。
```

好处：**主规则集不用动**。想覆盖某条规则，放一个 `zz-*.json` 就行；想加一批哈希，放一个 `rules.hash.json` 就行。

## B. hashgen.ps1：从样本目录生成哈希规则包

```powershell
# 从样本目录生成（首次）
powershell -ExecutionPolicy Bypass -File tools\hashgen.ps1 `
    -SampleDir D:\samples\cheats `
    -OutFile rules\rules.hash.json

# 后续增量合并（按 hash 去重，不会重复添加）
powershell -ExecutionPolicy Bypass -File tools\hashgen.ps1 `
    -SampleDir D:\samples\new-batch -Merge
```

参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `-SampleDir` | 必填 | 样本目录，只读遍历 |
| `-OutFile` | `tools\rules.hash.json` | 输出路径 |
| `-Extensions` | `.exe .dll .sys .bat .ps1` | 参与计算的扩展名 |
| `-Severity` / `-Confidence` | `5` / `0.95` | 生成的规则等级与置信度 |
| `-IdPrefix` | `hash.known` | 规则 id 前缀 |
| `-Merge` | 关 | 与既有输出按 hash 合并 |
| `-MaxSizeMB` | 512 | 超过则跳过 |

产物只含 `meta` + `rules` 两段，天然可被 `--rules-dir` 合并：

```json
{
  "meta": { "name": "hash-pack", "version": "2026.11.10", "updated": "2026-11-10", "schemaVersion": "2.0" },
  "rules": [
    {
      "id": "hash.known.b3bbd788adb7",
      "type": "file_hash",
      "pattern": "b3bbd788adb7fa3b0b95029e94fe3e91ed03bd04ee526aef0312cba6ef582a65",
      "hash": "b3bbd788adb7fa3b0b95029e94fe3e91ed03bd04ee526aef0312cba6ef582a65",
      "size": 10,
      "category": "file.suspect",
      "severity": 5,
      "confidence": 0.95,
      "enabled": true,
      "description": "已知样本: aimbot-loader.dll（SHA256=b3bb...）"
    }
  ]
}
```

## C. 实测：从样本到命中的完整链路

```
$ hashgen.ps1 -SampleDir samples\known-bad -OutFile samples\rules-pack\rules.hash.json
完成：新增 2 条，跳过（超大）0 个，总计 2 条

$ EagleEye.exe scan --rules-dir samples\rules-pack --file-root samples\known-bad
规则数量 : 通用 20（启用 19）
命中:
  hash.known.b3bbd788adb7 (sev 5, conf 0.95) → 95.0  已知样本: aimbot-loader.dll
  hash.known.39dd10b940aa (sev 5, conf 0.95) → 95.0  已知样本: speed-engine.exe
退出码: 3（高度可疑）
```

同一份规则包换机器也能直接用（路径无关，只比哈希）。

## D. 推荐的目录布局

```
rules\
├─ rules.json          主规则（人工维护，版本受控）
├─ rules.hash.json     样本哈希包（hashgen 生成，可随时替换）
├─ rules.local.json    本机/本客户特殊规则（覆盖用，可选）
└─ whitelist.local.json 本机白名单（覆盖用，可选）
```

热更新流程：把新文件丢进 `rules\` → 下次扫描自动生效 → 不需要重编译、不需要改代码。
---

# 附：游戏侧遥测对接规范（阶段 8）

## A. 为什么是"离线文件"而不是 API

本工具**不联网**（红线）。所以遥测以**文件**形式导入：运营/服务端导出 JSON → 放到玩家机器上 → 本地扫描时一起读。

对接约定等价于 API 约定：字段名、语义、单位定死，双方各自实现即可。

```powershell
EagleEye.exe scan --telemetry D:\telemetry\player-bravo.json
```

## B. 文件格式（`schemaVersion: 1.0`）

```json
{
  "schemaVersion": "1.0",
  "exportedBy": "game-telemetry-service",
  "exportedUtc": "2026-11-10T02:10:00Z",
  "sessions": [
    {
      "sessionId": "s-20261109-2317",
      "matchId": "m-88420",
      "playerId": "p-20777",
      "accountName": "player_bravo",
      "startedUtc": "2026-11-09T22:17:00Z",
      "durationSeconds": 540,
      "metrics": {
        "preAimRatio": 0.62,
        "reactionTimeP50Ms": 148,
        "reactionTimeStdMs": 19,
        "headshotRatio": 0.51,
        "snapAngleMeanDeg": 74,
        "trackingJitterPx": 0.6,
        "accuracyLongRange": 0.44
      }
    }
  ]
}
```

`metrics` 是**开放字典**：加新指标不用改程序，改规则即可。

## C. 指标词典（游戏侧要产出的口径）

| 指标 | 单位 | 定义 | 建议口径 |
|---|---|---|---|
| `preAimRatio` | 0-1 | 开镜/开火前准星已停在目标位置，且**目标当时不可见**的比例 | 0.5s 窗口；需服务端视线遮挡判定，排除已知位置 |
| `reactionTimeP50Ms` | ms | 目标首次可见 → 首次有效输入 的中位数 | 只统计"首次暴露"事件，排除预瞄 |
| `reactionTimeStdMs` | ms | 上述反应时的标准差 | 反映机械稳定性，人手约 70-100ms |
| `headshotRatio` | 0-1 | 爆头击杀 / 总击杀 | 分武器归一化后再比 |
| `snapAngleMeanDeg` | 度 | 单帧视角跳变角度均值（flick） | 排除传送/复活/读条 |
| `trackingJitterPx` | px | 跟枪阶段准星到目标投影点的残差抖动 | 人手 3-5px，脚本/机器视觉常 <1.5px |
| `accuracyLongRange` | 0-1 | >50m 距离命中率 | 分武器 |

## D. 规则配置（`rules.json` → `telemetry` 段）

```jsonc
"telemetry": {
  "enabled": true,
  "baseline": {                      // 人群基线，用于"高出多少"的解释
    "preAimRatio": 0.12,
    "reactionTimeP50Ms": 260,
    "reactionTimeStdMs": 85,
    "headshotRatio": 0.18,
    "snapAngleMeanDeg": 25,
    "trackingJitterPx": 3.5
  },
  "signals": [
    { "id": "tel.preaim", "metric": "preAimRatio", "comparator": "gte", "threshold": 0.35,
      "severity": 4, "confidence": 0.6,
      "description": "开镜前准星已稳定停在目标预设位置（隔墙预瞄）",
      "advice": "需要'目标当时不可见'的判定作为前提" },
    { "id": "tel.tracking_smooth", "metric": "trackingJitterPx", "comparator": "lte", "threshold": 1.2,
      "severity": 4, "confidence": 0.55, "description": "跟枪抖动接近完美平滑" }
  ],
  "bothSidesLevel": "高度可疑"
}
```

`comparator` 只支持 `gte` / `lte`；`severity 1-5`；`confidence 0-1`；校验器会检查 metric 是否有基线（缺基线只告警，不报错）。

## E. 联合判定口径（四种组合，实测）

| 本机 | 遥测 | 联合建议 | 含义与动作 |
|---|---|---|---|
| 信息 | 信息 | **信息** | 无进一步动作 |
| 信息 | 高度可疑 | **可疑** | 本机零痕迹 → **高度指向双机链路 / 外部采集卡 / 硬件转发**；调录像与设备指纹，别在本机继续找 |
| 高度可疑 | 高度可疑 | **高度可疑** | 两侧互相印证 → 优先复核 + 取证 |
| 高度可疑 | 信息 | **可疑** | 有痕迹但行为正常 → 可能是误装/残留/未使用；让玩家清理后复测，不直接处罚 |

实测输出：

```
本机等级 高度可疑 / 遥测等级 高度可疑 → 联合建议 高度可疑
  · 遥测行为异常 + 本机存在痕迹 → 两侧证据互相印证，优先复核
  · 遥测：tel.preaim: preAimRatio=0.62（阈值 0.35，人群基线 0.12（本次 0.62））
  · 遥测：tel.tracking_smooth: trackingJitterPx=0.6（阈值 1.2，人群基线 3.5（本次 0.6））
```

```
本机等级 信息 / 遥测等级 高度可疑 → 联合建议 可疑
  · 遥测出现行为异常，但本机进程/驱动/句柄全部干净 → 高度指向双机链路、外部采集卡或硬件转发
  · 建议：调取该玩家的对局录像与设备指纹，而不是继续在本机找证据
```

## F. 报告字段

```jsonc
"telemetry": {
  "enabled": true, "loaded": true,
  "sourcePath": "D:\\telemetry\\player-bravo.json",
  "schemaVersion": "1.0", "exportedUtc": "...",
  "sessions": 1,
  "localLevel": "高度可疑",
  "jointLevel": "高度可疑",
  "jointScore": 100,
  "jointReasons": [ "遥测行为异常 + 本机存在痕迹 → 两侧证据互相印证，优先复核", "..." ],
  "assessments": [{
    "sessionId": "...", "playerId": "...", "telemetryLevel": "高度可疑",
    "signals": [{
      "ruleId": "tel.preaim", "metric": "preAimRatio",
      "value": 0.62, "threshold": 0.35, "baseline": 0.12, "baselineKnown": true,
      "severity": 4, "confidence": 0.6, "score": 48, "riskLevel": "可疑"
    }]
  }],
  "note": "遥测只能反映行为异常，本地只能反映痕迹；两者单独都不构成判定。"
}
```

## G. 工作流

```
① 玩家机器跑 EagleEye（产出本机线索）
② 运营侧导出该玩家的遥测 JSON
③ 本地跑：scan --telemetry <文件> → 联合评估
④ 联合等级 = 复核优先级，不是判决
⑤ 复核：录像 + 设备指纹 + 人工确认
```

## H. 边界（写死在 note 里）

- 遥测异常 ≠ 作弊：高分段玩家、外设宏、辅助功能都可能触发
- 本机有痕迹 ≠ 作弊：误装、残留、家人共用
- **两者都不能单独定罪**；联合只解决"先查谁"，不解决"是不是"
- 指标口径由游戏侧定义，本工具只做比较与解释，不做重新计算
---

# 附：误报调参流程（阶段 9）

## A. 为什么先做工具而不是直接改数值

单台干净机器的噪音不能代表整个玩家群体。所以流程是：

```
批量扫描 → 打标签 → 统计每条规则的真实表现 → 产出调参包 → 应用 → 复测
```

工具：`tools\tune-thresholds.ps1`

## B. 打标签（关键）

报告文件名就是标签：

```
out\baseline\
├─ clean-machineA.json     干净机器
├─ clean-machineB.json
├─ cheat-case-2309.json    已确认作弊的机器
└─ cheat-case-2411.json
```

`cheat-*` 之外的都按 `-Label`（默认 `clean`）处理。
报告里的 `ruleset.ruleCount < -MinRuleCount`（默认 10）会被跳过，避免验证用的小规则包污染统计。

## C. 判定策略

| 情况 | 动作 |
|---|---|
| 只在干净机器命中、作弊样本 0 次、目标数 ≤ 20 | **仅加白**（不动规则） |
| 同上但目标数 > 20，且属句柄/驱动/哈希/特征码 | **降权**（受保护类型，不停用） |
| 同上但目标数 > 20，普通类型 | **停用**（干净报告 ≥ 3）或降权 |
| 干净和作弊都命中 | **保留规则**；只把"干净出现、作弊从未出现"的目标加白 |
| 规则集里不存在该 id | 忽略（测试规则） |

这条"干净出现过、作弊也出现过就不加白"的约束是刻意加的：防止把某个真作弊程序因为恰好出现在干净样本里而被放行。

## D. 用法

```powershell
powershell -ExecutionPolicy Bypass -File tools\tune-thresholds.ps1 `
    -ReportsDir out\baseline -Label clean

# 产出
#   rules\tuning.suggested.json      调参包（可直接 --rules-dir 加载）
#   out\baseline\tuning-report.md    人读分析报告
```

参数：`-DisableAt 3`、`-ConfidenceFactor 0.6`、`-WhitelistThreshold 20`、`-MinRuleCount 10`、`-NoWhitelist`。

## E. 本机真实跑的一轮（12 份报告：9 干净 / 3 作弊）

```
规则                      类型             干净命中 作弊命中  平均分 判定
sig.unsigned            signature         4    4   18   保留
handle.vm_write_remote  handle_access     1    0   25.6 仅加白
file.name.cheat         file_name         1    2   30   保留
hash.known.b3bbd788adb7 file_hash         0    1   95   保留
sig.example.cheatengine file_signature    0    1   30   保留
hash.known.39dd10b940aa file_hash         0    1   95   保留

调参包: rules\tuning.suggested.json（规则 0 条，白名单 1 条）
```

解读：

- `sig.unsigned` 两边都命中 → **保留**（它是真信号，不能因为干净机器上有几个未签名的商店应用就降权）
- `handle.vm_write_remote` 只在干净侧命中 1 次（`powershell.exe` 的父子句柄）→ **仅加白**
- 两条哈希规则只在作弊侧命中 → **保留**（真阳性，符合预期）

应用效果：

```
【调参前】findings: 5   suppressed: 0
【调参后】findings: 4   suppressed: 1
   [抑制] handle.vm_write_remote @ powershell.exe | 调参基线：…干净机器命中、作弊样本从未出现
   [活跃] sig.unsigned @ RoundedTB.exe / ArmouryCrate.exe / …（保持 信息级）
```

## F. 换到你们的机器群怎么用

1. 找 5-10 台**确认干净**的员工/测试机，各跑一次 → 重命名为 `clean-*.json`
2. 找 3-5 个**已确认作弊**的案例机（或已知样本环境）→ `cheat-*.json`
3. 跑 `tune-thresholds.ps1`，看 `tuning-report.md`
4. 人工确认调参包（尤其"建议停用"的那几条），放进 `rules\`
5. 用 `--rules-dir` 复测，对比 `findings` / `suppressedFindings`
6. 有新样本后 `-Merge` 再跑一轮，形成闭环

## G. 一个必须知道的坑

本次基线里 `cheat-*.json` 其实是**同一台干净机器上放了作弊样本**后扫出来的报告，所以它们的噪音和 `clean-*` 完全一样，导致 `sig.unsigned` 无法被加白。

真实部署时每台机器是一个独立样本点，噪音分布不同，工具才能把"这批进程在所有干净机器上都出现、在任何作弊机器上都不出现"正确识别出来。

## H. 实现中修掉的两个真 bug

1. **白名单不作用于句柄/驱动类命中** —— 原来 `WhitelistFilter` 只覆盖进程/文件扫描器。新增 `Core\WhitelistFilter.cs` 做统一后置过滤，支持 `suppressRules` 定向抑制。
2. **PowerShell `$Label` 变量被覆盖** —— `$label = ... else { $Label }` 因变量名大小写不敏感，把参数自己改了，导致所有报告被标成 `cheat`。改名为 `$reportLabel`。
---

# 附：三角洲行动专项包（阶段 10）

## A. 先说清楚：网上没有可靠的"外挂名单"

本轮检索的实际结果：

- 中文区对「三角洲行动 外挂/辅助/透视/自瞄」的搜索结果被平台过滤（Bing 明确提示"部分搜索结果未予显示"）
- 精确查询游戏进程名时，返回的全是垃圾站，没有一条可信内容

**所以本包不含任何"某某外挂 1.x"的具体产品名与哈希。** 编造这些东西只会带来两个后果：误报（同名正常软件被拦）和虚假安全感（以为覆盖了，其实一个新版本就绕过）。

真正有效的三条路径，下面都给了。

## B. 路径一：句柄（最强信号，已加进主规则集）

```json
{
  "id": "handle.game_process_access",
  "targetProcessPattern": "*DeltaForce*",
  "accessMaskAny": ["0x10", "0x20", "0x2"],
  "severity": 5, "confidence": 0.7,
  "description": "有进程以 VM_READ / VM_WRITE / CREATE_THREAD 打开了三角洲行动客户端进程"
}
```

**除了反作弊自己，正常软件不应该读游戏内存。** 这条规则不依赖任何外挂品牌名，外挂改名也躲不掉。

## C. 路径二：命名启发式（弱信号，专项包 20 条）

`rules\rules.delta-force.json`：

| 规则前缀 | 规则数 | 例子 | severity |
|---|---|---|---|
| `df.tool` 专项工具 | 6 | `*三角洲*辅助*`、`*三角洲*透视*`、`*三角洲*自瞄*`、`*DF*辅助*` | 3-4 |
| `df.name` 中文命名 | 5 | `*透视*`、`*自瞄*`、`*锁头*`、`*穿墙*`、`*方框*` | 2 |
| `df.loader` 加载器 | 4 | `*kmbox*`、`*kmnet*`、`*aim*loader*`、`*injector*` | 3-4 |
| `df.module` 模块 | 2 | `*deltaforce*cheat*.dll`、`*df*hack*.dll` | 4-5 |
| `df.file` 文件 | 3 | `*三角洲*辅助*.exe`、`*.ct`、`*kmbox*.dll` | 2-4 |

配套白名单（**避免误伤官方组件**）：`DeltaForceClient*`、`*DeltaForce*Shipping.exe`、`ACE-*`、`SGuard*`、`WeGame*`、`steam*`、腾讯签名。

> 命名类规则是**启发式**，误报面大：录屏软件、攻略工具、甚至玩家自己改名的快捷方式都可能命中。所以 `df.name.*` 只给 severity 2。

## D. 路径三：样本哈希（唯一能定性的本地证据）

```powershell
# 1. 把确认过的外挂样本放进 samples\known-bad\delta-force\
# 2. 生成哈希包
powershell -File tools\hashgen.ps1 -SampleDir samples\known-bad\delta-force -OutFile rules\rules.hash.json
# 3. 规则目录加载
EagleEye.exe scan --rules-dir rules\
```

哈希命中 = severity 5 / confidence 0.95，一条就顶到「高度可疑」。

## E. 采集真实基线：`tools\collect-game-info.ps1`

网上的名字不可信，那就用你自己的机器采：

```powershell
# 先启动游戏，再运行
powershell -File tools\collect-game-info.ps1 -Pattern DeltaForce
```

输出：

```
== DeltaForceClient-Win64-Shipping (PID 12345) ==
  路径   : D:\WeGameApps\三角洲行动\DeltaForceClient-Win64-Shipping.exe
  命令行 : ... -steam ...
  签名   : Valid  CN=Tencent Technology (Shenzhen) Company Limited
  版本   : Tencent / 1.12.0
  模块   : 187 个
  未验签模块（前 10 个）: ...
== 本机进程里命中外挂命名特征的 ==
  xxx辅助.exe    D:\tools\xxx\xxx辅助.exe
```

用途：
1. 把游戏进程名填进白名单与 `targetProcessPattern`
2. 把异常模块名补进 `df.module.*` 规则
3. 把"命中外挂命名特征"的清单变成白名单基线

## F. 实测

文件线索：

```
[可疑] 48.0  df.file.zh        三角洲辅助测试.exe
[可疑] 44.0  df.file.kmboxdll  kmbox_hid.dll
```

进程线索（真实拉起一个 `三角洲辅助.exe` 的进程）：

```
[可疑] 57.6  df.tool.nameassist  三角洲辅助.exe
[信息] 32.4  df.tool.name.zh     三角洲辅助.exe
总风险: 高度可疑 90
```

## G. 局限（诚实版）

| 局限 | 说明 |
|---|---|
| 品牌名每周变 | 命名规则只能拦"没改名"的，硬编码产品名性价比极低 |
| 改名即绕过 | 外挂作者改个 exe 名就绕过所有 `df.*.name` 规则 |
| 中文模式误报 | `*透视*` 也可能命中显卡驱动面板的翻译文件 |
| 双机/硬件 | 本机完全没有进程，命名规则一条都抓不到 |

**所以专项包的定位是"补充线索"，不是"覆盖率高"。真正的判定靠：句柄层 + 驱动层 + 哈希 + 遥测四件套。**
---

# 附：情报采集与转化（阶段 11）

## A. 直接回答："去卡密平台找名单"行不行？

**技术上能访问（域名没被封的话），但产出对检测的价值最低。** 原因：

| 卡密平台能给你 | 检测需要 |
|---|---|
| 品牌名、版本号、价格、功能描述 | ❌ 名字每周改 |
| 支付页、发卡机器人 | ❌ 与本地检测无关 |
| 下载入口（多数要注册/付费/加群） | ⚠️ 拿不到二进制就拿不到哈希 |
| 截图（有时能看到文件名） | ✅ 这是唯一有价值的碎片 |

而且这类站点域名日抛、内容随时下架，**采集成本高、留存差、还会把运营的浏览器环境弄脏**。所以我不建议把它当成主要渠道。

## B. 渠道价值排序（我的判断）

| 渠道 | 能拿到什么 | 价值 | 备注 |
|---|---|---|---|
| **你们自己的样本库** | 完整的 exe/dll/sys | ★★★★★ | 唯一能生成哈希、能喂给沙箱的 |
| **客服工单 / 玩家举报** | 截图、文件名、时间点 | ★★★★ | 截图里的文件名直接可用 |
| **游戏录像 + 遥测** | 行为异常 | ★★★★ | 命名规则完全替代不了 |
| **玩家社区曝光帖**（贴吧/小黑盒/B站） | 品牌名、版本、广告语 | ★★ | 品牌名 → 命名规则 |
| **卡密平台 / 发卡站** | 品牌名、价格 | ★ | 名字而已，且随时改 |
| **通用搜索引擎** | 本次实测：被过滤，几乎为零 | ☆ | 中文区对"外挂/辅助"类做了屏蔽 |

## C. 拿到字符串之后：`tools\intel-to-rules.ps1`

不管从哪个渠道拿到的词，都走同一条转化链路：

```
渠道 → 关键词 → intel-to-rules.ps1 → 规则包 → --rules-dir 加载 → tune-thresholds.ps1 复测
```

三种模式：

```powershell
# 1) list：一行一个词（最常用）
.\intel-to-rules.ps1 -InputFile rules\intel\delta-force-candidates.txt -Mode list `
    -Severity 2 -Confidence 0.25 -Category df.name

# 2) csv：结构化，可精确控制类型/等级
#    type,pattern,severity,confidence,description
#    process,某某辅助,4,0.55,情报：某品牌主程序

# 3) extract：丢一段网页/聊天记录，自动抽候选词（只出候选，不生成规则）
.\intel-to-rules.ps1 -InputFile page.txt -Mode extract -OutCandidates rules\intel\new-candidates.txt
```

产物：
- `rules\rules.intel.json` —— 规则包（自动去重、id 由 hash 生成）
- `rules\intel\intel-review.md` —— 复核清单（每条规则长什么样、误报面多大）

## D. 本次实测

候选词 25 个（命名构件，非品牌名）→ 自动生成 **75 条规则**（process/module/file × 25）：

```
规则包: rules\rules.intel.json（新增 75 条，跳过重复 0 条）
合并后: 通用 113 条（18 主 + 20 专项 + 75 情报）+ DMA 5 = 118 条
```

命中测试（构造 `三角洲辅助_v3.exe`、`内部版_锁头.dll`）：

```
[可疑] 48.0  df.file.zh                三角洲辅助_v3.exe
[信息]  7.0  intel.file_name.1a5335ea  三角洲辅助_v3.exe
[信息]  7.0  intel.file_name.f775b9d4  内部版_锁头.dll
[信息]  7.0  intel.file_name.9b76f034  内部版_锁头.dll
```

干净机器噪音：**0 条**（75 条情报规则全部未命中）。

## E. 命名构件的取舍（为什么没放"卡密/发卡"）

文件/进程命名里会出现：`辅助`、`透视`、`自瞄`、`锁头`、`方框`、`骨骼`、`雷达`、`防封`、`内部版`、`定制版`、`驱动版`、`自动压枪`、`硬件宏`……

不会出现：`卡密`、`发卡`、`代理`、`售后` —— 这些是**业务词汇**，放进命名规则只会制造噪音。这个取舍写在候选词文件头部注释里。

## F. 老实说：命名规则的投入产出比很低

- 外挂作者改个 exe 名（`三角洲辅助.exe` → `df_tool.exe`）就绕过全部 75 条
- 真正的检测靠：**句柄（谁读了游戏进程）+ 驱动（dbk64/winio/kdmapper）+ 哈希（样本）+ 遥测（行为）**
- 命名规则的价值只有一个：**在样本入库前的空窗期，给复核人一个线索**

所以我的建议：把预算花在**样本采集**（虚拟机跑样本、抓落地文件、自动 hashgen）和**遥测指标口径**上，别花在追名单上。
---

# 附：没有样本怎么办（阶段 12）

## A. 结论：换个打法，不是没得打

有样本 → 靠**哈希**（确定性最高）
没样本 → 靠**结构 + 行为**：外挂要生效，必然留下结构性痕迹，跟它叫什么名字无关。

本轮补了两块完全不依赖样本的能力。

## B. 新增一：注入痕迹检测（`InjectionTraceScanner`）

对目标进程（默认 `*DeltaForce*`）的模块列表做三个判断：

| 判断 | 含义 | 规则 id | severity |
|---|---|---|---|
| 模块文件在磁盘上不存在 | manual mapping / 反射注入 | `inj.module_missing_file` | 5 |
| 模块路径在 Temp/Downloads/Desktop/AppData | 释放式加载 | `inj.module_suspicious_path` | 4 |
| 非 Windows 目录 + 无有效签名 | 未知来源模块 | `inj.module_unsigned` | 2 |

只读：复用已枚举的模块列表 + 文件存在性 + Authenticode，**不读进程内存、不注入、不 Hook**。
Windows 目录下的模块直接跳过，避免几百次验签拖慢扫描。

配置：

```jsonc
"deep": {
  "injection": {
    "enabled": true,
    "targetProcessPatterns": ["*DeltaForce*"],
    "moduleWhitelist": [],
    "missingFileSeverity": 5,
    "suspiciousPathSeverity": 4,
    "unsignedSeverity": 2
  }
}
```

## C. 新增二：驱动白名单模式（不需要样本）

原来的驱动检测是**黑名单**（dbk64/winio/winring0…），没样本就查不到新驱动。
现在加**白名单模式**：不在规则里、又不是受信任签名的驱动，一律上报待复核。

```jsonc
"deep": {
  "drivers": {
    "whitelistMode": true,
    "trustedSigners": ["Microsoft", "NVIDIA", "AMD", "Intel", "Realtek", "Valve", "VMware", "雷神", "NetEase", "..."],
    "untrustedSeverity": 3,
    "untrustedConfidence": 0.45
  }
}
```

判定链：**目录签名（catalog_valid）直接放行 → 签名主体在受信任列表放行 → 其余上报**。

### 实测收敛过程（本机 266 个已加载驱动）

```
第一版：待复核 81 条（其中 74 条是 catalog_valid 的 Windows 自带驱动 —— 逻辑漏洞）
修 catalog 处理：81 → 7（Valve / VMware / 雷神 / 网易 / 迅雷 等真实厂商）
补齐 trustedSigners：7 → 1
再补迅雷：1 → 0
```

**这 1 条就是这套机制的价值**：266 个驱动里，只有 1 个需要人看一眼。外挂驱动也一定会落进这个列表。

## D. 无样本时的检测优先级（按性价比排序）

| 层 | 需要样本吗 | 本机可观测 | 说明 |
|---|---|---|---|
| **句柄**（谁以 VM_READ/WRITE 打开游戏） | ❌ | ✅ | 最强，外挂改名也躲不掉 |
| **驱动白名单**（非受信任签名） | ❌ | ✅ | 266 → 0~3 条待复核 |
| **注入痕迹**（模块不在磁盘/路径异常） | ❌ | ✅ | 结构证据 |
| **overlay 窗口** | ❌ | ✅ | ESP/视觉常见 |
| **视觉链路**（推理运行时+窗口） | ❌ | ✅ | AI 外挂 |
| **遥测**（行为异常） | ❌ | ⚠️ 需游戏侧 | 唯一能抓双机 |
| 哈希 | ✅ | ✅ | 有样本时才可用 |
| 命名规则 | ❌ | ⚠️ 噪音大 | 只作线索 |

前六层全部不需要样本。这就是"没有样本也能跑"的底气。

## E. 本轮修掉的一个真 bug

`DriverInterop` 里 `RTL_PROCESS_MODULE_INFORMATION` 的数组步长写成了 152 字节（x64 实际是 **296**），
导致驱动路径被截断（`System32\Drivers\crashdmp.sys`、`?aI^...`），
进而**验签全部失败、路径判定全废**。修正后路径恢复正常、签名可用。

这个 bug 在"有样本、只看黑名单命中"的模式下根本暴露不出来——是"白名单模式"把它逼出来的。

## F. 怎么拿到第一批样本（合法途径）

| 途径 | 做法 | 产出 |
|---|---|---|
| 客服工单 | 让举报玩家附截图（含任务管理器/文件列表） | 文件名、路径 |
| 申诉流程 | 要求被处罚者提交"清理证明"，常带安装路径 | 目录、文件名 |
| 授权远程取证 | 签授权书后远程采集，只读拷贝到隔离机 | 完整样本 → hashgen |
| 与 ACE/安全团队协作 | 他们手上一定有样本 | 哈希、驱动名 |
| 玩家社区 | 曝光帖里的截图 | 品牌名（弱） |

拿到第一个样本后的流程：
```
样本 → 隔离 VM 落地 → tools\hashgen.ps1 → rules\rules.hash.json → --rules-dir 加载
```

## G. 当前干净基线（本机实测）

```
drivers: 266          待复核: 0
injection traces: 0   （游戏未运行）
handles high access: 1834 → 命中 1（powershell.exe 父子句柄，已知）
findings: 5（4 条未签名商店应用 + 1 条句柄）→ 总体 信息 25.6
扫描耗时: 5.5s（含 266 次驱动验签）
```
---

# 附：现场部署自检与实测修正（阶段 13）

## A. 新增命令：`selftest`

现场拿到 exe 先跑这个，30 秒内判断"这台机器能不能查"：

```powershell
EagleEye.exe selftest --rules-dir rules\
```

输出 9 项检查：

```
[FAIL] 管理员权限     未提权 —— 游戏/反作弊等受保护进程读不到，覆盖不完整
[PASS] 规则加载       tuning-suggested v2026.11.10，通用 113 条 / DMA 5 条
[PASS] 进程枚举       315 个进程
[PASS] 签名校验       自身 exe 验签返回 unsigned（能返回结果即说明 wintrust 可用）
[PASS] 句柄枚举       句柄表 150544 个，高权限 1971 个，可解析配对 198 个（38 ms）
[PASS] 驱动枚举       273 个已加载驱动
[PASS] 设备枚举       设备 219 个，其中 PCI/PCIe 38 个
[PASS] 目标游戏进程    DeltaForceClient-Win64-Shipping(PID 11552)
[PASS] 输出目录可写    ...
结论：1 项关键检查未通过 —— 建议先解决再扫描：管理员权限
```

退出码 0 = 就绪，1 = 有关键项未通过。可直接放进部署脚本做前置检查。

## B. 本轮修掉的问题（都来自真实游戏实测）

### 1. 句柄噪音：41 条 → 15 条（且全部可抑制）

**现象**：游戏运行时报 41 条 `handle.*`，全是 `DeltaForceClient → 某个进程`，方向反了。

**原因**：规则 `targetProcessPattern: "*"` 让所有配对都命中，包括"游戏打开自己的子进程"。

**修复**：
- 规则收敛到 `*DeltaForce*`（只关心"谁打开了游戏"）
- 目标进程不在快照里（已退出 / ACE 拉起）→ 只记 `unresolvedTargets`，不出 Finding
- 祖先链过滤（游戏 → UnrealCEF → browser 这种隔代关系也跳过）

**效果**：非提权 41→0，提权 15（全是同名进程互相持有，已被游戏白名单抑制）。

### 2. 非管理员时静默降级 → 显式警告

```
管理员    : 否（部分进程不可查，已在未检查项注明）
            ⚠ 未提权：游戏进程（受 ACE 保护）的模块/句柄读不到，本次覆盖不完整
            ⚠ 现场扫描请用「以管理员身份运行」，否则注入痕迹与句柄线索会全部落空
```

报告里同步增加：

```jsonc
"summary": {
  "partialCoverage": true,      // 覆盖是否完整
  "unreadableTargets": 202      // 因权限读不到的进程数
}
```

### 3. 驱动模块结构体步长修正（上一轮）

`RTL_PROCESS_MODULE_INFORMATION` x64 步长 152 → **296**，修好后驱动路径与验签才正确。

## C. 实测对比（同一台机器，游戏运行中）

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 句柄命中（非提权） | 41 | **0** |
| 句柄命中（提权） | 41 | 15（全部被白名单抑制） |
| 抑制条目 | 42 | 16 |
| 活跃命中 | 4（全是未签名商店应用，信息级） | 4（不变） |
| 覆盖标记 | 无 | `partialCoverage` + `unreadableTargets` |
| 自检能力 | 无 | `selftest` 9 项 |

## D. 尚未解决的问题（已知，不影响判定）

| 问题 | 影响 | 计划 |
|---|---|---|
| 提权后仍有 15 条同名进程互持句柄 | 全被白名单抑制，不影响结论 | 后续按"同映像"规则再收一层 |
| 172 个进程提权也读不到（ACE 等） | 已知限制，报告已标注 | 无解，属系统保护 |
| 扫描 9s（273 个驱动逐一验签） | 现场体验一般 | 可加磁盘签名缓存 |
| `wegame_env.exe` 摘要不匹配 | 待人工确认 | 确认后加定向白名单 |
---

# 附：性能与体验优化（阶段 14）

## A. 验签磁盘缓存：8.3s → 1.55s（5.3 倍）

驱动与模块验签是扫描的主要耗时（273 个驱动 + 141 个模块）。加了**内存 + 磁盘两级缓存**：

- 缓存键 = `路径|大小|修改时间` —— 文件一变自动失效，不会误用旧结果
- 位置：`<exe目录>\out\cache\sigcache.json`（约 98 KB）
- 首次扫描写入，之后命中缓存直接返回

实测（同一台机器，游戏运行中）：

| 场景 | 耗时 | 缓存 |
|---|---|---|
| 冷缓存（首次） | **8.28 s** | 新增 351 条 |
| 热缓存（第二次起） | **1.55 s** | 新增 0 条，命中 351 |

开关：`--sig-cache <路径>` 指定位置，`--no-sig-cache` 关闭。

## B. 输出目录规范化

原来默认写到「当前工作目录」，运维在别的目录执行 exe 时报告会散落各处。
现在统一写到 **exe 同目录的 `out\`**：

```
<exe目录>\
├─ EagleEye.exe
├─ rules\
└─ out\
   ├─ reports\  scan-<时间>.json / .html
   ├─ logs\     audit-<时间>.jsonl
   └─ cache\    sigcache.json
```

不可写时（如装在 Program Files）自动回退到当前工作目录。

## C. 句柄噪音清零

同映像过滤之外，再加一条：**同名进程互持句柄不算外部读取**（受保护进程读不到路径时的兜底）。

```
修复前：41 条（全部噪音）→ 修复后：0 条
```

## D. 报告可用性

1. **HTML 顶部红色横幅**：非提权扫描时明确写「覆盖不完整 + 多少个受保护进程读不到 + 请用管理员重扫」
2. **`bad_digest` 给出可操作建议**：说明"签名后来被改"的常见良性原因（平台自更新打补丁），以及如何按 `suppressRules` 定向加白
3. **`summary.partialCoverage` / `unreadableTargets`** 字段化，便于批量统计"有多少机器的扫描是完整覆盖"

## E. 当前基线

```
冷启动 8.3s / 热启动 1.55s
进程 313 / 驱动 273 / 高权限句柄 1987
活跃命中 4（未签名商店应用，信息级）
句柄命中 0 / 注入痕迹 0 / 驱动待复核 0
红线自检 18/18 PASS
```
---

# 附：分发打包（阶段 15）

## A. 一条命令出安装包

```powershell
powershell -File tools\package.ps1
```

产出：

```
dist\EagleEye-20261110.zip     28.4 MB（压缩前 65 MB）
dist\EagleEye-20261110\
├─ EagleEye.exe    64.67 MB   自包含单文件，目标机无需 .NET
├─ rules\
│  ├─ rules.json                主规则 18 条
│  ├─ rules.delta-force.json    三角洲专项 20 条
│  └─ rules.intel.json          命名情报 75 条
├─ tools\
│  ├─ selftest 用的 audit-policy.ps1
│  ├─ hashgen.ps1               样本 → 哈希规则
│  ├─ intel-to-rules.ps1        情报 → 规则
│  ├─ tune-thresholds.ps1       误报调参
│  └─ collect-game-info.ps1     现场采集基线
├─ README.md
└─ 快速上手.txt
```

## B. 修掉的两个分发缺陷

### 1. 发布包里只有 18 条规则

`csproj` 原来只复制项目内的 `rules\rules.json`，仓库级的专项包/情报包不会被打包。
→ 用 `<None Include="..\..\rules\*.json" Link="rules\..." CopyToOutputDirectory="PreserveNewest" />` 把两个包链进发布。

### 2. 默认只加载单个文件

原来默认读 `rules\rules.json`（18 条），专项包在目录里也不生效。
→ 默认改为**加载 `rules\` 目录并按 id 合并**（113 条），目录不存在才退回单文件。

验证（解压到临时目录，模拟另一台机器，不带任何参数）：

```
规则文件 : ...\acprobe-dist-test\rules
规则数量 : 通用 113（启用 112），DMA 5，分类 11，白名单 28 条
  [警告] 已加载: rules.delta-force.json（规则 20 条）
  [警告] 已加载: rules.intel.json（规则 75 条）
  [警告] 已加载: rules.json（规则 18 条）
```

## C. 现场使用三步

```powershell
# 1. 解压，管理员打开 PowerShell
cd <解压目录>

# 2. 自检（9 项，确认能查）
.\EagleEye.exe selftest

# 3. 扫描
.\EagleEye.exe scan
# 结果：out\reports\scan-<时间>.json / .html
```

## D. 重新打包

```powershell
.\tools\package.ps1                 # 重新发布 + 打包
.\tools\package.ps1 -SkipPublish    # 用现有产物快速重打包
.\tools\package.ps1 -NoZip          # 只要目录不要 zip
```
---

# 附：汇总 + 调参串联（阶段 16）

## A. 一条命令走完"汇总 → 调参"

```powershell
EagleEye.exe aggregate --dir <报告目录> --tune
```

输出：

```
批量汇总：12 份报告（完整 0 / 不完整 12）
注意：12 台机器未提权，扫描不完整，结论需谨慎
Markdown: ...\aggregates\aggregate-<时间>.md

-- 继续做调参 --
调参分析：9 份干净 / 3 份作弊

规则                         类型            干净  作弊    均分  判定
sig.unsigned                signature         4    4     18  保留
handle.vm_write_remote      handle_access     1    0   25.6  仅加白
file.name.cheat             file_name         1    2     30  保留

调参包: ...\tuning.suggested.json（规则调整 0 条，白名单 1 条）
```

单独的调参命令：

```powershell
EagleEye.exe tune --dir <报告目录> [--tune-out <路径>] [--no-whitelist]
```

调参逻辑已用 C# 重写（`Reporting/RuleTuner.cs`），不依赖 PowerShell；`tools\tune-thresholds.ps1` 保留作为无 .NET 环境的备用。

## B. 判定策略（和脚本版一致，刻意保守）

| 情况 | 动作 |
|---|---|
| 只在干净机器命中、作弊 0 次、目标 ≤ 20 | 只加白，不动规则 |
| 同上但目标 > 20，属句柄/驱动/哈希/特征码 | 降权（受保护类型，不停用） |
| 同上但目标 > 20，普通类型 | 停用（干净报告 ≥ 3）或降权 |
| 干净/作弊都命中 | 保留规则，只把"干净出现、作弊从未出现"的目标加白 |

**关键约束**：干净样本出现过、作弊样本也出现过的目标**不加白** —— 防止把真作弊程序因为恰好出现在干净机器上而放行。

## C. 一个实现细节

调参需要判断"这条规则是否存在"，但规则分散在 `rules[]` / `dma.rules[]` / `vision.*` / `deep.*` 四个段里。
所以内部维护两份集合：

- `ruleById`：只有通用 `rules[]`（能写回 schema 的才能做覆盖）
- `knownIds`：全部段的 id（用于判定"是不是真规则"，决定是否加白）

漏掉后者时，`handle.vm_write_remote` 会被误判成"未知规则"而跳过加白（实测踩到过）。

## D. 闭环

```
多机扫描 → aggregate（机器排名/规则排行/重复对象）
        → tune（规则降权/停用 + 目标级加白）
        → 调参包放进 rules\
        → 下次扫描自动生效
        → 有新样本再来一轮
```

全部离线，不联网。