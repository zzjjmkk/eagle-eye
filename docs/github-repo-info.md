# GitHub 仓库文案（复制粘贴用）

## 1. About 描述（仓库右上角那一行）

**英文（推荐，约 190 字符）**

```
Read-only local anti-cheat scanner for Windows. Finds what cheat tools leave behind — processes, handles, drivers, injected modules, overlays, DMA devices — and reports with an evidence chain. No injection, no memory reads, no hooks.
```

**短版（约 120 字符，空间紧张时用）**

```
Read-only Windows anti-cheat scanner: process / handle / driver / injection / overlay / DMA traces, reported with evidence. No injection, no hooks.
```

**中文（约 90 字）**

```
Windows 本地反作弊只读扫描器。查进程、句柄、驱动、注入模块、叠加窗口、DMA 外设的可疑痕迹，输出带证据链的风险报告。不注入、不读内存、不 Hook、不联网。
```

## 2. Topics（标签，最多 20 个）

```
anti-cheat  windows  csharp  dotnet  security-tools  forensics  edr
threat-detection  handle-enumeration  driver-scanner  dma-detection
game-security  reverse-engineering  read-only  cli  incident-response
cheat-detection  windows-security  offensive-security  blue-team
```

按优先级取前 12 个：

```
anti-cheat, windows, csharp, dotnet, security-tools, forensics,
threat-detection, driver-scanner, dma-detection, game-security, cli, blue-team
```

## 3. 首次提交信息

```
Eagle Eye v1.0.0

Read-only local anti-cheat scanner for Windows x64.

- Process / handle / driver / injection / overlay / DMA detection layers
- Evidence-chain findings with severity + confidence, never a binary verdict
- External JSON rules with hot reload, whitelist suppression, auto tuning
- JSON + self-contained HTML reports, JSONL audit log, no network access
- 18 machine-checked red-line guarantees (no injection, no memory reads, no hooks)
```

## 4. Release 标题与说明（v1.0.0）

**标题**

```
Eagle Eye v1.0.0 — 首个公开版本
```

**说明**

```markdown
首个公开版本。

## 怎么用

1. 下载 `EagleEye-v1.0.0-win-x64.zip` 解压
2. **右键 exe → 以管理员身份运行**（或双击，向导会主动请求提权）
3. 等 10-20 秒，报告自动打开

目标机器**不需要安装 .NET**，单文件自包含。

## 这一版能查什么

| 层 | 内容 |
|---|---|
| 句柄 | 谁以 VM_READ / VM_WRITE / CREATE_THREAD 打开了游戏进程 |
| 驱动 | 已加载内核驱动：黑名单 + 白名单模式（非受信任签名全报） |
| 注入痕迹 | 游戏进程里「磁盘不存在 / 路径异常 / 无签名」的模块 |
| 进程 | 名称、路径、命令行、加载模块、父进程链 |
| 签名 | Authenticode 内嵌 + 目录签名双路校验 |
| 叠加窗口 | 透明置顶窗口覆盖在游戏之上 |
| 视觉链路 | 可见窗口 × 推理运行时 / 采集 hook 模块 |
| DMA | PCIe 设备枚举（可选一次性只读配置空间驱动） |
| 文件 | 只读遍历 + SHA256 + 字节特征码 |
| 遥测 | 导入游戏侧离线 JSON，与本机线索联合评估 |

前 8 层**不需要样本哈希** —— 外挂要生效就必须打开游戏进程、加载驱动、注入模块，这些是结构性痕迹。

## 判定口径

```
单条得分 = severity × 20 × confidence × 分类权重
0-39 信息 / 40-69 可疑 / 70-100 高度可疑
```

本地最高只给「高度可疑」，必须人工复核。双机链路、外部采集卡、硬件转发在本机没有痕迹，
报告会明确写「查不到」而不是假装干净。

## 红线

只读枚举：不注入、不读内存、不 Hook、不截屏、不联网、不加载常驻驱动。
仓库自带 `tools/audit-policy.ps1`，18 项机器校验，全部 PASS 才发布。

## 已知限制

- 双机链路查不到（另一台机器采集+识别）
- 硬件转发查不到（KMBox 类设备在主机看就是标准 HID）
- 内核隐藏模块查不到（用户态枚举不到被摘链的模块）
- 非管理员运行覆盖不完整（报告会标 `partialCoverage`）

---

作者：Tone Wang · 2802165750@qq.com
```

## 5. 一句话 slogan（可选，放 README 顶部或仓库简介）

```
See the traces a cheat leaves behind — without touching the game.
```

```
看见外挂留下的痕迹，而不去碰游戏本身。
```

## 6. 仓库名建议

```
eagle-eye
```

## 7. 社交预览图文字（GitHub Settings → Social preview）

```
Eagle Eye
Read-only local anti-cheat scanner for Windows
```