# Eagle Eye

[English](README.en.md) | 简体中文

> **作者**：Tone Wang　·　**联系**：2802165750@qq.com

> 本地反外挂**只读**查询工具 —— Windows x64 命令行程序。查本机有没有外挂痕迹，出一份带证据链的报告。

不给游戏注入、不读游戏内存、不 Hook、不截屏、不联网。
所有结论都是"线索 + 置信度"，不是"判决"。

---

## 它解决什么问题

玩家举报"这人像外挂"，但你手上只有一台机器。Eagle Eye 把这台机器上**可观测的痕迹**全捞一遍：
哪些进程在跑、谁打开了游戏进程、加载了什么驱动、有没有注入模块、有没有叠加窗口、插了什么采集/HID 设备，
然后按证据强度排出复核优先级。

双机链路、外接采集卡、硬件转发这类**本机没有痕迹**的情况，工具会明确告诉你"查不到"，而不是假装干净。

---

## 快速开始

1. 下载 Release 里的 `EagleEye-v1.0.0-win-x64.zip`，解压
2. **以管理员身份**打开 PowerShell（不提权读不到游戏等受保护进程）
3. 自检 → 扫描：

```powershell
cd <解压目录>

.\EagleEye.exe selftest      # 9 项环境自检，全 PASS 才开始
.\EagleEye.exe scan          # 完整扫描
```

结果：`out\reports\scan-<时间>.json` + `.html`（HTML 双击就能看），日志在 `out\logs\`。

其他命令：

```powershell
.\EagleEye.exe scan --no-files            # 快扫（跳过文件遍历）
.\EagleEye.exe scan --profile deep        # 深扫（+文件特征码 +输入统计）
.\EagleEye.exe validate                   # 只校验规则
.\EagleEye.exe aggregate --dir <目录> --tune   # 多机汇总 + 自动调参
```

---

## 检测能力

| 层 | 内容 | 需要样本 | 强度 |
|---|---|---|---|
| **句柄** | 谁以 `VM_READ/VM_WRITE/CREATE_THREAD` 打开了游戏进程 | ❌ | ★★★★★ |
| **驱动** | 已加载内核驱动：黑名单 + 白名单模式（非受信任签名全报） | ❌ | ★★★★ |
| **注入痕迹** | 游戏进程里"磁盘上不存在 / 路径异常 / 无签名"的模块 | ❌ | ★★★★ |
| **进程/模块/签名** | 名称、路径、命令行、加载模块、Authenticode | ❌ | ★★★ |
| **叠加窗口** | 透明置顶窗口覆盖在游戏之上（ESP 常见形态） | ❌ | ★★★ |
| **视觉链路** | 可见窗口 + 推理运行时/采集 hook 模块 | ❌ | ★★★ |
| **DMA 外设** | PCIe 设备枚举（VID/PID/类/服务），可选一次性只读驱动读配置空间 | ❌ | ★★★ |
| **文件** | 目录只读遍历 + SHA256 名单 + 字节特征码 | 部分 | ★★★ |
| **游戏侧遥测** | 隔墙预瞄比、跟枪抖动、反应时分布等（导入离线 JSON） | ❌ | ★★★★★ |
| **命名规则** | 进程名/文件名启发式（如 `*三角洲*辅助*`） | ❌ | ★ |

前 8 层都不需要样本哈希 —— 外挂要生效就必须打开游戏进程、加载驱动、注入模块，这些是**结构性痕迹**，改名字躲不掉。

---

## 风险等级

```
单条得分 = severity(1-5) × 20 × confidence(0-1) × 分类权重
同目标累加封顶 100；强信号(sev≥4 且 ≥70)直判；≥3 个弱信号可升级为可疑
0-39 信息 / 40-69 可疑 / 70-100 高度可疑
```

白名单命中 **抑制**（不参与计分），但保留记录并注明原因，可追溯、可复审。

---

## 报告

- **JSON**：机器读，含每条命中的完整 evidence
- **HTML**：单文件内联 CSS，**零外部引用**，断网双击可看
- **审计日志**（JSONL）：每个进程的打开请求与访问掩码、验签次数、驱动加载/卸载、无网络访问

没查到的东西会明确写进 `notChecked`：**没查到 ≠ 干净**。

---

## 规则

外置 JSON，`rules\` 目录整体加载并按 id 合并，改规则不用重编译。

```
rules\
├─ rules.json              主规则（进程/路径/模块/签名/文件/DMA/句柄/驱动/注入）
├─ rules.delta-force.json  三角洲行动专项（20 条）
├─ rules.intel.json        命名情报规则（75 条）
└─ tuning.suggested.json   调参产物（自动生成，可选）
```

配套工具：

| 工具 | 用途 |
|---|---|
| `tools\hashgen.ps1` | 样本目录 → SHA256 规则包 |
| `tools\intel-to-rules.ps1` | 关键词/网页文本 → 规则 |
| `tools\tune-thresholds.ps1` | 误报调参（也可用 `EagleEye.exe tune`） |
| `tools\collect-game-info.ps1` | 现场采集游戏进程基线 |
| `tools\audit-policy.ps1` | 红线自检（18 项） |
| `tools\package.ps1` | 一键打包 |

---

## 红线（可机器校验）

```powershell
powershell -File tools\audit-policy.ps1
```

18 项全部 PASS 才能发布。校验内容：无注入、无内存读写、无 Hook、无驱动隐藏、无提权、无关闭 HVCI、
驱动只发 `IRP_MN_READ_CONFIG`、规则都有 description、报告命中都有证据、无网络访问……

脚本会先剥离注释再匹配关键词，避免误报。

---

## 从源码构建

需要 .NET 8 SDK：

```powershell
dotnet build src\EagleEye\EagleEye.csproj -c Release

# 打包自包含单文件（目标机无需 .NET）
powershell -File tools\package.ps1
```

内核驱动（可选，仅诊断机）用 WDK 编译，见 `native\pciecfg\build.md`。

---

## 仓库结构

```
src\EagleEye\        C# 源码（约 7500 行）
native\pciecfg\      一次性只读 PCIe 配置空间驱动（WDM/C++）
rules\               规则包
tools\               运维脚本
docs\                设计文档（架构/规则 Schema/兼容性矩阵/风险说明）
samples\             测试夹具
```

---

## 已知限制

- **双机链路查不到**：另一台机器采集+识别，本机只有"正常鼠标输入"
- **硬件转发查不到**：KMBox 类设备在主机看就是标准 HID
- **内核隐藏查不到**：模块被摘链后用户态枚举不到
- **非管理员覆盖不完整**：受 ACE 等保护的进程读不到，报告会标 `partialCoverage`
- **命名规则很弱**：改个文件名就绕过，只作线索

---

## 许可

MIT，见 [LICENSE](LICENSE)。

---

## 免责

本工具仅用于**自有设备或已获授权的设备**的本地安全检查，只读、不上传任何数据。
请遵守当地法律与游戏服务条款。
---

## 联系

- 作者：Tone Wang
- 邮箱：2802165750@qq.com
- 问题反馈 / 功能建议：发邮件或提 Issue
