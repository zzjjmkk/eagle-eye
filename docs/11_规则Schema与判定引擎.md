# 设计 02：JSON 规则 Schema 与判定引擎

## 一、文件组织

规则可拆成多文件，启动时按 `meta.updated` 读入、按 `id` 去重（后加载覆盖先加载）：

```
rules\schema\rules.schema.json   规则格式定义（draft-07）
rules\rules.example.json         完整示例，可直接当模板
rules\rules.process.json         进程/模块/签名/组合
rules\rules.file.json            目录、扩展名、哈希名单
rules\rules.dma.json             VID/DID、PCIe 异常条件
rules\whitelist.json             进程/签名/文件/设备白名单（带过期时间）
```

校验方式：`AntiCheatProbe.Rules` 用 `JsonSchema.Net` 在加载时校验，校验失败**拒绝启动**并打印具体路径（`process.nameRules[3].severity`），避免规则写错导致误判。

## 二、Schema 结构（实际文件见 `rules\schema\rules.schema.json`）

```
ruleset
├─ meta            name / version / updated / author
├─ settings
│  ├─ thresholds   suspicious=40, high=70
│  ├─ categoryWeights  每类权重
│  ├─ protectedProcessPolicy  skip | minimal | report-only
│  └─ maxScanSeconds / hashCacheEnabled / reportLanguage
├─ process
│  ├─ nameRules        进程名（exact/glob/regex/contains）
│  ├─ pathRules        映像路径 / 工作目录 / 模块路径
│  ├─ commandLineRules 命令行子串或模式
│  ├─ moduleRules      已加载模块名（已知作弊 DLL）
│  ├─ parentRules      父进程特征
│  ├─ signatureRules   unsigned / invalid-chain / expired / revoked / catalog-only / signer-blacklisted
│  ├─ portRules        监听/连接端口，可绑定到某条进程规则
│  └─ compositeRules   allOf / anyOf / noneOf + boost（组合信号）
├─ file
│  ├─ scanRoots        支持 %ENV% 展开
│  ├─ includeExtensions / excludeGlobs / limits
│  ├─ nameRules        文件名规则
│  └─ hashRules        SHA256 名单（带 sizeBytes 快速预筛）
├─ dma
│  ├─ vidPidRules      Vendor ID + Device ID 列表
│  ├─ pcieAnomalyRules BAR 大小 / Class Code / Capability / MSI / Revision 等条件
│  └─ kernelEnum       驱动服务名、设备路径、超时、自动卸载、失败策略
└─ whitelist        processes / signers / files / dma / paths（均可带 expires）
```

## 三、核心字段语义

| 字段 | 类型 | 含义 |
|---|---|---|
| `id` | string | `[:lower:]` 点分，如 `proc.cheatengine`；组合规则靠它引用 |
| `severity` | 1-5 | 1 提示 / 2 低 / 3 中 / 4 高 / 5 确定 |
| `confidence` | 0-1 | 该信号本身的可靠度，用于乘算，避免"名字像就判死" |
| `category` | string | `tool.cheatengine`、`dll.cheat`、`dma` 等，便于统计 |
| `enabled` | bool | 灰度开关，方便线上关单条规则 |
| `advice` | string | 直接写进报告，告诉人工复核该看什么 |
| `match.match` | enum | `exact` / `glob` / `regex` / `contains`，默认 glob、忽略大小写 |

## 四、判定引擎

### 4.1 单条计分

```
score(rule) = severity * 20 * confidence * categoryWeight
```

5 级、置信 1.0、权重 1.0 → 100 分（满分），保证"确定"级单条即可顶格。

### 4.2 组合规则（吸收组合信号，抑制单特征误报）

```json
{ "id": "comp.cheat_tool_unsigned", "severity": 5, "boost": 25,
  "allOf": ["proc.cheatengine", "sig.unsigned"] }
```

- `allOf`：全部命中才计（进程规则 + 签名规则 + 端口规则）
- `anyOf`：任一命中即计，用于"多个弱信号之一"
- `noneOf`：命中则本条作废（例如已存在合法白名单签名时）
- `boost`：命中后额外加分，`allOf` 里每条子规则的分照常计入

判定顺序：先算全部单条 → 再叠加组合 boost → 再套白名单衰减 → 最后归一化。

### 4.3 归一化与风险等级

```
raw   = Σ 单条分 + Σ 组合 boost
score = min(100, raw)                       // 单调，不做平均，避免"命中越多分越低"
```

| 分数 | 等级 | 报告措辞 |
|---|---|---|
| 0-39 | 信息 | "未发现明显异常" / 单条低置信提示，仅记录 |
| 40-69 | 可疑 | "检测到需要人工确认的软件或配置" |
| 70-100 | 高度可疑 | "检测到与已知外挂特征高度一致的组合" |

**措辞纪律**：报告只输出"检测到 X 特征"，不输出"该玩家作弊"。等级是给复核人排序用的，不是判决。

### 4.4 白名单衰减

- 进程白名单按 `pattern` + 可选 `sha256` 双条件命中（只写 pattern 表示"同名即放过"，需谨慎使用）
- 带 `expires` 的过期后自动失效，下次启动打印"白名单已过期 N 条"
- 命中白名单不是删除 Finding，而是 `confidence *= 0.2` 并在报告里标 `whitelisted: true, reason: ...`，保证可审计

### 4.5 去重

同一 `(detectorId, target)` 只保留最高分一条；同进程多模块命中合并为一条 `dll.cheat` 聚合 Finding，`evidence.modules[]` 列出全部。

## 五、误报控制清单

1. 名字类规则默认 `confidence <= 0.7`，单靠它到不了"高度可疑"
2. 端口规则必须 `requireProcessRule` 绑定，防止 4000/8080 这类常见端口误伤
3. 签名规则区分 `catalog-only`（Windows 组件常态，severity 1）
4. 路径规则只做"降权/提示"，不单独定级
5. 每个 Finding 必须带 `evidence`（原始字符串、哈希、VID/DID、注册表键），能复现
6. `tests\fixtures` 存历史误报快照，回归时逐条比对