using EagleEye.Core;

namespace EagleEye.Models;

public sealed class RuleSetSummary
{
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public string? Updated { get; set; }
    public string? SchemaVersion { get; set; }
    public string? Path { get; set; }
    public int RuleCount { get; set; }
    public int EnabledRuleCount { get; set; }
    public int WhitelistCount { get; set; }
    public List<string> Categories { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
}

public sealed class ScanSummary
{
    public int ProcessesScanned { get; set; }
    public int FilesScanned { get; set; }
    public int FilesHashed { get; set; }
    public int Findings { get; set; }
    public int SuppressedFindings { get; set; }
    public double TotalScore { get; set; }
    public double SumScore { get; set; }
    public string RiskLevel { get; set; } = RiskLevels.Info;
    public Dictionary<string, int> ByRiskLevel { get; set; } = new();
    public int NotCheckedCount { get; set; }
    public int AssessedTargets { get; set; }
    public bool FileScanEnabled { get; set; }
    public int DmaDevicesEnumerated { get; set; }
    public int DmaPciDevices { get; set; }
    public int DmaFindings { get; set; }
    public string DmaRiskLevel { get; set; } = RiskLevels.Info;
    public bool DmaKernelLoaded { get; set; }
    public int VisionSoftwareIndicators { get; set; }
    public int VisionHardwareIndicators { get; set; }
    public string VisionLevel { get; set; } = RiskLevels.Info;
    public int HandleFindings { get; set; }
    public int DriverFindings { get; set; }
    public int FileSignatureHits { get; set; }
    public int OverlayIndicators { get; set; }
    public bool TelemetryLoaded { get; set; }
    /// <summary>非管理员运行：受保护进程（含游戏本体）读不到，覆盖不完整。</summary>
    public bool PartialCoverage { get; set; }
    public int UnreadableTargets { get; set; }
    public string TelemetryJointLevel { get; set; } = RiskLevels.Info;
}

/// <summary>扫描器自身行为摘要（详细记录在同目录的 audit JSONL 里）。</summary>
public sealed class AuditSummary
{
    public string? LogPath { get; set; }
    public int ProcessOpenAttempts { get; set; }
    public int ProcessOpenDenied { get; set; }
    public int SignatureChecks { get; set; }
    public int DriverLoadAttempts { get; set; }
    public bool DriverLoaded { get; set; }
    public bool DriverUnloaded { get; set; }
    /// <summary>本次扫描新写入验签缓存的条目数。</summary>
    public int SignatureCacheNew { get; set; }
    /// <summary>验签缓存总条目数。</summary>
    public int SignatureCacheSize { get; set; }
    /// <summary>恒为 false：工具不发起任何网络请求。</summary>
    public bool NetworkUsed { get; set; }
}

public sealed class ScanReport
{
    public string Tool { get; set; } = "EagleEye";
    public string Version { get; set; } = "2.0.0";
    public string ScanStartedUtc { get; set; } = "";
    public string ScanFinishedUtc { get; set; } = "";
    public double DurationSeconds { get; set; }
    public string Machine { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public string UserName { get; set; } = "";
    public bool IsElevated { get; set; }

    public RuleSetSummary Ruleset { get; set; } = new();
    public ScanSummary Summary { get; set; } = new();
    public AuditSummary Audit { get; set; } = new();

    /// <summary>参与风险聚合的命中（已排除白名单抑制项）。</summary>
    public List<Finding> Findings { get; set; } = new();
    /// <summary>被白名单抑制的命中，仅留痕，不参与评分。</summary>
    public List<Finding> SuppressedFindings { get; set; } = new();
    /// <summary>按目标聚合后的判定与证据链。</summary>
    public List<TargetAssessment> Assessments { get; set; } = new();

    public List<NotChecked> NotChecked { get; set; } = new();
    public List<DmaFinding> DmaUserModeFindings { get; set; } = new();
    /// <summary>视觉外挂线索（采集端/硬件/行为），独立成段，不进入主 risk_score。</summary>
    public VisionReport VisionCheatIndicators { get; set; } = new();
    /// <summary>句柄线索（谁以 VM_READ/WRITE 打开了目标进程）。</summary>
    public HandleScanReport Handles { get; set; } = new();
    /// <summary>已加载驱动线索。</summary>
    public DriverScanReport Drivers { get; set; } = new();
    /// <summary>文件特征码命中。</summary>
    public FileSignatureReport FileSignatures { get; set; } = new();
    /// <summary>注入痕迹：游戏进程里不在磁盘/路径异常/无签名的模块。</summary>
    public List<InjectionFindingInfo> InjectionTraces { get; set; } = new();
    /// <summary>游戏侧遥测与本机线索的联合评估。</summary>
    public TelemetryReport Telemetry { get; set; } = new();
    public DmaReport Dma { get; set; } = new();
    public List<ProcessRecord>? Processes { get; set; }
}