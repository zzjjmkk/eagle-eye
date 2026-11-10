namespace EagleEye.Models;

/// <summary>游戏侧导出的遥测文件（离线文件，不由本工具联网拉取）。</summary>
public sealed class TelemetryFile
{
    public string SchemaVersion { get; set; } = "1.0";
    public string? ExportedBy { get; set; }
    public string? ExportedUtc { get; set; }
    public List<TelemetrySession> Sessions { get; set; } = new();
}

public sealed class TelemetrySession
{
    public string SessionId { get; set; } = "";
    public string? MatchId { get; set; }
    public string? PlayerId { get; set; }
    public string? AccountName { get; set; }
    public string? StartedUtc { get; set; }
    public int DurationSeconds { get; set; }
    /// <summary>指标名 → 数值。指标名由规则里的 metric 字段引用。</summary>
    public Dictionary<string, double> Metrics { get; set; } = new();
}

/// <summary>一条遥测判定规则：metric 与 threshold 比较。</summary>
public sealed class TelemetrySignalRule
{
    public string Id { get; set; } = "";
    public string Metric { get; set; } = "";
    /// <summary>gte / lte</summary>
    public string Comparator { get; set; } = "gte";
    public double Threshold { get; set; }
    public int Severity { get; set; } = 3;
    public double Confidence { get; set; } = 0.5;
    public string? Description { get; set; }
    public string? Advice { get; set; }
    public bool Enabled { get; set; } = true;
}

public sealed class TelemetrySection
{
    public bool Enabled { get; set; } = true;
    /// <summary>人群基线，用于给出"高出基线多少"的解释。</summary>
    public Dictionary<string, double> Baseline { get; set; } = new();
    public List<TelemetrySignalRule> Signals { get; set; } = new();
    /// <summary>本地与遥测同时命中时的联合等级上限。</summary>
    public string BothSidesLevel { get; set; } = RiskLevels.High;
}

public sealed class TelemetrySignal
{
    public string RuleId { get; set; } = "";
    public string Metric { get; set; } = "";
    public string Description { get; set; } = "";
    public double Value { get; set; }
    public double Threshold { get; set; }
    public double Baseline { get; set; }
    public bool BaselineKnown { get; set; }
    public int Severity { get; set; }
    public double Confidence { get; set; }
    public double Score { get; set; }
    public string RiskLevel { get; set; } = RiskLevels.Info;
    public string? Advice { get; set; }
}

public sealed class SessionAssessment
{
    public string SessionId { get; set; } = "";
    public string? MatchId { get; set; }
    public string? PlayerId { get; set; }
    public string? AccountName { get; set; }
    public string? StartedUtc { get; set; }
    public int DurationSeconds { get; set; }
    public List<TelemetrySignal> Signals { get; set; } = new();
    public double TelemetryScore { get; set; }
    public string TelemetryLevel { get; set; } = RiskLevels.Info;
    public List<string> Reasons { get; set; } = new();
}

public sealed class TelemetryReport
{
    public bool Enabled { get; set; }
    public bool Loaded { get; set; }
    public string? SourcePath { get; set; }
    public string? Error { get; set; }
    public string? SchemaVersion { get; set; }
    public string? ExportedUtc { get; set; }
    public int Sessions { get; set; }
    public List<SessionAssessment> Assessments { get; set; } = new();

    /// <summary>本机侧（进程/文件/DMA/视觉/句柄/驱动）的等级。</summary>
    public string LocalLevel { get; set; } = RiskLevels.Info;
    /// <summary>联合后的建议等级。</summary>
    public string JointLevel { get; set; } = RiskLevels.Info;
    public double JointScore { get; set; }
    public List<string> JointReasons { get; set; } = new();

    public string Note { get; set; } =
        "遥测只能反映行为异常，本地只能反映痕迹；两者单独都不构成判定。" +
        "遥测异常但本机干净，高度指向双机/硬件链路或外部采集；本地有痕迹但行为正常，可能是误装或被利用的工具。" +
        "联合结论用于排序复核优先级，最终认定仍需人工复核与取证。";
}