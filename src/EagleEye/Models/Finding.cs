namespace EagleEye.Models;

public sealed class Finding
{
    public string RuleId { get; set; } = "";
    public string RuleType { get; set; } = "";
    /// <summary>规则分类（对应 meta.categories[].id）。</summary>
    public string? Category { get; set; }
    public string Target { get; set; } = "";
    public string? TargetPath { get; set; }
    public int? Pid { get; set; }
    public int Severity { get; set; }
    public double Confidence { get; set; }
    public double Score { get; set; }
    /// <summary>信息 / 可疑 / 高度可疑</summary>
    public string RiskLevel { get; set; } = RiskLevels.Info;
    public string Description { get; set; } = "";
    public string? Advice { get; set; }
    public Dictionary<string, object?> Evidence { get; set; } = new();

    /// <summary>被白名单抑制：不参与风险聚合，但保留记录以便追溯。</summary>
    public bool Suppressed { get; set; }
    public string? SuppressReason { get; set; }
    /// <summary>抑制来源（白名单条目原文）。</summary>
    public string? SuppressedBy { get; set; }
}

public static class RiskLevels
{
    public const string Info = "信息";
    public const string Suspicious = "可疑";
    public const string High = "高度可疑";
}

public sealed class NotChecked
{
    public string Target { get; set; } = "";
    public string? Path { get; set; }
    public int? Pid { get; set; }
    public string Reason { get; set; } = "";
}