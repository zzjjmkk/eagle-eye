namespace EagleEye.Models;

/// <summary>
/// 视觉外挂线索规则。
/// tier：
///   strong  —— 特异性高的模块（推理运行时 / CV 库 / 采集 hook），单独出现即可成条；
///   context —— 通用图形模块（gdi32/dxgi/d3d11），几乎所有 GUI 程序都加载，
///              只作为加权上下文，不单独成条（否则一台机器几百条噪音）。
/// </summary>
public sealed class VisionRule
{
    public string Id { get; set; } = "";
    public string Tier { get; set; } = "strong";
    public string? Pattern { get; set; }
    public string? Match { get; set; }
    public string? Category { get; set; }

    // 硬件规则字段
    public string? VendorId { get; set; }
    public string? DeviceId { get; set; }
    public string? DeviceClass { get; set; }
    public string? Service { get; set; }

    public int Severity { get; set; } = 1;
    public double Confidence { get; set; } = 0.2;
    public string? Description { get; set; }
    public string? Advice { get; set; }
    public bool Enabled { get; set; } = true;
}

public sealed class VisionWhitelistEntry
{
    public string? ProcessPattern { get; set; }
    public string? Match { get; set; }
    public string? VendorId { get; set; }
    public string? DeviceId { get; set; }
    public string? Reason { get; set; }
    public string? Expires { get; set; }
}

public sealed class VisionBehaviorOptions
{
    /// <summary>默认关闭：行为统计误报面最大，仅在有游戏侧遥测可比对时开启。</summary>
    public bool Enabled { get; set; }
    public int DurationMs { get; set; } = 3000;
    public int SampleMs { get; set; } = 16;
    public int MinSamples { get; set; } = 50;
    public double StraightLineRatio { get; set; } = 0.85;
    public double ConstantVelocityRatio { get; set; } = 0.80;
    public double ZeroDeltaRatio { get; set; } = 0.60;
}

public sealed class VisionAggregationOptions
{
    /// <summary>本地判定上限，不得高于「可疑」。</summary>
    public string MaxLevel { get; set; } = RiskLevels.Suspicious;
    public int RequireIndependentLayers { get; set; } = 2;
}

public sealed class VisionCaptureSection
{
    public bool Enabled { get; set; } = true;
    public List<VisionRule> ModuleRules { get; set; } = new();
}

public sealed class VisionHardwareSection
{
    public bool Enabled { get; set; } = true;
    public List<VisionRule> Rules { get; set; } = new();
}

public sealed class VisionSection
{
    public bool Enabled { get; set; } = true;
    public VisionCaptureSection Capture { get; set; } = new();
    public VisionHardwareSection Hardware { get; set; } = new();
    public List<VisionWhitelistEntry> Whitelist { get; set; } = new();
    public VisionBehaviorOptions Behavior { get; set; } = new();
    public VisionAggregationOptions Aggregation { get; set; } = new();
}

/// <summary>一条视觉外挂线索。始终 NeedsTelemetry=true：本地线索不等于判定。</summary>
public sealed class VisionIndicator
{
    public string Id { get; set; } = "";
    /// <summary>capture | hardware | behavior</summary>
    public string Layer { get; set; } = "";
    /// <summary>capture_client | inference_runtime | cv_library | video_capture | hid_injector | input_mapper</summary>
    public string? Category { get; set; }
    public string Target { get; set; } = "";
    public int? Pid { get; set; }
    public string? Path { get; set; }
    public string? SignatureState { get; set; }
    public string? CommandLineSummary { get; set; }
    public List<string> MatchedModules { get; set; } = new();
    public int Severity { get; set; }
    public double Confidence { get; set; }
    public double Score { get; set; }
    public string RiskLevel { get; set; } = RiskLevels.Info;
    public string Description { get; set; } = "";
    public string? Advice { get; set; }
    public bool Suppressed { get; set; }
    public string? SuppressReason { get; set; }
    public bool NeedsTelemetry { get; set; } = true;
    public Dictionary<string, object?> Evidence { get; set; } = new();
}

/// <summary>行为侧统计摘要：只保留聚合值，不保留任何坐标轨迹。</summary>
public sealed class VisionBehavioralHint
{
    public bool Collected { get; set; }
    public string? SkipReason { get; set; }
    public int SampleCount { get; set; }
    public int DurationMs { get; set; }
    public double StraightLineRatio { get; set; }
    public double ConstantVelocityRatio { get; set; }
    public double ZeroDeltaRatio { get; set; }
    public double AverageSpeedPxPerSec { get; set; }
    public double SpeedStdDev { get; set; }
    public int Severity { get; set; } = 1;
    public double Confidence { get; set; } = 0.1;
    public string Description { get; set; } = "";
    public string Note { get; set; } =
        "信息级提示：仅由 GetCursorPos 轮询得到的聚合统计，无原始轨迹、无 Hook、不关联具体游戏，不构成判定依据。";
}

public sealed class VisionReport
{
    public bool Enabled { get; set; }
    public string Note { get; set; } =
        "双机+外部采集+硬件注入链路在本机用户态无法独立确证，以下为可观测线索，不代表最终判定。";
    public List<VisionIndicator> SoftwareCapture { get; set; } = new();
    public List<VisionIndicator> HardwareIndicators { get; set; } = new();
    public VisionBehavioralHint BehavioralHint { get; set; } = new();
    public Dictionary<string, int> LayerSummary { get; set; } = new();
    public int IndependentLayers { get; set; }
    public string HighestLevel { get; set; } = RiskLevels.Info;
    public bool LevelCapped { get; set; } = true;
    public List<string> Notes { get; set; } = new();
}