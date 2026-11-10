namespace EagleEye.Models;

public static class RuleTypes
{
    public const string ProcessName = "process_name";
    public const string ProcessPath = "process_path";
    public const string ProcessCommandLine = "process_command_line";
    public const string ModuleName = "module_name";
    public const string FileName = "file_name";
    public const string FileHash = "file_hash";
    public const string Signature = "signature";
}

public static class SignaturePatterns
{
    public const string Unsigned = "unsigned";
    public const string BadDigest = "bad_digest";
    public const string UntrustedRoot = "untrusted_root";
    public const string Expired = "expired";
    public const string Revoked = "revoked";
    public const string CatalogOnly = "catalog_only";
    public const string AnyInvalid = "any_invalid";
}

/// <summary>规则分类：用于报告分组、统计与权重。</summary>
public sealed class RuleCategory
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    /// <summary>分类权重，乘进单条得分；默认 1.0。</summary>
    public double Weight { get; set; } = 1.0;
}

public sealed class RuleMeta
{
    public string Name { get; set; } = "";
    /// <summary>规则内容版本，如 1.3.0。</summary>
    public string Version { get; set; } = "1.0.0";
    /// <summary>规则内容更新时间，ISO 日期或 ISO 8601。</summary>
    public string? Updated { get; set; }
    /// <summary>格式版本，用于兼容性判断。</summary>
    public string SchemaVersion { get; set; } = "2.0";
    public string? Author { get; set; }
    public string? Description { get; set; }
    public List<RuleCategory> Categories { get; set; } = new();
}

public sealed class Rule
{
    public string Id { get; set; } = "";
    public string Type { get; set; } = "";
    /// <summary>规则分类 id，对应 meta.categories[].id。</summary>
    public string? Category { get; set; }
    public string? Pattern { get; set; }
    public int Severity { get; set; } = 3;
    public double Confidence { get; set; } = 0.7;
    public string? Description { get; set; }
    /// <summary>exact | glob | contains | regex，默认 glob。</summary>
    public string? Match { get; set; }
    /// <summary>file_hash 专用：期望的 SHA256 十六进制。</summary>
    public string? Hash { get; set; }
    /// <summary>file_hash 可选预筛：文件大小（字节）。</summary>
    public long? Size { get; set; }
    public bool Enabled { get; set; } = true;
    public string? Advice { get; set; }
    public string[]? Tags { get; set; }
}

public sealed class WhitelistEntry
{
    public string? Pattern { get; set; }
    public string? Hash { get; set; }
    public string? SubjectContains { get; set; }
    public string? Match { get; set; }
    public string? Reason { get; set; }
    public string? Expires { get; set; }
    /// <summary>可选：只抑制这些规则 id；为空表示抑制该目标上全部规则命中。</summary>
    public string[]? SuppressRules { get; set; }
}

public sealed class Whitelist
{
    public List<WhitelistEntry> Processes { get; set; } = new();
    public List<WhitelistEntry> Paths { get; set; } = new();
    public List<WhitelistEntry> Files { get; set; } = new();
    public List<WhitelistEntry> Signers { get; set; } = new();
}

public sealed class ScanOptionsConfig
{
    public List<string> ScanRoots { get; set; } = new();
    public List<string> IncludeExtensions { get; set; } = new() { ".exe", ".dll", ".sys" };
    public int MaxFiles { get; set; } = 20000;
    public int MaxDepth { get; set; } = 6;
    public long MaxFileSizeBytes { get; set; } = 268435456;
    public int MaxHashFiles { get; set; } = 3000;
}

public sealed class RuleSet
{
    public RuleMeta Meta { get; set; } = new();
    public List<Rule> Rules { get; set; } = new();
    public Whitelist Whitelist { get; set; } = new();
    public ScanOptionsConfig Options { get; set; } = new();
    /// <summary>DMA 外设（用户态初筛）规则段。</summary>
    public DmaSection Dma { get; set; } = new();
    /// <summary>AI 视觉外挂线索规则段。</summary>
    public VisionSection Vision { get; set; } = new();
    /// <summary>深度扫描：句柄 / 驱动 / overlay / 文件特征码。</summary>
    public DeepSection Deep { get; set; } = new();
    /// <summary>游戏侧遥测对接（离线文件）。</summary>
    public TelemetrySection Telemetry { get; set; } = new();
}