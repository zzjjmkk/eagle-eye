namespace EagleEye.Models;

/// <summary>句柄线索规则：谁以高权限打开了目标进程。</summary>
public sealed class HandleRule
{
    public string Id { get; set; } = "";
    public string? Category { get; set; } = "handle";
    /// <summary>目标进程名模式（glob），如 "*game*"、"*"。</summary>
    public string? TargetProcessPattern { get; set; }
    /// <summary>命中哪些访问权限即算一条，十六进制字符串。</summary>
    public string[]? AccessMaskAny { get; set; }
    public int Severity { get; set; } = 3;
    public double Confidence { get; set; } = 0.5;
    public string? Description { get; set; }
    public string? Advice { get; set; }
    public bool Enabled { get; set; } = true;
}

public sealed class HandleScanOptions
{
    public bool Enabled { get; set; } = true;
    public List<HandleRule> Rules { get; set; } = new();
    /// <summary>持有者白名单（进程名 glob），如系统组件、杀软。</summary>
    public List<string> HolderWhitelist { get; set; } = new();
    /// <summary>目标白名单（进程名 glob）。</summary>
    public List<string> TargetWhitelist { get; set; } = new();
}

/// <summary>驱动线索规则。</summary>
public sealed class DriverRule
{
    public string Id { get; set; } = "";
    public string? Category { get; set; } = "driver";
    /// <summary>驱动文件名 glob，如 "dbk64.sys"。</summary>
    public string? Pattern { get; set; }
    public string? Sha256 { get; set; }
    public int Severity { get; set; } = 4;
    public double Confidence { get; set; } = 0.7;
    public string? Description { get; set; }
    public string? Advice { get; set; }
    public bool Enabled { get; set; } = true;
}

public sealed class DriverScanOptions
{
    public bool Enabled { get; set; } = true;
    public List<DriverRule> Rules { get; set; } = new();

    /// <summary>白名单模式：不在规则里、又不是受信任签名的驱动，单独上报（无样本也能查）。</summary>
    public bool WhitelistMode { get; set; } = true;
    public List<string> TrustedSigners { get; set; } = new();
    public int UntrustedSeverity { get; set; } = 3;
    public double UntrustedConfidence { get; set; } = 0.45;
    /// <summary>对这些路径前缀之外的驱动做验签（默认只验规则命中项）。</summary>
    public List<string> SignatureWhitelistPaths { get; set; } = new();
}

public sealed class OverlayScanOptions
{
    public bool Enabled { get; set; } = true;
    /// <summary>overlay 面积 / 被覆盖窗口面积 的最小比例。</summary>
    public double MinAreaRatio { get; set; } = 0.4;
    public int MinWidth { get; set; } = 320;
    public int MinHeight { get; set; } = 240;
    public int Severity { get; set; } = 2;
    public double Confidence { get; set; } = 0.45;
}

/// <summary>文件特征码规则（只读前 N 字节做字节/ASCII 匹配）。</summary>
public sealed class FileSignatureRule
{
    public string Id { get; set; } = "";
    /// <summary>ascii | hex</summary>
    public string PatternType { get; set; } = "ascii";
    public string Pattern { get; set; } = "";
    public int Severity { get; set; } = 4;
    public double Confidence { get; set; } = 0.6;
    public string? Description { get; set; }
    public bool Enabled { get; set; } = true;
}

public sealed class FileSignatureOptions
{
    public bool Enabled { get; set; }
    public int MaxFiles { get; set; } = 2000;
    public int MaxBytesPerFile { get; set; } = 2097152;
    public List<string> IncludeExtensions { get; set; } = new() { ".dll", ".exe", ".sys" };
    public List<FileSignatureRule> Rules { get; set; } = new();
}

/// <summary>注入痕迹：游戏进程里的模块不在磁盘 / 路径异常 / 无签名（不需要样本哈希）。</summary>
public sealed class InjectionScanOptions
{
    public bool Enabled { get; set; } = true;
    public List<string> TargetProcessPatterns { get; set; } = new();
    public List<string> ModuleWhitelist { get; set; } = new();
    public int MissingFileSeverity { get; set; } = 5;
    public int SuspiciousPathSeverity { get; set; } = 4;
    public int UnsignedSeverity { get; set; } = 2;
}

public sealed class InjectionFindingInfo
{
    public string Target { get; set; } = "";
    public int Pid { get; set; }
    public string Module { get; set; } = "";
    public string? ModulePath { get; set; }
    public string Reason { get; set; } = "";
    public string? SignatureState { get; set; }
}

public sealed class DeepSection
{
    public HandleScanOptions Handles { get; set; } = new();
    public DriverScanOptions Drivers { get; set; } = new();
    public OverlayScanOptions Overlay { get; set; } = new();
    public FileSignatureOptions FileSignatures { get; set; } = new();
    public InjectionScanOptions Injection { get; set; } = new();
}

public sealed class HandleHolder
{
    public int HolderPid { get; set; }
    public string? HolderName { get; set; }
    public string? HolderPath { get; set; }
    public string? HolderSignature { get; set; }
    public int TargetPid { get; set; }
    public string? TargetName { get; set; }
    public string? AccessMask { get; set; }
    public List<string> AccessRights { get; set; } = new();
}

public sealed class HandleScanReport
{
    public bool Enabled { get; set; }
    public bool Attempted { get; set; }
    public string? Error { get; set; }
    public int HandlesEnumerated { get; set; }
    public int HighAccessHandles { get; set; }
    public int HoldersChecked { get; set; }
    /// <summary>目标进程已退出/不可查，且持有者是有效签名进程 + ALL_ACCESS（典型的 CreateProcess 子进程），已跳过。</summary>
    public int SkippedUnresolvedPairs { get; set; }
    /// <summary>目标进程不在快照里（已退出/ACE 拉起），只记录不告警。</summary>
    public int UnresolvedTargets { get; set; }
    public List<HandleHolder> Holders { get; set; } = new();
    public string Note { get; set; } =
        "只读枚举：仅查询系统句柄表并复制句柄读取目标 PID，不读取任何进程内存、不拦截任何操作。";
}

public sealed class LoadedDriverInfo
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public long ImageBase { get; set; }
    public uint ImageSize { get; set; }
    public string? SignatureState { get; set; }
    public string? Signer { get; set; }
    public string? MatchedRuleId { get; set; }
}

public sealed class DriverScanReport
{
    public bool Enabled { get; set; }
    public bool Attempted { get; set; }
    public string? Error { get; set; }
    public int DriversEnumerated { get; set; }
    public int UnsignedDrivers { get; set; }
    public List<LoadedDriverInfo> Suspicious { get; set; } = new();
}

public sealed class FileSignatureHit
{
    public string RuleId { get; set; } = "";
    public string FileName { get; set; } = "";
    public string Path { get; set; } = "";
    public long Size { get; set; }
    public string? Sha256 { get; set; }
    public string Pattern { get; set; } = "";
}

public sealed class FileSignatureReport
{
    public bool Enabled { get; set; }
    public string? Error { get; set; }
    public int FilesScanned { get; set; }
    public int FilesMatched { get; set; }
    public List<FileSignatureHit> Hits { get; set; } = new();
}

public sealed class DeepScanResult
{
    public List<Finding> Findings { get; set; } = new();
    public List<NotChecked> NotChecked { get; set; } = new();
    public List<VisionIndicator> Overlays { get; set; } = new();
    public HandleScanReport Handles { get; set; } = new();
    public DriverScanReport Drivers { get; set; } = new();
    public FileSignatureReport FileSignatures { get; set; } = new();
    public List<InjectionFindingInfo> InjectionTraces { get; set; } = new();
    public List<string> Notes { get; set; } = new();
}