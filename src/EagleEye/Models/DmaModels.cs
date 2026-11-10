namespace EagleEye.Models;

/// <summary>
/// DMA 外设规则。
/// 注意：用户态部分只能与"由 SetupAPI 设备类近似推导的 PCI 基础类"比对 classCode；
/// 启用 --kernel 后才会用配置空间里的真实 Class Code 覆盖这一判断。
/// conditions 只在拿到配置空间数据时生效。
/// </summary>
public sealed class DmaRule
{
    public string Id { get; set; } = "";
    /// <summary>厂商 ID，4 位十六进制，可带 0x 前缀，如 "10EE"。</summary>
    public string? Vid { get; set; }
    /// <summary>设备 ID，可选；不填表示该厂商下所有设备。</summary>
    public string? Pid { get; set; }
    /// <summary>修订号，可选，如 "01"。</summary>
    public string? Revision { get; set; }
    /// <summary>PCI 基础类，可选，如 "06"。</summary>
    public string? ClassCode { get; set; }
    /// <summary>规则分类 id，对应 meta.categories[].id。</summary>
    public string? Category { get; set; }
    public string? Vendor { get; set; }
    public int Severity { get; set; } = 3;
    public double Confidence { get; set; } = 0.5;
    public string? Description { get; set; }
    public string? Advice { get; set; }
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// 附加条件（需要内核配置空间数据才生效）：
    /// msi_missing / msix_missing / no_capability_list / bar0_zero / class_ff / revision_zero
    /// </summary>
    public string[]? Conditions { get; set; }
}

public sealed class DmaWhitelistEntry
{
    public string? Vid { get; set; }
    public string? Pid { get; set; }
    public string? Reason { get; set; }
    public string? Expires { get; set; }
}

public sealed class DmaKernelOptions
{
    /// <summary>默认 false：必须在命令行显式 --kernel 才会加载驱动。</summary>
    public bool Enabled { get; set; }
    public string ServiceName { get; set; } = "PcieCfg";
    public string DevicePath { get; set; } = "\\\\.\\PcieCfg";
    public string DriverFileName { get; set; } = "PcieCfg.sys";
    public int TimeoutMs { get; set; } = 5000;
}

public sealed class DmaSection
{
    public bool Enabled { get; set; } = true;
    /// <summary>是否把枚举到的全部 PCI 设备写进报告（排查用，默认 true）。</summary>
    public bool IncludeDeviceList { get; set; } = true;
    public List<DmaRule> Rules { get; set; } = new();
    public List<DmaWhitelistEntry> Whitelist { get; set; } = new();
    /// <summary>内核只读配置空间枚举（一次性装载，用完即卸）。</summary>
    public DmaKernelOptions Kernel { get; set; } = new();
}

public sealed class DmaDeviceInfo
{
    public string Name { get; set; } = "";
    public string InstanceId { get; set; } = "";
    public string? VendorId { get; set; }
    public string? DeviceId { get; set; }
    public string? SubsystemId { get; set; }
    public string? Revision { get; set; }
    /// <summary>SetupAPI 设备类名，如 Display / Net / System。</summary>
    public string? DeviceClass { get; set; }
    /// <summary>由设备类近似推导的 PCI 基础类（2 位十六进制），非配置空间真实值。</summary>
    public string? ClassCodeGuess { get; set; }
    public string? Service { get; set; }
    public string? Location { get; set; }
    public string? Manufacturer { get; set; }
    public uint? ProblemCode { get; set; }
    /// <summary>PDO 设备对象名（如 \Device\NTPNP_PCI0007），内核按它发 IRP_MN_READ_CONFIG。</summary>
    public string? PdoName { get; set; }
    /// <summary>内核读到的真实配置空间；未启用 --kernel 时为 null。</summary>
    public ConfigSpaceInfo? ConfigSpace { get; set; }
}

public sealed class DmaFinding
{
    public string RuleId { get; set; } = "";
    public string Target { get; set; } = "";
    public string InstanceId { get; set; } = "";
    public string? VendorId { get; set; }
    public string? DeviceId { get; set; }
    public string? Revision { get; set; }
    public string? ClassCodeGuess { get; set; }
    public int Severity { get; set; }
    public double Confidence { get; set; }
    public double Score { get; set; }
    public string RiskLevel { get; set; } = RiskLevels.Info;
    public string Description { get; set; } = "";
    public string? Advice { get; set; }
    public string? Category { get; set; }
    /// <summary>被白名单抑制：不参与聚合，但保留记录。</summary>
    public bool Suppressed { get; set; }
    public string? SuppressReason { get; set; }
    public string? SuppressedBy { get; set; }
    /// <summary>恒为 true：提醒这是用户态近似结果。</summary>
    public bool UserModeOnly { get; set; } = true;
    /// <summary>本条命中是否已经用真实配置空间数据校验过。</summary>
    public bool ConfigSpaceVerified { get; set; }
    public Dictionary<string, object?> Evidence { get; set; } = new();
}

public sealed class DmaReport
{
    public bool Enabled { get; set; }
    public bool UserModeOnly { get; set; } = true;
    public string Note { get; set; } =
        "用户态枚举无法读取 PCIe 配置空间（Vendor/Device/Revision/Class/Capability/BAR 均不可靠），" +
        "本段结果仅为线索，不能作为 DMA 检测的唯一依据；确认需要人工复核或内核辅助。";
    public int DevicesEnumerated { get; set; }
    public int PciDevices { get; set; }
    public int Findings { get; set; }
    public string RiskLevel { get; set; } = RiskLevels.Info;
    public double TopScore { get; set; }
    public List<DmaDeviceInfo> Devices { get; set; } = new();
    public DmaKernelReport Kernel { get; set; } = new();
}

public sealed class DmaKernelReport
{
    public bool Attempted { get; set; }
    public bool Loaded { get; set; }
    public bool Unloaded { get; set; }
    public string? DriverPath { get; set; }
    public string? Error { get; set; }
    public int DevicesAttempted { get; set; }
    public int DevicesRead { get; set; }
    public List<string> Errors { get; set; } = new();
    public string Note { get; set; } =
        "驱动只在扫描期间存在：加载 → 读配置空间 → 立即停止并删除服务；不做内存/进程/文件/网络/提权任何操作。" +
        "不要在 Vanguard / EAC / BattlEye 等反作弊活跃期间加载，建议先扫描后启动游戏。";
}