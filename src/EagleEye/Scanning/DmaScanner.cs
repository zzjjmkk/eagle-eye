using System.Text.RegularExpressions;
using EagleEye.Core;
using EagleEye.Models;
using EagleEye.Native;

namespace EagleEye.Scanning;

public sealed class DmaScanResult
{
    public bool Enabled { get; set; }
    public int DevicesEnumerated { get; set; }
    public List<DmaDeviceInfo> Devices { get; } = new();
    public List<DmaFinding> Findings { get; } = new();
    public List<NotChecked> NotChecked { get; } = new();
    public ConfigSpaceReadResult? Kernel { get; set; }
}

/// <summary>
/// DMA 外设检测。
///
/// 两阶段：
///   1) Enumerate —— 用户态 SetupAPI/CfgMgr32 枚举 PCI 设备（VID/PID/REV/设备类/服务/位置/PDO 名）；
///   2) Match     —— 可选先让 configReader 用一次性只读驱动补齐真实配置空间，再做规则比对。
///
/// 能做的：拿到 VID/PID/REV/近似或真实 Class Code、Capability 链、BAR 原始值、MSI 能力。
/// 不能做的：确定 BAR 大小需要写 0xFFFFFFFF 回读，本工具禁止写配置空间，故 barSizeDeterminable 恒为 false。
/// 不做的事：不加载常驻驱动、不改设备状态、不访问 IOMMU、不读写进程内存。
/// </summary>
public sealed class DmaScanner
{
    private static readonly Regex VidRegex = new(@"VEN_([0-9A-Fa-f]{4})", RegexOptions.Compiled);
    private static readonly Regex DidRegex = new(@"DEV_([0-9A-Fa-f]{4})", RegexOptions.Compiled);
    private static readonly Regex SubsysRegex = new(@"SUBSYS_([0-9A-Fa-f]{8})", RegexOptions.Compiled);
    private static readonly Regex RevRegex = new(@"REV_([0-9A-Fa-f]{2})", RegexOptions.Compiled);

    /// <summary>设备类名 → 近似 PCI 基础类（1 字节）。仅为启发式，非配置空间真实值。</summary>
    private static readonly Dictionary<string, string> ClassGuessMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Display"] = "03", ["Net"] = "02", ["Media"] = "04", ["System"] = "06",
        ["USB"] = "0C", ["Bluetooth"] = "0D", ["HDC"] = "01", ["SCSIAdapter"] = "01",
        ["DiskDrive"] = "01", ["CDROM"] = "01", ["Volume"] = "01", ["Mouse"] = "09",
        ["Keyboard"] = "09", ["HIDClass"] = "03", ["Ports"] = "07", ["Modem"] = "07",
        ["Processor"] = "0B", ["Memory"] = "05", ["SmartCardReader"] = "0C",
        ["SecurityDevices"] = "10", ["SoftwareDevice"] = "00", ["Unknown"] = "FF"
    };

    public DmaScanResult Scan(
        DmaSection section,
        CancellationToken ct,
        RuleSet ruleSet,
        Func<List<DmaDeviceInfo>, ConfigSpaceReadResult>? configReader = null)
    {
        var result = new DmaScanResult { Enabled = section.Enabled };
        if (!section.Enabled)
        {
            return result;
        }

        var raw = SetupApiInterop.EnumeratePresentDevices(out string? enumError);
        result.DevicesEnumerated = raw.Count;

        if (enumError is not null)
        {
            result.NotChecked.Add(new NotChecked { Target = "PCI/PCIe 设备", Reason = enumError });
        }

        // ---- 阶段 1：用户态枚举 ----
        foreach (var device in raw)
        {
            ct.ThrowIfCancellationRequested();

            if (!device.InstanceId.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            result.Devices.Add(new DmaDeviceInfo
            {
                Name = device.FriendlyName ?? device.DeviceDesc ?? "未知设备",
                InstanceId = device.InstanceId,
                VendorId = FirstGroup(VidRegex, device.InstanceId),
                DeviceId = FirstGroup(DidRegex, device.InstanceId),
                SubsystemId = FirstGroup(SubsysRegex, device.InstanceId),
                Revision = FirstGroup(RevRegex, device.InstanceId),
                DeviceClass = device.ClassName,
                ClassCodeGuess = GuessClassCode(device.ClassName),
                Service = device.Service,
                Location = device.Location,
                Manufacturer = device.Manufacturer,
                ProblemCode = device.ProblemCode,
                PdoName = device.PdoName
            });
        }

        // ---- 阶段 2（可选）：一次性只读内核枚举，补齐真实配置空间 ----
        if (configReader is not null && result.Devices.Count > 0)
        {
            result.Kernel = configReader(result.Devices);
        }

        // ---- 阶段 3：规则比对 ----
        var activeRules = section.Rules.Where(r => r.Enabled).ToList();

        foreach (var device in result.Devices)
        {
            ct.ThrowIfCancellationRequested();

            var (whitelisted, wlReason) = CheckWhitelist(section, device.VendorId, device.DeviceId);
            var config = device.ConfigSpace;

            foreach (var rule in activeRules)
            {
                if (!Matches(rule, device, config)) continue;
                if (!ConditionsSatisfied(rule, config)) continue;

                double score = Scoring.ComputeScore(rule.Severity, rule.Confidence, Scoring.WeightOf(ruleSet, rule.Category));

                result.Findings.Add(new DmaFinding
                {
                    RuleId = rule.Id,
                    Target = device.Name,
                    InstanceId = device.InstanceId,
                    VendorId = device.VendorId,
                    DeviceId = device.DeviceId,
                    Revision = config is not null ? $"{config.RevisionId:X2}" : device.Revision,
                    ClassCodeGuess = config is not null ? config.ClassCodeHex : device.ClassCodeGuess,
                    Severity = rule.Severity,
                    Confidence = rule.Confidence,
                    Score = score,
                    RiskLevel = Scoring.LevelOf(score),
                    Description = string.IsNullOrWhiteSpace(rule.Description) ? "DMA 外设规则命中" : rule.Description!,
                    Advice = rule.Advice,
                    Category = rule.Category,
                    Suppressed = whitelisted,
                    SuppressReason = wlReason,
                    SuppressedBy = whitelisted ? "whitelist" : null,
                    UserModeOnly = config is null,
                    ConfigSpaceVerified = config is not null,
                    Evidence = BuildEvidence(device, config)
                });
            }
        }

        result.Findings.Sort((a, b) => b.Score.CompareTo(a.Score));
        result.Devices.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return result;
    }

    private static Dictionary<string, object?> BuildEvidence(DmaDeviceInfo device, ConfigSpaceInfo? config)
    {
        var evidence = new Dictionary<string, object?>
        {
            ["instanceId"] = device.InstanceId,
            ["pdoName"] = device.PdoName,
            ["deviceClass"] = device.DeviceClass,
            ["classCodeSource"] = config is not null ? "pci-config-space" : "setupapi-derived-guess",
            ["service"] = device.Service,
            ["location"] = device.Location,
            ["manufacturer"] = device.Manufacturer,
            ["problemCode"] = device.ProblemCode,
            ["configSpaceAvailable"] = config is not null
        };

        if (config is not null)
        {
            evidence["configSpace"] = new
            {
                vendorId = $"0x{config.VendorId:X4}",
                deviceId = $"0x{config.DeviceId:X4}",
                revision = config.RevisionId,
                classCode = config.ClassCodeHex,
                subsystem = $"0x{config.SubsystemVendorId:X4}:0x{config.SubsystemId:X4}",
                capabilityIds = config.CapabilityIds.Select(c => $"0x{c:X2}").ToArray(),
                hasMsi = config.HasMsi,
                hasMsiX = config.HasMsiX,
                bars = config.Bars.Select(b => $"0x{b:X8}").ToArray(),
                barKinds = config.BarKinds,
                barSizeDeterminable = config.BarSizeDeterminable,
                raw64Bytes = config.RawHex
            };
        }

        return evidence;
    }

    private static bool Matches(DmaRule rule, DmaDeviceInfo device, ConfigSpaceInfo? config)
    {
        if (!string.IsNullOrWhiteSpace(rule.Vid) &&
            !HexEquals(rule.Vid, config is not null ? $"{config.VendorId:X4}" : device.VendorId))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(rule.Pid) &&
            !HexEquals(rule.Pid, config is not null ? $"{config.DeviceId:X4}" : device.DeviceId))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(rule.Revision) &&
            !HexEquals(rule.Revision, config is not null ? $"{config.RevisionId:X2}" : device.Revision))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(rule.ClassCode) &&
            !HexEquals(rule.ClassCode, config is not null ? config.ClassCodeHex[..2] : device.ClassCodeGuess))
        {
            return false;
        }

        return true;
    }

    /// <summary>conditions 只在拿到真实配置空间时生效；没有配置空间数据时该规则不触发。</summary>
    private static bool ConditionsSatisfied(DmaRule rule, ConfigSpaceInfo? config)
    {
        if (rule.Conditions is null || rule.Conditions.Length == 0)
        {
            return true;
        }

        if (config is null)
        {
            return false;
        }

        foreach (string condition in rule.Conditions)
        {
            bool ok = condition.Trim().ToLowerInvariant() switch
            {
                "msi_missing" => !config.HasMsi,
                "msix_missing" => !config.HasMsiX,
                "no_capability_list" => config.CapabilityIds.Length == 0,
                "bar0_zero" => config.Bars.Length > 0 && config.Bars[0] == 0,
                "class_ff" => config.BaseClass == 0xFF,
                "revision_zero" => config.RevisionId == 0,
                _ => true
            };

            if (!ok)
            {
                return false;
            }
        }

        return true;
    }

    private static (bool, string?) CheckWhitelist(DmaSection section, string? vid, string? did)
    {
        foreach (var entry in section.Whitelist)
        {
            if (!string.IsNullOrWhiteSpace(entry.Expires) &&
                DateTime.TryParse(entry.Expires, out DateTime expires) && expires.Date < DateTime.Today)
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(entry.Vid) && !HexEquals(entry.Vid, vid)) continue;
            if (!string.IsNullOrWhiteSpace(entry.Pid) && !HexEquals(entry.Pid, did)) continue;

            return (true, entry.Reason ?? $"DMA 白名单: VID {entry.Vid}");
        }

        return (false, null);
    }

    public static string NormalizeHex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        string s = value.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return s.ToUpperInvariant();
    }

    private static bool HexEquals(string? ruleValue, string? deviceValue)
        => string.Equals(NormalizeHex(ruleValue), NormalizeHex(deviceValue), StringComparison.Ordinal);

    private static string FirstGroup(Regex regex, string input)
    {
        Match m = regex.Match(input);
        return m.Success ? m.Groups[1].Value.ToUpperInvariant() : "";
    }

    private static string GuessClassCode(string? className)
    {
        if (string.IsNullOrWhiteSpace(className)) return "FF";
        return ClassGuessMap.TryGetValue(className!, out string? code) ? code : "FF";
    }
}