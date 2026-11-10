using EagleEye.Core;
using EagleEye.Models;
using EagleEye.Native;

namespace EagleEye.Scanning;

public sealed class VisionScanResult
{
    public bool Enabled { get; set; }
    public List<VisionIndicator> SoftwareCapture { get; } = new();
    public List<VisionIndicator> HardwareIndicators { get; } = new();
    public VisionBehavioralHint BehavioralHint { get; set; } = new();
    public List<NotChecked> NotChecked { get; } = new();
    public List<string> Notes { get; } = new();
    public int IndependentLayers { get; set; }
    public string HighestLevel { get; set; } = RiskLevels.Info;
}

/// <summary>
/// 视觉外挂线索扫描（用户态、只读）。
///
/// 三层：
///   capture  —— 进程同时具备「可见窗口」+「加载了采集/推理模块」；
///   hardware —— 复用 DmaScanner 已枚举的设备列表，按视觉类规则再匹配一次；
///   behavior —— 可选，GetCursorPos 轮询的聚合统计（信息级）。
///
/// 明确不做：不读进程内存、不注入 DLL、不 Hook API、不截屏、不判断窗口内容、
///           不关联具体游戏、不新增任何内核组件。
///
/// 判定口径：单层命中最高「信息」，≥2 个独立层才升到「可疑」，且封顶为「可疑」。
/// </summary>
public sealed class VisionScanner
{
    private readonly record struct WindowSummary(int Count, int MaxWidth, int MaxHeight, string? Title);

    public VisionScanResult Scan(
        RuleSet ruleSet,
        ProcessScanResult processes,
        List<DmaDeviceInfo>? devices,
        CancellationToken ct,
        AuditLogger? audit = null,
        bool behaviorOverride = false)
    {
        var section = ruleSet.Vision;
        var result = new VisionScanResult { Enabled = section.Enabled };
        if (!section.Enabled)
        {
            return result;
        }

        audit?.Write("vision.start", new
        {
            capture = section.Capture.Enabled,
            hardware = section.Hardware.Enabled,
            behavior = section.Behavior.Enabled || behaviorOverride,
            note = "只读枚举：窗口 + 模块 + 设备；不注入、不 Hook、不截屏"
        });

        if (section.Capture.Enabled)
        {
            ScanCapture(section, processes, result, ct);
        }

        if (section.Hardware.Enabled)
        {
            ScanHardware(section, devices, result);
        }

        if (section.Behavior.Enabled || behaviorOverride)
        {
            result.BehavioralHint = InputBehaviorSampler.Sample(section.Behavior, ct);
            if (result.BehavioralHint.Collected)
            {
                audit?.Write("vision.behavior", new
                {
                    samples = result.BehavioralHint.SampleCount,
                    straight = result.BehavioralHint.StraightLineRatio,
                    constant = result.BehavioralHint.ConstantVelocityRatio,
                    note = "信息级；GetCursorPos 轮询，无 Hook、无轨迹留存"
                });
            }
        }
        else
        {
            result.BehavioralHint.SkipReason = "未启用（默认关闭；需要时用 --vision-behavior 开启）";
        }

        Aggregate(section, result);
        audit?.Write("vision.end", new
        {
            software = result.SoftwareCapture.Count,
            hardware = result.HardwareIndicators.Count,
            layers = result.IndependentLayers,
            level = result.HighestLevel
        });

        return result;
    }

    // ---------------- 采集端 ----------------
    private static void ScanCapture(VisionSection section, ProcessScanResult processes, VisionScanResult result, CancellationToken ct)
    {
        var windows = WindowApi.EnumerateVisibleWindows();
        var windowsByPid = windows
            .GroupBy(w => w.ProcessId)
            .ToDictionary(
                g => g.Key,
                g => new WindowSummary(g.Count(), g.Max(w => w.Width), g.Max(w => w.Height),
                                       g.Select(w => w.Title).FirstOrDefault(t => !string.IsNullOrWhiteSpace(t))));

        var strongRules = section.Capture.ModuleRules.Where(r => r.Enabled && IsStrong(r)).ToList();
        var contextRules = section.Capture.ModuleRules.Where(r => r.Enabled && !IsStrong(r)).ToList();

        foreach (var process in processes.Processes)
        {
            ct.ThrowIfCancellationRequested();

            if (!windowsByPid.TryGetValue(process.Pid, out var window) || window.Count == 0)
            {
                continue;
            }

            if (process.Modules.Count == 0)
            {
                continue;
            }

            var matchedStrong = new List<VisionRule>();
            var matchedContext = new List<VisionRule>();
            var matchedModules = new List<string>();

            foreach (var rule in section.Capture.ModuleRules.Where(r => r.Enabled))
            {
                var hits = process.Modules
                    .Where(m => PatternMatcher.IsMatch(m.Name, rule.Pattern, rule.Match))
                    .Select(m => m.Name)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (hits.Count == 0) continue;

                matchedModules.AddRange(hits);
                if (IsStrong(rule)) matchedStrong.Add(rule);
                else matchedContext.Add(rule);
            }

            // 只有上下文模块（gdi32/dxgi 这类）不足以成条
            if (matchedStrong.Count == 0) continue;

            var (suppressed, reason) = CheckProcessWhitelist(section, process);

            double confidence = matchedStrong.Max(r => r.Confidence);
            confidence += Math.Min(0.15, matchedContext.Count * 0.05);
            if (process.Signature.State is SignatureStates.Unsigned or SignatureStates.BadDigest)
            {
                confidence += 0.05;
            }

            confidence = Math.Round(Math.Clamp(confidence, 0, 0.85), 2);
            int severity = Math.Max(1, matchedStrong.Max(r => r.Severity));
            double score = Scoring.ComputeScore(severity, confidence);

            result.SoftwareCapture.Add(new VisionIndicator
            {
                Id = matchedStrong[0].Id,
                Layer = "capture",
                Category = matchedStrong[0].Category,
                Target = process.Name,
                Pid = process.Pid,
                Path = process.ImagePath,
                SignatureState = process.Signature.State,
                CommandLineSummary = Summarize(process.CommandLine),
                MatchedModules = matchedModules.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                Severity = severity,
                Confidence = confidence,
                Score = score,
                RiskLevel = RiskLevels.Info,
                Description = matchedStrong[0].Description ?? "进程同时拥有可见窗口并加载了采集/推理相关模块",
                Advice = matchedStrong[0].Advice ?? "弱信号：需结合游戏侧遥测与人工复核，本地不作为判定依据",
                Suppressed = suppressed,
                SuppressReason = suppressed ? reason : null,
                Evidence = new Dictionary<string, object?>
                {
                    ["pid"] = process.Pid,
                    ["imagePath"] = process.ImagePath,
                    ["signatureState"] = process.Signature.State,
                    ["signer"] = process.Signature.SignerSubject,
                    ["commandLine"] = Summarize(process.CommandLine),
                    ["visibleWindows"] = window.Count,
                    ["windowTitle"] = window.Title,
                    ["largestWindow"] = $"{window.MaxWidth}x{window.MaxHeight}",
                    ["matchedModules"] = matchedModules.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                    ["strongRules"] = matchedStrong.Select(r => r.Id).ToArray(),
                    ["contextRules"] = matchedContext.Select(r => r.Id).ToArray(),
                    ["memoryRead"] = false,
                    ["screenshotTaken"] = false
                }
            });
        }
    }

    // ---------------- 硬件 ----------------
    private void ScanHardware(VisionSection section, List<DmaDeviceInfo>? devices, VisionScanResult result)
    {
        if (devices is null || devices.Count == 0)
        {
            result.Notes.Add("硬件枚举结果为空（可能未启用 DMA 枚举或本机无 PCI 设备）");
            return;
        }

        foreach (var device in devices)
        {
            foreach (var rule in section.Hardware.Rules.Where(r => r.Enabled))
            {
                if (!string.IsNullOrWhiteSpace(rule.VendorId) && !HexEquals(rule.VendorId, device.VendorId)) continue;
                if (!string.IsNullOrWhiteSpace(rule.DeviceId) && !HexEquals(rule.DeviceId, device.DeviceId)) continue;
                if (!string.IsNullOrWhiteSpace(rule.DeviceClass) &&
                    (device.DeviceClass is null || !device.DeviceClass.Contains(rule.DeviceClass!, StringComparison.OrdinalIgnoreCase))) continue;
                if (!string.IsNullOrWhiteSpace(rule.Service) &&
                    (device.Service is null || !device.Service.Contains(rule.Service!, StringComparison.OrdinalIgnoreCase))) continue;

                var (suppressed, reason) = CheckDeviceWhitelist(section, device);
                double confidence = Math.Round(Math.Clamp(rule.Confidence, 0, 0.7), 2);
                double score = Scoring.ComputeScore(rule.Severity, confidence);

                result.HardwareIndicators.Add(new VisionIndicator
                {
                    Id = rule.Id,
                    Layer = "hardware",
                    Category = rule.Category,
                    Target = device.Name,
                    Path = device.InstanceId,
                    SignatureState = null,
                    Severity = rule.Severity,
                    Confidence = confidence,
                    Score = score,
                    RiskLevel = RiskLevels.Info,
                    Description = rule.Description ?? "设备特征命中外设类规则",
                    Advice = rule.Advice ?? "需结合使用场景人工确认（直播/双机采集/硬件宏都可能同款设备）",
                    Suppressed = suppressed,
                    SuppressReason = suppressed ? reason : null,
                    Evidence = new Dictionary<string, object?>
                    {
                        ["instanceId"] = device.InstanceId,
                        ["vendorId"] = device.VendorId,
                        ["deviceId"] = device.DeviceId,
                        ["deviceClass"] = device.DeviceClass,
                        ["service"] = device.Service,
                        ["location"] = device.Location,
                        ["manufacturer"] = device.Manufacturer,
                        ["matchedRuleId"] = rule.Id,
                        ["category"] = rule.Category
                    }
                });
            }
        }
    }

    // ---------------- 聚合 ----------------
    /// <summary>重算层级与等级（追加 overlay 线索后调用）。</summary>
    public static void Aggregate(VisionSection section, VisionScanResult result)
    {
        int layers = 0;
        if (result.SoftwareCapture.Any(i => !i.Suppressed)) layers++;
        if (result.HardwareIndicators.Any(i => !i.Suppressed)) layers++;
        if (result.BehavioralHint.Collected && result.BehavioralHint.Confidence >= 0.15) layers++;

        result.IndependentLayers = layers;

        int required = Math.Clamp(section.Aggregation.RequireIndependentLayers, 1, 3);
        string level = layers >= required ? RiskLevels.Suspicious : RiskLevels.Info;

        // 封顶：无论多少层，本地最高只给「可疑」
        int cap = Math.Min(Scoring.Rank(section.Aggregation.MaxLevel), Scoring.Rank(RiskLevels.Suspicious));
        if (Scoring.Rank(level) > cap)
        {
            level = RiskLevels.Suspicious;
        }

        result.HighestLevel = level;

        foreach (var indicator in result.SoftwareCapture.Concat(result.HardwareIndicators))
        {
            indicator.RiskLevel = level;
        }

        if (result.SoftwareCapture.Count == 0 && result.HardwareIndicators.Count == 0 && !result.BehavioralHint.Collected)
        {
            result.Notes.Add("未发现视觉外挂相关线索（注意：双机链路在本机不会有任何痕迹）");
        }

        if (result.SoftwareCapture.Count > 0)
        {
            result.Notes.Add("软件采集线索基于「可见窗口 + 已加载模块」，无法区分正常直播/录屏与作弊采集");
        }

        if (result.HardwareIndicators.Count > 0)
        {
            result.Notes.Add("硬件线索只能说明设备存在，无法证明其被用于作弊（采集卡可用于直播，HID 开发板可用于自动化测试）");
        }
    }

    private static bool IsStrong(VisionRule rule)
        => !string.Equals(rule.Tier, "context", StringComparison.OrdinalIgnoreCase);

    private static (bool, string?) CheckProcessWhitelist(VisionSection section, ProcessRecord process)
    {
        foreach (var entry in section.Whitelist)
        {
            if (string.IsNullOrWhiteSpace(entry.ProcessPattern)) continue;
            if (entry.Expires is not null && DateTime.TryParse(entry.Expires, out DateTime expires) && expires.Date < DateTime.Today) continue;
            if (!PatternMatcher.IsMatch(process.Name, entry.ProcessPattern, entry.Match)) continue;

            return (true, entry.Reason ?? $"视觉白名单: {entry.ProcessPattern}");
        }

        return (false, null);
    }

    private static (bool, string?) CheckDeviceWhitelist(VisionSection section, DmaDeviceInfo device)
    {
        foreach (var entry in section.Whitelist)
        {
            if (string.IsNullOrWhiteSpace(entry.VendorId)) continue;
            if (!HexEquals(entry.VendorId, device.VendorId)) continue;
            if (!string.IsNullOrWhiteSpace(entry.DeviceId) && !HexEquals(entry.DeviceId, device.DeviceId)) continue;

            return (true, entry.Reason ?? $"视觉白名单: VID {entry.VendorId}");
        }

        return (false, null);
    }

    private static bool HexEquals(string? a, string? b)
        => string.Equals(DmaScanner.NormalizeHex(a), DmaScanner.NormalizeHex(b), StringComparison.Ordinal);

    private static string? Summarize(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        string trimmed = commandLine.Trim();
        return trimmed.Length <= 200 ? trimmed : trimmed[..200] + "…";
    }
}