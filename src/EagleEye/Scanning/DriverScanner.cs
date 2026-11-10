using EagleEye.Core;
using EagleEye.Models;
using EagleEye.Native;

namespace EagleEye.Scanning;

/// <summary>
/// 已加载驱动线索：枚举内核模块 → 比对规则（文件名 / 哈希）→ 验签。
/// 只读：SystemModuleInformation 查询 + 文件只读哈希与验签，不加载、不卸载、不打开设备。
/// </summary>
public sealed class DriverScanner
{
    public (DriverScanReport Report, List<Finding> Findings) Scan(
        DriverScanOptions options,
        SignatureChecker signatures,
        CancellationToken ct,
        AuditLogger? audit = null)
    {
        var report = new DriverScanReport { Enabled = options.Enabled, Attempted = options.Enabled };
        var findings = new List<Finding>();

        if (!options.Enabled)
        {
            return (report, findings);
        }

        var modules = DriverInterop.Enumerate(out string? error);
        if (error is not null)
        {
            report.Error = error;
            audit?.Write("driver.scan", new { result = "failed", error });
            return (report, findings);
        }

        report.DriversEnumerated = modules.Count;
        audit?.Write("driver.scan", new { modules = modules.Count, note = "只枚举已加载模块，不加载/卸载任何驱动" });

        var imagePaths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var matchedThisRun = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var module in modules)
        {
            ct.ThrowIfCancellationRequested();

            string win32Path = DriverInterop.ToWin32Path(module.FullPath);
            imagePaths[module.Name] = win32Path;

            foreach (var rule in options.Rules.Where(r => r.Enabled))
            {
                bool nameHit = !string.IsNullOrWhiteSpace(rule.Pattern) &&
                               PatternMatcher.IsMatch(module.Name, rule.Pattern, null);

                string? hash = null;
                bool hashHit = false;

                if (!nameHit && !string.IsNullOrWhiteSpace(rule.Sha256) && File.Exists(win32Path))
                {
                    hash = Hashing.TrySha256(win32Path, out _);
                    hashHit = string.Equals(hash, rule.Sha256, StringComparison.OrdinalIgnoreCase);
                }

                if (!nameHit && !hashHit) continue;

                matchedThisRun.Add(module.Name);
                var signature = File.Exists(win32Path) ? signatures.Check(win32Path) : null;
                if (signature is { State: SignatureStates.Unsigned }) report.UnsignedDrivers++;

                double score = Scoring.ComputeScore(rule.Severity, rule.Confidence);
                findings.Add(new Finding
                {
                    RuleId = rule.Id,
                    RuleType = "kernel_driver",
                    Category = rule.Category ?? "driver",
                    Target = module.Name,
                    TargetPath = win32Path,
                    Pid = null,
                    Severity = rule.Severity,
                    Confidence = rule.Confidence,
                    Score = score,
                    RiskLevel = Scoring.LevelOf(score),
                    Description = rule.Description ?? $"已加载驱动命中规则：{module.Name}",
                    Advice = rule.Advice,
                    Evidence = new Dictionary<string, object?>
                    {
                        ["moduleName"] = module.Name,
                        ["ntPath"] = module.FullPath,
                        ["win32Path"] = win32Path,
                        ["imageBase"] = $"0x{module.ImageBase:X}",
                        ["imageSize"] = module.ImageSize,
                        ["signatureState"] = signature?.State,
                        ["signer"] = signature?.SignerSubject,
                        ["sha256"] = hash,
                        ["loaded"] = true
                    }
                });

                report.Suspicious.Add(new LoadedDriverInfo
                {
                    Name = module.Name,
                    Path = win32Path,
                    ImageBase = module.ImageBase,
                    ImageSize = module.ImageSize,
                    SignatureState = signature?.State,
                    Signer = signature?.SignerSubject,
                    MatchedRuleId = rule.Id
                });
            }
        }

        // 白名单模式：不用样本也能查出"不该出现的驱动"
        if (options.WhitelistMode)
        {
            foreach (var module in modules)
            {
                ct.ThrowIfCancellationRequested();
                if (matchedThisRun.Contains(module.Name)) continue;

                string win32Path2 = DriverInterop.ToWin32Path(module.FullPath);
                if (!File.Exists(win32Path2)) continue;

                var signature = signatures.Check(win32Path2);
                bool validSignature = signature.State is SignatureStates.Valid or SignatureStates.CatalogValid;

                // 目录签名（catalog_valid）走的是 Windows 目录信任链，SignerSubject 常为空，直接放行
                if (signature.State == SignatureStates.CatalogValid) continue;

                bool trustedSigner = signature.SignerSubject is not null &&
                    options.TrustedSigners.Any(s => signature.SignerSubject!.Contains(s, StringComparison.OrdinalIgnoreCase));

                if (validSignature && (trustedSigner || options.TrustedSigners.Count == 0)) continue;

                string reason = validSignature
                    ? "驱动签名主体不在受信任列表：" + signature.SignerSubject
                    : "驱动无有效签名（" + signature.State + "）";

                double score = Scoring.ComputeScore(options.UntrustedSeverity, options.UntrustedConfidence);
                findings.Add(new Finding
                {
                    RuleId = "driver.untrusted_signature",
                    RuleType = "kernel_driver",
                    Category = "driver",
                    Target = module.Name,
                    TargetPath = win32Path2,
                    Severity = options.UntrustedSeverity,
                    Confidence = options.UntrustedConfidence,
                    Score = score,
                    RiskLevel = Scoring.LevelOf(score),
                    Description = reason,
                    Advice = "第三方驱动不一定是外挂，需核对厂商与用途；外挂驱动几乎都落在这里",
                    Evidence = new Dictionary<string, object?>
                    {
                        ["moduleName"] = module.Name,
                        ["win32Path"] = win32Path2,
                        ["signatureState"] = signature.State,
                        ["signer"] = signature.SignerSubject,
                        ["mode"] = "driver-whitelist",
                        ["note"] = "无样本哈希，仅依据签名与受信任主体列表"
                    }
                });

                report.Suspicious.Add(new LoadedDriverInfo
                {
                    Name = module.Name,
                    Path = win32Path2,
                    ImageBase = module.ImageBase,
                    ImageSize = module.ImageSize,
                    SignatureState = signature.State,
                    Signer = signature.SignerSubject,
                    MatchedRuleId = "driver.untrusted_signature"
                });
            }
        }

        return (report, findings);
    }
}