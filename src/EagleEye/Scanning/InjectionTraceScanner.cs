using EagleEye.Core;
using EagleEye.Models;
using EagleEye.Native;

namespace EagleEye.Scanning;

/// <summary>
/// 注入痕迹检测（**不需要样本哈希**）。
///
/// 原理：外挂 DLL 必须出现在目标进程的模块列表里，而它通常满足至少一条：
///   1. 模块文件在磁盘上不存在（内存加载 / 反射注入 / manual mapping）
///   2. 模块路径在临时目录、下载目录、用户公共目录
///   3. 模块没有有效数字签名（且不在 Windows 目录下）
/// 这三条都是**结构性痕迹**，与具体是哪个外挂无关，所以没有样本也能查。
///
/// 只读：复用已枚举的模块列表 + 只读文件属性与 Authenticode 校验，
///       不读进程内存、不注入、不 Hook。
/// </summary>
public sealed class InjectionTraceScanner
{
    private static readonly string[] SuspiciousPathMarkers =
    {
        "\\Temp\\", "\\Downloads\\", "\\Users\\Public\\", "\\AppData\\Local\\Temp\\",
        "\\Desktop\\", "\\Documents\\", "\\ProgramData\\Temp\\"
    };

    public (List<Finding> Findings, List<InjectionFindingInfo> Traces) Scan(
        InjectionScanOptions options,
        ProcessScanResult processes,
        SignatureChecker signatures,
        CancellationToken ct,
        AuditLogger? audit = null)
    {
        var findings = new List<Finding>();
        var traces = new List<InjectionFindingInfo>();

        if (!options.Enabled || options.TargetProcessPatterns.Count == 0)
        {
            return (findings, traces);
        }

        string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        foreach (var process in processes.Processes)
        {
            ct.ThrowIfCancellationRequested();

            bool isTarget = options.TargetProcessPatterns.Any(p => PatternMatcher.IsMatch(process.Name, p, null));
            if (!isTarget) continue;
            if (process.Modules.Count == 0) continue;

            foreach (var module in process.Modules)
            {
                if (string.IsNullOrWhiteSpace(module.Name)) continue;
                if (options.ModuleWhitelist.Any(w => PatternMatcher.IsMatch(module.Name, w, null))) continue;

                string? path = module.Path;

                // 1) 磁盘上不存在 —— manual mapping / 反射注入的典型特征
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    Add(findings, traces, options.MissingFileSeverity, 0.75,
                        "inj.module_missing_file", process, module,
                        $"模块「{module.Name}」在磁盘上不存在（内存加载/反射注入特征）",
                        "模块没有对应磁盘文件，这是手动映射注入最直接的本机证据", null);
                    continue;
                }

                // 2) 路径异常
                string marker = SuspiciousPathMarkers.FirstOrDefault(m =>
                    path.Contains(m, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                if (marker.Length > 0)
                {
                    Add(findings, traces, options.SuspiciousPathSeverity, 0.55,
                        "inj.module_suspicious_path", process, module,
                        $"模块「{module.Name}」从可疑目录加载：{path}",
                        "正常系统/游戏模块不会放在临时目录或下载目录", null);
                    continue;
                }

                // 3) 非 Windows 目录且无有效签名（Windows 目录下的系统模块跳过，省 IO）
                if (path.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase)) continue;

                var signature = signatures.Check(path);
                if (signature.State is SignatureStates.Unsigned or SignatureStates.BadDigest
                    or SignatureStates.UntrustedRoot or SignatureStates.InvalidChain or SignatureStates.Distrusted)
                {
                    Add(findings, traces, options.UnsignedSeverity, 0.35,
                        "inj.module_unsigned", process, module,
                        $"模块「{module.Name}」无有效签名（{signature.State}）：{path}",
                        "非系统目录 + 无签名，需人工确认来源", signature.State);
                }
            }
        }

        audit?.Write("injection.scan", new
        {
            traces = traces.Count,
            note = "只读模块枚举 + 文件存在性 + 验签；未读进程内存"
        });

        return (findings, traces);
    }

    private static void Add(
        List<Finding> findings,
        List<InjectionFindingInfo> traces,
        int severity,
        double confidence,
        string ruleId,
        ProcessRecord process,
        ModuleInfo module,
        string description,
        string advice,
        string? signatureState)
    {
        double score = Scoring.ComputeScore(severity, confidence);
        findings.Add(new Finding
        {
            RuleId = ruleId,
            RuleType = "module_injection",
            Category = "injection",
            Target = process.Name,
            TargetPath = process.ImagePath,
            Pid = process.Pid,
            Severity = severity,
            Confidence = confidence,
            Score = score,
            RiskLevel = Scoring.LevelOf(score),
            Description = description,
            Advice = advice,
            Evidence = new Dictionary<string, object?>
            {
                ["pid"] = process.Pid,
                ["processPath"] = process.ImagePath,
                ["module"] = module.Name,
                ["modulePath"] = module.Path,
                ["moduleSize"] = module.Size,
                ["signatureState"] = signatureState,
                ["memoryRead"] = false,
                ["note"] = "仅比对模块列表与磁盘文件，未读取进程内存"
            }
        });

        traces.Add(new InjectionFindingInfo
        {
            Target = process.Name,
            Pid = process.Pid,
            Module = module.Name,
            ModulePath = module.Path,
            Reason = description,
            SignatureState = signatureState
        });
    }
}
