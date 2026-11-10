using EagleEye.Core;
using EagleEye.Models;
using EagleEye.Native;

namespace EagleEye.Scanning;

/// <summary>
/// 句柄线索：找出"谁以 VM_READ / VM_WRITE / CREATE_THREAD 打开了某个进程"。
/// 这是软件外挂（读内存、远程线程）在本机最直接的痕迹。
///
/// 只读：枚举系统句柄表 + DuplicateHandle 读目标 PID；不读任何进程内存、不拦截、不修改对象。
/// 需要管理员权限（PROCESS_DUP_HANDLE）；失败时降级并在报告中注明。
/// </summary>
public sealed class HandleScanner
{
    public (HandleScanReport Report, List<Finding> Findings) Scan(
        HandleScanOptions options,
        ProcessScanResult processes,
        CancellationToken ct,
        AuditLogger? audit = null)
    {
        var report = new HandleScanReport { Enabled = options.Enabled, Attempted = options.Enabled };
        var findings = new List<Finding>();

        if (!options.Enabled)
        {
            return (report, findings);
        }

        var byPid = processes.Processes
            .GroupBy(p => p.Pid)
            .ToDictionary(g => g.Key, g => g.First());

        // 目标 PID → 父 PID：CreateProcess 会给父进程一个 ALL_ACCESS 句柄，属正常，必须排除
        var parentOf = processes.Processes
            .GroupBy(p => p.Pid)
            .ToDictionary(g => g.Key, g => g.First().ParentPid);

        var refs = HandleInterop.FindProcessHandles(out int total, out int highAccess, out string? error);
        report.HandlesEnumerated = total;
        report.HighAccessHandles = highAccess;

        if (error is not null)
        {
            report.Error = error;
            audit?.Write("handle.scan", new { result = "failed", error, note = "需要管理员权限（PROCESS_DUP_HANDLE）" });
            return (report, findings);
        }

        audit?.Write("handle.scan", new
        {
            handles = total,
            highAccess,
            pairs = refs.Count,
            note = "只读枚举：DuplicateHandle 读目标 PID，未读取任何进程内存"
        });

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var reference in refs)
        {
            ct.ThrowIfCancellationRequested();

            byPid.TryGetValue(reference.HolderPid, out ProcessRecord? holder);
            byPid.TryGetValue(reference.TargetPid, out ProcessRecord? target);

            // 目标进程不在快照里（已退出 / ACE 拉起的独立进程）→ 无法判断价值，只记录不告警
            if (target is null)
            {
                report.UnresolvedTargets++;
                continue;
            }

            string holderName = holder?.Name ?? $"pid{reference.HolderPid}";
            string targetName = target?.Name ?? $"pid{reference.TargetPid}";

            // 祖先关系：CreateProcess 会给父进程（乃至更上层）ALL_ACCESS 句柄，属正常
            // 只比直接父进程不够 —— 游戏 → UnrealCEFSubProcess → browser.exe 是隔代的
            if (IsAncestor(parentOf, reference.HolderPid, reference.TargetPid))
            {
                continue;
            }

            // 同映像（同一程序的多进程/子进程）也跳过
            if (holder is not null && target is not null &&
                !string.IsNullOrEmpty(holder.ImagePath) &&
                string.Equals(holder.ImagePath, target.ImagePath, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // 同名进程互持（受保护进程读不到路径时的兜底）：同一款程序内部句柄，不构成外部读取
            if (holder is not null && target is not null &&
                string.Equals(holder.Name, target.Name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (options.HolderWhitelist.Any(p => PatternMatcher.IsMatch(holderName, p, null))) continue;
            if (options.TargetWhitelist.Any(p => PatternMatcher.IsMatch(targetName, p, null))) continue;

            // 微软签名的持有者（杀软、系统服务）大量以 VM_READ 打开进程，默认放过
            if (holder?.Signature.SignerSubject is { } signer &&
                signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            report.HoldersChecked++;

            var holderInfo = new HandleHolder
            {
                HolderPid = reference.HolderPid,
                HolderName = holderName,
                HolderPath = holder?.ImagePath,
                HolderSignature = holder?.Signature.State,
                TargetPid = reference.TargetPid,
                TargetName = targetName,
                AccessMask = $"0x{reference.GrantedAccess:X}",
                AccessRights = HandleInterop.DescribeAccess(reference.GrantedAccess).Split(' ')[0].Split('|').ToList()
            };

            report.Holders.Add(holderInfo);

            foreach (var rule in options.Rules.Where(r => r.Enabled).OrderByDescending(r => r.Severity))
            {
                if (!string.IsNullOrWhiteSpace(rule.TargetProcessPattern) &&
                    !PatternMatcher.IsMatch(targetName, rule.TargetProcessPattern, null))
                {
                    continue;
                }

                bool accessHit = rule.AccessMaskAny is null || rule.AccessMaskAny.Length == 0;
                if (!accessHit)
                {
                    foreach (string mask in rule.AccessMaskAny!)
                    {
                        string hex = mask.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? mask[2..] : mask;
                        if (!uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out uint m)) continue;
                        if ((reference.GrantedAccess & m) == m) { accessHit = true; break; }
                    }
                }

                if (!accessHit) continue;

                // 同一对 (持有者, 目标) 只记一条，避免一个 ALL_ACCESS 句柄命中 3 条规则被重复累加
                string key = $"{reference.HolderPid}|{reference.TargetPid}";
                if (!seen.Add(key)) break;

                double confidence = rule.Confidence;
                if (reference.GrantedAccess == 0x1FFFFF)
                {
                    // ALL_ACCESS 常见于进程创建/宿主附加，置信度大幅打折
                    confidence = Math.Round(confidence * 0.5, 2);
                }

                double score = Scoring.ComputeScore(rule.Severity, confidence);
                findings.Add(new Finding
                {
                    RuleId = rule.Id,
                    RuleType = "handle_access",
                    Category = rule.Category ?? "handle",
                    Target = holderName,
                    TargetPath = holder?.ImagePath,
                    Pid = reference.HolderPid,
                    Severity = rule.Severity,
                    Confidence = confidence,
                    Score = score,
                    RiskLevel = Scoring.LevelOf(score),
                    Description = rule.Description ?? $"{holderName} 以 {HandleInterop.DescribeAccess(reference.GrantedAccess)} 打开了 {targetName}",
                    Advice = rule.Advice,
                    Evidence = new Dictionary<string, object?>
                    {
                        ["holderPid"] = reference.HolderPid,
                        ["holderPath"] = holder?.ImagePath,
                        ["holderSignature"] = holder?.Signature.State,
                        ["targetPid"] = reference.TargetPid,
                        ["targetName"] = targetName,
                        ["grantedAccess"] = $"0x{reference.GrantedAccess:X}",
                        ["accessMeaning"] = HandleInterop.DescribeAccess(reference.GrantedAccess),
                        ["memoryRead"] = false,
                        ["note"] = "仅枚举句柄表并复制句柄读取目标 PID，未读取目标进程内存"
                    }
                });

                break;
            }
        }

        return (report, findings);
    }
    /// <summary>holder 是否为 target 的祖先（最多向上追 6 层）。</summary>
    private static bool IsAncestor(Dictionary<int, int> parentOf, int holder, int target, int maxDepth = 6)
    {
        int current = target;
        for (int i = 0; i < maxDepth; i++)
        {
            if (!parentOf.TryGetValue(current, out int parent) || parent <= 4) return false;
            if (parent == holder) return true;
            current = parent;
        }

        return false;
    }
}
