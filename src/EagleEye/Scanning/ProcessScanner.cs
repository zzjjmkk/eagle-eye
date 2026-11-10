using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
using EagleEye.Core;
using EagleEye.Models;
using EagleEye.Native;
using EagleEye.Rules;

namespace EagleEye.Scanning;

public sealed class ProcessScanResult
{
    public List<ProcessRecord> Processes { get; } = new();
    public List<Finding> Findings { get; } = new();
    public List<NotChecked> NotChecked { get; } = new();
    public int SelfSkipped { get; set; }
}

/// <summary>
/// 进程扫描：Toolhelp 枚举 + 最小权限打开 + 名称/路径/命令行/模块/签名规则匹配。
/// 全程只读：只 OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)，不做任何内存读取或写入。
/// </summary>
public sealed class ProcessScanner
{
    private readonly SignatureChecker _signatures;

    public ProcessScanner(SignatureChecker signatures)
    {
        _signatures = signatures;
    }

    private readonly record struct ProcEntry(int Pid, int ParentPid, int Threads, string Name);

    public ProcessScanResult Scan(RuleSet rules, CancellationToken ct, AuditLogger? audit = null, bool forceModules = false)
    {
        var result = new ProcessScanResult();

        var activeRules = rules.Rules.Where(r => r.Enabled).ToList();
        var nameRules = activeRules.Where(r => Eq(r.Type, RuleTypes.ProcessName)).ToList();
        var pathRules = activeRules.Where(r => Eq(r.Type, RuleTypes.ProcessPath)).ToList();
        var cmdRules = activeRules.Where(r => Eq(r.Type, RuleTypes.ProcessCommandLine)).ToList();
        var moduleRules = activeRules.Where(r => Eq(r.Type, RuleTypes.ModuleName)).ToList();
        var signatureRules = activeRules.Where(r => Eq(r.Type, RuleTypes.Signature)).ToList();

        bool needModules = moduleRules.Count > 0 || forceModules;
        bool needSignature = signatureRules.Count > 0 || forceModules;   // 视觉线索需要签名状态
        bool needHashForWhitelist = rules.Whitelist.Processes.Any(w => !string.IsNullOrWhiteSpace(w.Hash))
                                    || rules.Whitelist.Paths.Any(w => !string.IsNullOrWhiteSpace(w.Hash));

        int selfPid = Environment.ProcessId;
        var entries = EnumerateProcessEntries(ct);

        var findings = new ConcurrentBag<Finding>();
        var records = new ConcurrentBag<ProcessRecord>();
        var skipped = new ConcurrentBag<NotChecked>();
        int selfSkipped = 0;

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 2, 8),
            CancellationToken = ct
        };

        Parallel.ForEach(entries, parallelOptions, entry =>
        {
            ct.ThrowIfCancellationRequested();

            // 跳过自身，避免把本工具的模块名当成可疑模块（自我误报）
            if (entry.Pid == selfPid)
            {
                Interlocked.Increment(ref selfSkipped);
                return;
            }

            var rec = new ProcessRecord
            {
                Pid = entry.Pid,
                ParentPid = entry.ParentPid,
                ThreadCount = entry.Threads,
                Name = entry.Name
            };

            var reasons = new List<string>();
            IntPtr handle = IntPtr.Zero;

            try
            {
                handle = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false, (uint)entry.Pid);
                if (handle == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    audit?.ProcessOpen(entry.Pid, entry.Name, NativeMethods.ProcessQueryLimitedInformation, false, err, null);
                    rec.AccessError = $"OpenProcess 失败（Win32={err} {new Win32Exception(err).Message}）";
                    reasons.Add("受保护进程或权限不足：仅完成名称级检查，路径/命令行/模块/签名未采集");
                }
                else
                {
                    rec.ImagePath = NativeMethods.TryGetImagePath(handle);
                    rec.CommandLine = NativeMethods.TryGetCommandLine(handle);
                    audit?.ProcessOpen(entry.Pid, entry.Name, NativeMethods.ProcessQueryLimitedInformation, true, 0, rec.ImagePath);
                }
            }
            catch (Exception ex)
            {
                rec.AccessError = ex.Message;
                reasons.Add($"打开进程异常：{ex.Message}");
            }
            finally
            {
                if (handle != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(handle);
                }
            }

            if (needModules && entry.Pid > 4)
            {
                var modules = TryGetModules(entry.Pid, out string? moduleError);
                if (modules is null)
                {
                    rec.ModuleError = moduleError;
                    reasons.Add($"模块列表不可枚举：{moduleError}");
                }
                else
                {
                    rec.Modules = modules;
                }
            }

            if (needSignature && !string.IsNullOrWhiteSpace(rec.ImagePath))
            {
                rec.Signature = _signatures.Check(rec.ImagePath);
                audit?.SignatureChecked(rec.ImagePath!, rec.Signature.State);
            }

            string? processHash = null;
            if (needHashForWhitelist && !string.IsNullOrWhiteSpace(rec.ImagePath))
            {
                processHash = Hashing.TrySha256(rec.ImagePath!, out _);
            }

            var (whitelisted, wlReason, suppressRules) = EvaluateWhitelist(rules, rec, processHash);

            foreach (var rule in nameRules)
            {
                if (!PatternMatcher.IsMatch(rec.Name, rule.Pattern, rule.Match)) continue;
                findings.Add(Build(rule, rec, rec.Name, whitelisted, wlReason, suppressRules, Scoring.WeightOf(rules, rule.Category), "进程名命中", new()
                {
                    ["matchedField"] = "processName",
                    ["matchedValue"] = rec.Name,
                    ["pid"] = rec.Pid,
                    ["parentPid"] = rec.ParentPid,
                    ["imagePath"] = rec.ImagePath
                }));
            }

            if (!string.IsNullOrWhiteSpace(rec.ImagePath))
            {
                foreach (var rule in pathRules)
                {
                    if (!PatternMatcher.IsMatch(rec.ImagePath, rule.Pattern, rule.Match)) continue;
                    findings.Add(Build(rule, rec, rec.Name, whitelisted, wlReason, suppressRules, Scoring.WeightOf(rules, rule.Category), "映像路径命中", new()
                    {
                        ["matchedField"] = "imagePath",
                        ["matchedValue"] = rec.ImagePath,
                        ["pid"] = rec.Pid,
                        ["signatureState"] = rec.Signature.State,
                        ["signer"] = rec.Signature.SignerSubject
                    }));
                }
            }

            if (!string.IsNullOrWhiteSpace(rec.CommandLine))
            {
                foreach (var rule in cmdRules)
                {
                    if (!PatternMatcher.IsMatch(rec.CommandLine, rule.Pattern, rule.Match)) continue;
                    findings.Add(Build(rule, rec, rec.Name, whitelisted, wlReason, suppressRules, Scoring.WeightOf(rules, rule.Category), "命令行命中", new()
                    {
                        ["matchedField"] = "commandLine",
                        ["matchedValue"] = rec.CommandLine,
                        ["pid"] = rec.Pid
                    }));
                }
            }

            if (moduleRules.Count > 0 && rec.Modules.Count > 0)
            {
                foreach (var rule in moduleRules)
                {
                    var hits = rec.Modules
                        .Where(m => PatternMatcher.IsMatch(m.Name, rule.Pattern, rule.Match))
                        .Select(m => new { name = m.Name, path = m.Path })
                        .ToList();

                    if (hits.Count == 0) continue;

                    findings.Add(Build(rule, rec, rec.Name, whitelisted, wlReason, suppressRules, Scoring.WeightOf(rules, rule.Category), "已加载模块命中", new()
                    {
                        ["matchedField"] = "moduleName",
                        ["matchedValue"] = string.Join("; ", hits.Select(h => h.name)),
                        ["matchedModules"] = hits,
                        ["pid"] = rec.Pid,
                        ["imagePath"] = rec.ImagePath
                    }));
                }
            }

            if (needSignature && !string.IsNullOrWhiteSpace(rec.ImagePath))
            {
                foreach (var rule in signatureRules)
                {
                    if (!SignatureMatches(rule.Pattern, rec.Signature.State)) continue;
                    findings.Add(Build(rule, rec, rec.Name, whitelisted, wlReason, suppressRules, Scoring.WeightOf(rules, rule.Category), "数字签名异常", new()
                    {
                        ["matchedField"] = "authenticode",
                        ["matchedValue"] = rec.Signature.State,
                        ["winTrustStatus"] = rec.Signature.WinTrustStatus is uint s ? $"0x{s:X8}" : null,
                        ["signer"] = rec.Signature.SignerSubject,
                        ["catalogSigned"] = rec.Signature.CatalogSigned,
                        ["pid"] = rec.Pid,
                        ["imagePath"] = rec.ImagePath
                    }));
                }
            }

            if (reasons.Count > 0)
            {
                skipped.Add(new NotChecked
                {
                    Target = entry.Name,
                    Path = rec.ImagePath,
                    Pid = entry.Pid,
                    Reason = string.Join("；", reasons)
                });
            }

            records.Add(rec);
        });

        result.SelfSkipped = selfSkipped;
        result.Findings.AddRange(findings.OrderByDescending(f => f.Score).ThenBy(f => f.RuleId));
        result.Processes.AddRange(records.OrderBy(r => r.Pid));
        result.NotChecked.AddRange(skipped.OrderBy(n => n.Pid ?? 0));
        return result;
    }

    private static bool Eq(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static bool IsSuppressed(bool whitelisted, string[]? suppressRules, string ruleId)
    {
        if (!whitelisted) return false;
        if (suppressRules is null || suppressRules.Length == 0) return true;
        return suppressRules.Any(r => string.Equals(r, ruleId, StringComparison.OrdinalIgnoreCase));
    }

    private static Finding Build(
        Rule rule,
        ProcessRecord rec,
        string target,
        bool whitelisted,
        string? whitelistReason,
        string[]? suppressRules,
        double categoryWeight,
        string fallbackDescription,
        Dictionary<string, object?> evidence)
    {
        bool suppressed = IsSuppressed(whitelisted, suppressRules, rule.Id);
        double score = Scoring.ComputeScore(rule.Severity, rule.Confidence, categoryWeight);
        return new Finding
        {
            RuleId = rule.Id,
            RuleType = rule.Type,
            Target = target,
            TargetPath = rec.ImagePath,
            Pid = rec.Pid,
            Severity = rule.Severity,
            Confidence = rule.Confidence,
            Score = score,
            RiskLevel = Scoring.LevelOf(score),
            Description = string.IsNullOrWhiteSpace(rule.Description) ? fallbackDescription : rule.Description!,
            Advice = rule.Advice,
            Evidence = evidence,
            Category = rule.Category,
            Suppressed = suppressed,
            SuppressReason = suppressed ? whitelistReason : null,
            SuppressedBy = suppressed ? "whitelist" : null
        };
    }

    private static (bool Matched, string? Reason, string[]? SuppressRules) EvaluateWhitelist(RuleSet rules, ProcessRecord rec, string? sha256)
    {
        foreach (var entry in rules.Whitelist.Processes)
        {
            if (RuleLoader.IsExpired(entry)) continue;

            bool nameHit = !string.IsNullOrWhiteSpace(entry.Pattern) &&
                           (entry.Pattern!.Contains('\\') || entry.Pattern.Contains('/')
                               ? PatternMatcher.IsMatch(rec.ImagePath, entry.Pattern, entry.Match)
                               : PatternMatcher.IsMatch(rec.Name, entry.Pattern, entry.Match));

            if (!nameHit) continue;
            if (!string.IsNullOrWhiteSpace(entry.Hash) &&
                !string.Equals(entry.Hash, sha256, StringComparison.OrdinalIgnoreCase)) continue;

            return (true, entry.Reason ?? $"进程白名单: {entry.Pattern}", entry.SuppressRules);
        }

        foreach (var entry in rules.Whitelist.Paths)
        {
            if (RuleLoader.IsExpired(entry)) continue;
            if (string.IsNullOrWhiteSpace(rec.ImagePath)) continue;
            if (!PatternMatcher.IsMatch(rec.ImagePath, entry.Pattern, entry.Match)) continue;
            if (!string.IsNullOrWhiteSpace(entry.Hash) &&
                !string.Equals(entry.Hash, sha256, StringComparison.OrdinalIgnoreCase)) continue;

            return (true, entry.Reason ?? $"路径白名单: {entry.Pattern}", entry.SuppressRules);
        }

        if (!string.IsNullOrWhiteSpace(rec.Signature.SignerSubject))
        {
            foreach (var entry in rules.Whitelist.Signers)
            {
                if (RuleLoader.IsExpired(entry)) continue;
                if (string.IsNullOrWhiteSpace(entry.SubjectContains)) continue;
                if (rec.Signature.SignerSubject!.Contains(entry.SubjectContains!, StringComparison.OrdinalIgnoreCase))
                {
                    return (true, entry.Reason ?? $"签名白名单: {entry.SubjectContains}", entry.SuppressRules);
                }
            }
        }

        return (false, null, null);
    }

    private static bool SignatureMatches(string? pattern, string state)
    {
        return (pattern ?? "").Trim().ToLowerInvariant() switch
        {
            SignaturePatterns.Unsigned => state == SignatureStates.Unsigned,
            SignaturePatterns.BadDigest => state == SignatureStates.BadDigest,
            SignaturePatterns.UntrustedRoot => state is SignatureStates.UntrustedRoot or SignatureStates.InvalidChain,
            SignaturePatterns.Expired => state == SignatureStates.Expired,
            SignaturePatterns.Revoked => state == SignatureStates.Revoked,
            SignaturePatterns.CatalogOnly => state == SignatureStates.CatalogValid,
            SignaturePatterns.AnyInvalid => state is SignatureStates.Unsigned
                or SignatureStates.BadDigest
                or SignatureStates.UntrustedRoot
                or SignatureStates.InvalidChain
                or SignatureStates.Expired
                or SignatureStates.Revoked
                or SignatureStates.Distrusted
                or SignatureStates.Error,
            _ => false
        };
    }

    private static List<ProcEntry> EnumerateProcessEntries(CancellationToken ct)
    {
        var list = new List<ProcEntry>();
        IntPtr snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero || snapshot == NativeMethods.InvalidHandleValue)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) 失败");
        }

        try
        {
            var entry = new NativeMethods.PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<NativeMethods.PROCESSENTRY32W>() };
            if (!NativeMethods.Process32First(snapshot, ref entry))
            {
                return list;
            }

            do
            {
                ct.ThrowIfCancellationRequested();
                list.Add(new ProcEntry(
                    (int)entry.th32ProcessID,
                    (int)entry.th32ParentProcessID,
                    (int)entry.cntThreads,
                    entry.szExeFile ?? ""));
            }
            while (NativeMethods.Process32Next(snapshot, ref entry));
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }

        return list;
    }

    private static List<ModuleInfo>? TryGetModules(int pid, out string? error)
    {
        error = null;
        var list = new List<ModuleInfo>();

        IntPtr snapshot = NativeMethods.CreateToolhelp32Snapshot(
            NativeMethods.TH32CS_SNAPMODULE | NativeMethods.TH32CS_SNAPMODULE32, (uint)pid);

        if (snapshot == IntPtr.Zero || snapshot == NativeMethods.InvalidHandleValue)
        {
            int err = Marshal.GetLastWin32Error();
            error = $"Win32={err} {new Win32Exception(err).Message}";
            return null;
        }

        try
        {
            var me = new NativeMethods.MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<NativeMethods.MODULEENTRY32W>() };
            if (!NativeMethods.Module32First(snapshot, ref me))
            {
                int err = Marshal.GetLastWin32Error();
                if (err != 0)
                {
                    error = $"Win32={err} {new Win32Exception(err).Message}";
                    return null;
                }
                return list;
            }

            do
            {
                list.Add(new ModuleInfo
                {
                    Name = me.szModule ?? "",
                    Path = string.IsNullOrWhiteSpace(me.szExePath) ? null : me.szExePath,
                    BaseAddress = me.modBaseAddr.ToInt64(),
                    Size = me.modBaseSize
                });
            }
            while (NativeMethods.Module32Next(snapshot, ref me));
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }

        return list;
    }
}