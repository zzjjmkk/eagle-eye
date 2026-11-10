using EagleEye.Core;
using EagleEye.Models;
using EagleEye.Rules;

namespace EagleEye.Scanning;

public sealed class FileScanResult
{
    public int FilesScanned { get; set; }
    public int FilesHashed { get; set; }
    public bool Truncated { get; set; }
    public List<Finding> Findings { get; } = new();
    public List<NotChecked> NotChecked { get; } = new();
}

/// <summary>
/// 文件扫描：只读遍历配置目录，按文件名规则 + SHA256 名单比对。
/// 不写文件、不改属性、不跟随符号链接。
/// </summary>
public sealed class FileScanner
{
    public FileScanResult Scan(RuleSet rules, IEnumerable<string> extraRoots, CancellationToken ct, AuditLogger? audit = null)
    {
        var result = new FileScanResult();
        var config = rules.Options;

        var nameRules = rules.Rules.Where(r => r.Enabled && IsType(r.Type, RuleTypes.FileName)).ToList();
        var hashRules = rules.Rules.Where(r => r.Enabled && IsType(r.Type, RuleTypes.FileHash)).ToList();

        bool needHash = hashRules.Count > 0 || rules.Whitelist.Files.Any(w => !string.IsNullOrWhiteSpace(w.Hash));

        var hashRuleMap = hashRules
            .Where(r => !string.IsNullOrWhiteSpace(r.Hash))
            .GroupBy(r => r.Hash!.ToLowerInvariant())
            .ToDictionary(g => g.Key, g => g.ToList());

        var sizePrefilter = hashRules
            .Where(r => r.Size.HasValue)
            .Select(r => r.Size!.Value)
            .ToHashSet();

        var extensions = new HashSet<string>(
            config.IncludeExtensions.Select(e => e.StartsWith('.') ? e : "." + e),
            StringComparer.OrdinalIgnoreCase);

        var roots = new List<string>();
        foreach (string raw in config.ScanRoots.Concat(extraRoots))
        {
            string expanded = Environment.ExpandEnvironmentVariables(raw);
            if (Directory.Exists(expanded))
            {
                roots.Add(expanded);
            }
            else
            {
                result.NotChecked.Add(new NotChecked { Target = raw, Reason = "扫描目录不存在或不可访问，已跳过" });
            }
        }

        if (roots.Count == 0)
        {
            return result;
        }

        foreach (string file in EnumerateFiles(roots, config.MaxDepth, result, ct))
        {
            ct.ThrowIfCancellationRequested();

            if (result.FilesScanned >= config.MaxFiles)
            {
                result.Truncated = true;
                result.NotChecked.Add(new NotChecked
                {
                    Target = string.Join("; ", roots),
                    Reason = $"已达到 maxFiles={config.MaxFiles} 上限，扫描不完整"
                });
                break;
            }

            string fileName = Path.GetFileName(file);
            if (!extensions.Contains(Path.GetExtension(file)))
            {
                continue;
            }

            long size = 0;
            try
            {
                size = new FileInfo(file).Length;
            }
            catch (Exception ex)
            {
                result.NotChecked.Add(new NotChecked { Target = fileName, Path = file, Reason = $"读取文件大小失败: {ex.Message}" });
                continue;
            }

            if (size > config.MaxFileSizeBytes)
            {
                result.NotChecked.Add(new NotChecked
                {
                    Target = fileName,
                    Path = file,
                    Reason = $"文件过大（{size} 字节），超过 maxFileSizeBytes，未计算哈希"
                });
                continue;
            }

            result.FilesScanned++;

            string? sha256 = null;
            bool sizeMatchesRule = sizePrefilter.Count == 0 || sizePrefilter.Contains(size);

            if (needHash && sizeMatchesRule && result.FilesHashed < config.MaxHashFiles && size > 0)
            {
                sha256 = Hashing.TrySha256(file, out string? hashError);
                if (sha256 is null)
                {
                    result.NotChecked.Add(new NotChecked { Target = fileName, Path = file, Reason = $"计算 SHA256 失败: {hashError}" });
                }
                else
                {
                    result.FilesHashed++;
                }
            }

            var (whitelisted, wlReason, suppressRules) = EvaluateWhitelist(rules, file, fileName, sha256);

            foreach (var rule in nameRules)
            {
                if (!PatternMatcher.IsMatch(fileName, rule.Pattern, rule.Match)) continue;
                result.Findings.Add(Build(rule, fileName, file, size, sha256, whitelisted, wlReason, suppressRules, Scoring.WeightOf(rules, rule.Category), "文件名命中", "fileName", fileName));
            }

            if (sha256 is not null && hashRuleMap.TryGetValue(sha256, out var matchedHashRules))
            {
                foreach (var rule in matchedHashRules)
                {
                    result.Findings.Add(Build(rule, fileName, file, size, sha256, whitelisted, wlReason, suppressRules, Scoring.WeightOf(rules, rule.Category), "SHA256 命中已知名单", "sha256", sha256));
                }
            }
        }

        result.Findings.Sort((a, b) => b.Score.CompareTo(a.Score));
        return result;
    }

    private static bool IsType(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static bool IsSuppressed(bool whitelisted, string[]? suppressRules, string ruleId)
    {
        if (!whitelisted) return false;
        if (suppressRules is null || suppressRules.Length == 0) return true;
        return suppressRules.Any(r => string.Equals(r, ruleId, StringComparison.OrdinalIgnoreCase));
    }

    private static Finding Build(
        Rule rule,
        string fileName,
        string fullPath,
        long size,
        string? sha256,
        bool whitelisted,
        string? whitelistReason,
        string[]? suppressRules,
        double categoryWeight,
        string fallbackDescription,
        string matchedField,
        string matchedValue)
    {
        bool suppressed = IsSuppressed(whitelisted, suppressRules, rule.Id);
        double score = Scoring.ComputeScore(rule.Severity, rule.Confidence, categoryWeight);
        return new Finding
        {
            RuleId = rule.Id,
            RuleType = rule.Type,
            Target = fileName,
            TargetPath = fullPath,
            Pid = null,
            Severity = rule.Severity,
            Confidence = rule.Confidence,
            Score = score,
            RiskLevel = Scoring.LevelOf(score),
            Description = string.IsNullOrWhiteSpace(rule.Description) ? fallbackDescription : rule.Description!,
            Advice = rule.Advice,
            Category = rule.Category,
            Suppressed = suppressed,
            SuppressReason = suppressed ? whitelistReason : null,
            SuppressedBy = suppressed ? "whitelist" : null,
            Evidence = new Dictionary<string, object?>
            {
                ["matchedField"] = matchedField,
                ["matchedValue"] = matchedValue,
                ["fileName"] = fileName,
                ["fullPath"] = fullPath,
                ["sizeBytes"] = size,
                ["sha256"] = sha256
            }
        };
    }

    private static (bool Matched, string? Reason, string[]? SuppressRules) EvaluateWhitelist(RuleSet rules, string fullPath, string fileName, string? sha256)
    {
        foreach (var entry in rules.Whitelist.Files)
        {
            if (RuleLoader.IsExpired(entry)) continue;

            bool hit = !string.IsNullOrWhiteSpace(entry.Pattern) && PatternMatcher.IsMatch(fileName, entry.Pattern, entry.Match);
            if (!hit && !string.IsNullOrWhiteSpace(entry.Hash) && sha256 is not null)
            {
                hit = string.Equals(entry.Hash, sha256, StringComparison.OrdinalIgnoreCase);
            }

            if (!hit) continue;
            if (!string.IsNullOrWhiteSpace(entry.Hash) &&
                !string.Equals(entry.Hash, sha256, StringComparison.OrdinalIgnoreCase)) continue;

            return (true, entry.Reason ?? $"文件白名单: {entry.Pattern ?? entry.Hash}", entry.SuppressRules);
        }

        foreach (var entry in rules.Whitelist.Paths)
        {
            if (RuleLoader.IsExpired(entry)) continue;
            if (string.IsNullOrWhiteSpace(entry.Pattern)) continue;
            if (!PatternMatcher.IsMatch(fullPath, entry.Pattern, entry.Match)) continue;

            return (true, entry.Reason ?? $"路径白名单: {entry.Pattern}", entry.SuppressRules);
        }

        return (false, null, null);
    }

    private static IEnumerable<string> EnumerateFiles(List<string> roots, int maxDepth, FileScanResult result, CancellationToken ct)
    {
        var stack = new Stack<(string Dir, int Depth)>();
        foreach (string root in roots)
        {
            stack.Push((root, 0));
        }

        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (dir, depth) = stack.Pop();

            string[] files;
            try
            {
                files = Directory.GetFiles(dir);
            }
            catch (Exception ex)
            {
                result.NotChecked.Add(new NotChecked { Target = dir, Reason = $"目录不可读，已跳过: {ex.Message}" });
                continue;
            }

            foreach (string f in files)
            {
                yield return f;
            }

            if (depth >= maxDepth)
            {
                continue;
            }

            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(dir);
            }
            catch
            {
                continue;
            }

            foreach (string sub in subDirs)
            {
                try
                {
                    var info = new DirectoryInfo(sub);
                    if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    {
                        continue;
                    }
                }
                catch
                {
                    continue;
                }

                stack.Push((sub, depth + 1));
            }
        }
    }
}