using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using EagleEye.Models;
using EagleEye.Rules;

namespace EagleEye.Reporting;

/// <summary>
/// 规则调参：从一批带标签的扫描报告里统计每条规则的真实误报/命中表现，
/// 产出可直接放进 rules\ 的调参包（rules\tuning.suggested.json）。
///
/// 判定策略（刻意保守）：
///   · 只在干净机器命中、作弊样本 0 次 → 噪音
///       - 目标数 ≤ whitelistThreshold → 只加白，不动规则
///       - 受保护类型（句柄/驱动/哈希/特征码）→ 只降权，不停用
///       - 普通类型且干净报告 ≥ disableAt → 停用
///   · 干净/作弊都命中 → 保留规则，只把"干净出现、作弊从未出现"的目标加白
/// </summary>
public static class RuleTuner
{
    public sealed class Options
    {
        public string ReportsDir { get; set; } = "";
        public string? OutputPath { get; set; }
        public string Label { get; set; } = "clean";
        public string? RulesDir { get; set; }
        public double ConfidenceFactor { get; set; } = 0.6;
        public int DisableAt { get; set; } = 3;
        public int WhitelistThreshold { get; set; } = 20;
        public int MinRuleCount { get; set; } = 10;
        public bool NoWhitelist { get; set; }
    }

    private static readonly HashSet<string> ProtectedTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "handle_access", "kernel_driver", "file_hash", "file_signature"
    };

    private sealed class Stat
    {
        public string RuleId { get; init; } = "";
        public HashSet<string> Clean { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Cheat { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Types { get; } = new();
        public double ScoreSum { get; set; }
        public int Hits { get; set; }
    }

    public static int Run(Options options, bool quiet)
    {
        if (!Directory.Exists(options.ReportsDir))
        {
            Console.Error.WriteLine($"报告目录不存在: {options.ReportsDir}");
            return 1;
        }

        var reports = Directory.GetFiles(options.ReportsDir, "*.json", SearchOption.TopDirectoryOnly)
            .Where(f => !Path.GetFileName(f).StartsWith("aggregate", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f)
            .ToList();

        var stats = new Dictionary<string, Stat>(StringComparer.OrdinalIgnoreCase);
        int cleanReports = 0, cheatReports = 0;

        foreach (string file in reports)
        {
            JsonDocument doc;
            try { doc = JsonDocument.Parse(File.ReadAllText(file)); }
            catch { continue; }

            using (doc)
            {
                var root = doc.RootElement;
                if (!root.TryGetProperty("tool", out var tool) || tool.GetString() != "EagleEye")
                {
                    continue;
                }

                // 跳过验证用的小规则包
                if (root.TryGetProperty("ruleset", out var rs) &&
                    rs.TryGetProperty("ruleCount", out var rc) && rc.GetInt32() < options.MinRuleCount)
                {
                    continue;
                }

                bool isCheat = Path.GetFileName(file).StartsWith("cheat-", StringComparison.OrdinalIgnoreCase);
                if (isCheat) cheatReports++; else cleanReports++;

                if (!root.TryGetProperty("findings", out var findings) || findings.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var f in findings.EnumerateArray())
                {
                    string ruleId = f.TryGetProperty("ruleId", out var id) ? id.GetString() ?? "" : "";
                    if (ruleId.Length == 0) continue;

                    string target = f.TryGetProperty("target", out var tg) ? tg.GetString() ?? "" : "";
                    string type = f.TryGetProperty("ruleType", out var rt) ? rt.GetString() ?? "" : "";
                    double score = f.TryGetProperty("score", out var sc) ? sc.GetDouble() : 0;

                    if (!stats.TryGetValue(ruleId, out var stat))
                    {
                        stat = new Stat { RuleId = ruleId };
                        stats[ruleId] = stat;
                    }

                    if (isCheat) stat.Cheat.Add(target); else stat.Clean.Add(target);
                    stat.ScoreSum += score;
                    stat.Hits++;
                    if (type.Length > 0 && !stat.Types.Contains(type)) stat.Types.Add(type);
                }
            }
        }

        if (cleanReports == 0 && cheatReports == 0)
        {
            Console.Error.WriteLine($"目录里没有可用的扫描报告: {options.ReportsDir}");
            return 1;
        }

        // 主规则集（用于复制完整定义做覆盖）
        string rulesDir = options.RulesDir ?? Path.Combine(AppContext.BaseDirectory, "rules");
        var ruleSet = RuleLoader.LoadDirectory(rulesDir).RuleSet;

        // 可被覆盖的规则（只有通用 rules[] 能写回 schema）
        var ruleById = ruleSet.Rules.ToDictionary(r => r.Id, r => r, StringComparer.OrdinalIgnoreCase);

        // 全部已知规则 id（含 DMA / 视觉 / 深度段）—— 用于判断"这条规则是不是真的存在"
        var knownIds = new HashSet<string>(ruleSet.Rules.Select(r => r.Id), StringComparer.OrdinalIgnoreCase);
        foreach (var r in ruleSet.Dma.Rules) knownIds.Add(r.Id);
        foreach (var r in ruleSet.Vision.Capture.ModuleRules) knownIds.Add(r.Id);
        foreach (var r in ruleSet.Vision.Hardware.Rules) knownIds.Add(r.Id);
        foreach (var r in ruleSet.Deep.Handles.Rules) knownIds.Add(r.Id);
        foreach (var r in ruleSet.Deep.Drivers.Rules) knownIds.Add(r.Id);
        foreach (var r in ruleSet.Deep.FileSignatures.Rules) knownIds.Add(r.Id);

        var rows = new List<(string RuleId, string Types, int Clean, int Cheat, double AvgScore, string Action)>();
        var tuningRules = new List<Rule>();
        var whitelist = new List<WhitelistEntry>();

        foreach (var stat in stats.Values)
        {
            var cleanOnly = stat.Clean.Where(t => !stat.Cheat.Contains(t)).ToList();
            bool isRealRule = knownIds.Contains(stat.RuleId);
            bool noise = isRealRule && stat.Clean.Count > 0 && stat.Cheat.Count == 0;
            bool isProtected = stat.Types.Any(t => ProtectedTypes.Contains(t));

            string action = "保留";
            if (noise)
            {
                if (stat.Clean.Count <= options.WhitelistThreshold) action = "仅加白";
                else if (isProtected) action = "建议降权（受保护类型）";
                else if (stat.Clean.Count >= options.DisableAt) action = "建议停用";
                else action = "建议降权";
            }

            double avg = stat.Hits > 0 ? Math.Round(stat.ScoreSum / stat.Hits, 1) : 0;
            rows.Add((stat.RuleId, string.Join("/", stat.Types), stat.Clean.Count, stat.Cheat.Count, avg, action));

            // 需要动规则的：复制完整定义后调整
            if (noise && action != "仅加白" && ruleById.TryGetValue(stat.RuleId, out var baseRule))
            {
                var copy = new Rule
                {
                    Id = baseRule.Id,
                    Type = baseRule.Type,
                    Category = baseRule.Category,
                    Pattern = baseRule.Pattern,
                    Match = baseRule.Match,
                    Hash = baseRule.Hash,
                    Size = baseRule.Size,
                    Severity = baseRule.Severity,
                    Confidence = Math.Round(baseRule.Confidence * options.ConfidenceFactor, 3),
                    Enabled = action != "建议停用",
                    Description = $"调参：干净基线命中 {stat.Clean.Count} 次、作弊样本 0 次 —— {baseRule.Description}",
                    Advice = baseRule.Advice,
                    Tags = baseRule.Tags
                };

                tuningRules.Add(copy);
            }

            // 目标级精准加白
            if (isRealRule && !options.NoWhitelist && cleanOnly.Count > 0 && cleanOnly.Count <= 50)
            {
                foreach (string target in cleanOnly)
                {
                    if (target.Length == 0 || target.StartsWith("pid", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                        !target.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                        !target.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)) continue;

                    whitelist.Add(new WhitelistEntry
                    {
                        Pattern = target,
                        Match = "exact",
                        Reason = $"调参基线：{stat.RuleId} 在干净机器命中、作弊样本从未出现",
                        SuppressRules = new[] { stat.RuleId }
                    });
                }
            }
        }

        // 输出
        string outPath = options.OutputPath ?? Path.Combine(rulesDir, "tuning.suggested.json");
        var pack = new
        {
            meta = new
            {
                name = "tuning-suggested",
                version = DateTime.Now.ToString("yyyy.MM.dd.HHmm"),
                updated = DateTime.Now.ToString("yyyy-MM-dd"),
                schemaVersion = "2.0",
                description = $"由 tune 命令生成：基于 {cleanReports} 份干净报告 / {cheatReports} 份作弊报告"
            },
            rules = tuningRules,
            whitelist = new
            {
                processes = whitelist,
                paths = Array.Empty<object>(),
                files = Array.Empty<object>(),
                signers = Array.Empty<object>()
            }
        };

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outPath))!);
        File.WriteAllText(outPath, JsonSerializer.Serialize(pack, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }), new UTF8Encoding(false));

        if (!quiet)
        {
            Console.WriteLine();
            Console.WriteLine($"调参分析：{cleanReports} 份干净 / {cheatReports} 份作弊");
            Console.WriteLine();
            Console.WriteLine($"{"规则",-34}{"类型",-16}{"干净",6}{"作弊",6}{"均分",8}  判定");
            foreach (var row in rows.OrderByDescending(r => r.Clean).Take(25))
            {
                Console.WriteLine($"{Trim(row.RuleId, 34),-34}{Trim(row.Types, 16),-16}{row.Clean,6}{row.Cheat,6}{row.AvgScore,8}  {row.Action}");
            }

            Console.WriteLine();
            Console.WriteLine($"调参包: {Path.GetFullPath(outPath)}（规则调整 {tuningRules.Count} 条，白名单 {whitelist.Count} 条）");
            Console.WriteLine("应用: 把该文件放进 rules\\ 目录，下次扫描自动生效");
        }

        return 0;
    }

    private static string Trim(string text, int max)
        => text.Length <= max ? text : text[..(max - 1)] + "…";
}
