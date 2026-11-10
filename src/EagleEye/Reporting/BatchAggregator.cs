using System.Text;
using System.Text.Json;

namespace EagleEye.Reporting;

/// <summary>
/// 批量汇总：把一次运营行动里收集到的多份报告合成一张总表。
/// 只读本地 JSON 文件，不联网、不改原始报告。
/// </summary>
public static class BatchAggregator
{
    private sealed class MachineRow
    {
        public string File { get; init; } = "";
        public string Machine { get; init; } = "";
        public string Time { get; init; } = "";
        public string Risk { get; init; } = "";
        public double Score { get; init; }
        public int Findings { get; init; }
        public int Suppressed { get; init; }
        public bool Elevated { get; init; }
        public int NotChecked { get; init; }
        public bool CoverageComplete => Elevated;
    }

    private sealed class RuleStat
    {
        public string RuleId { get; init; } = "";
        public int Machines { get; set; }
        public int Hits { get; set; }
        public double AvgScore { get; set; }
    }

    private sealed class TargetStat
    {
        public string Target { get; init; } = "";
        public int Machines { get; set; }
        public double MaxScore { get; set; }
    }

    public static int Run(string dir, string? outMd, string? outJson, bool quiet)
    {
        if (!Directory.Exists(dir))
        {
            Console.Error.WriteLine($"目录不存在: {dir}");
            return 1;
        }

        var files = Directory.GetFiles(dir, "*.json", SearchOption.TopDirectoryOnly)
            .Where(f => !Path.GetFileName(f).StartsWith("aggregate", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f)
            .ToList();

        var machines = new List<MachineRow>();
        var rules = new Dictionary<string, RuleStat>(StringComparer.OrdinalIgnoreCase);
        var targets = new Dictionary<string, TargetStat>(StringComparer.OrdinalIgnoreCase);

        foreach (string file in files)
        {
            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(File.ReadAllText(file));
            }
            catch
            {
                continue;
            }

            using (doc)
            {
                var root = doc.RootElement;

                if (!root.TryGetProperty("tool", out var tool) ||
                    tool.GetString() != "EagleEye")
                {
                    continue;
                }

                string machine = Get(root, "machine");
                string time = Get(root, "scanFinishedUtc");

                var summary = root.TryGetProperty("summary", out var s) ? s : default;
                var row = new MachineRow
                {
                    File = Path.GetFileName(file),
                    Machine = machine,
                    Time = time.Length >= 19 ? time[..19].Replace('T', ' ') : time,
                    Risk = summary.ValueKind == JsonValueKind.Object ? Get(summary, "riskLevel") : "",
                    Score = summary.ValueKind == JsonValueKind.Object && summary.TryGetProperty("totalScore", out var ts) ? ts.GetDouble() : 0,
                    Findings = summary.ValueKind == JsonValueKind.Object && summary.TryGetProperty("findings", out var fc) ? fc.GetInt32() : 0,
                    Suppressed = summary.ValueKind == JsonValueKind.Object && summary.TryGetProperty("suppressedFindings", out var sc) ? sc.GetInt32() : 0,
                    Elevated = root.TryGetProperty("isElevated", out var el) && el.GetBoolean(),
                    NotChecked = summary.ValueKind == JsonValueKind.Object && summary.TryGetProperty("notCheckedCount", out var nc) ? nc.GetInt32() : 0
                };

                machines.Add(row);

                if (root.TryGetProperty("findings", out var findings) && findings.ValueKind == JsonValueKind.Array)
                {
                    var seenRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var seenTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    foreach (var f in findings.EnumerateArray())
                    {
                        string ruleId = Get(f, "ruleId");
                        string target = Get(f, "target");
                        double score = f.TryGetProperty("score", out var fs) ? fs.GetDouble() : 0;

                        if (!string.IsNullOrEmpty(ruleId))
                        {
                            if (!rules.TryGetValue(ruleId, out var rs))
                            {
                                rs = new RuleStat { RuleId = ruleId };
                                rules[ruleId] = rs;
                            }

                            rs.Hits++;
                            rs.AvgScore += score;
                            if (seenRules.Add(ruleId)) rs.Machines++;
                        }

                        if (!string.IsNullOrEmpty(target))
                        {
                            if (!targets.TryGetValue(target, out var tg))
                            {
                                tg = new TargetStat { Target = target };
                                targets[target] = tg;
                            }

                            tg.MaxScore = Math.Max(tg.MaxScore, score);
                            if (seenTargets.Add(target)) tg.Machines++;
                        }
                    }
                }
            }
        }

        if (machines.Count == 0)
        {
            Console.Error.WriteLine($"没有找到本工具生成的报告: {dir}");
            return 1;
        }

        foreach (var rs in rules.Values)
        {
            if (rs.Hits > 0) rs.AvgScore = Math.Round(rs.AvgScore / rs.Hits, 1);
        }

        var ruleList = rules.Values.OrderByDescending(r => r.Machines).ThenByDescending(r => r.Hits).ToList();
        var targetList = targets.Values.OrderByDescending(t => t.Machines).ThenByDescending(t => t.MaxScore).Take(50).ToList();

        string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        string aggDir = Path.Combine(dir, "aggregates");
        Directory.CreateDirectory(aggDir);

        outMd ??= Path.Combine(aggDir, $"aggregate-{stamp}.md");
        outJson ??= Path.Combine(aggDir, $"aggregate-{stamp}.json");

        // ── JSON ──
        var payload = new
        {
            generatedAt = DateTime.UtcNow.ToString("o"),
            sourceDir = Path.GetFullPath(dir),
            machines = machines.Select(m => new
            {
                m.File, m.Machine, m.Time, m.Risk, m.Score, m.Findings, m.Suppressed,
                m.Elevated, m.NotChecked, m.CoverageComplete
            }),
            ruleStats = ruleList.Select(r => new { r.RuleId, r.Machines, r.Hits, r.AvgScore }),
            topTargets = targetList.Select(t => new { t.Target, t.Machines, t.MaxScore }),
            coverage = new
            {
                total = machines.Count,
                complete = machines.Count(m => m.CoverageComplete),
                partial = machines.Count(m => !m.CoverageComplete),
                note = "elevated=false 的机器扫描不完整（受保护进程读不到），结论需谨慎"
            }
        };

        File.WriteAllText(outJson, JsonSerializer.Serialize(payload,
            new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }),
            new UTF8Encoding(false));

        // ── Markdown ──
        var md = new StringBuilder();
        md.AppendLine("# 批量扫描汇总");
        md.AppendLine();
        md.AppendLine($"- 报告数：{machines.Count}（完整覆盖 {payload.coverage.complete} / 不完整 {payload.coverage.partial}）");
        md.AppendLine($"- 来源目录：{Path.GetFullPath(dir)}");
        md.AppendLine($"- 生成时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        md.AppendLine();

        md.AppendLine("## 各机器结果");
        md.AppendLine();
        md.AppendLine("| 机器 | 时间(UTC) | 等级 | 分数 | 命中 | 抑制 | 提权 | 未检查 |");
        md.AppendLine("|---|---|---|---|---|---|---|---|");
        foreach (var m in machines.OrderByDescending(x => x.Score))
        {
            md.AppendLine($"| {m.Machine} | {m.Time} | {m.Risk} | {m.Score} | {m.Findings} | {m.Suppressed} | {(m.Elevated ? "是" : "**否**")} | {m.NotChecked} |");
        }
        md.AppendLine();

        md.AppendLine("## 规则命中排行");
        md.AppendLine();
        md.AppendLine("| 规则 | 命中机器数 | 命中次数 | 平均分 |");
        md.AppendLine("|---|---|---|---|");
        foreach (var r in ruleList.Take(20))
        {
            md.AppendLine($"| {r.RuleId} | {r.Machines} | {r.Hits} | {r.AvgScore} |");
        }
        md.AppendLine();

        md.AppendLine("## 反复出现的对象（前 20）");
        md.AppendLine();
        md.AppendLine("| 对象 | 出现机器数 | 最高分 |");
        md.AppendLine("|---|---|---|");
        foreach (var t in targetList.Take(20))
        {
            md.AppendLine($"| {t.Target} | {t.Machines} | {t.MaxScore} |");
        }

        File.WriteAllText(outMd, md.ToString(), new UTF8Encoding(false));

        if (!quiet)
        {
            Console.WriteLine();
            Console.WriteLine($"批量汇总：{machines.Count} 份报告（完整 {payload.coverage.complete} / 不完整 {payload.coverage.partial}）");
            Console.WriteLine();
            Console.WriteLine("机器                 等级      分数   命中 抑制  提权");
            foreach (var m in machines.OrderByDescending(x => x.Score).Take(20))
            {
                Console.WriteLine($"{Trim(m.Machine, 20),-20} {m.Risk,-8} {m.Score,6} {m.Findings,5} {m.Suppressed,4}  {(m.Elevated ? "是" : "否")}");
            }

            if (payload.coverage.partial > 0)
            {
                Console.WriteLine();
                Console.WriteLine($"注意：{payload.coverage.partial} 台机器未提权，扫描不完整，结论需谨慎");
            }

            Console.WriteLine();
            Console.WriteLine($"Markdown: {Path.GetFullPath(outMd)}");
            Console.WriteLine($"JSON    : {Path.GetFullPath(outJson)}");
        }

        return 0;
    }

    private static string Get(JsonElement element, string name)
        => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? ""
            : "";

    private static string Trim(string text, int max)
        => text.Length <= max ? text : text[..(max - 1)] + "…";
}
