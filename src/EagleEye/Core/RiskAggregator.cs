using EagleEye.Models;

namespace EagleEye.Core;

/// <summary>证据链的一节：一条规则命中。</summary>
public sealed class EvidenceLink
{
    public string RuleId { get; set; } = "";
    public string RuleType { get; set; } = "";
    public string? Category { get; set; }
    public int Severity { get; set; }
    public double Confidence { get; set; }
    public double Score { get; set; }
    public string Description { get; set; } = "";
    public Dictionary<string, object?>? Evidence { get; set; }
}

/// <summary>针对单个目标（进程 / 文件 / 设备）的风险判定与证据链。</summary>
public sealed class TargetAssessment
{
    public string TargetKey { get; set; } = "";
    public string Target { get; set; } = "";
    public int? Pid { get; set; }
    public string? Path { get; set; }
    public string RiskLevel { get; set; } = RiskLevels.Info;
    public double Score { get; set; }
    public int StrongSignalCount { get; set; }
    public int MediumSignalCount { get; set; }
    public int WeakSignalCount { get; set; }
    /// <summary>等级是怎么升上去的（组合判定 / 强信号直判）。</summary>
    public List<string> EscalationReasons { get; set; } = new();
    public List<EvidenceLink> Evidence { get; set; } = new();
}

/// <summary>
/// 风险聚合：
///   1) 同一目标的多条规则命中累加（封顶 100）；
///   2) 强信号（severity>=4 且单条 >=70）直接判"高度可疑"；
///   3) 多个弱信号（severity<=2）叠加可升级为"可疑"——对应"组合信号"需求；
///   4) 最终等级取「分值等级」与「组合升级等级」中的较高者。
/// 被白名单抑制的命中不进入聚合。
/// </summary>
public static class RiskAggregator
{
    public static List<TargetAssessment> Assess(IEnumerable<Finding> findings)
    {
        var list = new List<TargetAssessment>();

        foreach (var group in findings.Where(f => !f.Suppressed).GroupBy(KeyOf))
        {
            var items = group.OrderByDescending(f => f.Score).ToList();
            var assessment = new TargetAssessment
            {
                TargetKey = group.Key,
                Target = items[0].Target,
                Pid = items[0].Pid,
                Path = items[0].TargetPath
            };

            foreach (var f in items)
            {
                assessment.Evidence.Add(new EvidenceLink
                {
                    RuleId = f.RuleId,
                    RuleType = f.RuleType,
                    Category = f.Category,
                    Severity = f.Severity,
                    Confidence = f.Confidence,
                    Score = f.Score,
                    Description = f.Description,
                    Evidence = f.Evidence
                });
            }

            assessment.Score = Math.Round(Math.Min(100.0, items.Sum(f => f.Score)), 2);
            assessment.StrongSignalCount = items.Count(f => f.Severity >= 4);
            assessment.MediumSignalCount = items.Count(f => f.Severity == 3);
            assessment.WeakSignalCount = items.Count(f => f.Severity <= 2);

            string byScore = Scoring.LevelOf(assessment.Score);
            string level = byScore;
            if (byScore != RiskLevels.Info)
            {
                assessment.EscalationReasons.Add($"累计得分 {assessment.Score} → {byScore}");
            }

            // 规则 2：强信号直判
            var strongest = items.FirstOrDefault(f => f.Severity >= 4 && f.Score >= Scoring.HighThreshold);
            if (strongest is not null && Scoring.Rank(RiskLevels.High) > Scoring.Rank(level))
            {
                level = RiskLevels.High;
                assessment.EscalationReasons.Add(
                    $"强信号直判：{strongest.RuleId}（severity {strongest.Severity}, 单条 {strongest.Score}）");
            }

            // 规则 3：弱信号组合升级
            if (Scoring.Rank(level) < Scoring.Rank(RiskLevels.Suspicious))
            {
                if (assessment.WeakSignalCount >= 3)
                {
                    level = RiskLevels.Suspicious;
                    assessment.EscalationReasons.Add(
                        $"组合升级：{assessment.WeakSignalCount} 个弱信号叠加（规则：弱信号≥3 视为可疑）");
                }
                else if (assessment.WeakSignalCount >= 2 && assessment.MediumSignalCount >= 1)
                {
                    level = RiskLevels.Suspicious;
                    assessment.EscalationReasons.Add(
                        $"组合升级：{assessment.WeakSignalCount} 弱 + {assessment.MediumSignalCount} 中（规则：弱≥2 且 中≥1 视为可疑）");
                }
                else if (assessment.MediumSignalCount >= 2)
                {
                    level = RiskLevels.Suspicious;
                    assessment.EscalationReasons.Add(
                        $"组合升级：{assessment.MediumSignalCount} 个中信号叠加");
                }
            }

            assessment.RiskLevel = level;
            list.Add(assessment);
        }

        return list
            .OrderByDescending(a => Scoring.Rank(a.RiskLevel))
            .ThenByDescending(a => a.Score)
            .ToList();
    }

    public static (double Score, string Level) Overall(IReadOnlyCollection<TargetAssessment> assessments)
    {
        if (assessments.Count == 0)
        {
            return (0, RiskLevels.Info);
        }

        double topScore = assessments.Max(a => a.Score);
        string level = RiskLevels.Info;
        foreach (var a in assessments)
        {
            level = Scoring.MaxLevel(level, a.RiskLevel);
        }

        return (Math.Round(topScore, 2), level);
    }

    private static string KeyOf(Finding f)
        => f.Pid.HasValue ? "pid:" + f.Pid.Value : "file:" + (f.TargetPath ?? f.Target);
}