using System.Text.Json;
using EagleEye.Core;
using EagleEye.Models;

namespace EagleEye.Scanning;

/// <summary>
/// 游戏侧遥测与本机线索的联合评估。
/// 遥测来自游戏/运营侧导出的**本地文件**（本工具不联网，不发起任何请求）。
///
/// 联合口径：
///   本机信息 + 遥测信息        → 信息
///   本机信息 + 遥测可疑/高危    → 可疑（本地无痕迹，指向双机/硬件链路）
///   本机可疑 + 遥测可疑/高危    → 高度可疑（建议人工复核 + 取证）
///   本机可疑 + 遥测信息        → 可疑（有痕迹但无行为异常）
/// 任何情况下都只给"复核优先级"，不给"作弊判定"。
/// </summary>
public static class TelemetryCorrelator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        NumberHandling = System.Text.Json.Serialization.JsonNumberHandling.AllowReadingFromString
    };

    public static TelemetryReport Load(string path, TelemetrySection section, string localLevel)
    {
        var report = new TelemetryReport
        {
            Enabled = section.Enabled,
            SourcePath = Path.GetFullPath(path),
            LocalLevel = localLevel
        };

        TelemetryFile? file;
        try
        {
            string json = File.ReadAllText(path);
            file = JsonSerializer.Deserialize<TelemetryFile>(json, JsonOptions);
        }
        catch (Exception ex)
        {
            report.Error = $"遥测文件读取/解析失败: {ex.Message}";
            report.JointLevel = localLevel;
            return report;
        }

        if (file is null)
        {
            report.Error = "遥测文件解析结果为空";
            report.JointLevel = localLevel;
            return report;
        }

        report.Loaded = true;
        report.SchemaVersion = file.SchemaVersion;
        report.ExportedUtc = file.ExportedUtc;
        report.Sessions = file.Sessions.Count;

        if (file.Sessions.Count == 0)
        {
            report.Error = "遥测文件里没有 sessions";
            report.JointLevel = localLevel;
            return report;
        }

        foreach (var session in file.Sessions)
        {
            report.Assessments.Add(AssessSession(session, section));
        }

        // 取最"热"的一场作为联合依据
        var hottest = report.Assessments
            .OrderByDescending(a => Scoring.Rank(a.TelemetryLevel))
            .ThenByDescending(a => a.TelemetryScore)
            .First();

        var (jointLevel, reasons) = Combine(localLevel, hottest, section);
        report.JointLevel = jointLevel;
        report.JointScore = hottest.TelemetryScore;
        report.JointReasons = reasons;

        return report;
    }

    private static SessionAssessment AssessSession(TelemetrySession session, TelemetrySection section)
    {
        var assessment = new SessionAssessment
        {
            SessionId = session.SessionId,
            MatchId = session.MatchId,
            PlayerId = session.PlayerId,
            AccountName = session.AccountName,
            StartedUtc = session.StartedUtc,
            DurationSeconds = session.DurationSeconds
        };

        foreach (var rule in section.Signals.Where(r => r.Enabled))
        {
            if (!session.Metrics.TryGetValue(rule.Metric, out double value)) continue;

            bool hit = rule.Comparator.Equals("lte", StringComparison.OrdinalIgnoreCase)
                ? value <= rule.Threshold
                : value >= rule.Threshold;

            if (!hit) continue;

            bool baselineKnown = section.Baseline.TryGetValue(rule.Metric, out double baseline);
            double score = Scoring.ComputeScore(rule.Severity, rule.Confidence);

            assessment.Signals.Add(new TelemetrySignal
            {
                RuleId = rule.Id,
                Metric = rule.Metric,
                Description = rule.Description ?? $"{rule.Metric} {rule.Comparator} {rule.Threshold}",
                Value = value,
                Threshold = rule.Threshold,
                Baseline = baselineKnown ? baseline : 0,
                BaselineKnown = baselineKnown,
                Severity = rule.Severity,
                Confidence = rule.Confidence,
                Score = score,
                RiskLevel = Scoring.LevelOf(score),
                Advice = rule.Advice
            });
        }

        assessment.Signals.Sort((a, b) => b.Score.CompareTo(a.Score));
        assessment.TelemetryScore = Math.Round(Math.Min(100.0, assessment.Signals.Sum(s => s.Score)), 2);
        assessment.TelemetryLevel = Scoring.LevelOf(assessment.TelemetryScore);

        foreach (var signal in assessment.Signals)
        {
            string baselineText = signal.BaselineKnown
                ? $"，人群基线 {signal.Baseline}（本次 {signal.Value}）"
                : string.Empty;
            assessment.Reasons.Add($"{signal.RuleId}: {signal.Metric}={signal.Value}（阈值 {signal.Threshold}{baselineText}）");
        }

        return assessment;
    }

    private static (string Level, List<string> Reasons) Combine(string localLevel, SessionAssessment telemetry, TelemetrySection section)
    {
        var reasons = new List<string>();
        int localRank = Scoring.Rank(localLevel);
        int telemetryRank = Scoring.Rank(telemetry.TelemetryLevel);

        string level;
        if (telemetryRank == 0 && localRank == 0)
        {
            level = RiskLevels.Info;
            reasons.Add("本机无线索，遥测无异常 → 无进一步动作");
        }
        else if (telemetryRank >= 1 && localRank == 0)
        {
            level = RiskLevels.Suspicious;
            reasons.Add("遥测出现行为异常，但本机进程/驱动/句柄全部干净 → 高度指向双机链路、外部采集卡或硬件转发");
            reasons.Add("建议：调取该玩家的对局录像与设备指纹，而不是继续在本机找证据");
        }
        else if (telemetryRank >= 1 && localRank >= 1)
        {
            level = Scoring.MaxLevel(section.BothSidesLevel, RiskLevels.Suspicious);
            reasons.Add("遥测行为异常 + 本机存在痕迹 → 两侧证据互相印证，优先复核");
        }
        else
        {
            level = RiskLevels.Suspicious;
            reasons.Add("本机存在痕迹，但遥测未见行为异常 → 可能是误装、残留工具，或尚未在对局中使用");
            reasons.Add("建议：让玩家清理后复测，而不是直接处罚");
        }

        foreach (string r in telemetry.Reasons.Take(5))
        {
            reasons.Add("遥测：" + r);
        }

        return (level, reasons);
    }
}