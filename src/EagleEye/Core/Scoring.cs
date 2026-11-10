using EagleEye.Models;

namespace EagleEye.Core;

public static class Scoring
{
    public const double SuspiciousThreshold = 40.0;
    public const double HighThreshold = 70.0;

    /// <summary>单条规则得分：severity(1-5) × 20 × confidence(0-1) × 分类权重。</summary>
    public static double ComputeScore(int severity, double confidence, double categoryWeight = 1.0)
    {
        double s = Math.Clamp(severity, 0, 5) * 20.0 * Math.Clamp(confidence, 0.0, 1.0) * Math.Clamp(categoryWeight, 0.0, 5.0);
        return Math.Round(s, 2);
    }

    public static string LevelOf(double score)
    {
        if (score >= HighThreshold) return RiskLevels.High;
        if (score >= SuspiciousThreshold) return RiskLevels.Suspicious;
        return RiskLevels.Info;
    }

    /// <summary>按分类 id 查权重；未定义分类返回 1.0。</summary>
    public static double WeightOf(RuleSet ruleSet, string? categoryId)
    {
        if (string.IsNullOrWhiteSpace(categoryId))
        {
            return 1.0;
        }

        var category = ruleSet.Meta.Categories.FirstOrDefault(
            c => string.Equals(c.Id, categoryId, StringComparison.OrdinalIgnoreCase));

        return category is not null && category.Weight > 0 ? category.Weight : 1.0;
    }

    public static int Rank(string level) => level switch
    {
        RiskLevels.High => 2,
        RiskLevels.Suspicious => 1,
        _ => 0
    };

    public static string MaxLevel(params string[] levels)
        => levels.OrderByDescending(Rank).FirstOrDefault() ?? RiskLevels.Info;
}