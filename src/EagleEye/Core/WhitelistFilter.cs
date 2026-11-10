using EagleEye.Models;
using EagleEye.Rules;

namespace EagleEye.Core;

/// <summary>
/// 统一的命中后置白名单过滤。
/// ProcessScanner / FileScanner 在生成命中时已经判过一次白名单；
/// 这里兜底处理句柄、驱动、overlay、特征码等"来自其它探测器"的命中，
/// 保证一条白名单对所有来源都生效（含 suppressRules 定向抑制）。
/// </summary>
public static class WhitelistFilter
{
    public static int Apply(RuleSet rules, IEnumerable<Finding> findings)
    {
        int suppressed = 0;

        foreach (var finding in findings)
        {
            if (finding.Suppressed) continue;
            if (string.IsNullOrWhiteSpace(finding.Target)) continue;

            foreach (var entry in rules.Whitelist.Processes)
            {
                if (RuleLoader.IsExpired(entry)) continue;
                if (string.IsNullOrWhiteSpace(entry.Pattern)) continue;
                if (!PatternMatcher.IsMatch(finding.Target, entry.Pattern, entry.Match)) continue;

                bool applies = entry.SuppressRules is null || entry.SuppressRules.Length == 0 ||
                               entry.SuppressRules.Any(r => string.Equals(r, finding.RuleId, StringComparison.OrdinalIgnoreCase));

                if (!applies) continue;

                finding.Suppressed = true;
                finding.SuppressReason = entry.Reason ?? $"白名单: {entry.Pattern}";
                finding.SuppressedBy = "whitelist";
                suppressed++;
                break;
            }
        }

        return suppressed;
    }
}