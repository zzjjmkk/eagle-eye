using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

namespace EagleEye.Core;

/// <summary>规则匹配：exact / glob / contains / regex，默认 glob，全部忽略大小写。</summary>
public static class PatternMatcher
{
    private static readonly ConcurrentDictionary<string, Regex> Cache = new();

    public static bool IsMatch(string? input, string? pattern, string? matchType)
    {
        if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(pattern))
        {
            return false;
        }

        string mode = (matchType ?? "glob").Trim().ToLowerInvariant();
        switch (mode)
        {
            case "exact":
                return string.Equals(input, pattern, StringComparison.OrdinalIgnoreCase);

            case "contains":
                return input.Contains(pattern, StringComparison.OrdinalIgnoreCase);

            case "regex":
                return GetRegex("r|" + pattern, pattern).IsMatch(input);

            default:
                return GetRegex("g|" + pattern, GlobToRegex(pattern)).IsMatch(input);
        }
    }

    private static Regex GetRegex(string key, string expression)
    {
        return Cache.GetOrAdd(key, _ => new Regex(
            expression,
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            TimeSpan.FromMilliseconds(200)));
    }

    /// <summary>glob → 正则：* 匹配任意字符（含路径分隔符），? 匹配单个字符。</summary>
    public static string GlobToRegex(string glob)
    {
        var sb = new StringBuilder(glob.Length + 8);
        sb.Append('^');
        foreach (char c in glob)
        {
            switch (c)
            {
                case '*':
                    sb.Append(".*");
                    break;
                case '?':
                    sb.Append('.');
                    break;
                default:
                    sb.Append(Regex.Escape(c.ToString()));
                    break;
            }
        }
        sb.Append('$');
        return sb.ToString();
    }
}