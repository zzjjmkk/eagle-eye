using System.Text;
using EagleEye.Core;
using EagleEye.Models;

namespace EagleEye.Scanning;

/// <summary>
/// 文件特征码扫描：只读文件前 N 字节，做 ASCII / 十六进制字节匹配。
/// 用途：识别没有哈希记录、但二进制里有已知特征的样本（如注入器字符串、驱动名）。
/// 只读：FileStream(Read) + 只读首部缓冲，不执行、不解包、不写回。
/// </summary>
public sealed class FileSignatureScanner
{
    public (FileSignatureReport Report, List<Finding> Findings) Scan(
        FileSignatureOptions options,
        IEnumerable<string> roots,
        CancellationToken ct,
        AuditLogger? audit = null)
    {
        var report = new FileSignatureReport { Enabled = options.Enabled };
        var findings = new List<Finding>();
        if (!options.Enabled || options.Rules.Count == 0)
        {
            return (report, findings);
        }

        var patterns = new List<(FileSignatureRule Rule, byte[] Bytes)>();
        foreach (var rule in options.Rules.Where(r => r.Enabled))
        {
            byte[]? bytes = rule.PatternType.Equals("hex", StringComparison.OrdinalIgnoreCase)
                ? ParseHex(rule.Pattern)
                : Encoding.ASCII.GetBytes(rule.Pattern);

            if (bytes is null || bytes.Length == 0)
            {
                report.Error = $"规则 {rule.Id} 的特征码格式不正确";
                continue;
            }

            patterns.Add((rule, bytes));
        }

        if (patterns.Count == 0) return (report, findings);

        var extensions = new HashSet<string>(
            options.IncludeExtensions.Select(e => e.StartsWith('.') ? e : "." + e),
            StringComparer.OrdinalIgnoreCase);

        var buffer = new byte[options.MaxBytesPerFile];
        int scanned = 0;

        foreach (string file in Enumerate(roots, ct))
        {
            if (scanned >= options.MaxFiles)
            {
                report.Error = $"达到 maxFiles={options.MaxFiles} 上限，扫描不完整";
                break;
            }

            if (!extensions.Contains(Path.GetExtension(file))) continue;

            long size;
            try { size = new FileInfo(file).Length; }
            catch { continue; }

            if (size == 0 || size > options.MaxBytesPerFile) continue;

            int read;
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                read = fs.Read(buffer, 0, (int)Math.Min(size, buffer.Length));
            }
            catch
            {
                continue;
            }

            scanned++;
            report.FilesScanned = scanned;

            var span = new ReadOnlySpan<byte>(buffer, 0, read);

            foreach (var (rule, bytes) in patterns)
            {
                ct.ThrowIfCancellationRequested();
                if (span.IndexOf(bytes) < 0) continue;

                string? sha = Hashing.TrySha256(file, out _);
                report.FilesMatched++;
                report.Hits.Add(new FileSignatureHit
                {
                    RuleId = rule.Id,
                    FileName = Path.GetFileName(file),
                    Path = file,
                    Size = size,
                    Sha256 = sha,
                    Pattern = rule.Pattern
                });

                double score = Scoring.ComputeScore(rule.Severity, rule.Confidence);
                findings.Add(new Finding
                {
                    RuleId = rule.Id,
                    RuleType = "file_signature",
                    Category = "file_signature",
                    Target = Path.GetFileName(file),
                    TargetPath = file,
                    Severity = rule.Severity,
                    Confidence = rule.Confidence,
                    Score = score,
                    RiskLevel = Scoring.LevelOf(score),
                    Description = rule.Description ?? $"文件命中特征码：{rule.Pattern}",
                    Evidence = new Dictionary<string, object?>
                    {
                        ["path"] = file,
                        ["sizeBytes"] = size,
                        ["sha256"] = sha,
                        ["patternType"] = rule.PatternType,
                        ["pattern"] = rule.Pattern,
                        ["note"] = "只读文件首部字节做匹配，未执行、未解包"
                    }
                });

                break;   // 一个文件只记一条，避免刷屏
            }
        }

        audit?.Write("file.signature", new { scanned = report.FilesScanned, matched = report.FilesMatched });
        return (report, findings);
    }

    private static byte[]? ParseHex(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex)) return null;

        string clean = hex.Replace(" ", "").Replace("-", "");
        if (clean.Contains('?')) return null;   // 不支持通配符，避免误报

        if (clean.Length % 2 != 0) return null;

        var bytes = new byte[clean.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            if (!byte.TryParse(clean.AsSpan(i * 2, 2), System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
            {
                return null;
            }
        }

        return bytes;
    }

    private static IEnumerable<string> Enumerate(IEnumerable<string> roots, CancellationToken ct)
    {
        foreach (string root in roots)
        {
            string expanded = Environment.ExpandEnvironmentVariables(root);
            if (!Directory.Exists(expanded)) continue;

            var stack = new Stack<string>();
            stack.Push(expanded);
            int guard = 0;

            while (stack.Count > 0 && guard++ < 20000)
            {
                ct.ThrowIfCancellationRequested();
                string dir = stack.Pop();

                string[] files;
                try { files = Directory.GetFiles(dir); }
                catch { continue; }

                foreach (string f in files) yield return f;

                string[] subs;
                try { subs = Directory.GetDirectories(dir); }
                catch { continue; }

                foreach (string s in subs)
                {
                    try
                    {
                        if (new DirectoryInfo(s).Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;
                    }
                    catch { continue; }

                    stack.Push(s);
                }
            }
        }
    }
}