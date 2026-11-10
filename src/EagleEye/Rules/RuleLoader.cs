using System.Text.Json;
using EagleEye.Models;

namespace EagleEye.Rules;

public sealed class RuleLoadResult
{
    public RuleSet RuleSet { get; set; } = new();
    public List<string> Errors { get; } = new();
    public List<string> Warnings { get; } = new();
    public string? SourcePath { get; set; }
    public bool Success => Errors.Count == 0;
}

public static class RuleLoader
{
    private static readonly HashSet<string> KnownTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        RuleTypes.ProcessName, RuleTypes.ProcessPath, RuleTypes.ProcessCommandLine,
        RuleTypes.ModuleName, RuleTypes.FileName, RuleTypes.FileHash, RuleTypes.Signature
    };

    private static readonly HashSet<string> KnownSignaturePatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        SignaturePatterns.Unsigned, SignaturePatterns.BadDigest, SignaturePatterns.UntrustedRoot,
        SignaturePatterns.Expired, SignaturePatterns.Revoked, SignaturePatterns.CatalogOnly,
        SignaturePatterns.AnyInvalid
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    // ───────────────────────── 单文件加载 ─────────────────────────
    public static RuleLoadResult Load(string path)
    {
        var result = new RuleLoadResult { SourcePath = path };

        if (!File.Exists(path))
        {
            result.Errors.Add($"规则文件不存在: {path}");
            return result;
        }

        RuleSet? ruleSet;
        try
        {
            ruleSet = JsonSerializer.Deserialize<RuleSet>(File.ReadAllText(path), JsonOptions);
        }
        catch (JsonException ex)
        {
            result.Errors.Add($"规则文件 JSON 解析失败: {ex.Message}");
            return result;
        }

        if (ruleSet is null)
        {
            result.Errors.Add("规则文件解析结果为空");
            return result;
        }

        result.RuleSet = ruleSet;
        Validate(ruleSet, result);
        return result;
    }

    // ───────────────────────── 目录合并加载 ─────────────────────────
    /// <summary>
    /// 加载目录下全部 *.json 并按 id 合并（热更新）。
    /// meta 逐字段覆盖；rules 按 id 后者覆盖前者；whitelist 追加去重；
    /// options/dma/vision/deep/telemetry 出现即整段替换。
    /// </summary>
    public static RuleLoadResult LoadDirectory(string directory)
    {
        var result = new RuleLoadResult { SourcePath = directory };

        if (!Directory.Exists(directory))
        {
            result.Errors.Add($"规则目录不存在: {directory}");
            return result;
        }

        // rules.json 作为基础规则集优先（决定 meta/options/各段默认值），
        // 其余补丁包按文件名顺序后合并
        var files = Directory.GetFiles(directory, "*.json", SearchOption.TopDirectoryOnly)
            .OrderBy(f => Path.GetFileName(f).Equals("rules.json", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(f => Path.GetFileName(f), StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (files.Count == 0)
        {
            result.Errors.Add($"规则目录里没有 json 文件: {directory}");
            return result;
        }

        var merged = new RuleSet();
        var ruleIndex = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        int overrides = 0;
        bool firstFile = true;

        foreach (string file in files)
        {
            string name = Path.GetFileName(file);

            RuleSet? part;
            HashSet<string> keys;
            try
            {
                string text = File.ReadAllText(file);
                using var doc = JsonDocument.Parse(text, new JsonDocumentOptions
                {
                    AllowTrailingCommas = true,
                    CommentHandling = JsonCommentHandling.Skip
                });

                keys = doc.RootElement.EnumerateObject().Select(p => p.Name)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                part = JsonSerializer.Deserialize<RuleSet>(text, JsonOptions);
            }
            catch (JsonException ex)
            {
                result.Errors.Add($"{name} JSON 解析失败: {ex.Message}");
                continue;
            }

            if (part is null)
            {
                result.Errors.Add($"{name} 解析结果为空");
                continue;
            }

            result.Warnings.Add($"已加载: {name}（规则 {part.Rules.Count} 条，白名单 {CountWhitelistEntries(part.Whitelist)} 条）");

            if (firstFile)
            {
                merged.Meta = part.Meta;
                merged.Options = part.Options;
                merged.Dma = part.Dma;
                merged.Vision = part.Vision;
                merged.Deep = part.Deep;
                merged.Telemetry = part.Telemetry;
                firstFile = false;
            }

            if (keys.Contains("meta"))
            {
                // 名称/版本/更新时间只认第一份（基础规则集），否则会被后加载的补丁包改名
                // 例如 tuning.suggested.json 会把整个规则集显示成 "tuning-suggested"
                foreach (var category in part.Meta.Categories)
                {
                    if (!merged.Meta.Categories.Any(c => string.Equals(c.Id, category.Id, StringComparison.OrdinalIgnoreCase)))
                    {
                        merged.Meta.Categories.Add(category);
                    }
                }

                if (string.IsNullOrWhiteSpace(merged.Meta.Description) && !string.IsNullOrWhiteSpace(part.Meta.Description))
                {
                    merged.Meta.Description = part.Meta.Description;
                }

            }


            if (keys.Contains("options")) merged.Options = part.Options;
            if (keys.Contains("dma")) merged.Dma = part.Dma;
            if (keys.Contains("vision")) merged.Vision = part.Vision;
            if (keys.Contains("deep")) merged.Deep = part.Deep;
            if (keys.Contains("telemetry")) merged.Telemetry = part.Telemetry;

            foreach (var rule in part.Rules)
            {
                if (ruleIndex.TryGetValue(rule.Id, out int index))
                {
                    merged.Rules[index] = rule;
                    overrides++;
                }
                else
                {
                    ruleIndex[rule.Id] = merged.Rules.Count;
                    merged.Rules.Add(rule);
                }
            }

            if (keys.Contains("whitelist"))
            {
                AppendWhitelist(merged.Whitelist, part.Whitelist);
            }
        }

        if (overrides > 0)
        {
            result.Warnings.Add($"规则 id 冲突 {overrides} 条，已按文件名顺序后者覆盖前者");
        }

        result.RuleSet = merged;
        Validate(merged, result);
        return result;
    }

    private static void AppendWhitelist(Whitelist target, Whitelist source)
    {
        void Merge(List<WhitelistEntry> dst, List<WhitelistEntry> src)
        {
            foreach (var entry in src)
            {
                bool exists = dst.Any(d =>
                    string.Equals(d.Pattern, entry.Pattern, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(d.Hash, entry.Hash, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(d.SubjectContains, entry.SubjectContains, StringComparison.OrdinalIgnoreCase));

                if (!exists) dst.Add(entry);
            }
        }

        Merge(target.Processes, source.Processes);
        Merge(target.Paths, source.Paths);
        Merge(target.Files, source.Files);
        Merge(target.Signers, source.Signers);
    }

    // ───────────────────────── 校验 ─────────────────────────
    private static void Validate(RuleSet ruleSet, RuleLoadResult result)
    {
        if (string.IsNullOrWhiteSpace(ruleSet.Meta.Name))
        {
            result.Warnings.Add("meta.name 为空");
        }

        var idSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < ruleSet.Rules.Count; i++)
        {
            var rule = ruleSet.Rules[i];
            string where = $"rules[{i}]";

            if (string.IsNullOrWhiteSpace(rule.Id))
            {
                result.Errors.Add($"{where}.id 不能为空");
            }
            else if (!idSeen.Add(rule.Id))
            {
                result.Errors.Add($"{where}.id 重复: {rule.Id}");
            }
            else
            {
                where = $"rules[{i}]({rule.Id})";
            }

            if (string.IsNullOrWhiteSpace(rule.Type))
            {
                result.Errors.Add($"{where}.type 不能为空");
            }
            else if (!KnownTypes.Contains(rule.Type))
            {
                result.Warnings.Add($"{where}.type 未知类型，将被忽略: {rule.Type}");
            }

            if (rule.Severity is < 1 or > 5)
            {
                result.Errors.Add($"{where}.severity 必须在 1-5 之间，当前 {rule.Severity}");
            }

            if (rule.Confidence is < 0 or > 1)
            {
                result.Errors.Add($"{where}.confidence 必须在 0-1 之间，当前 {rule.Confidence}");
            }

            switch (rule.Type.ToLowerInvariant())
            {
                case RuleTypes.FileHash:
                    if (string.IsNullOrWhiteSpace(rule.Hash) || rule.Hash.Length != 64)
                    {
                        result.Errors.Add($"{where}.hash 必须是 64 位 SHA256 十六进制");
                    }
                    break;

                case RuleTypes.Signature:
                    if (string.IsNullOrWhiteSpace(rule.Pattern) || !KnownSignaturePatterns.Contains(rule.Pattern))
                    {
                        result.Errors.Add($"{where}.pattern 必须是 unsigned|bad_digest|untrusted_root|expired|revoked|catalog_only|any_invalid");
                    }
                    break;

                default:
                    if (string.IsNullOrWhiteSpace(rule.Pattern))
                    {
                        result.Errors.Add($"{where}.pattern 不能为空");
                    }
                    break;
            }

            if (rule.Enabled && rule.Severity >= 4 && rule.Confidence < 0.5)
            {
                result.Warnings.Add($"{where} 高危规则但置信度偏低（{rule.Confidence}），可能放大误报");
            }
        }

        ValidateWhitelist(ruleSet.Whitelist, result);
        ValidateDma(ruleSet.Dma, result);
        ValidateVision(ruleSet.Vision, result);
        ValidateDeep(ruleSet.Deep, result);
        ValidateTelemetry(ruleSet.Telemetry, result);
    }

    private static void ValidateWhitelist(Whitelist whitelist, RuleLoadResult result)
    {
        void Check(List<WhitelistEntry> entries, string section)
        {
            for (int i = 0; i < entries.Count; i++)
            {
                var e = entries[i];
                if (string.IsNullOrWhiteSpace(e.Pattern) && string.IsNullOrWhiteSpace(e.Hash) && string.IsNullOrWhiteSpace(e.SubjectContains))
                {
                    result.Errors.Add($"whitelist.{section}[{i}] 至少要给 pattern / hash / subjectContains 之一");
                }

                if (!string.IsNullOrWhiteSpace(e.Hash) && e.Hash.Length != 64)
                {
                    result.Errors.Add($"whitelist.{section}[{i}].hash 必须是 64 位 SHA256 十六进制");
                }

                if (!string.IsNullOrWhiteSpace(e.Expires) && !DateTime.TryParse(e.Expires, out _))
                {
                    result.Warnings.Add($"whitelist.{section}[{i}].expires 格式不合法（应为 yyyy-MM-dd）: {e.Expires}");
                }
            }
        }

        Check(whitelist.Processes, "processes");
        Check(whitelist.Paths, "paths");
        Check(whitelist.Files, "files");
        Check(whitelist.Signers, "signers");
    }

    private static void ValidateDma(DmaSection dma, RuleLoadResult result)
    {
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < dma.Rules.Count; i++)
        {
            var rule = dma.Rules[i];
            string where = $"dma.rules[{i}]";

            if (string.IsNullOrWhiteSpace(rule.Id))
            {
                result.Errors.Add($"{where}.id 不能为空");
            }
            else if (!ids.Add(rule.Id))
            {
                result.Errors.Add($"{where}.id 重复: {rule.Id}");
            }
            else
            {
                where = $"dma.rules[{i}]({rule.Id})";
            }

            if (string.IsNullOrWhiteSpace(rule.Vid) && string.IsNullOrWhiteSpace(rule.ClassCode))
            {
                result.Warnings.Add($"{where} 既没有 vid 也没有 classCode，会匹配全部 PCI 设备");
            }

            if (!string.IsNullOrWhiteSpace(rule.Vid) && rule.Vid!.TrimStart('0', 'x', 'X').Length is < 1 or > 4)
            {
                result.Errors.Add($"{where}.vid 必须是 4 位十六进制，如 10EE");
            }

            if (!string.IsNullOrWhiteSpace(rule.Pid) && rule.Pid!.TrimStart('0', 'x', 'X').Length is < 1 or > 4)
            {
                result.Errors.Add($"{where}.pid 必须是 4 位十六进制，如 7024");
            }

            if (rule.Severity is < 1 or > 5)
            {
                result.Errors.Add($"{where}.severity 必须在 1-5 之间，当前 {rule.Severity}");
            }

            if (rule.Confidence is < 0 or > 1)
            {
                result.Errors.Add($"{where}.confidence 必须在 0-1 之间，当前 {rule.Confidence}");
            }

            if (rule.Severity >= 4 && rule.Confidence > 0.8)
            {
                result.Warnings.Add($"{where} 用户态无法验证配置空间，建议 confidence 不超过 0.8");
            }
        }

        foreach (var w in dma.Whitelist)
        {
            if (string.IsNullOrWhiteSpace(w.Vid) && string.IsNullOrWhiteSpace(w.Pid))
            {
                result.Errors.Add("dma.whitelist 条目至少要给 vid 或 pid");
            }
        }
    }

    private static void ValidateVision(VisionSection vision, RuleLoadResult result)
    {
        if (!vision.Enabled) return;

        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in vision.Capture.ModuleRules.Concat(vision.Hardware.Rules))
        {
            if (string.IsNullOrWhiteSpace(rule.Id))
            {
                result.Errors.Add("vision 规则 id 不能为空");
                continue;
            }

            if (!ids.Add(rule.Id))
            {
                result.Errors.Add($"vision 规则 id 重复: {rule.Id}");
            }

            if (rule.Severity is < 1 or > 4)
            {
                result.Errors.Add($"vision[{rule.Id}].severity 必须在 1-4 之间（视觉线索不应给高危）");
            }

            if (rule.Confidence is < 0 or > 0.7)
            {
                result.Errors.Add($"vision[{rule.Id}].confidence 必须在 0-0.7 之间（本地线索置信度上限 0.7）");
            }

            bool isHardware = !string.IsNullOrWhiteSpace(rule.VendorId) || !string.IsNullOrWhiteSpace(rule.Service);
            if (!isHardware && string.IsNullOrWhiteSpace(rule.Pattern))
            {
                result.Errors.Add($"vision[{rule.Id}] 既没有 pattern 也没有 vid/service");
            }
        }

        if (ScoringRank(vision.Aggregation.MaxLevel) > ScoringRank(RiskLevels.Suspicious))
        {
            result.Errors.Add("vision.aggregation.maxLevel 不得高于「可疑」：视觉线索不能单独定为高度可疑");
        }

        if (vision.Aggregation.RequireIndependentLayers is < 1 or > 3)
        {
            result.Errors.Add("vision.aggregation.requireIndependentLayers 必须在 1-3 之间");
        }

        foreach (var w in vision.Whitelist)
        {
            if (string.IsNullOrWhiteSpace(w.ProcessPattern) && string.IsNullOrWhiteSpace(w.VendorId))
            {
                result.Errors.Add("vision.whitelist 条目至少要给 processPattern 或 vid");
            }
        }
    }

    private static int ScoringRank(string level) => level switch
    {
        RiskLevels.High => 2,
        RiskLevels.Suspicious => 1,
        _ => 0
    };

    private static void ValidateDeep(DeepSection deep, RuleLoadResult result)
    {
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in deep.Handles.Rules.Where(r => r.Enabled))
        {
            if (string.IsNullOrWhiteSpace(rule.Id)) { result.Errors.Add("deep.handles 规则 id 不能为空"); continue; }
            if (!ids.Add(rule.Id)) result.Errors.Add($"deep 规则 id 重复: {rule.Id}");
            if (rule.Severity is < 1 or > 5) result.Errors.Add($"deep.handles[{rule.Id}].severity 必须在 1-5");
            if (rule.Confidence is < 0 or > 1) result.Errors.Add($"deep.handles[{rule.Id}].confidence 必须在 0-1");
        }

        foreach (var rule in deep.Drivers.Rules.Where(r => r.Enabled))
        {
            if (string.IsNullOrWhiteSpace(rule.Id)) { result.Errors.Add("deep.drivers 规则 id 不能为空"); continue; }
            if (!ids.Add(rule.Id)) result.Errors.Add($"deep 规则 id 重复: {rule.Id}");
            if (string.IsNullOrWhiteSpace(rule.Pattern) && string.IsNullOrWhiteSpace(rule.Sha256))
                result.Errors.Add($"deep.drivers[{rule.Id}] 需要 pattern 或 sha256");
            if (rule.Severity is < 1 or > 5) result.Errors.Add($"deep.drivers[{rule.Id}].severity 必须在 1-5");
        }

        foreach (var rule in deep.FileSignatures.Rules.Where(r => r.Enabled))
        {
            if (string.IsNullOrWhiteSpace(rule.Id)) { result.Errors.Add("deep.fileSignatures 规则 id 不能为空"); continue; }
            if (string.IsNullOrWhiteSpace(rule.Pattern)) result.Errors.Add($"deep.fileSignatures[{rule.Id}] 需要 pattern");
            string type = (rule.PatternType ?? "ascii").ToLowerInvariant();
            if (type is not ("ascii" or "hex"))
                result.Errors.Add($"deep.fileSignatures[{rule.Id}].patternType 只能是 ascii 或 hex");
        }

        if (deep.Overlay.MinAreaRatio is <= 0 or > 1)
            result.Errors.Add("deep.overlay.minAreaRatio 必须在 (0,1] 区间");
    }

    private static void ValidateTelemetry(TelemetrySection telemetry, RuleLoadResult result)
    {
        if (!telemetry.Enabled) return;

        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in telemetry.Signals.Where(r => r.Enabled))
        {
            if (string.IsNullOrWhiteSpace(rule.Id)) { result.Errors.Add("telemetry 规则 id 不能为空"); continue; }
            if (!ids.Add(rule.Id)) result.Errors.Add($"telemetry 规则 id 重复: {rule.Id}");
            if (string.IsNullOrWhiteSpace(rule.Metric)) result.Errors.Add($"telemetry[{rule.Id}].metric 不能为空");
            if ((rule.Comparator ?? "gte").ToLowerInvariant() is not ("gte" or "lte"))
                result.Errors.Add($"telemetry[{rule.Id}].comparator 只能是 gte 或 lte");
            if (rule.Severity is < 1 or > 5) result.Errors.Add($"telemetry[{rule.Id}].severity 必须在 1-5");
            if (rule.Confidence is < 0 or > 1) result.Errors.Add($"telemetry[{rule.Id}].confidence 必须在 0-1");
        }

        foreach (var rule in telemetry.Signals.Where(r => !string.IsNullOrWhiteSpace(r.Metric)))
        {
            if (!telemetry.Baseline.ContainsKey(rule.Metric))
                result.Warnings.Add($"telemetry[{rule.Id}] 的 metric '{rule.Metric}' 没有基线值，报告里无法给出人群对比");
        }
    }

    public static int CountWhitelistEntries(Whitelist w)
        => w.Processes.Count + w.Paths.Count + w.Files.Count + w.Signers.Count;

    public static bool IsExpired(WhitelistEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.Expires)) return false;
        return DateTime.TryParse(entry.Expires, out var d) && d.Date < DateTime.Today;
    }
}
