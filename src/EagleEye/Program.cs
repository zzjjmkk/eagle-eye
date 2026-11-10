using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using EagleEye.Core;
using EagleEye.Kernel;
using EagleEye.Models;
using EagleEye.Native;
using EagleEye.Reporting;
using EagleEye.Rules;
using EagleEye.Scanning;

namespace EagleEye;

internal static class Program
{
    private const string ToolVersion = "2.0.0";

    private static int Main(string[] args)
    {
        try
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
        }
        catch
        {
            // 控制台编码设置失败不影响主流程
        }

        try
        {
            return Run(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[FATAL] {ex.GetType().Name}: {ex.Message}");
            Console.Error.WriteLine(ex.StackTrace);
            return 1;
        }
    }

    private static int Run(string[] args)
    {
        if (args.Length == 0)
        {
            return Wizard.Run();
        }

        if (args[0] is "-h" or "--help" or "help" or "/?")
        {
            PrintHelp();
            return 0;
        }

        string command = args[0].StartsWith("-", StringComparison.Ordinal) ? "scan" : args[0].ToLowerInvariant();
        var options = ParseOptions(args);
        ApplyProfile(options);

        if (command is not ("scan" or "validate" or "selftest" or "aggregate" or "tune"))
        {
            Console.Error.WriteLine($"未知命令: {args[0]}");
            PrintHelp();
            return 1;
        }

        if (command == "aggregate")
        {
            string aggregateDir = options.AggregateDir ?? Path.Combine(OutputRoot(), "reports");

            int aggregateCode = BatchAggregator.Run(aggregateDir, options.AggregateMd, options.AggregateJson, options.Quiet);
            if (aggregateCode != 0 || !options.WithTune)
            {
                return aggregateCode;
            }

            Console.WriteLine();
            Console.WriteLine("-- 继续做调参 --");
            return RuleTuner.Run(new RuleTuner.Options
            {
                ReportsDir = aggregateDir,
                Label = options.TuneLabel,
                RulesDir = options.RulesDir,
                OutputPath = options.TuneOutputPath
            }, options.Quiet);
        }

        if (command == "tune")
        {
            return RuleTuner.Run(new RuleTuner.Options
            {
                ReportsDir = options.AggregateDir ?? Path.Combine(OutputRoot(), "reports"),
                Label = options.TuneLabel,
                RulesDir = options.RulesDir,
                OutputPath = options.TuneOutputPath,
                NoWhitelist = options.NoWhitelist
            }, options.Quiet);
        }

        RuleLoadResult load;

        if (!string.IsNullOrWhiteSpace(options.RulesDir))
        {
            load = RuleLoader.LoadDirectory(options.RulesDir!);
        }
        else if (!string.IsNullOrWhiteSpace(options.RulesPath))
        {
            load = RuleLoader.Load(options.RulesPath!);
        }
        else
        {
            // 默认：加载 exe 同目录的 rules 目录（把专项包/情报包一并合并），
            // 目录不存在再退回单文件
            string defaultDir = Path.Combine(AppContext.BaseDirectory, "rules");
            bool hasJson = Directory.Exists(defaultDir) &&
                           Directory.GetFiles(defaultDir, "*.json").Length > 0;

            load = hasJson
                ? RuleLoader.LoadDirectory(defaultDir)
                : RuleLoader.Load(ResolveRulesPath(null));
        }
        PrintRuleInfo(load);

        if (!load.Success)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("规则校验失败，已停止：");
            foreach (string err in load.Errors)
            {
                Console.Error.WriteLine("  - " + err);
            }
            return 1;
        }

        if (command == "validate")
        {
            Console.WriteLine();
            Console.WriteLine("规则校验通过。");
            return 0;
        }

        if (command == "selftest")
        {
            return SelfTest.Run(load, options.Quiet);
        }

        return ExecuteScan(load, options);
    }

    /// <summary>供向导调用的简化入口：等价于 scan（标准档位）。</summary>
    internal static int RunScanFromWizard(string rulesDir)
    {
        var load = RuleLoader.LoadDirectory(rulesDir);
        if (!load.Success)
        {
            return 1;
        }

        var options = new Options { RulesDir = rulesDir };
        ApplyProfile(options);
        return ExecuteScan(load, options);
    }

    private static int ExecuteScan(RuleLoadResult load, Options options)
    {
        var ruleSet = load.RuleSet;
        DateTime startedUtc = DateTime.UtcNow;
        var stopwatch = Stopwatch.StartNew();

        using var audit = new AuditLogger(options.LogPath ?? DefaultLogPath());
        audit.Write("scan.start", new
        {
            tool = "EagleEye",
            version = ToolVersion,
            rulesPath = load.SourcePath,
            rulesVersion = ruleSet.Meta.Version,
            rulesUpdated = ruleSet.Meta.Updated,
            options = new
            {
                fileScan = options.FileScanEnabled,
                dma = options.DmaEnabled,
                kernel = options.KernelEnabled,
                allProcesses = options.AllProcesses,
                timeoutSeconds = options.TimeoutSeconds
            },
            note = "本工具不发起任何网络请求，不上传任何数据"
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Max(10, options.TimeoutSeconds)));

        string sigCachePath = options.SigCachePath ?? Path.Combine(OutputRoot(), "cache", "sigcache.json");

        var signatureChecker = new SignatureChecker(
            options.CheckRevocation,
            string.IsNullOrEmpty(sigCachePath) ? null : sigCachePath);
        var processResult = new ProcessScanResult();
        FileScanResult? fileResult = null;
        DmaScanResult? dmaResult = null;
        VisionScanResult? visionResult = null;
        DeepScanResult? deepResult = null;
        bool timedOut = false;

        try
        {
            processResult = new ProcessScanner(signatureChecker).Scan(ruleSet, cts.Token, audit, ruleSet.Vision.Enabled && options.VisionEnabled);

            if (options.FileScanEnabled)
            {
                fileResult = new FileScanner().Scan(ruleSet, options.FileRoots, cts.Token, audit);
            }

            if (options.DmaEnabled && ruleSet.Dma.Enabled)
            {
                Func<List<DmaDeviceInfo>, ConfigSpaceReadResult>? configReader = null;

                if (options.KernelEnabled)
                {
                    var kernelOptions = ruleSet.Dma.Kernel;
                    string driverPath = options.DriverPath ?? Path.Combine(AppContext.BaseDirectory, kernelOptions.DriverFileName);
                    configReader = devices => ConfigSpaceProvider.ReadAll(
                        devices, driverPath, kernelOptions.ServiceName, kernelOptions.DevicePath);
                }

                dmaResult = new DmaScanner().Scan(ruleSet.Dma, cts.Token, ruleSet, configReader);

                if (dmaResult.Kernel is { } kernel)
                {
                    audit.DriverEvent("load", ruleSet.Dma.Kernel.ServiceName, kernel.DriverPath,
                        kernel.Loaded, kernel.Error);
                    if (kernel.Loaded)
                    {
                        audit.DriverEvent("unload", ruleSet.Dma.Kernel.ServiceName, kernel.DriverPath,
                            kernel.Unloaded, kernel.Error);
                    }
                }
            }
            if (options.VisionEnabled && ruleSet.Vision.Enabled)
            {
                visionResult = new VisionScanner().Scan(
                    ruleSet, processResult, dmaResult?.Devices, cts.Token, audit, options.VisionBehavior);
            }

            if (options.DeepEnabled)
            {
                deepResult = ExtendedScans.Run(ruleSet, processResult, new DeepScanRequest
                {
                    Handles = options.HandleScan,
                    Drivers = options.DriverScan,
                    Overlay = options.OverlayScan,
                    FileSignatures = options.FileSignatureScan,
                    FileRoots = options.FileRoots.ToList()
                }, signatureChecker, cts.Token, audit);

                if (visionResult is not null && deepResult.Overlays.Count > 0)
                {
                    visionResult.SoftwareCapture.AddRange(deepResult.Overlays);
                    VisionScanner.Aggregate(ruleSet.Vision, visionResult);
                }
            }
        }
        catch (OperationCanceledException)
        {
            timedOut = true;
        }

        signatureChecker.SaveCache();
        stopwatch.Stop();

        // ---- 命中分区：白名单抑制项不参与聚合，但保留记录 ----
        var allFindings = new List<Finding>();
        allFindings.AddRange(processResult.Findings);
        if (fileResult is not null)
        {
            allFindings.AddRange(fileResult.Findings);
        }
        if (deepResult is not null)
        {
            allFindings.AddRange(deepResult.Findings);
        }

        // 统一后置白名单：让句柄/驱动/overlay/特征码的命中也能被白名单抑制
        WhitelistFilter.Apply(ruleSet, allFindings);

        var activeFindings = allFindings.Where(f => !f.Suppressed).ToList();
        var suppressedFindings = allFindings.Where(f => f.Suppressed).ToList();
        activeFindings.Sort((a, b) => b.Score.CompareTo(a.Score));
        suppressedFindings.Sort((a, b) => b.Score.CompareTo(a.Score));

        var dmaFindings = dmaResult?.Findings ?? new List<DmaFinding>();
        var activeDma = dmaFindings.Where(f => !f.Suppressed).ToList();

        // ---- 风险聚合（进程/文件 + DMA 设备统一评估）----
        var aggregateInput = new List<Finding>(activeFindings);
        aggregateInput.AddRange(activeDma.Select(ToAggregateFinding));
        var assessments = RiskAggregator.Assess(aggregateInput);
        var (overallScore, overallLevel) = RiskAggregator.Overall(assessments);

        var (dmaScore, dmaLevel) = AggregateDma(activeDma);

        // 游戏侧遥测：离线文件导入，不联网
        TelemetryReport? telemetryReport = null;
        if (!string.IsNullOrWhiteSpace(options.TelemetryPath) && ruleSet.Telemetry.Enabled)
        {
            telemetryReport = TelemetryCorrelator.Load(options.TelemetryPath!, ruleSet.Telemetry, overallLevel);
            audit.Write("telemetry.load", new
            {
                path = telemetryReport.SourcePath,
                loaded = telemetryReport.Loaded,
                sessions = telemetryReport.Sessions,
                localLevel = telemetryReport.LocalLevel,
                jointLevel = telemetryReport.JointLevel,
                note = "离线文件导入，未发起任何网络请求"
            });
        }

        var notChecked = new List<NotChecked>();
        int unreadable = processResult.NotChecked.Count(n => n.Reason.Contains("拒绝访问", StringComparison.OrdinalIgnoreCase));
        notChecked.AddRange(processResult.NotChecked);
        if (fileResult is not null) notChecked.AddRange(fileResult.NotChecked);
        if (dmaResult is not null) notChecked.AddRange(dmaResult.NotChecked);
        if (deepResult is not null) notChecked.AddRange(deepResult.NotChecked);
        if (timedOut)
        {
            notChecked.Add(new NotChecked { Target = "scan", Reason = $"扫描超时（{options.TimeoutSeconds}s），结果不完整" });
        }

        var report = new ScanReport
        {
            Tool = "EagleEye",
            Version = ToolVersion,
            ScanStartedUtc = startedUtc.ToString("o"),
            ScanFinishedUtc = DateTime.UtcNow.ToString("o"),
            DurationSeconds = Math.Round(stopwatch.Elapsed.TotalSeconds, 2),
            Machine = Environment.MachineName,
            OsVersion = RuntimeInformation.OSDescription,
            UserName = Environment.UserName,
            IsElevated = IsElevated(),
            Ruleset = new RuleSetSummary
            {
                Name = ruleSet.Meta.Name,
                Version = ruleSet.Meta.Version,
                Updated = ruleSet.Meta.Updated,
                SchemaVersion = ruleSet.Meta.SchemaVersion,
                Path = load.SourcePath,
                RuleCount = ruleSet.Rules.Count + ruleSet.Dma.Rules.Count,
                EnabledRuleCount = ruleSet.Rules.Count(r => r.Enabled) + ruleSet.Dma.Rules.Count(r => r.Enabled),
                WhitelistCount = RuleLoader.CountWhitelistEntries(ruleSet.Whitelist) + ruleSet.Dma.Whitelist.Count,
                Categories = ruleSet.Meta.Categories.Select(c => $"{c.Id}:{c.Name}").ToList(),
                Warnings = load.Warnings.ToList()
            },
            Audit = new AuditSummary
            {
                LogPath = audit.LogPath,
                ProcessOpenAttempts = audit.ProcessOpenAttempts,
                ProcessOpenDenied = audit.ProcessOpenDenied,
                SignatureChecks = audit.SignatureChecks,
                SignatureCacheNew = signatureChecker.NewEntries,
                SignatureCacheSize = signatureChecker.CacheSize,
                DriverLoadAttempts = audit.DriverLoadAttempts,
                DriverLoaded = audit.DriverLoaded,
                DriverUnloaded = audit.DriverUnloaded,
                NetworkUsed = false
            },
            Findings = activeFindings,
            SuppressedFindings = suppressedFindings,
            Assessments = assessments,
            NotChecked = notChecked,
            DmaUserModeFindings = dmaFindings,
            Handles = deepResult?.Handles ?? new HandleScanReport(),
            Drivers = deepResult?.Drivers ?? new DriverScanReport(),
            FileSignatures = deepResult?.FileSignatures ?? new FileSignatureReport(),
            InjectionTraces = deepResult?.InjectionTraces ?? new List<InjectionFindingInfo>(),
            Telemetry = telemetryReport ?? new TelemetryReport { LocalLevel = overallLevel, JointLevel = overallLevel },

            VisionCheatIndicators = new VisionReport
            {
                Enabled = visionResult?.Enabled ?? false,
                SoftwareCapture = visionResult?.SoftwareCapture ?? new List<VisionIndicator>(),
                HardwareIndicators = visionResult?.HardwareIndicators ?? new List<VisionIndicator>(),
                BehavioralHint = visionResult?.BehavioralHint ?? new VisionBehavioralHint(),
                IndependentLayers = visionResult?.IndependentLayers ?? 0,
                HighestLevel = visionResult?.HighestLevel ?? RiskLevels.Info,
                Notes = visionResult?.Notes ?? new List<string>(),
                LayerSummary = new Dictionary<string, int>
                {
                    ["capture"] = visionResult?.SoftwareCapture.Count(i => !i.Suppressed) ?? 0,
                    ["hardware"] = visionResult?.HardwareIndicators.Count(i => !i.Suppressed) ?? 0,
                    ["behavior"] = (visionResult?.BehavioralHint.Collected ?? false) ? 1 : 0
                }
            },
            Dma = new DmaReport
            {
                Enabled = dmaResult?.Enabled ?? false,
                DevicesEnumerated = dmaResult?.DevicesEnumerated ?? 0,
                PciDevices = dmaResult?.Devices.Count ?? 0,
                Findings = activeDma.Count,
                TopScore = dmaScore,
                RiskLevel = dmaLevel,
                Kernel = ToKernelReport(dmaResult?.Kernel),
                Devices = options.IncludeDmaDeviceList
                    ? (dmaResult?.Devices ?? new List<DmaDeviceInfo>())
                    : new List<DmaDeviceInfo>()
            },
            Processes = options.AllProcesses ? processResult.Processes : null
        };

        report.Summary = new ScanSummary
        {
            ProcessesScanned = processResult.Processes.Count,
            FilesScanned = fileResult?.FilesScanned ?? 0,
            FilesHashed = fileResult?.FilesHashed ?? 0,
            Findings = activeFindings.Count,
            SuppressedFindings = suppressedFindings.Count,
            TotalScore = overallScore,
            SumScore = Math.Round(Math.Min(100.0, activeFindings.Sum(f => f.Score)), 2),
            RiskLevel = overallLevel,
            NotCheckedCount = notChecked.Count,
            AssessedTargets = assessments.Count,
            FileScanEnabled = options.FileScanEnabled,
            DmaDevicesEnumerated = dmaResult?.DevicesEnumerated ?? 0,
            DmaPciDevices = dmaResult?.Devices.Count ?? 0,
            DmaFindings = activeDma.Count,
            DmaRiskLevel = dmaLevel,
            DmaKernelLoaded = dmaResult?.Kernel?.Loaded ?? false,
            VisionSoftwareIndicators = visionResult?.SoftwareCapture.Count(i => !i.Suppressed) ?? 0,
            VisionHardwareIndicators = visionResult?.HardwareIndicators.Count(i => !i.Suppressed) ?? 0,
            VisionLevel = visionResult?.HighestLevel ?? RiskLevels.Info,
            HandleFindings = deepResult?.Findings.Count(f => f.RuleType == "handle_access") ?? 0,
            DriverFindings = deepResult?.Findings.Count(f => f.RuleType == "kernel_driver") ?? 0,
            FileSignatureHits = deepResult?.FileSignatures.Hits.Count ?? 0,
            OverlayIndicators = deepResult?.Overlays.Count ?? 0,
            TelemetryLoaded = telemetryReport?.Loaded ?? false,
            PartialCoverage = !IsElevated(),
            UnreadableTargets = unreadable,
            TelemetryJointLevel = telemetryReport?.JointLevel ?? overallLevel,
            ByRiskLevel = assessments
                .GroupBy(a => a.RiskLevel)
                .ToDictionary(g => g.Key, g => g.Count())
        };

        foreach (string level in new[] { RiskLevels.Info, RiskLevels.Suspicious, RiskLevels.High })
        {
            report.Summary.ByRiskLevel.TryAdd(level, 0);
        }

        // ---- 输出 ----
        var written = new List<string>();
        string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        string jsonPath = options.OutputPath ?? Path.Combine(OutputRoot(), "reports", $"scan-{stamp}.json");
        string htmlPath = options.HtmlPath ?? Path.Combine(OutputRoot(), "reports", $"scan-{stamp}.html");

        if (options.Format is "json" or "both")
        {
            written.Add(ReportWriter.WriteJson(report, jsonPath));
        }

        if (options.Format is "html" or "both")
        {
            written.Add(ReportWriter.WriteHtml(report, htmlPath));
        }

        audit.Write("scan.end", new
        {
            durationSeconds = report.DurationSeconds,
            riskLevel = overallLevel,
            score = overallScore,
            activeFindings = activeFindings.Count,
            suppressed = suppressedFindings.Count,
            assessments = assessments.Count,
            outputs = written
        });

        PrintResults(report, options, written);

        return Scoring.Rank(overallLevel) switch
        {
            >= 2 => 3,
            1 => 2,
            _ => 0
        };
    }

    /// <summary>把 DMA 命中转成统一 Finding，参与同一套风险聚合与证据链。</summary>
    private static Finding ToAggregateFinding(DmaFinding d) => new()
    {
        RuleId = d.RuleId,
        RuleType = "dma",
        Category = d.Category,
        Target = d.Target,
        TargetPath = d.InstanceId,
        Pid = null,
        Severity = d.Severity,
        Confidence = d.Confidence,
        Score = d.Score,
        RiskLevel = d.RiskLevel,
        Description = d.Description,
        Advice = d.Advice,
        Evidence = d.Evidence
    };

    private static void PrintResults(ScanReport report, Options options, List<string> written)
    {
        if (options.Quiet)
        {
            Console.WriteLine($"[{report.Summary.RiskLevel}] targets={report.Summary.AssessedTargets} " +
                              $"findings={report.Summary.Findings} suppressed={report.Summary.SuppressedFindings} " +
                              $"score={report.Summary.TotalScore} dma={report.Summary.DmaFindings} " +
                              $"outputs={string.Join(";", written)}");
            return;
        }

        Console.WriteLine();
        Console.WriteLine("================ 扫描结果 ================");
        Console.WriteLine($"主机      : {report.Machine}  ({report.OsVersion})");
        Console.WriteLine($"管理员    : {(report.IsElevated ? "是" : "否（部分进程不可查，已在未检查项注明）")}");
        if (!report.IsElevated)
        {
            Console.WriteLine("            ⚠ 未提权：游戏进程（受 ACE 保护）的模块/句柄读不到，本次覆盖不完整");
            Console.WriteLine("            ⚠ 现场扫描请用「以管理员身份运行」，否则注入痕迹与句柄线索会全部落空");
        }
        Console.WriteLine($"耗时      : {report.DurationSeconds}s");
        Console.WriteLine($"规则集    : {report.Ruleset.Name} v{report.Ruleset.Version}（更新 {report.Ruleset.Updated ?? "-"}）");
        Console.WriteLine($"进程/文件 : {report.Summary.ProcessesScanned} 个进程 / {report.Summary.FilesScanned} 个文件（哈希 {report.Summary.FilesHashed}）");
        Console.WriteLine($"DMA 设备  : {report.Summary.DmaDevicesEnumerated} 个，其中 PCI/PCIe {report.Summary.DmaPciDevices} 个");
        Console.WriteLine($"总体风险  : {report.Summary.RiskLevel}（最高目标分 {report.Summary.TotalScore} / 100，阈值 40 可疑 / 70 高度可疑）");
        Console.WriteLine($"目标分布  : " + string.Join("  ", report.Summary.ByRiskLevel.Select(kv => $"{kv.Key} {kv.Value}")));
        Console.WriteLine($"命中/抑制 : {report.Summary.Findings} 条活跃 / {report.Summary.SuppressedFindings} 条被白名单抑制");
        Console.WriteLine($"未检查项  : {report.Summary.NotCheckedCount}");

        var visible = report.Assessments
            .Where(a => Scoring.Rank(a.RiskLevel) >= Scoring.Rank(options.MinLevel))
            .Take(10)
            .ToList();

        if (visible.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("---- 风险评定（按等级/分值排序，最多 10 个目标）----");
            foreach (var a in visible)
            {
                string who = a.Pid.HasValue ? $"PID {a.Pid}" : "文件/设备";
                Console.WriteLine($"[{a.RiskLevel}] {a.Score,6:F1}  {a.Target} ({who})");
                if (!string.IsNullOrEmpty(a.Path))
                {
                    Console.WriteLine($"           {a.Path}");
                }

                Console.WriteLine($"           信号: 强 {a.StrongSignalCount} / 中 {a.MediumSignalCount} / 弱 {a.WeakSignalCount}");

                foreach (string reason in a.EscalationReasons)
                {
                    Console.WriteLine($"           ↑ {reason}");
                }

                int index = 1;
                foreach (var e in a.Evidence.Take(6))
                {
                    Console.WriteLine($"           {index++}. {e.RuleId} (sev {e.Severity}, conf {e.Confidence:F2}) → {e.Score:F1}  {e.Description}");
                }

                if (a.Evidence.Count > 6)
                {
                    Console.WriteLine($"           ... 另 {a.Evidence.Count - 6} 条证据见报告");
                }
            }

            if (report.Assessments.Count > visible.Count)
            {
                Console.WriteLine($"... 另有 {report.Assessments.Count - visible.Count} 个目标，详见报告");
            }
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine("没有达到当前显示等级（--min-level）的目标。");
        }

        if (report.SuppressedFindings.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"---- 白名单抑制记录（{report.SuppressedFindings.Count} 条，不计分）----");
            foreach (var f in report.SuppressedFindings.Take(5))
            {
                Console.WriteLine($"  {f.RuleId}  {f.Target}  原因: {f.SuppressReason}");
            }
            if (report.SuppressedFindings.Count > 5)
            {
                Console.WriteLine($"  ... 另 {report.SuppressedFindings.Count - 5} 条见报告");
            }
        }

        if (report.Dma.Enabled)
        {
            Console.WriteLine();
            Console.WriteLine($"---- DMA 外设（用户态初筛，等级 {report.Dma.RiskLevel}）----");
            Console.WriteLine($"枚举设备 {report.Dma.DevicesEnumerated} 个 / PCI {report.Dma.PciDevices} 个 / 命中 {report.Dma.Findings} 条");

            if (report.Dma.Kernel.Attempted)
            {
                string state = report.Dma.Kernel.Loaded
                    ? (report.Dma.Kernel.Unloaded ? "已加载并已卸载" : "已加载，卸载失败！")
                    : $"加载失败：{report.Dma.Kernel.Error}";
                Console.WriteLine($"内核配置空间: {state}，读取 {report.Dma.Kernel.DevicesRead}/{report.Dma.Kernel.DevicesAttempted} 个设备");
            }
            else
            {
                Console.WriteLine("内核配置空间: 未启用（加 --kernel 才会装载驱动）");
            }

            Console.WriteLine("注意: 用户态枚举读不到 PCIe 配置空间，DMA 段仅为线索，不能作为唯一依据。");
        }

        Console.WriteLine();
        if (report.VisionCheatIndicators.Enabled)
        {
            var vision = report.VisionCheatIndicators;
            Console.WriteLine();
            Console.WriteLine($"---- 视觉外挂线索（等级 {vision.HighestLevel}，{vision.IndependentLayers} 层独立线索）----");
            Console.WriteLine($"软件采集 {report.Summary.VisionSoftwareIndicators} 条 / 硬件 {report.Summary.VisionHardwareIndicators} 条 / " +
                              $"行为提示 {(vision.BehavioralHint.Collected ? "已采集（信息级）" : "未启用")}");

            foreach (var item in vision.SoftwareCapture.Take(5))
            {
                string wl = item.Suppressed ? $"  [白名单: {item.SuppressReason}]" : "";
                Console.WriteLine($"[{item.RiskLevel}] {item.Score,6:F1}  {item.Id}  {item.Target} (PID {item.Pid}){wl}");
                Console.WriteLine($"           模块: {string.Join(", ", item.MatchedModules.Take(4))}");
                Console.WriteLine($"           签名: {item.SignatureState}   窗口: {item.Evidence.GetValueOrDefault("largestWindow")}");
            }

            foreach (var item in vision.HardwareIndicators.Take(5))
            {
                string wl = item.Suppressed ? $"  [白名单: {item.SuppressReason}]" : "";
                Console.WriteLine($"[{item.RiskLevel}] {item.Score,6:F1}  {item.Id}  {item.Target}{wl}");
                Console.WriteLine($"           VID:PID {item.Evidence.GetValueOrDefault("vendorId")}:{item.Evidence.GetValueOrDefault("deviceId")}" +
                                  $"  Class {item.Evidence.GetValueOrDefault("deviceClass")}  Service {item.Evidence.GetValueOrDefault("service")}");
            }

            if (vision.BehavioralHint.Collected)
            {
                Console.WriteLine($"行为提示: {vision.BehavioralHint.Description}");
            }

            foreach (string note in vision.Notes.Take(3))
            {
                Console.WriteLine("  · " + note);
            }

            Console.WriteLine("声明: 双机+外部采集+硬件注入链路在本机用户态无法独立确证，以上为可观测线索，不代表最终判定。");
        }

        if (report.Telemetry.Loaded)
        {
            var tel = report.Telemetry;
            Console.WriteLine();
            Console.WriteLine("---- 游戏侧遥测（联合评估）----");
            Console.WriteLine($"本机等级 {tel.LocalLevel} / 遥测等级 {(tel.Assessments.Count > 0 ? tel.Assessments[0].TelemetryLevel : "信息")} → 联合建议 {tel.JointLevel}");

            foreach (var s in tel.Assessments.Take(2))
            {
                Console.WriteLine($"会话 {s.SessionId}（玩家 {s.AccountName ?? s.PlayerId ?? "-"}，{s.DurationSeconds}s，信号 {s.Signals.Count} 条）");
                foreach (var signal in s.Signals.Take(4))
                {
                    string baseText = signal.BaselineKnown ? $"，基线 {signal.Baseline}" : "";
                    Console.WriteLine($"  [{signal.RiskLevel}] {signal.RuleId}  {signal.Metric}={signal.Value}（阈值 {signal.Threshold}{baseText}）");
                }
            }

            foreach (string reason in tel.JointReasons.Take(4))
            {
                Console.WriteLine("  · " + reason);
            }

            Console.WriteLine("说明: 遥测只反映行为异常，本地只反映痕迹，联合结论用于排序复核优先级，不构成判定。");
        }
        else if (!string.IsNullOrWhiteSpace(report.Telemetry.Error))
        {
            Console.WriteLine();
            Console.WriteLine("---- 游戏侧遥测 ----");
            Console.WriteLine("导入失败: " + report.Telemetry.Error);
        }

        if (report.Handles.Enabled || report.Drivers.Enabled)
        {
            Console.WriteLine();
            Console.WriteLine("---- 深度线索（句柄 / 驱动 / 特征码）----");

            if (report.Handles.Enabled)
            {
                Console.WriteLine(report.Handles.Error is not null
                    ? $"句柄枚举: 失败（{report.Handles.Error}）"
                    : $"句柄枚举: 共 {report.Handles.HandlesEnumerated} 个，高权限 {report.Handles.HighAccessHandles} 个，命中 {report.Summary.HandleFindings} 条");
            }

            if (report.Drivers.Enabled)
            {
                Console.WriteLine(report.Drivers.Error is not null
                    ? $"驱动枚举: 失败（{report.Drivers.Error}）"
                    : $"已加载驱动: {report.Drivers.DriversEnumerated} 个，命中规则 {report.Summary.DriverFindings} 条");
            }

            if (report.FileSignatures.Enabled)
            {
                Console.WriteLine($"文件特征码: 扫描 {report.FileSignatures.FilesScanned} 个文件，命中 {report.Summary.FileSignatureHits} 条");
            }

            foreach (var f in report.Findings.Where(x => x.RuleType is "handle_access" or "kernel_driver").Take(6))
            {
                Console.WriteLine($"[{f.RiskLevel}] {f.Score,6:F1}  {f.RuleId}  {f.Target}");
                Console.WriteLine($"           {f.Description}");
            }
        }

        Console.WriteLine("---- 审计 ----");
        Console.WriteLine($"进程打开 {report.Audit.ProcessOpenAttempts} 次（拒绝 {report.Audit.ProcessOpenDenied}），权限仅 0x1000 QUERY_LIMITED");
        Console.WriteLine($"验签 {report.Audit.SignatureChecks} 次（缓存新增 {report.Audit.SignatureCacheNew}，总量 {report.Audit.SignatureCacheSize}），驱动 {(report.Audit.DriverLoadAttempts == 0 ? "未加载" : (report.Audit.DriverLoaded ? "已加载并卸载" : "加载失败"))}，网络访问：无");
        Console.WriteLine($"审计日志: {report.Audit.LogPath ?? "-"}");

        Console.WriteLine();
        foreach (string path in written)
        {
            Console.WriteLine($"报告: {path}");
        }
        Console.WriteLine("退出码: 0=未发现可疑  2=存在可疑  3=存在高度可疑  1=错误");
    }

    private static (double Score, string Level) AggregateDma(List<DmaFinding> findings)
    {
        double best = 0;
        foreach (var group in findings.GroupBy(f => f.InstanceId))
        {
            double sum = Math.Min(100.0, group.Sum(f => f.Score));
            if (sum > best) best = sum;
        }

        best = Math.Round(best, 2);
        return (best, Scoring.LevelOf(best));
    }

    private static DmaKernelReport ToKernelReport(ConfigSpaceReadResult? read)
    {
        if (read is null)
        {
            return new DmaKernelReport();
        }

        return new DmaKernelReport
        {
            Attempted = read.Attempted,
            Loaded = read.Loaded,
            Unloaded = read.Unloaded,
            DriverPath = read.DriverPath,
            Error = read.Error,
            DevicesAttempted = read.DevicesAttempted,
            DevicesRead = read.DevicesRead,
            Errors = read.Errors
        };
    }

    private static void ApplyProfile(Options options)
    {
        switch (options.Profile)
        {
            case "quick":
                options.HandleScan = false;
                options.DriverScan = true;
                options.OverlayScan = false;
                options.FileSignatureScan = false;
                break;
            case "deep":
                options.HandleScan = true;
                options.DriverScan = true;
                options.OverlayScan = true;
                options.FileSignatureScan = true;
                break;
            default:
                break;
        }
    }

    /// <summary>
    /// 输出根目录：优先 exe 同目录下的 out\（便携分发时结果跟着程序走），
    /// 不可写时回退到当前工作目录。
    /// </summary>
    private static string OutputRoot()
    {
        try
        {
            string baseDir = Path.Combine(AppContext.BaseDirectory, "out");
            Directory.CreateDirectory(baseDir);
            return baseDir;
        }
        catch
        {
            return Path.Combine(Directory.GetCurrentDirectory(), "out");
        }
    }

    private static string DefaultLogPath()
    {
        string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        return Path.Combine(OutputRoot(), "logs", $"audit-{stamp}.jsonl");
    }

    private static bool IsElevated()
    {
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static void PrintRuleInfo(RuleLoadResult load)
    {
        Console.WriteLine($"规则文件 : {load.SourcePath}");
        if (load.Success)
        {
            var rs = load.RuleSet;
            Console.WriteLine($"规则集   : {rs.Meta.Name} v{rs.Meta.Version}（更新 {rs.Meta.Updated ?? "-"}，schema {rs.Meta.SchemaVersion}）");
            Console.WriteLine($"规则数量 : 通用 {rs.Rules.Count}（启用 {rs.Rules.Count(r => r.Enabled)}），DMA {rs.Dma.Rules.Count}，" +
                              $"分类 {rs.Meta.Categories.Count}，白名单 {RuleLoader.CountWhitelistEntries(rs.Whitelist) + rs.Dma.Whitelist.Count} 条");
        }

        foreach (string w in load.Warnings)
        {
            Console.WriteLine("  [警告] " + w);
        }
    }

    internal sealed class Options
    {
        public string? RulesPath { get; set; }
        public string? RulesDir { get; set; }
        public string? OutputPath { get; set; }
        public string? HtmlPath { get; set; }
        public string? LogPath { get; set; }
        public string Format { get; set; } = "both";
        public bool FileScanEnabled { get; set; } = true;
        public bool DmaEnabled { get; set; } = true;
        public bool KernelEnabled { get; set; }
        public string? DriverPath { get; set; }
        public bool IncludeDmaDeviceList { get; set; } = true;
        public bool VisionEnabled { get; set; } = true;
        public bool VisionBehavior { get; set; }
        public bool DeepEnabled { get; set; } = true;
        public bool HandleScan { get; set; } = true;
        public bool DriverScan { get; set; } = true;
        public bool OverlayScan { get; set; } = true;
        public bool FileSignatureScan { get; set; }
        public string Profile { get; set; } = "standard";
        public string? TelemetryPath { get; set; }
        public string? SigCachePath { get; set; }
        public string? AggregateDir { get; set; }
        public string? AggregateMd { get; set; }
        public string? AggregateJson { get; set; }
        public bool WithTune { get; set; }
        public string TuneLabel { get; set; } = "clean";
        public string? TuneOutputPath { get; set; }
        public bool NoWhitelist { get; set; }
        public bool AllProcesses { get; set; }
        public bool CheckRevocation { get; set; }
        public bool Quiet { get; set; }
        public List<string> FileRoots { get; } = new();
        public int TimeoutSeconds { get; set; } = 180;
        public string MinLevel { get; set; } = RiskLevels.Info;
    }

    private static Options ParseOptions(string[] args)
    {
        var options = new Options();
        int start = args.Length > 0 && !args[0].StartsWith("-", StringComparison.Ordinal) ? 1 : 0;

        for (int i = start; i < args.Length; i++)
        {
            string arg = args[i];
            string? inline = null;

            int eq = arg.IndexOf('=');
            if (arg.StartsWith("--", StringComparison.Ordinal) && eq > 0)
            {
                inline = arg[(eq + 1)..];
                arg = arg[..eq];
            }

            string? TakeValue()
            {
                if (inline is not null) return inline;
                return i + 1 < args.Length ? args[++i] : null;
            }

            switch (arg.ToLowerInvariant())
            {
                case "--rules": options.RulesPath = TakeValue(); break;
                case "--rules-dir": options.RulesDir = TakeValue(); break;
                case "--out": options.OutputPath = TakeValue(); break;
                case "--html": options.HtmlPath = TakeValue(); break;
                case "--log": options.LogPath = TakeValue(); break;
                case "--format":
                    options.Format = (TakeValue() ?? "both").ToLowerInvariant() switch
                    {
                        "json" => "json",
                        "html" => "html",
                        _ => "both"
                    };
                    break;
                case "--file-root":
                    string? root = TakeValue();
                    if (!string.IsNullOrWhiteSpace(root)) options.FileRoots.Add(root!);
                    break;
                case "--no-files": options.FileScanEnabled = false; break;
                case "--no-vision": options.VisionEnabled = false; break;
                case "--vision-behavior": options.VisionBehavior = true; break;
                case "--no-handles": options.HandleScan = false; break;
                case "--no-drivers": options.DriverScan = false; break;
                case "--no-overlay": options.OverlayScan = false; break;
                case "--file-signatures": options.FileSignatureScan = true; break;
                case "--profile": options.Profile = (TakeValue() ?? "standard").ToLowerInvariant(); break;
                case "--telemetry": options.TelemetryPath = TakeValue(); break;
                case "--dir": options.AggregateDir = TakeValue(); break;
                case "--label": options.TuneLabel = TakeValue() ?? "clean"; break;
                case "--tune": options.WithTune = true; break;
                case "--no-whitelist": options.NoWhitelist = true; break;
                case "--tune-out": options.TuneOutputPath = TakeValue(); break;
                case "--json": options.AggregateJson = TakeValue(); break;
                case "--sig-cache": options.SigCachePath = TakeValue(); break;
                case "--no-sig-cache": options.SigCachePath = ""; break;
                case "--no-dma": options.DmaEnabled = false; break;
                case "--kernel": options.KernelEnabled = true; break;
                case "--driver-path": options.DriverPath = TakeValue(); break;
                case "--no-device-list": options.IncludeDmaDeviceList = false; break;
                case "--all-processes": options.AllProcesses = true; break;
                case "--check-revocation": options.CheckRevocation = true; break;
                case "--quiet": options.Quiet = true; break;
                case "--timeout":
                    if (int.TryParse(TakeValue(), out int timeout)) options.TimeoutSeconds = timeout;
                    break;
                case "--min-level":
                    options.MinLevel = TakeValue()?.ToLowerInvariant() switch
                    {
                        "suspicious" => RiskLevels.Suspicious,
                        "high" => RiskLevels.High,
                        _ => RiskLevels.Info
                    };
                    break;
                default:
                    if (arg.StartsWith("-", StringComparison.Ordinal))
                    {
                        Console.Error.WriteLine($"[警告] 未识别的参数: {arg}");
                    }
                    break;
            }
        }

        return options;
    }

    private static string ResolveRulesPath(string? explicitPath)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            return explicitPath!;
        }

        string baseDir = AppContext.BaseDirectory;
        string cwd = Directory.GetCurrentDirectory();

        string[] candidates =
        {
            Path.Combine(baseDir, "rules", "rules.json"),
            Path.Combine(cwd, "rules", "rules.json")
        };

        foreach (string candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return candidates[0];
    }

    private static void PrintHelp()
    {
        Console.WriteLine($"""
        EagleEye v{ToolVersion} —— 本地反外挂只读查询工具（进程 / 文件 / 签名 / DMA）

        用法:
          EagleEye scan     [选项]   # 默认命令
          EagleEye validate [选项]   # 只校验规则文件
          EagleEye selftest [选项]   # 环境自检（权限/规则/句柄/驱动/目标进程）
          EagleEye aggregate --dir <报告目录> [--tune]  # 批量汇总；加 --tune 顺带生成调参包
          EagleEye tune --dir <报告目录>                # 只做调参分析（clean-*/cheat-* 标签）
          EagleEye --help

        报告输出:
          --format <json|html|both>  输出格式，默认 both
          --out  <路径>              JSON 报告路径
          --html <路径>              HTML 报告路径
          --log  <路径>              审计日志路径（JSONL）

        扫描范围:
          --no-files                 跳过文件扫描
          --no-dma                   跳过 DMA 外设枚举
          --no-vision                跳过 AI 视觉外挂线索扫描
          --vision-behavior          采集输入行为统计（信息级，默认关闭）
          --no-handles               跳过句柄线索（谁以 VM_READ 打开目标进程）
          --no-drivers               跳过已加载驱动线索
          --no-overlay               跳过 overlay 窗口检测
          --file-signatures          启用文件特征码扫描（默认关闭，需规则）
          --profile <quick|standard|deep>  扫描档位预设
          --telemetry <文件>        导入游戏侧遥测 JSON，做本地×遥测联合评估（离线文件，不联网）
          --kernel                   加载一次性只读驱动读取 PCIe 配置空间（用完立即卸载）
          --driver-path <路径>       指定 PcieCfg.sys
          --no-device-list           报告不附全部 PCI 设备清单
          --file-root <目录>         追加文件扫描目录，可重复
          --all-processes            报告附全部进程清单
          --check-revocation         验签时检查吊销（需联网，默认关闭）

        其他:
          --timeout <秒>             整体超时，默认 180
          --min-level <等级>         控制台只显示 >= 该等级：info | suspicious | high
          --quiet                    只输出一行摘要

        退出码: 0=未发现可疑  2=存在可疑  3=存在高度可疑  1=错误

        安全约束: 只读枚举；不读进程内存、不注入、不 Hook、不联网、不上传数据。
        """ );
    }
}