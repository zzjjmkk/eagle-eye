using EagleEye.Models;
using EagleEye.Native;

namespace EagleEye.Scanning;

public sealed class DeepScanRequest
{
    public bool Handles { get; set; } = true;
    public bool Drivers { get; set; } = true;
    public bool Overlay { get; set; } = true;
    public bool FileSignatures { get; set; }
    public List<string> FileRoots { get; set; } = new();
}

/// <summary>
/// 深度扫描编排：句柄线索 + 已加载驱动线索 + overlay 窗口 + 文件特征码。
/// 全部只读；不新增任何内核组件；不使用任何 Hook。
/// </summary>
public static class ExtendedScans
{
    public static DeepScanResult Run(
        RuleSet rules,
        ProcessScanResult processes,
        DeepScanRequest request,
        SignatureChecker signatures,
        CancellationToken ct,
        AuditLogger? audit = null)
    {
        var result = new DeepScanResult();

        try
        {
            if (request.Handles && rules.Deep.Handles.Enabled)
            {
                var (handleReport, handleFindings) = new HandleScanner()
                    .Scan(rules.Deep.Handles, processes, ct, audit);
                result.Handles = handleReport;
                result.Findings.AddRange(handleFindings);

                if (handleReport.Error is not null)
                {
                    result.NotChecked.Add(new NotChecked
                    {
                        Target = "句柄表",
                        Reason = $"句柄枚举未完成：{handleReport.Error}（通常需要管理员权限）"
                    });
                }
            }

            if (request.Drivers && rules.Deep.Drivers.Enabled)
            {
                var (driverReport, driverFindings) = new DriverScanner()
                    .Scan(rules.Deep.Drivers, signatures, ct, audit);
                result.Drivers = driverReport;
                result.Findings.AddRange(driverFindings);

                if (driverReport.Error is not null)
                {
                    result.NotChecked.Add(new NotChecked
                    {
                        Target = "已加载驱动",
                        Reason = $"驱动枚举未完成：{driverReport.Error}"
                    });
                }
            }

            if (rules.Deep.Injection.Enabled)
            {
                var (injFindings, injTraces) = new InjectionTraceScanner()
                    .Scan(rules.Deep.Injection, processes, signatures, ct, audit);
                result.Findings.AddRange(injFindings);
                result.InjectionTraces.AddRange(injTraces);
            }

            if (request.Overlay && rules.Deep.Overlay.Enabled && rules.Vision.Enabled)
            {
                result.Overlays.AddRange(new OverlayScanner().Scan(rules.Deep.Overlay, processes, ct));
            }

            if (request.FileSignatures && rules.Deep.FileSignatures.Enabled)
            {
                // 显式指定的 --file-root 优先，避免被默认目录先占满 maxFiles
                var roots = request.FileRoots.Concat(rules.Options.ScanRoots);

                var (sigReport, sigFindings) = new FileSignatureScanner()
                    .Scan(rules.Deep.FileSignatures, roots, ct, audit);
                result.FileSignatures = sigReport;
                result.Findings.AddRange(sigFindings);
            }

            if (result.Findings.Count == 0 && result.Overlays.Count == 0)
            {
                result.Notes.Add("深度扫描未发现句柄/驱动/overlay 相关线索");
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            result.NotChecked.Add(new NotChecked { Target = "deep-scan", Reason = ex.Message });
        }

        return result;
    }
}