using EagleEye.Core;
using EagleEye.Models;
using EagleEye.Native;

namespace EagleEye.Scanning;

/// <summary>
/// 叠加层（overlay）检测：找出"透明/置顶、覆盖在别的进程窗口之上的窗口"。
/// 这是 ESP / AI 框最常见的显示方式（画在游戏画面之上，不改游戏本身）。
///
/// 只读：EnumWindows + 读扩展样式/矩形，不截屏、不点击、不发消息。
/// </summary>
public sealed class OverlayScanner
{
    public List<VisionIndicator> Scan(
        OverlayScanOptions options,
        ProcessScanResult processes,
        CancellationToken ct)
    {
        var results = new List<VisionIndicator>();
        if (!options.Enabled)
        {
            return results;
        }

        var windows = WindowApi.EnumerateVisibleWindows()
            .Where(w => w.Width >= 64 && w.Height >= 64)
            .ToList();

        var byPid = processes.Processes
            .GroupBy(p => p.Pid)
            .ToDictionary(g => g.Key, g => g.First());

        foreach (var candidate in windows)
        {
            ct.ThrowIfCancellationRequested();

            bool layered = (candidate.ExStyle & WindowApi.WS_EX_LAYERED) != 0;
            bool transparent = (candidate.ExStyle & WindowApi.WS_EX_TRANSPARENT) != 0;
            bool topmost = (candidate.ExStyle & WindowApi.WS_EX_TOPMOST) != 0;
            bool noActivate = (candidate.ExStyle & WindowApi.WS_EX_NOACTIVATE) != 0;
            bool toolWindow = (candidate.ExStyle & WindowApi.WS_EX_TOOLWINDOW) != 0;

            if (!layered) continue;
            if (!(transparent || topmost || noActivate)) continue;
            if (candidate.Width < options.MinWidth || candidate.Height < options.MinHeight) continue;

            // 找被它覆盖的、属于其它进程的窗口
            WindowApi.WindowInfo? covered = null;
            double bestRatio = 0;

            foreach (var other in windows)
            {
                if (other.ProcessId == candidate.ProcessId) continue;
                if (other.Handle == candidate.Handle) continue;
                if (other.Area <= 0) continue;

                double ratio = IntersectionArea(candidate, other) / (double)other.Area;
                if (ratio > bestRatio)
                {
                    bestRatio = ratio;
                    covered = other;
                }
            }

            if (covered is null || bestRatio < options.MinAreaRatio) continue;

            byPid.TryGetValue(candidate.ProcessId, out ProcessRecord? owner);
            byPid.TryGetValue(covered.Value.ProcessId, out ProcessRecord? target);

            double confidence = options.Confidence;
            if (owner?.Signature.State is SignatureStates.Unsigned) confidence += 0.1;
            confidence = Math.Round(Math.Clamp(confidence, 0, 0.7), 2);

            double score = Scoring.ComputeScore(options.Severity, confidence);

            results.Add(new VisionIndicator
            {
                Id = "vision.overlay.window",
                Layer = "capture",
                Category = "overlay",
                Target = owner?.Name ?? $"pid{candidate.ProcessId}",
                Pid = candidate.ProcessId,
                Path = owner?.ImagePath,
                SignatureState = owner?.Signature.State,
                Severity = options.Severity,
                Confidence = confidence,
                Score = score,
                Description = $"检测到叠加窗口覆盖在 {target?.Name ?? $"pid{covered.Value.ProcessId}"} 之上" +
                              $"（覆盖 {bestRatio:P0}，Layered/Transparent/Topmost 样式）",
                Advice = "覆盖层也可能是 Discord/Steam/录屏软件的合法覆盖，需结合进程签名与场景复核",
                Evidence = new Dictionary<string, object?>
                {
                    ["overlayHandle"] = $"0x{candidate.Handle.ToInt64():X}",
                    ["overlayTitle"] = candidate.Title,
                    ["overlaySize"] = $"{candidate.Width}x{candidate.Height}",
                    ["exStyle"] = $"0x{candidate.ExStyle:X}",
                    ["layered"] = layered,
                    ["transparent"] = transparent,
                    ["topmost"] = topmost,
                    ["noActivate"] = noActivate,
                    ["toolWindow"] = toolWindow,
                    ["coveredPid"] = covered.Value.ProcessId,
                    ["coveredName"] = target?.Name,
                    ["coveredRatio"] = Math.Round(bestRatio, 3),
                    ["memoryRead"] = false,
                    ["screenshotTaken"] = false
                }
            });
        }

        return results
            .GroupBy(v => v.Pid)
            .Select(g => g.OrderByDescending(v => v.Score).First())
            .ToList();
    }

    private static double IntersectionArea(WindowApi.WindowInfo a, WindowApi.WindowInfo b)
    {
        int left = Math.Max(a.Left, b.Left);
        int top = Math.Max(a.Top, b.Top);
        int right = Math.Min(a.Left + a.Width, b.Left + b.Width);
        int bottom = Math.Min(a.Top + a.Height, b.Top + b.Height);

        if (right <= left || bottom <= top) return 0;
        return (right - left) * (bottom - top);
    }
}