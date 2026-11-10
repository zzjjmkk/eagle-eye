using EagleEye.Models;
using EagleEye.Native;

namespace EagleEye.Scanning;

/// <summary>
/// 输入行为统计（信息级）。
///
/// 实现选择与理由：
///   1. **不使用 WH_MOUSE_LL 低级钩子**。SetWindowsHookEx 是系统级全局钩子，
///      属于本项目红线（不 Hook 任何 API），且会被反作弊视为高风险行为。
///   2. **不使用 Raw Input**。RIDEV_INPUTSINK 需要后台收包，等价于全局输入捕获，
///      同样踩线且需要窗口与消息循环。
///   3. **不使用系统性能计数器**。Windows 没有暴露"鼠标移动平滑度"这类计数器。
///   4. 因此只能用 GetCursorPos 定时轮询：无钩子、无注册、无消息循环，
///      对目标进程零侵入，反作弊侧完全不可见。
///
/// 只计算聚合指标，采样缓冲区只在本地栈上，函数返回即丢弃，
/// 不写盘、不关联窗口、不记录任何坐标轨迹。
/// </summary>
public static class InputBehaviorSampler
{
    private const double StraightAngleDegrees = 8.0;
    private const double ConstantVelocityTolerance = 0.15;

    public static VisionBehavioralHint Sample(VisionBehaviorOptions options, CancellationToken ct)
    {
        var hint = new VisionBehavioralHint
        {
            DurationMs = Math.Clamp(options.DurationMs, 500, 60000)
        };

        int interval = Math.Clamp(options.SampleMs, 8, 200);
        int totalSamples = hint.DurationMs / interval;

        if (totalSamples < options.MinSamples)
        {
            hint.SkipReason = $"采样窗口太短（{totalSamples} 个采样点 < MinSamples {options.MinSamples}），已跳过";
            return hint;
        }

        var points = new List<(int X, int Y)>(totalSamples + 1);

        try
        {
            for (int i = 0; i <= totalSamples; i++)
            {
                ct.ThrowIfCancellationRequested();

                if (!WindowApi.GetCursorPos(out WindowApi.POINT p))
                {
                    hint.SkipReason = "GetCursorPos 调用失败，已跳过行为统计";
                    return hint;
                }

                points.Add((p.X, p.Y));
                Thread.Sleep(interval);
            }
        }
        catch (OperationCanceledException)
        {
            hint.SkipReason = "扫描被取消，行为统计未完成";
            return hint;
        }

        return Analyze(points, hint, options);
    }

    private static VisionBehavioralHint Analyze(List<(int X, int Y)> points, VisionBehavioralHint hint, VisionBehaviorOptions options)
    {
        hint.Collected = true;
        hint.SampleCount = points.Count;

        var deltas = new List<(double Dx, double Dy, double Speed)>(points.Count);

        for (int i = 1; i < points.Count; i++)
        {
            double dx = points[i].X - points[i - 1].X;
            double dy = points[i].Y - points[i - 1].Y;
            deltas.Add((dx, dy, Math.Sqrt(dx * dx + dy * dy)));
        }

        if (deltas.Count == 0)
        {
            hint.Collected = false;
            hint.SkipReason = "没有采集到移动样本";
            return hint;
        }

        int zeroDelta = deltas.Count(d => d.Speed < 0.5);
        hint.ZeroDeltaRatio = Math.Round((double)zeroDelta / deltas.Count, 3);

        // 只对"有移动"的相邻采样做角度/速度统计
        var moving = deltas.Where(d => d.Speed >= 0.5).ToList();
        if (moving.Count < 3)
        {
            hint.Description = "本段时间内几乎没有鼠标移动，统计无意义";
            hint.Confidence = 0.05;
            return hint;
        }

        int straightPairs = 0;
        int constantPairs = 0;
        int pairs = 0;

        for (int i = 1; i < moving.Count; i++)
        {
            var a = moving[i - 1];
            var b = moving[i];

            double dot = a.Dx * b.Dx + a.Dy * b.Dy;
            double norm = a.Speed * b.Speed;
            if (norm <= 0) continue;

            double cos = Math.Clamp(dot / norm, -1.0, 1.0);
            double angle = Math.Acos(cos) * 180.0 / Math.PI;

            if (angle <= StraightAngleDegrees) straightPairs++;

            double mean = (a.Speed + b.Speed) / 2.0;
            if (mean > 0 && Math.Abs(a.Speed - b.Speed) / mean <= ConstantVelocityTolerance) constantPairs++;

            pairs++;
        }

        if (pairs == 0)
        {
            hint.Description = "样本不足以计算方向一致性";
            hint.Confidence = 0.05;
            return hint;
        }

        hint.StraightLineRatio = Math.Round((double)straightPairs / pairs, 3);
        hint.ConstantVelocityRatio = Math.Round((double)constantPairs / pairs, 3);

        double avgSpeed = moving.Average(d => d.Speed);
        double variance = moving.Average(d => (d.Speed - avgSpeed) * (d.Speed - avgSpeed));

        hint.AverageSpeedPxPerSec = Math.Round(avgSpeed * (1000.0 / Math.Max(1, options.SampleMs)), 1);
        hint.SpeedStdDev = Math.Round(Math.Sqrt(variance), 2);

        bool suspicious =
            hint.StraightLineRatio >= options.StraightLineRatio ||
            hint.ConstantVelocityRatio >= options.ConstantVelocityRatio ||
            hint.ZeroDeltaRatio >= options.ZeroDeltaRatio;

        hint.Severity = suspicious ? 1 : 1;   // 永远是 1：信息级
        hint.Confidence = suspicious ? 0.15 : 0.08;
        hint.Description = suspicious
            ? $"输入轨迹呈现较高机械性（直线化 {hint.StraightLineRatio:P0}，匀速 {hint.ConstantVelocityRatio:P0}，静止占比 {hint.ZeroDeltaRatio:P0}）"
            : $"输入轨迹未见明显机械特征（直线化 {hint.StraightLineRatio:P0}，匀速 {hint.ConstantVelocityRatio:P0}）";

        return hint;
    }
}