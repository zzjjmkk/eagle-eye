using System.Diagnostics;
using System.Security.Principal;
using EagleEye.Models;
using EagleEye.Native;
using EagleEye.Rules;
using EagleEye.Scanning;

namespace EagleEye;

/// <summary>
/// 环境自检：现场部署前先跑这个，确认这台机器能不能查。
/// 只做只读探测，不写任何配置。
/// </summary>
public static class SelfTest
{
    private sealed record Item(string Name, bool Ok, string Detail, bool Critical);

    public static int Run(RuleLoadResult load, bool quiet)
    {
        var items = new List<Item>();
        var sw = Stopwatch.StartNew();

        // 1. 管理员权限
        bool elevated = IsElevated();
        items.Add(new Item("管理员权限", elevated,
            elevated ? "已提权" : "未提权 —— 游戏/反作弊等受保护进程读不到，覆盖不完整", true));

        // 2. 规则
        bool rulesOk = load.Success && load.RuleSet.Rules.Count > 0;
        items.Add(new Item("规则加载", rulesOk,
            rulesOk
                ? $"{load.RuleSet.Meta.Name} v{load.RuleSet.Meta.Version}，通用 {load.RuleSet.Rules.Count} 条 / DMA {load.RuleSet.Dma.Rules.Count} 条"
                : $"失败：{string.Join("; ", load.Errors.Take(3))}", true));

        // 3. 进程枚举
        int procCount = 0;
        try { procCount = Process.GetProcesses().Length; } catch { }
        items.Add(new Item("进程枚举", procCount > 0, $"{procCount} 个进程", true));

        // 4. 签名校验
        string selfExe = Environment.ProcessPath ?? "";
        bool sigOk = false;
        string sigDetail = "无法定位自身 exe";
        if (!string.IsNullOrEmpty(selfExe) && File.Exists(selfExe))
        {
            var sig = new SignatureChecker(false).Check(selfExe);
            sigOk = sig.State is SignatureStates.Valid or SignatureStates.CatalogValid or SignatureStates.Unsigned;
            sigDetail = $"自身 exe 验签返回 {sig.State}（能返回结果即说明 wintrust 可用）";
        }
        items.Add(new Item("签名校验", sigOk, sigDetail, true));

        // 5. 句柄枚举（需要管理员）
        var handleSw = Stopwatch.StartNew();
        var refs = HandleInterop.FindProcessHandles(out int totalHandles, out int highAccess, out string? handleError);
        handleSw.Stop();
        bool handleOk = handleError is null;
        items.Add(new Item("句柄枚举", handleOk,
            handleOk
                ? $"句柄表 {totalHandles} 个，高权限 {highAccess} 个，可解析配对 {refs.Count} 个（{handleSw.ElapsedMilliseconds} ms）"
                : $"失败：{handleError}（通常是没有管理员权限）", true));

        // 6. 驱动枚举
        var drivers = DriverInterop.Enumerate(out string? driverError);
        items.Add(new Item("驱动枚举", driverError is null, driverError ?? $"{drivers.Count} 个已加载驱动", true));

        // 7. 设备枚举
        var devices = SetupApiInterop.EnumeratePresentDevices(out string? devError);
        int pci = devices.Count(d => d.InstanceId.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase));
        items.Add(new Item("设备枚举", devError is null, devError ?? $"设备 {devices.Count} 个，其中 PCI/PCIe {pci} 个", false));

        // 8. 目标游戏是否在运行
        var patterns = load.RuleSet.Deep.Injection.TargetProcessPatterns;
        if (patterns.Count == 0) patterns = new List<string> { "*DeltaForce*" };

        var targets = new List<string>();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (patterns.Any(x => Core.PatternMatcher.IsMatch(p.ProcessName, x, null)))
                    {
                        targets.Add($"{p.ProcessName}(PID {p.Id})");
                    }
                }
                catch { }
            }
        }
        catch { }

        items.Add(new Item("目标游戏进程", targets.Count > 0,
            targets.Count > 0 ? string.Join(", ", targets) : "未检测到（先启动游戏再跑自检）", false));

        // 9. 输出目录可写
        bool canWrite = true;
        try
        {
            string probe = Path.Combine(Directory.GetCurrentDirectory(), $".write-test-{Guid.NewGuid():N}.tmp");
            File.WriteAllText(probe, "x");
            File.Delete(probe);
        }
        catch { canWrite = false; }
        items.Add(new Item("输出目录可写", canWrite, Directory.GetCurrentDirectory(), true));

        sw.Stop();

        // 输出
        if (!quiet)
        {
            Console.WriteLine();
            Console.WriteLine("================ 环境自检 ================");
            foreach (var item in items)
            {
                string mark = item.Ok ? "[PASS]" : "[FAIL]";
                Console.WriteLine($"{mark} {item.Name,-12} {item.Detail}");
            }

            Console.WriteLine();
            var critical = items.Where(i => !i.Ok && i.Critical).ToList();
            if (critical.Count > 0)
            {
                Console.WriteLine($"结论：{critical.Count} 项关键检查未通过 —— 建议先解决再扫描：");
                foreach (var c in critical)
                {
                    Console.WriteLine($"  - {c.Name}: {c.Detail}");
                }
            }
            else
            {
                Console.WriteLine("结论：环境就绪，可以扫描。");
            }

            Console.WriteLine($"耗时 {sw.ElapsedMilliseconds} ms");
        }

        return items.Any(i => !i.Ok && i.Critical) ? 1 : 0;
    }

    private static bool IsElevated()
    {
        try
        {
            using WindowsIdentity id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
