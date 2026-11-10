using System.Diagnostics;
using System.Security.Principal;
using EagleEye.Rules;

namespace EagleEye;

/// <summary>
/// 双击向导：不带参数运行时进入。
/// 面向不熟悉命令行的使用者：自检 → 必要时提权 → 扫描 → 打开报告 → 停留等按键。
/// </summary>
public static class Wizard
{
    public static int Run()
    {
        Console.Title = "Eagle Eye - 本地外挂痕迹扫描";

        Console.WriteLine();
        Console.WriteLine("  ███████╗ █████╗  ██████╗ ██╗     ███████╗    ███████╗██╗   ██╗███████╗");
        Console.WriteLine("  ██╔════╝██╔══██╗██╔════╝ ██║     ██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝");
        Console.WriteLine("  █████╗  ███████║██║  ███╗██║     █████╗      █████╗   ╚████╔╝ █████╗  ");
        Console.WriteLine("  ██╔══╝  ██╔══██║██║   ██║██║     ██╔══╝      ██╔══╝    ╚██╔╝  ██╔══╝  ");
        Console.WriteLine("  ███████╗██║  ██║╚██████╔╝███████╗███████╗    ███████╗   ██║   ███████╗");
        Console.WriteLine("  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝   ╚═╝   ╚══════╝");
        Console.WriteLine();
        Console.WriteLine("  本地反外挂只读查询工具 · 只读枚举，不注入、不读内存、不 Hook、不联网");
        Console.WriteLine();

        // 1. 权限
        if (!IsElevated())
        {
            Console.WriteLine("  [提示] 当前不是管理员权限。");
            Console.WriteLine("         游戏等受保护进程的模块、句柄读不到，扫描会不完整。");
            Console.WriteLine();
            Console.Write("  是否以管理员身份重新运行？(Y/n) ");
            string? answer = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(answer) || answer.Trim().ToLowerInvariant().StartsWith("y"))
            {
                return RelaunchElevated();
            }

            Console.WriteLine();
            Console.WriteLine("  继续以普通权限扫描（结果会标注「覆盖不完整」）...");
        }

        // 2. 规则
        string rulesDir = Path.Combine(AppContext.BaseDirectory, "rules");
        var load = Directory.Exists(rulesDir)
            ? RuleLoader.LoadDirectory(rulesDir)
            : RuleLoader.Load(Path.Combine(AppContext.BaseDirectory, "rules", "rules.json"));

        if (!load.Success)
        {
            Console.WriteLine();
            Console.WriteLine("  [错误] 规则加载失败：");
            foreach (string err in load.Errors.Take(5))
            {
                Console.WriteLine("         " + err);
            }
            Pause();
            return 1;
        }

        Console.WriteLine($"  规则: {load.RuleSet.Meta.Name} v{load.RuleSet.Meta.Version}，" +
                          $"{load.RuleSet.Rules.Count + load.RuleSet.Dma.Rules.Count} 条");
        Console.WriteLine();

        // 3. 扫描
        Console.WriteLine("  开始扫描（约 10-20 秒，请不要关闭窗口）...");
        Console.WriteLine();

        int exitCode;
        try
        {
            exitCode = Program.RunScanFromWizard(rulesDir);
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.WriteLine("  [错误] 扫描中断: " + ex.Message);
            Pause();
            return 1;
        }

        // 4. 打开报告
        string reportDir = Path.Combine(AppContext.BaseDirectory, "out", "reports");
        string? html = Directory.Exists(reportDir)
            ? Directory.GetFiles(reportDir, "*.html").OrderByDescending(f => f).FirstOrDefault()
            : null;

        Console.WriteLine();
        if (html is not null)
        {
            Console.WriteLine("  报告已生成：");
            Console.WriteLine("    " + html);
            Console.WriteLine();
            Console.Write("  是否立即打开报告？(Y/n) ");
            string? open = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(open) || open.Trim().ToLowerInvariant().StartsWith("y"))
            {
                try { Process.Start(new ProcessStartInfo(html) { UseShellExecute = true }); }
                catch { Console.WriteLine("  打开失败，请手动双击上面的路径。"); }
            }
        }
        else
        {
            Console.WriteLine("  报告目录: " + reportDir);
        }

        Console.WriteLine();
        Console.WriteLine("  判定说明：本地最高只给「高度可疑」，需要人工复核。");
        Console.WriteLine("  双机 / 外部采集 / 硬件转发在本机不会留下痕迹，这类只能靠游戏侧遥测。");
        Console.WriteLine();

        Pause();
        return exitCode;
    }

    private static int RelaunchElevated()
    {
        string? exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe))
        {
            Console.WriteLine("  无法定位自身路径，请手动以管理员身份运行。");
            Pause();
            return 1;
        }

        try
        {
            Process.Start(new ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = AppContext.BaseDirectory
            });
            Console.WriteLine("  已请求管理员权限，请在弹出的窗口中继续。");
            Thread.Sleep(800);
            return 0;
        }
        catch
        {
            Console.WriteLine("  提权被取消，改为普通权限扫描。");
            return Run();
        }
    }

    private static void Pause()
    {
        Console.WriteLine("  按 Enter 键关闭窗口...");
        try { Console.ReadLine(); } catch { }
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
