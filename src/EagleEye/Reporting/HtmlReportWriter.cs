using System.Text;
using System.Text.Json;
using EagleEye.Core;
using EagleEye.Models;

namespace EagleEye.Reporting;

/// <summary>
/// 生成单文件 HTML 报告：内联 CSS、不引用任何外部资源、不含脚本，
/// 双击即可在本地浏览器打开，断网也能看。
/// </summary>
public static class HtmlReportWriter
{
    private static readonly JsonSerializerOptions EvidenceJson = new() { WriteIndented = false };

    public static string Build(ScanReport report)
    {
        var sb = new StringBuilder(64 * 1024);

        sb.Append(@"<!DOCTYPE html>
<html lang=""zh-CN"">
<head>
<meta charset=""utf-8"">
<meta name=""viewport"" content=""width=device-width, initial-scale=1"">
<title>本地反外挂扫描报告 - ").Append(Escape(report.Machine)).Append(@"</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--line:#e3e6ea;--text:#1f2328;--muted:#6b7280;
      --high:#dc2626;--susp:#d97706;--info:#6b7280;--ok:#059669}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--text);
     font:14px/1.6 -apple-system,""Segoe UI"",""Microsoft YaHei"",sans-serif}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:16px;margin:28px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--line)}
.sub{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:14px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.kpi{flex:1 1 150px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi .k{color:var(--muted);font-size:12px}
.kpi .v{font-size:22px;font-weight:600;margin-top:2px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:13px}
th{background:#fafbfc;color:var(--muted);font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-size:12px;white-space:nowrap}
.b-high{background:var(--high)}.b-susp{background:var(--susp)}.b-info{background:var(--info)}
.mono{font-family:Consolas,""Courier New"",monospace;font-size:12px;word-break:break-all}
.muted{color:var(--muted)}
details{margin-top:6px}
summary{cursor:pointer;color:#2563eb;font-size:13px}
ol.ev{margin:6px 0 0 18px;padding:0}
ol.ev li{margin-bottom:6px}
.reason{margin:6px 0 0 0;padding:6px 10px;background:#fff7ed;border-left:3px solid var(--susp);border-radius:4px;font-size:12px}
.note{font-size:12px;color:var(--muted)}
footer{margin-top:28px;color:var(--muted);font-size:12px;text-align:center}
</style>
</head>
<body>
");

        sb.Append("<h1>本地反外挂扫描报告</h1><div class=\"sub\">")
          .Append(Escape(report.Tool)).Append(" v").Append(Escape(report.Version))
          .Append(" &nbsp;|&nbsp; 扫描开始 ").Append(Escape(report.ScanStartedUtc))
          .Append(" &nbsp;|&nbsp; 耗时 ").Append(report.DurationSeconds.ToString("F2")).Append(" s")
          .Append("</div>");

        // 主机信息
        if (!report.IsElevated)
        {
            sb.Append("<div class=\"card\" style=\"border-color:#dc2626;background:#fef2f2\">")
              .Append("<strong style=\"color:#dc2626\">⚠ 本次扫描未提权，覆盖不完整</strong>")
              .Append("<div class=\"note\">").Append(report.Summary.UnreadableTargets)
              .Append(" 个受保护进程的模块、句柄、签名读不到，注入痕迹与句柄线索可能全部落空。现场取证请用「以管理员身份运行」重扫。</div></div>");
        }

        sb.Append("<div class=\"card\" style=\"margin-top:16px\">")
          .Append("<table><tr><th style=\"width:120px\">主机</th><td>").Append(Escape(report.Machine)).Append("</td>")
          .Append("<th style=\"width:120px\">系统</th><td>").Append(Escape(report.OsVersion)).Append("</td></tr>")
          .Append("<tr><th>用户</th><td>").Append(Escape(report.UserName)).Append("</td>")
          .Append("<th>管理员权限</th><td>").Append(report.IsElevated ? "是" : "否（部分进程无法查询，见未检查项）").Append("</td></tr>")
          .Append("<tr><th>规则集</th><td>").Append(Escape(report.Ruleset.Name)).Append(" v").Append(Escape(report.Ruleset.Version))
          .Append("</td><th>规则更新时间</th><td>").Append(Escape(report.Ruleset.Updated ?? "-")).Append("</td></tr>")
          .Append("<tr><th>规则数量</th><td>").Append(report.Ruleset.RuleCount).Append("（启用 ").Append(report.Ruleset.EnabledRuleCount).Append("）</td>")
          .Append("<th>白名单条目</th><td>").Append(report.Ruleset.WhitelistCount).Append("</td></tr>")
          .Append("</table></div>");

        // KPI
        sb.Append("<div class=\"cards\">");
        AppendKpi(sb, "总体风险", report.Summary.RiskLevel, LevelClass(report.Summary.RiskLevel));
        AppendKpi(sb, "活跃命中", report.Summary.Findings.ToString(), null);
        AppendKpi(sb, "白名单抑制", report.Summary.SuppressedFindings.ToString(), null);
        AppendKpi(sb, "未检查项", report.Summary.NotCheckedCount.ToString(), null);
        AppendKpi(sb, "进程 / 文件", report.Summary.ProcessesScanned + " / " + report.Summary.FilesScanned, null);
        AppendKpi(sb, "DMA PCI 设备", report.Summary.DmaPciDevices + "（" + report.Summary.DmaRiskLevel + "）", null);
        sb.Append("</div>");

        // 风险评定
        sb.Append("<h2>风险评定与证据链</h2>");
        if (report.Assessments.Count == 0)
        {
            sb.Append("<div class=\"card muted\">没有达到任何等级的命中。</div>");
        }
        else
        {
            sb.Append("<table><tr><th style=\"width:110px\">等级</th><th>目标</th><th style=\"width:80px\">得分</th>")
              .Append("<th style=\"width:150px\">信号构成</th><th>证据链</th></tr>");

            foreach (var a in report.Assessments)
            {
                sb.Append("<tr><td><span class=\"badge ").Append(LevelClass(a.RiskLevel)).Append("\">")
                  .Append(Escape(a.RiskLevel)).Append("</span></td>");

                sb.Append("<td><strong>").Append(Escape(a.Target)).Append("</strong>");
                if (a.Pid.HasValue)
                {
                    sb.Append("<div class=\"muted\">PID ").Append(a.Pid.Value).Append("</div>");
                }
                if (!string.IsNullOrEmpty(a.Path))
                {
                    sb.Append("<div class=\"mono muted\">").Append(Escape(a.Path!)).Append("</div>");
                }
                sb.Append("</td>");

                sb.Append("<td>").Append(a.Score.ToString("F1")).Append("</td>");
                sb.Append("<td class=\"muted\">强 ").Append(a.StrongSignalCount)
                  .Append(" / 中 ").Append(a.MediumSignalCount)
                  .Append(" / 弱 ").Append(a.WeakSignalCount).Append("</td>");

                sb.Append("<td>");
                if (a.EscalationReasons.Count > 0)
                {
                    foreach (string reason in a.EscalationReasons)
                    {
                        sb.Append("<div class=\"reason\">").Append(Escape(reason)).Append("</div>");
                    }
                }

                sb.Append("<details><summary>展开 ").Append(a.Evidence.Count).Append(" 条证据</summary><ol class=\"ev\">");
                foreach (var e in a.Evidence)
                {
                    sb.Append("<li><strong>").Append(Escape(e.RuleId)).Append("</strong> ")
                      .Append("<span class=\"muted\">[").Append(Escape(e.Category ?? e.RuleType)).Append("]</span> ")
                      .Append(Escape(e.Description))
                      .Append("<div class=\"muted\">severity ").Append(e.Severity)
                      .Append(" · confidence ").Append(e.Confidence.ToString("F2"))
                      .Append(" · score ").Append(e.Score.ToString("F1"));

                    if (e.Evidence is { Count: > 0 })
                    {
                        foreach (var kv in e.Evidence)
                        {
                            if (kv.Value is null) continue;
                            sb.Append("<br><span class=\"mono\">").Append(Escape(kv.Key)).Append(": ")
                              .Append(Escape(FormatValue(kv.Value))).Append("</span>");
                        }
                    }

                    sb.Append("</div></li>");
                }
                sb.Append("</ol></details></td></tr>");
            }

            sb.Append("</table>");
        }

        // 白名单抑制
        sb.Append("<h2>白名单抑制记录</h2>");
        if (report.SuppressedFindings.Count == 0)
        {
            sb.Append("<div class=\"card muted\">本次没有命中被白名单抑制。</div>");
        }
        else
        {
            sb.Append("<div class=\"note\" style=\"margin-bottom:8px\">这些命中已被白名单抑制，<strong>不参与风险评分</strong>，仅保留记录以便追溯与白名单复核。</div>");
            sb.Append("<table><tr><th style=\"width:170px\">规则</th><th>目标</th><th style=\"width:280px\">抑制原因</th><th style=\"width:70px\">原始分</th></tr>");
            foreach (var f in report.SuppressedFindings)
            {
                sb.Append("<tr><td class=\"mono\">").Append(Escape(f.RuleId)).Append("</td>")
                  .Append("<td>").Append(Escape(f.Target));
                if (f.TargetPath is not null)
                {
                    sb.Append("<div class=\"mono muted\">").Append(Escape(f.TargetPath)).Append("</div>");
                }
                sb.Append("</td><td>").Append(Escape(f.SuppressReason ?? "-")).Append("</td>")
                  .Append("<td class=\"muted\">").Append(f.Score.ToString("F1")).Append("</td></tr>");
            }
            sb.Append("</table>");
        }

        // 未检查项
        if (report.NotChecked.Count > 0)
        {
            sb.Append("<h2>未检查项（没查到 ≠ 干净）</h2>");
            sb.Append("<table><tr><th style=\"width:220px\">目标</th><th style=\"width:80px\">PID</th><th>原因</th></tr>");
            foreach (var n in report.NotChecked.Take(200))
            {
                sb.Append("<tr><td>").Append(Escape(n.Target)).Append("</td><td class=\"muted\">")
                  .Append(n.Pid?.ToString() ?? "-").Append("</td><td class=\"muted\">")
                  .Append(Escape(n.Reason)).Append("</td></tr>");
            }
            sb.Append("</table>");
            if (report.NotChecked.Count > 200)
            {
                sb.Append("<div class=\"note\">仅显示前 200 条，完整内容见 JSON 报告。</div>");
            }
        }

        // DMA
        if (report.Dma.Enabled)
        {
            sb.Append("<h2>DMA 外设（用户态初筛 · 等级 ").Append(Escape(report.Dma.RiskLevel)).Append("）</h2>");
            sb.Append("<div class=\"card\">枚举设备 ").Append(report.Dma.DevicesEnumerated)
              .Append(" 个，其中 PCI/PCIe ").Append(report.Dma.PciDevices)
              .Append(" 个，命中 ").Append(report.Dma.Findings).Append(" 条。<div class=\"note\">")
              .Append(Escape(report.Dma.Note)).Append("</div>");

            if (report.Dma.Kernel.Attempted)
            {
                sb.Append("<div class=\"note\">内核配置空间：")
                  .Append(report.Dma.Kernel.Loaded
                      ? (report.Dma.Kernel.Unloaded ? "已加载并已卸载" : "已加载，卸载失败！")
                      : "加载失败：" + Escape(report.Dma.Kernel.Error ?? "-"))
                  .Append("，读取 ").Append(report.Dma.Kernel.DevicesRead).Append("/")
                  .Append(report.Dma.Kernel.DevicesAttempted).Append(" 个设备</div>");
            }
            else
            {
                sb.Append("<div class=\"note\">内核配置空间：未启用。</div>");
            }
            sb.Append("</div>");

            if (report.DmaUserModeFindings.Count > 0)
            {
                sb.Append("<table><tr><th style=\"width:170px\">规则</th><th>设备</th><th style=\"width:140px\">VID:PID</th><th style=\"width:70px\">得分</th><th>说明</th></tr>");
                foreach (var f in report.DmaUserModeFindings)
                {
                    sb.Append("<tr><td class=\"mono\">").Append(Escape(f.RuleId)).Append("</td>")
                      .Append("<td>").Append(Escape(f.Target));
                    if (f.Suppressed)
                    {
                        sb.Append(" <span class=\"muted\">（已抑制）</span>");
                    }
                    sb.Append("<div class=\"mono muted\">").Append(Escape(f.InstanceId)).Append("</div></td>")
                      .Append("<td class=\"mono\">").Append(Escape(f.VendorId ?? "-")).Append(":").Append(Escape(f.DeviceId ?? "-")).Append("</td>")
                      .Append("<td>").Append(f.Score.ToString("F1")).Append("</td>")
                      .Append("<td>").Append(Escape(f.Description)).Append("</td></tr>");
                }
                sb.Append("</table>");
            }

            if (report.Dma.Devices.Count > 0)
            {
                sb.Append("<details style=\"margin-top:10px\"><summary>展开全部 ").Append(report.Dma.Devices.Count).Append(" 个 PCI 设备</summary>");
                sb.Append("<table><tr><th>设备</th><th>VID:PID</th><th>REV</th><th>类</th><th>近似Class</th><th>服务</th><th>位置</th></tr>");
                foreach (var d in report.Dma.Devices)
                {
                    sb.Append("<tr><td>").Append(Escape(d.Name)).Append("</td>")
                      .Append("<td class=\"mono\">").Append(Escape(d.VendorId ?? "-")).Append(":").Append(Escape(d.DeviceId ?? "-")).Append("</td>")
                      .Append("<td class=\"mono\">").Append(Escape(d.Revision ?? "-")).Append("</td>")
                      .Append("<td>").Append(Escape(d.DeviceClass ?? "-")).Append("</td>")
                      .Append("<td class=\"mono\">").Append(Escape((d.ConfigSpace is not null ? d.ConfigSpace.ClassCodeHex : d.ClassCodeGuess) ?? "-")).Append("</td>")
                      .Append("<td class=\"mono\">").Append(Escape(d.Service ?? "-")).Append("</td>")
                      .Append("<td class=\"muted\">").Append(Escape(d.Location ?? "-")).Append("</td></tr>");
                }
                sb.Append("</table></details>");
            }
        }

        // 审计
        AppendVisionSection(sb, report);
        AppendDeepSection(sb, report);
        AppendTelemetrySection(sb, report);

        sb.Append("<h2>扫描器自身行为审计</h2>");
        sb.Append("<div class=\"card\"><table>")
          .Append("<tr><th style=\"width:200px\">进程打开次数</th><td>").Append(report.Audit.ProcessOpenAttempts)
          .Append("（被拒绝 ").Append(report.Audit.ProcessOpenDenied).Append("）</td></tr>")
          .Append("<tr><th>申请权限</th><td>仅 <span class=\"mono\">PROCESS_QUERY_LIMITED_INFORMATION (0x1000)</span>，从不申请 PROCESS_VM_READ / WRITE</td></tr>")
          .Append("<tr><th>数字签名校验</th><td>").Append(report.Audit.SignatureChecks).Append(" 次</td></tr>")
          .Append("<tr><th>驱动加载</th><td>")
          .Append(report.Audit.DriverLoadAttempts == 0
              ? "未尝试"
              : (report.Audit.DriverLoaded ? "已加载" + (report.Audit.DriverUnloaded ? "，已卸载" : "，未卸载！") : "尝试但失败"))
          .Append("</td></tr>")
          .Append("<tr><th>网络访问</th><td>无（本工具不发起任何网络请求，不上传任何数据）</td></tr>")
          .Append("<tr><th>审计日志</th><td class=\"mono\">").Append(Escape(report.Audit.LogPath ?? "-")).Append("</td></tr>")
          .Append("</table></div>");

        sb.Append("<footer>由 ").Append(Escape(report.Tool)).Append(" v").Append(Escape(report.Version))
          .Append(" 生成 · 本报告为本地离线产物，不含任何外发数据 · 生成时间 ")
          .Append(Escape(report.ScanFinishedUtc)).Append("</footer>\n</body>\n</html>\n");

        return sb.ToString();
    }

    private static void AppendTelemetrySection(StringBuilder sb, ScanReport report)
    {
        var tel = report.Telemetry;
        if (!tel.Enabled && !tel.Loaded && string.IsNullOrEmpty(tel.Error))
        {
            return;
        }

        sb.Append("<h2>游戏侧遥测（联合评估）</h2>");

        if (!string.IsNullOrEmpty(tel.Error))
        {
            sb.Append("<div class=\"card\"><span class=\"muted\">导入失败：").Append(Escape(tel.Error)).Append("</span></div>");
            return;
        }

        sb.Append("<div class=\"card\">本机等级 <strong>").Append(Escape(tel.LocalLevel))
          .Append("</strong> · 遥测等级 <strong>").Append(Escape(tel.Assessments.Count > 0 ? tel.Assessments[0].TelemetryLevel : RiskLevels.Info))
          .Append("</strong> · 联合建议 <span class=\"badge ").Append(LevelClass(tel.JointLevel)).Append("\">")
          .Append(Escape(tel.JointLevel)).Append("</span>")
          .Append("<div class=\"note\">").Append(Escape(tel.Note)).Append("</div></div>");

        foreach (var session in tel.Assessments.Take(5))
        {
            sb.Append("<table style=\"margin-top:10px\"><tr><th style=\"width:200px\">会话</th><th>玩家</th>")
              .Append("<th style=\"width:80px\">时长</th><th style=\"width:90px\">遥测等级</th><th style=\"width:70px\">信号</th></tr>")
              .Append("<tr><td class=\"mono\">").Append(Escape(session.SessionId)).Append("</td><td>")
              .Append(Escape(session.AccountName ?? session.PlayerId ?? "-"))
              .Append("</td><td class=\"muted\">").Append(session.DurationSeconds).Append("s</td>")
              .Append("<td><span class=\"badge ").Append(LevelClass(session.TelemetryLevel)).Append("\">")
              .Append(Escape(session.TelemetryLevel)).Append("</span></td>")
              .Append("<td>").Append(session.Signals.Count).Append("</td></tr></table>");

            if (session.Signals.Count > 0)
            {
                sb.Append("<table><tr><th style=\"width:170px\">规则</th><th style=\"width:170px\">指标</th>")
                  .Append("<th style=\"width:100px\">实测</th><th style=\"width:100px\">阈值</th>")
                  .Append("<th style=\"width:100px\">人群基线</th><th>说明</th></tr>");

                foreach (var signal in session.Signals)
                {
                    sb.Append("<tr><td class=\"mono\">").Append(Escape(signal.RuleId)).Append("</td>")
                      .Append("<td class=\"mono\">").Append(Escape(signal.Metric)).Append("</td>")
                      .Append("<td>").Append(signal.Value).Append("</td>")
                      .Append("<td class=\"muted\">").Append(signal.Threshold).Append("</td>")
                      .Append("<td class=\"muted\">").Append(signal.BaselineKnown ? signal.Baseline.ToString() : "-").Append("</td>")
                      .Append("<td>").Append(Escape(signal.Description)).Append("</td></tr>");
                }

                sb.Append("</table>");
            }
        }

        if (tel.JointReasons.Count > 0)
        {
            sb.Append("<ul class=\"note\">");
            foreach (string reason in tel.JointReasons)
            {
                sb.Append("<li>").Append(Escape(reason)).Append("</li>");
            }
            sb.Append("</ul>");
        }
    }

    private static void AppendDeepSection(StringBuilder sb, ScanReport report)
    {
        if (!report.Handles.Enabled && !report.Drivers.Enabled && !report.FileSignatures.Enabled)
        {
            return;
        }

        sb.Append("<h2>深度线索（句柄 / 驱动 / 特征码）</h2>");

        if (report.Handles.Enabled)
        {
            sb.Append("<div class=\"card\">");
            if (!string.IsNullOrEmpty(report.Handles.Error))
            {
                sb.Append("句柄枚举：<span class=\"muted\">失败 —— ").Append(Escape(report.Handles.Error)).Append("</span>");
            }
            else
            {
                sb.Append("句柄表 ").Append(report.Handles.HandlesEnumerated)
                  .Append(" 个 · 高权限句柄 ").Append(report.Handles.HighAccessHandles)
                  .Append(" 个 · 命中 ").Append(report.Summary.HandleFindings).Append(" 条");
            }
            sb.Append("<div class=\"note\">").Append(Escape(report.Handles.Note)).Append("</div></div>");

            if (report.Handles.Holders.Count > 0)
            {
                sb.Append("<table><tr><th>持有者</th><th style=\"width:80px\">PID</th><th>目标</th>")
                  .Append("<th style=\"width:150px\">权限</th><th style=\"width:80px\">签名</th></tr>");

                foreach (var h in report.Handles.Holders.Take(30))
                {
                    sb.Append("<tr><td><strong>").Append(Escape(h.HolderName)).Append("</strong>");
                    if (!string.IsNullOrEmpty(h.HolderPath))
                    {
                        sb.Append("<div class=\"mono muted\">").Append(Escape(h.HolderPath)).Append("</div>");
                    }
                    sb.Append("</td><td class=\"muted\">").Append(h.HolderPid)
                      .Append("</td><td>").Append(Escape(h.TargetName ?? "-"))
                      .Append("</td><td class=\"mono\">").Append(Escape(string.Join("|", h.AccessRights)))
                      .Append("</td><td class=\"muted\">").Append(Escape(h.HolderSignature ?? "-")).Append("</td></tr>");
                }

                sb.Append("</table>");
            }
        }

        if (report.Drivers.Enabled)
        {
            sb.Append("<div class=\"card\" style=\"margin-top:10px\">");
            if (!string.IsNullOrEmpty(report.Drivers.Error))
            {
                sb.Append("驱动枚举：<span class=\"muted\">失败 —— ").Append(Escape(report.Drivers.Error)).Append("</span></div>");
            }
            else
            {
                sb.Append("已加载驱动 ").Append(report.Drivers.DriversEnumerated)
                  .Append(" 个 · 命中规则 ").Append(report.Summary.DriverFindings).Append(" 条</div>");
            }

            if (report.Drivers.Suspicious.Count > 0)
            {
                sb.Append("<table><tr><th>驱动</th><th>路径</th><th style=\"width:160px\">匹配规则</th><th style=\"width:80px\">签名</th></tr>");
                foreach (var d in report.Drivers.Suspicious)
                {
                    sb.Append("<tr><td class=\"mono\">").Append(Escape(d.Name)).Append("</td>")
                      .Append("<td class=\"mono muted\">").Append(Escape(d.Path)).Append("</td>")
                      .Append("<td class=\"mono\">").Append(Escape(d.MatchedRuleId ?? "-")).Append("</td>")
                      .Append("<td class=\"muted\">").Append(Escape(d.SignatureState ?? "-")).Append("</td></tr>");
                }
                sb.Append("</table>");
            }
        }

        if (report.FileSignatures.Enabled)
        {
            sb.Append("<div class=\"card\" style=\"margin-top:10px\">文件特征码：扫描 ")
              .Append(report.FileSignatures.FilesScanned).Append(" 个文件，命中 ")
              .Append(report.FileSignatures.FilesMatched).Append(" 个</div>");

            if (report.FileSignatures.Hits.Count > 0)
            {
                sb.Append("<table><tr><th style=\"width:180px\">规则</th><th>文件</th>")
                  .Append("<th style=\"width:110px\">大小</th><th>SHA256</th></tr>");
                foreach (var hit in report.FileSignatures.Hits.Take(30))
                {
                    sb.Append("<tr><td class=\"mono\">").Append(Escape(hit.RuleId)).Append("</td>")
                      .Append("<td>").Append(Escape(hit.FileName))
                      .Append("<div class=\"mono muted\">").Append(Escape(hit.Path)).Append("</div></td>")
                      .Append("<td class=\"muted\">").Append(hit.Size).Append("</td>")
                      .Append("<td class=\"mono muted\">").Append(Escape(hit.Sha256 ?? "-")).Append("</td></tr>");
                }
                sb.Append("</table>");
            }
        }
    }

    private static void AppendVisionSection(StringBuilder sb, ScanReport report)
    {
        var vision = report.VisionCheatIndicators;
        if (!vision.Enabled)
        {
            return;
        }

        sb.Append("<h2>视觉外挂线索（AI Vision · 等级 ").Append(Escape(vision.HighestLevel)).Append("）</h2>");
        sb.Append("<div class=\"card\">软件采集 ").Append(report.Summary.VisionSoftwareIndicators)
          .Append(" 条 · 硬件 ").Append(report.Summary.VisionHardwareIndicators)
          .Append(" 条 · 独立层 ").Append(vision.IndependentLayers).Append(" 层")
          .Append("<div class=\"note\">").Append(Escape(vision.Note)).Append("</div></div>");

        if (vision.SoftwareCapture.Count > 0)
        {
            sb.Append("<table><tr><th style=\"width:180px\">规则</th><th>进程</th><th style=\"width:220px\">匹配模块</th>")
              .Append("<th style=\"width:80px\">签名</th><th style=\"width:60px\">置信度</th></tr>");

            foreach (var item in vision.SoftwareCapture)
            {
                sb.Append("<tr><td class=\"mono\">").Append(Escape(item.Id)).Append("</td>")
                  .Append("<td><strong>").Append(Escape(item.Target)).Append("</strong>")
                  .Append("<div class=\"muted\">PID ").Append(item.Pid?.ToString() ?? "-").Append("</div>");

                if (!string.IsNullOrEmpty(item.Path))
                {
                    sb.Append("<div class=\"mono muted\">").Append(Escape(item.Path)).Append("</div>");
                }

                if (item.Suppressed)
                {
                    sb.Append("<div class=\"reason\">已被白名单抑制：").Append(Escape(item.SuppressReason ?? "")).Append("</div>");
                }

                sb.Append("</td><td class=\"mono\">").Append(Escape(string.Join(", ", item.MatchedModules.Take(6))))
                  .Append("</td><td class=\"muted\">").Append(Escape(item.SignatureState ?? "-"))
                  .Append("</td><td>").Append(item.Confidence.ToString("F2")).Append("</td></tr>");
            }

            sb.Append("</table>");
        }

        if (vision.HardwareIndicators.Count > 0)
        {
            sb.Append("<table style=\"margin-top:10px\"><tr><th style=\"width:180px\">规则</th><th>设备</th>")
              .Append("<th style=\"width:120px\">VID:PID</th><th style=\"width:120px\">Class</th>")
              .Append("<th style=\"width:140px\">Service</th><th style=\"width:60px\">置信度</th></tr>");

            foreach (var item in vision.HardwareIndicators)
            {
                sb.Append("<tr><td class=\"mono\">").Append(Escape(item.Id)).Append("</td><td>")
                  .Append(Escape(item.Target));

                if (item.Suppressed)
                {
                    sb.Append(" <span class=\"muted\">（已抑制）</span>");
                }

                sb.Append("<div class=\"mono muted\">").Append(Escape(item.Path ?? "")).Append("</div></td>")
                  .Append("<td class=\"mono\">").Append(Escape(Value(item, "vendorId"))).Append(":")
                  .Append(Escape(Value(item, "deviceId"))).Append("</td>")
                  .Append("<td class=\"muted\">").Append(Escape(Value(item, "deviceClass"))).Append("</td>")
                  .Append("<td class=\"mono\">").Append(Escape(Value(item, "service"))).Append("</td>")
                  .Append("<td>").Append(item.Confidence.ToString("F2")).Append("</td></tr>");
            }

            sb.Append("</table>");
        }

        if (vision.BehavioralHint.Collected)
        {
            var bh = vision.BehavioralHint;
            sb.Append("<div class=\"card\" style=\"margin-top:10px\"><strong>行为提示（信息级）</strong>")
              .Append("<div class=\"note\">").Append(Escape(bh.Description)).Append("</div>")
              .Append("<div class=\"mono muted\">直线化 ").Append(bh.StraightLineRatio.ToString("P0"))
              .Append(" · 匀速 ").Append(bh.ConstantVelocityRatio.ToString("P0"))
              .Append(" · 静止占比 ").Append(bh.ZeroDeltaRatio.ToString("P0"))
              .Append(" · 平均速度 ").Append(bh.AverageSpeedPxPerSec.ToString("F0")).Append(" px/s")
              .Append(" · 采样 ").Append(bh.SampleCount).Append(" 点</div>")
              .Append("<div class=\"note\">").Append(Escape(bh.Note)).Append("</div></div>");
        }
        else if (!string.IsNullOrEmpty(vision.BehavioralHint.SkipReason))
        {
            sb.Append("<div class=\"note\">行为提示：").Append(Escape(vision.BehavioralHint.SkipReason)).Append("</div>");
        }

        if (vision.Notes.Count > 0)
        {
            sb.Append("<ul class=\"note\">");
            foreach (string n in vision.Notes)
            {
                sb.Append("<li>").Append(Escape(n)).Append("</li>");
            }
            sb.Append("</ul>");
        }

        sb.Append("<div class=\"reason\"><strong>声明：</strong>双机 + 外部采集 + 硬件注入链路在本机用户态无法独立确证，");
        sb.Append("以上为可观测线索，不代表最终判定；本地最高等级为「可疑」，最终认定需游戏侧遥测与人工复核。</div>");
    }

    private static string Value(VisionIndicator item, string key)
    {
        return item.Evidence.TryGetValue(key, out object? v) && v is not null ? v.ToString() ?? "" : "-";
    }

    private static void AppendKpi(StringBuilder sb, string key, string value, string? levelClass)
    {
        sb.Append("<div class=\"kpi\"><div class=\"k\">").Append(Escape(key)).Append("</div><div class=\"v\">");
        if (levelClass is not null)
        {
            sb.Append("<span class=\"badge ").Append(levelClass).Append("\">").Append(Escape(value)).Append("</span>");
        }
        else
        {
            sb.Append(Escape(value));
        }
        sb.Append("</div></div>");
    }

    private static string LevelClass(string level) => level switch
    {
        RiskLevels.High => "b-high",
        RiskLevels.Suspicious => "b-susp",
        _ => "b-info"
    };

    private static string FormatValue(object value)
    {
        try
        {
            return value is string s ? s : JsonSerializer.Serialize(value, EvidenceJson);
        }
        catch
        {
            return value.ToString() ?? "";
        }
    }

    private static string Escape(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return "";
        }

        return text.Replace("&", "&amp;")
                   .Replace("<", "&lt;")
                   .Replace(">", "&gt;")
                   .Replace("\"", "&quot;");
    }
}