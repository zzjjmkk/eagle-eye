using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using EagleEye.Models;

namespace EagleEye.Reporting;

public static class ReportWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string WriteJson(ScanReport report, string outputPath)
    {
        string full = EnsureDirectory(outputPath);
        string json = JsonSerializer.Serialize(report, JsonOptions);
        File.WriteAllText(full, json, new System.Text.UTF8Encoding(false));
        return full;
    }

    public static string WriteHtml(ScanReport report, string outputPath)
    {
        string full = EnsureDirectory(outputPath);
        string html = HtmlReportWriter.Build(report);
        File.WriteAllText(full, html, new System.Text.UTF8Encoding(false));
        return full;
    }

    private static string EnsureDirectory(string path)
    {
        string full = Path.GetFullPath(path);
        string? dir = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        return full;
    }
}