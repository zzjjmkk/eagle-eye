using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace EagleEye.Scanning;

/// <summary>
/// 扫描器自身行为日志（JSONL，一行一个事件）。
/// 记录：扫描起止与参数、每个进程的打开请求与申请的权限、验签次数、驱动加载/卸载、报告输出路径。
/// 全程只写本地文件，不联网、不上传。
/// </summary>
public sealed class AuditLogger : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private readonly object _lock = new();
    private readonly StreamWriter? _writer;

    private int _openAttempts;
    private int _openDenied;
    private int _signatureChecks;
    private int _driverAttempts;
    private int _driverLoadedFlag;
    private int _driverUnloadedFlag;
    private int _disposed;

    public string? LogPath { get; }

    public int ProcessOpenAttempts => Volatile.Read(ref _openAttempts);
    public int ProcessOpenDenied => Volatile.Read(ref _openDenied);
    public int SignatureChecks => Volatile.Read(ref _signatureChecks);
    public int DriverLoadAttempts => Volatile.Read(ref _driverAttempts);
    public bool DriverLoaded => Volatile.Read(ref _driverLoadedFlag) == 1;
    public bool DriverUnloaded => Volatile.Read(ref _driverUnloadedFlag) == 1;

    public AuditLogger(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        LogPath = Path.GetFullPath(path!);
        string? dir = Path.GetDirectoryName(LogPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        _writer = new StreamWriter(
            new FileStream(LogPath, FileMode.Append, FileAccess.Write, FileShare.Read),
            new UTF8Encoding(false))
        {
            AutoFlush = true
        };
    }

    public void Write(string eventName, object? payload)
    {
        if (_writer is null || Volatile.Read(ref _disposed) == 1)
        {
            return;
        }

        var record = new Dictionary<string, object?>
        {
            ["ts"] = DateTime.UtcNow.ToString("o"),
            ["event"] = eventName,
            ["data"] = payload
        };

        string line = JsonSerializer.Serialize(record, JsonOptions);
        lock (_lock)
        {
            _writer.WriteLine(line);
        }
    }

    /// <summary>记录一次进程打开：目标、申请的访问掩码、结果。</summary>
    public void ProcessOpen(int pid, string name, uint accessMask, bool success, int win32Error, string? path)
    {
        Interlocked.Increment(ref _openAttempts);
        if (!success)
        {
            Interlocked.Increment(ref _openDenied);
        }

        Write("process.open", new
        {
            pid,
            name,
            accessMask = $"0x{accessMask:X}",
            accessMeaning = accessMask == 0x1000 ? "PROCESS_QUERY_LIMITED_INFORMATION（只读查询）" : "unknown",
            result = success ? "granted" : "denied",
            win32Error = success ? 0 : win32Error,
            imagePath = path,
            note = "不申请 PROCESS_VM_READ / PROCESS_VM_WRITE，不读写进程内存"
        });
    }

    public void SignatureChecked(string path, string state)
    {
        Interlocked.Increment(ref _signatureChecks);
        if (SignatureChecks <= 400)
        {
            Write("signature.verify", new { path, state });
        }
    }

    public void DriverEvent(string phase, string serviceName, string? driverPath, bool success, string? detail)
    {
        if (phase == "load")
        {
            Interlocked.Increment(ref _driverAttempts);
            if (success)
            {
                Interlocked.Exchange(ref _driverLoadedFlag, 1);
            }
        }
        else if (phase == "unload" && success)
        {
            Interlocked.Exchange(ref _driverUnloadedFlag, 1);
        }

        Write("driver." + phase, new
        {
            service = serviceName,
            driverPath,
            result = success ? "ok" : "failed",
            detail
        });
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        if (_writer is null)
        {
            return;
        }

        var summary = new Dictionary<string, object?>
        {
            ["ts"] = DateTime.UtcNow.ToString("o"),
            ["event"] = "audit.closed",
            ["data"] = new
            {
                processOpenAttempts = ProcessOpenAttempts,
                processOpenDenied = ProcessOpenDenied,
                signatureChecks = SignatureChecks,
                driverLoadAttempts = DriverLoadAttempts,
                driverLoaded = DriverLoaded,
                driverUnloaded = DriverUnloaded
            }
        };

        lock (_lock)
        {
            _writer.WriteLine(JsonSerializer.Serialize(summary, JsonOptions));
            _writer.Flush();
            _writer.Dispose();
        }
    }
}