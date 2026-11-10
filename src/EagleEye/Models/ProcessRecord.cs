namespace EagleEye.Models;

public sealed class ModuleInfo
{
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public long BaseAddress { get; set; }
    public uint Size { get; set; }
}

public sealed class SignatureInfo
{
    /// <summary>valid / catalog_valid / unsigned / expired / revoked / untrusted_root / invalid_chain / bad_digest / distrusted / error / unavailable</summary>
    public string State { get; set; } = SignatureStates.Unavailable;
    public string? SignerSubject { get; set; }
    public bool CatalogSigned { get; set; }
    public bool HasEmbeddedSignature { get; set; }
    public uint? WinTrustStatus { get; set; }
    public string? Error { get; set; }
}

public static class SignatureStates
{
    public const string Valid = "valid";
    public const string CatalogValid = "catalog_valid";
    public const string Unsigned = "unsigned";
    public const string Expired = "expired";
    public const string Revoked = "revoked";
    public const string UntrustedRoot = "untrusted_root";
    public const string InvalidChain = "invalid_chain";
    public const string BadDigest = "bad_digest";
    public const string Distrusted = "distrusted";
    public const string Error = "error";
    public const string Unavailable = "unavailable";
}

public sealed class ProcessRecord
{
    public int Pid { get; set; }
    public int ParentPid { get; set; }
    public int ThreadCount { get; set; }
    public string Name { get; set; } = "";
    public string? ImagePath { get; set; }
    public string? CommandLine { get; set; }
    /// <summary>拿不到路径/命令行时的原因（受保护进程等）。</summary>
    public string? AccessError { get; set; }
    public string? ModuleError { get; set; }
    public List<ModuleInfo> Modules { get; set; } = new();
    public SignatureInfo Signature { get; set; } = new();
}