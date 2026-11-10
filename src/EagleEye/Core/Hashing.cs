using System.Security.Cryptography;

namespace EagleEye.Core;

public static class Hashing
{
    /// <summary>只读方式计算 SHA256，返回小写十六进制；失败返回 null 并给出原因。</summary>
    public static string? TrySha256(string path, out string? error)
    {
        error = null;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20, FileOptions.SequentialScan);
            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(fs);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return null;
        }
    }
}