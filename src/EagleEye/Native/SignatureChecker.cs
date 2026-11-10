using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using EagleEye.Models;

namespace EagleEye.Native;

/// <summary>
/// Authenticode 校验：内嵌签名（WinVerifyTrust）+ 目录签名（cat 文件）双路。
/// 结果按 路径+大小+修改时间 缓存，避免重复验签。
/// </summary>
public sealed class SignatureChecker
{
    private static readonly Guid WinTrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;
    private const uint WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x00000400;

    private const uint S_OK = 0;
    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    private const uint CERT_E_EXPIRED = 0x800B0101;
    private const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;
    private const uint CERT_E_CHAINING = 0x800B010A;
    private const uint CERT_E_REVOKED = 0x800B010C;
    private const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;
    private const uint TRUST_E_BAD_DIGEST = 0x80096010;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    private readonly ConcurrentDictionary<string, SignatureInfo> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly bool _checkRevocation;
    private readonly string? _cachePath;
    private int _newEntries;

    /// <summary>
    /// 验签结果缓存：内存 + 磁盘。
    /// 磁盘缓存键 = 路径|大小|修改时间，文件一变自动失效，因此不会误用旧结果。
    /// 273 个驱动逐一验签约 4-5s，命中缓存后接近 0。
    /// </summary>
    public SignatureChecker(bool checkRevocation, string? cachePath = null)
    {
        _checkRevocation = checkRevocation;
        _cachePath = cachePath;
        LoadCache();
    }

    public int CacheSize => _cache.Count;
    public int NewEntries => _newEntries;

    private void LoadCache()
    {
        if (string.IsNullOrWhiteSpace(_cachePath) || !File.Exists(_cachePath)) return;

        try
        {
            string json = File.ReadAllText(_cachePath!);
            var loaded = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, SignatureInfo>>(json);
            if (loaded is null) return;

            foreach (var kv in loaded.Take(20000))
            {
                _cache[kv.Key] = kv.Value;
            }
        }
        catch
        {
            // 缓存损坏就当没有，不影响扫描
        }
    }

    public void SaveCache()
    {
        if (string.IsNullOrWhiteSpace(_cachePath) || _newEntries == 0) return;

        try
        {
            string? dir = Path.GetDirectoryName(Path.GetFullPath(_cachePath!));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var snapshot = _cache.Take(20000).ToDictionary(kv => kv.Key, kv => kv.Value);
            string json = System.Text.Json.JsonSerializer.Serialize(snapshot, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = false,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
            File.WriteAllText(_cachePath!, json, new System.Text.UTF8Encoding(false));
        }
        catch
        {
            // 写缓存失败不影响扫描
        }
    }

    public SignatureInfo Check(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return new SignatureInfo { State = SignatureStates.Unavailable, Error = "文件不存在或路径不可读" };
        }

        string key = BuildCacheKey(path);

        if (_cache.TryGetValue(key, out SignatureInfo? cached))
        {
            return cached;
        }

        var fresh = CheckCore(path!);
        if (_cache.TryAdd(key, fresh))
        {
            Interlocked.Increment(ref _newEntries);
        }

        return fresh;
    }

    private static string BuildCacheKey(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            return $"{fi.FullName}|{fi.Length}|{fi.LastWriteTimeUtc.Ticks}";
        }
        catch
        {
            return path;
        }
    }

    private SignatureInfo CheckCore(string path)
    {
        uint status = VerifyEmbedded(path);
        if (status == S_OK)
        {
            return new SignatureInfo
            {
                State = SignatureStates.Valid,
                HasEmbeddedSignature = true,
                WinTrustStatus = status,
                SignerSubject = TryGetSignerSubject(path)
            };
        }

        if (status == TRUST_E_NOSIGNATURE)
        {
            // 无内嵌签名 → 查目录签名（大量 Windows 组件只有 cat 签名）
            if (HasCatalogSignature(path))
            {
                return new SignatureInfo
                {
                    State = SignatureStates.CatalogValid,
                    CatalogSigned = true,
                    HasEmbeddedSignature = false,
                    WinTrustStatus = status,
                    SignerSubject = null
                };
            }

            return new SignatureInfo
            {
                State = SignatureStates.Unsigned,
                HasEmbeddedSignature = false,
                WinTrustStatus = status
            };
        }

        string state = status switch
        {
            TRUST_E_BAD_DIGEST => SignatureStates.BadDigest,
            CERT_E_EXPIRED => SignatureStates.Expired,
            CERT_E_REVOKED => SignatureStates.Revoked,
            CERT_E_UNTRUSTEDROOT => SignatureStates.UntrustedRoot,
            CERT_E_CHAINING => SignatureStates.InvalidChain,
            TRUST_E_EXPLICIT_DISTRUST => SignatureStates.Distrusted,
            _ => SignatureStates.Error
        };

        return new SignatureInfo
        {
            State = state,
            HasEmbeddedSignature = true,
            WinTrustStatus = status,
            Error = $"0x{status:X8}",
            SignerSubject = TryGetSignerSubject(path)
        };
    }

    private uint VerifyEmbedded(string path)
    {
        IntPtr pFilePath = IntPtr.Zero;
        IntPtr pFileInfo = IntPtr.Zero;
        IntPtr pData = IntPtr.Zero;

        try
        {
            pFilePath = Marshal.StringToHGlobalUni(path);

            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = pFilePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = _checkRevocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFileInfo,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = _checkRevocation
                    ? WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                    : WTD_CACHE_ONLY_URL_RETRIEVAL,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(data, pData, false);

            uint result = WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2, pData);

            // 关闭状态句柄，避免内存泄漏
            var after = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            after.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(after, pData, false);
            WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2, pData);

            return result;
        }
        catch (Exception ex)
        {
            return unchecked((uint)ex.HResult);
        }
        finally
        {
            if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
            if (pFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pFileInfo);
            if (pFilePath != IntPtr.Zero) Marshal.FreeHGlobal(pFilePath);
        }
    }

    private bool HasCatalogSignature(string path)
    {
        IntPtr hCatAdmin = IntPtr.Zero;
        FileStream? fs = null;
        try
        {
            if (!CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0))
            {
                return false;
            }

            fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            uint hashSize = 0;
            if (!CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle.DangerousGetHandle(), ref hashSize, null, 0) || hashSize == 0)
            {
                return false;
            }

            byte[] hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle.DangerousGetHandle(), ref hashSize, hash, 0))
            {
                return false;
            }

            IntPtr prev = IntPtr.Zero;
            IntPtr catInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, ref prev);
            if (catInfo == IntPtr.Zero)
            {
                return false;
            }

            CryptCATAdminReleaseCatalogContext(hCatAdmin, catInfo, 0);
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            fs?.Dispose();
            if (hCatAdmin != IntPtr.Zero)
            {
                CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
        }
    }

    private static string? TryGetSignerSubject(string path)
    {
        try
        {
#pragma warning disable SYSLIB0026
            using X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
            return cert.Subject;
#pragma warning restore SYSLIB0026
        }
        catch
        {
            return null;
        }
    }
}