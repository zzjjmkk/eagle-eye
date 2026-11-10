using System.Runtime.InteropServices;
using System.Text;

namespace EagleEye.Native;

/// <summary>已加载内核模块枚举（只读，SystemModuleInformation）。</summary>
internal static class DriverInterop
{
    private const int SystemModuleInformation = 11;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int systemInformationClass, IntPtr systemInformation, int systemInformationLength, out int returnLength);

    public readonly record struct LoadedModule(string Name, string FullPath, long ImageBase, uint ImageSize);

    public static List<LoadedModule> Enumerate(out string? error)
    {
        error = null;
        var list = new List<LoadedModule>();

        IntPtr buffer = IntPtr.Zero;
        try
        {
            int length = 1 << 20;
            int status = -1;

            for (int attempt = 0; attempt < 5; attempt++)
            {
                buffer = Marshal.AllocHGlobal(length);
                status = NtQuerySystemInformation(SystemModuleInformation, buffer, length, out int needed);

                if (status == 0) break;

                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;

                if (status != unchecked((int)0xC0000004) || needed <= 0)
                {
                    error = $"NtQuerySystemInformation(SystemModuleInformation) 失败: 0x{status:X8}";
                    return list;
                }

                length = needed + (1 << 16);
            }

            if (buffer == IntPtr.Zero)
            {
                error = "无法分配模块信息缓冲区";
                return list;
            }

            int moduleCount = Marshal.ReadInt32(buffer);

            // RTL_PROCESS_MODULE_INFORMATION (x64) 布局：
            //   Section@0 MappedBase@8 ImageBase@16 ImageSize@24 Flags@28
            //   LoadOrderIndex@32 InitOrderIndex@34 LoadCount@36 OffsetToFileName@38
            //   FullPathName[256]@40  → 结构体步长 296（不是 152，早期写错导致路径被截断）
            const int ModuleStride = 296;
            const int PathOffset = 40;

            for (int i = 0; i < moduleCount; i++)
            {
                IntPtr entry = buffer + 8 + i * ModuleStride;

                long imageBase = Marshal.ReadIntPtr(entry, 16).ToInt64();
                uint imageSize = (uint)Marshal.ReadInt32(entry, 24);
                ushort offsetToFileName = (ushort)Marshal.ReadInt16(entry, 38);

                byte[] nameBuffer = new byte[256];
                Marshal.Copy(entry + PathOffset, nameBuffer, 0, 256);

                string fullPath = Encoding.ASCII.GetString(nameBuffer).TrimEnd('\0');
                if (string.IsNullOrEmpty(fullPath)) continue;

                string name = offsetToFileName < fullPath.Length ? fullPath[offsetToFileName..] : Path.GetFileName(fullPath);
                if (name.Contains('\0')) name = name[..name.IndexOf('\0')];

                list.Add(new LoadedModule(name, fullPath, imageBase, imageSize));
            }

            return list;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return list;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>\SystemRoot\System32\drivers\xxx.sys → C:\Windows\System32\drivers\xxx.sys</summary>
    public static string ToWin32Path(string ntPath)
    {
        if (ntPath.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return Path.Combine(win, ntPath.Substring(@"\SystemRoot\".Length));
        }

        if (ntPath.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            return ntPath[4..];
        }

        if (ntPath.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            return ntPath;   // 无法映射到 Win32 路径
        }

        return ntPath;
    }
}