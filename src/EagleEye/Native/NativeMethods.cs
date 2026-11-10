using System.Runtime.InteropServices;
using System.Text;

namespace EagleEye.Native;

/// <summary>
/// 只用到的 Win32 / NT 原生接口集合。
/// 设计约束：只用只读、最小权限接口；不包含任何内存写入、注入、Hook 相关 API。
/// </summary>
internal static class NativeMethods
{
    // ---- 进程访问权限（只请求查询权限，绝不请求 VM_READ / VM_WRITE / VM_OPERATION）----
    public const uint ProcessQueryLimitedInformation = 0x1000;
    public const uint ProcessQueryInformation = 0x0400;

    // ---- Toolhelp 快照 ----
    public const uint TH32CS_SNAPPROCESS = 0x00000002;
    public const uint TH32CS_SNAPMODULE = 0x00000008;
    public const uint TH32CS_SNAPMODULE32 = 0x00000010;

    public static readonly IntPtr InvalidHandleValue = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MODULEENTRY32W
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32FirstW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32NextW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Module32FirstW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Module32NextW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref int lpdwSize);

    // ---- 命令行：走内核信息类查询（ProcessCommandLineInformation），不做内存读取 ----
    private const int ProcessCommandLineInformation = 60;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        IntPtr processInformation,
        int processInformationLength,
        out int returnLength);

    public static string? TryGetImagePath(IntPtr hProcess)
    {
        var sb = new StringBuilder(1024);
        int size = sb.Capacity;
        if (QueryFullProcessImageName(hProcess, 0, sb, ref size))
        {
            return sb.ToString(0, size);
        }
        return null;
    }

    /// <summary>
    /// 通过 ProcessCommandLineInformation 信息类取命令行。
    /// 需要 PROCESS_QUERY_LIMITED_INFORMATION；不读取目标进程地址空间。
    /// </summary>
    public static string? TryGetCommandLine(IntPtr hProcess)
    {
        int needed = 0;
        // 第一次调用拿所需缓冲区大小，预期返回 STATUS_INFO_LENGTH_MISMATCH / STATUS_BUFFER_TOO_SMALL
        NtQueryInformationProcess(hProcess, ProcessCommandLineInformation, IntPtr.Zero, 0, out needed);
        if (needed <= 0 || needed > 64 * 1024)
        {
            return null;
        }

        IntPtr buffer = Marshal.AllocHGlobal(needed);
        try
        {
            int status = NtQueryInformationProcess(hProcess, ProcessCommandLineInformation, buffer, needed, out _);
            if (status < 0)
            {
                return null;
            }

            // 返回的是 UNICODE_STRING：Length(2) MaximumLength(2) padding Buffer(8)  —— x64 布局
            int length = Marshal.ReadInt16(buffer, 0);
            IntPtr stringPtr = Marshal.ReadIntPtr(buffer, 8);
            if (length <= 0 || stringPtr == IntPtr.Zero)
            {
                return string.Empty;
            }

            return Marshal.PtrToStringUni(stringPtr, length / 2);
        }
        catch
        {
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}