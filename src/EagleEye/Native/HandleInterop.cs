using System.Runtime.InteropServices;

namespace EagleEye.Native;

/// <summary>
/// 系统句柄表枚举（只读）。
/// 用途：找出"谁以 VM_READ / VM_WRITE / CREATE_THREAD 打开了某个进程"。
/// 做法：NtQuerySystemInformation(SystemExtendedHandleInformation) 拿句柄表 →
///       对高权限句柄 DuplicateHandle 到自己进程 → GetProcessId 得到目标 PID。
/// 不读取目标进程内存、不拦截、不修改任何对象。
/// </summary>
internal static class HandleInterop
{
    private const int SystemExtendedHandleInformation = 64;

    private const uint ProcessDuplicateHandle = 0x0040;
    private const uint DuplicateSameAccess = 0x00000002;

    private const uint AccessVmOperation = 0x0008;
    private const uint AccessVmRead = 0x0010;
    private const uint AccessVmWrite = 0x0020;
    private const uint AccessCreateThread = 0x0002;

    public const uint HighAccessMask = AccessVmOperation | AccessVmRead | AccessVmWrite | AccessCreateThread;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int systemInformationClass, IntPtr systemInformation, int systemInformationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle,
        out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(IntPtr Process);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    public readonly record struct RawHandle(int HolderPid, IntPtr HandleValue, uint GrantedAccess, ushort TypeIndex);
    public readonly record struct TargetRef(int HolderPid, int TargetPid, uint GrantedAccess);

    public static List<TargetRef> FindProcessHandles(out int totalHandles, out int highAccessHandles, out string? error)
    {
        totalHandles = 0;
        highAccessHandles = 0;
        error = null;
        var results = new List<TargetRef>();

        IntPtr buffer = IntPtr.Zero;
        IntPtr probe = OpenProcess(ProcessDuplicateHandle, false, Environment.ProcessId);
        try
        {
            int length = 1 << 20;
            int status;
            for (int attempt = 0; attempt < 6; attempt++)
            {
                buffer = Marshal.AllocHGlobal(length);
                status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, length, out int needed);

                if (status == 0)
                {
                    break;
                }

                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;

                // STATUS_INFO_LENGTH_MISMATCH
                if (status != unchecked((int)0xC0000004) || needed <= 0)
                {
                    error = $"NtQuerySystemInformation 失败: 0x{status:X8}";
                    return results;
                }

                length = needed + (1 << 20);
            }

            if (buffer == IntPtr.Zero)
            {
                error = "无法分配句柄表缓冲区";
                return results;
            }

            long count = Marshal.ReadIntPtr(buffer, 0).ToInt64();
            totalHandles = (int)Math.Min(count, int.MaxValue);

            ushort processTypeIndex = ResolveProcessTypeIndex(buffer, count, probe);
            if (processTypeIndex == ushort.MaxValue)
            {
                error = "无法解析 Process 对象的类型索引";
                return results;
            }

            var holderHandles = new Dictionary<int, IntPtr>();
            IntPtr self = GetCurrentProcess();

            for (long i = 0; i < count; i++)
            {
                IntPtr entry = buffer + 16 + (int)(i * 40);

                IntPtr handleValue = Marshal.ReadIntPtr(entry, 16);
                uint grantedAccess = (uint)Marshal.ReadInt32(entry, 24);
                ushort typeIndex = (ushort)Marshal.ReadInt16(entry, 30);
                int holderPid = (int)Marshal.ReadIntPtr(entry, 8).ToInt64();

                if (typeIndex != processTypeIndex) continue;
                if ((grantedAccess & HighAccessMask) == 0) continue;
                if (holderPid <= 4) continue;

                highAccessHandles++;

                if (!holderHandles.TryGetValue(holderPid, out IntPtr holder))
                {
                    holder = OpenProcess(ProcessDuplicateHandle, false, holderPid);
                    holderHandles[holderPid] = holder;
                    if (holder != IntPtr.Zero) { }
                }

                if (holder == IntPtr.Zero) continue;

                if (!DuplicateHandle(holder, handleValue, self, out IntPtr dup, 0, false, DuplicateSameAccess))
                {
                    continue;
                }

                try
                {
                    uint targetPid = GetProcessId(dup);
                    if (targetPid > 4 && targetPid != holderPid)
                    {
                        results.Add(new TargetRef(holderPid, (int)targetPid, grantedAccess));
                    }
                }
                finally
                {
                    CloseHandle(dup);
                }
            }

            foreach (var kv in holderHandles)
            {
                if (kv.Value != IntPtr.Zero) CloseHandle(kv.Value);
            }

            return results;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return results;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (probe != IntPtr.Zero) CloseHandle(probe);
        }
    }

    /// <summary>用自己进程的一个已知 Process 句柄反查类型索引。</summary>
    private static ushort ResolveProcessTypeIndex(IntPtr buffer, long count, IntPtr probe)
    {
        int selfPid = Environment.ProcessId;

        if (probe == IntPtr.Zero)
        {
            return ushort.MaxValue;
        }

        try
        {
            for (long i = 0; i < count; i++)
            {
                IntPtr entry = buffer + 16 + (int)(i * 40);
                int holderPid = (int)Marshal.ReadIntPtr(entry, 8).ToInt64();
                if (holderPid != selfPid) continue;

                IntPtr handleValue = Marshal.ReadIntPtr(entry, 16);
                if (handleValue.ToInt64() == probe.ToInt64())
                {
                    return (ushort)Marshal.ReadInt16(entry, 30);
                }
            }

            return ushort.MaxValue;
        }
        catch
        {
            return ushort.MaxValue;
        }
    }

    public static string DescribeAccess(uint access)
    {
        var parts = new List<string>();
        if ((access & AccessVmOperation) != 0) parts.Add("VM_OPERATION");
        if ((access & AccessVmRead) != 0) parts.Add("VM_READ");
        if ((access & AccessVmWrite) != 0) parts.Add("VM_WRITE");
        if ((access & AccessCreateThread) != 0) parts.Add("CREATE_THREAD");
        return parts.Count == 0 ? $"0x{access:X}" : string.Join("|", parts) + $" (0x{access:X})";
    }
}