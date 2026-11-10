using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EagleEye.Kernel;

/// <summary>
/// 驱动装载/卸载：CreateService(DEMAND_START) → StartService → (调用方读数据) → ControlService(STOP) → DeleteService。
/// 驱动服务名固定，启动类型固定为按需启动，绝不会注册成自启动。
/// </summary>
public sealed class PcieCfgDriverHost
{
    private const uint ScManagerAllAccess = 0xF003F;
    private const uint ServiceAllAccess = 0xF01FF;
    private const uint ServiceKernelDriver = 0x00000001;
    private const uint ServiceDemandStart = 0x00000003;
    private const uint ServiceErrorNormal = 0x00000001;
    private const uint ServiceControlStop = 0x00000001;

    private const uint ServiceStopped = 0x00000001;
    private const uint ServiceRunning = 0x00000004;

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateService(
        IntPtr hSCManager,
        string lpServiceName,
        string? lpDisplayName,
        uint dwDesiredAccess,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string lpBinaryPathName,
        string? lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string? lpDependencies,
        string? lpServiceStartName,
        string? lpPassword);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(IntPtr hService, uint dwNumServiceArgs, IntPtr lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteService(IntPtr hService);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(IntPtr hService, ref SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    public string ServiceName { get; }
    public string DevicePath { get; }

    public PcieCfgDriverHost(string serviceName = "PcieCfg", string devicePath = @"\\.\PcieCfg")
    {
        ServiceName = serviceName;
        DevicePath = devicePath;
    }

    /// <summary>安装并启动驱动。已存在同名服务时先删除（清理上次异常退出的残留）。</summary>
    public bool EnsureLoaded(string driverPath, out string? error)
    {
        error = null;

        if (!File.Exists(driverPath))
        {
            error = $"驱动文件不存在: {driverPath}";
            return false;
        }

        IntPtr scm = OpenSCManager(null, null, ScManagerAllAccess);
        if (scm == IntPtr.Zero)
        {
            error = Win32("OpenSCManager", out _);
            return false;
        }

        try
        {
            // 清理残留
            IntPtr stale = OpenService(scm, ServiceName, ServiceAllAccess);
            if (stale != IntPtr.Zero)
            {
                var staleStatus = default(SERVICE_STATUS);
                ControlService(stale, ServiceControlStop, ref staleStatus);
                DeleteService(stale);
                CloseServiceHandle(stale);
                Thread.Sleep(300);
            }

            IntPtr service = CreateService(
                scm,
                ServiceName,
                ServiceName,
                ServiceAllAccess,
                ServiceKernelDriver,
                ServiceDemandStart,          // 关键：按需启动，绝不设成自启动
                ServiceErrorNormal,
                driverPath,
                null,
                IntPtr.Zero,
                null,
                null,
                null);

            if (service == IntPtr.Zero)
            {
                error = Win32("CreateService", out int code);
                if (code == 5)
                {
                    error += "（需要以管理员身份运行）";
                }
                return false;
            }

            try
            {
                if (!StartService(service, 0, IntPtr.Zero))
                {
                    int startError = Marshal.GetLastWin32Error();
                    // 1056 = 服务已在运行，视为成功
                    if (startError != 1056)
                    {
                        error = $"StartService 失败（Win32={startError} {new Win32Exception(startError).Message}）";
                        if (startError == 577)
                        {
                            error += " —— 驱动签名不被信任：正式使用需 EV 签名 + Microsoft attestation，测试机需 testsigning";
                        }
                        else if (startError == 1275)
                        {
                            error += " —— 驱动被系统策略/HVCI 阻止加载";
                        }

                        DeleteService(service);
                        return false;
                    }
                }

                for (int i = 0; i < 50; i++)
                {
                    var status = default(SERVICE_STATUS);
                    if (QueryServiceStatus(service, ref status) && status.dwCurrentState == ServiceRunning)
                    {
                        return true;
                    }

                    Thread.Sleep(100);
                }

                error = "驱动启动后未进入 RUNNING 状态（超时 5s）";
                return false;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    /// <summary>停止并删除服务。必须放在 finally 里，保证用完即卸。</summary>
    public bool TryUnload(out string? error)
    {
        error = null;

        IntPtr scm = OpenSCManager(null, null, ScManagerAllAccess);
        if (scm == IntPtr.Zero)
        {
            error = Win32("OpenSCManager", out _);
            return false;
        }

        try
        {
            IntPtr service = OpenService(scm, ServiceName, ServiceAllAccess);
            if (service == IntPtr.Zero)
            {
                int code = Marshal.GetLastWin32Error();
                if (code == 1060) // 服务不存在，视为已卸载
                {
                    return true;
                }

                error = Win32("OpenService", out _);
                return false;
            }

            try
            {
                var stopStatus = default(SERVICE_STATUS);
                ControlService(service, ServiceControlStop, ref stopStatus);

                for (int i = 0; i < 50; i++)
                {
                    var status = default(SERVICE_STATUS);
                    if (QueryServiceStatus(service, ref status) && status.dwCurrentState == ServiceStopped)
                    {
                        break;
                    }

                    Thread.Sleep(100);
                }

                if (!DeleteService(service))
                {
                    int code = Marshal.GetLastWin32Error();
                    if (code != 1072) // ERROR_SERVICE_MARKED_FOR_DELETE
                    {
                        error = Win32("DeleteService", out _);
                        return false;
                    }
                }

                return true;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    public SafeFileHandle? OpenDevice(out string? error)
    {
        const uint genericRead = 0x80000000;
        const uint shareReadWrite = 0x00000003;
        const uint openExisting = 3;
        const uint fileAttributeNormal = 0x80;

        SafeFileHandle handle = CreateFileW(DevicePath, genericRead, shareReadWrite, IntPtr.Zero, openExisting, fileAttributeNormal, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int code = Marshal.GetLastWin32Error();
            handle.Dispose();
            error = $"打开设备 {DevicePath} 失败（Win32={code} {new Win32Exception(code).Message}）";
            return null;
        }

        error = null;
        return handle;
    }

    private static string Win32(string api, out int code)
    {
        code = Marshal.GetLastWin32Error();
        return $"{api} 失败（Win32={code} {new Win32Exception(code).Message}）";
    }
}