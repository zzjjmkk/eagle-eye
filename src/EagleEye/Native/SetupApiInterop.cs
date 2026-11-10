using System.Runtime.InteropServices;
using System.Text;

namespace EagleEye.Native;

/// <summary>
/// 用户态设备枚举：SetupAPI + CfgMgr32。
///
/// 只读约束（重要）：
/// 1. 只调用 SetupDiGetClassDevs / SetupDiEnumDeviceInfo / CM_Get_Device_ID / CM_Get_DevNode_Registry_Property /
///    CM_Get_DevNode_Status 这几个查询接口，不改设备状态、不改注册表、不打开设备句柄。
/// 2. 不访问 IOMMU、不读写 PCIe 配置空间（用户态本来也做不到）。
/// 3. 因此本模块拿到的 VID/PID/REV 来自设备实例 ID 字符串，Class 来自设备类名，
///    并不是配置空间真实值；ClassCode 只能"近似推导"。
/// </summary>
internal static class SetupApiInterop
{
    private const uint DIGCF_PRESENT = 0x00000002;
    private const uint DIGCF_ALLCLASSES = 0x00000004;

    private const int CR_SUCCESS = 0;
    private const int CR_BUFFER_SMALL = 0x1A;

    // CM_DRP_* —— cfg.h
    private const uint CM_DRP_DEVICEDESC = 0x01;
    private const uint CM_DRP_HARDWAREID = 0x02;
    private const uint CM_DRP_SERVICE = 0x05;   // cfg.h: 0x04 是 UNUSED4，SERVICE 是 0x05
    private const uint CM_DRP_CLASS = 0x08;
    private const uint CM_DRP_CLASSGUID = 0x09;
    private const uint CM_DRP_MFG = 0x0C;
    private const uint CM_DRP_FRIENDLYNAME = 0x0D;
    private const uint CM_DRP_LOCATION_INFORMATION = 0x0E;
    private const uint CM_DRP_PHYSICAL_DEVICE_OBJECT_NAME = 0x0F;

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVINFO_DATA
    {
        public uint cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevsW(IntPtr classGuid, string? enumerator, IntPtr hwndParent, uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiEnumDeviceInfo(IntPtr deviceInfoSet, uint memberIndex, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern int CM_Get_Device_IDW(uint devInst, StringBuilder buffer, int bufferLen, int flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern int CM_Get_DevNode_Registry_PropertyW(
        uint devInst, uint property, out uint regDataType, byte[]? buffer, ref uint length, uint flags);

    [DllImport("cfgmgr32.dll")]
    private static extern int CM_Get_DevNode_Status(out uint status, out uint problemNumber, uint devInst, uint flags);

    public sealed class RawDevice
    {
        public string InstanceId { get; set; } = "";
        public string? DeviceDesc { get; set; }
        public string? FriendlyName { get; set; }
        public string? ClassName { get; set; }
        public string? ClassGuid { get; set; }
        public string? Service { get; set; }
        public string? Location { get; set; }
        public string? Manufacturer { get; set; }
        public string? HardwareIds { get; set; }
        /// <summary>PDO 设备对象名，如 \Device\NTPNP_PCI0007</summary>
        public string? PdoName { get; set; }
        public uint? ProblemCode { get; set; }
    }

    /// <summary>枚举当前存在的所有设备，调用方自行按实例 ID 前缀过滤 PCI。</summary>
    public static List<RawDevice> EnumeratePresentDevices(out string? error)
    {
        error = null;
        var list = new List<RawDevice>();

        IntPtr deviceInfoSet = SetupDiGetClassDevsW(IntPtr.Zero, null, IntPtr.Zero, DIGCF_PRESENT | DIGCF_ALLCLASSES);
        if (deviceInfoSet == IntPtr.Zero || deviceInfoSet == new IntPtr(-1))
        {
            error = $"SetupDiGetClassDevs 失败（Win32={Marshal.GetLastWin32Error()}）";
            return list;
        }

        try
        {
            var info = new SP_DEVINFO_DATA { cbSize = (uint)Marshal.SizeOf<SP_DEVINFO_DATA>() };

            for (uint index = 0; ; index++)
            {
                info.cbSize = (uint)Marshal.SizeOf<SP_DEVINFO_DATA>();
                if (!SetupDiEnumDeviceInfo(deviceInfoSet, index, ref info))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err != 259) // ERROR_NO_MORE_ITEMS
                    {
                        error = $"SetupDiEnumDeviceInfo 在第 {index} 项失败（Win32={err}）";
                    }
                    break;
                }

                string? instanceId = GetInstanceId(info.DevInst);
                if (string.IsNullOrEmpty(instanceId))
                {
                    continue;
                }

                var device = new RawDevice
                {
                    InstanceId = instanceId!,
                    DeviceDesc = ReadString(info.DevInst, CM_DRP_DEVICEDESC),
                    FriendlyName = ReadString(info.DevInst, CM_DRP_FRIENDLYNAME),
                    ClassName = ReadString(info.DevInst, CM_DRP_CLASS),
                    ClassGuid = ReadString(info.DevInst, CM_DRP_CLASSGUID),
                    Service = ReadString(info.DevInst, CM_DRP_SERVICE),
                    Location = ReadString(info.DevInst, CM_DRP_LOCATION_INFORMATION),
                    Manufacturer = ReadString(info.DevInst, CM_DRP_MFG),
                    HardwareIds = ReadMultiString(info.DevInst, CM_DRP_HARDWAREID),
                    PdoName = ReadString(info.DevInst, CM_DRP_PHYSICAL_DEVICE_OBJECT_NAME)
                };

                if (CM_Get_DevNode_Status(out _, out uint problem, info.DevInst, 0) == CR_SUCCESS)
                {
                    device.ProblemCode = problem;
                }

                list.Add(device);
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(deviceInfoSet);
        }

        return list;
    }

    private static string? GetInstanceId(uint devInst)
    {
        var sb = new StringBuilder(512);
        return CM_Get_Device_IDW(devInst, sb, sb.Capacity, 0) == CR_SUCCESS ? sb.ToString() : null;
    }

    private static string? ReadString(uint devInst, uint property)
    {
        uint type;
        uint length = 0;

        int cr = CM_Get_DevNode_Registry_PropertyW(devInst, property, out type, null, ref length, 0);
        if (cr != CR_BUFFER_SMALL || length == 0)
        {
            return null;
        }

        var buffer = new byte[length];
        cr = CM_Get_DevNode_Registry_PropertyW(devInst, property, out type, buffer, ref length, 0);
        if (cr != CR_SUCCESS)
        {
            return null;
        }

        string value = Encoding.Unicode.GetString(buffer, 0, (int)length).TrimEnd('\0');
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static string? ReadMultiString(uint devInst, uint property)
    {
        string? raw = ReadString(devInst, property);
        return raw;
    }
}