using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EagleEye.Kernel;

/// <summary>
/// 与 PcieCfg.sys 的 IOCTL 契约。结构体布局必须与驱动里的 PCIECFG_REQUEST / PCIECFG_RESULT 完全一致。
/// </summary>
public static class PcieCfgIoctl
{
    /// <summary>CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_READ_DATA)</summary>
    public const uint IoctlPing = 0x80002001;

    /// <summary>CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_READ_DATA)</summary>
    public const uint IoctlReadConfig = 0x80002005;

    public const int MaxPath = 260;
    public const int ConfigLength = 256;
    public const int MaxCapabilities = 48;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PcieCfgRequest
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MaxPath)]
        public string PdoPath;

        public uint Offset;
        public uint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PcieCfgResult
    {
        public uint Status;
        public uint Ids;
        public uint Subsystem;
        public uint ClassInfo;
        public uint HeaderType;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public uint[] Bar;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public uint[] BarFlags;

        public uint CapCount;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxCapabilities)]
        public byte[] CapIds;

        public byte HasMsi;
        public byte HasMsix;
        public byte CapabilityListOffset;
        public byte Reserved0;
        public uint MsiControl;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = ConfigLength)]
        public byte[] Raw;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    public static bool TryPing(SafeFileHandle device, out uint version, out string? error)
    {
        version = 0;
        error = null;

        IntPtr outBuffer = Marshal.AllocHGlobal(sizeof(uint));
        try
        {
            if (!DeviceIoControl(device, IoctlPing, IntPtr.Zero, 0, outBuffer, sizeof(uint), out uint returned, IntPtr.Zero) || returned < sizeof(uint))
            {
                error = $"IOCTL_PCIECFG_PING 失败（Win32={Marshal.GetLastWin32Error()}）";
                return false;
            }

            version = (uint)Marshal.ReadInt32(outBuffer);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(outBuffer);
        }
    }

    public static bool TryReadConfig(SafeFileHandle device, string pdoPath, out PcieCfgResult result, out string? error)
    {
        result = default;
        error = null;

        var request = new PcieCfgRequest { PdoPath = pdoPath, Offset = 0, Length = ConfigLength };
        int inSize = Marshal.SizeOf<PcieCfgRequest>();
        int outSize = Marshal.SizeOf<PcieCfgResult>();

        IntPtr inBuffer = Marshal.AllocHGlobal(inSize);
        IntPtr outBuffer = Marshal.AllocHGlobal(outSize);

        try
        {
            Marshal.StructureToPtr(request, inBuffer, false);
            RtlZeroMemory(outBuffer, outSize);

            bool ok = DeviceIoControl(device, IoctlReadConfig, inBuffer, (uint)inSize, outBuffer, (uint)outSize, out uint returned, IntPtr.Zero);

            if (!ok)
            {
                error = $"IOCTL_PCIECFG_READ_CONFIG 失败（Win32={Marshal.GetLastWin32Error()}）";
                return false;
            }

            if (returned < outSize)
            {
                error = $"驱动返回长度不足（{returned}/{outSize}）";
                return false;
            }

            result = Marshal.PtrToStructure<PcieCfgResult>(outBuffer)!;
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(inBuffer);
            Marshal.FreeHGlobal(outBuffer);
        }
    }

    private static void RtlZeroMemory(IntPtr buffer, int size)
    {
        byte[] zeros = new byte[size];
        Marshal.Copy(zeros, 0, buffer, size);
    }
}