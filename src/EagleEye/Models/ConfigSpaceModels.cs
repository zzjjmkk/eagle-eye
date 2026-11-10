using EagleEye.Kernel;

namespace EagleEye.Models;

/// <summary>
/// 由内核 IOCTL 返回的真实 PCIe 配置空间解析结果。
/// 与用户态近似值不同：这里的 VID/DID/Revision/ClassCode/Subsystem/Capability 都是硬件真值，
/// 但 BAR 只有原始寄存器值 —— 确定 BAR 大小需要写 0xFFFFFFFF 回读，本工具禁止写配置空间。
/// </summary>
public sealed class ConfigSpaceInfo
{
    public ushort VendorId { get; set; }
    public ushort DeviceId { get; set; }
    public ushort SubsystemVendorId { get; set; }
    public ushort SubsystemId { get; set; }
    public byte RevisionId { get; set; }
    public byte BaseClass { get; set; }
    public byte SubClass { get; set; }
    public byte ProgIf { get; set; }
    public byte HeaderType { get; set; }
    public byte[] BarRaw { get; set; } = Array.Empty<uint>().Select(_ => (byte)0).ToArray();
    public uint[] Bars { get; set; } = new uint[6];
    public string[] BarKinds { get; set; } = new string[6];
    public byte[] CapabilityIds { get; set; } = Array.Empty<byte>();
    public bool HasMsi { get; set; }
    public bool HasMsiX { get; set; }
    public ushort MsiControl { get; set; }
    public byte CapabilityListOffset { get; set; }
    /// <summary>恒为 false：只读实现无法确定 BAR 大小。</summary>
    public bool BarSizeDeterminable { get; set; }
    /// <summary>原始配置空间前 64 字节的十六进制串，作为证据留痕。</summary>
    public string RawHex { get; set; } = "";

    public string ClassCodeHex => $"{BaseClass:X2}{SubClass:X2}";

    public static ConfigSpaceInfo From(PcieCfgIoctl.PcieCfgResult raw)
    {
        var info = new ConfigSpaceInfo
        {
            VendorId = (ushort)(raw.Ids & 0xFFFF),
            DeviceId = (ushort)(raw.Ids >> 16),
            SubsystemVendorId = (ushort)(raw.Subsystem & 0xFFFF),
            SubsystemId = (ushort)(raw.Subsystem >> 16),
            BaseClass = (byte)(raw.ClassInfo >> 24),
            SubClass = (byte)(raw.ClassInfo >> 16),
            ProgIf = (byte)(raw.ClassInfo >> 8),
            RevisionId = (byte)raw.ClassInfo,
            HeaderType = (byte)(raw.HeaderType & 0x7F),
            HasMsi = raw.HasMsi != 0,
            HasMsiX = raw.HasMsix != 0,
            MsiControl = (ushort)raw.MsiControl,
            CapabilityListOffset = raw.CapabilityListOffset,
            BarSizeDeterminable = false
        };

        info.Bars = raw.Bar ?? new uint[6];
        info.CapabilityIds = (raw.CapIds ?? Array.Empty<byte>()).Take((int)Math.Min(raw.CapCount, 48)).ToArray();

        for (int i = 0; i < 6; i++)
        {
            uint bar = info.Bars[i];
            uint flags = raw.BarFlags is null ? 0 : raw.BarFlags[i];

            if ((flags & 0x8) == 0)
            {
                info.BarKinds[i] = "none";
            }
            else if ((flags & 0x1) != 0)
            {
                info.BarKinds[i] = "io";
            }
            else if ((flags & 0x2) != 0)
            {
                info.BarKinds[i] = "mem64";
            }
            else
            {
                info.BarKinds[i] = "mem32";
            }
        }

        if (raw.Raw is not null)
        {
            int take = Math.Min(64, raw.Raw.Length);
            info.RawHex = Convert.ToHexString(raw.Raw, 0, take).ToLowerInvariant();
        }

        return info;
    }
}

/// <summary>内核配置空间读取的总体结果（含装载/卸载状态，便于审计）。</summary>
public sealed class ConfigSpaceReadResult
{
    public bool Attempted { get; set; }
    public bool Loaded { get; set; }
    public bool Unloaded { get; set; }
    public string? DriverPath { get; set; }
    public string? Error { get; set; }
    public int DevicesAttempted { get; set; }
    public int DevicesRead { get; set; }
    public List<string> Errors { get; set; } = new();
}