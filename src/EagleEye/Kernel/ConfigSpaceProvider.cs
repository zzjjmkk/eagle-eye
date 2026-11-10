using EagleEye.Models;

namespace EagleEye.Kernel;

/// <summary>
/// 一次性读取流程：装载驱动 → 逐设备 IOCTL → 立即停止并删除服务。
/// 卸载放在 finally，任何异常都不会留下驱动服务。
/// </summary>
public static class ConfigSpaceProvider
{
    public static ConfigSpaceReadResult ReadAll(
        List<DmaDeviceInfo> devices,
        string driverPath,
        string serviceName,
        string devicePath)
    {
        var result = new ConfigSpaceReadResult { Attempted = true, DriverPath = driverPath };
        var host = new PcieCfgDriverHost(serviceName, devicePath);
        Microsoft.Win32.SafeHandles.SafeFileHandle? device = null;

        try
        {
            if (!host.EnsureLoaded(driverPath, out string? loadError))
            {
                result.Error = loadError;
                return result;
            }

            result.Loaded = true;

            device = host.OpenDevice(out string? openError);
            if (device is null)
            {
                result.Error = openError;
                return result;
            }

            if (!PcieCfgIoctl.TryPing(device, out uint version, out string? pingError))
            {
                result.Error = pingError;
                return result;
            }

            if (version != 1)
            {
                result.Error = $"驱动协议版本不匹配（驱动 {version}，客户端 1）";
                return result;
            }

            foreach (var info in devices)
            {
                if (string.IsNullOrWhiteSpace(info.PdoName))
                {
                    result.Errors.Add($"{info.Name}: 缺少 PDO 名称，跳过");
                    continue;
                }

                result.DevicesAttempted++;

                if (PcieCfgIoctl.TryReadConfig(device, info.PdoName!, out var raw, out string? readError))
                {
                    if (raw.Status == 0)
                    {
                        info.ConfigSpace = ConfigSpaceInfo.From(raw);
                        result.DevicesRead++;
                    }
                    else
                    {
                        result.Errors.Add($"{info.Name}: 驱动返回 0x{raw.Status:X8}");
                    }
                }
                else
                {
                    result.Errors.Add($"{info.Name}: {readError}");
                }
            }

            return result;
        }
        finally
        {
            device?.Dispose();

            if (result.Loaded)
            {
                result.Unloaded = host.TryUnload(out string? unloadError);
                if (!result.Unloaded && result.Error is null)
                {
                    result.Error = unloadError;
                }
            }
        }
    }
}