# PcieCfg 驱动构建说明

> 本机（E:\查挂小程序 所在机器）没有 WDK/MSVC，**这个驱动没有在本机编译过**。
> 下面的步骤在装了 WDK 的机器上可直接跑通。

## 1. 环境

| 组件 | 版本 |
|---|---|
| Visual Studio 2022（含 C++ 桌面开发） | 17.x |
| Windows SDK | 10.0.22621 或更新 |
| WDK（Windows Driver Kit） | 10.0.22621 或更新 |
| 目标系统 | Windows 10 / 11 x64 |

## 2. 编译（两种方式任选）

### 方式 A：命令行（推荐，最快）

打开 **"x64 Native Tools Command Prompt for VS 2022"**（管理员），执行：

```bat
cd /d E:\查挂小程序\native\pciecfg

cl /nologo /c /W4 /WX- /O2 /GL /D_AMD64_ /DWIN32=100 /D_WIN64=1 ^
   /I"%WindowsSdkDir%Include\%WindowsSDKVersion%km" ^
   /I"%WindowsSdkDir%Include\%WindowsSDKVersion%shared" ^
   /FoPcieCfg.obj PcieCfg.c

link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /MACHINE:X64 ^
     /OUT:PcieCfg.sys PcieCfg.obj ^
     "%WindowsSdkDir%Lib\%WindowsSDKVersion%km\x64\BufferOverflowFastFailK.lib" ^
     "%WindowsSdkDir%Lib\%WindowsSDKVersion%km\x64\ntoskrnl.lib" ^
     "%WindowsSdkDir%Lib\%WindowsSDKVersion%km\x64\hal.lib" ^
     "%WindowsSdkDir%Lib\%WindowsSDKVersion%km\x64\netio.lib" ^
     "%WindowsSdkDir%Lib\%WindowsSDKVersion%km\x64\ntstrsafe.lib" ^
     "%WindowsSdkDir%Lib\%WindowsSDKVersion%km\x64\wdmsec.lib" ^
     "%WindowsSdkDir%Lib\%WindowsSDKVersion%km\x64\wmilib.lib"
```

关键链接参数：`/DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry`。
若报 `_fltused` 或 CRT 符号缺失，说明误引入了用户态头，检查 include 顺序（只用 `ntifs.h`）。

### 方式 B：VS + WDK 工程

1. 新建 **Empty WDM Driver** 工程（x64）
2. 加入 `PcieCfg.c`
3. 工程属性 → Driver Settings → Target OS Version: Windows 10；Target Platform: Desktop
4. 关闭 **Inf2Cat** 之外的所有自动化（INF 里没有硬件 ID，不需要 PnP 相关校验）
5. Build

## 3. 签名

### 3.1 测试（隔离 VM，仅一次）

```bat
:: 只在测试 VM 上做，且用完立刻回滚
bcdedit /set testsigning on
shutdown /r /t 0
:: 重启后
makecert -r -pe -ss PrivateCertStore -n "CN=LocalTestPcieCfg" PcieCfgTest.cer
signtool sign /v /s PrivateCertStore /n LocalTestPcieCfg /t http://timestamp.digicert.com PcieCfg.sys
```

> ⚠️ 打开 testsigning 属于"修改系统安全配置"，与工具的整体约束冲突。
> 因此这一步只能在**一次性测试虚拟机**里做，绝不写进交付流程。

### 3.2 正式分发

1. EV 代码签名证书（DigiCert / Sectigo 等）
2. 提交 Microsoft Partner Center 做 **attestation signing**（不需要 WHQL 全量测试）
3. `signtool sign /fd sha256 /tr <timestamp> /td sha256 /a PcieCfg.sys`
4. 验证：`signtool verify /kp /v PcieCfg.sys`

**没有正式签名的驱动在开 Secure Boot + HVCI 的机器上根本加载不了**（`StartService` 返回 577），这是硬门槛，绕不过去也不该绕。

## 4. 安装 / 卸载（开发期手动验证用）

```bat
:: 安装（DEMAND_START，不会自启）
sc create PcieCfg type= kernel start= demand binPath= "E:\查挂小程序\native\pciecfg\PcieCfg.sys"
sc start PcieCfg
sc query PcieCfg

:: 卸载
sc stop PcieCfg
sc delete PcieCfg
```

工具本身（`--kernel`）会自动做这四步并在 `finally` 里保证 stop+delete。

## 5. 验证清单

| 检查 | 命令 | 期望 |
|---|---|---|
| 驱动已加载 | `sc query PcieCfg` | `STATE: 4 RUNNING` |
| 设备对象存在 | `WinObj` 查看 `\Device\PcieCfg` | 存在 |
| 符号链接存在 | `\DosDevices\PcieCfg` | 存在 |
| IOCTL 可读 | `EagleEye.exe scan --kernel --no-files` | 报告里 `dma.kernel.devicesRead > 0` |
| 用完已卸载 | `sc query PcieCfg` | `[SC] EnumQueryServicesStatus:OpenService 失败 1060`（服务不存在） |
| 无残留 | `reg query HKLM\SYSTEM\CurrentControlSet\Services\PcieCfg` | 报错（键不存在） |

## 6. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `StartService` 577 | 签名不受信任 | 用正式签名，或（仅 VM）开 testsigning |
| `StartService` 1275 | 驱动被策略/ELAM 阻止 | 检查 HVCI 与黑名单策略 |
| `StartService` 5 | 非管理员 | 用管理员运行 CLI |
| IOCTL 返回 `0xC0000022` | Token 提权检查未通过 | 用"以管理员身份运行"启动 |
| IOCTL 返回 `0xC0000034` | PDO 名称无效 | 检查 `dma.devices[].pdoName` 是否为空 |
| `IoGetDeviceObjectPointer` 失败 | 设备已被移除 | 跳过该设备（代码已处理） |