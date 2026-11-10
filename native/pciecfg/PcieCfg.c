/*++
Module Name:
    PcieCfg.c

Abstract:
    一次性只读 PCIe 配置空间枚举驱动（WDM，最小实现）。

    能力范围（硬性）：
      - 只发送 IRP_MJ_PNP / IRP_MN_READ_CONFIG（PCI_WHICHSPACE_CONFIG）
      - 只输出：VendorId / DeviceId / Revision / ClassCode / Subsystem / Capability 链 / BAR 原始值 / MSI 能力
      - 绝不发送 IRP_MN_WRITE_CONFIG（不写配置空间，因此也不做 BAR size 回读）

    明确禁止（代码中不存在，可 grep 验证）：
      - 内存读写（MmCopyVirtualMemory / 物理内存映射 / MDL 读写别的进程）
      - 进程/线程操作（ZwOpenProcess / KeStackAttachProcess / PsLookupProcessByProcessId）
      - 句柄操作、SSDT/Inline Hook、ObRegisterCallbacks
      - 文件操作（ZwCreateFile / ZwOpenKey 都不需要）、网络操作、提权

    生命周期：
      由用户态 CreateService(DEMAND_START) -> StartService -> IOCTL -> Stop -> DeleteService。
      驱动本身不注册自启动、不常驻做任何后台工作。

Environment:
    Windows 10 / 11 x64，WDK 10.0.22621 及以上。
--*/

#include <ntifs.h>
#include <ntstrsafe.h>

/* PCI_WHICHSPACE_CONFIG 在某些 include 组合下没有定义，兜底一份（值固定为 0） */
#ifndef PCI_WHICHSPACE_CONFIG
#define PCI_WHICHSPACE_CONFIG 0x00000000
#endif

#define PCIECFG_DEVICE_NAME      L"\\Device\\PcieCfg"
#define PCIECFG_SYMLINK_NAME     L"\\DosDevices\\PcieCfg"
#define PCIECFG_POOL_TAG         'gfCP'
#define PCIECFG_PROTOCOL_VERSION 1

#define PCIECFG_MAX_PATH   260
#define PCIECFG_CONFIG_LEN 256
#define PCIECFG_MAX_CAPS   48

#define PCIECFG_DEVICE_TYPE 0x8000
#define IOCTL_PCIECFG_PING \
    CTL_CODE(PCIECFG_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_PCIECFG_READ_CONFIG \
    CTL_CODE(PCIECFG_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

/* 与 C# 端 PcieCfgRequest 一一对应：WCHAR[260] + ULONG + ULONG = 528 字节 */
typedef struct _PCIECFG_REQUEST
{
    WCHAR PdoPath[PCIECFG_MAX_PATH];
    ULONG Offset;
    ULONG Length;
} PCIECFG_REQUEST, *PPCIECFG_REQUEST;

/* 与 C# 端 PcieCfgResult 一一对应。全部字段按 4 字节对齐，避免结构体填充差异 */
typedef struct _PCIECFG_RESULT
{
    ULONG Status;                                  /* NTSTATUS 原值 */
    ULONG Ids;                                     /* VendorId | DeviceId << 16 */
    ULONG Subsystem;                               /* SubsystemVendorId | SubsystemId << 16 */
    ULONG ClassInfo;                               /* BaseClass<<24 | SubClass<<16 | ProgIf<<8 | Revision */
    ULONG HeaderType;                              /* bit0-6 = header type, bit8 = multifunction */
    ULONG Bar[6];                                  /* BAR0-5 原始值（只读，未做 size 回读） */
    ULONG BarFlags[6];                             /* bit0 IO / bit1 64bit / bit2 prefetch / bit3 非零 */
    ULONG CapCount;
    UCHAR CapIds[PCIECFG_MAX_CAPS];                /* Capability ID 链表 */
    UCHAR HasMsi;
    UCHAR HasMsix;
    UCHAR CapabilityListOffset;
    UCHAR Reserved0;
    ULONG MsiControl;                              /* MSI capability 的 Message Control 字 */
    UCHAR Raw[PCIECFG_CONFIG_LEN];                 /* 原始配置空间前 256 字节，作为证据 */
} PCIECFG_RESULT, *PPCIECFG_RESULT;

typedef struct _PCIECFG_WAIT_CONTEXT
{
    KEVENT Event;
    IO_STATUS_BLOCK Iosb;
} PCIECFG_WAIT_CONTEXT, *PPCIECFG_WAIT_CONTEXT;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD PcieCfgUnload;
DRIVER_DISPATCH PcieCfgCreateClose;
DRIVER_DISPATCH PcieCfgDeviceControl;

static NTSTATUS PcieCfgCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_reads_opt_(_Inexpressible_("varies")) PVOID Context)
{
    PPCIECFG_WAIT_CONTEXT wait = (PPCIECFG_WAIT_CONTEXT)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    wait->Iosb = Irp->IoStatus;
    KeSetEvent(&wait->Event, IO_NO_INCREMENT, FALSE);

    /* 自己回收 IRP，避免泄漏 */
    IoFreeIrp(Irp);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/*++
    只读：向 PDO 发送 IRP_MN_READ_CONFIG。
    绝不发送 IRP_MN_WRITE_CONFIG。
--*/
static NTSTATUS PcieCfgReadConfigSpace(
    _In_ PDEVICE_OBJECT Pdo,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    PCIECFG_WAIT_CONTEXT wait;
    PIRP irp;
    PIO_STACK_LOCATION stack;
    NTSTATUS status;

    KeInitializeEvent(&wait.Event, NotificationEvent, FALSE);
    RtlZeroMemory(&wait.Iosb, sizeof(wait.Iosb));

    irp = IoAllocateIrp(Pdo->StackSize, FALSE);
    if (irp == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    stack = IoGetNextIrpStackLocation(irp);
    stack->MajorFunction = IRP_MJ_PNP;
    stack->MinorFunction = IRP_MN_READ_CONFIG;
    stack->Parameters.ReadWriteConfig.WhichSpace = PCI_WHICHSPACE_CONFIG;
    stack->Parameters.ReadWriteConfig.Buffer = Buffer;
    stack->Parameters.ReadWriteConfig.Offset = Offset;
    stack->Parameters.ReadWriteConfig.Length = Length;

    IoSetCompletionRoutine(irp, PcieCfgCompletion, &wait, TRUE, TRUE, TRUE);

    status = IoCallDriver(Pdo, irp);
    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&wait.Event, Executive, KernelMode, FALSE, NULL);
        status = wait.Iosb.Status;
    }

    return status;
}

static UCHAR PcieCfgReadU8(_In_reads_bytes_(PCIECFG_CONFIG_LEN) const UCHAR* Config, _In_ ULONG Offset)
{
    return Config[Offset];
}

static USHORT PcieCfgReadU16(_In_reads_bytes_(PCIECFG_CONFIG_LEN) const UCHAR* Config, _In_ ULONG Offset)
{
    USHORT value;
    RtlCopyMemory(&value, Config + Offset, sizeof(value));
    return value;
}

static ULONG PcieCfgReadU32(_In_reads_bytes_(PCIECFG_CONFIG_LEN) const UCHAR* Config, _In_ ULONG Offset)
{
    ULONG value;
    RtlCopyMemory(&value, Config + Offset, sizeof(value));
    return value;
}

static VOID PcieCfgParseConfig(
    _In_reads_bytes_(PCIECFG_CONFIG_LEN) const UCHAR* Config,
    _Out_ PPCIECFG_RESULT Result)
{
    ULONG index;
    USHORT vendorId;
    USHORT deviceId;
    USHORT status;
    USHORT subsystemId;
    USHORT subsystemVendorId;
    UCHAR headerType;
    UCHAR baseClass;
    UCHAR subClass;
    UCHAR progIf;
    UCHAR revision;

    vendorId = PcieCfgReadU16(Config, 0x00);
    deviceId = PcieCfgReadU16(Config, 0x02);
    status = PcieCfgReadU16(Config, 0x06);
    revision = PcieCfgReadU8(Config, 0x08);
    progIf = PcieCfgReadU8(Config, 0x09);
    subClass = PcieCfgReadU8(Config, 0x0A);
    baseClass = PcieCfgReadU8(Config, 0x0B);
    headerType = PcieCfgReadU8(Config, 0x0E);
    subsystemVendorId = PcieCfgReadU16(Config, 0x2C);
    subsystemId = PcieCfgReadU16(Config, 0x2E);

    Result->Ids = (ULONG)vendorId | ((ULONG)deviceId << 16);
    Result->Subsystem = (ULONG)subsystemVendorId | ((ULONG)subsystemId << 16);
    Result->ClassInfo = ((ULONG)baseClass << 24) | ((ULONG)subClass << 16) | ((ULONG)progIf << 8) | revision;
    Result->HeaderType = (ULONG)(headerType & 0x7F) | ((headerType & 0x80) ? 0x100UL : 0UL);

    /* BAR：只读原值，不解码大小（确定大小必须写 0xFFFFFFFF 回读，本驱动禁止写） */
    for (index = 0; index < 6; index++)
    {
        ULONG bar = PcieCfgReadU32(Config, 0x10 + index * 4);
        ULONG flags = 0;

        Result->Bar[index] = bar;

        if (bar != 0)
        {
            flags |= 0x8; /* 非零，存在 */
        }

        if ((bar & 0x1) != 0)
        {
            flags |= 0x1; /* IO 空间 */
        }
        else
        {
            if ((bar & 0x6) == 0x4)
            {
                flags |= 0x2; /* 64 位 */
            }
            if ((bar & 0x8) != 0)
            {
                flags |= 0x4; /* 可预取 */
            }
        }

        Result->BarFlags[index] = flags;
    }

    /* Capability 链：只有 header type 0 且有 Capabilities List 位时才有 */
    if ((headerType & 0x7F) == 0 && (status & 0x0010) != 0)
    {
        ULONG pointer = (ULONG)(PcieCfgReadU8(Config, 0x34) & 0xFC);
        ULONG guard = 0;

        Result->CapabilityListOffset = (UCHAR)pointer;

        while (pointer >= 0x40 && pointer <= 0xFC && Result->CapCount < PCIECFG_MAX_CAPS)
        {
            UCHAR capId = PcieCfgReadU8(Config, pointer);
            UCHAR next = (UCHAR)(PcieCfgReadU8(Config, pointer + 1) & 0xFC);

            Result->CapIds[Result->CapCount] = capId;
            Result->CapCount++;

            if (capId == 0x05) /* MSI */
            {
                Result->HasMsi = 1;
                Result->MsiControl = PcieCfgReadU16(Config, pointer + 2);
            }
            else if (capId == 0x11) /* MSI-X */
            {
                Result->HasMsix = 1;
            }

            if (next == 0 || next <= pointer || ++guard > PCIECFG_MAX_CAPS)
            {
                break;
            }

            pointer = next;
        }
    }
}

static BOOLEAN PcieCfgCallerIsElevated(VOID)
{
    PACCESS_TOKEN token;
    PVOID info = NULL;
    BOOLEAN elevated = FALSE;
    NTSTATUS status;

    token = PsReferencePrimaryToken(PsGetCurrentProcess());
    if (token == NULL)
    {
        return FALSE;
    }

    status = SeQueryInformationToken(token, TokenElevation, &info);
    ObDereferenceObject(token);

    if (NT_SUCCESS(status) && info != NULL)
    {
        elevated = (((PTOKEN_ELEVATION)info)->TokenIsElevated != 0);
        ExFreePool(info);
    }

    return elevated;
}

static NTSTATUS PcieCfgCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS PcieCfgDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    ULONG ioControlCode;
    ULONG inputLength;
    ULONG outputLength;
    PVOID systemBuffer;
    PPCIECFG_REQUEST request;
    PPCIECFG_RESULT result;
    UNICODE_STRING pdoName;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT pdo = NULL;
    UCHAR configSpace[PCIECFG_CONFIG_LEN];
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG information = 0;
    ULONG pathIndex;
    BOOLEAN pathTerminated;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    /* 只允许管理员调用，避免低权限进程借用本驱动读硬件 */
    if (!PcieCfgCallerIsElevated())
    {
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    if (ioControlCode == IOCTL_PCIECFG_PING)
    {
        if (systemBuffer != NULL && outputLength >= sizeof(ULONG) && inputLength == 0)
        {
            *(ULONG*)systemBuffer = PCIECFG_PROTOCOL_VERSION;
            status = STATUS_SUCCESS;
            information = sizeof(ULONG);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }

        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = information;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    if (ioControlCode != IOCTL_PCIECFG_READ_CONFIG)
    {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    if (systemBuffer == NULL || inputLength < sizeof(PCIECFG_REQUEST) || outputLength < sizeof(PCIECFG_RESULT))
    {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PPCIECFG_REQUEST)systemBuffer;
    result = (PPCIECFG_RESULT)systemBuffer;

    /* 路径必须自行终止，防止越界读 */
    pathTerminated = FALSE;
    for (pathIndex = 0; pathIndex < PCIECFG_MAX_PATH; pathIndex++)
    {
        if (request->PdoPath[pathIndex] == L'\0')
        {
            pathTerminated = TRUE;
            break;
        }
    }

    if (!pathTerminated || request->PdoPath[0] == L'\0')
    {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    /* 只允许读第一个 256 字节，且 4 字节对齐 */
    if (request->Offset != 0 ||
        request->Length < 4 ||
        request->Length > PCIECFG_CONFIG_LEN ||
        (request->Length & 0x3) != 0)
    {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(configSpace, sizeof(configSpace));
    RtlZeroMemory(result, sizeof(PCIECFG_RESULT));

    RtlInitUnicodeString(&pdoName, request->PdoPath);

    status = IoGetDeviceObjectPointer(&pdoName, FILE_READ_ATTRIBUTES, &fileObject, &pdo);
    if (NT_SUCCESS(status))
    {
        status = PcieCfgReadConfigSpace(pdo, configSpace, 0, request->Length);
        ObDereferenceObject(fileObject);
    }

    result = (PPCIECFG_RESULT)systemBuffer;
    result->Status = (ULONG)status;

    if (NT_SUCCESS(status))
    {
        PcieCfgParseConfig(configSpace, result);
        RtlCopyMemory(result->Raw, configSpace, request->Length);
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = sizeof(PCIECFG_RESULT);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID PcieCfgUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLink;

    RtlInitUnicodeString(&symbolicLink, PCIECFG_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symbolicLink);

    if (DriverObject->DeviceObject != NULL)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&deviceName, PCIECFG_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlInitUnicodeString(&symbolicLink, PCIECFG_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = PcieCfgCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = PcieCfgCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PcieCfgDeviceControl;
    DriverObject->DriverUnload = PcieCfgUnload;

    return STATUS_SUCCESS;
}