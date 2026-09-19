// MyArk device-audit module: IOCTL handlers + global device walker.
//
// Five surfaces:
//   DEVICE_STACK    -- all device objects, no filter
//   USB_TOPOLOGY    -- DO names matching "USB" + their filter chains
//   GPU_DISPLAY     -- DO names matching "Dxgk*" or "BasicDisplay"
//   INPUT_STACK     -- DO names matching KBDCLASS / MOUCLASS / HID
//   WATCHDOG        -- DO names matching "Watchdog"
//
// Enumeration walks the \Device object directory with the documented
// directory APIs and resolves each name via ObReferenceObjectByName, so we
// never depend on the undocumented IoDeviceObjectListHead.ListEntry offset.
// IoEnumerateDeviceObjectList is deliberately NOT used: it requires a real
// PDRIVER_OBJECT and dereferences it, and passing NULL bugchecked the guest
// with 0x0A (read of address 8 at DISPATCH_LEVEL).

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

//
// Directory/object APIs (ntifs.h is not included by project policy, so the
// prototypes are declared here, like the other NTKERNELAPI forward decls in
// this code base).
//
extern POBJECT_TYPE *IoDeviceObjectType;

NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
    _In_       PUNICODE_STRING ObjectName,
    _In_       ULONG           Attributes,
    _In_opt_   PACCESS_STATE   PassedAccessState,
    _In_opt_   ACCESS_MASK     DesiredAccess,
    _In_       POBJECT_TYPE    ObjectType,
    _In_       KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID          ParseContext,
    _Out_      PVOID*          Object);

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenDirectoryObject(
    _Out_ PHANDLE            DirectoryHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject(
    _In_     HANDLE   DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_     ULONG    Length,
    _In_     BOOLEAN  ReturnSingleEntry,
    _In_     BOOLEAN  RestartScan,
    _Inout_  PULONG   Context,
    _Out_opt_ PULONG  ReturnLength);

typedef struct _MYARK_OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} MYARK_OBJECT_DIRECTORY_INFORMATION, *PMYARK_OBJECT_DIRECTORY_INFORMATION;
#include "Trace.h"
#include "MyArkPoolAlloc.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkDeviceAuditIoctl.h"
#include "devaudit_descriptor.h"
#include "devaudit_internal.h"

#if MYARK_MODULE_DEVICE_AUDIT

#define MYARK_DEVAUDIT_DEVICE_LIST_POOL_TAG   'aDdD'
#define MYARK_DEVAUDIT_DIR_BUFFER_SIZE        4096
#define MYARK_DEVAUDIT_NAME_CHARS             128
#define MYARK_DEVAUDIT_DEVNAME_PREFIX_LEN     8   // chars in "\Device\"
#define MYARK_DEVAUDIT_MAX_DEVICES            4096

static
VOID
MyArkDevAuditSafeCopyUnicode(
    _Out_writes_z_(Capacity) PWCHAR Dest,
    _In_ size_t Capacity,
    _In_opt_ PUNICODE_STRING Src)
{
    if (Dest == NULL || Capacity == 0) {
        return;
    }
    RtlZeroMemory(Dest, Capacity * sizeof(WCHAR));

    if (Src == NULL || Src->Buffer == NULL || Src->Length == 0) {
        return;
    }

    size_t copyChars = Src->Length / sizeof(WCHAR);
    if (copyChars >= Capacity) {
        copyChars = Capacity - 1;
    }

    if (!MmIsAddressValid(Src->Buffer) ||
        !MmIsAddressValid((PUCHAR)Src->Buffer + (copyChars * sizeof(WCHAR)))) {
        return;
    }

    RtlCopyMemory(Dest, Src->Buffer, copyChars * sizeof(WCHAR));
    Dest[copyChars] = L'\0';
}

static
ULONG
MyArkDevAuditMatchName(
    _In_opt_ PUNICODE_STRING Name,
    _In_ PCWSTR Prefix)
{
    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) {
        return FALSE;
    }
    UNICODE_STRING prefix;
    RtlInitUnicodeString(&prefix, Prefix);
    if (RtlCompareUnicodeString(Name, &prefix, TRUE) == 0) {
        return TRUE;
    }
    if (Name->Length > prefix.Length) {
        UNICODE_STRING head;
        head.Buffer = Name->Buffer;
        head.Length = prefix.Length;
        head.MaximumLength = prefix.Length;
        return RtlCompareUnicodeString(&head, &prefix, TRUE) == 0;
    }
    return FALSE;
}

static
VOID
MyArkDevAuditWalkChain(
    _In_  PDEVICE_OBJECT Top,
    _Out_writes_(MaxEntries) PMYARK_DEVICE_ENTRY OutEntries,
    _In_  ULONG MaxEntries,
    _Out_ PULONG CountOut)
//
// Walk the AttachedDevice chain downward, writing one row per DO.
//
{
    PDEVICE_OBJECT current = Top;
    ULONG written = 0;
    ULONG depth = 0;
    const ULONG HARD_CAP = 32;

    while (current != NULL && written < MaxEntries && depth < HARD_CAP) {
        if (!MmIsAddressValid(current)) {
            break;
        }
        PDEVICE_OBJECT next = *(PDEVICE_OBJECT*)((PUCHAR)current + MYARK_OFF_DO_ATTACHED_DEVICE);
        PDRIVER_OBJECT driver = *(PDRIVER_OBJECT*)((PUCHAR)current + MYARK_OFF_DO_DRIVER_OBJECT);

        PMYARK_DEVICE_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->DeviceObjectAddress = (UINT64)current;
        row->AttachedToAddress   = (UINT64)next;
        row->StackDepth = depth;

        if (driver != NULL && MmIsAddressValid(driver)) {
            MyArkDevAuditSafeCopyUnicode(row->DriverName,
                                         MYARK_DEVAUDIT_NAME_MAX,
                                         &driver->DriverName);
        }

        if (row->DriverName[0] == L'\0') {
            row->Flags |= MYARK_DEV_FLAG_HIDDEN;
        }

        written++;
        depth++;
        current = next;
    }

    *CountOut = written;
}

//
// Append one already-referenced device object to the growing array.
//
static
NTSTATUS
MyArkDevAuditDeviceListAppend(
    _Inout_ PDEVICE_OBJECT** Merged,
    _Inout_ PULONG           Count,
    _Inout_ PULONG           Capacity,
    _In_    PDEVICE_OBJECT   Device)
{
    if (*Count == *Capacity) {
        ULONG  newCapacity = (*Capacity == 0) ? 32 : (*Capacity * 2);
        size_t bytes = (size_t)newCapacity * sizeof(PDEVICE_OBJECT);

        PDEVICE_OBJECT* grown = (PDEVICE_OBJECT*)MyArkAllocatePool(
            NonPagedPoolNx, bytes, MYARK_DEVAUDIT_DEVICE_LIST_POOL_TAG);
        if (grown == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(grown, bytes);

        if (*Merged != NULL) {
            RtlCopyMemory(grown, *Merged,
                          (size_t)(*Count) * sizeof(PDEVICE_OBJECT));
            ExFreePoolWithTag(*Merged, MYARK_DEVAUDIT_DEVICE_LIST_POOL_TAG);
        }
        *Merged   = grown;
        *Capacity = newCapacity;
    }

    (*Merged)[(*Count)++] = Device;
    return STATUS_SUCCESS;
}

//
// Drop the references held on a device list and free the array.
//
static
VOID
MyArkDevAuditFreeDeviceList(
    _In_opt_ PDEVICE_OBJECT* List,
    _In_     ULONG           Count)
{
    if (List == NULL) {
        return;
    }

    for (ULONG i = 0; i < Count; i++) {
        if (List[i] != NULL) {
            ObDereferenceObject(List[i]);
        }
    }
    ExFreePoolWithTag(List, MYARK_DEVAUDIT_DEVICE_LIST_POOL_TAG);
}

static
NTSTATUS
MyArkDevAuditSnapshotDevices(
    _Outptr_result_maybenull_ PDEVICE_OBJECT** OutList,
    _Out_ PULONG OutCount)
//
// Snapshot every device object reachable through the \Device object
// directory. Callers filter by device name themselves.
//
// Every device handed back carries a reference taken here; the caller must
// release them with MyArkDevAuditFreeDeviceList (never a bare ExFreePool).
//
{
    *OutList  = NULL;
    *OutCount = 0;

    UNICODE_STRING deviceDir;
    RtlInitUnicodeString(&deviceDir, L"\\Device");

    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes,
                               &deviceDir,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    HANDLE dirHandle = NULL;
    NTSTATUS status = ZwOpenDirectoryObject(&dirHandle, DIRECTORY_QUERY, &attributes);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;      // nothing to enumerate
    }

    PMYARK_OBJECT_DIRECTORY_INFORMATION info =
        (PMYARK_OBJECT_DIRECTORY_INFORMATION)MyArkAllocatePool(
            NonPagedPoolNx,
            MYARK_DEVAUDIT_DIR_BUFFER_SIZE,
            MYARK_DEVAUDIT_DEVICE_LIST_POOL_TAG);
    if (info == NULL) {
        ZwClose(dirHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDEVICE_OBJECT* merged    = NULL;
    ULONG           count     = 0;
    ULONG           capacity  = 0;
    ULONG           context   = 0;
    BOOLEAN         firstScan = TRUE;

    for (;;) {
        ULONG returned = 0;
        status = ZwQueryDirectoryObject(dirHandle,
                                        info,
                                        MYARK_DEVAUDIT_DIR_BUFFER_SIZE,
                                        TRUE,       // one entry per call
                                        firstScan,
                                        &context,
                                        &returned);
        if (status == STATUS_NO_MORE_ENTRIES) {
            break;
        }
        if (!NT_SUCCESS(status)) {
            break;      // buffer/short-read pathologies: keep what we have
        }
        firstScan = FALSE;

        if (count >= MYARK_DEVAUDIT_MAX_DEVICES) {
            break;      // sanity bound on the snapshot
        }

        if (info->Name.Buffer == NULL || info->Name.Length == 0 ||
            info->Name.Length > MYARK_DEVAUDIT_NAME_CHARS * sizeof(WCHAR)) {
            continue;
        }

        WCHAR fullName[MYARK_DEVAUDIT_NAME_CHARS + MYARK_DEVAUDIT_DEVNAME_PREFIX_LEN + 1];
        size_t nameChars = info->Name.Length / sizeof(WCHAR);

        RtlCopyMemory(fullName, L"\\Device\\",
                      MYARK_DEVAUDIT_DEVNAME_PREFIX_LEN * sizeof(WCHAR));
        RtlCopyMemory(fullName + MYARK_DEVAUDIT_DEVNAME_PREFIX_LEN,
                      info->Name.Buffer,
                      info->Name.Length);
        fullName[MYARK_DEVAUDIT_DEVNAME_PREFIX_LEN + nameChars] = L'\0';

        UNICODE_STRING full;
        full.Buffer = fullName;
        full.Length = (USHORT)((MYARK_DEVAUDIT_DEVNAME_PREFIX_LEN + nameChars) * sizeof(WCHAR));
        full.MaximumLength = (USHORT)(full.Length + sizeof(WCHAR));

        PVOID object = NULL;
        status = ObReferenceObjectByName(&full,
                                         OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                         NULL,
                                         0,
                                         *IoDeviceObjectType,
                                         KernelMode,
                                         NULL,
                                         &object);
        if (!NT_SUCCESS(status) || object == NULL) {
            continue;   // symlink / non-device entry / inaccessible type
        }

        if (!NT_SUCCESS(MyArkDevAuditDeviceListAppend(&merged, &count,
                                                      &capacity,
                                                      (PDEVICE_OBJECT)object))) {
            ObDereferenceObject(object);
            break;      // out of pool: return the partial list
        }
    }

    ZwClose(dirHandle);
    ExFreePoolWithTag(info, MYARK_DEVAUDIT_DEVICE_LIST_POOL_TAG);

    *OutList  = merged;
    *OutCount = count;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkDeviceAuditIoctlQueryDeviceStack(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_DEVAUDIT_INPUT                   inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DEVAUDIT_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DEVAUDIT_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DEVAUDIT_DEVICE_STACK_OUTPUT out = (PMYARK_DEVAUDIT_DEVICE_STACK_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT, Entries[0]))
                               / sizeof(MYARK_DEVICE_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_DEVAUDIT_HARD_CAP) {
        maxEntries = MYARK_DEVAUDIT_HARD_CAP;
    }
    if (maxEntries == 0) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    PDEVICE_OBJECT* deviceList = NULL;
    ULONG deviceCount = 0;
    status = MyArkDevAuditSnapshotDevices(&deviceList, &deviceCount);
    if (!NT_SUCCESS(status)) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return status;
    }

    ULONG written = 0;
    ULONG seen = 0;
    for (ULONG i = 0; i < deviceCount && written < maxEntries; i++) {
        PDEVICE_OBJECT dev = deviceList[i];
        if (dev == NULL || !MmIsAddressValid(dev)) {
            continue;
        }
        seen++;
        MyArkDevAuditWalkChain(dev, &out->Entries[written], maxEntries - written, &written);
    }

    if (deviceList != NULL) {
        MyArkDevAuditFreeDeviceList(deviceList, deviceCount);
    }

    out->Size      = (UINT32)(FIELD_OFFSET(MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT, Entries[0])
                              + written * sizeof(MYARK_DEVICE_ENTRY));
    out->Count     = written;
    out->TotalSeen = seen;
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkDeviceAuditIoctlQueryUsbTopology(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_DEVAUDIT_INPUT                   inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DEVAUDIT_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DEVAUDIT_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DEVAUDIT_USB_TOPOLOGY_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DEVAUDIT_USB_TOPOLOGY_OUTPUT out = (PMYARK_DEVAUDIT_USB_TOPOLOGY_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_DEVAUDIT_USB_TOPOLOGY_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_DEVAUDIT_USB_TOPOLOGY_OUTPUT, Entries[0]))
                               / sizeof(MYARK_USB_TOPOLOGY_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_DEVAUDIT_HARD_CAP) {
        maxEntries = MYARK_DEVAUDIT_HARD_CAP;
    }

    PDEVICE_OBJECT* deviceList = NULL;
    ULONG deviceCount = 0;
    status = MyArkDevAuditSnapshotDevices(&deviceList, &deviceCount);
    if (!NT_SUCCESS(status)) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_DEVAUDIT_USB_TOPOLOGY_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return status;
    }

    ULONG written = 0;
    ULONG rootHub = 0;
    ULONG seen = 0;
    for (ULONG i = 0; i < deviceCount && written < maxEntries; i++) {
        PDEVICE_OBJECT dev = deviceList[i];
        if (dev == NULL || !MmIsAddressValid(dev)) {
            continue;
        }
        seen++;

        PDRIVER_OBJECT driver = *(PDRIVER_OBJECT*)((PUCHAR)dev + MYARK_OFF_DO_DRIVER_OBJECT);
        if (driver == NULL || !MmIsAddressValid(driver)) {
            continue;
        }

        if (!MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\USBHUB")
            && !MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\USBPORT")
            && !MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\USBSTOR")) {
            continue;
        }

        PMYARK_USB_TOPOLOGY_ENTRY row = &out->Entries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->DeviceObjectAddress = (UINT64)dev;

        if (MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\USBHUB")) {
            row->Flags = MYARK_USB_FLAG_ROOT_HUB;
            row->Depth = 0;
            rootHub++;
        } else if (MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\USBPORT")) {
            row->Flags = MYARK_USB_FLAG_DEVICE;
            row->Depth = 1;
        } else {
            row->Flags = MYARK_USB_FLAG_EXTERNAL_HUB;
            row->Depth = 1;
        }

        MyArkDevAuditSafeCopyUnicode(row->DriverName,
                                     MYARK_DEVAUDIT_NAME_MAX,
                                     &driver->DriverName);
        written++;
    }

    if (deviceList != NULL) {
        MyArkDevAuditFreeDeviceList(deviceList, deviceCount);
    }

    out->Size         = (UINT32)(FIELD_OFFSET(MYARK_DEVAUDIT_USB_TOPOLOGY_OUTPUT, Entries[0])
                                 + written * sizeof(MYARK_USB_TOPOLOGY_ENTRY));
    out->Count        = written;
    out->RootHubCount = rootHub;
    out->TotalSeen    = seen;
    *BytesReturned    = out->Size;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkDeviceAuditIoctlQueryGpuDisplay(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_DEVAUDIT_INPUT                   inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DEVAUDIT_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DEVAUDIT_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DEVAUDIT_GPU_DISPLAY_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DEVAUDIT_GPU_DISPLAY_OUTPUT out = (PMYARK_DEVAUDIT_GPU_DISPLAY_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_DEVAUDIT_GPU_DISPLAY_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_DEVAUDIT_GPU_DISPLAY_OUTPUT, Entries[0]))
                               / sizeof(MYARK_GPU_DISPLAY_ENTRY));
    if (maxEntries > MYARK_DEVAUDIT_HARD_CAP) {
        maxEntries = MYARK_DEVAUDIT_HARD_CAP;
    }

    PDEVICE_OBJECT* deviceList = NULL;
    ULONG deviceCount = 0;
    status = MyArkDevAuditSnapshotDevices(&deviceList, &deviceCount);
    if (!NT_SUCCESS(status)) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_DEVAUDIT_GPU_DISPLAY_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return status;
    }

    ULONG written = 0;
    ULONG adapter = 0;
    ULONG seen = 0;
    for (ULONG i = 0; i < deviceCount && written < maxEntries; i++) {
        PDEVICE_OBJECT dev = deviceList[i];
        if (dev == NULL || !MmIsAddressValid(dev)) {
            continue;
        }
        seen++;

        PDRIVER_OBJECT driver = *(PDRIVER_OBJECT*)((PUCHAR)dev + MYARK_OFF_DO_DRIVER_OBJECT);
        if (driver == NULL || !MmIsAddressValid(driver)) {
            continue;
        }

        if (!MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\Dxgk")
            && !MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\BasicDisplay")) {
            continue;
        }

        PMYARK_GPU_DISPLAY_ENTRY row = &out->Entries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->DeviceObjectAddress = (UINT64)dev;
        row->AdapterIndex = adapter++;
        MyArkDevAuditSafeCopyUnicode(row->DriverName,
                                     MYARK_DEVAUDIT_NAME_MAX,
                                     &driver->DriverName);
        written++;
    }

    if (deviceList != NULL) {
        MyArkDevAuditFreeDeviceList(deviceList, deviceCount);
    }

    out->Size      = (UINT32)(FIELD_OFFSET(MYARK_DEVAUDIT_GPU_DISPLAY_OUTPUT, Entries[0])
                              + written * sizeof(MYARK_GPU_DISPLAY_ENTRY));
    out->Count     = written;
    out->TotalSeen = seen;
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkDeviceAuditIoctlQueryInputStack(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_DEVAUDIT_INPUT                   inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DEVAUDIT_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DEVAUDIT_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DEVAUDIT_INPUT_STACK_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DEVAUDIT_INPUT_STACK_OUTPUT out = (PMYARK_DEVAUDIT_INPUT_STACK_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_DEVAUDIT_INPUT_STACK_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_DEVAUDIT_INPUT_STACK_OUTPUT, Entries[0]))
                               / sizeof(MYARK_INPUT_STACK_ENTRY));
    if (maxEntries > MYARK_DEVAUDIT_HARD_CAP) {
        maxEntries = MYARK_DEVAUDIT_HARD_CAP;
    }

    PDEVICE_OBJECT* deviceList = NULL;
    ULONG deviceCount = 0;
    status = MyArkDevAuditSnapshotDevices(&deviceList, &deviceCount);
    if (!NT_SUCCESS(status)) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_DEVAUDIT_INPUT_STACK_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return status;
    }

    ULONG written = 0;
    ULONG keyboard = 0;
    ULONG mouse = 0;
    ULONG seen = 0;
    for (ULONG i = 0; i < deviceCount && written < maxEntries; i++) {
        PDEVICE_OBJECT dev = deviceList[i];
        if (dev == NULL || !MmIsAddressValid(dev)) {
            continue;
        }
        seen++;

        PDRIVER_OBJECT driver = *(PDRIVER_OBJECT*)((PUCHAR)dev + MYARK_OFF_DO_DRIVER_OBJECT);
        if (driver == NULL || !MmIsAddressValid(driver)) {
            continue;
        }

        ULONG flags = 0;
        if (MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\KBDCLASS")) {
            flags = MYARK_INPUT_FLAG_KEYBOARD;
            keyboard++;
        } else if (MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\MOUCLASS")) {
            flags = MYARK_INPUT_FLAG_MOUSE;
            mouse++;
        } else if (MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\HID")) {
            flags = MYARK_INPUT_FLAG_HID;
        } else {
            continue;
        }

        PMYARK_INPUT_STACK_ENTRY row = &out->Entries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->DeviceObjectAddress = (UINT64)dev;
        row->Flags = flags;
        row->StackDepth = 0;
        MyArkDevAuditSafeCopyUnicode(row->DriverName,
                                     MYARK_DEVAUDIT_NAME_MAX,
                                     &driver->DriverName);
        written++;
    }

    if (deviceList != NULL) {
        MyArkDevAuditFreeDeviceList(deviceList, deviceCount);
    }

    out->Size          = (UINT32)(FIELD_OFFSET(MYARK_DEVAUDIT_INPUT_STACK_OUTPUT, Entries[0])
                                  + written * sizeof(MYARK_INPUT_STACK_ENTRY));
    out->Count         = written;
    out->KeyboardCount = keyboard;
    out->MouseCount    = mouse;
    out->TotalSeen     = seen;
    *BytesReturned     = out->Size;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkDeviceAuditIoctlQueryWatchdog(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// Heuristic only -- the WDI driver is the canonical target but
// third-party watchdog drivers live under their own naming.
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_DEVAUDIT_INPUT                   inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DEVAUDIT_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DEVAUDIT_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DEVAUDIT_WATCHDOG_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DEVAUDIT_WATCHDOG_OUTPUT out = (PMYARK_DEVAUDIT_WATCHDOG_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_DEVAUDIT_WATCHDOG_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_DEVAUDIT_WATCHDOG_OUTPUT, Entries[0]))
                               / sizeof(MYARK_WATCHDOG_ENTRY));
    if (maxEntries > MYARK_DEVAUDIT_HARD_CAP) {
        maxEntries = MYARK_DEVAUDIT_HARD_CAP;
    }

    PDEVICE_OBJECT* deviceList = NULL;
    ULONG deviceCount = 0;
    status = MyArkDevAuditSnapshotDevices(&deviceList, &deviceCount);
    if (!NT_SUCCESS(status)) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_DEVAUDIT_WATCHDOG_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return status;
    }

    ULONG written = 0;
    ULONG seen = 0;
    for (ULONG i = 0; i < deviceCount && written < maxEntries; i++) {
        PDEVICE_OBJECT dev = deviceList[i];
        if (dev == NULL || !MmIsAddressValid(dev)) {
            continue;
        }
        seen++;

        PDRIVER_OBJECT driver = *(PDRIVER_OBJECT*)((PUCHAR)dev + MYARK_OFF_DO_DRIVER_OBJECT);
        if (driver == NULL || !MmIsAddressValid(driver)) {
            continue;
        }

        if (!MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\WDI")
            && !MyArkDevAuditMatchName(&driver->DriverName, L"\\Driver\\WDT")) {
            continue;
        }

        PMYARK_WATCHDOG_ENTRY row = &out->Entries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->DeviceObjectAddress = (UINT64)dev;
        row->TimerObjectAddress = 0;
        MyArkDevAuditSafeCopyUnicode(row->DriverName,
                                     MYARK_DEVAUDIT_NAME_MAX,
                                     &driver->DriverName);
        written++;
    }

    if (deviceList != NULL) {
        MyArkDevAuditFreeDeviceList(deviceList, deviceCount);
    }

    out->Size      = (UINT32)(FIELD_OFFSET(MYARK_DEVAUDIT_WATCHDOG_OUTPUT, Entries[0])
                              + written * sizeof(MYARK_WATCHDOG_ENTRY));
    out->Count     = written;
    out->TotalSeen = seen;
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_DEVICE_AUDIT