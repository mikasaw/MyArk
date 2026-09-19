// MyArk storage module: IOCTL handlers + device-object walker.
//
// Device enumeration walks the \Device object directory with the documented
// directory APIs (ZwOpenDirectoryObject / ZwQueryDirectoryObject) and
// resolves each name via ObReferenceObjectByName, so we never depend on the
// undocumented IoDeviceObjectListHead.ListEntry offset in DEVICE_OBJECT.
// IoEnumerateDeviceObjectList is deliberately NOT used: it requires a real
// PDRIVER_OBJECT and dereferences it, and passing NULL bugchecked the guest
// with 0x0A (read of address 8 at DISPATCH_LEVEL).

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

//
// ntifs.h is not included (it would redeclare PEPROCESS / PETHREAD after
// wdm.h). We forward-declare just the prototypes we need.
//
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
#include "../../../shared/driver/MyArkStorageIoctl.h"
#include "storage_descriptor.h"
#include "storage_internal.h"

#if MYARK_MODULE_STORAGE

#define MYARK_STORAGE_DEVICE_LIST_POOL_TAG   'kAsS'

static
VOID
MyArkStorageSafeCopyUnicode(
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
MyArkStorageMatchNameSuffix(
    _In_ PCUNICODE_STRING Name,
    _In_ PCWSTR Suffix)
//
// Returns TRUE when Name ends with Suffix (case-insensitive). Used to
// tag FVE / mountmgr / USN journal volumes without bringing in the
// full driver-name table.
//
{
    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) {
        return FALSE;
    }
    size_t suffixChars = wcslen(Suffix);
    if (suffixChars * sizeof(WCHAR) > Name->Length) {
        return FALSE;
    }

    PWCHAR tail = (PWCHAR)((PUCHAR)Name->Buffer + Name->Length - suffixChars * sizeof(WCHAR));
    UNICODE_STRING tailString;
    tailString.Buffer = tail;
    tailString.Length = (USHORT)(suffixChars * sizeof(WCHAR));
    tailString.MaximumLength = (USHORT)(suffixChars * sizeof(WCHAR));
    UNICODE_STRING suffixString;
    RtlInitUnicodeString(&suffixString, Suffix);
    return RtlCompareUnicodeString(&tailString, &suffixString, TRUE) == 0;
}

static
ULONG
MyArkStorageDeviceToLayer(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PUNICODE_STRING DriverName)
//
// Classify a device object by its driver name. Used to populate
// MYARK_VOLUME_STACK_ENTRY::Layer. Returns MYARK_VOLUME_LAYER_NONE
// when the driver is unknown.
//
{
    UNREFERENCED_PARAMETER(DeviceObject);

    if (DriverName == NULL || DriverName->Buffer == NULL) {
        return MYARK_VOLUME_LAYER_NONE;
    }

    UNICODE_STRING partmgr;
    RtlInitUnicodeString(&partmgr, L"\\Driver\\PartMgr");
    if (RtlCompareUnicodeString(DriverName, &partmgr, TRUE) == 0) {
        return MYARK_VOLUME_LAYER_PARTITION;
    }
    UNICODE_STRING disk;
    RtlInitUnicodeString(&disk, L"\\Driver\\Disk");
    if (RtlCompareUnicodeString(DriverName, &disk, TRUE) == 0) {
        return MYARK_VOLUME_LAYER_DISK;
    }
    UNICODE_STRING volmgr;
    RtlInitUnicodeString(&volmgr, L"\\Driver\\VolMgr");
    if (RtlCompareUnicodeString(DriverName, &volmgr, TRUE) == 0) {
        return MYARK_VOLUME_LAYER_VOLUME;
    }
    UNICODE_STRING ntfs;
    RtlInitUnicodeString(&ntfs, L"\\FileSystem\\Ntfs");
    if (RtlCompareUnicodeString(DriverName, &ntfs, TRUE) == 0) {
        return MYARK_VOLUME_LAYER_FS;
    }
    UNICODE_STRING fve;
    RtlInitUnicodeString(&fve, L"\\Driver\\fvevol");
    if (RtlCompareUnicodeString(DriverName, &fve, TRUE) == 0) {
        return MYARK_VOLUME_LAYER_FILTER;
    }
    return MYARK_VOLUME_LAYER_NONE;
}

static
ULONG
MyArkStorageWalkStack(
    _In_  PDEVICE_OBJECT Top,
    _Out_writes_(MaxEntries) PMYARK_VOLUME_STACK_ENTRY OutEntries,
    _In_  ULONG MaxEntries)
//
// Walk the AttachedDevice chain downward from Top. Top must be the
// highest device in the stack (FsContext-style). Stops when we hit a
// NULL AttachedDevice or exceed MaxEntries.
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
        PUNICODE_STRING driverName = (driver != NULL && MmIsAddressValid(driver))
                                         ? &driver->DriverName
                                         : NULL;

        PMYARK_VOLUME_STACK_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->DeviceObjectAddress = (UINT64)current;
        row->Layer = MyArkStorageDeviceToLayer(current, driverName);
        row->StackDepth = depth;

        if (driverName != NULL) {
            MyArkStorageSafeCopyUnicode(row->DriverName,
                                        MYARK_STORAGE_NAME_MAX,
                                        driverName);
        }

        written++;
        depth++;
        current = next;
    }

    return written;
}

#define MYARK_STORAGE_DIR_BUFFER_SIZE    4096
#define MYARK_STORAGE_NAME_CHARS         128
#define MYARK_STORAGE_DEVNAME_PREFIX_LEN 8   // chars in "\Device\"

//
// True when the device object belongs to a driver the layer classifier knows.
//
static
BOOLEAN
MyArkStorageDeviceIsStorageLayer(
    _In_ PDEVICE_OBJECT Device)
{
    if (Device == NULL || !MmIsAddressValid(Device)) {
        return FALSE;
    }

    PDRIVER_OBJECT driver =
        *(PDRIVER_OBJECT*)((PUCHAR)Device + MYARK_OFF_DO_DRIVER_OBJECT);
    if (driver == NULL || !MmIsAddressValid(driver)) {
        return FALSE;
    }

    return MyArkStorageDeviceToLayer(Device, &driver->DriverName)
               != MYARK_VOLUME_LAYER_NONE;
}

//
// Append one already-referenced device object to the growing array.
//
static
NTSTATUS
MyArkStorageDeviceListAppend(
    _Inout_ PDEVICE_OBJECT** Merged,
    _Inout_ PULONG           Count,
    _Inout_ PULONG           Capacity,
    _In_    PDEVICE_OBJECT   Device)
{
    if (*Count == *Capacity) {
        ULONG  newCapacity = (*Capacity == 0) ? 16 : (*Capacity * 2);
        size_t bytes = (size_t)newCapacity * sizeof(PDEVICE_OBJECT);

        PDEVICE_OBJECT* grown = (PDEVICE_OBJECT*)MyArkAllocatePool(
            NonPagedPoolNx, bytes, MYARK_STORAGE_DEVICE_LIST_POOL_TAG);
        if (grown == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(grown, bytes);

        if (*Merged != NULL) {
            RtlCopyMemory(grown, *Merged,
                          (size_t)(*Count) * sizeof(PDEVICE_OBJECT));
            ExFreePoolWithTag(*Merged, MYARK_STORAGE_DEVICE_LIST_POOL_TAG);
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
MyArkStorageFreeDeviceList(
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
    ExFreePoolWithTag(List, MYARK_STORAGE_DEVICE_LIST_POOL_TAG);
}

static
NTSTATUS
MyArkStorageSnapshotDevices(
    _Outptr_result_maybenull_ PDEVICE_OBJECT** OutList,
    _Out_ PULONG OutCount)
//
// Snapshot the storage-layer device objects by enumerating the \Device
// object directory and resolving each name with ObReferenceObjectByName.
//
// Every device handed back carries a reference taken here; the caller must
// release them with MyArkStorageFreeDeviceList (never a bare ExFreePool).
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
            MYARK_STORAGE_DIR_BUFFER_SIZE,
            MYARK_STORAGE_DEVICE_LIST_POOL_TAG);
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
                                        MYARK_STORAGE_DIR_BUFFER_SIZE,
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

        if (info->Name.Buffer == NULL || info->Name.Length == 0 ||
            info->Name.Length > MYARK_STORAGE_NAME_CHARS * sizeof(WCHAR)) {
            continue;
        }

        WCHAR fullName[MYARK_STORAGE_NAME_CHARS + MYARK_STORAGE_DEVNAME_PREFIX_LEN + 1];
        size_t nameChars = info->Name.Length / sizeof(WCHAR);

        RtlCopyMemory(fullName, L"\\Device\\",
                      MYARK_STORAGE_DEVNAME_PREFIX_LEN * sizeof(WCHAR));
        RtlCopyMemory(fullName + MYARK_STORAGE_DEVNAME_PREFIX_LEN,
                      info->Name.Buffer,
                      info->Name.Length);
        fullName[MYARK_STORAGE_DEVNAME_PREFIX_LEN + nameChars] = L'\0';

        UNICODE_STRING full;
        full.Buffer = fullName;
        full.Length = (USHORT)((MYARK_STORAGE_DEVNAME_PREFIX_LEN + nameChars) * sizeof(WCHAR));
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

        PDEVICE_OBJECT device = (PDEVICE_OBJECT)object;
        if (MyArkStorageDeviceIsStorageLayer(device)) {
            if (!NT_SUCCESS(MyArkStorageDeviceListAppend(&merged, &count,
                                                         &capacity, device))) {
                ObDereferenceObject(device);
                break;      // out of pool: return the partial list
            }
        } else {
            ObDereferenceObject(device);
        }
    }

    ZwClose(dirHandle);
    ExFreePoolWithTag(info, MYARK_STORAGE_DEVICE_LIST_POOL_TAG);

    *OutList  = merged;
    *OutCount = count;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkStorageIoctlQueryVolumeStack(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_STORAGE_VOLUME_STACK_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    NTSTATUS                                       status;
    PMYARK_STORAGE_VOLUME_STACK_INPUT              inBuf = NULL;
    size_t                                         inSize = 0;
    PVOID                                          outBuf = NULL;
    size_t                                         outSize = 0;

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_STORAGE_VOLUME_STACK_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_STORAGE_VOLUME_STACK_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_STORAGE_VOLUME_STACK_OUTPUT out = (PMYARK_STORAGE_VOLUME_STACK_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_STORAGE_VOLUME_STACK_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_STORAGE_VOLUME_STACK_OUTPUT, Entries[0]))
                               / sizeof(MYARK_VOLUME_STACK_ENTRY));
    if (maxEntries > MYARK_STORAGE_HARD_CAP) {
        maxEntries = MYARK_STORAGE_HARD_CAP;
    }
    if (maxEntries == 0) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_STORAGE_VOLUME_STACK_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Emit the stack for the first device whose driver matches a known
    // storage layer. R3 can refine the volume match through its own
    // symbolic-link resolver.
    //
    PDEVICE_OBJECT* deviceList = NULL;
    ULONG deviceCount = 0;
    status = MyArkStorageSnapshotDevices(&deviceList, &deviceCount);
    if (!NT_SUCCESS(status)) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_STORAGE_VOLUME_STACK_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return status;
    }

    ULONG written = 0;
    for (ULONG i = 0; i < deviceCount && written < maxEntries; i++) {
        PDEVICE_OBJECT dev = deviceList[i];
        if (dev == NULL || !MmIsAddressValid(dev)) {
            continue;
        }
        PDRIVER_OBJECT driver = *(PDRIVER_OBJECT*)((PUCHAR)dev + MYARK_OFF_DO_DRIVER_OBJECT);
        if (driver == NULL || !MmIsAddressValid(driver)) {
            continue;
        }
        ULONG layer = MyArkStorageDeviceToLayer(dev, &driver->DriverName);
        if (layer == MYARK_VOLUME_LAYER_NONE) {
            continue;
        }
        written += MyArkStorageWalkStack(dev,
                                         &out->Entries[written],
                                         maxEntries - written);
    }

    if (deviceList != NULL) {
        MyArkStorageFreeDeviceList(deviceList, deviceCount);
    }

    out->Size  = (UINT32)(FIELD_OFFSET(MYARK_STORAGE_VOLUME_STACK_OUTPUT, Entries[0])
                          + written * sizeof(MYARK_VOLUME_STACK_ENTRY));
    out->Count = written;
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkStorageIoctlQueryBitlocker(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// Walk every device's AttachedDevice chain looking for fvevol. When
// found, conservatively tag the underlying volume as encrypted.
//
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    NTSTATUS status = MyArkIoctlFetchOutputBuffer(Request,
                                                  FIELD_OFFSET(MYARK_STORAGE_BITLOCKER_OUTPUT, Entries[0]),
                                                  &outBuf,
                                                  &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_STORAGE_BITLOCKER_OUTPUT out = (PMYARK_STORAGE_BITLOCKER_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_STORAGE_BITLOCKER_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_STORAGE_BITLOCKER_OUTPUT, Entries[0]))
                               / sizeof(MYARK_BITLOCKER_ENTRY));
    if (maxEntries > MYARK_STORAGE_HARD_CAP) {
        maxEntries = MYARK_STORAGE_HARD_CAP;
    }
    if (maxEntries == 0) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_STORAGE_BITLOCKER_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    PDEVICE_OBJECT* deviceList = NULL;
    ULONG deviceCount = 0;
    status = MyArkStorageSnapshotDevices(&deviceList, &deviceCount);
    if (!NT_SUCCESS(status)) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_STORAGE_BITLOCKER_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return status;
    }

    ULONG written = 0;
    for (ULONG i = 0; i < deviceCount && written < maxEntries; i++) {
        PDEVICE_OBJECT dev = deviceList[i];
        if (dev == NULL || !MmIsAddressValid(dev)) {
            continue;
        }

        PDEVICE_OBJECT upper = *(PDEVICE_OBJECT*)((PUCHAR)dev + MYARK_OFF_DO_ATTACHED_DEVICE);
        while (upper != NULL && MmIsAddressValid(upper)) {
            PDRIVER_OBJECT driver = *(PDRIVER_OBJECT*)((PUCHAR)upper + MYARK_OFF_DO_DRIVER_OBJECT);
            if (driver != NULL && MmIsAddressValid(driver)) {
                if (MyArkStorageMatchNameSuffix(&driver->DriverName, L"fvevol")) {
                    PMYARK_BITLOCKER_ENTRY row = &out->Entries[written];
                    RtlZeroMemory(row, sizeof(*row));
                    row->VolumeDeviceAddress = (UINT64)dev;
                    row->Encrypted = 1;
                    row->Protection = 1;
                    RtlStringCbCopyW(row->VolumeName,
                                     sizeof(row->VolumeName),
                                     L"\\Device\\HarddiskVolume?");
                    written++;
                    break;
                }
            }
            upper = *(PDEVICE_OBJECT*)((PUCHAR)upper + MYARK_OFF_DO_ATTACHED_DEVICE);
        }
    }

    if (deviceList != NULL) {
        MyArkStorageFreeDeviceList(deviceList, deviceCount);
    }

    out->Size  = (UINT32)(FIELD_OFFSET(MYARK_STORAGE_BITLOCKER_OUTPUT, Entries[0])
                          + written * sizeof(MYARK_BITLOCKER_ENTRY));
    out->Count = written;
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkStorageIoctlQueryMountmgrMapping(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// The cross-driver IOCTL path requires IoBuildDeviceIoControlRequest
// + forward-progress bookkeeping that belongs in a dedicated session
// module (S7). R3 sees Source=0 and an empty entry list; the UI then
// prompts the user to run a tools-level mountmgr scan instead.
//
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PVOID                                       outBuf = NULL;
    size_t                                      outSize = 0;

    NTSTATUS status = MyArkIoctlFetchOutputBuffer(Request,
                                                  FIELD_OFFSET(MYARK_STORAGE_MOUNTMGR_OUTPUT, Entries[0]),
                                                  &outBuf,
                                                  &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_STORAGE_MOUNTMGR_OUTPUT out = (PMYARK_STORAGE_MOUNTMGR_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_STORAGE_MOUNTMGR_OUTPUT, Entries[0]));
    out->Size = (UINT32)FIELD_OFFSET(MYARK_STORAGE_MOUNTMGR_OUTPUT, Entries[0]);
    out->Count = 0;
    out->Source = 0;
    *BytesReturned = out->Size;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
MyArkStorageIoctlQueryFsIntegrity(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// Emit one row per VPB-backed volume. R3 owns the USN journal query.
//
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    PVOID                                       outBuf = NULL;
    size_t                                      outSize = 0;

    NTSTATUS status = MyArkIoctlFetchOutputBuffer(Request,
                                                  FIELD_OFFSET(MYARK_STORAGE_FS_INTEGRITY_OUTPUT, Entries[0]),
                                                  &outBuf,
                                                  &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_STORAGE_FS_INTEGRITY_OUTPUT out = (PMYARK_STORAGE_FS_INTEGRITY_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_STORAGE_FS_INTEGRITY_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_STORAGE_FS_INTEGRITY_OUTPUT, Entries[0]))
                               / sizeof(MYARK_FS_INTEGRITY_ENTRY));
    if (maxEntries > MYARK_STORAGE_HARD_CAP) {
        maxEntries = MYARK_STORAGE_HARD_CAP;
    }
    if (maxEntries == 0) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_STORAGE_FS_INTEGRITY_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    PDEVICE_OBJECT* deviceList = NULL;
    ULONG deviceCount = 0;
    status = MyArkStorageSnapshotDevices(&deviceList, &deviceCount);
    if (!NT_SUCCESS(status)) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_STORAGE_FS_INTEGRITY_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return status;
    }

    ULONG written = 0;
    for (ULONG i = 0; i < deviceCount && written < maxEntries; i++) {
        PDEVICE_OBJECT dev = deviceList[i];
        if (dev == NULL || !MmIsAddressValid(dev)) {
            continue;
        }

        PVOID vpb = *(PVOID*)((PUCHAR)dev + MYARK_OFF_DO_VPB);
        if (vpb != NULL && MmIsAddressValid(vpb)) {
            PMYARK_FS_INTEGRITY_ENTRY row = &out->Entries[written];
            RtlZeroMemory(row, sizeof(*row));
            row->State = MYARK_FS_INTEGRITY_STATE_UNKNOWN;
            RtlStringCbCopyW(row->VolumeName,
                             sizeof(row->VolumeName),
                             L"\\Device\\HarddiskVolume?");
            written++;
        }
    }

    if (deviceList != NULL) {
        MyArkStorageFreeDeviceList(deviceList, deviceCount);
    }

    out->Size  = (UINT32)(FIELD_OFFSET(MYARK_STORAGE_FS_INTEGRITY_OUTPUT, Entries[0])
                          + written * sizeof(MYARK_FS_INTEGRITY_ENTRY));
    out->Count = written;
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_STORAGE