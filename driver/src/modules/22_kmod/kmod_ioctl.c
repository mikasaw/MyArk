// MyArk kmod module: IOCTL handlers + IoDriverListHead walker.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkKmodIoctl.h"
#include "kmod_descriptor.h"
#include "kmod_internal.h"

#if MYARK_MODULE_KMODULE

static
VOID
MyArkKmodSafeCopyUnicode(
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

//
// IoDriverListHead is the canonical global walk. Its LIST_ENTRY lives
// at offset 0x058 inside DRIVER_OBJECT (where the DriverInit function
// pointer is overloaded on Win11 24H2). We subtract that offset to get
// the DriverObject base.
//
// (For builds where DriverInit is not the link, we fall through and
// emit zero rows -- the list-head probe catches the misalignment.)
//
#define MYARK_IO_DRIVER_LINK_OFFSET         0x058UL

static
PDRIVER_OBJECT
MyArkKmodDriverFromListEntry(
    _In_ PLIST_ENTRY Entry)
{
    return (PDRIVER_OBJECT)((PUCHAR)Entry - MYARK_IO_DRIVER_LINK_OFFSET);
}

static
ULONG
MyArkKmodWalkDriverList(
    _Out_writes_(MaxEntries) PMYARK_KMODULE_ENTRY OutEntries,
    _In_  ULONG MaxEntries,
    _Out_ PULONG TotalSeenOut)
//
// Walk IoDriverListHead and emit one row per DRIVER_OBJECT. The walk
// terminates at the list-head sentinel; each iteration probes for page
// validity before reading.
//
{
    PLIST_ENTRY head = &IoDriverListHead;
    if (!MmIsAddressValid(head)) {
        *TotalSeenOut = 0;
        return 0;
    }

    PLIST_ENTRY current = head->Flink;
    ULONG written = 0;
    ULONG seen = 0;
    const ULONG HARD_CAP = 1024;     // hard cap -- 1024 drivers is well beyond what's ever loaded

    while (current != NULL
           && current != head
           && seen < HARD_CAP
           && written < MaxEntries) {

        PDRIVER_OBJECT driver = MyArkKmodDriverFromListEntry(current);
        seen++;

        if (!MmIsAddressValid((PVOID)driver)) {
            current = current->Flink;
            continue;
        }

        //
        // Validate that this is plausibly a DRIVER_OBJECT: Type should
        // be IO_TYPE_DRIVER (4) at offset 0.
        //
        UINT16 type = *(PUINT16)((PUCHAR)driver + MYARK_OFF_DRV_TYPE);
        if (type != 4) {
            //
            // The list link may live in a sub-structure. Skip this entry.
            //
            current = current->Flink;
            continue;
        }

        PMYARK_KMODULE_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->DriverObjectAddress = (UINT64)driver;
        row->DriverStartAddress  = (UINT64)*(PVOID*)((PUCHAR)driver + MYARK_OFF_DRV_DRIVER_START);
        row->DriverSize          = *(PULONG)((PUCHAR)driver + MYARK_OFF_DRV_DRIVER_SIZE);

        //
        // DriverName: read the UNICODE_STRING header, then copy with
        // page probing.
        //
        PUNICODE_STRING name = (PUNICODE_STRING)((PUCHAR)driver + MYARK_OFF_DRV_DRIVER_NAME);
        MyArkKmodSafeCopyUnicode(row->DriverName, MYARK_KMODULE_NAME_MAX, name);

        //
        // DriverPath -- best-effort: registry path lives in the
        // _DRIVER_EXTENSION (DriverObject->DriverExtension). Without the
        // exact offset we fall back to "<unknown>".
        //
        RtlStringCbCopyW(row->DriverPath, sizeof(row->DriverPath), L"<see registry>");

        UINT32 flags = 0;

        if (*(PVOID*)((PUCHAR)driver + MYARK_OFF_DRV_FAST_IO_DISPATCH) != NULL) {
            flags |= MYARK_KMODULE_FLAG_HAS_FAST_IO;
        }

        //
        // Count populated MajorFunction slots: a slot is "populated" if
        // it does not match the IopInvalidDeviceRequest stub. We don't
        // have the stub address handy, so we just count any non-NULL
        // entry. Zero entries are the common case for legacy drivers.
        //
        ULONG populated = 0;
        PUCHAR majorBase = (PUCHAR)driver + MYARK_OFF_DRV_MAJOR_FUNCTION;
        for (ULONG i = 0; i < MYARK_DRV_MAJOR_FUNCTION_COUNT; i++) {
            if (*(PVOID*)(majorBase + i * sizeof(PVOID)) != NULL) {
                populated++;
            }
        }
        row->MajorFunctionCount = populated;
        if (populated > 0) {
            flags |= MYARK_KMODULE_FLAG_HAS_MAJOR_TABLE;
        }

        if (row->DriverName[0] == L'\0') {
            flags |= MYARK_KMODULE_FLAG_ANONYMOUS;
        }

        row->Flags = flags;
        written++;

        current = current->Flink;
    }

    *TotalSeenOut = seen;
    return written;
}

static
ULONG
MyArkKmodWalkIoctlDispatch(
    _Out_writes_(MaxEntries) PMYARK_IOCTL_REG_ENTRY OutEntries,
    _In_  ULONG MaxEntries,
    _Out_ PULONG TotalSeenOut)
//
// For every driver on IoDriverListHead, read the
// MajorFunction[IRP_MJ_DEVICE_CONTROL] entry and emit one row.
//
{
    PLIST_ENTRY head = &IoDriverListHead;
    if (!MmIsAddressValid(head)) {
        *TotalSeenOut = 0;
        return 0;
    }

    PLIST_ENTRY current = head->Flink;
    ULONG written = 0;
    ULONG seen = 0;
    const ULONG HARD_CAP = 1024;

    while (current != NULL
           && current != head
           && seen < HARD_CAP
           && written < MaxEntries) {

        PDRIVER_OBJECT driver = MyArkKmodDriverFromListEntry(current);
        seen++;

        if (!MmIsAddressValid((PVOID)driver)) {
            current = current->Flink;
            continue;
        }

        UINT16 type = *(PUINT16)((PUCHAR)driver + MYARK_OFF_DRV_TYPE);
        if (type != 4) {
            current = current->Flink;
            continue;
        }

        PVOID dispatch = *(PVOID*)((PUCHAR)driver
                                   + MYARK_OFF_DRV_MAJOR_FUNCTION
                                   + IRP_MJ_DEVICE_CONTROL * sizeof(PVOID));

        PMYARK_IOCTL_REG_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->DriverObjectAddress = (UINT64)driver;
        row->DispatchAddress     = (UINT64)dispatch;

        PUNICODE_STRING name = (PUNICODE_STRING)((PUCHAR)driver + MYARK_OFF_DRV_DRIVER_NAME);
        MyArkKmodSafeCopyUnicode(row->DriverName, MYARK_KMODULE_NAME_MAX, name);

        UINT32 flags = 0;
        if (dispatch != NULL) {
            flags |= MYARK_IOCTL_REG_FLAG_POPULATED;
        }
        row->Flags = flags;

        written++;
        current = current->Flink;
    }

    *TotalSeenOut = seen;
    return written;
}

NTSTATUS
MyArkKmodIoctlQueryDriverObject(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// QUERY_DRIVER_OBJECT: one row per driver on IoDriverListHead.
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_MODULE_QUERY_DRIVER_OBJECT_INPUT inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_MODULE_QUERY_DRIVER_OBJECT_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_MODULE_QUERY_DRIVER_OBJECT_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT out = (PMYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT, Entries[0]))
                               / sizeof(MYARK_KMODULE_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_KMODULE_HARD_CAP) {
        maxEntries = MYARK_KMODULE_HARD_CAP;
    }
    if (maxEntries == 0) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG totalSeen = 0;
    ULONG written = MyArkKmodWalkDriverList(out->Entries, maxEntries, &totalSeen);

    out->Size      = (UINT32)(FIELD_OFFSET(MYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT, Entries[0])
                              + written * sizeof(MYARK_KMODULE_ENTRY));
    out->Count     = written;
    out->TotalSeen = totalSeen;
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkKmodIoctlQueryIoctlRegistry(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// QUERY_IOCTL_REGISTRY: one row per MajorFunction[IRP_MJ_DEVICE_CONTROL]
// dispatch function on every loaded driver.
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_MODULE_QUERY_IOCTL_REGISTRY_INPUT  inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_MODULE_QUERY_IOCTL_REGISTRY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_MODULE_QUERY_IOCTL_REGISTRY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_MODULE_QUERY_IOCTL_REGISTRY_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_MODULE_QUERY_IOCTL_REGISTRY_OUTPUT out = (PMYARK_MODULE_QUERY_IOCTL_REGISTRY_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_MODULE_QUERY_IOCTL_REGISTRY_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_MODULE_QUERY_IOCTL_REGISTRY_OUTPUT, Entries[0]))
                               / sizeof(MYARK_IOCTL_REG_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_KMODULE_HARD_CAP) {
        maxEntries = MYARK_KMODULE_HARD_CAP;
    }
    if (maxEntries == 0) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_MODULE_QUERY_IOCTL_REGISTRY_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG totalSeen = 0;
    ULONG written = MyArkKmodWalkIoctlDispatch(out->Entries, maxEntries, &totalSeen);

    out->Size      = (UINT32)(FIELD_OFFSET(MYARK_MODULE_QUERY_IOCTL_REGISTRY_OUTPUT, Entries[0])
                              + written * sizeof(MYARK_IOCTL_REG_ENTRY));
    out->Count     = written;
    out->TotalSeen = totalSeen;
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_KMODULE
