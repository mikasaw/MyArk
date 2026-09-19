// MyArk hwid module: R3-1 disk-backed spoof classes.
//
//   MYARK_HWID_SPOOF_CLASS_DISK_SERIAL    - IOCTL_STORAGE_QUERY_PROPERTY
//                                           (StorageDeviceProperty) serial
//                                           string rewrite.
//   MYARK_HWID_SPOOF_CLASS_MOUNTMGR_UID   - IOCTL_STORAGE_QUERY_PROPERTY
//                                           (StorageDeviceUniqueIdProperty)
//                                           embedded-descriptor serial rewrite
//                                           (the field mountmgr hashes into
//                                           volume UniqueIds).
//   MYARK_HWID_SPOOF_CLASS_PARTITION_GUID - IOCTL_DISK_GET_PARTITION_INFO_EX
//                                           Gpt.PartitionId + IOCTL_DISK_GET_
//                                           DRIVE_LAYOUT_EX per-partition ids.
//
// All rewrites happen in completion routines on METHOD_BUFFERED response
// buffers: the SystemBuffer still holds the response when the completion
// runs and the I/O manager copies it to the caller afterwards. Only the
// bytes of the reported value are replaced (never longer than the
// original value extent; descriptor Size/offsets stay untouched).

#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntddstor.h>
#include <ntdddisk.h>
#include <storduid.h>      // STORAGE_DEVICE_UNIQUE_IDENTIFIER
#include "hwid_spoof_internal.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"

#if MYARK_MODULE_HWID

#define MYARK_TRACE_SPOOF "[hwid-spoof] "
#define MYARK_HWID_SPOOF_POOL_TAG       0x6D485357UL  // 'WSHm'
#define MYARK_HWID_PROBE_OUT_BYTES      4096

// StorageDeviceUniqueIdProperty (ntddstor STORAGE_PROPERTY_ID).
#define MYARK_HWID_PROPERTY_UNIQUE_ID   3

// Per-IRP capture for IOCTL_STORAGE_QUERY_PROPERTY: METHOD_BUFFERED
// overwrites the input with the output, so the requested PropertyId must
// be captured at dispatch time and freed at completion.
typedef struct _MYARK_HWID_QUERY_CTX {
    ULONG                    Magic;      // MYARK_HWID_QUERY_CTX_MAGIC
    ULONG                    PropertyId;
    PMYARK_HWID_FILTER_EXT   Ext;
} MYARK_HWID_QUERY_CTX, *PMYARK_HWID_QUERY_CTX;

#define MYARK_HWID_QUERY_CTX_MAGIC      0x48575143UL  // 'HWQC'

static CONST GUID MyArkHwidZeroGuid = { 0 };

//
// Context plumbing (called from the dispatch router / completion).
//

static
BOOLEAN
MyArkHwidIsQueryCtx(_In_ PVOID Context)
{
    return Context != NULL
           && ((PMYARK_HWID_QUERY_CTX)Context)->Magic == MYARK_HWID_QUERY_CTX_MAGIC;
}

PMYARK_HWID_FILTER_EXT
MyArkHwidExtFromContext(_In_ PVOID Context)
{
    if (MyArkHwidIsQueryCtx(Context)) {
        return ((PMYARK_HWID_QUERY_CTX)Context)->Ext;
    }
    if (Context != NULL
        && ((PMYARK_HWID_ARP_CTX)Context)->Magic == MYARK_HWID_ARP_CTX_MAGIC) {
        return ((PMYARK_HWID_ARP_CTX)Context)->Ext;
    }
    return (PMYARK_HWID_FILTER_EXT)Context;
}

PVOID
MyArkHwidCaptureQueryContext(
    _In_ PMYARK_HWID_FILTER_EXT Ext,
    _Inout_ PIRP                Irp,
    _In_ PIO_STACK_LOCATION     Slot)
{
    PMYARK_HWID_QUERY_CTX ctx;
    PSTORAGE_PROPERTY_QUERY query;

    if (Slot->Parameters.DeviceIoControl.IoControlCode != IOCTL_STORAGE_QUERY_PROPERTY
        || Slot->Parameters.DeviceIoControl.InputBufferLength < sizeof(STORAGE_PROPERTY_QUERY)
        || Irp->AssociatedIrp.SystemBuffer == NULL) {
        return Ext;                       // no capture needed
    }

    query = (PSTORAGE_PROPERTY_QUERY)Irp->AssociatedIrp.SystemBuffer;
    ctx = (PMYARK_HWID_QUERY_CTX)MyArkAllocatePool(NonPagedPoolNx,
                                                   sizeof(MYARK_HWID_QUERY_CTX),
                                                   MYARK_HWID_SPOOF_POOL_TAG);
    if (ctx == NULL) {
        return Ext;                       // fail open: pass-through, no rewrite
    }
    ctx->Magic = MYARK_HWID_QUERY_CTX_MAGIC;
    ctx->PropertyId = query->PropertyId;
    ctx->Ext = Ext;
    return ctx;
}

VOID
MyArkHwidFreeQueryContext(_In_ PVOID Context)
{
    if (MyArkHwidIsQueryCtx(Context)) {
        ExFreePoolWithTag(Context, MYARK_HWID_SPOOF_POOL_TAG);
        return;
    }
    if (Context != NULL
        && ((PMYARK_HWID_ARP_CTX)Context)->Magic == MYARK_HWID_ARP_CTX_MAGIC) {
        ExFreePoolWithTag(Context, MYARK_HWID_ARP_POOL_TAG);
    }
}

//
// Spoof snapshot for the completion path: copies the spoof bytes to a
// stack buffer under the shared lock (no pool work at DISPATCH).
//
static
BOOLEAN
MyArkHwidSpoofSnapshot(
    _In_  PMYARK_HWID_SPOOF_CLASS_STATE State,
    _Out_ PUCHAR                        Spoof,
    _Out_ PULONG                        SpoofLen)
{
    ULONG oldIrql;

    oldIrql = MyArkHwidSpoofLockShared();
    if (!State->Active || !State->CacheValid || State->SpoofLen == 0) {
        MyArkHwidSpoofUnlockShared(oldIrql);
        return FALSE;
    }
    *SpoofLen = State->SpoofLen;
    RtlCopyMemory(Spoof, State->Spoof, State->SpoofLen);
    MyArkHwidSpoofUnlockShared(oldIrql);
    return TRUE;
}

//
// Rewrite the serial string of a STORAGE_DEVICE_DESCRIPTOR at Base
// (TotalLen = valid bytes). Offsets inside the descriptor are relative
// to Base.
//
static
VOID
MyArkHwidRewriteDescriptorSerial(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ PUCHAR                        Base,
    _In_ ULONG                         TotalLen,
    _In_ PUCHAR                        Spoof,
    _In_ ULONG                         SpoofLen)
{
    PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)Base;
    ULONG off;
    ULONG avail;
    ULONG origLen;
    ULONG copy;

    if (TotalLen < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return;
    }
    off = desc->SerialNumberOffset;
    if (off == 0 || off >= TotalLen) {
        return;
    }
    avail = TotalLen - off;
    origLen = 0;
    while (origLen < avail && Base[off + origLen] != 0) {
        origLen++;
    }
    if (origLen == 0) {
        return;
    }
    // Cap at the original string extent: the rewrite never writes past
    // the serial's own NUL, so descriptor neighbours stay untouched.
    copy = (SpoofLen < origLen) ? SpoofLen : origLen;
    RtlCopyMemory(Base + off, Spoof, copy);
    Base[off + copy] = 0;
    InterlockedIncrement(&State->RewrittenCount);
}

//
// STORAGE_DEVICE_UNIQUE_IDENTIFIER: rewrite the serial string of the
// embedded STORAGE_DEVICE_DESCRIPTOR (StorageDeviceOffset).
//
static
VOID
MyArkHwidRewriteUniqueId(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _Inout_ PUCHAR                     Buf,
    _In_ ULONG                         InfoLen,
    _In_ PUCHAR                        Spoof,
    _In_ ULONG                         SpoofLen)
{
    PSTORAGE_DEVICE_UNIQUE_IDENTIFIER uid = (PSTORAGE_DEVICE_UNIQUE_IDENTIFIER)Buf;
    ULONG descLen;

    if (InfoLen < sizeof(STORAGE_DEVICE_UNIQUE_IDENTIFIER)) {
        return;
    }
    if (uid->StorageDeviceOffset == 0 || uid->StorageDeviceOffset >= InfoLen) {
        return;
    }
    // The embedded STORAGE_DEVICE_DESCRIPTOR runs to the end of the
    // valid response (the DUID struct carries no explicit length for it).
    descLen = InfoLen - uid->StorageDeviceOffset;
    MyArkHwidRewriteDescriptorSerial(State,
                                     Buf + uid->StorageDeviceOffset,
                                     descLen,
                                     Spoof,
                                     SpoofLen);
}

//
// STORAGE_DEVICE_ID_DESCRIPTOR (SCSI VPD page 0x83, R3-1b): rewrite the
// data bytes of every identifier whose length matches the spoof value.
// Each identifier is a raw VPD entry -- CodeSet(1), IdentifierType(1),
// IdentifierLength(2, SPC big-endian) -- followed by the data; the 4-byte
// header stays untouched so consumers still parse the entry. The offset
// array is relative to the descriptor start (Buf).
//
static
VOID
MyArkHwidRewriteDeviceIds(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _Inout_ PUCHAR                     Buf,
    _In_ ULONG                         InfoLen,
    _In_ PUCHAR                        Spoof,
    _In_ ULONG                         SpoofLen)
{
    PSTORAGE_DEVICE_ID_DESCRIPTOR desc = (PSTORAGE_DEVICE_ID_DESCRIPTOR)Buf;
    ULONG i;

    if (InfoLen < sizeof(STORAGE_DEVICE_ID_DESCRIPTOR)
        || desc->NumberOfIdentifiers == 0
        || desc->NumberOfIdentifiers > 64
        || InfoLen < FIELD_OFFSET(STORAGE_DEVICE_ID_DESCRIPTOR, Identifiers)
                        + (SIZE_T)desc->NumberOfIdentifiers * sizeof(ULONG)) {
        return;                       // P2 (review): bounds-check the array
    }
    for (i = 0; i < desc->NumberOfIdentifiers; i++) {
        ULONG off = desc->Identifiers[i];
        ULONG avail;
        ULONG lenBE;
        ULONG lenLE;
        ULONG len;

        if (off < 4 || off >= InfoLen) {
            continue;
        }
        avail = InfoLen - off;
        if (avail < 4) {
            continue;
        }
        lenBE = ((ULONG)Buf[off + 2] << 8) | Buf[off + 3];
        lenLE = ((ULONG)Buf[off + 3] << 8) | Buf[off + 2];
        len = (lenBE <= avail - 4) ? lenBE
                                   : ((lenLE <= avail - 4) ? lenLE : 0);
        if (len == 0 || len != SpoofLen) {
            continue;                     // length-gated: headers untouched
        }
        RtlCopyMemory(Buf + off + 4, Spoof, SpoofLen);
        InterlockedIncrement(&State->RewrittenCount);
    }
}

//
// GPT partition-id rewrite (per-partition query). The MBR flavor rewrites
// only the layout signature (see RewriteDriveLayout): MBR partition
// entries carry no per-partition identifier.
//

static
VOID
MyArkHwidRewritePartitionInfo(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _Inout_ PUCHAR                     Buf,
    _In_ ULONG                         InfoLen,
    _In_ const GUID*                   SpoofGuid)
{
    PPARTITION_INFORMATION_EX pie = (PPARTITION_INFORMATION_EX)Buf;

    if (InfoLen < sizeof(PARTITION_INFORMATION_EX)) {
        return;
    }
    if (pie->PartitionStyle != PARTITION_STYLE_GPT) {
        return;
    }
    pie->Gpt.PartitionId = *SpoofGuid;
    InterlockedIncrement(&State->RewrittenCount);
}

static
VOID
MyArkHwidRewriteDriveLayout(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _Inout_ PUCHAR                     Buf,
    _In_ ULONG                         InfoLen,
    _In_ PUCHAR                        Spoof,
    _In_ ULONG                         SpoofLen)
{
    PDRIVE_LAYOUT_INFORMATION_EX layout = (PDRIVE_LAYOUT_INFORMATION_EX)Buf;
    PPARTITION_INFORMATION_EX entry;
    SIZE_T needed;
    ULONG i;

    if (InfoLen < sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {
        return;
    }

    if (layout->PartitionStyle == PARTITION_STYLE_MBR) {
        // MBR flavor: the disk signature is the stable identifier.
        if (SpoofLen == sizeof(ULONG)
            && InfoLen >= FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, Mbr)
                          + sizeof(DRIVE_LAYOUT_INFORMATION_MBR)) {
            layout->Mbr.Signature = *(const ULONG*)Spoof;
            InterlockedIncrement(&State->RewrittenCount);
        }
        return;
    }

    if (layout->PartitionStyle != PARTITION_STYLE_GPT) {
        return;
    }
    if (layout->PartitionCount == 0 || layout->PartitionCount > 1024) {
        return;
    }
    needed = FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry)
             + (SIZE_T)layout->PartitionCount * sizeof(PARTITION_INFORMATION_EX);
    if (InfoLen < needed) {
        return;
    }
    entry = layout->PartitionEntry;
    for (i = 0; i < layout->PartitionCount; i++) {
        if (entry[i].PartitionStyle == PARTITION_STYLE_GPT
            && RtlCompareMemory(&entry[i].Gpt.PartitionId,
                                &MyArkHwidZeroGuid,
                                sizeof(GUID)) == sizeof(GUID)) {
            continue;                     // empty slot, leave zeroed
        }
        if (entry[i].PartitionStyle == PARTITION_STYLE_GPT) {
            entry[i].Gpt.PartitionId = *(const GUID*)Spoof;
            InterlockedIncrement(&State->RewrittenCount);
        }
    }
}

//
// Completion dispatcher (called from the router's control completion in
// hwid_spoof_state.c). Context is the captured per-IRP ctx or the filter
// extension.
//
VOID
MyArkHwidRewriteControlBuffer(
    _In_ PVOID   Context,
    _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION slot;
    PMYARK_HWID_FILTER_EXT ext;
    PMYARK_HWID_SPOOF_CLASS_STATE state;
    PUCHAR sysBuf;
    ULONG info;
    ULONG code;
    ULONG propertyId = (ULONG)-1;
    UCHAR spoof[MYARK_HWID_SPOOF_VALUE_MAX_BYTES];
    ULONG spoofLen = 0;

    slot = IoGetCurrentIrpStackLocation(Irp);
    ext = MyArkHwidExtFromContext(Context);
    state = MyArkHwidSpoofClassState(ext->Class);
    if (state == NULL) {
        return;
    }

    if (NT_SUCCESS(Irp->IoStatus.Status)) {
        InterlockedIncrement(&state->QueryCount);
    }

    sysBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    info = (ULONG)Irp->IoStatus.Information;
    if (sysBuf == NULL || info == 0) {
        return;
    }
    if (MyArkHwidIsQueryCtx(Context)) {
        propertyId = ((PMYARK_HWID_QUERY_CTX)Context)->PropertyId;
    }
    if (!MyArkHwidSpoofSnapshot(state, spoof, &spoofLen)) {
        return;
    }

    code = slot->Parameters.DeviceIoControl.IoControlCode;
    switch (ext->Class) {
    case MYARK_HWID_SPOOF_CLASS_DISK_SERIAL:
        if (code == IOCTL_STORAGE_QUERY_PROPERTY
            && propertyId == StorageDeviceProperty) {
            MyArkHwidRewriteDescriptorSerial(state, sysBuf, info, spoof, spoofLen);
        }
        break;

    case MYARK_HWID_SPOOF_CLASS_MOUNTMGR_UID:
        if (code == IOCTL_STORAGE_QUERY_PROPERTY
            && propertyId == MYARK_HWID_PROPERTY_UNIQUE_ID) {
            MyArkHwidRewriteUniqueId(state, sysBuf, info, spoof, spoofLen);
        }
        break;

    case MYARK_HWID_SPOOF_CLASS_DEVICE_ID:
        if (code == IOCTL_STORAGE_QUERY_PROPERTY
            && propertyId == StorageDeviceIdProperty) {
            MyArkHwidRewriteDeviceIds(state, sysBuf, info, spoof, spoofLen);
        }
        break;

    case MYARK_HWID_SPOOF_CLASS_PARTITION_GUID:
        if (code == IOCTL_DISK_GET_PARTITION_INFO_EX) {
            // GPT only: MBR partition entries carry no per-partition id.
            MyArkHwidRewritePartitionInfo(state, sysBuf, info, (const GUID*)spoof);
        } else if (code == IOCTL_DISK_GET_DRIVE_LAYOUT_EX) {
            MyArkHwidRewriteDriveLayout(state, sysBuf, info, spoof, spoofLen);
        }
        break;

    default:
        break;
    }
}

//
// Probe plumbing.
//

NTSTATUS
MyArkHwidSpoofProbeControl(
    _In_ PDEVICE_OBJECT TargetDevice,
    _In_ ULONG          Ioctl,
    _In_opt_ PVOID      InputBuf,
    _In_ ULONG          InputLen,
    _Out_ PVOID         OutputBuf,
    _In_ ULONG          OutputLen,
    _Out_ PULONG_PTR    Returned)
{
    KEVENT           event;
    PIRP             irp;
    IO_STATUS_BLOCK  iosb;
    NTSTATUS         status;

    *Returned = 0;
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = IoBuildDeviceIoControlRequest(Ioctl,
                                        TargetDevice,
                                        InputBuf,
                                        InputLen,
                                        OutputBuf,
                                        OutputLen,
                                        FALSE,
                                        &event,
                                        &iosb);
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(TargetDevice, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    } else if (!NT_SUCCESS(status)) {
        // Completed-without-completing: the IRP was never handed down, so
        // iosb was never filled -- return the call status, not garbage
        // (observed as bogus 0xF2xxxxxx probe results on 22631).
        return status;
    } else {
        status = iosb.Status;
    }
    *Returned = (ULONG_PTR)iosb.Information;
    return status;
}

//
// Pull the ASCII serial string out of a STORAGE_DEVICE_DESCRIPTOR.
//
static
NTSTATUS
MyArkHwidExtractDescriptorSerial(
    _In_ PUCHAR  Buf,
    _In_ ULONG   TotalLen,
    _Out_ PUCHAR Real,
    _Inout_ PULONG RealLen)
{
    PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)Buf;
    ULONG off;
    ULONG len;
    ULONG maxLen = *RealLen;

    if (TotalLen < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return STATUS_NOT_FOUND;
    }
    off = desc->SerialNumberOffset;
    if (off == 0 || off >= TotalLen) {
        return STATUS_NOT_FOUND;
    }
    len = 0;
    while (off + len < TotalLen && Buf[off + len] != 0) {
        len++;
    }
    if (len == 0) {
        return STATUS_NOT_FOUND;
    }
    if (len > maxLen) {
        len = maxLen;
    }
    RtlCopyMemory(Real, Buf + off, len);
    *RealLen = len;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkHwidSpoofProbeDiskSerial(
    _In_ PDEVICE_OBJECT TargetDevice,
    _Out_ PUCHAR        Real,
    _Inout_ PULONG      RealLen)
{
    STORAGE_PROPERTY_QUERY query;
    PUCHAR out;
    ULONG_PTR returned = 0;
    NTSTATUS status;

    out = (PUCHAR)MyArkAllocatePool(NonPagedPoolNx,
                                    MYARK_HWID_PROBE_OUT_BYTES,
                                    MYARK_HWID_SPOOF_POOL_TAG);
    if (out == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    status = MyArkHwidSpoofProbeControl(TargetDevice,
                                        IOCTL_STORAGE_QUERY_PROPERTY,
                                        &query,
                                        sizeof(query),
                                        out,
                                        MYARK_HWID_PROBE_OUT_BYTES,
                                        &returned);
    if (NT_SUCCESS(status)) {
        status = MyArkHwidExtractDescriptorSerial(out,
                                                  (ULONG)returned,
                                                  Real,
                                                  RealLen);
    }
    ExFreePoolWithTag(out, MYARK_HWID_SPOOF_POOL_TAG);
    return status;
}

NTSTATUS
MyArkHwidSpoofProbeUniqueId(
    _In_ PDEVICE_OBJECT TargetDevice,
    _Out_ PUCHAR        Real,
    _Inout_ PULONG      RealLen)
{
    STORAGE_PROPERTY_QUERY query;
    PUCHAR out;
    ULONG_PTR returned = 0;
    NTSTATUS status;

    out = (PUCHAR)MyArkAllocatePool(NonPagedPoolNx,
                                    MYARK_HWID_PROBE_OUT_BYTES,
                                    MYARK_HWID_SPOOF_POOL_TAG);
    if (out == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    query.PropertyId = MYARK_HWID_PROPERTY_UNIQUE_ID;
    query.QueryType = PropertyStandardQuery;
    status = MyArkHwidSpoofProbeControl(TargetDevice,
                                        IOCTL_STORAGE_QUERY_PROPERTY,
                                        &query,
                                        sizeof(query),
                                        out,
                                        MYARK_HWID_PROBE_OUT_BYTES,
                                        &returned);
    if (NT_SUCCESS(status)) {
        PSTORAGE_DEVICE_UNIQUE_IDENTIFIER uid =
            (PSTORAGE_DEVICE_UNIQUE_IDENTIFIER)out;
        if (returned < sizeof(STORAGE_DEVICE_UNIQUE_IDENTIFIER)
            || uid->StorageDeviceOffset == 0
            || uid->StorageDeviceOffset >= (ULONG)returned) {
            status = STATUS_NOT_FOUND;
        } else {
            ULONG descLen = (ULONG)returned - uid->StorageDeviceOffset;
            status = MyArkHwidExtractDescriptorSerial(
                out + uid->StorageDeviceOffset,
                descLen,
                Real,
                RealLen);
        }
    }
    ExFreePoolWithTag(out, MYARK_HWID_SPOOF_POOL_TAG);
    return status;
}

//
// VPD 0x83 probe: StorageDeviceIdProperty response, the data bytes of
// the FIRST identifier (the rewrite is length-gated per identifier, so
// the caller must present a spoof value of this exact length to change
// the first entry).
//
NTSTATUS
MyArkHwidSpoofProbeDeviceId(
    _In_ PDEVICE_OBJECT TargetDevice,
    _Out_ PUCHAR        Real,
    _Inout_ PULONG      RealLen)
{
    STORAGE_PROPERTY_QUERY query;
    PUCHAR out;
    ULONG_PTR returned = 0;
    NTSTATUS status;

    out = (PUCHAR)MyArkAllocatePool(NonPagedPoolNx,
                                    MYARK_HWID_PROBE_OUT_BYTES,
                                    MYARK_HWID_SPOOF_POOL_TAG);
    if (out == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    query.PropertyId = StorageDeviceIdProperty;
    query.QueryType = PropertyStandardQuery;
    status = MyArkHwidSpoofProbeControl(TargetDevice,
                                        IOCTL_STORAGE_QUERY_PROPERTY,
                                        &query,
                                        sizeof(query),
                                        out,
                                        MYARK_HWID_PROBE_OUT_BYTES,
                                        &returned);
    if (NT_SUCCESS(status)) {
        PSTORAGE_DEVICE_ID_DESCRIPTOR desc =
            (PSTORAGE_DEVICE_ID_DESCRIPTOR)out;
        status = STATUS_NOT_FOUND;
        if (returned >= sizeof(STORAGE_DEVICE_ID_DESCRIPTOR)
            && desc->NumberOfIdentifiers != 0
            && desc->NumberOfIdentifiers <= 64) {
            ULONG i;
            for (i = 0; i < desc->NumberOfIdentifiers; i++) {
                ULONG off = desc->Identifiers[i];
                ULONG avail;
                ULONG lenBE;
                ULONG lenLE;
                ULONG len;

                if (off < 4 || off >= (ULONG)returned) {
                    continue;
                }
                avail = (ULONG)returned - off;
                if (avail < 4) {
                    continue;
                }
                lenBE = ((ULONG)out[off + 2] << 8) | out[off + 3];
                lenLE = ((ULONG)out[off + 3] << 8) | out[off + 2];
                len = (lenBE <= avail - 4) ? lenBE
                                           : ((lenLE <= avail - 4) ? lenLE : 0);
                if (len == 0 || len > *RealLen) {
                    continue;
                }
                RtlCopyMemory(Real, out + off + 4, len);
                *RealLen = len;
                status = STATUS_SUCCESS;
                break;
            }
        }
    }
    ExFreePoolWithTag(out, MYARK_HWID_SPOOF_POOL_TAG);
    return status;
}

//
// Partition identifier probe. GPT disks expose a 16-byte PartitionId per
// partition (GET_PARTITION_INFO_EX on the partition device); MBR disks
// expose a 4-byte disk Signature (GET_DRIVE_LAYOUT_EX Mbr.Signature on
// the whole-disk device). The spoof value must match whichever flavor
// the probed style reports (16 or 4 bytes).
//
NTSTATUS
MyArkHwidSpoofProbePartitionId(
    _In_ PDEVICE_OBJECT DiskDevice,
    _In_ PDEVICE_OBJECT PartDevice,
    _Out_ PUCHAR        Real,
    _Inout_ PULONG      RealLen)
{
    UCHAR out[1024];
    ULONG_PTR returned = 0;
    PPARTITION_INFORMATION_EX pie;
    NTSTATUS status;

    status = MyArkHwidSpoofProbeControl(PartDevice,
                                        IOCTL_DISK_GET_PARTITION_INFO_EX,
                                        NULL,
                                        0,
                                        out,
                                        sizeof(out),
                                        &returned);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (returned < sizeof(PARTITION_INFORMATION_EX)) {
        return STATUS_NOT_FOUND;
    }
    pie = (PPARTITION_INFORMATION_EX)out;

    if (pie->PartitionStyle == PARTITION_STYLE_GPT) {
        if (*RealLen < sizeof(GUID)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(GUID*)Real = pie->Gpt.PartitionId;
        *RealLen = sizeof(GUID);
        return STATUS_SUCCESS;
    }

    if (pie->PartitionStyle != PARTITION_STYLE_MBR) {
        return STATUS_NOT_FOUND;
    }

    // MBR: the signature lives in the drive layout on the disk device.
    status = MyArkHwidSpoofProbeControl(DiskDevice,
                                        IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                                        NULL,
                                        0,
                                        out,
                                        sizeof(out),
                                        &returned);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    {
        PDRIVE_LAYOUT_INFORMATION_EX layout = (PDRIVE_LAYOUT_INFORMATION_EX)out;
        if (returned < FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry)
            || layout->PartitionStyle != PARTITION_STYLE_MBR) {
            return STATUS_NOT_FOUND;
        }
        if (*RealLen < sizeof(ULONG)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(Real, &layout->Mbr.Signature, sizeof(ULONG));
        *RealLen = sizeof(ULONG);
    }
    return STATUS_SUCCESS;
}

//
// Target open helper: \Device\Harddisk<Disk>\Partition<Part>.
//
static
NTSTATUS
MyArkHwidOpenTarget(
    _In_  ULONG            DiskIndex,
    _In_  ULONG            PartitionIndex,
    _Out_ PDEVICE_OBJECT*  DeviceOut,
    _Out_ PFILE_OBJECT*    FileOut)
{
    WCHAR          name[80];
    UNICODE_STRING uni;

    RtlStringCbPrintfW(name,
                       sizeof(name) / sizeof(WCHAR),
                       L"\\Device\\Harddisk%lu\\Partition%lu",
                       DiskIndex,
                       PartitionIndex);
    RtlInitUnicodeString(&uni, name);
    return IoGetDeviceObjectPointer(&uni,
                                    FILE_READ_ATTRIBUTES,
                                    FileOut,
                                    DeviceOut);
}

//
// Attach the per-class stack set. Attachments happen while the class is
// still inactive, so queries pass through untouched until the publish
// step flips Active.
//
static
NTSTATUS
MyArkHwidAttachClassTargets(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ UINT32                           DiskIndex)
{
    WCHAR          name[80];
    UNICODE_STRING uni;
    NTSTATUS       status;
    ULONG          part;

    RtlStringCbPrintfW(name,
                       sizeof(name) / sizeof(WCHAR),
                       L"\\Device\\Harddisk%lu\\Partition0",
                       DiskIndex);
    RtlInitUnicodeString(&uni, name);
    status = MyArkHwidSpoofAttachTarget(State->Class, &uni,
                                        MYARK_HWID_TARGET_DISK, 0, State);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (State->Class != MYARK_HWID_SPOOF_CLASS_PARTITION_GUID) {
        return STATUS_SUCCESS;
    }

    // Partition class: P1..PN (best effort after the mandatory P1).
    for (part = 1; part < MYARK_HWID_SPOOF_MAX_PARTITIONS; part++) {
        RtlStringCbPrintfW(name,
                           sizeof(name) / sizeof(WCHAR),
                           L"\\Device\\Harddisk%lu\\Partition%lu",
                           DiskIndex,
                           part);
        RtlInitUnicodeString(&uni, name);
        status = MyArkHwidSpoofAttachTarget(State->Class, &uni,
                                            MYARK_HWID_TARGET_PARTITION,
                                            part, State);
        if (!NT_SUCCESS(status)) {
            break;                        // first missing partition ends the walk
        }
    }
    return STATUS_SUCCESS;
}

//
// Open the probe targets for one class (disk classes: P0 only; partition
// class: P0 + P1) and run the class probe. Caller dereferences the file
// objects via MyArkHwidCloseTargets.
//
static
NTSTATUS
MyArkHwidProbeForClass(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ UINT32                        DiskIndex,
    _Out_ PDEVICE_OBJECT*              DiskDev,
    _Out_ PFILE_OBJECT*                DiskFile,
    _Out_ PDEVICE_OBJECT*              PartDev,
    _Out_ PFILE_OBJECT*                PartFile,
    _Out_ PUCHAR                       Real,
    _Inout_ PULONG                     RealLen)
{
    NTSTATUS status;

    *DiskDev = NULL;
    *DiskFile = NULL;
    *PartDev = NULL;
    *PartFile = NULL;

    status = MyArkHwidOpenTarget(DiskIndex, 0, DiskDev, DiskFile);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (State->Class == MYARK_HWID_SPOOF_CLASS_PARTITION_GUID) {
        status = MyArkHwidOpenTarget(DiskIndex, 1, PartDev, PartFile);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(*DiskFile);
            *DiskFile = NULL;
            return status;
        }
        return MyArkHwidSpoofProbePartitionId(*DiskDev, *PartDev, Real, RealLen);
    }

    switch (State->Class) {
    case MYARK_HWID_SPOOF_CLASS_DISK_SERIAL:
        status = MyArkHwidSpoofProbeDiskSerial(*DiskDev, Real, RealLen);
        break;
    case MYARK_HWID_SPOOF_CLASS_MOUNTMGR_UID:
        status = MyArkHwidSpoofProbeUniqueId(*DiskDev, Real, RealLen);
        break;
    case MYARK_HWID_SPOOF_CLASS_DEVICE_ID:
        status = MyArkHwidSpoofProbeDeviceId(*DiskDev, Real, RealLen);
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    return status;
}

static
VOID
MyArkHwidCloseTargets(
    _In_opt_ PFILE_OBJECT DiskFile,
    _In_opt_ PFILE_OBJECT PartFile)
{
    if (DiskFile != NULL) {
        ObDereferenceObject(DiskFile);
    }
    if (PartFile != NULL) {
        ObDereferenceObject(PartFile);
    }
}

//
// DRY_RUN: probe the current value with no state change and no
// attachment. Same validation as APPLY so the preview reflects what
// APPLY would accept. The partition class accepts either flavor: the
// spoof length must equal the probed identifier length (16 GPT / 4 MBR).
//
NTSTATUS
MyArkHwidSpoofDiskDryRun(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ UINT32                        DiskIndex,
    _In_ PUCHAR                        Spoof,
    _In_ ULONG                         SpoofLen,
    _Out_ PUCHAR                       Real,
    _Inout_ PULONG                     RealLen)
{
    PDEVICE_OBJECT diskDev = NULL;
    PFILE_OBJECT   diskFile = NULL;
    PDEVICE_OBJECT partDev = NULL;
    PFILE_OBJECT   partFile = NULL;
    NTSTATUS       status;

    UNREFERENCED_PARAMETER(Spoof);

    if (SpoofLen == 0 || SpoofLen > MYARK_HWID_SPOOF_VALUE_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    if (DiskIndex > 63) {
        return STATUS_INVALID_PARAMETER;
    }

    status = MyArkHwidProbeForClass(State, DiskIndex,
                                    &diskDev, &diskFile, &partDev, &partFile,
                                    Real, RealLen);
    MyArkHwidCloseTargets(diskFile, partFile);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (State->Class == MYARK_HWID_SPOOF_CLASS_PARTITION_GUID
            && SpoofLen != *RealLen) {
        return STATUS_INVALID_PARAMETER;   // 16 = GPT id, 4 = MBR signature
    }
    if (State->Class == MYARK_HWID_SPOOF_CLASS_DEVICE_ID
        && SpoofLen != *RealLen) {
        return STATUS_INVALID_PARAMETER;   // VPD 0x83: length-gated rewrite
    }
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkHwidSpoofDiskApply(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ UINT32                           DiskIndex,
    _In_ PUCHAR                           Spoof,
    _In_ ULONG                            SpoofLen,
    _Out_ PUCHAR                          Real,
    _Inout_ PULONG                        RealLen)
{
    PDEVICE_OBJECT diskDev = NULL;
    PFILE_OBJECT   diskFile = NULL;
    PDEVICE_OBJECT partDev = NULL;
    PFILE_OBJECT   partFile = NULL;
    NTSTATUS       status;
    ULONG          oldIrql;

    if (State->Active) {
        return STATUS_INVALID_DEVICE_STATE;   // RESTORE first
    }
    if (SpoofLen == 0 || SpoofLen > MYARK_HWID_SPOOF_VALUE_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    if (DiskIndex > 63) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 1. Probe the hardware value from fresh top-of-stack references
    //    (our filter is not attached yet, so this is the true value).
    //
    status = MyArkHwidProbeForClass(State, DiskIndex,
                                    &diskDev, &diskFile, &partDev, &partFile,
                                    Real, RealLen);
    MyArkHwidCloseTargets(diskFile, partFile);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (State->Class == MYARK_HWID_SPOOF_CLASS_PARTITION_GUID
            && SpoofLen != *RealLen) {
        return STATUS_INVALID_PARAMETER;   // 16 = GPT id, 4 = MBR signature
    }
    if (State->Class == MYARK_HWID_SPOOF_CLASS_DEVICE_ID
        && SpoofLen != *RealLen) {
        return STATUS_INVALID_PARAMETER;   // VPD 0x83: length-gated rewrite
    }

    //
    // 2. Attach the completion-routine filter set at PASSIVE_LEVEL with NO
    //    lock held: IoGetDeviceObjectPointer / IoAttachDeviceToDeviceStackSafe
    //    are PASSIVE-only APIs (they open devices and wait on IRPs). Holding
    //    the class spin lock (IRQL 2) across them deadlocked the whole guest.
    //    AttachTarget takes the exclusive lock only for the brief array
    //    insert; the class stays inactive until step 3, so early completions
    //    pass through untouched.
    //
    status = MyArkHwidAttachClassTargets(State, DiskIndex);
    if (!NT_SUCCESS(status)) {
        MyArkHwidSpoofDetachClassLocked(State);
        return status;
    }

    //
    // 3. Publish: cache the original, set the spoof, flip Active. The
    //    Active re-check under the lock keeps the state machine atomic
    //    even if a second APPLY ever reaches this point.
    //
    oldIrql = MyArkHwidSpoofLockExclusive();
    if (State->Active) {
        MyArkHwidSpoofUnlockExclusive(oldIrql);
        MyArkHwidSpoofDetachClassLocked(State);
        return STATUS_INVALID_DEVICE_STATE;
    }
    State->DiskIndex = DiskIndex;
    State->SpoofLen = SpoofLen;
    RtlCopyMemory(State->Spoof, Spoof, SpoofLen);
    State->CacheLen = *RealLen;
    RtlCopyMemory(State->Cache, Real, *RealLen);
    State->CacheValid = TRUE;
    State->Active = TRUE;
    State->LastStatus = STATUS_SUCCESS;
    MyArkHwidSpoofUnlockExclusive(oldIrql);

    return STATUS_SUCCESS;
}

NTSTATUS
MyArkHwidSpoofDiskRestore(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _Out_ PUCHAR                          Real,
    _Inout_ PULONG                        RealLen)
{
    UCHAR          cache[MYARK_HWID_SPOOF_VALUE_MAX_BYTES];
    ULONG          cacheLen = 0;
    BOOLEAN        hadCache;
    PDEVICE_OBJECT diskDev = NULL;
    PFILE_OBJECT   diskFile = NULL;
    PDEVICE_OBJECT partDev = NULL;
    PFILE_OBJECT   partFile = NULL;
    NTSTATUS       status;
    ULONG          oldIrql;
    BOOLEAN        match;

    //
    // Stop rewriting first (completions then pass through untouched), and
    // snapshot the cache under the exclusive lock. The detach itself runs
    // OUTSIDE the lock: IoDetachDevice/IoDeleteDevice/ObDereferenceObject
    // are PASSIVE-only APIs.
    //
    oldIrql = MyArkHwidSpoofLockExclusive();
    hadCache = State->CacheValid;
    cacheLen = State->CacheLen;
    RtlCopyMemory(cache, State->Cache, State->CacheLen);
    State->Active = FALSE;
    State->CacheValid = FALSE;
    State->SpoofLen = 0;
    MyArkHwidSpoofUnlockExclusive(oldIrql);

    if (State->AttachedCount != 0) {
        MyArkHwidSpoofDetachClassLocked(State);
    }

    if (!hadCache) {
        *RealLen = 0;
        State->LastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Re-probe (fresh references, filters gone) and compare against the
    // cached original.
    //
    status = MyArkHwidProbeForClass(State, State->DiskIndex,
                                    &diskDev, &diskFile, &partDev, &partFile,
                                    Real, RealLen);
    MyArkHwidCloseTargets(diskFile, partFile);

    match = NT_SUCCESS(status)
            && (*RealLen == cacheLen)
            && (cacheLen != 0)
            && (RtlCompareMemory(Real, cache, cacheLen) == cacheLen);

    oldIrql = MyArkHwidSpoofLockExclusive();
    State->LastStatus = match ? STATUS_SUCCESS : STATUS_VERIFY_REQUIRED;
    MyArkHwidSpoofUnlockExclusive(oldIrql);

    return match ? STATUS_SUCCESS : (NT_SUCCESS(status) ? STATUS_VERIFY_REQUIRED
                                                        : status);
}

#endif // MYARK_MODULE_HWID
