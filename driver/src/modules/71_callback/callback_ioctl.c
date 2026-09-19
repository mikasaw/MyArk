// MyArk callback module: 10 IOCTL handlers.
//
// All 10 handlers follow the MyArk IOCTL convention: fetch input/output
// buffers via MyArkIoctlFetch* helpers, validate sizes, then walk the
// resolved kernel data structure into the caller's variable-length
// output. None of the walks touch the un-resolved path -- when a symbol
// is absent on the running build the handler returns STATUS_SUCCESS with
// Count=0 so R3 clients render an empty table instead of getting a
// STATUS_NOT_FOUND exception.
//
// All walks defend against the BSOD-on-corrupt-list class of bugs by
// probing each address with MmIsAddressValid before dereferencing and
// hard-capping iteration counts at the corresponding HARD_CAP constant.
//
// The REMOVE / RESTORE / BACKUP handlers are reserved for the S7.2-fix
// stage: each one returns STATUS_NOT_IMPLEMENTED with an empty payload so
// R3 can probe the IOCTL but no mutating path is reachable.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkCallbackIoctl.h"
#include "callback_descriptor.h"
#include "callback_internal.h"
#include "../../dispatch/safety_token.h"

#if MYARK_MODULE_CALLBACK

//
// ---------------------------------------------------------------------------
// Helpers shared by the QUERY_* handlers.
// ---------------------------------------------------------------------------
//

static
VOID
MyArkCallbackZeroHeader(
    _Out_writes_bytes_(HeaderSize) PUCHAR Buffer,
    _In_                            ULONG  HeaderSize)
{
    RtlZeroMemory(Buffer, HeaderSize);
}

//
// Generic PS array walker. Each PS array is a contiguous array of
// PVOID-sized slots at ArrayBase. We read up to SlotCount slots and emit
// one MYARK_CALLBACK_PS_ENTRY row per populated slot. The SubType lets
// QUERY_PS distinguish between PROCESS / / / IMAGE rows when it walks
// all three arrays back-to-back.
//
static
ULONG
MyArkCallbackWalkPsArray(
    _In_     PVOID  ArrayBase,
    _In_     ULONG  SlotCount,
    _In_     UINT32 SubType,
    _Out_writes_(MaxEntries) PMYARK_CALLBACK_PS_ENTRY OutEntries,
    _In_     ULONG  MaxEntries)
{
    if (ArrayBase == NULL || SlotCount == 0 || MaxEntries == 0) {
        return 0;
    }
    if (!MmIsAddressValid(ArrayBase)) {
        return 0;
    }

    PUCHAR slotBase = (PUCHAR)ArrayBase;
    ULONG written = 0;

    for (ULONG i = 0; i < SlotCount && written < MaxEntries; i++) {
        PVOID slot = (PVOID)(slotBase + (SIZE_T)i * sizeof(PVOID));
        if (!MmIsAddressValid(slot)) {
            continue;
        }

        PVOID callback = *(PVOID*)slot;
        if (callback == NULL) {
            continue;
        }

        PMYARK_CALLBACK_PS_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->Index   = i;
        row->SubType = SubType;
        row->Flags   = MyArkCallbackAddressFlags((UINT64)callback,
                                                  g_MyArkCallbackNtoskrnlTextBase,
                                                  g_MyArkCallbackNtoskrnlTextEnd);
        row->Callback = (UINT64)callback;

        MyArkCallbackResolveDriverName((UINT64)callback,
                                       row->DriverName,
                                       MYARK_CALLBACK_DRIVER_NAME_MAX);

        written++;
    }

    return written;
}

//
// ---------------------------------------------------------------------------
// QUERY_PS: walk PspCreateProcessNotifyRoutine, PspCreateThreadNotifyRoutine,
// and PspLoadImageNotifyRoutine. Each sub-array is read in order, with the
// row's SubType field letting the caller route rows by category.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkCallbackIoctlQueryPs(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_CALLBACK_QUERY_PS_INPUT            inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_CALLBACK_QUERY_PS_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_QUERY_PS_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_CALLBACK_QUERY_PS_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_CALLBACK_QUERY_PS_OUTPUT out = (PMYARK_CALLBACK_QUERY_PS_OUTPUT)outBuf;
    MyArkCallbackZeroHeader((PUCHAR)out,
                            FIELD_OFFSET(MYARK_CALLBACK_QUERY_PS_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_CALLBACK_QUERY_PS_OUTPUT, Entries[0]))
                              / sizeof(MYARK_CALLBACK_PS_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_CALLBACK_PS_HARD_CAP) {
        maxEntries = MYARK_CALLBACK_PS_HARD_CAP;
    }

    UINT32 subMask = inBuf->SubTypeMask;
    if (subMask == 0) {
        subMask = MYARK_CALLBACK_PS_SUBTYPE_PROCESS
                | MYARK_CALLBACK_PS_SUBTYPE_THREAD
                | MYARK_CALLBACK_PS_SUBTYPE_IMAGE;
    }

    ULONG written = 0;
    ULONG totalSeen = 0;

    if ((subMask & MYARK_CALLBACK_PS_SUBTYPE_PROCESS) != 0
        && g_MyArkCallbackPspCreateProcessNotifyRoutine != NULL
        && written < maxEntries) {
        ULONG n = MyArkCallbackWalkPsArray(g_MyArkCallbackPspCreateProcessNotifyRoutine,
                                            MYARK_CALLBACK_PS_PROCESS_SLOTS,
                                            MYARK_CALLBACK_PS_SUBTYPE_PROCESS,
                                            &out->Entries[written],
                                            maxEntries - written);
        written += n;
        totalSeen += MYARK_CALLBACK_PS_PROCESS_SLOTS;
    }

    if ((subMask & MYARK_CALLBACK_PS_SUBTYPE_THREAD) != 0
        && g_MyArkCallbackPspCreateThreadNotifyRoutine != NULL
        && written < maxEntries) {
        ULONG n = MyArkCallbackWalkPsArray(g_MyArkCallbackPspCreateThreadNotifyRoutine,
                                            MYARK_CALLBACK_PS_THREAD_SLOTS,
                                            MYARK_CALLBACK_PS_SUBTYPE_THREAD,
                                            &out->Entries[written],
                                            maxEntries - written);
        written += n;
        totalSeen += MYARK_CALLBACK_PS_THREAD_SLOTS;
    }

    if ((subMask & MYARK_CALLBACK_PS_SUBTYPE_IMAGE) != 0
        && g_MyArkCallbackPspLoadImageNotifyRoutine != NULL
        && written < maxEntries) {
        ULONG n = MyArkCallbackWalkPsArray(g_MyArkCallbackPspLoadImageNotifyRoutine,
                                            MYARK_CALLBACK_PS_IMAGE_SLOTS,
                                            MYARK_CALLBACK_PS_SUBTYPE_IMAGE,
                                            &out->Entries[written],
                                            maxEntries - written);
        written += n;
        totalSeen += MYARK_CALLBACK_PS_IMAGE_SLOTS;
    }

    out->Size                            = (UINT32)(FIELD_OFFSET(MYARK_CALLBACK_QUERY_PS_OUTPUT, Entries[0])
                                                   + written * sizeof(MYARK_CALLBACK_PS_ENTRY));
    out->Count                           = written;
    out->TotalSeen                       = totalSeen;
    out->PspCreateProcessNotifyRoutine   = (UINT64)g_MyArkCallbackPspCreateProcessNotifyRoutine;
    out->PspCreateThreadNotifyRoutine    = (UINT64)g_MyArkCallbackPspCreateThreadNotifyRoutine;
    out->PspLoadImageNotifyRoutine       = (UINT64)g_MyArkCallbackPspLoadImageNotifyRoutine;
    out->EntryStructSize                 = (UINT32)sizeof(MYARK_CALLBACK_PS_ENTRY);
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// QUERY_CM: walk CmpCallbackListHead. Each CALLBACK_OBJECT item embeds
// the callback routine + altitude + cookie; we copy each one into a single
// MYARK_CALLBACK_CM_ENTRY row.
// ---------------------------------------------------------------------------
//

//
// Forward-declared layout of the kernel CALLBACK_OBJECT for the fields
// the callback walker touches. Defined here (not in the public WDK) --
// the offsets are pinned to Win11 24H2 / build 26100.x.
//
typedef struct _MYARK_CALLBACK_CM_ITEM {
    LIST_ENTRY    Link;                  // 0x000
    ULONG         Reserved0;             // 0x008
    ULONG         Reserved1;             // 0x00C
    PVOID         Reserved2;             // 0x010
    PVOID         Reserved3;             // 0x018
    UNICODE_STRING Altitude;             // 0x020 (offset is build-specific; assumed 0x020)
    PVOID         Callback;              // 0x030 (the registration routine)
    UINT64        Cookie;                // 0x038
} MYARK_CALLBACK_CM_ITEM, *PMYARK_CALLBACK_CM_ITEM;

static
ULONG
MyArkCallbackWalkCmList(
    _In_     PVOID  ListHeadAddr,
    _In_     ULONG  HardCap,
    _Out_writes_(MaxEntries) PMYARK_CALLBACK_CM_ENTRY OutEntries,
    _In_     ULONG  MaxEntries)
{
    if (ListHeadAddr == NULL || MaxEntries == 0) {
        return 0;
    }
    if (!MmIsAddressValid(ListHeadAddr)) {
        return 0;
    }

    PLIST_ENTRY head = (PLIST_ENTRY)ListHeadAddr;
    PLIST_ENTRY node = head->Flink;
    ULONG written = 0;
    ULONG iterGuard = HardCap;

    while (node != NULL && node != head && iterGuard > 0 && written < MaxEntries) {
        iterGuard--;
        if (!MmIsAddressValid(node)) {
            break;
        }

        PUCHAR itemBase = (PUCHAR)node - FIELD_OFFSET(MYARK_CALLBACK_CM_ITEM, Link);
        if (!MmIsAddressValid(itemBase)) {
            break;
        }

        PMYARK_CALLBACK_CM_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));

        UNICODE_STRING alt;
        RtlZeroMemory(&alt, sizeof(alt));
        MyArkCallbackSafeRead(itemBase + FIELD_OFFSET(MYARK_CALLBACK_CM_ITEM, Altitude),
                              (PUCHAR)&alt,
                              (ULONG)sizeof(alt));
        PVOID callback = NULL;
        UINT64 cookie = 0;
        MyArkCallbackSafeRead(itemBase + FIELD_OFFSET(MYARK_CALLBACK_CM_ITEM, Callback),
                              (PUCHAR)&callback,
                              (ULONG)sizeof(callback));
        MyArkCallbackSafeRead(itemBase + FIELD_OFFSET(MYARK_CALLBACK_CM_ITEM, Cookie),
                              (PUCHAR)&cookie,
                              (ULONG)sizeof(cookie));

        row->Callback = (UINT64)callback;
        row->Cookie   = cookie;
        row->Flags    = MYARK_CALLBACK_FLAG_POPULATED;
        if (callback != NULL) {
            row->Flags |= MyArkCallbackAddressFlags((UINT64)callback,
                                                     g_MyArkCallbackNtoskrnlTextBase,
                                                     g_MyArkCallbackNtoskrnlTextEnd);
            MyArkCallbackResolveDriverName((UINT64)callback,
                                           row->DriverName,
                                           MYARK_CALLBACK_DRIVER_NAME_MAX);
        }
        if (alt.Buffer != NULL && alt.Length != 0) {
            row->Flags |= MYARK_CALLBACK_FLAG_ALTITUDE;
            MyArkCallbackReadUnicodeString(&alt,
                                           row->Altitude,
                                           MYARK_CALLBACK_NAME_MAX);
        }

        written++;
        node = node->Flink;
    }

    return written;
}

NTSTATUS
MyArkCallbackIoctlQueryCm(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_CALLBACK_QUERY_CM_INPUT            inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_CALLBACK_QUERY_CM_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_QUERY_CM_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_CALLBACK_QUERY_CM_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_CALLBACK_QUERY_CM_OUTPUT out = (PMYARK_CALLBACK_QUERY_CM_OUTPUT)outBuf;
    MyArkCallbackZeroHeader((PUCHAR)out,
                            FIELD_OFFSET(MYARK_CALLBACK_QUERY_CM_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_CALLBACK_QUERY_CM_OUTPUT, Entries[0]))
                              / sizeof(MYARK_CALLBACK_CM_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_CALLBACK_CM_HARD_CAP) {
        maxEntries = MYARK_CALLBACK_CM_HARD_CAP;
    }

    out->CmpCallbackListHead = (UINT64)g_MyArkCallbackCmpCallbackListHead;
    out->EntryStructSize     = (UINT32)sizeof(MYARK_CALLBACK_CM_ENTRY);

    if (g_MyArkCallbackCmpCallbackListHead == NULL
        || !MmIsAddressValid(g_MyArkCallbackCmpCallbackListHead)
        || maxEntries == 0) {
        out->Size       = (UINT32)FIELD_OFFSET(MYARK_CALLBACK_QUERY_CM_OUTPUT, Entries[0]);
        out->Count      = 0;
        out->TotalSeen  = 0;
        *BytesReturned  = out->Size;
        return STATUS_SUCCESS;
    }

    ULONG written = MyArkCallbackWalkCmList(g_MyArkCallbackCmpCallbackListHead,
                                            MYARK_CALLBACK_CM_HARD_CAP,
                                            out->Entries,
                                            maxEntries);

    out->Size       = (UINT32)(FIELD_OFFSET(MYARK_CALLBACK_QUERY_CM_OUTPUT, Entries[0])
                               + written * sizeof(MYARK_CALLBACK_CM_ENTRY));
    out->Count      = written;
    out->TotalSeen  = written;
    *BytesReturned  = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// QUERY_OB: walk ObCallbackListHead. Layout mirrors the Cm item; the
// altitude string is named differently in Ob but lives at the same offset.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_CALLBACK_OB_ITEM {
    LIST_ENTRY    Link;                  // 0x000
    ULONG         Reserved0;             // 0x008
    ULONG         Operation;             // 0x00C (process-handle vs thread-handle)
    PVOID         PreOperation;          // 0x010
    PVOID         PostOperation;         // 0x018
    UNICODE_STRING Altitude;             // 0x020
    UINT64        AltitudeVa;            // 0x030
    UINT64        Cookie;                // 0x038
} MYARK_CALLBACK_OB_ITEM, *PMYARK_CALLBACK_OB_ITEM;

static
ULONG
MyArkCallbackWalkObList(
    _In_     PVOID  ListHeadAddr,
    _In_     ULONG  HardCap,
    _Out_writes_(MaxEntries) PMYARK_CALLBACK_OB_ENTRY OutEntries,
    _In_     ULONG  MaxEntries)
{
    if (ListHeadAddr == NULL || MaxEntries == 0) {
        return 0;
    }
    if (!MmIsAddressValid(ListHeadAddr)) {
        return 0;
    }

    PLIST_ENTRY head = (PLIST_ENTRY)ListHeadAddr;
    PLIST_ENTRY node = head->Flink;
    ULONG written = 0;
    ULONG iterGuard = HardCap;

    while (node != NULL && node != head && iterGuard > 0 && written < MaxEntries) {
        iterGuard--;
        if (!MmIsAddressValid(node)) {
            break;
        }

        PUCHAR itemBase = (PUCHAR)node - FIELD_OFFSET(MYARK_CALLBACK_OB_ITEM, Link);
        if (!MmIsAddressValid(itemBase)) {
            break;
        }

        PMYARK_CALLBACK_OB_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));

        UINT32 operation = 0;
        PVOID preOp = NULL;
        UNICODE_STRING alt;
        UINT64 altVa = 0;
        UINT64 cookie = 0;
        RtlZeroMemory(&alt, sizeof(alt));
        MyArkCallbackSafeRead(itemBase + FIELD_OFFSET(MYARK_CALLBACK_OB_ITEM, Operation),
                              (PUCHAR)&operation,
                              (ULONG)sizeof(operation));
        MyArkCallbackSafeRead(itemBase + FIELD_OFFSET(MYARK_CALLBACK_OB_ITEM, PreOperation),
                              (PUCHAR)&preOp,
                              (ULONG)sizeof(preOp));
        MyArkCallbackSafeRead(itemBase + FIELD_OFFSET(MYARK_CALLBACK_OB_ITEM, Altitude),
                              (PUCHAR)&alt,
                              (ULONG)sizeof(alt));
        MyArkCallbackSafeRead(itemBase + FIELD_OFFSET(MYARK_CALLBACK_OB_ITEM, AltitudeVa),
                              (PUCHAR)&altVa,
                              (ULONG)sizeof(altVa));
        MyArkCallbackSafeRead(itemBase + FIELD_OFFSET(MYARK_CALLBACK_OB_ITEM, Cookie),
                              (PUCHAR)&cookie,
                              (ULONG)sizeof(cookie));

        row->Index     = written;
        row->Operation = (operation != 0)
                       ? MYARK_CALLBACK_OB_OPERATION_THREAD
                       : MYARK_CALLBACK_OB_OPERATION_PROCESS;
        row->Callback  = (UINT64)preOp;
        row->Altitude  = altVa;
        row->Cookie    = cookie;
        row->Flags     = MYARK_CALLBACK_FLAG_POPULATED;
        if (preOp != NULL) {
            row->Flags |= MyArkCallbackAddressFlags((UINT64)preOp,
                                                     g_MyArkCallbackNtoskrnlTextBase,
                                                     g_MyArkCallbackNtoskrnlTextEnd);
            MyArkCallbackResolveDriverName((UINT64)preOp,
                                           row->DriverName,
                                           MYARK_CALLBACK_DRIVER_NAME_MAX);
        }
        if (alt.Buffer != NULL && alt.Length != 0) {
            row->Flags |= MYARK_CALLBACK_FLAG_ALTITUDE;
            MyArkCallbackReadUnicodeString(&alt,
                                           row->AltitudeString,
                                           MYARK_CALLBACK_NAME_MAX);
        }

        written++;
        node = node->Flink;
    }

    return written;
}

NTSTATUS
MyArkCallbackIoctlQueryOb(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_CALLBACK_QUERY_OB_INPUT            inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_CALLBACK_QUERY_OB_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_QUERY_OB_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_CALLBACK_QUERY_OB_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_CALLBACK_QUERY_OB_OUTPUT out = (PMYARK_CALLBACK_QUERY_OB_OUTPUT)outBuf;
    MyArkCallbackZeroHeader((PUCHAR)out,
                            FIELD_OFFSET(MYARK_CALLBACK_QUERY_OB_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_CALLBACK_QUERY_OB_OUTPUT, Entries[0]))
                              / sizeof(MYARK_CALLBACK_OB_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_CALLBACK_OB_HARD_CAP) {
        maxEntries = MYARK_CALLBACK_OB_HARD_CAP;
    }

    out->ObCallbackListHead = (UINT64)g_MyArkCallbackObCallbackListHead;
    out->EntryStructSize    = (UINT32)sizeof(MYARK_CALLBACK_OB_ENTRY);

    if (g_MyArkCallbackObCallbackListHead == NULL
        || !MmIsAddressValid(g_MyArkCallbackObCallbackListHead)
        || maxEntries == 0) {
        out->Size       = (UINT32)FIELD_OFFSET(MYARK_CALLBACK_QUERY_OB_OUTPUT, Entries[0]);
        out->Count      = 0;
        out->TotalSeen  = 0;
        *BytesReturned  = out->Size;
        return STATUS_SUCCESS;
    }

    ULONG written = MyArkCallbackWalkObList(g_MyArkCallbackObCallbackListHead,
                                            MYARK_CALLBACK_OB_HARD_CAP,
                                            out->Entries,
                                            maxEntries);

    out->Size       = (UINT32)(FIELD_OFFSET(MYARK_CALLBACK_QUERY_OB_OUTPUT, Entries[0])
                               + written * sizeof(MYARK_CALLBACK_OB_ENTRY));
    out->Count      = written;
    out->TotalSeen  = written;
    *BytesReturned  = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// QUERY_IMAGE: read the PspLoadImageNotifyRoutine array. Same layout as
// the PS IMAGE sub-array; emits one row per populated slot.
// ---------------------------------------------------------------------------
//

static
ULONG
MyArkCallbackWalkImageArray(
    _In_     PVOID  ArrayBase,
    _In_     ULONG  SlotCount,
    _Out_writes_(MaxEntries) PMYARK_CALLBACK_IMAGE_ENTRY OutEntries,
    _In_     ULONG  MaxEntries)
{
    if (ArrayBase == NULL || SlotCount == 0 || MaxEntries == 0) {
        return 0;
    }
    if (!MmIsAddressValid(ArrayBase)) {
        return 0;
    }

    PUCHAR slotBase = (PUCHAR)ArrayBase;
    ULONG written = 0;

    for (ULONG i = 0; i < SlotCount && written < MaxEntries; i++) {
        PVOID slot = (PVOID)(slotBase + (SIZE_T)i * sizeof(PVOID));
        if (!MmIsAddressValid(slot)) {
            continue;
        }

        PVOID callback = *(PVOID*)slot;
        if (callback == NULL) {
            continue;
        }

        PMYARK_CALLBACK_IMAGE_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->Index    = i;
        row->Flags    = MyArkCallbackAddressFlags((UINT64)callback,
                                                   g_MyArkCallbackNtoskrnlTextBase,
                                                   g_MyArkCallbackNtoskrnlTextEnd);
        row->Callback = (UINT64)callback;

        MyArkCallbackResolveDriverName((UINT64)callback,
                                       row->DriverName,
                                       MYARK_CALLBACK_DRIVER_NAME_MAX);

        written++;
    }

    return written;
}

NTSTATUS
MyArkCallbackIoctlQueryImage(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                    status;
    PMYARK_CALLBACK_QUERY_IMAGE_INPUT           inBuf = NULL;
    size_t                                      inSize = 0;
    PVOID                                       outBuf = NULL;
    size_t                                      outSize = 0;

    if (InputBufferLength < sizeof(MYARK_CALLBACK_QUERY_IMAGE_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_QUERY_IMAGE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_CALLBACK_QUERY_IMAGE_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_CALLBACK_QUERY_IMAGE_OUTPUT out = (PMYARK_CALLBACK_QUERY_IMAGE_OUTPUT)outBuf;
    MyArkCallbackZeroHeader((PUCHAR)out,
                            FIELD_OFFSET(MYARK_CALLBACK_QUERY_IMAGE_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_CALLBACK_QUERY_IMAGE_OUTPUT, Entries[0]))
                              / sizeof(MYARK_CALLBACK_IMAGE_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_CALLBACK_IMAGE_HARD_CAP) {
        maxEntries = MYARK_CALLBACK_IMAGE_HARD_CAP;
    }

    out->PspLoadImageNotifyRoutine = (UINT64)g_MyArkCallbackPspLoadImageNotifyRoutine;
    out->EntryStructSize           = (UINT32)sizeof(MYARK_CALLBACK_IMAGE_ENTRY);

    if (g_MyArkCallbackPspLoadImageNotifyRoutine == NULL
        || !MmIsAddressValid(g_MyArkCallbackPspLoadImageNotifyRoutine)
        || maxEntries == 0) {
        out->Size       = (UINT32)FIELD_OFFSET(MYARK_CALLBACK_QUERY_IMAGE_OUTPUT, Entries[0]);
        out->Count      = 0;
        out->TotalSeen  = 0;
        *BytesReturned  = out->Size;
        return STATUS_SUCCESS;
    }

    ULONG written = MyArkCallbackWalkImageArray(g_MyArkCallbackPspLoadImageNotifyRoutine,
                                                  MYARK_CALLBACK_IMAGE_SLOTS,
                                                  out->Entries,
                                                  maxEntries);

    out->Size       = (UINT32)(FIELD_OFFSET(MYARK_CALLBACK_QUERY_IMAGE_OUTPUT, Entries[0])
                               + written * sizeof(MYARK_CALLBACK_IMAGE_ENTRY));
    out->Count      = written;
    out->TotalSeen  = MYARK_CALLBACK_IMAGE_SLOTS;
    *BytesReturned  = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// QUERY_DBG: enumerate the kernel debugger object table. The Dbg rows
// include DbgkDebugObjectType (singleton) plus the bound debugger object
// table (4 slots).
// ---------------------------------------------------------------------------
//

static
ULONG
MyArkCallbackWalkDbgTable(
    _Out_writes_(MaxEntries) PMYARK_CALLBACK_DBG_ENTRY OutEntries,
    _In_     ULONG  MaxEntries)
{
    if (MaxEntries == 0) {
        return 0;
    }

    ULONG written = 0;

    //
    // Sub-row 1: the DbgkDebugObjectType pointer (singleton).
    //
    if (g_MyArkCallbackDbgkDebugObjectType != NULL
        && MmIsAddressValid(g_MyArkCallbackDbgkDebugObjectType)
        && written < MaxEntries) {
        PMYARK_CALLBACK_DBG_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->Index   = 0;
        row->SubType = MYARK_CALLBACK_DBG_SUBTYPE_DEBUG;
        row->Object  = (UINT64)g_MyArkCallbackDbgkDebugObjectType;
        row->Flags   = MYARK_CALLBACK_FLAG_POPULATED
                     | MyArkCallbackAddressFlags((UINT64)g_MyArkCallbackDbgkDebugObjectType,
                                                   g_MyArkCallbackNtoskrnlTextBase,
                                                   g_MyArkCallbackNtoskrnlTextEnd);
        written++;
    }

    //
    // Sub-rows 2..N: the bound debugger object table. Each slot holds a
    // pointer to a KDEBUG_OBJECT; populated rows emit an entry. We treat
    // a NULL slot as "not bound".
    //
    if (g_MyArkCallbackPsNtDebuggerObject != NULL
        && MmIsAddressValid(g_MyArkCallbackPsNtDebuggerObject)
        && written < MaxEntries) {
        for (ULONG i = 0; i < MYARK_CALLBACK_DBG_BOUND_SLOTS && written < MaxEntries; i++) {
            PUCHAR slot = (PUCHAR)g_MyArkCallbackPsNtDebuggerObject + (SIZE_T)i * sizeof(PVOID);
            if (!MmIsAddressValid(slot)) {
                continue;
            }
            PVOID obj = *(PVOID*)slot;
            if (obj == NULL) {
                continue;
            }

            PMYARK_CALLBACK_DBG_ENTRY row = &OutEntries[written];
            RtlZeroMemory(row, sizeof(*row));
            row->Index   = i;
            row->SubType = MYARK_CALLBACK_DBG_SUBTYPE_BOUND;
            row->Object  = (UINT64)obj;
            row->Flags   = MYARK_CALLBACK_FLAG_POPULATED;
            written++;
        }
    }

    return written;
}

NTSTATUS
MyArkCallbackIoctlQueryDbg(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_CALLBACK_QUERY_DBG_INPUT           inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_CALLBACK_QUERY_DBG_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_QUERY_DBG_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_CALLBACK_QUERY_DBG_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_CALLBACK_QUERY_DBG_OUTPUT out = (PMYARK_CALLBACK_QUERY_DBG_OUTPUT)outBuf;
    MyArkCallbackZeroHeader((PUCHAR)out,
                            FIELD_OFFSET(MYARK_CALLBACK_QUERY_DBG_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_CALLBACK_QUERY_DBG_OUTPUT, Entries[0]))
                              / sizeof(MYARK_CALLBACK_DBG_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_CALLBACK_DBG_HARD_CAP) {
        maxEntries = MYARK_CALLBACK_DBG_HARD_CAP;
    }

    out->DbgkDebugObjectType = (UINT64)g_MyArkCallbackDbgkDebugObjectType;
    out->EntryStructSize     = (UINT32)sizeof(MYARK_CALLBACK_DBG_ENTRY);

    if (maxEntries == 0) {
        out->Size       = (UINT32)FIELD_OFFSET(MYARK_CALLBACK_QUERY_DBG_OUTPUT, Entries[0]);
        out->Count      = 0;
        out->TotalSeen  = 0;
        *BytesReturned  = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG written = MyArkCallbackWalkDbgTable(out->Entries, maxEntries);

    out->Size       = (UINT32)(FIELD_OFFSET(MYARK_CALLBACK_QUERY_DBG_OUTPUT, Entries[0])
                               + written * sizeof(MYARK_CALLBACK_DBG_ENTRY));
    out->Count      = written;
    out->TotalSeen  = MYARK_CALLBACK_DBG_BOUND_SLOTS + 1;
    *BytesReturned  = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// ENUMERATE: walk all 5 categories and emit a flat list of rows. The
// Category + SubType fields let R3 split the rows back into per-category
// tables without a second round-trip.
// ---------------------------------------------------------------------------
//

//
// Local struct used to ship a count + base pair through the dispatch helpers
// without dragging in the Output struct from the QUERY_* handlers.
//
typedef struct _MYARK_CALLBACK_ENUM_HELPER {
    PMYARK_CALLBACK_ENUM_ENTRY OutEntries;
    ULONG Capacity;
    ULONG Written;
    UINT32 Category;
    UINT32 CategoryCount;
} MYARK_CALLBACK_ENUM_HELPER, *PMYARK_CALLBACK_ENUM_HELPER;

static
VOID
MyArkCallbackEmitEnumRow(
    PMYARK_CALLBACK_ENUM_HELPER Helper,
    UINT32 SubType,
    UINT32 Index,
    PVOID  Callback,
    UINT64 Cookie)
{
    if (Helper == NULL) {
        return;
    }
    if (Helper->Written >= Helper->Capacity) {
        return;
    }

    PMYARK_CALLBACK_ENUM_ENTRY row = &Helper->OutEntries[Helper->Written];
    RtlZeroMemory(row, sizeof(*row));
    row->Category = Helper->Category;
    row->SubType  = SubType;
    row->Index    = Index;
    row->Callback = (UINT64)Callback;
    row->Cookie   = Cookie;
    row->Flags    = MYARK_CALLBACK_FLAG_POPULATED;

    if (Callback != NULL) {
        row->Flags |= MyArkCallbackAddressFlags((UINT64)Callback,
                                                 g_MyArkCallbackNtoskrnlTextBase,
                                                 g_MyArkCallbackNtoskrnlTextEnd);
        MyArkCallbackResolveDriverName((UINT64)Callback,
                                       row->DriverName,
                                       MYARK_CALLBACK_DRIVER_NAME_MAX);
    }

    Helper->Written++;
    Helper->CategoryCount++;
}

NTSTATUS
MyArkCallbackIoctlEnumerate(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                    status;
    PMYARK_CALLBACK_ENUMERATE_INPUT             inBuf = NULL;
    size_t                                      inSize = 0;
    PVOID                                       outBuf = NULL;
    size_t                                      outSize = 0;

    if (InputBufferLength < sizeof(MYARK_CALLBACK_ENUMERATE_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_ENUMERATE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_CALLBACK_ENUMERATE_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_CALLBACK_ENUMERATE_OUTPUT out = (PMYARK_CALLBACK_ENUMERATE_OUTPUT)outBuf;
    MyArkCallbackZeroHeader((PUCHAR)out,
                            FIELD_OFFSET(MYARK_CALLBACK_ENUMERATE_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_CALLBACK_ENUMERATE_OUTPUT, Entries[0]))
                              / sizeof(MYARK_CALLBACK_ENUM_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }

    UINT32 categoryMask = inBuf->CategoryMask;
    if (categoryMask == 0) {
        categoryMask = MYARK_CALLBACK_CATEGORY_PS
                     | MYARK_CALLBACK_CATEGORY_CM
                     | MYARK_CALLBACK_CATEGORY_OB
                     | MYARK_CALLBACK_CATEGORY_IMAGE
                     | MYARK_CALLBACK_CATEGORY_DBG;
    }

    MYARK_CALLBACK_ENUM_HELPER helper;
    helper.OutEntries = out->Entries;
    helper.Capacity   = maxEntries;
    helper.Written    = 0;
    helper.CategoryCount = 0;

    UINT32 psCount = 0, cmCount = 0, obCount = 0, imageCount = 0, dbgCount = 0;

    //
    // PS: emit one row per populated slot across PROCESS / / / IMAGE.
    //
    if ((categoryMask & MYARK_CALLBACK_CATEGORY_PS) != 0) {
        helper.Category     = MYARK_CALLBACK_CATEGORY_PS;
        helper.CategoryCount = 0;

        MYARK_CALLBACK_PS_ENTRY scratch[16];
        for (UINT32 sub = 0; sub < 3 && helper.Written < maxEntries; sub++) {
            PVOID arrayHead = NULL;
            ULONG slotCount = 0;
            UINT32 subType = 0;
            switch (sub) {
            case 0:
                arrayHead = g_MyArkCallbackPspCreateProcessNotifyRoutine;
                slotCount = MYARK_CALLBACK_PS_PROCESS_SLOTS;
                subType   = MYARK_CALLBACK_PS_SUBTYPE_PROCESS;
                break;
            case 1:
                arrayHead = g_MyArkCallbackPspCreateThreadNotifyRoutine;
                slotCount = MYARK_CALLBACK_PS_THREAD_SLOTS;
                subType   = MYARK_CALLBACK_PS_SUBTYPE_THREAD;
                break;
            default:
                arrayHead = g_MyArkCallbackPspLoadImageNotifyRoutine;
                slotCount = MYARK_CALLBACK_PS_IMAGE_SLOTS;
                subType   = MYARK_CALLBACK_PS_SUBTYPE_IMAGE;
                break;
            }
            ULONG n = MyArkCallbackWalkPsArray(arrayHead,
                                                slotCount,
                                                subType,
                                                scratch,
                                                RTL_NUMBER_OF(scratch));
            for (ULONG k = 0; k < n && helper.Written < maxEntries; k++) {
                MyArkCallbackEmitEnumRow(&helper,
                                          scratch[k].SubType,
                                          scratch[k].Index,
                                          (PVOID)scratch[k].Callback,
                                          0);
            }
        }
        psCount = helper.CategoryCount;
    }

    //
    // CM: walk CmpCallbackListHead. The helper does not emit rows itself,
    // so we copy from the QUERY_CM row format into the ENUM row format.
    //
    if ((categoryMask & MYARK_CALLBACK_CATEGORY_CM) != 0
        && g_MyArkCallbackCmpCallbackListHead != NULL
        && MmIsAddressValid(g_MyArkCallbackCmpCallbackListHead)) {
        helper.Category      = MYARK_CALLBACK_CATEGORY_CM;
        helper.CategoryCount = 0;

        MYARK_CALLBACK_CM_ENTRY scratch[16];
        ULONG n = MyArkCallbackWalkCmList(g_MyArkCallbackCmpCallbackListHead,
                                           MYARK_CALLBACK_CM_HARD_CAP,
                                           scratch,
                                           RTL_NUMBER_OF(scratch));
        for (ULONG k = 0; k < n && helper.Written < maxEntries; k++) {
            MyArkCallbackEmitEnumRow(&helper,
                                      0,
                                      scratch[k].Index,
                                      (PVOID)scratch[k].Callback,
                                      scratch[k].Cookie);
            // Inherit DriverName + Altitude from the QUERY_CM scratch.
            PMYARK_CALLBACK_ENUM_ENTRY row = &helper.OutEntries[helper.Written - 1];
            RtlCopyMemory(row->DriverName,
                          scratch[k].DriverName,
                          MYARK_CALLBACK_DRIVER_NAME_MAX);
            if ((scratch[k].Flags & MYARK_CALLBACK_FLAG_ALTITUDE) != 0) {
                RtlCopyMemory(row->Altitude,
                              scratch[k].Altitude,
                              MYARK_CALLBACK_NAME_MAX);
                row->Flags |= MYARK_CALLBACK_FLAG_ALTITUDE;
            }
        }
        cmCount = helper.CategoryCount;
    }

    //
    // OB: walk ObCallbackListHead, mirror into ENUM rows.
    //
    if ((categoryMask & MYARK_CALLBACK_CATEGORY_OB) != 0
        && g_MyArkCallbackObCallbackListHead != NULL
        && MmIsAddressValid(g_MyArkCallbackObCallbackListHead)) {
        helper.Category      = MYARK_CALLBACK_CATEGORY_OB;
        helper.CategoryCount = 0;

        MYARK_CALLBACK_OB_ENTRY scratch[16];
        ULONG n = MyArkCallbackWalkObList(g_MyArkCallbackObCallbackListHead,
                                           MYARK_CALLBACK_OB_HARD_CAP,
                                           scratch,
                                           RTL_NUMBER_OF(scratch));
        for (ULONG k = 0; k < n && helper.Written < maxEntries; k++) {
            MyArkCallbackEmitEnumRow(&helper,
                                      scratch[k].Operation,
                                      scratch[k].Index,
                                      (PVOID)scratch[k].Callback,
                                      scratch[k].Cookie);
            PMYARK_CALLBACK_ENUM_ENTRY row = &helper.OutEntries[helper.Written - 1];
            RtlCopyMemory(row->DriverName,
                          scratch[k].DriverName,
                          MYARK_CALLBACK_DRIVER_NAME_MAX);
            if ((scratch[k].Flags & MYARK_CALLBACK_FLAG_ALTITUDE) != 0) {
                RtlCopyMemory(row->Altitude,
                              scratch[k].AltitudeString,
                              MYARK_CALLBACK_NAME_MAX);
                row->Flags |= MYARK_CALLBACK_FLAG_ALTITUDE;
            }
        }
        obCount = helper.CategoryCount;
    }

    //
    // IMAGE: walk PspLoadImageNotifyRoutine.
    //
    if ((categoryMask & MYARK_CALLBACK_CATEGORY_IMAGE) != 0
        && g_MyArkCallbackPspLoadImageNotifyRoutine != NULL
        && MmIsAddressValid(g_MyArkCallbackPspLoadImageNotifyRoutine)) {
        helper.Category      = MYARK_CALLBACK_CATEGORY_IMAGE;
        helper.CategoryCount = 0;

        MYARK_CALLBACK_IMAGE_ENTRY scratch[16];
        ULONG n = MyArkCallbackWalkImageArray(g_MyArkCallbackPspLoadImageNotifyRoutine,
                                                MYARK_CALLBACK_IMAGE_SLOTS,
                                                scratch,
                                                RTL_NUMBER_OF(scratch));
        for (ULONG k = 0; k < n && helper.Written < maxEntries; k++) {
            MyArkCallbackEmitEnumRow(&helper,
                                      MYARK_CALLBACK_PS_SUBTYPE_IMAGE,
                                      scratch[k].Index,
                                      (PVOID)scratch[k].Callback,
                                      0);
            PMYARK_CALLBACK_ENUM_ENTRY row = &helper.OutEntries[helper.Written - 1];
            RtlCopyMemory(row->DriverName,
                          scratch[k].DriverName,
                          MYARK_CALLBACK_DRIVER_NAME_MAX);
        }
        imageCount = helper.CategoryCount;
    }

    //
    // DBG: DbgkDebugObjectType + bound debugger object table.
    //
    if ((categoryMask & MYARK_CALLBACK_CATEGORY_DBG) != 0) {
        helper.Category      = MYARK_CALLBACK_CATEGORY_DBG;
        helper.CategoryCount = 0;

        MYARK_CALLBACK_DBG_ENTRY scratch[8];
        ULONG n = MyArkCallbackWalkDbgTable(scratch, RTL_NUMBER_OF(scratch));
        for (ULONG k = 0; k < n && helper.Written < maxEntries; k++) {
            MyArkCallbackEmitEnumRow(&helper,
                                      scratch[k].SubType,
                                      scratch[k].Index,
                                      (PVOID)scratch[k].Object,
                                      0);
        }
        dbgCount = helper.CategoryCount;
    }

    out->Size           = (UINT32)(FIELD_OFFSET(MYARK_CALLBACK_ENUMERATE_OUTPUT, Entries[0])
                                   + helper.Written * sizeof(MYARK_CALLBACK_ENUM_ENTRY));
    out->Count          = helper.Written;
    out->TotalSeen      = psCount + cmCount + obCount + imageCount + dbgCount;
    out->PsCount        = psCount;
    out->CmCount        = cmCount;
    out->ObCount        = obCount;
    out->ImageCount     = imageCount;
    out->DbgCount       = dbgCount;
    out->EntryStructSize = (UINT32)sizeof(MYARK_CALLBACK_ENUM_ENTRY);
    *BytesReturned      = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// STATS: cheap per-category totals. The walker reuses the QUERY_* paths
// but only emits one count row per category.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkCallbackIoctlStats(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < sizeof(MYARK_CALLBACK_STATS_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PVOID  outBuf = NULL;
    size_t outSize = 0;
    NTSTATUS status = MyArkIoctlFetchOutputBuffer(Request,
                                                  sizeof(MYARK_CALLBACK_STATS_OUTPUT),
                                                  &outBuf,
                                                  &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_CALLBACK_STATS_OUTPUT out = (PMYARK_CALLBACK_STATS_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));

    //
    // Recompute per-category totals by walking the same QUERY_* arrays.
    // Each walk uses a 64-byte scratch buffer (Size/Count/TotalSeen +
    // Reserved + 3 pointer fields + EntryStructSize + Reserved1 =
    // 32 bytes) so the output size is bounded.
    //
    UCHAR scratch[64];

    if (g_MyArkCallbackPspCreateProcessNotifyRoutine != NULL
        && MmIsAddressValid(g_MyArkCallbackPspCreateProcessNotifyRoutine)) {
        MYARK_CALLBACK_PS_ENTRY local[16];
        ULONG n = MyArkCallbackWalkPsArray(g_MyArkCallbackPspCreateProcessNotifyRoutine,
                                            MYARK_CALLBACK_PS_PROCESS_SLOTS,
                                            MYARK_CALLBACK_PS_SUBTYPE_PROCESS,
                                            local,
                                            RTL_NUMBER_OF(local));
        out->PsCount += n;
    }
    if (g_MyArkCallbackPspCreateThreadNotifyRoutine != NULL
        && MmIsAddressValid(g_MyArkCallbackPspCreateThreadNotifyRoutine)) {
        MYARK_CALLBACK_PS_ENTRY local[16];
        ULONG n = MyArkCallbackWalkPsArray(g_MyArkCallbackPspCreateThreadNotifyRoutine,
                                            MYARK_CALLBACK_PS_THREAD_SLOTS,
                                            MYARK_CALLBACK_PS_SUBTYPE_THREAD,
                                            local,
                                            RTL_NUMBER_OF(local));
        out->PsCount += n;
    }
    if (g_MyArkCallbackPspLoadImageNotifyRoutine != NULL
        && MmIsAddressValid(g_MyArkCallbackPspLoadImageNotifyRoutine)) {
        MYARK_CALLBACK_PS_ENTRY local[16];
        ULONG n = MyArkCallbackWalkPsArray(g_MyArkCallbackPspLoadImageNotifyRoutine,
                                            MYARK_CALLBACK_PS_IMAGE_SLOTS,
                                            MYARK_CALLBACK_PS_SUBTYPE_IMAGE,
                                            local,
                                            RTL_NUMBER_OF(local));
        out->PsCount += n;
    }

    if (g_MyArkCallbackCmpCallbackListHead != NULL
        && MmIsAddressValid(g_MyArkCallbackCmpCallbackListHead)) {
        MYARK_CALLBACK_CM_ENTRY local[16];
        out->CmCount += MyArkCallbackWalkCmList(g_MyArkCallbackCmpCallbackListHead,
                                                  MYARK_CALLBACK_CM_HARD_CAP,
                                                  local,
                                                  RTL_NUMBER_OF(local));
    }

    if (g_MyArkCallbackObCallbackListHead != NULL
        && MmIsAddressValid(g_MyArkCallbackObCallbackListHead)) {
        MYARK_CALLBACK_OB_ENTRY local[16];
        out->ObCount += MyArkCallbackWalkObList(g_MyArkCallbackObCallbackListHead,
                                                   MYARK_CALLBACK_OB_HARD_CAP,
                                                   local,
                                                   RTL_NUMBER_OF(local));
    }

    if (g_MyArkCallbackPspLoadImageNotifyRoutine != NULL
        && MmIsAddressValid(g_MyArkCallbackPspLoadImageNotifyRoutine)) {
        MYARK_CALLBACK_IMAGE_ENTRY local[16];
        out->ImageCount += MyArkCallbackWalkImageArray(g_MyArkCallbackPspLoadImageNotifyRoutine,
                                                        MYARK_CALLBACK_IMAGE_SLOTS,
                                                        local,
                                                        RTL_NUMBER_OF(local));
    }

    MYARK_CALLBACK_DBG_ENTRY localDbg[8];
    out->DbgCount += MyArkCallbackWalkDbgTable(localDbg, RTL_NUMBER_OF(localDbg));

    out->TotalCount = out->PsCount + out->CmCount + out->ObCount
                    + out->ImageCount + out->DbgCount;
    out->Size       = sizeof(MYARK_CALLBACK_STATS_OUTPUT);

    *BytesReturned  = out->Size;
    (void)scratch;                       // reserved for future expansion
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// REMOVE / RESTORE / BACKUP are reserved for the S7.2-fix stage. The
// handlers return STATUS_NOT_IMPLEMENTED with an empty payload so the
// dispatch table entry exists but no mutating path is reachable.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkCallbackIoctlRemove(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    //
    // REMOVE / RESTORE / BACKUP are reserved for the S7.2-fix stage; the
    // handler returns STATUS_NOT_IMPLEMENTED without touching the WDF
    // output buffer so R3 sees the NTSTATUS and degrades gracefully.
    //
    *BytesReturned = 0;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
MyArkCallbackIoctlRestore(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    //
    // REMOVE / RESTORE / BACKUP are reserved for the S7.2-fix stage; the
    // handler returns STATUS_NOT_IMPLEMENTED without touching the WDF
    // output buffer so R3 sees the NTSTATUS and degrades gracefully.
    //
    *BytesReturned = 0;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
MyArkCallbackIoctlBackup(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    //
    // The WDF buffer-fetch helper would be the conventional path, but
    // BACKUP has no input struct and the response is fixed-size. We keep
    // the implementation here so future S7.2-fix work has a single anchor.
    //
    NTSTATUS                                    status;
    PMYARK_CALLBACK_BACKUP_INPUT                inBuf = NULL;
    size_t                                      inSize = 0;
    PVOID                                       outBuf = NULL;
    size_t                                      outSize = 0;

    if (InputBufferLength < sizeof(MYARK_CALLBACK_BACKUP_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_BACKUP_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_CALLBACK_BACKUP_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_CALLBACK_BACKUP_OUTPUT out = (PMYARK_CALLBACK_BACKUP_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    out->Size       = (UINT32)FIELD_OFFSET(MYARK_CALLBACK_BACKUP_OUTPUT, Entries[0]);
    out->Count      = 0;
    out->TotalSeen  = 0;
    out->EntryStructSize = (UINT32)sizeof(MYARK_CALLBACK_ENUM_ENTRY);
    *BytesReturned  = out->Size;
    return STATUS_NOT_IMPLEMENTED;
}


//
// OB_PROTECT_SET (R3-9): SAFETY_TOKEN-gated ADD/REMOVE/CLEAR.
//
NTSTATUS
MyArkCallbackIoctlObProtectSet(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    MYARK_CALLBACK_OB_PROTECT_SET_INPUT snap;
    PMYARK_CALLBACK_OB_PROTECT_SET_INPUT inBuf = NULL;
    PMYARK_CALLBACK_OB_PROTECT_SET_OUTPUT outBuf = NULL;
    size_t inSize = 0;
    size_t outSize = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_CALLBACK_OB_PROTECT_SET_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < sizeof(MYARK_CALLBACK_OB_PROTECT_SET_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_OB_PROTECT_SET_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_CALLBACK_OB_PROTECT_SET_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // METHOD_BUFFERED aliasing: snapshot before zeroing the output.
    snap = *inBuf;
    RtlZeroMemory(outBuf, sizeof(*outBuf));

    status = MyArkSafetyTokenValidate(&snap.Token,
                                      MYARK_CALLBACK_OP_OB_PROTECT_SET,
                                      (UINT32)(UINT_PTR)PsGetCurrentProcessId());
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    status = MyArkObProtSet(snap.Action, snap.Pid, outBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_CALLBACK_OB_PROTECT_SET_OUTPUT);
    return STATUS_SUCCESS;
}

//
// OB_PROTECT_STATUS (R3-9): read-only inventory.
//
NTSTATUS
MyArkCallbackIoctlObProtectStatus(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    PMYARK_CALLBACK_OB_PROTECT_STATUS_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < sizeof(MYARK_CALLBACK_OB_PROTECT_STATUS_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_CALLBACK_OB_PROTECT_STATUS_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkObProtFillStatus(outBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_CALLBACK_OB_PROTECT_STATUS_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_CALLBACK
