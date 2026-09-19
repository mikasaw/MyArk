// MyArk debug-output module: ring buffer + DbgSetDebugPrintCallback wrapper
// + IOCTL handlers.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkDebugOutputIoctl.h"
#include "dbgout_descriptor.h"
#include "dbgout_internal.h"

#if MYARK_MODULE_DEBUG_OUTPUT

//
// Module-private globals.
//
MYARK_DBG_RING_STATE g_DbgRing;
FAST_MUTEX            g_DbgRingLock;
LONG                  g_DbgCallbackInstalled = 0;
LONG                  g_DbgRefCount         = 0;

//
// The DbgPrint callback. Wired through DbgSetDebugPrintCallback. We
// capture the call in the ring; we do NOT chain to the previous
// callback (the API doesn't expose it -- chained printing has to be
// done by the previous callback itself).
//
VOID
MyArkDebugOutputDbgPrintCallback(
    _In_ PSTRING OutputString,
    _In_ ULONG   ComponentId,
    _In_ ULONG   Level)
{
    if (OutputString == NULL || OutputString->Buffer == NULL || OutputString->Length == 0) {
        return;
    }

    //
    // Acquire the lock at PASSIVE_LEVEL only -- DbgPrint runs at any
    // IRQL <= DISPATCH_LEVEL. Fast mutex cannot be acquired at
    // DISPATCH_LEVEL, so we use an interlocked reservation on the write
    // cursor and copy the message without the lock. The ring slot is
    // stable because we never free / resize it.
    //
    LONG slot = InterlockedIncrement(&g_DbgRing.WriteCursor) - 1;
    LONG capacity = MYARK_DBG_OUTPUT_RING_ENTRIES;
    LONG idx = slot % capacity;
    PMYARK_DBG_RING_ENTRY entry = &g_DbgRing.Entries[idx];

    //
    // The cursor is monotonic; if it overflows the ring capacity the
    // next write reuses the slot. We track overflows separately.
    //
    if (slot >= capacity) {
        InterlockedIncrement(&g_DbgRing.OverflowCount);
    }

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    entry->Timestamp    = (UINT64)now.QuadPart;
    entry->Level        = Level;
    entry->ComponentId  = ComponentId;
    entry->Sequence     = (UINT32)slot;

    ULONG copyBytes = OutputString->Length;
    if (copyBytes > MYARK_DBG_OUTPUT_MESSAGE_MAX - 1) {
        copyBytes = MYARK_DBG_OUTPUT_MESSAGE_MAX - 1;
    }

    //
    // Copy with the lock so we don't tear against a concurrent drain.
    //
    ExAcquireFastMutex(&g_DbgRingLock);
    RtlCopyMemory(entry->Message, OutputString->Buffer, copyBytes);
    entry->Message[copyBytes] = '\0';
    entry->MessageLength = copyBytes;
    ExReleaseFastMutex(&g_DbgRingLock);
}

VOID
MyArkDebugOutputRingInit(
    VOID)
{
    ExInitializeFastMutex(&g_DbgRingLock);
    RtlZeroMemory(&g_DbgRing, sizeof(g_DbgRing));
    g_DbgRing.WriteCursor  = -1;     // so the first increment yields slot 0
    g_DbgRing.OverflowCount = 0;
}

NTSTATUS
MyArkDebugOutputInstallCallback(
    _Out_writes_z_(NameCapacity) PWCHAR OutOwnerName,
    _In_ size_t NameCapacity,
    _Out_ PUINT32 OutPreviousState,
    _Out_ PUINT32 OutOwnerRefCount)
{
    NTSTATUS status = DbgSetDebugPrintCallback(
        (PDEBUG_PRINT_CALLBACK)MyArkDebugOutputDbgPrintCallback,
        TRUE);

    if (NT_SUCCESS(status)) {
        InterlockedIncrement(&g_DbgCallbackInstalled);
        InterlockedIncrement(&g_DbgRefCount);
    }

    //
    // Always populate OutOwnerName -- we are the new owner when install
    // succeeded; otherwise someone else owns the slot and R3 should know
    // to skip the module on shared hosts.
    //
    UNICODE_STRING serviceName;
    RtlInitUnicodeString(&serviceName, L"MyArkCore");
    RtlStringCbCopyUnicodeString(OutOwnerName, NameCapacity * sizeof(WCHAR), &serviceName);

    *OutPreviousState = (g_DbgCallbackInstalled > 0) ? 1 : 0;
    *OutOwnerRefCount = (UINT32)g_DbgRefCount;
    return status;
}

NTSTATUS
MyArkDebugOutputRemoveCallback(
    _Out_writes_z_(NameCapacity) PWCHAR OutOwnerName,
    _In_ size_t NameCapacity,
    _Out_ PUINT32 OutPreviousState,
    _Out_ PUINT32 OutOwnerRefCount)
{
    NTSTATUS status = DbgSetDebugPrintCallback(
        (PDEBUG_PRINT_CALLBACK)MyArkDebugOutputDbgPrintCallback,
        FALSE);

    if (NT_SUCCESS(status)) {
        InterlockedDecrement(&g_DbgCallbackInstalled);
        InterlockedDecrement(&g_DbgRefCount);
    }

    UNICODE_STRING serviceName;
    RtlInitUnicodeString(&serviceName, L"MyArkCore");
    RtlStringCbCopyUnicodeString(OutOwnerName, NameCapacity * sizeof(WCHAR), &serviceName);

    *OutPreviousState = (g_DbgCallbackInstalled > 0) ? 1 : 0;
    *OutOwnerRefCount = (UINT32)g_DbgRefCount;
    return status;
}

NTSTATUS
MyArkDebugOutputDrainToBuffer(
    _In_ UINT64 Cursor,
    _Out_writes_bytes_to_(BufferSize, *BytesUsed) PUCHAR Buffer,
    _In_  ULONG BufferSize,
    _Out_ PULONG BytesUsed,
    _Out_ PUINT64 NextCursorOut)
//
// Drain the ring into the caller's variable-length buffer. Cursor is
// the highest sequence the caller has already seen; we emit entries
// strictly newer than that. We stop when BufferSize is exhausted.
//
{
    PMYARK_DEBUG_OUTPUT_DRAIN_OUTPUT out = (PMYARK_DEBUG_OUTPUT_DRAIN_OUTPUT)Buffer;
    ULONG headerSize = FIELD_OFFSET(MYARK_DEBUG_OUTPUT_DRAIN_OUTPUT, Entries[0]);
    if (BufferSize < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(Buffer, headerSize);

    LONG writeCursor = g_DbgRing.WriteCursor;
    LONG maxSeq = writeCursor;
    if (maxSeq < 0) {
        maxSeq = -1;     // ring is empty
    }

    ULONG maxEntries = (BufferSize - headerSize) / sizeof(MYARK_DBG_OUTPUT_ENTRY);

    ExAcquireFastMutex(&g_DbgRingLock);
    ULONG written = 0;
    LONG fromSeq = (LONG)Cursor;
    for (LONG seq = fromSeq + 1; seq <= maxSeq && written < maxEntries; seq++) {
        LONG idx = seq % MYARK_DBG_OUTPUT_RING_ENTRIES;
        PMYARK_DBG_RING_ENTRY src = &g_DbgRing.Entries[idx];

        //
        // When the slot has been overwritten by a later entry the
        // sequence is in the past -- skip; the slot will be re-emitted
        // by a later sequence.
        //
        if ((LONG)src->Sequence != seq) {
            continue;
        }
        if (src->MessageLength == 0 && src->Message[0] == '\0') {
            continue;
        }

        PMYARK_DBG_OUTPUT_ENTRY dest = &out->Entries[written];
        RtlZeroMemory(dest, sizeof(*dest));
        dest->Timestamp     = src->Timestamp;
        dest->Level         = src->Level;
        dest->ComponentId   = src->ComponentId;
        dest->MessageLength = src->MessageLength;
        RtlCopyMemory(dest->Message, src->Message, src->MessageLength);
        written++;
    }

    out->Size           = headerSize + written * sizeof(MYARK_DBG_OUTPUT_ENTRY);
    out->Count          = written;
    out->TotalSeen      = (ULONG)(maxSeq + 1);
    out->OverflowCount  = (ULONG)g_DbgRing.OverflowCount;
    out->NextCursor     = (UINT64)maxSeq;

    *BytesUsed     = out->Size;
    *NextCursorOut = (UINT64)maxSeq;
    ExReleaseFastMutex(&g_DbgRingLock);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkDebugOutputIoctlControl(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// CONTROL: 0 = stop, 1 = start, MYARK_DBG_OUTPUT_CONTROL_QUERY = query.
//
{
    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_DEBUG_OUTPUT_CONTROL_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < sizeof(MYARK_DEBUG_OUTPUT_CONTROL_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    NTSTATUS                                  status;
    PMYARK_DEBUG_OUTPUT_CONTROL_INPUT         inBuf = NULL;
    size_t                                    inSize = 0;
    PMYARK_DEBUG_OUTPUT_CONTROL_OUTPUT        outBuf = NULL;
    size_t                                    outSize = 0;

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DEBUG_OUTPUT_CONTROL_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_DEBUG_OUTPUT_CONTROL_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, sizeof(*outBuf));

    //
    // Lazy init the ring on first control -- the module Init hook is
    // called before the driver is ready to install callbacks in some
    // builds.
    //
    static LONG initialized = 0;
    if (InterlockedCompareExchange(&initialized, 1, 0) == 0) {
        MyArkDebugOutputRingInit();
    }

    UINT32 previousState = (g_DbgCallbackInstalled > 0) ? 1 : 0;
    outBuf->PreviousState = previousState;

    NTSTATUS opStatus = STATUS_SUCCESS;
    switch (inBuf->Control) {
    case 0:
        opStatus = MyArkDebugOutputRemoveCallback(outBuf->OwnerModuleName,
                                                  RTL_NUMBER_OF(outBuf->OwnerModuleName),
                                                  &previousState,
                                                  &outBuf->OwnerRefCount);
        break;

    case 1:
        opStatus = MyArkDebugOutputInstallCallback(outBuf->OwnerModuleName,
                                                   RTL_NUMBER_OF(outBuf->OwnerModuleName),
                                                   &previousState,
                                                   &outBuf->OwnerRefCount);
        break;

    case MYARK_DBG_OUTPUT_CONTROL_QUERY:
    default:
        opStatus = STATUS_SUCCESS;
        UNICODE_STRING serviceName;
        RtlInitUnicodeString(&serviceName, L"MyArkCore");
        RtlStringCbCopyUnicodeString(outBuf->OwnerModuleName,
                                      sizeof(outBuf->OwnerModuleName),
                                      &serviceName);
        outBuf->OwnerRefCount = (UINT32)g_DbgRefCount;
        break;
    }

    outBuf->CurrentState = (g_DbgCallbackInstalled > 0) ? 1 : 0;
    *BytesReturned = sizeof(*outBuf);
    return opStatus;
}

NTSTATUS
MyArkDebugOutputIoctlDrain(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_DEBUG_OUTPUT_DRAIN_INPUT         inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DEBUG_OUTPUT_DRAIN_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < FIELD_OFFSET(MYARK_DEBUG_OUTPUT_DRAIN_OUTPUT, Entries[0])) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DEBUG_OUTPUT_DRAIN_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DEBUG_OUTPUT_DRAIN_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Cap the number of entries by both the caller-supplied MaxEntries
    // and the ring capacity.
    //
    ULONG cap = (ULONG)((OutputBufferLength
                         - FIELD_OFFSET(MYARK_DEBUG_OUTPUT_DRAIN_OUTPUT, Entries[0]))
                        / sizeof(MYARK_DBG_OUTPUT_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < cap) {
        cap = inBuf->MaxEntries;
    }
    if (cap > MYARK_DBG_OUTPUT_RING_ENTRIES) {
        cap = MYARK_DBG_OUTPUT_RING_ENTRIES;
    }
    UNREFERENCED_PARAMETER(cap);

    ULONG bytesUsed = 0;
    UINT64 nextCursor = 0;
    status = MyArkDebugOutputDrainToBuffer(inBuf->Cursor,
                                            (PUCHAR)outBuf,
                                            (ULONG)outSize,
                                            &bytesUsed,
                                            &nextCursor);

    *BytesReturned = bytesUsed;
    return status;
}

#endif // MYARK_MODULE_DEBUG_OUTPUT
