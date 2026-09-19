// MyArk process module: top-level IOCTL handlers + entry points that the
// module descriptor table calls. Each handler follows the MYARK_IOCTL_HANDLER
// signature, validates input/output buffers via the core helpers, then
// delegates to the per-feature implementation (enum / crossview / detail /
// actions).
//
// Handlers do not hold any module state of their own -- the actual work
// lives in process_query.c, process_detail.c, process_crossview.c and
// process_actions.c.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "MyArkPoolAlloc.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "safety_token.h"
#include "../../../shared/driver/MyArkProcessIoctl.h"
#include "process_internal.h"

#if MYARK_MODULE_PROCESS

//
// Forward decl for the kernel export we use in ENUM_THREAD. ntddk.h omits
// the process-manager APIs that are not part of the WDM surface; declare
// them here so this translation unit compiles cleanly regardless of header
// ordering.
//
NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);
NTKERNELAPI
NTSTATUS PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD* Thread);


//
// Local enum-output builder: walks a kernel view + public Pid array, fills
// MYARK_PROCESS_ENTRY rows. Used by both MyArkProcessIoctlEnum and
// MyArkProcessIoctlCrossview. The two callers differ only in their output
// struct shape and whether they filter by a single PID.
//

typedef
VOID
(*MYARK_PROCESS_ENUM_ROW_FILLER)(
    _Out_ PMYARK_PROCESS_ENTRY Entry,
    _In_  PMYARK_PICKED_PROC Picked,
    _In_  UINT8 SourceMask,
    _In_  UINT8 Hidden);

static
ULONG
MyArkProcessIoctlRequiredHeaderSize(
    _In_ ULONG EntryCount)
//
// Per-row size of the variable-length output buffer: header (everything up
// to Entries[]) plus EntryCount copies of MYARK_PROCESS_ENTRY.
//
{
    return FIELD_OFFSET(MYARK_PROCESS_ENUM_OUTPUT, Entries[EntryCount]);
}

static
NTSTATUS
MyArkProcessIoctlBuildEnumRows(
    _Out_writes_bytes_to_(BufferSize, *BytesUsed) PUCHAR Buffer,
    _In_  ULONG BufferSize,
    _Out_ PULONG BytesUsed,
    _In_reads_(PublicCount) const ULONG* PublicPids,
    _In_  ULONG PublicCount,
    _In_  BOOLEAN PublicUsable,
    _In_  PMYARK_PICKED_LIST KernelView,
    _In_  ULONG PidFilter,
    _Out_ PULONG HiddenCountOut,
    _Out_ PULONG TotalSeenOut)
//
// Walk the kernel view (every row is in ActiveProcessLinks), classify each
// Picked record, and stream into the caller's variable-length buffer. Used
// by both MyArkProcessIoctlEnum and MyArkProcessIoctlCrossview.
//
{
    PMYARK_PROCESS_ENUM_OUTPUT out = (PMYARK_PROCESS_ENUM_OUTPUT)Buffer;
    ULONG written = 0;
    ULONG hidden = 0;
    ULONG total = 0;
    ULONG headerSize = FIELD_OFFSET(MYARK_PROCESS_ENUM_OUTPUT, Entries[0]);

    *BytesUsed = 0;
    *HiddenCountOut = 0;
    *TotalSeenOut = 0;

    if (BufferSize < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(Buffer, headerSize);

    for (ULONG i = 0; i < KernelView->Count; i++) {
        PMYARK_PICKED_PROC picked = &KernelView->Items[i];

        if (PidFilter != 0 && picked->Pid != PidFilter) {
            continue;
        }

        UINT8 mask = MYARK_PROCESS_SRC_ACTIVE_LINKS | MYARK_PROCESS_SRC_PSPCIDTABLE;
        UINT8 hiddenFlag = MYARK_PROCESS_HIDDEN_NONE;

        if (!MyArkProcessPidIsInPspCidTable(picked->Pid)) {
            mask &= (UINT8)~MYARK_PROCESS_SRC_PSPCIDTABLE;
        }

        //
        // HIDDEN_VIA_DKOM means "the process exists in the kernel list but
        // the public API does not report it". That verdict is only meaningful
        // when the public view actually produced data: if it came back empty
        // (API unavailable on this build), every PID would otherwise be
        // flagged hidden -- 124 false positives on the 1903 test guest.
        //
        if (!PublicUsable) {
            mask &= (UINT8)~MYARK_PROCESS_SRC_PUBLIC;
        } else if (MyArkProcessPidIsInPublicView(PublicPids, PublicCount, picked->Pid)) {
            mask |= MYARK_PROCESS_SRC_PUBLIC;
        } else {
            hiddenFlag = MYARK_PROCESS_HIDDEN_VIA_DKOM;
        }
        total++;

        ULONG rowSize = headerSize + (written + 1) * sizeof(MYARK_PROCESS_ENTRY);
        if (rowSize > BufferSize) {
            break;
        }

        MyArkProcessFillEntryFromPicked(&out->Entries[written],
                                        picked,
                                        mask,
                                        hiddenFlag);
        if (hiddenFlag != MYARK_PROCESS_HIDDEN_NONE) {
            hidden++;
        }
        written++;
    }

    out->Size        = (UINT32)(headerSize + written * sizeof(MYARK_PROCESS_ENTRY));
    out->Count       = written;
    out->TotalSeen   = total;
    out->HiddenCount = hidden;

    *BytesUsed       = out->Size;
    *HiddenCountOut  = hidden;
    *TotalSeenOut    = total;
    return STATUS_SUCCESS;
}


//
// ---------------------------------------------------------------------
// Working buffers for the view-collecting handlers.
//
// MYARK_PICKED_LIST is ~160 KiB and the public-PID array 8 KiB; both are
// far beyond the 12 KiB kernel stack, so they must never be stack locals
// (a stack-local picked list bugchecked the guest with 0x50 as soon as
// this module started loading on Win10). The control device dispatches on
// a sequential queue, so only one handler runs at a time and a single
// shared buffer is safe -- the same pattern the thread module uses for its
// module-range cache. Each handler zeroes what it needs on entry.
//
static MYARK_PICKED_LIST g_ProcessPickedList;
static ULONG             g_ProcessPublicPids[MYARK_PROCESS_PUBLIC_PID_CAP];

//
// ----------------------------------------------------------------- ENUM


NTSTATUS
MyArkProcessIoctlEnum(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// ENUM_PROCESS: returns up to MaxEntries rows for the requested SourceMask.
// The SourceMask currently has no behavioural effect -- the row's SourceMask
// field always reports which of the three views saw the PID; callers post-
// filter on the R3 side. S6.1 documents this for forward compatibility.
//
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    NTSTATUS                          status;
    PMYARK_PROCESS_ENUM_INPUT         inBuf = NULL;
    size_t                            inSize = 0;
    PVOID                             outBuf = NULL;
    size_t                            outSize = 0;

    if (InputBufferLength < sizeof(MYARK_PROCESS_ENUM_INPUT)) {
        status = MyArkIoctlFetchInputBuffer(Request,
                                            0,
                                            (PVOID*)&inBuf,
                                            &inSize);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    } else {
        status = MyArkIoctlFetchInputBuffer(Request,
                                            sizeof(MYARK_PROCESS_ENUM_INPUT),
                                            (PVOID*)&inBuf,
                                            &inSize);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_PROCESS_ENUM_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_PICKED_LIST kernelView = &g_ProcessPickedList;
    PULONG publicPids = g_ProcessPublicPids;
    ULONG publicCount = 0;
    BOOLEAN publicUsable = FALSE;
    ULONG hiddenCount = 0;
    ULONG totalSeen = 0;
    ULONG bytesUsed = 0;

    RtlZeroMemory(kernelView, sizeof(*kernelView));
    RtlZeroMemory(publicPids, MYARK_PROCESS_PUBLIC_PID_CAP * sizeof(ULONG));

    status = MyArkProcessCollectViews(kernelView,
                                      publicPids,
                                      MYARK_PROCESS_PUBLIC_PID_CAP,
                                      &publicCount);
    if (NT_SUCCESS(status)) {
        //
        // A public view whose PIDs never intersect the kernel list is not
        // trustworthy (wrong field offset for this build), and trusting it
        // would flag every process as DKOM-hidden. Require at least one
        // shared PID before using it for the hidden verdict.
        //
        for (ULONG i = 0; i < kernelView->Count && !publicUsable; i++) {
            publicUsable = MyArkProcessPidIsInPublicView(publicPids, publicCount,
                                                         kernelView->Items[i].Pid);
        }
    }
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_PROCESS_ENUM_OUTPUT, Entries[0]));
        ((PMYARK_PROCESS_ENUM_OUTPUT)outBuf)->Size =
            FIELD_OFFSET(MYARK_PROCESS_ENUM_OUTPUT, Entries[0]);
        ((PMYARK_PROCESS_ENUM_OUTPUT)outBuf)->Count = 0;
        *BytesReturned = ((PMYARK_PROCESS_ENUM_OUTPUT)outBuf)->Size;
        return status;
    }

    status = MyArkProcessIoctlBuildEnumRows((PUCHAR)outBuf,
                                            (ULONG)outSize,
                                            &bytesUsed,
                                            publicPids,
                                            publicCount,
                                            publicUsable,
                                            kernelView,
                                            0,
                                            &hiddenCount,
                                            &totalSeen);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = bytesUsed;
    UNREFERENCED_PARAMETER(inBuf);
    return STATUS_SUCCESS;
}


//
// ----------------------------------------------------------------- ENUM_THREAD


static
ULONG
MyArkProcessThreadBufferSize(
    _In_ ULONG Count)
{
    return FIELD_OFFSET(MYARK_PROCESS_ENUM_THREAD_OUTPUT, Entries[Count]);
}


static
NTSTATUS
MyArkProcessFillThreadRow(
    _Out_ PMYARK_THREAD_ENTRY Row,
    _In_  PETHREAD EThread)
//
// Extract one thread's snapshot. ETHREAD offsets live in process_internal.h.
//
{
    if (EThread == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!MmIsAddressValid(EThread)) {
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(Row, sizeof(*Row));

    //
    // Tier A: identity comes from the exported accessors (build-independent);
    // the profile offsets used here before produced garbage TIDs and PIDs on
    // any build other than the one they were extracted from. Tier C detail
    // (state/priority/wait reason) is only read on the profile build.
    //
    Row->Tid = (UINT32)MYARK_THREAD_TID(EThread);

    PEPROCESS owningEp = MYARK_THREAD_PROCESS(EThread);
    if (owningEp != NULL && MmIsAddressValid(owningEp)) {
        Row->OwnerPid = MYARK_PROC_PID(owningEp);
    }

    Row->CreateTime = MYARK_THREAD_CREATETIME(EThread);

    {
        const MYARK_ARK_OFFSETS* offsets = MyArkArkOffsetsGet();
        if (offsets != NULL && offsets->ProfileMatched) {
            Row->State      = *((PUCHAR)((PUCHAR)EThread + MYARK_OFF_ETHREAD_STATE));
            Row->Priority   = *((PUCHAR)((PUCHAR)EThread + MYARK_OFF_ETHREAD_PRIORITY));
            Row->WaitReason = *((PUCHAR)((PUCHAR)EThread + MYARK_OFF_ETHREAD_WAIT_REASON));
        }
    }

    return STATUS_SUCCESS;
}


//
// Enumerate a process's threads WITHOUT any structural offset.
//
// PsLookupThreadByThreadId is an exported accessor and thread IDs are handed
// out in steps of 4, so scanning the plausible TID range and keeping the
// threads whose owner matches is equivalent to walking
// EPROCESS.ThreadListHead -- and it works on every supported build. The
// offset-based walk that used to live here read a profile-only offset and
// silently returned zero threads on the 1903 test guest.
//
// Each hit holds a reference, released as soon as its row is filled.
//
#define MYARK_PROC_TID_SCAN_LIMIT   0x100000UL
#define MYARK_PROC_TID_MISS_RUN     32768UL

static
NTSTATUS
MyArkProcessWalkThreadList(
    _In_  PVOID  EProcess,
    _Out_writes_(MaxEntries) PMYARK_THREAD_ENTRY OutEntries,
    _In_  ULONG  MaxEntries,
    _Out_ PULONG CountOut)
{
    const ULONG targetPid = MYARK_PROC_PID(EProcess);
    ULONG misses = 0;
    ULONG count  = 0;

    *CountOut = 0;

    for (ULONG tid = 4;
         tid < MYARK_PROC_TID_SCAN_LIMIT && count < MaxEntries;
         tid += 4) {

        PETHREAD thread = NULL;
        if (!NT_SUCCESS(PsLookupThreadByThreadId(UlongToHandle(tid), &thread)) ||
            thread == NULL) {
            misses++;
            if (count > 0 && misses >= MYARK_PROC_TID_MISS_RUN) {
                break;
            }
            continue;
        }

        misses = 0;

        PEPROCESS owner = MYARK_THREAD_PROCESS(thread);
        if (owner == EProcess ||
            (owner != NULL && MYARK_PROC_PID(owner) == targetPid)) {
            if (NT_SUCCESS(MyArkProcessFillThreadRow(&OutEntries[count], thread))) {
                count++;
            }
        }

        ObDereferenceObject(thread);
    }

    *CountOut = count;
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkProcessIoctlEnumThread(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// ENUM_THREAD: list threads of a single process. Caller-supplied Pid drives
// the EPROCESS lookup; the thread walk terminates at the list head sentinel.
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                              status;
    PMYARK_PROCESS_ENUM_THREAD_INPUT      inBuf = NULL;
    size_t                                inSize = 0;
    PVOID                                 outBuf = NULL;
    size_t                                outSize = 0;

    if (InputBufferLength < sizeof(MYARK_PROCESS_ENUM_THREAD_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_PROCESS_ENUM_THREAD_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_PROCESS_ENUM_THREAD_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_PROCESS_ENUM_THREAD_OUTPUT out = (PMYARK_PROCESS_ENUM_THREAD_OUTPUT)outBuf;

    //
    // METHOD_BUFFERED: the 16-byte output header zeroed below IS the shared
    // SystemBuffer's first bytes, and the input struct is only 8 bytes, so
    // Pid / MaxEntries must be snapshotted first. Reading Pid afterwards
    // looked up PID 0 and every call failed with STATUS_NOT_FOUND.
    //
    const ULONG requestedPid = inBuf->Pid;
    const ULONG requestedMax = inBuf->MaxEntries;
    inBuf = NULL;

    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_PROCESS_ENUM_THREAD_OUTPUT, Entries[0]));

    PEPROCESS proc = NULL;
    status = PsLookupProcessByProcessId(UlongToHandle(requestedPid), &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        out->Size  = (UINT32)FIELD_OFFSET(MYARK_PROCESS_ENUM_THREAD_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_NOT_FOUND;
    }

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_PROCESS_ENUM_THREAD_OUTPUT, Entries[0]))
                               / sizeof(MYARK_THREAD_ENTRY));
    if (requestedMax != 0 && requestedMax < maxEntries) {
        maxEntries = requestedMax;
    }
    if (maxEntries > MYARK_PROCESS_THREAD_ENUM_MAX_ENTRIES) {
        maxEntries = MYARK_PROCESS_THREAD_ENUM_MAX_ENTRIES;
    }

    ULONG written = 0;
    status = MyArkProcessWalkThreadList(proc,
                                        out->Entries,
                                        maxEntries,
                                        &written);

    out->Size     = (UINT32)MyArkProcessThreadBufferSize(written);
    out->Count    = written;
    out->OwnerPid = requestedPid;
    out->Reserved = 0;

    ObDereferenceObject(proc);
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}


//
// ----------------------------------------------------------------- DETAIL / DETAIL_RUNTIME


NTSTATUS
MyArkProcessIoctlDetail(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// Single-PID deep-dump. Input is a bare UINT32 (Pid) packed in the input
// buffer; output is a single MYARK_PROCESS_DETAIL.
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                       status;
    PULONG                         inBuf = NULL;
    size_t                         inSize = 0;
    PMYARK_PROCESS_DETAIL          outBuf = NULL;
    size_t                         outSize = 0;

    if (InputBufferLength < sizeof(ULONG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(ULONG),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_PROCESS_DETAIL)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_PROCESS_DETAIL),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkProcessFillDetail(outBuf, *inBuf);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, sizeof(*outBuf));
    }
    *BytesReturned = sizeof(*outBuf);
    return status;
}


NTSTATUS
MyArkProcessIoctlDetailRuntime(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                              status;
    PULONG                                inBuf = NULL;
    size_t                                inSize = 0;
    PMYARK_PROCESS_DETAIL_RUNTIME         outBuf = NULL;
    size_t                                outSize = 0;

    if (InputBufferLength < sizeof(ULONG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(ULONG),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_PROCESS_DETAIL_RUNTIME)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_PROCESS_DETAIL_RUNTIME),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkProcessFillDetailRuntime(outBuf, *inBuf);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, sizeof(*outBuf));
    }
    *BytesReturned = sizeof(*outBuf);
    return status;
}


//
// ----------------------------------------------------------------- CROSSVIEW


NTSTATUS
MyArkProcessIoctlCrossview(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// CROSSVIEW: like ENUM but the input Pid filters to a single row (0 = all).
// The output struct is a cross-view-shaped header; the row array reuses
// MYARK_PROCESS_ENTRY so the R3 parser can share code with ENUM.
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                          status;
    PMYARK_PROCESS_CROSSVIEW_INPUT    inBuf = NULL;
    size_t                            inSize = 0;
    PVOID                             outBuf = NULL;
    size_t                            outSize = 0;

    if (InputBufferLength < sizeof(MYARK_PROCESS_CROSSVIEW_INPUT)) {
        status = MyArkIoctlFetchInputBuffer(Request,
                                            0,
                                            (PVOID*)&inBuf,
                                            &inSize);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    } else {
        status = MyArkIoctlFetchInputBuffer(Request,
                                            sizeof(MYARK_PROCESS_CROSSVIEW_INPUT),
                                            (PVOID*)&inBuf,
                                            &inSize);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_PROCESS_CROSSVIEW_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_PICKED_LIST kernelView = &g_ProcessPickedList;
    PULONG publicPids = g_ProcessPublicPids;
    ULONG publicCount = 0;
    BOOLEAN publicUsable = FALSE;
    ULONG hiddenCount = 0;
    ULONG totalSeen = 0;
    ULONG bytesUsed = 0;

    RtlZeroMemory(kernelView, sizeof(*kernelView));
    RtlZeroMemory(publicPids, MYARK_PROCESS_PUBLIC_PID_CAP * sizeof(ULONG));

    status = MyArkProcessCollectViews(kernelView,
                                      publicPids,
                                      MYARK_PROCESS_PUBLIC_PID_CAP,
                                      &publicCount);
    if (NT_SUCCESS(status)) {
        //
        // A public view whose PIDs never intersect the kernel list is not
        // trustworthy (wrong field offset for this build), and trusting it
        // would flag every process as DKOM-hidden. Require at least one
        // shared PID before using it for the hidden verdict.
        //
        for (ULONG i = 0; i < kernelView->Count && !publicUsable; i++) {
            publicUsable = MyArkProcessPidIsInPublicView(publicPids, publicCount,
                                                         kernelView->Items[i].Pid);
        }
    }
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_PROCESS_CROSSVIEW_OUTPUT, Entries[0]));
        ((PMYARK_PROCESS_CROSSVIEW_OUTPUT)outBuf)->Size =
            FIELD_OFFSET(MYARK_PROCESS_CROSSVIEW_OUTPUT, Entries[0]);
        *BytesReturned = ((PMYARK_PROCESS_CROSSVIEW_OUTPUT)outBuf)->Size;
        return status;
    }

    //
    // The cross-view header has a slightly different shape: PublicOnly +
    // HiddenCount instead of TotalSeen / HiddenCount. We compute the rows
    // first, then patch the header.
    //
    ULONG scratchBufferSize = (ULONG)outSize;
    PUCHAR scratch = (PUCHAR)MyArkAllocatePool(PagedPool,
                                             (SIZE_T)scratchBufferSize,
                                             'XpmP');
    if (scratch == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = MyArkProcessIoctlBuildEnumRows(scratch,
                                            scratchBufferSize,
                                            &bytesUsed,
                                            publicPids,
                                            publicCount,
                                            publicUsable,
                                            kernelView,
                                            (inBuf != NULL) ? inBuf->Pid : 0,
                                            &hiddenCount,
                                            &totalSeen);

    if (NT_SUCCESS(status)) {
        PMYARK_PROCESS_CROSSVIEW_OUTPUT dst =
            (PMYARK_PROCESS_CROSSVIEW_OUTPUT)outBuf;
        ULONG publicOnly = 0;
        for (ULONG p = 0; p < publicCount; p++) {
            BOOLEAN found = FALSE;
            for (ULONG k = 0; k < kernelView->Count; k++) {
                if (kernelView->Items[k].Pid == publicPids[p]) {
                    found = TRUE;
                    break;
                }
            }
            if (!found) {
                publicOnly++;
            }
        }

        dst->Size        = bytesUsed;
        dst->Count       = ((PMYARK_PROCESS_ENUM_OUTPUT)scratch)->Count;
        dst->HiddenCount = hiddenCount;
        dst->PublicOnly  = publicOnly;

        //
        // Copy the rows across (skip the enum-output header so we land
        // exactly at the cross-view Entries[]).
        //
        ULONG rowsBytes = bytesUsed
                          - FIELD_OFFSET(MYARK_PROCESS_ENUM_OUTPUT, Entries[0]);
        if (rowsBytes <= outSize - FIELD_OFFSET(MYARK_PROCESS_CROSSVIEW_OUTPUT, Entries[0])) {
            RtlCopyMemory(dst->Entries,
                          scratch + FIELD_OFFSET(MYARK_PROCESS_ENUM_OUTPUT, Entries[0]),
                          rowsBytes);
            *BytesReturned = dst->Size;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }

    ExFreePoolWithTag(scratch, 'XpmP');
    UNREFERENCED_PARAMETER(OutputBufferLength);
    return status;
}


//
// ----------------------------------------------------------------- action IOCTLs
//
// The action helpers in process_actions.c take raw ULONG / UCHAR args; we
// only need to extract them from METHOD_BUFFERED input and pack the output.
// Each handler writes exactly one struct back.


NTSTATUS
MyArkProcessIoctlTerminate(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                       status;
    PMYARK_PROCESS_TERMINATE_INPUT inBuf = NULL;
    size_t                         inSize = 0;
    PVOID                          outBuf = NULL;
    size_t                         outSize = 0;

    if (InputBufferLength < sizeof(MYARK_PROCESS_TERMINATE_INPUT)
        || OutputBufferLength < sizeof(MYARK_PROCESS_TERMINATE_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_PROCESS_TERMINATE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Mutating dispatch: the HMAC safety token must verify before
    // anything touches the target process (dispatch/safety_token.c).
    //
    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_PROCESS_OP_TERMINATE,
                                      inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_PROCESS_TERMINATE_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG innerStatus = STATUS_SUCCESS;
    MyArkProcessPerformTerminate(inBuf->Pid,
                                 inBuf->ExitCode,
                                 &innerStatus);
    NTSTATUS inner = (NTSTATUS)innerStatus;

    PMYARK_PROCESS_TERMINATE_OUTPUT out = (PMYARK_PROCESS_TERMINATE_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    out->Pid            = inBuf->Pid;
    out->Status         = (UINT32)inner;
    out->UsedR0Fallback = NT_SUCCESS(inner) ? 1U : 0U;
    *BytesReturned = sizeof(*out);
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkProcessIoctlSuspend(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                       status;
    PMYARK_PROCESS_SUSPEND_INPUT   inBuf = NULL;
    size_t                         inSize = 0;
    PVOID                          outBuf = NULL;
    size_t                         outSize = 0;

    if (InputBufferLength < sizeof(MYARK_PROCESS_SUSPEND_INPUT)
        || OutputBufferLength < sizeof(MYARK_PROCESS_SUSPEND_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_PROCESS_SUSPEND_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_PROCESS_OP_SUSPEND_RESUME,
                                      inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_PROCESS_SUSPEND_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    NTSTATUS inner = MyArkProcessSuspendOrResume(inBuf->Pid,
                                                 (BOOLEAN)(inBuf->Resume != 0));

    PMYARK_PROCESS_SUSPEND_OUTPUT out = (PMYARK_PROCESS_SUSPEND_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    out->Pid       = inBuf->Pid;
    out->Suspended = (inBuf->Resume == 0 && NT_SUCCESS(inner)) ? 1U : 0U;
    out->Status    = (UINT32)inner;
    *BytesReturned = sizeof(*out);
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkProcessIoctlSetPplLevel(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                         status;
    PMYARK_PROCESS_SET_PPL_INPUT     inBuf = NULL;
    size_t                           inSize = 0;
    PVOID                            outBuf = NULL;
    size_t                           outSize = 0;

    if (InputBufferLength < sizeof(MYARK_PROCESS_SET_PPL_INPUT)
        || OutputBufferLength < sizeof(MYARK_PROCESS_SET_PPL_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_PROCESS_SET_PPL_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_PROCESS_OP_SET_PPL_LEVEL,
                                      inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_PROCESS_SET_PPL_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UCHAR previous = 0;
    NTSTATUS inner = MyArkProcessPerformSetPpl(inBuf->Pid,
                                               inBuf->Level,
                                               inBuf->Audit,
                                               inBuf->Type,
                                               &previous);

    PMYARK_PROCESS_SET_PPL_OUTPUT out = (PMYARK_PROCESS_SET_PPL_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    out->Pid           = inBuf->Pid;
    out->Status        = (UINT32)inner;
    out->PreviousLevel = previous;
    *BytesReturned = sizeof(*out);
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkProcessIoctlSetIntegrity(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                              status;
    PMYARK_PROCESS_SET_INTEGRITY_INPUT    inBuf = NULL;
    size_t                                inSize = 0;
    PVOID                                 outBuf = NULL;
    size_t                                outSize = 0;

    if (InputBufferLength < sizeof(MYARK_PROCESS_SET_INTEGRITY_INPUT)
        || OutputBufferLength < sizeof(MYARK_PROCESS_SET_INTEGRITY_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_PROCESS_SET_INTEGRITY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_PROCESS_OP_SET_INTEGRITY,
                                      inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_PROCESS_SET_INTEGRITY_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG previous = 0;
    NTSTATUS inner = MyArkProcessPerformSetIntegrity(inBuf->Pid,
                                                     inBuf->IntegrityLevel,
                                                     &previous);

    PMYARK_PROCESS_SET_INTEGRITY_OUTPUT out = (PMYARK_PROCESS_SET_INTEGRITY_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    out->Pid               = inBuf->Pid;
    out->Status            = (UINT32)inner;
    out->PreviousIntegrity = previous;
    *BytesReturned = sizeof(*out);
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkProcessIoctlSetVisibility(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                              status;
    PMYARK_PROCESS_SET_VISIBILITY_INPUT   inBuf = NULL;
    size_t                                inSize = 0;
    PVOID                                 outBuf = NULL;
    size_t                                outSize = 0;

    if (InputBufferLength < sizeof(MYARK_PROCESS_SET_VISIBILITY_INPUT)
        || OutputBufferLength < sizeof(MYARK_PROCESS_SET_VISIBILITY_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_PROCESS_SET_VISIBILITY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_PROCESS_OP_SET_VISIBILITY,
                                      inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_PROCESS_SET_VISIBILITY_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UCHAR hidden = 0;
    NTSTATUS inner = MyArkProcessPerformDkom(inBuf->Pid,
                                             (BOOLEAN)(inBuf->Hide != 0),
                                             &hidden);

    PMYARK_PROCESS_SET_VISIBILITY_OUTPUT out = (PMYARK_PROCESS_SET_VISIBILITY_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    out->Pid    = inBuf->Pid;
    out->Status = (UINT32)inner;
    out->Hidden = hidden;
    *BytesReturned = sizeof(*out);
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkProcessIoctlSetSpecialFlags(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_PROCESS_SET_SPECIAL_FLAGS_INPUT    inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_PROCESS_SET_SPECIAL_FLAGS_INPUT)
        || OutputBufferLength < sizeof(MYARK_PROCESS_SET_SPECIAL_FLAGS_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_PROCESS_SET_SPECIAL_FLAGS_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_PROCESS_OP_SET_SPECIAL_FLAGS,
                                      inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_PROCESS_SET_SPECIAL_FLAGS_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG previous = 0;
    NTSTATUS inner = MyArkProcessPerformSetSpecialFlags(inBuf->Pid,
                                                        inBuf->FlagsMask,
                                                        inBuf->FlagsValue,
                                                        &previous);

    PMYARK_PROCESS_SET_SPECIAL_FLAGS_OUTPUT out = (PMYARK_PROCESS_SET_SPECIAL_FLAGS_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    out->Pid            = inBuf->Pid;
    out->Status         = (UINT32)inner;
    out->PreviousFlags  = previous;
    *BytesReturned = sizeof(*out);
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkProcessIoctlDkom(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                   status;
    PMYARK_PROCESS_DKOM_INPUT   inBuf = NULL;
    size_t                     inSize = 0;
    PVOID                      outBuf = NULL;
    size_t                     outSize = 0;

    if (InputBufferLength < sizeof(MYARK_PROCESS_DKOM_INPUT)
        || OutputBufferLength < sizeof(MYARK_PROCESS_DKOM_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_PROCESS_DKOM_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_PROCESS_OP_DKOM,
                                      inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_PROCESS_DKOM_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UCHAR hidden = 0;
    NTSTATUS inner = MyArkProcessPerformDkom(inBuf->Pid,
                                             (BOOLEAN)(inBuf->Action != 0),
                                             &hidden);

    PMYARK_PROCESS_DKOM_OUTPUT out = (PMYARK_PROCESS_DKOM_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    out->Pid    = inBuf->Pid;
    out->Status = (UINT32)inner;
    out->Hidden = hidden;
    *BytesReturned = sizeof(*out);
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkProcessIoctlInject(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                    status;
    PMYARK_PROCESS_INJECT_INPUT inBuf = NULL;
    size_t                      inSize = 0;
    PVOID                       outBuf = NULL;
    size_t                      outSize = 0;

    if (InputBufferLength < sizeof(MYARK_PROCESS_INJECT_INPUT)
        || OutputBufferLength < sizeof(MYARK_PROCESS_INJECT_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_PROCESS_INJECT_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_PROCESS_OP_INJECT,
                                      inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_PROCESS_INJECT_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    NTSTATUS inner = STATUS_SUCCESS;
    ULONG innerStatus = STATUS_SUCCESS;
    MyArkProcessPerformInject(inBuf->Pid,
                              inBuf->Method,
                              inBuf->DllPath,
                              MYARK_PROCESS_PATH_MAX,
                              &innerStatus);
    inner = (NTSTATUS)innerStatus;

    PMYARK_PROCESS_INJECT_OUTPUT out = (PMYARK_PROCESS_INJECT_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    out->Pid            = inBuf->Pid;
    out->Status         = (UINT32)inner;
    out->UsedR0Fallback = (inner == STATUS_NOT_IMPLEMENTED) ? 1U : 0U;
    *BytesReturned = sizeof(*out);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_PROCESS