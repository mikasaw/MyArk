// MyArk thread module: top-level IOCTL handlers + entry points that the
// module descriptor table calls. Each handler follows the MYARK_IOCTL_HANDLER
// signature, validates input/output buffers via the core helpers, then
// delegates to the per-feature implementation (enum / detail / crossview /
// actions).
//
// Handlers do not hold any module state of their own -- the actual work
// lives in thread_query.c, thread_detail.c, thread_crossview.c and
// thread_actions.c.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkThreadIoctl.h"
#include "thread_internal.h"

#if MYARK_MODULE_THREAD

//
// Forward decl for the kernel export we use in ENUM / DETAIL / TERMINATE.
// ntddk.h omits the thread-manager APIs that are not part of the WDM
// surface; declare them here so this translation unit compiles cleanly.
//
NTSTATUS PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD* Thread);
NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);


//
// ----------------------------------------------------------------- ENUM

//
// Working buffers for the view-collecting handlers: MYARK_PICKED_THREAD_LIST
// and MYARK_PUBLIC_THREAD_SET together dwarf the 12 KiB kernel stack, so
// they are module-global (sequential device queue => one handler at a time;
// same pattern as g_MyArkThreadModuleRanges).
//
MYARK_PICKED_THREAD_LIST g_ThreadPickedList;
MYARK_PUBLIC_THREAD_SET  g_ThreadPublicSet;

NTSTATUS
MyArkThreadIoctlEnum(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// ENUM_THREAD: list threads of a single Pid. Caller-supplied Pid drives
// the EPROCESS lookup; the thread walk terminates at the list head sentinel.
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                       status;
    PMYARK_THREAD_ENUM_INPUT       inBuf = NULL;
    size_t                         inSize = 0;
    PVOID                          outBuf = NULL;
    size_t                         outSize = 0;

    if (InputBufferLength < sizeof(MYARK_THREAD_ENUM_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_THREAD_ENUM_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_THREAD_ENUM_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_THREAD_ENUM_OUTPUT out = (PMYARK_THREAD_ENUM_OUTPUT)outBuf;

    //
    // METHOD_BUFFERED: input and output share one SystemBuffer and the input
    // struct is exactly the 16 bytes the header zeroing below would wipe, so
    // Pid / MaxEntries must be snapshotted first. Reading Pid afterwards made
    // every call look up PID 0 and fail with STATUS_NOT_FOUND.
    //
    const ULONG requestedPid = inBuf->Pid;
    const ULONG requestedMax = inBuf->MaxEntries;
    inBuf = NULL;

    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_THREAD_ENUM_OUTPUT, Entries[0]));

    //
    // Resolve the Pid to an EPROCESS and collect the views. We re-use
    // MyArkThreadCollectViews so the kernel-view portion is identical to what
    // CROSSVIEW computes.
    //
    PEPROCESS proc = NULL;
    status = PsLookupProcessByProcessId(UlongToHandle(requestedPid), &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_THREAD_ENUM_OUTPUT, Entries[0]);
        out->Count = 0;
        out->OwnerPid = requestedPid;
        out->AnomalyCount = 0;
        *BytesReturned = out->Size;
        return STATUS_NOT_FOUND;
    }

    PMYARK_PICKED_THREAD_LIST kernelView = &g_ThreadPickedList;
    PMYARK_PUBLIC_THREAD_SET  publicSet  = &g_ThreadPublicSet;
    RtlZeroMemory(kernelView, sizeof(*kernelView));
    RtlZeroMemory(publicSet, sizeof(*publicSet));
    status = MyArkThreadCollectViews(requestedPid, kernelView, publicSet);
    ObDereferenceObject(proc);
    if (!NT_SUCCESS(status)) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_THREAD_ENUM_OUTPUT, Entries[0]);
        out->Count = 0;
        out->OwnerPid = requestedPid;
        out->AnomalyCount = 0;
        *BytesReturned = out->Size;
        return status;
    }

    //
    // Compute the row cap from caller + driver defaults.
    //
    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_THREAD_ENUM_OUTPUT, Entries[0]))
                               / sizeof(MYARK_THREAD_ENTRY));
    if (requestedMax != 0 && requestedMax < maxEntries) {
        maxEntries = requestedMax;
    }
    if (maxEntries > MYARK_THREAD_ENUM_MAX_ENTRIES) {
        maxEntries = MYARK_THREAD_ENUM_MAX_ENTRIES;
    }

    ULONG written = 0;
    ULONG anomalyCount = 0;
    for (ULONG i = 0;
         i < kernelView->Count && written < maxEntries;
         i++) {
        PMYARK_PICKED_THREAD picked = &kernelView->Items[i];

        ULONG rowSize = (ULONG)FIELD_OFFSET(MYARK_THREAD_ENUM_OUTPUT, Entries[0])
                        + (written + 1) * sizeof(MYARK_THREAD_ENTRY);
        if (rowSize > OutputBufferLength) {
            break;
        }

        MYARK_THREAD_ENTRY row;
        RtlZeroMemory(&row, sizeof(row));
        row.Tid          = picked->Tid;
        row.Pid          = picked->OwnerPid;
        row.StartAddress = picked->StartAddress;
        row.EThreadKernelAddress = (UINT64)(ULONG_PTR)picked->EThread;

        //
        // Values came from the collector: reading through picked->EThread is
        // no longer possible because the TID-scan enumerator releases its
        // ETHREAD reference as soon as the row is snapshotted.
        //
        row.State      = picked->State;
        row.Priority   = picked->Priority;
        row.WaitReason = picked->WaitReason;
        row.CreateTime = picked->CreateTime;

        row.Anomaly = MyArkThreadClassifyStartAddress(row.StartAddress,
                                                     row.Module,
                                                     MYARK_THREAD_MODULE_NAME_MAX);
        if (row.Anomaly != MYARK_THREAD_ANOMALY_NONE) {
            anomalyCount++;
        }

        out->Entries[written] = row;
        written++;
    }

    out->Size         = (UINT32)FIELD_OFFSET(MYARK_THREAD_ENUM_OUTPUT, Entries[0])
                        + written * sizeof(MYARK_THREAD_ENTRY);
    out->Count        = written;
    out->OwnerPid     = requestedPid;
    out->AnomalyCount = anomalyCount;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}


//
// ----------------------------------------------------------------- DETAIL / DETAIL_RUNTIME

NTSTATUS
MyArkThreadIoctlDetail(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// Single-TID deep dump. Input is a bare UINT32 (Tid); output is a single
// MYARK_THREAD_DETAIL.
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                       status;
    PULONG                         inBuf = NULL;
    size_t                         inSize = 0;
    PMYARK_THREAD_DETAIL           outBuf = NULL;
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
    if (OutputBufferLength < sizeof(MYARK_THREAD_DETAIL)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_THREAD_DETAIL),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkThreadFillDetail(outBuf, *inBuf);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, sizeof(*outBuf));
    }
    *BytesReturned = sizeof(*outBuf);
    return status;
}


NTSTATUS
MyArkThreadIoctlDetailRuntime(
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
    PMYARK_THREAD_DETAIL_RUNTIME          outBuf = NULL;
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
    if (OutputBufferLength < sizeof(MYARK_THREAD_DETAIL_RUNTIME)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_THREAD_DETAIL_RUNTIME),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkThreadFillDetailRuntime(outBuf, *inBuf);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, sizeof(*outBuf));
    }
    *BytesReturned = sizeof(*outBuf);
    return status;
}


//
// ----------------------------------------------------------------- CROSSVIEW

NTSTATUS
MyArkThreadIoctlCrossview(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// CROSSVIEW: per-Pid three-view classification. The input is a single
// MYARK_THREAD_CROSSVIEW_INPUT with a Tid filter (0 = every TID).
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                          status;
    PMYARK_THREAD_CROSSVIEW_INPUT     inBuf = NULL;
    size_t                            inSize = 0;
    PVOID                             outBuf = NULL;
    size_t                            outSize = 0;

    if (InputBufferLength < sizeof(MYARK_THREAD_CROSSVIEW_INPUT)) {
        status = MyArkIoctlFetchInputBuffer(Request,
                                            0,
                                            (PVOID*)&inBuf,
                                            &inSize);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    } else {
        status = MyArkIoctlFetchInputBuffer(Request,
                                            sizeof(MYARK_THREAD_CROSSVIEW_INPUT),
                                            (PVOID*)&inBuf,
                                            &inSize);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_THREAD_CROSSVIEW_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // The cross-view input doesn't carry a Pid -- the caller supplies one
    // out-of-band (the IOCTL handler uses the same Pid from the most
    // recent ENUM). For now we require Pid=0 semantics; crossview by
    // individual Pid is the most common case the CLI exercises.
    //
    ULONG pid = 0;
    ULONG tidFilter = (inBuf != NULL) ? inBuf->Tid : 0;

    //
    // If the caller has no Pid context we treat TidFilter as the Pid too,
    // matching the existing "enum --pid N" CLI flow. The driver returns
    // an empty result for a Pid=0 crossview.
    //
    if (pid == 0) {
        //
        // Caller is expected to feed us a Pid via the input's Reserved0
        // (lo 16 bits). This is a deliberate protocol extension so the
        // single IOCTL covers both Pid-scoped and Tid-scoped queries.
        //
        if (inBuf != NULL) {
            pid = inBuf->Reserved0;
            if (pid != 0 && tidFilter == 0) {
                tidFilter = 0;
            }
        }
    }

    ULONG bytesUsed = 0;
    ULONG hiddenCount = 0;

    status = MyArkThreadBuildCrossview(pid,
                                       tidFilter,
                                       (PUCHAR)outBuf,
                                       (ULONG)outSize,
                                       &bytesUsed,
                                       &hiddenCount);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_THREAD_CROSSVIEW_OUTPUT, Entries[0]));
        *BytesReturned = FIELD_OFFSET(MYARK_THREAD_CROSSVIEW_OUTPUT, Entries[0]);
        return status;
    }

    *BytesReturned = bytesUsed;
    UNREFERENCED_PARAMETER(OutputBufferLength);
    return STATUS_SUCCESS;
}


//
// ----------------------------------------------------------------- TERMINATE

NTSTATUS
MyArkThreadIoctlTerminate(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
//
// TERMINATE_THREAD: kill one thread by TID. Caller-supplied ExitCode +
// Force flags ride in the input; the driver returns the NTSTATUS.
//
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                        status;
    PMYARK_THREAD_TERMINATE_INPUT   inBuf = NULL;
    size_t                          inSize = 0;
    PVOID                           outBuf = NULL;
    size_t                          outSize = 0;

    if (InputBufferLength < sizeof(MYARK_THREAD_TERMINATE_INPUT)
        || OutputBufferLength < sizeof(MYARK_THREAD_TERMINATE_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_THREAD_TERMINATE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_THREAD_TERMINATE_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG innerStatus = STATUS_SUCCESS;
    MyArkThreadPerformTerminate(inBuf->Tid,
                                inBuf->ExitCode,
                                &innerStatus);
    NTSTATUS inner = (NTSTATUS)innerStatus;

    PMYARK_THREAD_TERMINATE_OUTPUT out = (PMYARK_THREAD_TERMINATE_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));
    out->Tid            = inBuf->Tid;
    out->Status         = (UINT32)inner;
    out->UsedR0Fallback = NT_SUCCESS(inner) ? 1U : 0U;
    *BytesReturned      = sizeof(*out);

    UNREFERENCED_PARAMETER(inBuf->Force);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_THREAD
