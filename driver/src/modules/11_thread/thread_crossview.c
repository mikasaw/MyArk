// MyArk thread module: three-view comparison builder (cross-view IOCTL).
//
// Given a Pid (or all PIDs), walk the kernel ThreadListHead for that Pid,
// look up each thread in the public view + PspCidTable, classify the row,
// and stream MYARK_THREAD_ENTRY records into the caller's variable-length
// output buffer.
//
// View semantics match the cross-view contract documented in
// MyArkThreadIoctl.h:
//   public       = ZwQuerySystemInformation(SystemProcessInformation)
//   thread_list  = EPROCESS.ThreadListHead
//   pspcidtable  = kernel handle table (PsLookupThreadByThreadId)
//
// A TID in ThreadListHead + PspCidTable but missing from public is flagged
// HIDDEN_VIA_DKOM. Renders show this as "ThreadList yes, Public no".

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "thread_internal.h"

#if MYARK_MODULE_THREAD

NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);
NTSTATUS PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD* Thread);


//
// Helper: is a (Pid, Tid) tuple present in the public view?
//
static
BOOLEAN
MyArkThreadIsPublicTid(
    _In_ PMYARK_PUBLIC_THREAD_SET PublicSet,
    _In_ ULONG Pid,
    _In_ ULONG Tid)
{
    for (ULONG i = 0; i < PublicSet->Count; i++) {
        if (PublicSet->Items[i].Pid == Pid
            && PublicSet->Items[i].Tid == Tid) {
            return TRUE;
        }
    }
    return FALSE;
}


NTSTATUS
MyArkThreadBuildCrossview(
    _In_  ULONG  Pid,
    _In_  ULONG  TidFilter,
    _Out_writes_bytes_to_(BufferSize, *BytesUsed) PUCHAR Buffer,
    _In_  ULONG  BufferSize,
    _Out_ PULONG BytesUsed,
    _Out_ PULONG HiddenCountOut)
//
// Build the cross-view output for Pid. TidFilter != 0 restricts to one
// TID; 0 returns every TID. PublicOnly (TIDs in public but missing from
// kernel) is computed and stored in the output header.
//
// Returns STATUS_SUCCESS even when no rows fit; caller can retry with a
// bigger buffer.
//
{
    PMYARK_THREAD_CROSSVIEW_OUTPUT out = (PMYARK_THREAD_CROSSVIEW_OUTPUT)Buffer;
    ULONG headerSize = FIELD_OFFSET(MYARK_THREAD_CROSSVIEW_OUTPUT, Entries[0]);

    *BytesUsed = 0;
    *HiddenCountOut = 0;

    if (BufferSize < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(Buffer, headerSize);

    if (Pid == 0) {
        out->Size  = headerSize;
        out->Count = 0;
        out->PublicOnly = 0;
        out->HiddenCount = 0;
        *BytesUsed = headerSize;
        return STATUS_SUCCESS;
    }

    PMYARK_PICKED_THREAD_LIST kernelView = &g_ThreadPickedList;
    PMYARK_PUBLIC_THREAD_SET  publicSet  = &g_ThreadPublicSet;
    RtlZeroMemory(kernelView, sizeof(*kernelView));
    RtlZeroMemory(publicSet, sizeof(*publicSet));

    NTSTATUS status = MyArkThreadCollectViews(Pid, kernelView, publicSet);
    if (!NT_SUCCESS(status)) {
        out->Size  = headerSize;
        out->Count = 0;
        out->PublicOnly = 0;
        out->HiddenCount = 0;
        *BytesUsed = headerSize;
        return status;
    }

    ULONG written = 0;
    ULONG hidden  = 0;

    for (ULONG i = 0; i < kernelView->Count; i++) {
        PMYARK_PICKED_THREAD picked = &kernelView->Items[i];

        if (TidFilter != 0 && picked->Tid != TidFilter) {
            continue;
        }

        MYARK_THREAD_ENTRY row;
        RtlZeroMemory(&row, sizeof(row));
        row.Tid          = picked->Tid;
        row.Pid          = picked->OwnerPid;
        row.StartAddress = picked->StartAddress;
        row.EThreadKernelAddress = (UINT64)(ULONG_PTR)picked->EThread;

        //
        // Snapshot the rest of the fields from the ETHREAD pointer so the
        // row matches the ENUM output.
        //
        row.State      = picked->State;
        row.Priority   = picked->Priority;
        row.WaitReason = picked->WaitReason;
        row.CreateTime = picked->CreateTime;

        row.Anomaly = MyArkThreadClassifyStartAddress(row.StartAddress,
                                                     row.Module,
                                                     MYARK_THREAD_MODULE_NAME_MAX);

        //
        // Membership probes: PspCidTable first, then public view.
        //
        UINT8 src = MYARK_THREAD_SRC_THREADLIST;

        //
        // PspCidTable via PsLookupThreadByThreadId (increments refcount).
        //
        NTSTATUS psLookup;
        PETHREAD probe = NULL;
        psLookup = PsLookupThreadByThreadId(UlongToHandle(picked->Tid), &probe);
        if (NT_SUCCESS(psLookup) && probe != NULL) {
            src |= MYARK_THREAD_SRC_PSPCIDTABLE;
            ObDereferenceObject(probe);
        }

        if (MyArkThreadIsPublicTid(publicSet, picked->OwnerPid, picked->Tid)) {
            src |= MYARK_THREAD_SRC_PUBLIC;
        } else if ((src & MYARK_THREAD_SRC_PSPCIDTABLE)
                   && (src & MYARK_THREAD_SRC_THREADLIST)) {
            //
            // In kernel + thread_list but missing from public: classic DKOM.
            //
            hidden++;
        }

        UNREFERENCED_PARAMETER(src);

        ULONG rowSize = (headerSize + (written + 1) * sizeof(MYARK_THREAD_ENTRY));
        if (rowSize > BufferSize) {
            break;
        }

        out->Entries[written] = row;
        written++;
    }

    //
    // PublicOnly: TIDs the public view listed but the kernel list didn't.
    // On a healthy system these are the threads that exited between the
    // two snapshots (a benign transient); a sustained nonzero value means
    // some user-mode hook is suppressing them.
    //
    ULONG publicOnly = 0;
    for (ULONG p = 0; p < publicSet->Count; p++) {
        if (publicSet->Items[p].Pid != Pid) {
            continue;
        }
        BOOLEAN found = FALSE;
        for (ULONG k = 0; k < kernelView->Count; k++) {
            if (kernelView->Items[k].Tid == publicSet->Items[p].Tid) {
                found = TRUE;
                break;
            }
        }
        if (!found) {
            publicOnly++;
        }
    }

    out->Size        = (UINT32)(headerSize + written * sizeof(MYARK_THREAD_ENTRY));
    out->Count       = written;
    out->HiddenCount = hidden;
    out->PublicOnly  = publicOnly;

    *BytesUsed       = out->Size;
    *HiddenCountOut  = hidden;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_THREAD
