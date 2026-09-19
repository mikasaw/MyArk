// MyArk process module: cross-view diff (public + PspCidTable + ActiveLinks).
//
// Given the two views collected by process_query.c, walks every picked (kernel)
// record, figures out which of the three views saw it, flags HIDDEN_VIA_DKOM
// for rows missing from public, and writes the merged result into a caller-
// provided output buffer (variable-length row array).

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "process_internal.h"

#if MYARK_MODULE_PROCESS

//
// Build a single MYARK_PROCESS_ENTRY from a picked (kernel) record plus the
// public-Pid set. Helper split out so the IOCTL handler stays small.
//

static
VOID
MyArkProcessCrossviewClassify(
    _Out_ PMYARK_PROCESS_ENTRY Entry,
    _In_ PMYARK_PICKED_PROC Picked,
    _In_reads_(PublicCount) const ULONG* PublicPids,
    _In_ ULONG PublicCount)
{
    UINT8 mask = MYARK_PROCESS_SRC_ACTIVE_LINKS | MYARK_PROCESS_SRC_PSPCIDTABLE;
    UINT8 hidden = MYARK_PROCESS_HIDDEN_NONE;

    //
    // PspCidTable membership check via the documented lookup -- a successful
    // PsLookupProcessByProcessId means PspCidTable still owns the PID.
    //
    if (!MyArkProcessPidIsInPspCidTable(Picked->Pid)) {
        mask &= (UINT8)~MYARK_PROCESS_SRC_PSPCIDTABLE;
    }

    if (MyArkProcessPidIsInPublicView(PublicPids, PublicCount, Picked->Pid)) {
        mask |= MYARK_PROCESS_SRC_PUBLIC;
    } else {
        //
        // In kernel + ActiveLinks but not in public: classic DKOM unlink.
        // The user's PspCidTable lookup is the authoritative answer for
        // "is this PID still alive" -- a process can be doubly hidden by
        // stripping the PspCidTable handle too, but that takes a custom
        // kernel module and is out of scope.
        //
        hidden = MYARK_PROCESS_HIDDEN_VIA_DKOM;
    }

    MyArkProcessFillEntryFromPicked(Entry, Picked, mask, hidden);
}


//
// Compute how many bytes an output buffer of `count` rows needs.
//

static
ULONG
MyArkProcessCrossviewBufferSize(
    _In_ ULONG Count)
{
    if (Count == 0) {
        return FIELD_OFFSET(MYARK_PROCESS_CROSSVIEW_OUTPUT, Entries[0]);
    }
    return FIELD_OFFSET(MYARK_PROCESS_CROSSVIEW_OUTPUT, Entries[Count]);
}


NTSTATUS
MyArkProcessBuildCrossview(
    _Out_writes_bytes_to_(BufferSize, *BytesUsed) PUCHAR Buffer,
    _In_  ULONG BufferSize,
    _Out_ PULONG BytesUsed,
    _In_reads_(PublicCount) const ULONG* PublicPids,
    _In_  ULONG PublicCount,
    _In_  PMYARK_PICKED_LIST KernelView,
    _In_  ULONG PidFilter,
    _Out_ PULONG HiddenCountOut)
//
// Walk the kernel view, classify each row, and stream into the caller's
// buffer. Stops when either the kernel list is exhausted or the buffer is
// full. PidFilter == 0 means "every PID"; non-zero restricts to that one.
//
// Returns STATUS_SUCCESS even when no rows fit -- *BytesUsed tells the
// caller how much was actually written, and they can retry with a bigger
// buffer.
//
{
    PMYARK_PROCESS_CROSSVIEW_OUTPUT out = (PMYARK_PROCESS_CROSSVIEW_OUTPUT)Buffer;
    ULONG written = 0;
    ULONG hidden = 0;
    ULONG headerSize = FIELD_OFFSET(MYARK_PROCESS_CROSSVIEW_OUTPUT, Entries[0]);

    *BytesUsed = 0;
    *HiddenCountOut = 0;

    if (BufferSize < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(Buffer, headerSize);

    for (ULONG i = 0; i < KernelView->Count; i++) {
        PMYARK_PICKED_PROC picked = &KernelView->Items[i];

        if (PidFilter != 0 && picked->Pid != PidFilter) {
            continue;
        }

        ULONG rowSize = (headerSize
                         + (written + 1) * sizeof(MYARK_PROCESS_ENTRY));
        if (rowSize > BufferSize) {
            //
            // Buffer too small to fit another row. Stop early -- caller can
            // retry with a bigger buffer. This branch is what triggers a
            // STATUS_BUFFER_OVERFLOW return below.
            //
            break;
        }

        MyArkProcessCrossviewClassify(&out->Entries[written],
                                      picked,
                                      PublicPids,
                                      PublicCount);
        if (out->Entries[written].Hidden == MYARK_PROCESS_HIDDEN_VIA_DKOM) {
            hidden++;
        }
        written++;
    }

    out->Size        = (UINT32)(headerSize + written * sizeof(MYARK_PROCESS_ENTRY));
    out->Count       = written;
    out->HiddenCount = hidden;

    //
    // PublicOnly: PIDs in public view but missing from the kernel list. A
    // process in public view without an EPROCESS means it has exited (or
    // the public view's data is stale, which is rare). Scan the public
    // list against the kernel view to count those.
    //
    ULONG publicOnly = 0;
    for (ULONG p = 0; p < PublicCount; p++) {
        BOOLEAN found = FALSE;
        for (ULONG k = 0; k < KernelView->Count; k++) {
            if (KernelView->Items[k].Pid == PublicPids[p]) {
                found = TRUE;
                break;
            }
        }
        if (!found) {
            publicOnly++;
        }
    }
    out->PublicOnly = publicOnly;

    *BytesUsed        = out->Size;
    *HiddenCountOut   = hidden;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_PROCESS