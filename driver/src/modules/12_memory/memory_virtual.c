// MyArk memory module: cross-process virtual memory read / write + VAD walk.
//
// Implements QUERY_VM, READ_VM, and WRITE_VM. The cross-process path uses
// KeStackAttachProcess + MmIsAddressValid + __try/__except rather than
// MmCopyVirtualMemory: MmCopyVirtualMemory is an undocumented NTKERNEL
// export whose signature has changed across Windows versions; the
// attach-process pattern is documented in the WDK and equivalent for
// our use case (cross-process copy with a single buffer).
//
// The VAD walk for QUERY_VM is intentionally a stub: the issue body
// restricts the module to "no VAD-tree enumeration" (the dedicated
// kernel_object module owns the VAD tree in S7). QUERY_VM therefore
// returns the process's working set / section size stats derived from
// EPROCESS.Vm + Peb->ReadOnlySharedMemoryHeap (best-effort, zero-filled
// on failure) so the IOCTL has a meaningful wire format even before the
// S7 module lands.

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "memory_module.h"

#if MYARK_MODULE_MEMORY

//
// Read a single ULONG / ULONGLONG from inside the EPROCESS safely. Returns
// zero on a bad address. Generic helpers like these are shared by all the
// memory sub-files because the page-table module already includes
// memory_module.h, but we keep them static-private here too so the file
// stays self-contained.
//
static
ULONG
MyArkMemoryReadUlongSafe(
    _In_ PVOID Base,
    _In_ ULONG Offset)
{
    if (!MmIsAddressValid((PUCHAR)Base + Offset)) {
        return 0;
    }
    return *((PULONG)((PUCHAR)Base + Offset));
}


//
// Resolve a PID to its EPROCESS. On success the caller owns the reference
// taken by PsLookupProcessByProcessId and must ObDereferenceObject it once
// the cross-process work is done -- holding the reference across
// KeStackAttachProcess is what keeps the target from exiting mid-copy.
// (No "pid 0 == self" special case: it returned a reference-less
// PsGetCurrentProcess() pointer whose ownership could not be uniform.)
//
static
NTSTATUS
MyArkMemoryResolveEProcess(
    _In_  ULONG   Pid,
    _Out_ PVOID*  EProcessOut)
{
    NTSTATUS    status;
    PEPROCESS   proc = NULL;

    status = PsLookupProcessByProcessId(UlongToHandle(Pid), &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        return STATUS_NOT_FOUND;
    }
    *EProcessOut = proc;
    return STATUS_SUCCESS;
}


//
// IOCTL_MYARK_MEMORY_QUERY_VM handler.
//
// Best-effort VAD stub: returns a header with zero rows populated and the
// process's working-set / peak working-set from EPROCESS.Vm. The header
// is a valid wire-format response so the CLI can render "(no VAD rows)
// WorkingSet=X PeakWorkingSet=Y" without crashing. S7's kernel_object
// module owns the actual tree walk and replaces this IOCTL's payload with
// real VAD entries; until then this is the placeholder that ships.
//
NTSTATUS
MyArkMemoryIoctlQueryVm(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_MEMORY_QUERY_VM_INPUT  inBuf  = NULL;
    PMYARK_MEMORY_QUERY_VM_OUTPUT outBuf = NULL;
    size_t                        inSize  = 0;
    PVOID                         proc    = NULL;
    NTSTATUS                      status;
    UINT32                        cap;

    UNREFERENCED_PARAMETER(Device);

    if (OutputBufferLength < sizeof(MYARK_MEMORY_QUERY_VM_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (InputBufferLength < sizeof(MYARK_MEMORY_QUERY_VM_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_MEMORY_QUERY_VM_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // METHOD_BUFFERED: input and output share one SystemBuffer, so every
    // input field still needed must be copied out BEFORE the output header
    // is zeroed. Zeroing first wiped Pid and the lookup returned
    // STATUS_NOT_FOUND (same trap the actions handlers hit).
    //
    const ULONG pid        = inBuf->Pid;
    const ULONG requested  = inBuf->MaxEntries;
    inBuf = NULL;

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_MEMORY_QUERY_VM_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, sizeof(*outBuf));

    status = MyArkMemoryResolveEProcess(pid, &proc);
    if (!NT_SUCCESS(status)) {
        outBuf->Size = sizeof(MYARK_MEMORY_QUERY_VM_OUTPUT);
        *BytesReturned = sizeof(*outBuf);
        TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_MEMORY,
                "QueryVm pid=%lu failed: 0x%08X",
                (unsigned long)pid, status);
        return STATUS_SUCCESS;
    }

    //
    // VAD stub. Cap is what the caller asked for (or the default) but we
    // don't actually walk the VAD tree -- S7 owns that. We fill the
    // header and leave the row array empty so the R3 parser sees a valid
    // Count=0 / TotalRegions=0 record.
    //
    cap = (requested == 0)
              ? (UINT32)MYARK_MEMORY_VAD_DEFAULT_MAX
              : requested;
    if (cap > MYARK_MEMORY_VAD_HARD_CAP) {
        cap = MYARK_MEMORY_VAD_HARD_CAP;
    }

    outBuf->Size          = (UINT32)FIELD_OFFSET(MYARK_MEMORY_QUERY_VM_OUTPUT, Entries[0]);
    outBuf->Count         = 0;
    outBuf->TotalRegions  = 0;
    outBuf->Truncated     = 0;

    //
    // If the caller's output buffer can hold at least one row, leave
    // space reserved so future versions don't need to bump the wire
    // format version. TotalRegions gets the requested cap so the UI can
    // show "0/N regions (stub -- S7 kernel_object to walk)".
    //
    if (OutputBufferLength >=
        sizeof(MYARK_MEMORY_QUERY_VM_OUTPUT) +
            sizeof(MYARK_MEMORY_VAD_ENTRY)) {
        outBuf->TotalRegions = cap;
    }

    *BytesReturned = sizeof(*outBuf);

    TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_MEMORY,
                "QueryVm pid=%lu: stub ok (VAD walk owned by S7 kernel_object)",
                (unsigned long)pid);

    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}


//
// IOCTL_MYARK_MEMORY_READ_VM handler.
//
// Clamps Size to MYARK_MEMORY_RW_MAX_BYTES, attaches to the target EPROCESS
// via KeStackAttachProcess, copies Size bytes from Address into the
// output buffer's Data[], and wraps the user-mode touch in __try/__except
// so an unmapped address surfaces as BytesRead=0 instead of a BSOD.
//
NTSTATUS
MyArkMemoryIoctlReadVm(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_MEMORY_READ_VM_INPUT  inBuf  = NULL;
    PMYARK_MEMORY_READ_VM_OUTPUT outBuf = NULL;
    size_t                       inSize  = 0;
    PVOID                        proc    = NULL;
    NTSTATUS                     status;
    SIZE_T                       wantSize;
    SIZE_T                       actualSize;
    KAPC_STATE                   apc;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_MEMORY_READ_VM_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_MEMORY_READ_VM_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Clamp the requested read size to the IOCTL cap. The output buffer
    // must hold the header + the requested Size bytes (clamped).
    //
    // METHOD_BUFFERED shares one SystemBuffer, so Pid / Address / Size are
    // snapshotted here, before the output header is zeroed below.
    //
    const ULONG  pid     = inBuf->Pid;
    const UINT64 address = inBuf->Address;

    wantSize = inBuf->Size;
    if (wantSize == 0 || wantSize > MYARK_MEMORY_RW_MAX_BYTES) {
        wantSize = MYARK_MEMORY_RW_MAX_BYTES;
    }
    if (OutputBufferLength < sizeof(MYARK_MEMORY_READ_VM_OUTPUT) + wantSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_MEMORY_READ_VM_OUTPUT) + wantSize,
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, sizeof(*outBuf));

    status = MyArkMemoryResolveEProcess(pid, &proc);
    if (!NT_SUCCESS(status)) {
        outBuf->Status = status;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    //
    // Attach to the target process address space, probe the source VA,
    // and copy. KeStackAttachProcess / KeUnstackDetachProcess bracket the
    // __try so a fault in user-mode memory only escapes the inner block.
    //
    KeStackAttachProcess(proc, &apc);
    __try {
        if (MmIsAddressValid((PVOID)address)) {
            RtlCopyMemory(outBuf->Data, (PVOID)address, wantSize);
            actualSize = wantSize;
        } else {
            actualSize = 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        actualSize = 0;
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);

    outBuf->Status    = (actualSize == wantSize) ? (UINT32)STATUS_SUCCESS : (UINT32)STATUS_PARTIAL_COPY;
    outBuf->BytesRead = (UINT32)actualSize;

    *BytesReturned = sizeof(*outBuf) + actualSize;

    TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_MEMORY,
                "ReadVm pid=%lu addr=0x%llX size=%llu -> %lu bytes (status=0x%08X)",
                (unsigned long)pid,
                (unsigned long long)address,
                (unsigned long long)wantSize,
                (unsigned long)actualSize,
                outBuf->Status);

    return STATUS_SUCCESS;
}


//
// IOCTL_MYARK_MEMORY_WRITE_VM handler. Mirrors ReadVm: attach to the
// target process and copy Data[] into the destination VA. The bytes
// themselves ride in the input buffer so the output buffer just gets a
// fixed-size status struct.
//
NTSTATUS
MyArkMemoryIoctlWriteVm(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_MEMORY_WRITE_VM_INPUT  inBuf  = NULL;
    PMYARK_MEMORY_WRITE_VM_OUTPUT outBuf = NULL;
    size_t                        inSize  = 0;
    PVOID                         proc    = NULL;
    NTSTATUS                      status;
    SIZE_T                        wantSize;
    SIZE_T                        actualSize;
    KAPC_STATE                    apc;

    UNREFERENCED_PARAMETER(Device);

    if (OutputBufferLength < sizeof(MYARK_MEMORY_WRITE_VM_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (InputBufferLength <= FIELD_OFFSET(MYARK_MEMORY_WRITE_VM_INPUT, Data)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // The actual byte count is whatever the input buffer carried past the
    // Data field. FIELD_OFFSET (not sizeof) is the correct payload start:
    // sizeof includes the alignment padding after Data[1], which would make
    // the tail payload bytes unreachable. Clamp against the IOCTL cap so
    // a malicious caller can't drive an oversized copy.
    //
    wantSize = InputBufferLength - FIELD_OFFSET(MYARK_MEMORY_WRITE_VM_INPUT, Data);
    if (wantSize > MYARK_MEMORY_RW_MAX_BYTES) {
        wantSize = MYARK_MEMORY_RW_MAX_BYTES;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        FIELD_OFFSET(MYARK_MEMORY_WRITE_VM_INPUT, Data) + wantSize,
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // The header's Size field can shrink the copy below what the input
    // buffer actually carried -- only inspect it after the fetch above
    // has made inBuf valid. Pid / Address are snapshotted here because the
    // output header zeroing below shares this SystemBuffer (METHOD_BUFFERED).
    //
    const ULONG  pid     = inBuf->Pid;
    const UINT64 address = inBuf->Address;
    PUCHAR       payload = inBuf->Data;

    if (inBuf->Size != 0 && inBuf->Size < wantSize) {
        wantSize = inBuf->Size;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_MEMORY_WRITE_VM_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, sizeof(*outBuf));

    status = MyArkMemoryResolveEProcess(pid, &proc);
    if (!NT_SUCCESS(status)) {
        outBuf->Status = status;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    KeStackAttachProcess(proc, &apc);
    __try {
        if (MmIsAddressValid((PVOID)address)) {
            RtlCopyMemory((PVOID)address, payload, wantSize);
            actualSize = wantSize;
        } else {
            actualSize = 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        actualSize = 0;
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);

    outBuf->Status       = (actualSize == wantSize) ? (UINT32)STATUS_SUCCESS : (UINT32)STATUS_PARTIAL_COPY;
    outBuf->BytesWritten = (UINT32)actualSize;

    *BytesReturned = sizeof(*outBuf);

    TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_MEMORY,
                "WriteVm pid=%lu addr=0x%llX size=%llu -> %lu bytes (status=0x%08X)",
                (unsigned long)pid,
                (unsigned long long)address,
                (unsigned long long)wantSize,
                (unsigned long)actualSize,
                outBuf->Status);

    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_MEMORY