// MyArk process module: three-view enumeration (public / PspCidTable /
// ActiveProcessLinks). Called by ENUM_PROCESS, CROSSVIEW, and indirectly by
// DETAIL / DKOM (to validate the target PID).
//
// All three views are derived from documented kernel APIs:
//
//   * public       -- NtQuerySystemInformation(SystemProcessInformation).
//                     R0 callers see exactly the same data R3 callers do, so
//                     a process missing from this list is missing from
//                     Task Manager / tasklist / Get-Process too.
//
//   * pspecidtable -- the kernel handle table is what every Ps* lookup hits.
//                     We confirm membership by calling PsLookupProcessByProcessId
//                     on each PID the ActiveProcessLinks walk surfaces --
//                     that path goes through PspCidTable internally, so a
//                     successful lookup means "present in PspCidTable".
//                     Parsing TableCode directly is a (3) class concern (DynData
//                     profile) and lands in a later stage; the proxy gives
//                     identical answers for the public/crossview use cases.
//
//   * active_links -- traverse EPROCESS.ActiveProcessLinks starting from
//                     PsInitialSystemProcess. The head lives in the kernel
//                     .data section (no exported symbol), so we obtain the
//                     seed via the documented PsInitialSystemProcess global
//                     and then walk to its ActiveProcessLinks head.
//
// All offsets are documented in process_internal.h.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "MyArkPoolAlloc.h"
#include "process_internal.h"

//
// Smallest plausible SYSTEM_PROCESS_INFORMATION record: enough to cover the
// NextEntryOffset + UniqueProcessId fields the walk reads, with room to spare.
//
#define MYARK_SPI_MIN_RECORD_SIZE 0x60UL

#if MYARK_MODULE_PROCESS

//
// Forward decl for the IFS-style kernel export that the ActiveLinks walk +
// PspCidTable probe both rely on. ntddk.h does not include this prototype,
// so the .c file declares it here to avoid the ntifs.h vs wdm.h PEPROCESS
// redefinition trap.
//
NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

//
// Forward decl for the Zw* wrapper and the SYSTEM_PROCESS_INFORMATION
// structure. ZwQuerySystemInformation and the SystemProcessInformation enum
// value live in zwapi.h / a kernel-only header that ntddk.h does not pull
// in directly.
//
NTSTATUS ZwQuerySystemInformation(
    _In_      UINT32 SystemInformationClass,
    _Inout_   PVOID SystemInformationBuffer,
    _In_      ULONG SystemInformationBufferLength,
    _Out_opt_ PULONG ReturnLength);

typedef enum _SYSTEM_INFORMATION_CLASS_EX {
    SystemProcessInformation_Ex = 11
} SYSTEM_INFORMATION_CLASS_EX;

#define SystemProcessInformation ((UINT32)SystemProcessInformation_Ex)

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG Reserved0;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG Reserved1[2];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

//
// Public-view entry: a single SYSTEM_PROCESS_INFORMATION record as returned
// by NtQuerySystemInformation. We only keep the fields we render; the
// header buffer is the caller's and we read it in place.
//
typedef struct _MYARK_PUBLIC_PROC_RECORD {
    ULONG   Pid;
    ULONG   Ppid;
    UINT64  CreateTime;
    UINT64  KernelTime;
    UINT64  UserTime;
    ULONG   HandleCount;
    ULONG   ThreadCount;
    WCHAR   ImageName[MYARK_PROCESS_NAME_MAX];
} MYARK_PUBLIC_PROC_RECORD, *PMYARK_PUBLIC_PROC_RECORD;

//
// Layout of SYSTEM_PROCESS_INFORMATION for Win10 21H2+ / Win11 (offset table
// must match the kernel we run on; treat as hardcoded for S6.1).
//
#define MYARK_OFF_SPI_NEXT_ENTRY_OFFSET       0x000UL
#define MYARK_OFF_SPI_NUMBER_OF_THREADS       0x004UL
#define MYARK_OFF_SPI_CREATE_TIME             0x020UL
#define MYARK_OFF_SPI_USER_TIME               0x028UL
#define MYARK_OFF_SPI_KERNEL_TIME             0x030UL
#define MYARK_OFF_SPI_IMAGE_NAME              0x038UL   // UNICODE_STRING (16 bytes)
#define MYARK_OFF_SPI_BASE_PRIORITY           0x048UL
#define MYARK_OFF_SPI_UNIQUE_PROCESS_ID       0x050UL
#define MYARK_OFF_SPI_INHERITED_PROCESS_ID    0x058UL
#define MYARK_OFF_SPI_HANDLE_COUNT            0x060UL

//
// Picked-up view: PIDs the ActiveProcessLinks walk surfaced, with the EPROCESS
// pointers cached for the cross-view diff. Stored separately so we can
// iterate it twice without walking the kernel list again.
//
// Picked-list / record structs are declared in process_internal.h so the
// other module files can use the same view type without duplicating the
// layout.
//


//
// -------------------------------------------------------------------- utils


static
VOID
MyArkProcessCopyWString(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ size_t DestChars,
    _In_opt_ PCWSTR Source)
//
// Copy a NUL-terminated wide string into a fixed-width field with bounded
// length and explicit NUL terminator. Source==NULL yields an empty string.
//
{
    size_t i;

    if (Dest == NULL || DestChars == 0) {
        return;
    }
    for (i = 0; i + 1 < DestChars && Source != NULL && Source[i] != L'\0'; i++) {
        Dest[i] = Source[i];
    }
    Dest[i] = L'\0';
}


static
VOID
MyArkProcessCopyNameFromImageFileName(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ size_t DestChars,
    _In_ PUCHAR ImageFileName)
//
// EPROCESS.ImageFileName is a CHAR[16] (not NUL-terminated reliably). Copy
// the trimmed 8.3-friendly base name into the wide Name[] field.
//
{
    size_t i = 0;

    if (Dest == NULL || DestChars == 0) {
        return;
    }
    Dest[0] = L'\0';

    if (ImageFileName == NULL) {
        return;
    }

    while (i + 1 < MYARK_PROCESS_IMAGE_FILE_NAME_MAX &&
           ImageFileName[i] != '\0' &&
           i + 1 < DestChars) {
        Dest[i] = (WCHAR)ImageFileName[i];
        i++;
    }
    Dest[i] = L'\0';
}


static
BOOLEAN
MyArkProcessIsPidInPublic(
    _In_reads_(PublicCount) const ULONG* PublicPids,
    _In_ ULONG PublicCount,
    _In_ ULONG Pid)
//
// Linear scan over the public view's Pid array. The PublicCount cap is
// modest (a few hundred on a typical VM) so a O(n^2) total cost is fine.
//
{
    for (ULONG i = 0; i < PublicCount; i++) {
        if (PublicPids[i] == Pid) {
            return TRUE;
        }
    }
    return FALSE;
}


static
ULONG
MyArkProcessQuerySystemInfoRead(
    _Out_writes_(MaxPublic) PULONG PublicPids,
    _In_ ULONG MaxPublic)
//
// Pull the public view via NtQuerySystemInformation. Allocates a probe
// buffer, retries with bigger buffers if STATUS_INFO_LENGTH_MISMATCH comes
// back, copies every UniqueProcessId into a flat array, and frees the
// kernel-side buffer with ExFreePool.
//
// Returns the number of PIDs actually copied; 0 on failure (e.g. memory
// exhausted or the call rejected).
//
{
    NTSTATUS            status;
    ULONG               probeSize = 0x4000;
    ULONG               returnedLength = 0;
    ULONG               copied = 0;
    PVOID               buffer = NULL;

    for (int attempt = 0; attempt < 4; attempt++) {
        buffer = MyArkAllocatePool(PagedPool, (SIZE_T)probeSize, 'kpmP');
        if (buffer == NULL) {
            return 0;
        }

        returnedLength = 0;
        status = ZwQuerySystemInformation(SystemProcessInformation,
                                          buffer,
                                          probeSize,
                                          &returnedLength);
        if (NT_SUCCESS(status)) {
            break;
        }

        ExFreePoolWithTag(buffer, 'kpmP');
        buffer = NULL;

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            probeSize *= 2;
            continue;
        }

        //
        // Any other error is fatal: don't loop forever.
        //
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_PROCESS,
                    "ZwQuerySystemInformation failed: 0x%08X", status);
        return 0;
    }

    if (buffer == NULL) {
        return 0;
    }

    //
    // Walk the variable-length record chain. Each record starts with a
    // ULONG NextEntryOffset (0 == last entry).
    //
    //
    // Bounded walk. Every step is validated against the length the call
    // actually reported: an unvalidated `cursor += next` walked off the
    // allocation and bugchecked the guest with 0x50 (reading a wild paged-pool
    // address) as soon as this code ran on a build it had never seen.
    //
    ULONG limit = (returnedLength != 0 && returnedLength <= probeSize)
                      ? returnedLength
                      : probeSize;
    ULONG offset = 0;

    while (offset + MYARK_SPI_MIN_RECORD_SIZE <= limit) {
        PUCHAR cursor = (PUCHAR)buffer + offset;
        ULONG  next = *((PULONG)(cursor + MYARK_OFF_SPI_NEXT_ENTRY_OFFSET));
        HANDLE pidHandle = *((PHANDLE)(cursor + MYARK_OFF_SPI_UNIQUE_PROCESS_ID));
        ULONG  pid = HandleToULong(pidHandle);

        if (copied < MaxPublic && pid != 0) {
            PublicPids[copied++] = pid;
        }

        if (next == 0) {
            break;
        }
        if (next < MYARK_SPI_MIN_RECORD_SIZE || next > limit - offset) {
            TraceEvents(TRACE_LEVEL_WARNING,
                        MYARK_TRACE_PROCESS,
                        "SystemProcessInformation chain malformed at +0x%X "
                        "(next=0x%X limit=0x%X); stopping walk",
                        offset, next, limit);
            break;
        }
        offset += next;
    }

    ExFreePoolWithTag(buffer, 'kpmP');
    return copied;
}


static
VOID
MyArkProcessPickedAdd(
    _Inout_ PMYARK_PICKED_LIST List,
    _In_ ULONG Pid,
    _In_ ULONG Ppid,
    _In_ PVOID EProcess,
    _In_ PUCHAR ImageFileName)
//
// Append one row to the picked-list. Silently drops when the cap is hit
// (caller is responsible for reporting the cap as a warning if needed).
//
{
    if (List->Count >= 1024) {
        return;
    }

    PMYARK_PICKED_PROC item = &List->Items[List->Count];

    item->Pid       = Pid;
    item->Ppid      = Ppid;
    item->EProcess  = EProcess;
    RtlCopyMemory(item->ImageFileName,
                  ImageFileName,
                  MYARK_PROCESS_IMAGE_FILE_NAME_MAX);
    MyArkProcessCopyNameFromImageFileName(item->Name,
                                         MYARK_PROCESS_NAME_MAX,
                                          ImageFileName);
    List->Count++;
}


static
NTSTATUS
MyArkProcessWalkActiveLinks(
    _Out_ PMYARK_PICKED_LIST List)
//
// Walk EPROCESS.ActiveProcessLinks via PsInitialSystemProcess. The seed
// EPROCESS lives at the well-known exported address; every other EPROCESS
// is reachable through its ActiveProcessLinks.Flink (a circular list). We
// stop when we either loop back to the seed (the standard sentinel) or
// exceed a sane hard cap so a corrupt list can't blue-screen us.
//
{
    LIST_ENTRY  headAnchor;
    PLIST_ENTRY  current = NULL;
    ULONG       walked = 0;
    const ULONG  HARD_CAP = 1024 * 4;

    RtlZeroMemory(List, sizeof(*List));

    //
    // Tier B: the ActiveProcessLinks offset is discovered at init (see
    // process_offsets.h), so this walk works on any supported build instead
    // of only the one the constants were extracted from.
    //
    const MYARK_ARK_OFFSETS* offsets = MyArkArkOffsetsGet();
    if (offsets == NULL || !offsets->Valid) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_PROCESS,
                    "ActiveProcessLinks walk unavailable: offsets not resolved");
        return STATUS_NOT_SUPPORTED;
    }
    const ULONG linksOffset = offsets->ActiveProcessLinks;

    //
    // PsInitialSystemProcess is the documented entry point into the EPROCESS
    // chain. Its ActiveProcessLinks.Flink is the first real process entry.
    //
    PVOID seed = PsInitialSystemProcess;
    if (seed == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // The seed's ActiveProcessLinks points back to itself when the system is
    // idle (only System present). Otherwise its Flink points to the next
    // process. Read the Flink pointer and follow the chain.
    //
    PLIST_ENTRY seedLink = (PLIST_ENTRY)((PUCHAR)seed + linksOffset);

    //
    // Snapshot the seed's address for loop detection: if we ever see a
    // list entry whose Flink/Blink equals the seed's ActiveProcessLinks
    // address, the list has come full circle.
    //
    PLIST_ENTRY startLink = seedLink->Flink;

    current = startLink;
    while (current != NULL && walked < HARD_CAP) {
        PVOID ep = (PUCHAR)current - linksOffset;

        //
        // Dereference the EPROCESS fields through ProbeForRead-style
        // helpers. MmIsAddressValid gates every read so we don't fault.
        // Tier A accessors supply pid / ppid / image name on every build.
        //
        if (!MmIsAddressValid(ep)) {
            break;
        }

        MyArkProcessPickedAdd(List,
                              MYARK_PROC_PID(ep),
                              MYARK_PROC_PPID(ep),
                              ep,
                              (PUCHAR)MYARK_PROC_IMAGE(ep));

        walked++;
        current = current->Flink;

        if (current == seedLink || current == startLink) {
            break;
        }
    }

    UNREFERENCED_PARAMETER(headAnchor);

    TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_PROCESS,
                "ActiveProcessLinks walk: %u/%u picked (cap %u)",
                List->Count, walked, 1024);

    return STATUS_SUCCESS;
}


static
BOOLEAN
MyArkProcessIsPidInPspCidTable(
    _In_ ULONG Pid)
//
// Probe PspCidTable membership via PsLookupProcessByProcessId. Internally
// that goes through the kernel's handle table; a successful lookup means
// "the kernel still has a handle for this PID".
//
// PsLookupProcessByProcessId requires IRQL == PASSIVE_LEVEL -- the caller
// is the IOCTL dispatch handler which runs in Passive, so this is safe.
//
{
    NTSTATUS    status;
    PEPROCESS   proc = NULL;

    status = PsLookupProcessByProcessId(UlongToHandle(Pid), &proc);
    if (NT_SUCCESS(status) && proc != NULL) {
        ObDereferenceObject(proc);
        return TRUE;
    }
    return FALSE;
}


//
// ----------------------------------------------------------------- public API


//
// Build a MYARK_PROCESS_ENTRY from a picked (kernel-view) record plus the
// public-Pid set. The caller decides which SourceMask bits to set.
//
VOID
MyArkProcessFillEntryFromPicked(
    _Out_ PMYARK_PROCESS_ENTRY Entry,
    _In_ PMYARK_PICKED_PROC Picked,
    _In_ UINT8 SourceMask,
    _In_ UINT8 Hidden)
{
    RtlZeroMemory(Entry, sizeof(*Entry));

    Entry->Pid        = Picked->Pid;
    Entry->Ppid       = Picked->Ppid;
    Entry->SourceMask = SourceMask;
    Entry->Hidden     = Hidden;
    Entry->Ppl        = 0;
    Entry->MemKb      = 0;

    MyArkProcessCopyWString(Entry->Name,
                            MYARK_PROCESS_NAME_MAX,
                            Picked->Name);
    MyArkProcessCopyWString(Entry->Path,
                            MYARK_PROCESS_PATH_MAX,
                            L"");
    MyArkProcessCopyWString(Entry->User,
                            MYARK_PROCESS_USER_MAX,
                            L"");
}


NTSTATUS
MyArkProcessCollectViews(
    _Out_ PMYARK_PICKED_LIST KernelView,
    _Out_writes_(MaxPublic) PULONG PublicPids,
    _In_ ULONG MaxPublic,
    _Out_ PULONG PublicCountOut)
//
// Drive both views and return everything the crossview / enum handlers
// need. Returns the kernel view via KernelView and the public view as a flat
// Pid array (sized to MaxPublic; *PublicCountOut is the real count).
//
{
    NTSTATUS status;

    *PublicCountOut = 0;
    RtlZeroMemory(KernelView, sizeof(*KernelView));

    *PublicCountOut = MyArkProcessQuerySystemInfoRead(PublicPids, MaxPublic);
    status = MyArkProcessWalkActiveLinks(KernelView);
    return status;
}


BOOLEAN
MyArkProcessPidIsInActiveLinks(
    _In_ PMYARK_PICKED_LIST KernelView,
    _In_ ULONG Pid)
//
// Helper used by DETAIL / DKOM to confirm a target PID is still reachable
// from the kernel list -- a doubly-hidden process can't be operated on.
//
{
    for (ULONG i = 0; i < KernelView->Count; i++) {
        if (KernelView->Items[i].Pid == Pid) {
            return TRUE;
        }
    }
    return FALSE;
}


BOOLEAN
MyArkProcessPidIsInPublicView(
    _In_reads_(PublicCount) const ULONG* PublicPids,
    _In_ ULONG PublicCount,
    _In_ ULONG Pid)
//
// Re-export of the internal scanner so other files can check without
// exposing the helper signature.
//
{
    return MyArkProcessIsPidInPublic(PublicPids, PublicCount, Pid);
}


BOOLEAN
MyArkProcessPidIsInPspCidTable(
    _In_ ULONG Pid)
//
// Re-export of the lookup helper so other files (DKOM / DETAIL) can use
// the same PspCidTable probe without re-importing the static version.
//
{
    return MyArkProcessIsPidInPspCidTable(Pid);
}

#endif // MYARK_MODULE_PROCESS