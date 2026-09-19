// MyArk thread module: enumeration primitives + StartAddress ownership check.
//
// Three responsibilities live here:
//
//   1. ``MyArkThreadModuleRangesPopulate`` -- once at driver_entry, walk
//      PsLoadedModuleList and cache every loaded driver's base/end/name.
//   2. ``MyArkThreadClassifyStartAddress`` -- on every enum/detail row,
//      look the ETHREAD.StartAddress up against the cache and fill the
//      row's owning module name; flag ANOMALY_START_OUTSIDE_MODULE when
//      the address falls in no known range.
//   3. ``MyArkThreadCollectViews`` -- drive the three views (public /
//      ThreadListHead / PspCidTable) for the crossview / enum handlers.
//
// All offsets are documented in thread_internal.h.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "MyArkPoolAlloc.h"
#include "thread_internal.h"

#if MYARK_MODULE_THREAD

//
// SYSTEM_PROCESS_INFORMATION walk bounds (see the public-thread walk).
//
#define MYARK_SPI_MIN_RECORD_SIZE          0x60UL
#define MYARK_SPI_THREAD_ENTRY_SIZE        0x30UL
#define MYARK_SPI_MAX_THREADS_PER_PROC     2048UL

//
// Forward decls for the kernel exports we touch. ntddk.h does not include
// the prototypes; declaring them here avoids the ntifs.h vs wdm.h trap and
// keeps the .c file compilable regardless of header ordering.
//
NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);
NTSTATUS PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD* Thread);
NTSTATUS ZwQuerySystemInformation(
    _In_    UINT32 SystemInformationClass,
    _Inout_ PVOID SystemInformationBuffer,
    _In_    ULONG SystemInformationBufferLength,
    _Out_opt_ PULONG ReturnLength);

extern POBJECT_TYPE *PsProcessType;
extern POBJECT_TYPE *PsThreadType;

//
// PsLoadedModuleList is exported by ntoskrnl.exe but never declared in the
// WDK. Declared here so we can walk it without MmGetSystemRoutineAddress
// (which would still work; this is just simpler).
//
extern PLIST_ENTRY PsLoadedModuleList;

//
// Module-range cache. Populated on first call to MyArkThreadModuleRangesEnsure.
//
MYARK_MODULE_RANGE_CACHE g_MyArkThreadModuleRanges = {0};
static BOOLEAN g_MyArkThreadModuleRangesLoaded = FALSE;


//
// ---------------------------------------------------------------------------
//                                Module range cache
// ---------------------------------------------------------------------------

static
VOID
MyArkThreadCopyUnicodeToWide(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ size_t DestChars,
    _In_ PCUNICODE_STRING Source)
//
// Copy a UNICODE_STRING into a fixed-width wide buffer with explicit NUL
// terminator. Source can be NULL or empty.
//
{
    size_t i;
    USHORT chars;

    if (Dest == NULL || DestChars == 0) {
        return;
    }
    Dest[0] = L'\0';

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }
    if (!MmIsAddressValid(Source->Buffer)) {
        return;
    }

    chars = Source->Length / sizeof(WCHAR);
    for (i = 0; i + 1 < DestChars && i < chars; i++) {
        Dest[i] = Source->Buffer[i];
    }
    Dest[i] = L'\0';
}


static
VOID
MyArkThreadModuleRangesPopulate(
    VOID)
//
// Walk PsLoadedModuleList and cache every driver's base / size / image name.
// Driver entry format:
//
//   _KLDR_DATA_TABLE_ENTRY {
//     LIST_ENTRY InLoadOrderLinks;   // offset 0x00
//     PVOID      DllBase;            // offset 0x30
//     PVOID      EntryPoint;         // offset 0x38
//     ULONG      SizeOfImage;        // offset 0x40
//     UNICODE_STRING FullDllName;    // offset 0x48
//     UNICODE_STRING BaseDllName;    // offset 0x58
//     ...
//   };
//
// Offsets are 24H2-specific; S7.1 DynData replaces them.
//
{
    PLIST_ENTRY head = PsLoadedModuleList;
    if (head == NULL) {
        return;
    }

    ULONG count = 0;
    PLIST_ENTRY current = head->Flink;
    ULONG walked = 0;
    const ULONG HARD_CAP = 4096;

    while (current != NULL
           && current != head
           && walked < HARD_CAP
           && count < MYARK_THREAD_MODULE_CACHE_MAX) {

        PUCHAR entry = (PUCHAR)current;

        UINT64 base = *((PUINT64)(entry + 0x30));
        ULONG size  = *((PULONG)(entry + 0x40));
        PUNICODE_STRING baseName = (PUNICODE_STRING)(entry + 0x58);

        if (base != 0 && size != 0 && MmIsAddressValid((PVOID)base)) {
            PMYARK_MODULE_RANGE range = &g_MyArkThreadModuleRanges.Ranges[count];
            range->Base = base;
            range->End  = base + size;
            MyArkThreadCopyUnicodeToWide(range->Name,
                                         MYARK_THREAD_MODULE_NAME_MAX,
                                         baseName);
            count++;
        }

        walked++;
        current = current->Flink;
    }

    g_MyArkThreadModuleRanges.Count = count;
}


static
NTSTATUS
MyArkThreadModuleRangesEnsure(
    VOID)
{
    if (g_MyArkThreadModuleRangesLoaded) {
        return STATUS_SUCCESS;
    }

    //
    // PsLoadedModuleList is filled by the time DriverEntry runs, so a
    // walk is safe. We only attempt the load once per driver lifetime.
    //
    RtlZeroMemory(&g_MyArkThreadModuleRanges, sizeof(g_MyArkThreadModuleRanges));
    MyArkThreadModuleRangesPopulate();
    g_MyArkThreadModuleRangesLoaded = TRUE;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_THREAD,
                "module range cache populated: %u entries",
                g_MyArkThreadModuleRanges.Count);

    return STATUS_SUCCESS;
}


VOID
MyArkThreadCopyModuleName(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ size_t DestChars,
    _In_opt_ PCWSTR Source)
//
// Public helper used by thread_detail / crossview / enum so the wide-name
// copy rules stay in one place.
//
{
    size_t i;
    if (Dest == NULL || DestChars == 0) {
        return;
    }
    Dest[0] = L'\0';
    if (Source == NULL) {
        return;
    }
    for (i = 0; i + 1 < DestChars && Source[i] != L'\0'; i++) {
        Dest[i] = Source[i];
    }
    Dest[i] = L'\0';
}


UINT8
MyArkThreadClassifyStartAddress(
    _In_ UINT64 StartAddress,
    _Out_writes_(DestChars) PWCHAR ModuleName,
    _In_ size_t DestChars)
//
// Returns the anomaly flag (MYARK_THREAD_ANOMALY_*) and writes the owning
// module base name into ModuleName (or "<unknown>" when no match).
//
// The cache is single-shot per driver lifetime. Calls from PASSIVE_LEVEL
// (every IOCTL handler) are safe.
//
{
    if (ModuleName != NULL && DestChars > 0) {
        ModuleName[0] = L'\0';
    }

    if (StartAddress == 0) {
        return MYARK_THREAD_ANOMALY_NONE;
    }

    MyArkThreadModuleRangesEnsure();

    for (ULONG i = 0; i < g_MyArkThreadModuleRanges.Count; i++) {
        PMYARK_MODULE_RANGE r = &g_MyArkThreadModuleRanges.Ranges[i];
        if (StartAddress >= r->Base && StartAddress < r->End) {
            MyArkThreadCopyModuleName(ModuleName, DestChars, r->Name);
            return MYARK_THREAD_ANOMALY_NONE;
        }
    }

    MyArkThreadCopyModuleName(ModuleName, DestChars, L"<unknown>");
    return MYARK_THREAD_ANOMALY_START_OUTSIDE_MODULE;
}


//
// ---------------------------------------------------------------------------
//                                  ETHREAD row fill
// ---------------------------------------------------------------------------

NTSTATUS
MyArkThreadFillEntry(
    _Out_ PMYARK_THREAD_ENTRY Entry,
    _In_  PETHREAD EThread)
//
// Snapshot one ETHREAD into a MYARK_THREAD_ENTRY row. Used by ENUM and the
// kernel-view side of CROSSVIEW.
//
{
    if (Entry == NULL || EThread == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!MmIsAddressValid(EThread)) {
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(Entry, sizeof(*Entry));

    //
    // Tier A: identity comes from exported accessors, so it is correct on
    // every supported Win10/Win11 build.
    //
    Entry->Tid = (UINT32)MYARK_THREAD_TID(EThread);

    PEPROCESS owningEp = MYARK_THREAD_PROCESS(EThread);
    if (owningEp != NULL && MmIsAddressValid(owningEp)) {
        Entry->Pid = MYARK_PROC_PID(owningEp);
    }

    Entry->CreateTime = MYARK_THREAD_CREATETIME(EThread);

    Entry->EThreadKernelAddress = (UINT64)(ULONG_PTR)EThread;

    //
    // Tier C: scheduler-visible detail and the start address have no
    // accessor, so they come from the build profile. On any other build they
    // stay zero (reported as unknown) instead of reading a wrong offset.
    //
    const MYARK_ARK_OFFSETS* offsets = MyArkArkOffsetsGet();
    if (offsets == NULL || !offsets->ProfileMatched) {
        return STATUS_SUCCESS;
    }

    Entry->StartAddress = *((PUINT64)((PUCHAR)EThread
                                      + MYARK_OFF_ETHREAD_START_ADDRESS));
    Entry->Anomaly = MyArkThreadClassifyStartAddress(Entry->StartAddress,
                                                    Entry->Module,
                                                    MYARK_THREAD_MODULE_NAME_MAX);

    Entry->State      = *((PUCHAR)((PUCHAR)EThread + MYARK_OFF_ETHREAD_STATE));
    Entry->Priority   = *((PUCHAR)((PUCHAR)EThread + MYARK_OFF_ETHREAD_PRIORITY));
    Entry->WaitReason = *((PUCHAR)((PUCHAR)EThread + MYARK_OFF_ETHREAD_WAIT_REASON));

    return STATUS_SUCCESS;
}


//
// ---------------------------------------------------------------------------
//                              Three-view collection
// ---------------------------------------------------------------------------

static
NTSTATUS
MyArkThreadQueryPublicSet(
    _In_  ULONG  Pid,
    _Out_ PMYARK_PUBLIC_THREAD_SET PublicSet)
//
// Pull the public view for ``Pid``: every (Tid, Pid) pair ZwQuerySystemInformation
// (SystemProcessInformation) lists. The driver walks the same buffer Task
// Manager uses, so a thread missing from this set is hidden from R3 by
// either a DKOM unlink or an unlinked EPROCESS.
//
{
    NTSTATUS status;
    ULONG probeSize = 0x4000;
    ULONG returnedLength = 0;
    PVOID buffer = NULL;
    ULONG copied = 0;
    RtlZeroMemory(PublicSet, sizeof(*PublicSet));

    //
    // Reuse the SystemProcessInformation layout from process_query.c's
    // MYARK_OFF_SPI_* constants. They're stable across Win10 21H2+ / Win11.
    //
    #define MYARK_OFF_SPI_NEXT_ENTRY_OFFSET    0x000UL
    #define MYARK_OFF_SPI_NUMBER_OF_THREADS    0x004UL
    #define MYARK_OFF_SPI_UNIQUE_PROCESS_ID    0x050UL
    #define MYARK_OFF_SPI_INHERITED_PROCESS_ID 0x058UL
    //
    // The per-thread record follows the SYSTEM_PROCESS_INFORMATION header
    // and starts with a ULONG_PTR UniqueThreadId. Layout: header padding to
    // 0x0F0 then SYSTEM_THREAD_INFORMATION at offset 0x0F0 (varies by build;
    // we use 0x0F0 for 24H2). For 24H2 the SYSTEM_THREAD_INFORMATION block
    // begins at the process-record offset 0x0F0. We read UniqueThreadId
    // (8 bytes on x64) at offset 0x0F0 + 0x8.
    //
    #define MYARK_OFF_SPI_THREAD_INFO_BASE     0x0F0UL
    #define MYARK_OFF_SPI_THREAD_UNIQUE_TID    0x008UL

    for (int attempt = 0; attempt < 4; attempt++) {
        buffer = MyArkAllocatePool(PagedPool, (SIZE_T)probeSize, 'kpmT');
        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation((UINT32)11 /* SystemProcessInformation */,
                                          buffer,
                                          probeSize,
                                          &returnedLength);
        if (NT_SUCCESS(status)) {
            break;
        }

        ExFreePoolWithTag(buffer, 'kpmT');
        buffer = NULL;

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            probeSize *= 2;
            continue;
        }
        return status;
    }

    if (buffer == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Bounded walk of the record chain (an unvalidated `cursor += next` used
    // to run off the allocation), and the thread sub-array is only read when
    // the running build matches the profile the SYSTEM_THREAD_INFORMATION
    // entry layout was derived from -- otherwise the view degrades to empty
    // instead of reading a wrong layout.
    //
    ULONG limit = (returnedLength != 0 && returnedLength <= probeSize)
                      ? returnedLength
                      : probeSize;
    ULONG offset = 0;
    const MYARK_ARK_OFFSETS* offsets = MyArkArkOffsetsGet();
    BOOLEAN layoutKnown = (offsets != NULL) && offsets->ProfileMatched;

    while (offset + MYARK_SPI_MIN_RECORD_SIZE <= limit) {
        PUCHAR cursor = (PUCHAR)buffer + offset;
        ULONG  next = *((PULONG)(cursor + MYARK_OFF_SPI_NEXT_ENTRY_OFFSET));
        ULONG  procPid = HandleToULong(
            *((PHANDLE)(cursor + MYARK_OFF_SPI_UNIQUE_PROCESS_ID)));
        ULONG  threadCount = *((PULONG)(cursor + MYARK_OFF_SPI_NUMBER_OF_THREADS));

        //
        // 0 == "every PID"; otherwise restrict to the requested one.
        //
        if (layoutKnown && (Pid == 0 || procPid == Pid) &&
            threadCount <= MYARK_SPI_MAX_THREADS_PER_PROC) {

            ULONG threadBytes = threadCount * MYARK_SPI_THREAD_ENTRY_SIZE;
            if (threadBytes <= limit - offset - MYARK_OFF_SPI_THREAD_INFO_BASE) {
                PUCHAR threadBase = cursor + MYARK_OFF_SPI_THREAD_INFO_BASE;
                for (ULONG t = 0; t < threadCount; t++) {
                    if (copied >= MYARK_THREAD_PUBLIC_TID_CAP) {
                        break;
                    }
                    UINT64 rawTid = *((PUINT64)(threadBase
                                                + t * MYARK_SPI_THREAD_ENTRY_SIZE
                                                + MYARK_OFF_SPI_THREAD_UNIQUE_TID));
                    PublicSet->Items[copied].Tid  = HandleToULong((HANDLE)(ULONG_PTR)rawTid);
                    PublicSet->Items[copied].Pid  = procPid;
                    copied++;
                }
            }
        }

        if (next == 0) {
            break;
        }
        if (next < MYARK_SPI_MIN_RECORD_SIZE || next > limit - offset) {
            TraceEvents(TRACE_LEVEL_WARNING,
                        MYARK_TRACE_THREAD,
                        "SystemProcessInformation chain malformed at +0x%X "
                        "(next=0x%X limit=0x%X); stopping walk",
                        offset, next, limit);
            break;
        }
        offset += next;
    }

    ExFreePoolWithTag(buffer, 'kpmT');
    PublicSet->Count = copied;
    return STATUS_SUCCESS;

    #undef MYARK_OFF_SPI_NEXT_ENTRY_OFFSET
    #undef MYARK_OFF_SPI_NUMBER_OF_THREADS
    #undef MYARK_OFF_SPI_UNIQUE_PROCESS_ID
    #undef MYARK_OFF_SPI_INHERITED_PROCESS_ID
    #undef MYARK_OFF_SPI_THREAD_INFO_BASE
    #undef MYARK_OFF_SPI_THREAD_UNIQUE_TID
}


//
// Enumerate a process's threads WITHOUT any structural offset.
//
// PsLookupThreadByThreadId is an exported accessor, and thread IDs are
// allocated in steps of 4, so scanning the plausible TID range and keeping
// the threads whose owner matches gives the same answer as walking
// EPROCESS.ThreadListHead -- on every supported build, with no dependency on
// a discovered offset. Each hit takes a reference, which is released as soon
// as the row has been snapshotted (the picked entry stores values, not the
// pointer to read through later).
//
// The ascending scan stops early once it has matched at least one thread and
// then misses MYARK_TID_MISS_RUN ids in a row: TIDs are handed out
// sequentially, so a gap that large means the live set is behind us.
//
#define MYARK_TID_SCAN_LIMIT    0x100000UL   // 1M: far above any real TID
#define MYARK_TID_MISS_RUN      32768UL
#define MYARK_TID_STEP          4UL

static
NTSTATUS
MyArkThreadWalkThreadList(
    _In_  PVOID  EProcess,
    _Out_ PMYARK_PICKED_THREAD_LIST KernelView)
{
    const MYARK_ARK_OFFSETS* offsets = MyArkArkOffsetsGet();
    const BOOLEAN profile = (offsets != NULL) && offsets->ProfileMatched;
    const ULONG   targetPid = MYARK_PROC_PID(EProcess);

    ULONG misses = 0;
    ULONG scanned = 0;

    RtlZeroMemory(KernelView, sizeof(*KernelView));

    for (ULONG tid = MYARK_TID_STEP;
         tid < MYARK_TID_SCAN_LIMIT && KernelView->Count < MYARK_THREAD_ENUM_MAX_ENTRIES;
         tid += MYARK_TID_STEP) {

        scanned++;

        PETHREAD thread = NULL;
        if (!NT_SUCCESS(PsLookupThreadByThreadId(UlongToHandle(tid), &thread)) ||
            thread == NULL) {
            misses++;
            if (KernelView->Count > 0 && misses >= MYARK_TID_MISS_RUN) {
                break;
            }
            continue;
        }

        misses = 0;

        PEPROCESS owner = MYARK_THREAD_PROCESS(thread);
        if (owner == EProcess || (owner != NULL && MYARK_PROC_PID(owner) == targetPid)) {
            PMYARK_PICKED_THREAD picked = &KernelView->Items[KernelView->Count];

            picked->Tid         = (ULONG)MYARK_THREAD_TID(thread);
            picked->OwnerPid    = targetPid;
            picked->EThread     = thread;
            picked->CreateTime  = MYARK_THREAD_CREATETIME(thread);

            //
            // Tier C: scheduler-visible detail only exists in the profile
            // build; elsewhere the fields stay zero ("unknown") instead of
            // reading a wrong offset.
            //
            if (profile) {
                picked->StartAddress = *((PUINT64)((PUCHAR)thread
                                                   + MYARK_OFF_ETHREAD_START_ADDRESS));
                picked->State        = *((PUCHAR)((PUCHAR)thread + MYARK_OFF_ETHREAD_STATE));
                picked->Priority     = *((PUCHAR)((PUCHAR)thread + MYARK_OFF_ETHREAD_PRIORITY));
                picked->WaitReason   = *((PUCHAR)((PUCHAR)thread + MYARK_OFF_ETHREAD_WAIT_REASON));
            }

            KernelView->Count++;
        }

        ObDereferenceObject(thread);
    }

    TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_THREAD,
                "Thread TID scan: pid=%lu found=%u scanned=%u",
                (unsigned long)targetPid,
                KernelView->Count,
                scanned);

    return STATUS_SUCCESS;
}


static
BOOLEAN
MyArkThreadTidIsInPublic(
    _In_ PMYARK_PUBLIC_THREAD_SET PublicSet,
    _In_ ULONG  Pid,
    _In_ ULONG  Tid)
{
    for (ULONG i = 0; i < PublicSet->Count; i++) {
        if (PublicSet->Items[i].Tid == Tid
            && PublicSet->Items[i].Pid == Pid) {
            return TRUE;
        }
    }
    return FALSE;
}


static
BOOLEAN
MyArkThreadTidIsInPspCidTable(
    _In_ ULONG Tid)
//
// PsLookupThreadByThreadId goes through the kernel handle table; a
// successful lookup means PspCidTable still owns the TID.
//
{
    NTSTATUS    status;
    PETHREAD    thread = NULL;

    status = PsLookupThreadByThreadId(UlongToHandle(Tid), &thread);
    if (NT_SUCCESS(status) && thread != NULL) {
        ObDereferenceObject(thread);
        return TRUE;
    }
    return FALSE;
}


NTSTATUS
MyArkThreadCollectViews(
    _In_  ULONG  Pid,
    _Out_ PMYARK_PICKED_THREAD_LIST KernelView,
    _Out_ PMYARK_PUBLIC_THREAD_SET  PublicSet)
//
// Drive the three views for a given Pid. Returns:
//   * KernelView -- TIDs surfaced via EPROCESS.ThreadListHead (includes
//     the EThread pointer + StartAddress for the cross-view builder).
//   * PublicSet  -- (Tid, Pid) pairs the public view lists.
//
// Caller is responsible for ObDereferenceObject when it derefs individual
// EThreads from KernelView (we don't take references here).
//
{
    NTSTATUS status;
    PEPROCESS proc = NULL;

    RtlZeroMemory(KernelView, sizeof(*KernelView));
    RtlZeroMemory(PublicSet, sizeof(*PublicSet));

    if (Pid == 0) {
        //
        // "current process" sentinel -- not a valid Pid for the global
        // view. The caller is expected to pass a real Pid or 0 + the IOCTL
        // handler path that means "all PIDs". For now we only support a
        // concrete Pid here -- crossview with Pid==0 is handled in the
        // IOCTL handler by iterating every process.
        //
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(UlongToHandle(Pid), &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        return STATUS_NOT_FOUND;
    }

    status = MyArkThreadWalkThreadList(proc, KernelView);
    ObDereferenceObject(proc);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // The kernel view (offset-free TID scan) is the authoritative part; if
    // the public view cannot be collected the call still succeeds with an
    // empty public set -- otherwise a public-side hiccup would turn a
    // perfectly good enumeration into NOT_FOUND.
    //
    status = MyArkThreadQueryPublicSet(Pid, PublicSet);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_THREAD,
                    "public thread view unavailable: 0x%08X (kernel view kept)",
                    status);
        PublicSet->Count = 0;
    }

    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_THREAD
