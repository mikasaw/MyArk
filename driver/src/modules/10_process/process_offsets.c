// MyArk: runtime EPROCESS / ETHREAD offset resolution.
//
// See process_offsets.h for the three-tier design. Nothing here trusts a
// hardcoded offset: the two structural offsets are discovered and validated
// against the exported accessors, so the result is correct on any build
// where the accessors themselves are correct.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "process_offsets.h"

#if MYARK_MODULE_PROCESS || MYARK_MODULE_THREAD

//
// Discovery search bounds. The structural offsets live well inside the first
// 2 KiB of both structures on every build observed so far.
//
#define MYARK_OFFSET_SEARCH_START   0x000UL
#define MYARK_OFFSET_SEARCH_END     0x800UL
#define MYARK_OFFSET_STEP           sizeof(PVOID)

//
// ActiveProcessLinks chain sanity: the process list always contains the
// System process (PID 4), which is also what PsInitialSystemProcess points
// at. Requiring the chain to include PID 4 rejects any other LIST_ENTRY that
// happens to satisfy the local invariant.
//
//
// The ActiveProcessLinks list is circular and System may be dozens of hops
// away from the anchor (a fresh Win10 VM has 40+ processes), so the probe
// budget must comfortably exceed the process count -- an 8-hop limit made
// discovery fail on every build where the anchor sat mid-list.
//
#define MYARK_CHAIN_PROBE_LINKS     1024
#define MYARK_SYSTEM_PID            4
#define MYARK_MAX_PLAUSIBLE_PID     0x400000UL   // 4M: real PIDs stay far below

static MYARK_ARK_OFFSETS g_ArkOffsets;
static BOOLEAN           g_ArkOffsetsInitDone = FALSE;

static
BOOLEAN
MyArkIsKernelPointer(
    _In_opt_ PVOID Pointer)
{
    UINT64 value = (UINT64)Pointer;
    return value >= 0xFFFF800000000000ULL &&
           value != 0xFFFFFFFFFFFFFFFFULL &&
           MmIsAddressValid(Pointer);
}

static
BOOLEAN
MyArkReadPointerSafe(
    _In_  PVOID  Address,
    _Out_ PVOID* Value)
{
    *Value = NULL;
    if (!MmIsAddressValid(Address)) {
        return FALSE;
    }
    __try {
        *Value = *(PVOID*)Address;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *Value = NULL;
    }
    return *Value != NULL;
}

//
// The LIST_ENTRY invariant: entry->Flink->Blink == entry and
// entry->Blink->Flink == entry. One wrong candidate in a billion, and it
// costs nothing to check.
//
static
BOOLEAN
MyArkListEntryLooksValid(
    _In_ PVOID Entry)
{
    PVOID flink = NULL;
    PVOID blink = NULL;
    PVOID back = NULL;

    if (!MyArkReadPointerSafe(Entry, &flink) ||
        !MyArkReadPointerSafe((PUCHAR)Entry + sizeof(PVOID), &blink)) {
        return FALSE;
    }
    if (!MyArkIsKernelPointer(flink) || !MyArkIsKernelPointer(blink)) {
        return FALSE;
    }
    if (!MyArkReadPointerSafe((PUCHAR)flink + sizeof(PVOID), &back) ||
        back != Entry) {
        return FALSE;
    }
    if (!MyArkReadPointerSafe(blink, &back) || back != Entry) {
        return FALSE;
    }
    return TRUE;
}

//
// Walk the candidate list and require the System process to show up. This is
// what separates ActiveProcessLinks from any other EPROCESS list node.
//
static
BOOLEAN
MyArkChainLooksLikeProcessList(
    _In_ PEPROCESS Start,
    _In_ ULONG     LinksOffset)
//
// Strong signature for ActiveProcessLinks, all checks build-independent:
//   * the anchor's own PID comes back around (the list is circular),
//   * System (PID 4) is on the chain,
//   * at least three distinct plausible PIDs were seen,
//   * every hop resolved a plausible PID (a garbage chain almost never does).
//
// A single "some hop happened to be PID 4" check was not enough: EPROCESS+8
// satisfied it by chance and discovery locked onto 0x8.
//
{
    const ULONG selfPid = HandleToULong(PsGetProcessId(Start));
    ULONG       distinct = 0;
    ULONG       seenPids[4] = { 0 };
    ULONG       hops = 0;
    BOOLEAN     sawSystem = FALSE;
    BOOLEAN     sawSelf = FALSE;
    PVOID       entry = (PUCHAR)Start + LinksOffset;

    for (hops = 0; hops < MYARK_CHAIN_PROBE_LINKS; hops++) {
        PVOID flink = NULL;
        if (!MyArkReadPointerSafe(entry, &flink) ||
            !MyArkIsKernelPointer(flink)) {
            return FALSE;
        }

        PVOID candidate = (PUCHAR)flink - LinksOffset;
        if (!MyArkIsKernelPointer(candidate)) {
            return FALSE;
        }

        ULONG pid = HandleToULong(PsGetProcessId(candidate));
        //
        // PID 0 (Idle) is a legitimate member of ActiveProcessLinks, so a
        // zero is tolerated here and simply not counted towards the distinct
        // requirement -- rejecting it outright made every real candidate fail.
        // Anything larger than a plausible PID means the container was wrong.
        //
        if (pid > MYARK_MAX_PLAUSIBLE_PID) {
            return FALSE;
        }

        BOOLEAN known = FALSE;
        for (ULONG i = 0; i < distinct; i++) {
            if (seenPids[i] == pid) {
                known = TRUE;
                break;
            }
        }
        if (!known && distinct < RTL_NUMBER_OF(seenPids)) {
            seenPids[distinct++] = pid;
        }

        if (pid == MYARK_SYSTEM_PID) {
            sawSystem = TRUE;
        }
        if (pid == selfPid) {
            sawSelf = TRUE;
        }
        if (sawSystem && sawSelf && distinct >= 3) {
            return TRUE;
        }

        entry = flink;
    }
    return FALSE;
}

//
// Discover EPROCESS.ActiveProcessLinks using our own process as the anchor.
//
static
ULONG
MyArkDiscoverActiveProcessLinks(
    _In_ PEPROCESS Self)
{
    for (ULONG offset = MYARK_OFFSET_SEARCH_START;
         offset < MYARK_OFFSET_SEARCH_END;
         offset += MYARK_OFFSET_STEP) {

        PVOID entry = (PUCHAR)Self + offset;
        if (!MyArkListEntryLooksValid(entry)) {
            continue;
        }

        //
        // Neighbour must be a process the kernel itself recognises, and the
        // chain must contain the System process.
        //
        PVOID flink = NULL;
        if (!MyArkReadPointerSafe(entry, &flink)) {
            continue;
        }
        PEPROCESS neighbour = (PEPROCESS)((PUCHAR)flink - offset);
        if (!MyArkIsKernelPointer(neighbour)) {
            continue;
        }
        HANDLE pid = PsGetProcessId(neighbour);
        if (pid == NULL) {
            continue;
        }
        if (!MyArkChainLooksLikeProcessList(Self, offset)) {
            continue;
        }

        return offset;
    }

    return 0;
}

//
// Discover ETHREAD.ThreadListEntry. A candidate is accepted only when the
// peer at the same offset is recognised as a thread of the SAME process.
//
static
ULONG
MyArkDiscoverThreadListEntry(
    _In_ PETHREAD  SelfThread,
    _In_ PEPROCESS SelfProcess)
{
    for (ULONG offset = MYARK_OFFSET_SEARCH_START;
         offset < MYARK_OFFSET_SEARCH_END;
         offset += MYARK_OFFSET_STEP) {

        PVOID entry = (PUCHAR)SelfThread + offset;
        if (!MyArkListEntryLooksValid(entry)) {
            continue;
        }

        PVOID flink = NULL;
        if (!MyArkReadPointerSafe(entry, &flink)) {
            continue;
        }

        PETHREAD peer = (PETHREAD)((PUCHAR)flink - offset);
        if (!MyArkIsKernelPointer(peer)) {
            continue;
        }
        if (PsGetThreadId(peer) == NULL) {
            continue;
        }

        //
        // Same process => this is the thread list, not the wait list or the
        // APC queue. PsGetThreadProcess does the container lookup with the
        // kernel's own offsets, which is exactly the validation we want.
        //
        if (PsGetThreadProcess(peer) != SelfProcess) {
            continue;
        }

        return offset;
    }

    return 0;
}

//
// Discover EPROCESS.ThreadListHead: the entry whose first link resolves to a
// thread of this process at the already-known ThreadListEntry offset.
//
static
ULONG
MyArkDiscoverThreadListHead(
    _In_ PEPROCESS Self,
    _In_ ULONG     ThreadListEntryOffset)
{
    for (ULONG offset = MYARK_OFFSET_SEARCH_START;
         offset < MYARK_OFFSET_SEARCH_END;
         offset += MYARK_OFFSET_STEP) {

        PVOID entry = (PUCHAR)Self + offset;
        if (!MyArkListEntryLooksValid(entry)) {
            continue;
        }

        PVOID flink = NULL;
        if (!MyArkReadPointerSafe(entry, &flink)) {
            continue;
        }

        PETHREAD first = (PETHREAD)((PUCHAR)flink - ThreadListEntryOffset);
        if (!MyArkIsKernelPointer(first)) {
            continue;
        }
        if (PsGetThreadId(first) == NULL) {
            continue;
        }
        if (PsGetThreadProcess(first) != Self) {
            continue;
        }

        return offset;
    }

    return 0;
}

NTSTATUS
MyArkArkOffsetsInit(
    VOID)
{
    if (g_ArkOffsetsInitDone) {
        return g_ArkOffsets.Valid ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
    }
    g_ArkOffsetsInitDone = TRUE;

    RtlZeroMemory(&g_ArkOffsets, sizeof(g_ArkOffsets));

    PEPROCESS self = PsGetCurrentProcess();
    PETHREAD  selfThread = PsGetCurrentThread();
    if (self == NULL || selfThread == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    g_ArkOffsets.ActiveProcessLinks = MyArkDiscoverActiveProcessLinks(self);
    g_ArkOffsets.ThreadListEntry = MyArkDiscoverThreadListEntry(selfThread, self);
    g_ArkOffsets.ThreadListHead = (g_ArkOffsets.ThreadListEntry != 0)
                                      ? MyArkDiscoverThreadListHead(
                                            self, g_ArkOffsets.ThreadListEntry)
                                      : 0;

    //
    // Availability is per-view: the process list only needs
    // ActiveProcessLinks, and thread enumeration is done with the
    // offset-free TID scan (PsLookupThreadByThreadId), so the ETHREAD list
    // offsets are informational and must NOT gate the modules. Requiring all
    // three made every view report NOT_SUPPORTED when only the thread-side
    // discovery failed.
    //
    g_ArkOffsets.Valid = (g_ArkOffsets.ActiveProcessLinks != 0);

    //
    // Tier C: the informational fields (KTHREAD.State/Priority/WaitReason,
    // EPROCESS.Peb/ActiveThreads/Flags2/BasePriority/Affinity, ETHREAD start
    // addresses) have no accessor, so they come from the profile table this
    // driver was built against -- Windows 11 24H2 / 25H2 (26100..26299).
    // Outside that window they read as zero and callers must surface them as
    // unknown; nothing structural depends on them.
    //
    {
        RTL_OSVERSIONINFOW info;
        RtlZeroMemory(&info, sizeof(info));
        info.dwOSVersionInfoSize = sizeof(info);
        if (NT_SUCCESS(RtlGetVersion(&info))) {
            g_ArkOffsets.ProfileMatched =
                (info.dwBuildNumber >= 26100 && info.dwBuildNumber <= 26299);
        }
    }

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MODULE,
                "ArkOffsets: ActiveProcessLinks=0x%X ThreadListHead=0x%X "
                "ThreadListEntry=0x%X profile=%s (discovered=%s)",
                g_ArkOffsets.ActiveProcessLinks,
                g_ArkOffsets.ThreadListHead,
                g_ArkOffsets.ThreadListEntry,
                g_ArkOffsets.ProfileMatched ? "matched" : "other-build",
                g_ArkOffsets.Valid ? "yes" : "no");

    return g_ArkOffsets.Valid ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

const MYARK_ARK_OFFSETS*
MyArkArkOffsetsGet(
    VOID)
{
    return g_ArkOffsetsInitDone ? &g_ArkOffsets : NULL;
}

#endif // MYARK_MODULE_PROCESS || MYARK_MODULE_THREAD