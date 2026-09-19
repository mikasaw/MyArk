// timerdpc walk: per-CPU timer table + DPC queue snapshot emission.
//
// Everything reads through page-gated probes; a bad pointer at ANY step
// stops that walk (or skips that row) instead of faulting. The DPC
// decode reverses the Win8+ KiWaitNever/KiWaitAlways obfuscation that
// KiSetTimerEx applies to KTIMER.Dpc (verified against live targets:
// stored = ROR64(bswap64(Always ^ Dpc) ^ Timer, Never & 0x3F) ^ Never).

#include <ntddk.h>
#include <wdf.h>
#include <intrin.h>
#include "Trace.h"
#include "myark_config.h"
#include "timerdpc_descriptor.h"
#include "timerdpc_internal.h"
#include "../../../shared/driver/MyArkTimerIoctl.h"

#if MYARK_MODULE_TIMERDPC

//
// Decode the obfuscated KTIMER.Dpc back-pointer. Returns 0 when the
// decoded value is non-canonical (timer with no DPC encodes to garbage;
// Dpc==0 is the honest answer for a notification timer).
//
static
UINT64
MyArkTdpDecodeDpc(
    _In_ UINT64 Timer,
    _In_ UINT64 Encoded,
    _In_ UINT64 Never,
    _In_ UINT64 Always)
{
    UINT64 x = _rotl64(Encoded ^ Never, (unsigned char)(Never & 0x3F));
    x ^= Timer;
    x = _byteswap_uint64(x);
    x ^= Always;
    if ((x & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
        return 0;
    }
    return x;
}

static
VOID
MyArkTdpFlagsForRoutine(
    _In_ UINT64 Routine,
    _In_ UINT32 BaseFlags,
    _Out_writes_bytes_(OwnerBytes) PUCHAR Owner,
    _In_ ULONG OwnerBytes,
    _Out_ UINT32* Flags)
{
    ULONG ownerChars;

    *Flags = BaseFlags;          // preserve EXPIRY/NO_DPC set by callers
    if (g_MyArkTdpNtTextBase != 0
        && Routine >= g_MyArkTdpNtTextBase
        && Routine < g_MyArkTdpNtTextEnd) {
        *Flags |= MYARK_TIMER_FLAG_NTROUTINE;
    }
    ownerChars = MyArkTdpOwnerForAddress(Routine, Owner, OwnerBytes);
    if (ownerChars == 0
        && (*Flags & MYARK_TIMER_FLAG_NTROUTINE) == 0
        && Routine != 0) {
        *Flags |= MYARK_TIMER_FLAG_SUSPECT;
    }
}

//
// Emit one timer row (dedup by KTIMER address against recent rows).
//
static
VOID
MyArkTdpEmitTimer(
    _Inout_ PMYARK_TIMER_QUERY_OUTPUT Out,
    _In_ ULONG MaxEntries,
    _Inout_ PULONG Written,
    _In_ UINT64 Timer,
    _In_ ULONG Cpu,
    _In_ UINT32 ExtraFlags,
    _In_ const MYARK_TDP_PROFILE* Profile)
{
    UINT64 never = 0;
    UINT64 always = 0;
    UINT64 dueTime = 0;
    UINT64 encDpc = 0;
    UINT64 dpc = 0;
    UINT64 routine = 0;
    UINT64 context = 0;
    UINT32 period = 0;
    UINT32 flags = ExtraFlags;
    PMYARK_TIMER_ENTRY row;
    BOOLEAN flags_out = FALSE;

    for (ULONG i = 0; i < *Written; i++) {
        if (Out->Entries[i].Timer == Timer) {
            return;                  // already emitted (expiry + bucket)
        }
    }

    if (*Written >= MaxEntries) {
        return;
    }

    (VOID)MyArkTdpReadU64(Timer + MYARK_TDP_KTIMER_DUETIME, &dueTime);
    (VOID)MyArkTdpReadU32(Timer + MYARK_TDP_KTIMER_PERIOD, &period);

    if (MyArkTdpReadU64(Timer + MYARK_TDP_KTIMER_DPC, &encDpc)
        && MyArkTdpReadU64(g_MyArkTdpNtBase + Profile->KiWaitNever, &never)
        && MyArkTdpReadU64(g_MyArkTdpNtBase + Profile->KiWaitAlways, &always)) {
        dpc = MyArkTdpDecodeDpc(Timer, encDpc, never, always);
    }

    if (dpc != 0) {
        if (MyArkTdpReadU64(dpc + MYARK_TDP_KDPC_ROUTINE, &routine)
            && MyArkTdpReadU64(dpc + MYARK_TDP_KDPC_CONTEXT, &context)) {
            flags_out = TRUE;
        } else {
            dpc = 0;                 // unreadable DPC: report as absent
            flags |= MYARK_TIMER_FLAG_NO_DPC;
        }
    } else {
        flags |= MYARK_TIMER_FLAG_NO_DPC;
    }

    row = &Out->Entries[*Written];
    RtlZeroMemory(row, sizeof(*row));
    row->Timer = Timer;
    row->DueTime = dueTime;
    row->Dpc = dpc;
    row->Routine = routine;
    row->Context = context;
    row->Cpu = (UINT32)Cpu;
    row->Period = period;
    if (flags_out) {
        MyArkTdpFlagsForRoutine(routine, flags,
                                (PUCHAR)row->Owner,
                                MYARK_TIMERDPC_OWNER_MAX, &row->Flags);
    } else {
        row->Flags = flags;
    }
    (*Written)++;
}

NTSTATUS
MyArkTimerDpcWalkTimers(
    _Out_writes_bytes_(OutSize) PUCHAR OutBuf,
    _In_ SIZE_T OutSize,
    _Out_ PULONG BytesReturned)
{
    const MYARK_TDP_PROFILE* prof = g_MyArkTdpProfile;
    SIZE_T headSize = FIELD_OFFSET(MYARK_TIMER_QUERY_OUTPUT, Entries[0]);
    PMYARK_TIMER_QUERY_OUTPUT out = (PMYARK_TIMER_QUERY_OUTPUT)OutBuf;
    ULONG maxEntries;
    ULONG written = 0;
    ULONG cpuCount;
    ULONG status = MYARK_TDP_STATUS_OK;

    maxEntries = (ULONG)((OutSize - headSize) / sizeof(MYARK_TIMER_ENTRY));

    if (g_MyArkDynDataPsLoadedModuleList == NULL
        || !MmIsAddressValid(g_MyArkDynDataPsLoadedModuleList)) {
        status = MYARK_TDP_STATUS_NO_MODULELIST;   // owners degrade to ""
    }

    cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (cpuCount > MYARK_TDP_MAX_CPU) {
        cpuCount = MYARK_TDP_MAX_CPU;
    }

    for (ULONG cpu = 0; cpu < cpuCount; cpu++) {
        UINT64 prcb = 0;
        UINT64 table = 0;

        if (!MyArkTdpReadU64(g_MyArkTdpNtBase + prof->KiProcessorBlock
                             + (UINT64)cpu * sizeof(UINT64), &prcb)
            || prcb == 0) {
            continue;
        }
        table = prcb + prof->PrcbTimerTable;

        //
        // TimerExpiry[64]: expired timers awaiting DPC delivery, stored
        // as plain KTIMER pointers.
        //
        for (ULONG e = 0; e < MYARK_TDP_EXPIRY_SLOTS; e++) {
            UINT64 tmr = 0;
            (VOID)MyArkTdpReadU64(table + MYARK_TDP_TABLE_EXPIRY
                                  + (UINT64)e * sizeof(UINT64), &tmr);
            if (tmr != 0) {
                MyArkTdpEmitTimer(out, maxEntries, &written, tmr, cpu,
                                  MYARK_TIMER_FLAG_EXPIRY, prof);
            }
        }

        //
        // TimerEntries[buckets]: LIST_ENTRY chains of KTIMER.TimerListEntry
        // (+0x20 inside the KTIMER).
        //
        for (ULONG b = 0; b < prof->BucketCount; b++) {
            UINT64 head = table + prof->BucketBase
                          + (UINT64)b * MYARK_TDP_ENTRY_STRIDE
                          + MYARK_TDP_TABLE_ENTRY_HEAD;
            UINT64 cur = 0;

            if (!MyArkTdpReadU64(head, &cur) || cur == 0) {
                continue;
            }
            for (ULONG it = 0; it < MYARK_TDP_BUCKET_ITERS; it++) {
                UINT64 timer;
                UINT64 next;

                if (cur == head) {
                    break;
                }
                if ((cur & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
                    break;
                }
                timer = cur - MYARK_TDP_KTIMER_LISTENTRY;
                MyArkTdpEmitTimer(out, maxEntries, &written, timer, cpu,
                                  0, prof);
                if (!MyArkTdpReadU64(cur, &next) || next == 0) {
                    break;
                }
                cur = next;
            }
        }
    }

    out->Count = written;
    out->Status = status;
    out->EntryStructSize = (UINT32)sizeof(MYARK_TIMER_ENTRY);
    *BytesReturned = (ULONG)(headSize + (SIZE_T)written * sizeof(MYARK_TIMER_ENTRY));
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkTimerDpcWalkDpcs(
    _Out_writes_bytes_(OutSize) PUCHAR OutBuf,
    _In_ SIZE_T OutSize,
    _Out_ PULONG BytesReturned)
//
// Snapshot the per-CPU DPC queues (normal + threaded). The queue is
// transient: rows appear only while DPCs are pending. Link pointers are
// validated at every hop -- if a build encodes them, the walk stops
// cleanly (ActiveDpc + counters remain honest).
//
{
    const MYARK_TDP_PROFILE* prof = g_MyArkTdpProfile;
    SIZE_T headSize = FIELD_OFFSET(MYARK_DPC_QUERY_OUTPUT, Entries[0]);
    PMYARK_DPC_QUERY_OUTPUT out = (PMYARK_DPC_QUERY_OUTPUT)OutBuf;
    ULONG maxEntries;
    ULONG written = 0;
    ULONG cpuCount;

    maxEntries = (ULONG)((OutSize - headSize) / sizeof(MYARK_DPC_ENTRY));

    cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (cpuCount > MYARK_TDP_MAX_CPU) {
        cpuCount = MYARK_TDP_MAX_CPU;
    }

    for (ULONG cpu = 0; cpu < cpuCount; cpu++) {
        UINT64 prcb = 0;

        if (!MyArkTdpReadU64(g_MyArkTdpNtBase + prof->KiProcessorBlock
                             + (UINT64)cpu * sizeof(UINT64), &prcb)
            || prcb == 0) {
            continue;
        }

        for (ULONG q = 0; q < 2; q++) {
            UINT64 kd = prcb + prof->PrcbDpcData + (UINT64)q * prof->DpcDataStride;
            UINT64 active = 0;
            UINT64 node = 0;
            UINT32 flags;

            (VOID)MyArkTdpReadU64(kd + MYARK_TDP_KDPCDATA_ACTIVE, &active);

            if (active != 0
                && (active & 0xFFFF800000000000ULL) == 0xFFFF800000000000ULL
                && written < maxEntries) {
                UINT64 routine = 0;
                UINT64 context = 0;
                if (MyArkTdpReadU64(active + MYARK_TDP_KDPC_ROUTINE, &routine)
                    && MyArkTdpReadU64(active + MYARK_TDP_KDPC_CONTEXT, &context)) {
                    PMYARK_DPC_ENTRY row = &out->Entries[written];
                    RtlZeroMemory(row, sizeof(*row));
                    row->Dpc = active;
                    row->Routine = routine;
                    row->Context = context;
                    row->Cpu = (UINT32)cpu;
                    row->QueueType = (UINT32)q;
                    flags = (q == 1) ? MYARK_DPC_FLAG_THREADED : 0;
                    if (g_MyArkTdpNtTextBase != 0
                        && routine >= g_MyArkTdpNtTextBase
                        && routine < g_MyArkTdpNtTextEnd) {
                        flags |= MYARK_DPC_FLAG_NTROUTINE;
                    } else if (routine != 0) {
                        flags |= MYARK_DPC_FLAG_SUSPECT;
                    }
                    (VOID)MyArkTdpOwnerForAddress(routine, (PUCHAR)row->Owner,
                                                  MYARK_TIMERDPC_OWNER_MAX);
                    row->Flags = flags;
                    written++;
                }
            }

            node = 0;
            (VOID)MyArkTdpReadU64(kd + MYARK_TDP_KDPCDATA_HEAD, &node);
            for (ULONG it = 0; it < MYARK_TDP_DPC_ITERS && written < maxEntries; it++) {
                UINT64 dpc;
                UINT64 routine = 0;
                UINT64 context = 0;
                UINT64 next;

                if (node == 0
                    || (node & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
                    break;
                }
                dpc = node - MYARK_TDP_KDPC_DpclISTENTRY;
                if (!MyArkTdpReadU64(dpc + MYARK_TDP_KDPC_ROUTINE, &routine)
                    || !MyArkTdpReadU64(dpc + MYARK_TDP_KDPC_CONTEXT, &context)
                    || (routine & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
                    break;               // encoded/corrupt link: stop cleanly
                }
                if (dpc != active && written < maxEntries) {
                    PMYARK_DPC_ENTRY row = &out->Entries[written];
                    RtlZeroMemory(row, sizeof(*row));
                    row->Dpc = dpc;
                    row->Routine = routine;
                    row->Context = context;
                    row->Cpu = (UINT32)cpu;
                    row->QueueType = (UINT32)q;
                    flags = (q == 1) ? MYARK_DPC_FLAG_THREADED : 0;
                    if (g_MyArkTdpNtTextBase != 0
                        && routine >= g_MyArkTdpNtTextBase
                        && routine < g_MyArkTdpNtTextEnd) {
                        flags |= MYARK_DPC_FLAG_NTROUTINE;
                    } else {
                        flags |= MYARK_DPC_FLAG_SUSPECT;
                    }
                    (VOID)MyArkTdpOwnerForAddress(routine, (PUCHAR)row->Owner,
                                                  MYARK_TIMERDPC_OWNER_MAX);
                    row->Flags = flags;
                    written++;
                }
                if (!MyArkTdpReadU64(node, &next) || next == 0) {
                    break;
                }
                node = next;
            }
        }
    }

    out->Count = written;
    out->Status = MYARK_TDP_STATUS_OK;
    out->EntryStructSize = (UINT32)sizeof(MYARK_DPC_ENTRY);
    *BytesReturned = (ULONG)(headSize + (SIZE_T)written * sizeof(MYARK_DPC_ENTRY));
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_TIMERDPC