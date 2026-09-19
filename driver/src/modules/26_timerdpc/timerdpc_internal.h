// MyArk timerdpc module: internal profile + helpers (compile-time only).
//
// The KPRCB TimerTable / DpcData offsets and the KiWaitNever/KiWaitAlways
// nt-data offsets are Tier C build-pinned constants, each verified live
// over KDNET (18362 on 2026-09-17, 22621 on 2026-09-17 -- see
// tests/CRASH_DEBUG_LOG.md). Builds outside both profiles answer
// MYARK_TDP_STATUS_NO_OFFSETS instead of guessing.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "timerdpc_descriptor.h"
#include "../../../shared/driver/MyArkTimerIoctl.h"

#if MYARK_MODULE_TIMERDPC

#define MYARK_TRACE_TIMERDPC "[timerdpc] "

//
// Build profile (all values nt-relative or KPRCB-relative byte offsets).
//
typedef struct _MYARK_TDP_PROFILE {
    ULONG BuildMin;
    ULONG BuildMax;
    ULONG PrcbTimerTable;      // KPRCB.TimerTable
    ULONG PrcbDpcData;         // KPRCB.DpcData[2]
    ULONG DpcDataStride;       // sizeof(_KDPC_DATA) on this build
    ULONG KiWaitNever;         // nt data offset
    ULONG KiWaitAlways;        // nt data offset
    ULONG KiProcessorBlock;    // nt data offset (PKPRCB per CPU)
    ULONG BucketBase;          // KTIMER_TABLE.TimerEntries byte offset
    ULONG BucketCount;         // number of timer buckets (stride 0x20)
} MYARK_TDP_PROFILE;

// Verified 1903 (18362/18363, 19H1).
#define MYARK_TDP_PROFILE_18362 \
    { 18362, 18363, 0x3680UL, 0x2E00UL, 0x28UL, 0x574700UL, 0x5748F0UL, \
      0x575AC0UL, 0x200UL, 256UL }
// Verified Win11 22H2 (22621/22631, ni_release).
#define MYARK_TDP_PROFILE_22621 \
    { 22621, 22631, 0x3C00UL, 0x3340UL, 0x30UL, 0xD1EE88UL, 0xD1F120UL, \
      0xD20980UL, 0x2200UL, 512UL }

//
// Build-stable structure offsets (identical on 18362 and 22621; asserted
// live via KDNET `dt` both days).
//
#define MYARK_TDP_KTIMER_DUETIME        0x18UL
#define MYARK_TDP_KTIMER_LISTENTRY      0x20UL
#define MYARK_TDP_KTIMER_DPC            0x30UL
#define MYARK_TDP_KTIMER_PERIOD         0x3CUL
#define MYARK_TDP_KDPC_DpclISTENTRY     0x08UL
#define MYARK_TDP_KDPC_ROUTINE          0x18UL
#define MYARK_TDP_KDPC_CONTEXT          0x20UL
#define MYARK_TDP_KDPCDATA_HEAD         0x00UL
#define MYARK_TDP_KDPCDATA_DEPTH        0x18UL
#define MYARK_TDP_KDPCDATA_ACTIVE       0x20UL
#define MYARK_TDP_TABLE_EXPIRY          0x000UL   // TimerExpiry[64] KTIMER*
#define MYARK_TDP_EXPIRY_SLOTS          64UL
#define MYARK_TDP_ENTRY_STRIDE          0x20UL
#define MYARK_TDP_TABLE_ENTRY_HEAD      0x08UL    // Entry within TABLE_ENTRY

#define MYARK_TDP_MAX_CPU               32UL
#define MYARK_TDP_BUCKET_ITERS          64UL
#define MYARK_TDP_DPC_ITERS             128UL

//
// Lazily resolved module state (one-shot at first IOCTL).
//
extern const MYARK_TDP_PROFILE* g_MyArkTdpProfile;   // NULL = unsupported build
extern UINT64 g_MyArkTdpNtBase;                      // ntoskrnl image base
extern UINT64 g_MyArkTdpNtTextBase;                  // from dyndata (0 = unknown)
extern UINT64 g_MyArkTdpNtTextEnd;

NTSTATUS MyArkTdpEnsureInit(VOID);

// Dyndata resolver outputs (same externs the callback/wfp modules
// import). Text bounds gate the NTROUTINE flag; the module list powers
// owner lookup. Both may legitimately be 0 -- rows stay valid, flags
// degrade.
extern UINT64 g_MyArkDynDataNtoskrnlTextBase;
extern UINT64 g_MyArkDynDataNtoskrnlTextEnd;
extern PVOID  g_MyArkDynDataPsLoadedModuleList;

//
// Walk engines (timerdpc_walk.c). Both emit into a METHOD_BUFFERED
// output buffer and always succeed: failures degrade to fewer rows.
//
NTSTATUS MyArkTimerDpcWalkTimers(
    _Out_writes_bytes_(OutSize) PUCHAR OutBuf,
    _In_ SIZE_T OutSize,
    _Out_ PULONG BytesReturned);

NTSTATUS MyArkTimerDpcWalkDpcs(
    _Out_writes_bytes_(OutSize) PUCHAR OutBuf,
    _In_ SIZE_T OutSize,
    _Out_ PULONG BytesReturned);

//
// Probe-safe readers (page-gated; never fault).
//
BOOLEAN MyArkTdpReadU32(_In_ UINT64 Address, _Out_ UINT32* ValueOut);
BOOLEAN MyArkTdpReadU64(_In_ UINT64 Address, _Out_ UINT64* ValueOut);

//
// Owner lookup: BaseDllName of the loaded module containing Address.
// Returns chars written (0 = not found / module list unavailable).
//
ULONG MyArkTdpOwnerForAddress(_In_ UINT64 Address,
                              _Out_writes_bytes_(OutBytes) PUCHAR Out,
                              _In_ ULONG OutBytes);

#endif // MYARK_MODULE_TIMERDPC