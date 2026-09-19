// MyArk hwid module: R3-1b ARP class (nsiproxy neighbor-table rewrite).
//
// GetIpNetTable / GetIpNetTable2 read the kernel neighbor table through
// \\.\Nsi (nsiproxy.sys) device-controls. A completion routine on a
// filter attached at the top of that stack sees every response buffer
// while it still lives in the METHOD_BUFFERED SystemBuffer, so neighbor
// MAC bytes can be rewritten in flight without touching the kernel
// table itself.
//
// Two modes on the same attachment:
//   CAPTURE  - passive bring-up tool: record the last N request tuples
//              (code + sizes + input head) and keep the head of the most
//              recent enumerate-shaped response, read back via 0x754.
//              This is how the per-build NSI layout (module GUID, table
//              offsets, entry strides) gets pinned into the Tier C
//              profile below.
//   REWRITE  - class ACTIVE: for responses matching the pinned profile
//              (IOCTL code + neighbor-module GUID in the input head),
//              find entries for the configured neighbor IP and replace
//              their MAC bytes. The kernel table is never modified, so
//              RESTORE simply stops rewriting and detaches; the caller
//              re-queries to prove the original MAC came back.
//
// Until a profile is pinned for the running build the class reports
// UNSUPPORTED and every 0x753 action on it returns
// STATUS_NOT_IMPLEMENTED; the capture tool still works (it is
// profile-independent).

#include <ntddk.h>
#include <ntstrsafe.h>
#include "hwid_spoof_internal.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"

#if MYARK_MODULE_HWID

//
// Tier C build profiles: pinned from 0x754 captures on real guests.
// Unpinned builds keep the rewrite dormant (actions refuse cleanly)
// while the passive capture stays available.
//
typedef struct _MYARK_HWID_ARP_PROFILE {
    ULONG OsBuild;
    ULONG EnumerateIoctl;                // DeviceIoControl code
    GUID  NeighborModuleId;              // input-head GUID of the table
    ULONG CountOffset;                   // request: entry count offset
    ULONG RwTableOffset;                 // request: RW column {ptr, stride}
    ULONG RwStride;
    ULONG RwDataOffset;                  // MAC records start in the RW buffer
    ULONG RwMacOffset;                   // MAC within a record (0 = at start)
    ULONG Spare1;
    ULONG Spare2;
} MYARK_HWID_ARP_PROFILE;

//
// 18362/18363 pinned from the 0x754 captures + the offline decode of the
// OUI-gated dump on 2026-09-19 (CRASH_DEBUG_LOG): the table enumerate is
// the 112-byte 0x12001B request; count @0x18, the RW (MAC) column pair
// @0x38 {ptr, stride 32}, and the MAC records start RwDataOffset bytes
// into that buffer (0x80), 6-byte MAC at record+0. 18363 (19H2) and
// 22631 (Win11 23H2) share the 1903 NSI surface (both byte-verified on
// their guests); 24H2 (26100+) awaits a test VM.
//
static CONST MYARK_HWID_ARP_PROFILE g_MyArkHwidArpProfiles[] = {
    { 18362, 0x12001B,
      { 0 },               // NeighborModuleId not asserted (nsi build-dependent)
      0x18,                // CountOffset
      0x38, 32,            // RW column: offset, stride
      0x80, 0,             // records start, MAC offset
      0, 0 },
    { 18363, 0x12001B,
      { 0 },
      0x18,
      0x38, 32,
      0x80, 0,
      0, 0 },
    // 22631 (Win11 23H2): identical to 1903/19H2 -- byte-verified from
    // the 0x754 capture on the 22631 guest on 2026-09-19 (keys[3]
    // gateway pairs with rw[3], all 11 rows self-consistent).
    { 22631, 0x12001B,
      { 0 },
      0x18,
      0x38, 32,
      0x80, 0,
      0, 0 },
    { 0 }
};

//
// Passive capture ring (nonpaged globals; the completion runs at
// DISPATCH). Guarded by a spin lock -- the ring is tiny and the
// completion must never block on the engine's shared/exclusive lock.
//
typedef struct _MYARK_HWID_ARP_CAPTURE {
    KSPIN_LOCK               Lock;
    LONG                     Armed;
    LONG                     Sequence;
    ULONG                    TupleTotal;
    MYARK_HWID_CAPTURE_TUPLE Tuples[MYARK_HWID_CAPTURE_MAX_TUPLES];
    ULONG                    DumpLen;
    UCHAR                    Dump[MYARK_HWID_CAPTURE_DUMP_BYTES];
    // Round-9b early-return diagnostics (interlocked, unsynchronized read).
    volatile LONG            DiagNotCaller;
    volatile LONG            DiagInFail;
    volatile LONG            DiagNotBig;
    volatile LONG            DiagBig;
} MYARK_HWID_ARP_CAPTURE;

static MYARK_HWID_ARP_CAPTURE g_MyArkHwidArpCapture;

// Exported by ntoskrnl; declared in ntifs.h which this driver does not
// otherwise include.
NTKERNELAPI PEPROCESS IoGetRequestorProcess(_In_ PIRP Irp);

static
NTSTATUS
MyArkHwidSafeCopy(
    _Out_ PUCHAR Dst,
    _In_ PVOID   UserVa,
    _In_ ULONG   Len,
    _Out_ PULONG Copied);

#define MYARK_HWID_ARP_SCRATCH_BYTES  2048
#define MYARK_HWID_ARP_OUT_HEAD_BYTES 512

BOOLEAN
MyArkHwidArpProfileAvailable(VOID)
{
    // Build-constant per boot; cache so 0x752 does not probe under the
    // engine lock on every status query (P2, review).
    static LONG cached = -1;

    if (cached < 0) {
        RTL_OSVERSIONINFOW info;
        ULONG              i;
        LONG               found = 0;

        RtlZeroMemory(&info, sizeof(info));
        info.dwOSVersionInfoSize = sizeof(info);
        if (NT_SUCCESS(RtlGetVersion(&info))) {
            for (i = 0; i < RTL_NUMBER_OF(g_MyArkHwidArpProfiles); i++) {
                if (g_MyArkHwidArpProfiles[i].OsBuild == info.dwBuildNumber) {
                    found = 1;
                    break;
                }
            }
        }
        InterlockedExchange(&cached, found);
    }
    return cached != 0;
}

//
// Profile row for the running build (NULL when unpinned). Cached per
// boot; callers must treat the returned row as immutable.
//
static
CONST MYARK_HWID_ARP_PROFILE*
MyArkHwidArpProfileGet(VOID)
{
    static CONST MYARK_HWID_ARP_PROFILE* cached;
    static LONG                          looked = -1;

    if (looked < 0) {
        RTL_OSVERSIONINFOW info;
        ULONG              i;

        RtlZeroMemory(&info, sizeof(info));
        info.dwOSVersionInfoSize = sizeof(info);
        if (NT_SUCCESS(RtlGetVersion(&info))) {
            for (i = 0; i < RTL_NUMBER_OF(g_MyArkHwidArpProfiles); i++) {
                if (g_MyArkHwidArpProfiles[i].OsBuild == info.dwBuildNumber) {
                    cached = &g_MyArkHwidArpProfiles[i];
                    break;
                }
            }
        }
        InterlockedExchange(&looked, cached != NULL ? 1L : 0L);
    }
    return cached;
}

//
// Round 16b (2026-09-19): the rewrite pass. Runs from the completion when
// the ARP class is active and the request is the profile-pinned table
// enumerate. The RW (MAC) column records are NOT guaranteed to share the
// keys row order, so no index math: the pass reads the RW buffer and
// replaces every occurrence of the ORIGINAL 6-byte MAC with the fake.
// Class value = 16 bytes {IPv4[4], original MAC[6], fake MAC[6]}.
// Everything is SEH/PASSIVE/caller guarded and fails open: any
// read/write error leaves the bytes untouched.
//
static
VOID
MyArkHwidArpRewritePass(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ CONST MYARK_HWID_ARP_PROFILE*    Profile,
    _In_ PUCHAR                           Params)
{
    UINT64 rwPtr;
    UINT64 rwStride;
    UINT64 count;
    ULONG  rwBytes;
    ULONG  got = 0;
    ULONG  scan;
    NTSTATUS st;

    RtlCopyMemory(&count, Params + Profile->CountOffset, sizeof(count));
    RtlCopyMemory(&rwPtr, Params + Profile->RwTableOffset, sizeof(rwPtr));
    RtlCopyMemory(&rwStride, Params + Profile->RwTableOffset + 8,
                  sizeof(rwStride));

    if (count == 0 || count > 64) {
        return;
    }
    if (rwStride == 0 || rwStride > 64) {
        return;
    }
    if (rwPtr < 0x10000 || (rwPtr & 0xFFFF000000000000ULL) != 0) {
        return;
    }

    rwBytes = (ULONG)(count * rwStride);
    if (rwBytes > 1024) {
        rwBytes = 1024;                     // scratch budget guard
    }
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return;
    }

    {
        PUCHAR rwCopy = (PUCHAR)ExAllocatePoolUninitialized(
            NonPagedPoolNx, rwBytes, MYARK_HWID_ARP_POOL_TAG);

        if (rwCopy == NULL) {
            return;
        }
        st = MyArkHwidSafeCopy(rwCopy, (PVOID)rwPtr, rwBytes, &got);
        if (!NT_SUCCESS(st)) {
            ExFreePoolWithTag(rwCopy, MYARK_HWID_ARP_POOL_TAG);
            return;
        }

        for (scan = 0; scan + 6 <= got; scan++) {
            if (RtlCompareMemory(rwCopy + scan, &State->Spoof[4], 6) == 6) {
                try {
                    ProbeForWrite((PVOID)(rwPtr + scan), 6, 1);
                    RtlCopyMemory((PVOID)(rwPtr + scan), &State->Spoof[10], 6);
                    InterlockedIncrement(&State->RewrittenCount);
                } except (EXCEPTION_EXECUTE_HANDLER) {
                    // fail open; keep scanning later offsets
                }
                scan += 5;
            }
        }
        ExFreePoolWithTag(rwCopy, MYARK_HWID_ARP_POOL_TAG);
    }
}

//
// Dispatch-time context: remember the request code + input head (the
// METHOD_BUFFERED buffer is about to be overwritten by the response).
// Allocation failure fails open: the completion receives Ext itself and
// that one IRP is neither captured nor rewritten.
//
// Bring-up instrumentation: EVERY major is captured (non-device-control
// failures are recorded too
// recorded too -- the first calibration round showed zero tuples for
// plain successful device controls, which means nothing reached the
// filter at all.
//
PVOID
MyArkHwidArpCaptureRequestContext(
    _In_ PMYARK_HWID_FILTER_EXT Ext,
    _Inout_ PIRP                Irp,
    _In_ PIO_STACK_LOCATION     Slot)
{
    PMYARK_HWID_ARP_CTX ctx;
    ULONG inLen;

    // Non-device-control IRPs (creates/closes flooded the first rounds)
    // no longer take a context -- only device controls are captured.
    if (Slot->MajorFunction != IRP_MJ_DEVICE_CONTROL) {
        return Ext;
    }

    ctx = (PMYARK_HWID_ARP_CTX)MyArkAllocatePool(NonPagedPoolNx,
                                                 sizeof(MYARK_HWID_ARP_CTX),
                                                 MYARK_HWID_ARP_POOL_TAG);
    if (ctx == NULL) {
        return Ext;
    }
    ctx->Magic = MYARK_HWID_ARP_CTX_MAGIC;
    ctx->Ext = Ext;
    ctx->Code = Slot->Parameters.DeviceIoControl.IoControlCode;
    inLen = Slot->Parameters.DeviceIoControl.InputBufferLength;
    ctx->InLen = (inLen <= MYARK_HWID_CAPTURE_IN_BYTES)
                     ? inLen : MYARK_HWID_CAPTURE_IN_BYTES;
    // METHOD_BUFFERED / OUT_DIRECT: input head from SystemBuffer. For
    // METHOD_NEITHER the input is a raw user VA -- never touched here.
    if (Irp->AssociatedIrp.SystemBuffer != NULL) {
        RtlCopyMemory(ctx->In, Irp->AssociatedIrp.SystemBuffer, ctx->InLen);
    } else {
        RtlZeroMemory(ctx->In, sizeof(ctx->In));
        ctx->In[0] = (UCHAR)((Slot->Parameters.DeviceIoControl.IoControlCode & 3));
    }
    return ctx;
}

static
BOOLEAN
MyArkHwidArpIsCtx(_In_ PVOID Context)
{
    return Context != NULL
           && ((PMYARK_HWID_ARP_CTX)Context)->Magic == MYARK_HWID_ARP_CTX_MAGIC;
}

//
// Completion: bookkeeping for one completed \Device\Nsi device-control.
// METHOD_NEITHER requests complete synchronously in the caller's thread,
// which the capture below verifies before touching any user VA.
//
VOID
MyArkHwidArpControlComplete(
    _In_ PMYARK_HWID_FILTER_EXT       Ext,
    _In_opt_ PVOID                    Context,
    _Inout_ PIRP                      Irp)
{
    PMYARK_HWID_SPOOF_CLASS_STATE state;
    PIO_STACK_LOCATION            slot;
    PMYARK_HWID_ARP_CTX           ctx;
    BOOLEAN                       rewriteOn;

    if (!MyArkHwidArpIsCtx(Context)) {
        return;                     // dispatch alloc failed: nothing to do
    }
    ctx = (PMYARK_HWID_ARP_CTX)Context;

    slot = IoGetCurrentIrpStackLocation(Irp);

    state = MyArkHwidSpoofClassState(Ext->Class);
    if (state != NULL) {
        InterlockedIncrement(&state->QueryCount);   // any IRP reaching us
    }

    // REWRITE mode (Round 16b): with a pinned profile and an active
    // class the completion also patches the MAC the user tables see --
    // the capture ring below stays capture-only and keeps requiring
    // Armed.

    //
    // Bring-up calibration, round 4: the NSI IOCTLs are METHOD_NEITHER
    // (0x120007/0x12000F/0x12001B on 1903; SystemBuffer always NULL).
    // The request (64B NSI_PARAMS) carries embedded USER pointers to the
    // table buffers and the response (UserBuffer) is a result header --
    // the enumerate payload flows through those user VAs, not the IRP.
    // Record: params copy + UserBuffer head + IRQL + caller-context flag.
    // Everything SEH-guarded, caller-context only, fail-open.
    //
    rewriteOn = (state != NULL && state->Active && state->SpoofLen == 16
                 && MyArkHwidArpProfileGet() != NULL);
    if ((g_MyArkHwidArpCapture.Armed || rewriteOn)
        && Irp->RequestorMode == UserMode) {
        KIRQL          oldIrql;
        ULONG          idx;
        PVOID          inVa = slot->Parameters.DeviceIoControl.Type3InputBuffer;
        PVOID          outVa = Irp->UserBuffer;
        ULONG          inLen2 = slot->Parameters.DeviceIoControl.InputBufferLength;
        ULONG          outLen2 = slot->Parameters.DeviceIoControl.OutputBufferLength;
        BOOLEAN        inCaller = (IoGetRequestorProcess(Irp) == PsGetCurrentProcess());
        BOOLEAN        armed = g_MyArkHwidArpCapture.Armed ? TRUE : FALSE;

        if (!inCaller) {
            InterlockedIncrement(&g_MyArkHwidArpCapture.DiagNotCaller);
        }
        UCHAR          scratch[MYARK_HWID_ARP_SCRATCH_BYTES];
        ULONG          scratchLen = 0;
        ULONG          paramsGot = 0;
        ULONG          diag;
        BOOLEAN        big;
        BOOLEAN        bigSlot;
        NTSTATUS       st2 = STATUS_SUCCESS;

        //
        // Round 5: capture the full METHOD_NEITHER request (NSI_PARAMS,
        // 112 bytes for 0x12001B on 1903) plus SEH-dereferenced heads of
        // the embedded user buffers (qword pointers at +0x10 and every
        // +0x10 after -- paired with a u64 size at +8). The neighbor
        // enumerate is the call whose embedded buffers are the largest.
        //
        if (inCaller && inVa != NULL && inLen2 > 0
            && inLen2 <= MYARK_HWID_ARP_SCRATCH_BYTES / 2) {
            ULONG got = 0;
            st2 = MyArkHwidSafeCopy(scratch + scratchLen, inVa, inLen2, &got);
            paramsGot = got;
            scratchLen += got;
        }
        if (!NT_SUCCESS(st2)) {
            InterlockedIncrement(&g_MyArkHwidArpCapture.DiagInFail);
        }

        //
        // Round 16b: the rewrite pass -- every profile-pinned enumerate
        // while the class is active, independent of the capture ring.
        //
        if (rewriteOn && inCaller && paramsGot == 112) {
            CONST MYARK_HWID_ARP_PROFILE* profile = MyArkHwidArpProfileGet();

            // P2 (review): the profile's opcode is part of the pin --
            // a 112-byte non-enumerate request must not run the pass.
            if (profile != NULL && ctx->Code == profile->EnumerateIoctl) {
                MyArkHwidArpRewritePass(state, profile, scratch);
            }
        }

        //
        // Round 7: only table-sized enumerates are interesting -- the
        // neighbor table carries >= 0x200 bytes of embedded buffers on
        // this guest. Sizing probes (null buffers) and the 0x120007
        // query flood never reach the ring; deref outcome bits:
        // 0x200 module GUID, 0x400/0x800/0x1000/0x2000/0x4000 = n-th
        // dedup'd pair deref, 0x8000 out-VA-null, 0x0001 out-head.
        //
        diag = 0;
        //
        // Round 15e: slot 0 wants the 0x12001B (112B) table enumerate --
        // on 1903 GetIpNetTable2 rides ONE 112B call per table with
        // per-row-stride column pairs, not a single 104B blob.
        //
        big = inCaller && (inLen2 == 104 || inLen2 == 112);
        bigSlot = inCaller && (inLen2 == 112);
        if (armed && scratchLen >= 0x40) {
            //
            // Round 14 (2026-09-19): sliding pair scan. The NSI_PARAMS
            // pair layout differs per opcode -- 1903 snapshots show the
            // module pointer at 0x10 (0x12000F) or 0x18 (0x120007/1B)
            // and pairs at 0x28..0x60 in opcode-specific positions --
            // so no fixed offset table can work. Slide over the whole
            // request: every qword that looks like a user VA and is
            // followed 8 bytes later by a sane size gets deref'd once
            // (dedup by pointer). 0x7ff-range pointers are the module
            // descriptor; take 16 bytes there (the NSI module GUID).
            //
            ULONG  off;
            ULONG  pairs = 0;
            SIZE_T seenPtrs[8];
            ULONG  seenCount = 0;

            for (off = 0x10;
                 off + 16 <= inLen2 && off + 16 <= scratchLen;
                 off += 8) {
                SIZE_T ptr2;
                SIZE_T len2;
                ULONG  cap2;
                ULONG  k;

                RtlCopyMemory(&ptr2, scratch + off, sizeof(SIZE_T));
                RtlCopyMemory(&len2, scratch + off + 8, sizeof(SIZE_T));
                if (ptr2 < 0x10000 || (ptr2 & 0xFFFF000000000000ULL) != 0) {
                    continue;
                }
                // Module descriptor (nsi.dll data) pointers ride the
                // 0x7Fxx ASLR range (0x7ffab0f3b070, 0x7fac4c1c10 both
                // seen) -- 16-byte GUID head, dedup not needed (one
                // slot per request).
                if ((ptr2 >> 40) == 0x7FULL) {
                    // module descriptor (nsi.dll data): 16-byte GUID head
                    if (scratchLen + 16 <= MYARK_HWID_ARP_SCRATCH_BYTES) {
                        ULONG got16 = 0;
                        if (NT_SUCCESS(MyArkHwidSafeCopy(
                                scratch + scratchLen, (PVOID)ptr2, 16,
                                &got16))) {
                            diag |= 0x200UL;
                            scratchLen += got16;
                        }
                    }
                    continue;
                }
                if (len2 == 0 || len2 > 0x100000) {
                    continue;
                }
                for (k = 0; k < seenCount; k++) {
                    if (seenPtrs[k] == ptr2) {
                        break;
                    }
                }
                if (k < seenCount) {
                    continue;
                }
                if (seenCount < RTL_NUMBER_OF(seenPtrs)) {
                    seenPtrs[seenCount++] = ptr2;
                }
                //
                // Round 15d: the pair size field is the PER-ROW stride;
                // the buffer holds Count x stride records (the neighbor
                // enumerate runs with count=11 on this guest). Deref a
                // stride-multiple so the whole column lands in scratch,
                // not just record 0.
                //
                cap2 = (ULONG)len2 * 16;
                if (cap2 > 384) {
                    cap2 = 384;
                }
                if (scratchLen + cap2 > MYARK_HWID_ARP_SCRATCH_BYTES) {
                    break;
                }
                {
                    ULONG got = 0;
                    if (NT_SUCCESS(MyArkHwidSafeCopy(scratch + scratchLen,
                                                     (PVOID)ptr2, cap2,
                                                     &got))) {
                        switch (pairs) {
                        case 0: diag |= 0x400UL; break;
                        case 1: diag |= 0x800UL; break;
                        case 2: diag |= 0x1000UL; break;
                        case 3: diag |= 0x2000UL; break;
                        default: diag |= 0x4000UL; break;
                        }
                        pairs++;
                        scratchLen += got;
                    }
                }
            }
        }
        // Round 12: no big gate -- the neighbor request may carry small
        // column buffers; the OUI content gate alone decides the dump.
        if (big) {
            InterlockedIncrement(&g_MyArkHwidArpCapture.DiagBig);
        } else {
            InterlockedIncrement(&g_MyArkHwidArpCapture.DiagNotBig);
        }
        if (outVa == NULL) {
            diag |= 0x8000UL;
        } else if (inCaller && NT_SUCCESS(st2) && outLen2 > 0) {
            // P1-3 (review): only read the requester's UserBuffer when the
            // completion runs in the requester's address space.
            ULONG c2 = (outLen2 <= MYARK_HWID_ARP_OUT_HEAD_BYTES)
                           ? outLen2 : MYARK_HWID_ARP_OUT_HEAD_BYTES;
            if (c2 <= MYARK_HWID_ARP_SCRATCH_BYTES - scratchLen) {
                ULONG got = 0;
                if (NT_SUCCESS(MyArkHwidSafeCopy(scratch + scratchLen, outVa,
                                                 c2, &got))) {
                    diag |= 0x0001UL;   // 0x4000 now means pair@0x60
                    scratchLen += got;
                }
            }
        }

        // Round 16b: everything from here to KeReleaseSpinLock is
        // capture-ring work and only runs while the capture is armed --
        // the rewrite pass above must keep working with the ring
        // disarmed.
        if (armed) {
        KeAcquireSpinLock(&g_MyArkHwidArpCapture.Lock, &oldIrql);
        // Round 15: slot 0 is reserved for the most recent big (table-
        // sized) request -- the 0x120007 flood behind every enumerate
        // otherwise churns the ring before the readback ever sees a
        // big tuple.
        idx = bigSlot ? 0
                      : (1 + (g_MyArkHwidArpCapture.TupleTotal
                              % (MYARK_HWID_CAPTURE_MAX_TUPLES - 1)));
        g_MyArkHwidArpCapture.Tuples[idx].IoctlCode = ctx->Code;
        g_MyArkHwidArpCapture.Tuples[idx].InLen = inLen2;
        g_MyArkHwidArpCapture.Tuples[idx].OutLen = outLen2;
        // Reserved: high 16 bits = scratchLen, bit 0x8000 out-VA null,
        // 0x0001 out-head copied, 0x100 caller, 0x7FFE deref diag.
        g_MyArkHwidArpCapture.Tuples[idx].Reserved =
            (UINT32)((scratchLen << 16)
                     | (outVa == NULL ? 0x8000UL : 0UL)
                     | (diag & 0x7FFFUL)
                     | (inCaller ? 0x100UL : 0UL));
        //
        // P1-2 (review): scratch may be uninitialized when the first copy
        // never ran (buffered IRP / !inCaller / SEH fault) -- publish only
        // the bytes actually captured, never raw kernel stack.
        //
        RtlZeroMemory(g_MyArkHwidArpCapture.Tuples[idx].Input,
                      MYARK_HWID_CAPTURE_IN_BYTES);
        {
            // Round 15f (review P1): publish only bytes actually copied
            // from the request. When the first copy was SKIPPED (!inCaller,
            // NULL inVa, oversized), st2 still reads SUCCESS from init and
            // scratch holds raw kernel stack -- paramsGot stays 0 there,
            // so the zeroed Input goes out empty instead of leaking.
            ULONG headLen = paramsGot;
            if (headLen > MYARK_HWID_CAPTURE_IN_BYTES) {
                headLen = MYARK_HWID_CAPTURE_IN_BYTES;
            }
            if (headLen != 0) {
                RtlCopyMemory(g_MyArkHwidArpCapture.Tuples[idx].Input,
                              scratch,
                              headLen);
            }
        }
        g_MyArkHwidArpCapture.TupleTotal++;

        BOOLEAN hasOui = FALSE;
        ULONG   scan;
        for (scan = 0; scan + 3 <= scratchLen; scan++) {
            if (scratch[scan] == 0x00 && scratch[scan + 1] == 0x50
                && scratch[scan + 2] == 0x56) {
                hasOui = TRUE;
                break;
            }
        }
        if (NT_SUCCESS(st2) && scratchLen >= 64) {
            ULONG copy = (scratchLen <= MYARK_HWID_CAPTURE_DUMP_BYTES)
                             ? scratchLen : MYARK_HWID_CAPTURE_DUMP_BYTES;
            if (bigSlot && !hasOui) {
                // Round 15: keep the last big enumerate's scratch even
                // when the OUI gate has not fired -- the pair contents
                // ARE the calibration payload this tool exists for.
                RtlCopyMemory(g_MyArkHwidArpCapture.Dump, scratch, copy);
                g_MyArkHwidArpCapture.DumpLen = copy;
            }
            if (hasOui) {
                RtlCopyMemory(g_MyArkHwidArpCapture.Dump, scratch, copy);
                g_MyArkHwidArpCapture.DumpLen = copy;
                InterlockedIncrement(&g_MyArkHwidArpCapture.Sequence);
            }
        }
        KeReleaseSpinLock(&g_MyArkHwidArpCapture.Lock, oldIrql);
        }
    }
}

//
// SEH-guarded capture copy (PASSIVE_LEVEL only, caller context). Returns
// STATUS_SUCCESS with *Copied filled, or a failure and *Copied untouched.
//
static
NTSTATUS
MyArkHwidSafeCopy(
    _Out_ PUCHAR  Dst,
    _In_  PVOID   UserVa,
    _In_  ULONG   Len,
    _Out_ PULONG  Copied)
{
    NTSTATUS status = STATUS_SUCCESS;

    *Copied = 0;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return STATUS_UNSUCCESSFUL;
    }
    try {
        ProbeForRead(UserVa, Len, 1);
        RtlCopyMemory(Dst, UserVa, Len);
        *Copied = Len;
    } except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

NTSTATUS
MyArkHwidSpoofArpCaptureStart(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State)
{
    UNICODE_STRING nsi;
    NTSTATUS       status;

    if (State->AttachedCount != 0) {
        return STATUS_INVALID_DEVICE_STATE;    // already armed / active
    }

    {
        // P2 (review): clear the ring under its own lock so a completion
        // racing the arm cannot interleave with the reset.
        KIRQL irql;
        KeAcquireSpinLock(&g_MyArkHwidArpCapture.Lock, &irql);
        RtlZeroMemory(&g_MyArkHwidArpCapture.Tuples,
                      sizeof(g_MyArkHwidArpCapture.Tuples));
        g_MyArkHwidArpCapture.TupleTotal = 0;
        g_MyArkHwidArpCapture.DumpLen = 0;
        KeReleaseSpinLock(&g_MyArkHwidArpCapture.Lock, irql);
    }

    RtlInitUnicodeString(&nsi, L"\\Device\\Nsi");
    status = MyArkHwidSpoofAttachTarget(MYARK_HWID_SPOOF_CLASS_ARP,
                                        &nsi,
                                        MYARK_HWID_TARGET_NSIPROXY,
                                        0,
                                        State);
    if (NT_SUCCESS(status)) {
        InterlockedExchange(&g_MyArkHwidArpCapture.Armed, 1);
    }
    return status;
}

VOID
MyArkHwidSpoofArpCaptureStop(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State)
{
    InterlockedExchange(&g_MyArkHwidArpCapture.Armed, 0);
    if (State->AttachedCount != 0) {
        // Single-thread contract (WDF sequential queue + teardown
        // ordering), same as the disk classes' DetachClassLocked.
        MyArkHwidSpoofDetachClassLocked(State);
    }
}

VOID
MyArkHwidSpoofArpFillCaptureOutput(
    _Out_ PMYARK_HWID_CAPTURE_OUTPUT Output)
{
    KIRQL oldIrql;

    RtlZeroMemory(Output, sizeof(*Output));
    Output->Magic = MYARK_HWID_CAPTURE_MAGIC;

    KeAcquireSpinLock(&g_MyArkHwidArpCapture.Lock, &oldIrql);
    Output->Armed = (UINT32)g_MyArkHwidArpCapture.Armed;
    Output->Sequence = (UINT64)g_MyArkHwidArpCapture.Sequence;
    Output->TupleCount = g_MyArkHwidArpCapture.TupleTotal
                             > MYARK_HWID_CAPTURE_MAX_TUPLES
                         ? MYARK_HWID_CAPTURE_MAX_TUPLES
                         : g_MyArkHwidArpCapture.TupleTotal;
    RtlCopyMemory(Output->Tuples,
                  g_MyArkHwidArpCapture.Tuples,
                  sizeof(Output->Tuples));
    Output->DumpLen = g_MyArkHwidArpCapture.DumpLen;
    RtlCopyMemory(Output->Dump, g_MyArkHwidArpCapture.Dump, Output->DumpLen);
    Output->DiagNotCaller = (UINT32)g_MyArkHwidArpCapture.DiagNotCaller;
    Output->DiagInFail = (UINT32)g_MyArkHwidArpCapture.DiagInFail;
    Output->DiagNotBig = (UINT32)g_MyArkHwidArpCapture.DiagNotBig;
    Output->DiagBig = (UINT32)g_MyArkHwidArpCapture.DiagBig;
    KeReleaseSpinLock(&g_MyArkHwidArpCapture.Lock, oldIrql);
}

//
// 0x753 actions for the ARP class. Profile-gated: without a pinned
// layout every action refuses cleanly (no attachment, no state).
//

NTSTATUS
MyArkHwidSpoofArpDryRun(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ PUCHAR                        Spoof,
    _In_ ULONG                         SpoofLen,
    _Out_ PUCHAR                       Real,
    _Inout_ PULONG                     RealLen)
{
    UNREFERENCED_PARAMETER(State);

    if (!MyArkHwidArpProfileAvailable()) {
        return STATUS_NOT_IMPLEMENTED;      // unpinned build: dormant
    }
    if (SpoofLen != 16) {
        return STATUS_INVALID_PARAMETER;
    }
    if (*RealLen < 6) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    // Preview: the original the caller is about to replace.
    RtlCopyMemory(Real, &Spoof[4], 6);
    *RealLen = 6;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkHwidSpoofArpApply(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ PUCHAR                           Spoof,
    _In_ ULONG                            SpoofLen,
    _Out_ PUCHAR                          Real,
    _Inout_ PULONG                        RealLen)
{
    UNICODE_STRING nsi;
    NTSTATUS       status;

    if (!MyArkHwidArpProfileAvailable()) {
        return STATUS_NOT_IMPLEMENTED;
    }
    if (SpoofLen != 16) {
        return STATUS_INVALID_PARAMETER;
    }

    if (State->AttachedCount == 0) {
        RtlInitUnicodeString(&nsi, L"\\Device\\Nsi");
        status = MyArkHwidSpoofAttachTarget(MYARK_HWID_SPOOF_CLASS_ARP,
                                            &nsi,
                                            MYARK_HWID_TARGET_NSIPROXY,
                                            0,
                                            State);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    State->SpoofLen = SpoofLen;
    RtlCopyMemory(State->Spoof, Spoof, SpoofLen);
    State->CacheLen = 6;
    RtlCopyMemory(State->Cache, &Spoof[4], 6);
    State->CacheValid = TRUE;               // the caller-probed original
    State->Active = TRUE;
    State->LastStatus = STATUS_SUCCESS;

    if (*RealLen >= 6) {
        RtlCopyMemory(Real, &Spoof[4], 6);
        *RealLen = 6;
    } else {
        *RealLen = 0;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkHwidSpoofArpRestore(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _Out_ PUCHAR                          Real,
    _Inout_ PULONG                        RealLen)
{
    UCHAR   cache[6];
    ULONG   cacheLen = 0;
    BOOLEAN hadCache;
    BOOLEAN wasActive;

    if (State->AttachedCount == 0 && !State->Active) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Stop rewriting first: every future enumerate passes through
    // untouched and the next user query shows the kernel truth again.
    // The attachment stays up while the capture still needs it.
    wasActive = State->Active;
    hadCache = State->CacheValid;
    cacheLen = State->CacheLen;
    RtlCopyMemory(cache, State->Cache, sizeof(cache));
    State->Active = FALSE;
    State->CacheValid = FALSE;
    State->SpoofLen = 0;

    if (!g_MyArkHwidArpCapture.Armed && State->AttachedCount != 0) {
        MyArkHwidSpoofDetachClassLocked(State);
    }

    if (hadCache && cacheLen == 6 && Real != NULL
        && RealLen != NULL && *RealLen >= 6) {
        RtlCopyMemory(Real, cache, 6);
        *RealLen = 6;
    } else if (RealLen != NULL) {
        *RealLen = 0;
    }
    State->LastStatus = wasActive ? STATUS_SUCCESS
                                  : STATUS_INVALID_DEVICE_STATE;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_HWID
