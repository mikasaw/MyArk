// MyArk hwid module: R3-1 spoof IOCTL handlers.
//
//   0x752 QUERY_SPOOF_STATUS - read-only per-class snapshot (no token).
//   0x753 SET_SPOOF_CONFIG   - SAFETY_TOKEN gated. APPLY additionally
//                              requires UI_CONFIRMED|FORCE (T-D double
//                              flag); DRY_RUN and RESTORE need the token
//                              only.

#include "hwid_spoof_internal.h"
#include "../../dispatch/ioctl_helpers.h"
#include "../../dispatch/safety_token.h"

#if MYARK_MODULE_HWID

static
VOID
MyArkHwidSpoofFillPreview(
    _Out_ PMYARK_HWID_SPOOF_PREVIEW Preview,
    _In_  NTSTATUS                  Status,
    _In_  PUCHAR                    Real,
    _In_  ULONG                     RealLen,
    _In_  PUCHAR                    Spoof,
    _In_  ULONG                     SpoofLen)
{
    RtlZeroMemory(Preview, sizeof(*Preview));
    Preview->Status = (UINT32)Status;
    Preview->RealLen = (RealLen <= MYARK_HWID_SPOOF_VALUE_MAX_BYTES)
                           ? RealLen : MYARK_HWID_SPOOF_VALUE_MAX_BYTES;
    Preview->SpoofLen = (SpoofLen <= MYARK_HWID_SPOOF_VALUE_MAX_BYTES)
                            ? SpoofLen : MYARK_HWID_SPOOF_VALUE_MAX_BYTES;
    if (Real != NULL && Preview->RealLen != 0) {
        RtlCopyMemory(Preview->Real, Real, Preview->RealLen);
    }
    if (Spoof != NULL && Preview->SpoofLen != 0) {
        RtlCopyMemory(Preview->Spoof, Spoof, Preview->SpoofLen);
    }
}

NTSTATUS
MyArkHwidIoctlQuerySpoofStatus(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_HWID_SPOOF_STATUS_OUTPUT out;
    size_t                          outSize = sizeof(MYARK_HWID_SPOOF_STATUS_OUTPUT);
    ULONG                           oldIrql;
    UINT32                          i;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < outSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    {
        NTSTATUS status = MyArkIoctlFetchOutputBuffer(Request, outSize, (PVOID*)&out);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    oldIrql = MyArkHwidSpoofLockExclusive();
    out->Count = MYARK_HWID_SPOOF_CLASS_COUNT;
    out->Reserved1 = 0;
    out->Reserved64 = 0;
    for (i = 0; i < MYARK_HWID_SPOOF_CLASS_COUNT; i++) {
        PMYARK_HWID_SPOOF_CLASS_STATE state = MyArkHwidSpoofClassState(i + 1);
        PMYARK_HWID_SPOOF_CLASS_STATUS entry = &out->Classes[i];

        RtlZeroMemory(entry, sizeof(*entry));
        entry->Class = i + 1;
        if (state == NULL) {
            continue;
        }
        entry->Flags = 0;
        if (state->Active)          entry->Flags |= MYARK_HWID_SPOOF_ST_ACTIVE;
        if (state->SpoofLen != 0)   entry->Flags |= MYARK_HWID_SPOOF_ST_SPOOF_SET;
        if (state->CacheValid)      entry->Flags |= MYARK_HWID_SPOOF_ST_CACHE_VALID;
        if (state->AttachedCount != 0) entry->Flags |= MYARK_HWID_SPOOF_ST_ATTACHED;
        if (i + 1 == MYARK_HWID_SPOOF_CLASS_ARP
            && !MyArkHwidArpProfileAvailable()) {
            // R3-1b: the rewrite path needs the per-build NSI layout
            // profile; capture still works, actions refuse.
            entry->Flags |= MYARK_HWID_SPOOF_ST_UNSUPPORTED;
        }
        entry->SpoofLen = state->SpoofLen;
        entry->CacheLen = state->CacheLen;
        entry->RewrittenCount = (UINT32)state->RewrittenCount;
        entry->AttachedCount = state->AttachedCount;
        entry->QueryCount = (UINT32)state->QueryCount;
        entry->LastStatus = (UINT32)state->LastStatus;
    }
    MyArkHwidSpoofUnlockExclusive(oldIrql);

    *BytesReturned = outSize;
    return STATUS_SUCCESS;
}

//
// Run one DRY_RUN/APPLY/RESTORE for a disk-backed or GPU class. Returns
// the overall status; preview fields are filled for every outcome.
//
static
NTSTATUS
MyArkHwidSpoofDispatchAction(
    _In_  PMYARK_HWID_SPOOF_SET_INPUT  Input,
    _Out_ PMYARK_HWID_SPOOF_SET_OUTPUT Output)
{
    PMYARK_HWID_SPOOF_CLASS_STATE state;
    UCHAR                         real[MYARK_HWID_SPOOF_VALUE_MAX_BYTES];
    ULONG                         realLen = sizeof(real);
    NTSTATUS                      status = STATUS_SUCCESS;
    BOOLEAN                       applied = FALSE;

    state = MyArkHwidSpoofClassState(Input->Class);
    if (state == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(real, sizeof(real));
    Output->Preview.RealLen = 0;
    Output->Preview.SpoofLen = 0;
    Output->Preview.Status = 0;

    switch (Input->Action) {
    case MYARK_HWID_SPOOF_ACTION_DRY_RUN:
        if (Input->Class == MYARK_HWID_SPOOF_CLASS_GPU_SERIAL) {
            status = MyArkHwidSpoofGpuDryRun(state, Input->Value, Input->ValueSize,
                                             real, &realLen);
        } else if (Input->Class == MYARK_HWID_SPOOF_CLASS_ARP) {
            status = MyArkHwidSpoofArpDryRun(state, Input->Value, Input->ValueSize,
                                             real, &realLen);
        } else {
            status = MyArkHwidSpoofDiskDryRun(state, Input->DiskIndex,
                                              Input->Value, Input->ValueSize,
                                              real, &realLen);
        }
        break;

    case MYARK_HWID_SPOOF_ACTION_APPLY:
        // (double-flag gate enforced at the IOCTL boundary above)
        if (Input->Class == MYARK_HWID_SPOOF_CLASS_GPU_SERIAL) {
            status = MyArkHwidSpoofGpuApply(state, Input->Value, Input->ValueSize,
                                            real, &realLen);
        } else if (Input->Class == MYARK_HWID_SPOOF_CLASS_ARP) {
            status = MyArkHwidSpoofArpApply(state, Input->Value, Input->ValueSize,
                                            real, &realLen);
        } else {
            status = MyArkHwidSpoofDiskApply(state, Input->DiskIndex,
                                             Input->Value, Input->ValueSize,
                                             real, &realLen);
        }
        applied = NT_SUCCESS(status);
        break;

    case MYARK_HWID_SPOOF_ACTION_RESTORE:
        if (Input->Class == MYARK_HWID_SPOOF_CLASS_GPU_SERIAL) {
            status = MyArkHwidSpoofGpuRestore(state, real, &realLen);
        } else if (Input->Class == MYARK_HWID_SPOOF_CLASS_ARP) {
            status = MyArkHwidSpoofArpRestore(state, real, &realLen);
        } else {
            status = MyArkHwidSpoofDiskRestore(state, real, &realLen);
        }
        break;

    case MYARK_HWID_SPOOF_ACTION_CAPTURE:
        if (Input->Class != MYARK_HWID_SPOOF_CLASS_ARP) {
            status = STATUS_INVALID_PARAMETER;
        } else if (Input->Flags & MYARK_HWID_SPOOF_FLAG_CAPTURE_START) {
            status = MyArkHwidSpoofArpCaptureStart(state);
        } else {
            MyArkHwidSpoofArpCaptureStop(state);
            status = STATUS_SUCCESS;
        }
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    MyArkHwidSpoofFillPreview(&Output->Preview, status,
                              NT_SUCCESS(status) ? real : NULL,
                              NT_SUCCESS(status) ? realLen : 0,
                              Input->Value, Input->ValueSize);
    Output->Applied = applied ? 1 : 0;
    Output->RewrittenCount = (UINT32)state->RewrittenCount;
    Output->AttachedCount = state->AttachedCount;
    return status;
}

NTSTATUS
MyArkHwidIoctlSetSpoofConfig(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_HWID_SPOOF_SET_INPUT    inBuf;
    PMYARK_HWID_SPOOF_SET_OUTPUT   outBuf;
    MYARK_HWID_SPOOF_SET_INPUT     snap;
    size_t                         inSize = sizeof(MYARK_HWID_SPOOF_SET_INPUT);
    size_t                         outSize = sizeof(MYARK_HWID_SPOOF_SET_OUTPUT);
    NTSTATUS                       status;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < inSize || OutputBufferLength < outSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request, inSize, (PVOID*)&inBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request, outSize, (PVOID*)&outBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // METHOD_BUFFERED: input and output alias ONE SystemBuffer. Snapshot
    // the input before touching the output (the T-C P0-1 lesson) -- every
    // field read below comes from the snapshot, never from inBuf.
    //
    snap = *inBuf;

    RtlZeroMemory(outBuf, outSize);

    // SAFETY_TOKEN gate: HMAC + freshness window + caller-PID binding.
    status = MyArkSafetyTokenValidate(&snap.Token,
                                      MYARK_HWID_OP_SPOOF_CONFIG,
                                      (UINT32)(UINT_PTR)PsGetCurrentProcessId());
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    if (snap.Class == 0 || snap.Class > MYARK_HWID_SPOOF_CLASS_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }
    //
    // T-D double flag: APPLY is only reachable with UI_CONFIRMED|FORCE.
    // Denied at the IOCTL boundary (win32 ERROR_ACCESS_DENIED) so the
    // negative gate mirrors the SAFETY_TOKEN path; DRY_RUN and RESTORE
    // need the token only.
    //
    if (snap.Action == MYARK_HWID_SPOOF_ACTION_APPLY
        && (snap.Flags & (MYARK_HWID_SPOOF_FLAG_UI_CONFIRMED | MYARK_HWID_SPOOF_FLAG_FORCE))
           != (MYARK_HWID_SPOOF_FLAG_UI_CONFIRMED | MYARK_HWID_SPOOF_FLAG_FORCE)) {
        return STATUS_ACCESS_DENIED;
    }

    status = MyArkHwidSpoofDispatchAction(&snap, outBuf);
    outBuf->Status = (UINT32)status;

    *BytesReturned = outSize;
    return STATUS_SUCCESS;
}

//
// 0x754 QUERY_SPOOF_CAPTURE (R3-1b): read back the passive NSI capture
// ring. Token gated (same operation id as 0x753); read-only.
//
NTSTATUS
MyArkHwidIoctlQuerySpoofCapture(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_HWID_CAPTURE_OUTPUT outBuf;
    size_t                     outSize = sizeof(MYARK_HWID_CAPTURE_OUTPUT);
    size_t                     inSize = sizeof(MYARK_HWID_SPOOF_SET_INPUT);
    PMYARK_HWID_SPOOF_SET_INPUT inBuf;
    MYARK_HWID_SPOOF_SET_INPUT  snap;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < inSize || OutputBufferLength < outSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request, inSize, (PVOID*)&inBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request, outSize, (PVOID*)&outBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // METHOD_BUFFERED: input and output alias ONE SystemBuffer (T-C P0-1).
    // Snapshot the token before zeroing the output.
    //
    snap = *inBuf;
    RtlZeroMemory(outBuf, outSize);

    status = MyArkSafetyTokenValidate(&snap.Token,
                                      MYARK_HWID_OP_SPOOF_CONFIG,
                                      (UINT32)(UINT_PTR)PsGetCurrentProcessId());
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    MyArkHwidSpoofArpFillCaptureOutput(outBuf);
    *BytesReturned = outSize;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_HWID
