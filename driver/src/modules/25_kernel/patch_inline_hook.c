// MyArk kernel module: PATCH_INLINE_HOOK + QUERY_PATCH_TARGET (R2-1).
//
// PATCH_INLINE_HOOK restores original bytes over a hook stub. The write
// goes through an MDL alias so read-only code pages stay reachable:
//   1. MmProbeAndLockPages(IoWriteAccess) for writable targets,
//   2. fallback MmBuildMdlForNonPagedPool + map for read-only code pages
//      (ntoskrnl / driver .text are nonpaged, so the PFNs are resident).
// The target must live inside a loaded kernel image (RtlPcToFileHeader)
// and the patched range must stay within one page. Token (op
// MYARK_KERNEL_OP_PATCH_HOOK) + FORCE magic are both mandatory.
//
// QUERY_PATCH_TARGET reports the never-called probe function below -- the
// regression drives the full expected-check -> write -> restore cycle
// against it instead of live ntoskrnl code (zero guest-stability risk).
//
// Known-inherent race (accepted, documented): the dwell compare and the
// MDL write are not atomic -- bytes that change between the two steps are
// detected only for the scan-driven flow (compare happens right before the
// write). The MmBuildMdlForNonPagedPool fallback is only reached for
// targets whose full dwell read via MmCopyMemory just succeeded, which
// rules out paged-out pages; pageable-but-resident image pages remain a
// theoretical hazard accepted by the FORCE gate.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkKernelIoctl.h"
#include "../../../shared/driver/MyArkSafetyToken.h"
#include "../../dispatch/safety_token.h"
#include "kernel_descriptor.h"
#include "kernel_internal.h"

#if MYARK_MODULE_KERNEL

//
// Never-called probe function (R2-1 acceptance target). Nothing in the
// product calls it; it exists only so QUERY_PATCH_TARGET can hand the
// regression a stable address inside the MyArkCore image. noinline plus
// address-taken keeps the compiler from discarding or merging it.
//
__declspec(noinline)
UINT32
MyArkKernelPatchProbeTarget(
    VOID)
{
    return 0x4D41524BU;  // 'MARK'
}

//
// Read ByteCount dwell bytes from a kernel VA. MmCopyMemory tolerates
// every corner the target range could present (resident image pages in
// practice); PASSIVE_LEVEL guaranteed by the sequential queue.
//
static
NTSTATUS
MyArkKernelReadDwell(
    _In_  UINT64  Address,
    _Out_writes_bytes_(ByteCount) PUCHAR OutBytes,
    _In_  ULONG   ByteCount)
{
    MM_COPY_ADDRESS src;
    SIZE_T copied = 0;

    src.VirtualAddress = (PVOID)(UINT_PTR)Address;
    NTSTATUS status = MmCopyMemory(OutBytes, src, ByteCount,
                                   MM_COPY_MEMORY_VIRTUAL, &copied);
    if (!NT_SUCCESS(status) || copied != ByteCount) {
        return STATUS_INVALID_ADDRESS;
    }
    return STATUS_SUCCESS;
}

//
// Write ByteCount bytes to a kernel code page via an MDL alias. The
// probe path handles writable data pages; the nonpaged rebuild path
// handles read-only .text pages whose PTEs reject IoWriteAccess.
//
static
NTSTATUS
MyArkKernelWriteCodeBytes(
    _In_ PVOID       Va,
    _In_reads_bytes_(ByteCount) const UINT8* Bytes,
    _In_ ULONG       ByteCount)
{
    PMDL mdl = IoAllocateMdl(Va, ByteCount, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN locked = FALSE;
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
        locked = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        //
        // Read-only code page: lock raises STATUS_ACCESS_VIOLATION. The
        // target is in a driver image (.text is nonpaged), so rebuild the
        // PFN array directly and let the alias mapping provide write access.
        //
        status = STATUS_SUCCESS;
        __try {
            MmBuildMdlForNonPagedPool(mdl);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_INVALID_ADDRESS;
        }
    }

    if (NT_SUCCESS(status)) {
        PVOID mapped = MmMapLockedPagesSpecifyCache(mdl,
                                                    KernelMode,
                                                    MmCached,
                                                    NULL,
                                                    FALSE,
                                                    NormalPagePriority);
        if (mapped == NULL) {
            status = STATUS_INVALID_ADDRESS;
        } else {
            RtlCopyMemory(mapped, Bytes, ByteCount);
            MmUnmapLockedPages(mapped, mdl);
        }
    }

    //
    // Only the probe path takes a PFN reference that must be released;
    // IoFreeMdl alone does not unlock -- skipping this would pin the page
    // for the life of the boot (acceptance MF-1).
    //
    if (locked) {
        MmUnlockPages(mdl);
    }
    IoFreeMdl(mdl);
    return status;
}

NTSTATUS
MyArkKernelIoctlPatchHook(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PMYARK_KERNEL_PATCH_HOOK_INPUT inBuf = NULL;
    size_t inSize = 0;
    NTSTATUS status;

    if (InputBufferLength < sizeof(MYARK_KERNEL_PATCH_HOOK_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_KERNEL_PATCH_HOOK_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Snapshot every input field before touching the output buffer
    // (METHOD_BUFFERED: the output zero would clobber the shared buffer).
    //
    UINT64 hookAddress = inBuf->HookAddress;
    ULONG byteCount = inBuf->ByteCount;
    ULONG force = inBuf->Force;
    UINT8 expected[MYARK_KERNEL_PATCH_BYTE_MAX];
    UINT8 restore[MYARK_KERNEL_PATCH_BYTE_MAX];
    RtlCopyMemory(expected, inBuf->ExpectedBytes, sizeof(expected));
    RtlCopyMemory(restore, inBuf->RestoreBytes, sizeof(restore));

    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_KERNEL_OP_PATCH_HOOK,
                                      (UINT32)(UINT_PTR)PsGetCurrentProcessId());
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    if (force != MYARK_KERNEL_PATCH_FORCE_MAGIC) {
        return STATUS_ACCESS_DENIED;
    }

    if (byteCount == 0 || byteCount > MYARK_KERNEL_PATCH_BYTE_MAX) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Single-page range: the MDL alias maps whole pages, so a range that
    // crosses a page boundary would silently patch the wrong tail bytes.
    //
    UINT64 pageFirst = hookAddress & ~0xFFFULL;
    UINT64 pageLast = (hookAddress + byteCount - 1) & ~0xFFFULL;
    if (pageFirst != pageLast) {
        return STATUS_INVALID_PARAMETER;
    }

    if (hookAddress < (UINT64)(UINT_PTR)MmSystemRangeStart) {
        // Parameter-domain rejection (acceptance MF-2): a user-mode target
        // is a malformed request, not an unresolvable kernel address.
        return STATUS_INVALID_PARAMETER;
    }

    PVOID hdrBase = NULL;
    PVOID (NTAPI *pcToFile)(PVOID, PVOID*) = NULL;
    pcToFile = (PVOID (NTAPI *)(PVOID, PVOID *))MmGetSystemRoutineAddress(
        &(UNICODE_STRING)RTL_CONSTANT_STRING(L"RtlPcToFileHeader"));
    if (pcToFile == NULL
        || pcToFile((PVOID)(UINT_PTR)hookAddress, &hdrBase) == NULL
        || hdrBase == NULL) {
        //
        // Not inside any loaded kernel image -- PATCH is scoped to
        // hook-stub restoration, never to raw kernel pool.
        //
        return STATUS_INVALID_ADDRESS;
    }
    UINT64 moduleBase = (UINT64)(UINT_PTR)hdrBase;

    UINT8 prior[MYARK_KERNEL_PATCH_BYTE_MAX] = { 0 };
    status = MyArkKernelReadDwell(hookAddress, prior, byteCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (RtlCompareMemory(prior, expected, byteCount) != byteCount) {
        //
        // Dwell mismatch: the stub moved since the scan. Refuse rather
        // than corrupt whatever now sits at the address.
        //
        return STATUS_INVALID_PARAMETER;
    }

    status = MyArkKernelWriteCodeBytes((PVOID)(UINT_PTR)hookAddress,
                                       restore, byteCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_KERNEL_PATCH_HOOK_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_KERNEL_PATCH_HOOK_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    outBuf->Status = 0;
    outBuf->BytesPatched = byteCount;
    RtlCopyMemory(outBuf->PriorBytes, prior, sizeof(prior));
    outBuf->ModuleBase = moduleBase;
    *BytesReturned = sizeof(MYARK_KERNEL_PATCH_HOOK_OUTPUT);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkKernelIoctlQueryPatchTarget(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < sizeof(MYARK_KERNEL_PATCH_TARGET_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PMYARK_KERNEL_PATCH_TARGET_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    NTSTATUS status = MyArkIoctlFetchOutputBuffer(Request,
                                                  sizeof(MYARK_KERNEL_PATCH_TARGET_OUTPUT),
                                                  (PVOID*)&outBuf,
                                                  &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UINT64 targetVa = (UINT64)(UINT_PTR)&MyArkKernelPatchProbeTarget;
    const ULONG byteCount = 6;  // mov eax, imm32 (5) + ret (1)

    PVOID hdrBase = NULL;
    UINT64 moduleBase = 0;
    PVOID (NTAPI *pcToFile)(PVOID, PVOID*) = NULL;
    pcToFile = (PVOID (NTAPI *)(PVOID, PVOID *))MmGetSystemRoutineAddress(
        &(UNICODE_STRING)RTL_CONSTANT_STRING(L"RtlPcToFileHeader"));
    if (pcToFile != NULL
        && pcToFile((PVOID)(UINT_PTR)targetVa, &hdrBase) != NULL
        && hdrBase != NULL) {
        moduleBase = (UINT64)(UINT_PTR)hdrBase;
    }

    outBuf->Size = (UINT32)sizeof(MYARK_KERNEL_PATCH_TARGET_OUTPUT);
    outBuf->Status = 0;
    outBuf->TargetVa = targetVa;
    outBuf->ModuleBase = moduleBase;
    outBuf->ByteCount = byteCount;
    outBuf->Reserved1 = 0;

    UINT8 dwell[MYARK_KERNEL_PATCH_BYTE_MAX] = { 0 };
    if (NT_SUCCESS(MyArkKernelReadDwell(targetVa, dwell, byteCount))) {
        RtlCopyMemory(outBuf->CurrentBytes, dwell, byteCount);
    }

    *BytesReturned = outBuf->Size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_KERNEL
