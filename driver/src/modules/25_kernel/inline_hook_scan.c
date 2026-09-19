// MyArk kernel module: inline-hook scanner (R1-4).
//
// Byte-pattern scan of the ntoskrnl image for inline-hook jump stubs whose
// target lands OUTSIDE the image. Chunked MmCopyMemory keeps the read safe
// on no-SMEP CPUs and across paging; a 16-byte overlap between chunks keeps
// boundary-spanning stubs visible. Read-only; PASSIVE_LEVEL (sequential
// queue).

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkKernelIoctl.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"
#include "kernel_descriptor.h"
#include "kernel_internal.h"

#if MYARK_MODULE_KERNEL

extern UINT64 g_MyArkKernelNtoskrnlTextBase;
extern UINT64 g_MyArkKernelNtoskrnlTextEnd;

#define MYARK_HOOK_CHUNK_BYTES             0x10000UL   // 64 KiB
#define MYARK_HOOK_OVERLAP_BYTES           16

NTSTATUS
MyArkKernelIoctlScanInlineHooks(
    _In_ WDFDEVICE   Device,
    _In_ WDFREQUEST  Request,
    _In_ size_t      InputBufferLength,
    _In_ size_t      OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_KERNEL_SCAN_HOOKS_INPUT  inBuf = NULL;
    PMYARK_KERNEL_SCAN_HOOKS_OUTPUT outBuf = NULL;
    PUCHAR                          chunkBuf = NULL;
    size_t                          inSize = 0;
    size_t                          outSize = 0;
    NTSTATUS                        status;
    UINT64                          scanBase;
    UINT64                          scanEnd;
    UINT64                          offset;
    ULONG                           maxEntries;
    ULONG                           emitted = 0;
    ULONG                           totalHooks = 0;
    ULONG                           bytesScanned = 0;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < sizeof(MYARK_KERNEL_SCAN_HOOKS_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_KERNEL_SCAN_HOOKS_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    maxEntries = inBuf->MaxEntries;
    if (maxEntries == 0 || maxEntries > MYARK_KERNEL_HOOK_HARD_CAP) {
        maxEntries = MYARK_KERNEL_HOOK_HARD_CAP;
    }

    //
    // Lazy-resolve the ntoskrnl bounds (PsNtosImageBase + image size).
    // Unresolvable bounds mean "R3-only" -- report invalid state instead
    // of scanning blindly.
    //
    MyArkKernelEnsureNtoskrnlBounds();
    if (g_MyArkKernelNtoskrnlTextBase == 0
        || g_MyArkKernelNtoskrnlTextEnd <= g_MyArkKernelNtoskrnlTextBase) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_KERNEL_SCAN_HOOKS_OUTPUT, Entries),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Cap emitted entries by the available output space -- a large
    // MaxEntries against a small buffer would otherwise overflow the
    // METHOD_BUFFERED system buffer.
    //
    {
        ULONG spaceForEntries = (ULONG)((outSize
            - FIELD_OFFSET(MYARK_KERNEL_SCAN_HOOKS_OUTPUT, Entries))
            / sizeof(MYARK_KERNEL_HOOK_ENTRY));
        if (spaceForEntries < maxEntries) {
            maxEntries = spaceForEntries;
        }
    }

    chunkBuf = (PUCHAR)MyArkAllocatePool(NonPagedPoolNx,
                                         MYARK_HOOK_CHUNK_BYTES,
                                         'KhsK');
    if (chunkBuf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    scanBase = g_MyArkKernelNtoskrnlTextBase;
    scanEnd = g_MyArkKernelNtoskrnlTextEnd;
    outBuf->NtoskrnlTextBase = scanBase;
    outBuf->NtoskrnlTextEnd = scanEnd;

    //
    // RtlPcToFileHeader maps an address back to its image base: candidates
    // whose target still resolves inside ntoskrnl are normal compiler
    // output and are skipped; only cross-module / unresolved targets are
    // emitted as hook candidates (precision filter).
    //
    PVOID (NTAPI *pcToFile)(PVOID, PVOID *) = NULL;
    {
        UNICODE_STRING pcName;
        RtlInitUnicodeString(&pcName, L"RtlPcToFileHeader");
        pcToFile = (PVOID (NTAPI *)(PVOID, PVOID *))MmGetSystemRoutineAddress(&pcName);
    }

    offset = scanBase;
    while (offset < scanEnd) {
        MM_COPY_ADDRESS src;
        SIZE_T copied = 0;
        ULONG chunkLen = MYARK_HOOK_CHUNK_BYTES;
        ULONG scanLen;
        ULONG i;

        if (offset + chunkLen > scanEnd) {
            chunkLen = (ULONG)(scanEnd - offset);
        }

        src.VirtualAddress = (PVOID)(UINT_PTR)offset;
        status = MmCopyMemory(chunkBuf, src, chunkLen,
                              MM_COPY_MEMORY_VIRTUAL, &copied);
        if (!NT_SUCCESS(status) || copied == 0) {
            //
            // Unreadable page (paged out / guarded): skip one page and
            // continue -- terminating the whole scan would leave most of
            // the image unchecked (R1-4 review fix).
            //
            offset += 0x1000;
            continue;
        }
        scanLen = (ULONG)copied;

        //
        // Classify jump stubs. The overlap keeps boundary-spanning stubs
        // visible; emitted entries inside one chunk are unique.
        //
        for (i = 0; i + 2 < scanLen; i++) {
            UINT64 va = offset + i;
            UCHAR b0 = chunkBuf[i];
            UCHAR b1 = chunkBuf[i + 1];

            if (b0 == 0xE9) {
                LONG rel;
                UINT64 target;
                if (i + 5 > scanLen) {
                    break;
                }
                rel = (LONG)(chunkBuf[i + 1] | (chunkBuf[i + 2] << 8) |
                             (chunkBuf[i + 3] << 16) | (chunkBuf[i + 4] << 24));
                target = va + 5 + (UINT64)(LONG_PTR)rel;
                if (target < scanBase || target >= scanEnd) {
                    PVOID targetBase = NULL;
                    BOOLEAN crossModule = (pcToFile == NULL)
                        || (pcToFile((PVOID)(UINT_PTR)target, &targetBase) != NULL
                            && targetBase != NULL
                            && (UINT64)(UINT_PTR)targetBase != scanBase);
                    if (crossModule && emitted < maxEntries) {
                        outBuf->Entries[emitted].HookAddress = va;
                        outBuf->Entries[emitted].JumpTarget = target;
                        outBuf->Entries[emitted].Class = MYARK_KERNEL_HOOK_CLASS_E9;
                        outBuf->Entries[emitted].Reserved0 = 0;
                        emitted++;
                    }
                    if (crossModule) {
                        totalHooks++;
                    }
                    i += 4;
                }
            } else if (b0 == 0xEB) {
                signed char rel8;
                UINT64 target;

                rel8 = (signed char)chunkBuf[i + 1];
                target = va + 2 + (UINT64)(LONG_PTR)rel8;
                if (target < scanBase || target >= scanEnd) {
                    if (emitted < maxEntries) {
                        outBuf->Entries[emitted].HookAddress = va;
                        outBuf->Entries[emitted].JumpTarget = target;
                        outBuf->Entries[emitted].Class = MYARK_KERNEL_HOOK_CLASS_EB;
                        outBuf->Entries[emitted].Reserved0 = 0;
                        emitted++;
                    }
                    totalHooks++;
                    i += 1;
                }
            } else if (b0 == 0xFF && b1 == 0x25) {
                LONG rel;
                UINT64 slotVa;
                UINT64 target = 0;
                MM_COPY_ADDRESS slotSrc;
                SIZE_T slotCopied = 0;

                if (i + 6 > scanLen) {
                    break;
                }
                rel = (LONG)(chunkBuf[i + 2] | (chunkBuf[i + 3] << 8) |
                             (chunkBuf[i + 4] << 16) | (chunkBuf[i + 5] << 24));
                slotVa = va + 6 + (UINT64)(LONG_PTR)rel;
                slotSrc.VirtualAddress = (PVOID)(UINT_PTR)slotVa;
                if (NT_SUCCESS(MmCopyMemory(&target, slotSrc, sizeof(target),
                                            MM_COPY_MEMORY_VIRTUAL, &slotCopied))
                    && slotCopied == sizeof(target)) {
                    if (target < scanBase || target >= scanEnd) {
                        PVOID targetBase = NULL;
                        BOOLEAN crossModule = (pcToFile == NULL)
                            || (pcToFile((PVOID)(UINT_PTR)target, &targetBase) != NULL
                                && targetBase != NULL
                                && (UINT64)(UINT_PTR)targetBase != scanBase);
                        if (crossModule && emitted < maxEntries) {
                            outBuf->Entries[emitted].HookAddress = va;
                            outBuf->Entries[emitted].JumpTarget = target;
                            outBuf->Entries[emitted].Class = MYARK_KERNEL_HOOK_CLASS_FF25;
                            outBuf->Entries[emitted].Reserved0 = 0;
                            emitted++;
                        }
                        if (crossModule) {
                            totalHooks++;
                        }
                    }
                }
                i += 5;
            }
        }

        bytesScanned += scanLen;
        offset += chunkLen;
        if (offset >= scanEnd) {
            break;
        }

        //
        // Rewind by the overlap so stubs spanning the chunk boundary are
        // re-scanned by the next chunk.
        //
        offset -= MYARK_HOOK_OVERLAP_BYTES;
    }

    ExFreePoolWithTag(chunkBuf, 'KhsK');

    outBuf->Size = (UINT32)(FIELD_OFFSET(MYARK_KERNEL_SCAN_HOOKS_OUTPUT, Entries)
                            + emitted * sizeof(MYARK_KERNEL_HOOK_ENTRY));
    outBuf->Count = emitted;
    outBuf->TotalHooks = totalHooks;
    outBuf->BytesScannedKb = bytesScanned / 1024;
    outBuf->EntryStructSize = (UINT32)sizeof(MYARK_KERNEL_HOOK_ENTRY);
    *BytesReturned = FIELD_OFFSET(MYARK_KERNEL_SCAN_HOOKS_OUTPUT, Entries)
                     + emitted * sizeof(MYARK_KERNEL_HOOK_ENTRY);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_KERNEL
