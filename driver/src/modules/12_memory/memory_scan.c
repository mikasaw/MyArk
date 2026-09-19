// MyArk memory module: kernel signature + evidence scan.
//
// Implements SCAN_KERNEL_EXECUTABLE and SCAN_KERNEL_MEMORY_EVIDENCE.
// Both walk a caller-supplied kernel VA range one window at a time and
// copy each hit into a caller-provided output buffer.
//
//   SCAN_KERNEL_EXECUTABLE -- byte signature (up to 16 bytes), exact match.
//                            Useful for finding MZ headers hidden in
//                            kernel .text, specific instruction prefixes,
//                            etc. Output is the matched address + the
//                            surrounding bytes captured for rendering.
//
//   SCAN_KERNEL_MEMORY_EVIDENCE -- PUNICODE_STRING-style signature match.
//                                 Walks one WCHAR at a time comparing the
//                                 first WCHAR against the caller's wide
//                                 signature, then checks the next N chars.
//                                 Case-insensitive (RtlUpcaseUnicodeChar).
//
// Both walks are gated by MmIsAddressValid per page so a missing page
// doesn't fault. The scans read kernel memory in PASSIVE_LEVEL only --
// the IOCTL dispatcher guarantees that posture.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "memory_module.h"

#if MYARK_MODULE_MEMORY


//
// Walk a kernel VA range one 16-byte window at a time and report every
// page-aligned window whose first `SignatureLength` bytes equal the
// caller-supplied signature. Returns when the range is exhausted, the
// caller's output buffer fills, or `MaxResults` hits are recorded.
//
// Cap defaults to MYARK_MEMORY_SCAN_DEFAULT_MAX and is hard-clamped to
// MYARK_MEMORY_SCAN_HARD_CAP. *Truncated tells the caller that more
// hits exist so the UI can say "(more results available, increase cap)".
//
static
NTSTATUS
MyArkMemoryScanByteSignature(
    _In_    UINT64  RangeStart,
    _In_    UINT64  RangeEnd,
    _In_reads_(SignatureLength) const UINT8* Signature,
    _In_    ULONG   SignatureLength,
    _In_    ULONG   MaxResults,
    _Out_writes_to_(BufferSize, *BytesUsed) PUCHAR Buffer,
    _In_    ULONG   BufferSize,
    _Out_   PULONG  BytesUsed,
    _Out_   PULONG  HitCount,
    _Out_   PULONG  Truncated)
{
    ULONG  cap;
    ULONG  headerSize = FIELD_OFFSET(MYARK_MEMORY_SCAN_KERNEL_OUTPUT, Entries[0]);
    ULONG  written    = 0;
    UINT64 cursor;

    *HitCount = 0;
    *Truncated = 0;
    *BytesUsed = headerSize;

    if (SignatureLength == 0 || SignatureLength > MYARK_MEMORY_SCAN_SIGNATURE_MAX) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RangeEnd <= RangeStart) {
        return STATUS_INVALID_PARAMETER;
    }
    if (BufferSize < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    cap = MaxResults;
    if (cap == 0) {
        cap = MYARK_MEMORY_SCAN_DEFAULT_MAX;
    }
    if (cap > MYARK_MEMORY_SCAN_HARD_CAP) {
        cap = MYARK_MEMORY_SCAN_HARD_CAP;
    }

    PMYARK_MEMORY_SCAN_KERNEL_OUTPUT out = (PMYARK_MEMORY_SCAN_KERNEL_OUTPUT)Buffer;
    RtlZeroMemory(Buffer, headerSize);

    for (cursor = RangeStart; cursor + SignatureLength <= RangeEnd; cursor += SignatureLength) {
        //
        // MmIsAddressValid probes the page; without it the RtlCompareMemory
        // read could fault on a missing kernel page.
        //
        if (!MmIsAddressValid((PVOID)cursor)) {
            continue;
        }

        BOOLEAN match = TRUE;
        __try {
            if (RtlCompareMemory((PVOID)cursor, Signature, SignatureLength)
                != SignatureLength) {
                match = FALSE;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            match = FALSE;
        }
        if (!match) {
            continue;
        }

        if (written >= cap ||
            (headerSize + (written + 1) * sizeof(MYARK_MEMORY_SCAN_KERNEL_ENTRY)) > BufferSize) {
            *Truncated = 1;
            break;
        }

        PMYARK_MEMORY_SCAN_KERNEL_ENTRY row = &out->Entries[written];
        row->Address = cursor;
        RtlZeroMemory(row->SignatureBytes, MYARK_MEMORY_SCAN_SIGNATURE_MAX);
        __try {
            RtlCopyMemory(row->SignatureBytes, (PVOID)cursor, SignatureLength);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Best-effort: address matched but bytes vanished mid-copy.
            // Keep the row -- the caller still gets the hit address.
        }
        written++;
    }

    out->Size  = (UINT32)(headerSize + written * sizeof(MYARK_MEMORY_SCAN_KERNEL_ENTRY));
    out->Count = written;
    *BytesUsed = out->Size;
    *HitCount  = written;

    return STATUS_SUCCESS;
}


//
// Case-insensitive comparison of two wide strings up to Length WCHARs.
// Returns the number of matched chars (Length) on full match, the index
// of the first mismatch (0..Length) on mismatch. Mimics the semantics
// PUNICODE_STRING-aware consumers expect: case-insensitive prefix.
//
static
ULONG
MyArkMemoryWidePrefixMatch(
    _In_reads_(Length) PCWSTR Haystack,
    _In_reads_(Length) PCWSTR Needle,
    _In_ ULONG Length)
{
    for (ULONG i = 0; i < Length; i++) {
        WCHAR a = RtlUpcaseUnicodeChar(Haystack[i]);
        WCHAR b = RtlUpcaseUnicodeChar(Needle[i]);
        if (a != b) {
            return i;
        }
    }
    return Length;
}


//
// Walk a kernel VA range 16 WCHARs at a time and report every window
// whose first SignatureLength chars (case-insensitive) match the
// caller's wide signature. Output rows carry the matched address and
// MatchedChars count.
//
static
NTSTATUS
MyArkMemoryScanEvidence(
    _In_    PCWSTR  Signature,
    _In_    ULONG   SignatureLength,
    _In_    UINT64  RangeStart,
    _In_    UINT64  RangeEnd,
    _In_    ULONG   MaxResults,
    _Out_writes_to_(BufferSize, *BytesUsed) PUCHAR Buffer,
    _In_    ULONG   BufferSize,
    _Out_   PULONG  BytesUsed,
    _Out_   PULONG  HitCount,
    _Out_   PULONG  Truncated)
{
    ULONG  cap;
    ULONG  headerSize = FIELD_OFFSET(MYARK_MEMORY_SCAN_EVIDENCE_OUTPUT, Entries[0]);
    ULONG  written    = 0;
    UINT64 cursor;
    WCHAR  window[16];

    *HitCount = 0;
    *Truncated = 0;
    *BytesUsed = headerSize;

    if (SignatureLength == 0 || SignatureLength > MYARK_MEMORY_SCAN_UNICODE_MAX) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RangeEnd <= RangeStart) {
        return STATUS_INVALID_PARAMETER;
    }
    if (BufferSize < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    cap = MaxResults;
    if (cap == 0) {
        cap = MYARK_MEMORY_SCAN_DEFAULT_MAX;
    }
    if (cap > MYARK_MEMORY_SCAN_HARD_CAP) {
        cap = MYARK_MEMORY_SCAN_HARD_CAP;
    }

    PMYARK_MEMORY_SCAN_EVIDENCE_OUTPUT out = (PMYARK_MEMORY_SCAN_EVIDENCE_OUTPUT)Buffer;
    RtlZeroMemory(Buffer, headerSize);

    for (cursor = RangeStart; cursor + (UINT64)SignatureLength * sizeof(WCHAR) <= RangeEnd;
         cursor += sizeof(WCHAR)) {
        if (!MmIsAddressValid((PVOID)cursor)) {
            continue;
        }

        ULONG matched = 0;
        __try {
            RtlCopyMemory(window, (PVOID)cursor, sizeof(WCHAR) * SignatureLength);
            matched = MyArkMemoryWidePrefixMatch(window, Signature, SignatureLength);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            matched = 0;
        }
        if (matched != SignatureLength) {
            continue;
        }

        if (written >= cap ||
            (headerSize + (written + 1) * sizeof(MYARK_MEMORY_SCAN_EVIDENCE_ENTRY)) > BufferSize) {
            *Truncated = 1;
            break;
        }

        PMYARK_MEMORY_SCAN_EVIDENCE_ENTRY row = &out->Entries[written];
        row->Address      = cursor;
        row->MatchedChars = matched;
        row->Reserved     = 0;
        written++;
    }

    out->Size  = (UINT32)(headerSize + written * sizeof(MYARK_MEMORY_SCAN_EVIDENCE_ENTRY));
    out->Count = written;
    *BytesUsed = out->Size;
    *HitCount  = written;

    return STATUS_SUCCESS;
}


//
// IOCTL_MYARK_MEMORY_SCAN_KERNEL_EXECUTABLE handler.
//
NTSTATUS
MyArkMemoryIoctlScanKernelExecutable(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_MEMORY_SCAN_KERNEL_INPUT  inBuf  = NULL;
    PUCHAR                            outBuf = NULL;
    size_t                            inSize  = 0;
    NTSTATUS                          status;
    ULONG                             bytesUsed = 0;
    ULONG                             hits = 0;
    ULONG                             truncated = 0;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_MEMORY_SCAN_KERNEL_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < FIELD_OFFSET(MYARK_MEMORY_SCAN_KERNEL_OUTPUT, Entries[0])) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_MEMORY_SCAN_KERNEL_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // METHOD_BUFFERED shares one SystemBuffer and the scan walker zeroes the
    // output header (== the first bytes of the input struct, where
    // Signature[] lives) before matching. Copy the whole input struct into a
    // local so the walker still sees the caller's signature and range.
    //
    MYARK_MEMORY_SCAN_KERNEL_INPUT scanInput = *inBuf;
    inBuf = NULL;

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         OutputBufferLength,
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkMemoryScanByteSignature(scanInput.RangeStart,
                                          scanInput.RangeEnd,
                                          scanInput.Signature,
                                          scanInput.SignatureLength,
                                          scanInput.MaxResults,
                                          outBuf,
                                          (ULONG)OutputBufferLength,
                                          &bytesUsed,
                                          &hits,
                                          &truncated);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = bytesUsed;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MEMORY,
                "ScanKernelExecutable range=0x%llX..0x%llX sig_len=%lu -> %lu hits (truncated=%lu)",
                (unsigned long long)scanInput.RangeStart,
                (unsigned long long)scanInput.RangeEnd,
                (unsigned long)scanInput.SignatureLength,
                hits,
                truncated);

    return STATUS_SUCCESS;
}


//
// IOCTL_MYARK_MEMORY_SCAN_KERNEL_MEMORY_EVIDENCE handler.
//
NTSTATUS
MyArkMemoryIoctlScanKernelMemoryEvidence(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_MEMORY_SCAN_EVIDENCE_INPUT  inBuf  = NULL;
    PUCHAR                             outBuf = NULL;
    size_t                             inSize  = 0;
    NTSTATUS                           status;
    ULONG                              sigLen = 0;
    ULONG                              bytesUsed = 0;
    ULONG                              hits = 0;
    ULONG                              truncated = 0;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_MEMORY_SCAN_EVIDENCE_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < FIELD_OFFSET(MYARK_MEMORY_SCAN_EVIDENCE_OUTPUT, Entries[0])) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_MEMORY_SCAN_EVIDENCE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // METHOD_BUFFERED shares one SystemBuffer and the scan walker zeroes the
    // output header (== the input struct's leading fields) before matching.
    // Copy the input into a local so the signature and range survive.
    //
    MYARK_MEMORY_SCAN_EVIDENCE_INPUT scanInput = *inBuf;
    inBuf = NULL;

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         OutputBufferLength,
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Compute the unicode signature length (chars before the first NUL).
    // Cap at MYARK_MEMORY_SCAN_UNICODE_MAX - 1 so we never overrun the
    // fixed-width field.
    //
    while (sigLen < MYARK_MEMORY_SCAN_UNICODE_MAX - 1 &&
           scanInput.Signature[sigLen] != L'\0') {
        sigLen++;
    }

    status = MyArkMemoryScanEvidence(scanInput.Signature,
                                     sigLen,
                                     scanInput.RangeStart,
                                     scanInput.RangeEnd,
                                     scanInput.MaxResults,
                                     outBuf,
                                     (ULONG)OutputBufferLength,
                                     &bytesUsed,
                                     &hits,
                                     &truncated);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = bytesUsed;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MEMORY,
                "ScanKernelMemoryEvidence range=0x%llX..0x%llX sig_len=%lu -> %lu hits (truncated=%lu)",
                (unsigned long long)scanInput.RangeStart,
                (unsigned long long)scanInput.RangeEnd,
                (unsigned long)sigLen,
                hits,
                truncated);

    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_MEMORY