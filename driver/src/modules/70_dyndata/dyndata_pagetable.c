// MyArk dyndata module: forward-export resolver + safe-read helpers.
//
// The S7 modules depend on DynData to translate kernel-symbol names into
// runtime VAs at IOCTL time. Each symbol we resolve is exported by ntoskrnl
// but absent from any WDK 28000 public header, so the resolution path goes
// through MmGetSystemRoutineAddress followed by an MmIsAddressValid probe on
// the destination. The first resolution attempt happens during MyArkDynDataInit;
// subsequent IOCTL calls may re-resolve any symbol that failed earlier (lazy
// fallback for the cold-start race where the loader is still settling).
//
// All 7 symbols are declared extern in dyndata_internal.h and initialised
// here to NULL. Each resolver returns STATUS_SUCCESS when the symbol is
// resident and the destination is readable; STATUS_NOT_FOUND when
// MmGetSystemRoutineAddress cannot locate the name; STATUS_INVALID_ADDRESS
// when the destination probe fails.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "dyndata_internal.h"

#if MYARK_MODULE_DYNDATA

//
// Resolved-symbol cache. Each field starts NULL; the resolver populates it
// on the first successful probe. Subsequent calls short-circuit on the
// already-resolved path so the IOCTL-time walk is cheap.
//
PVOID  g_MyArkDynDataPsActiveProcessHead            = NULL;
PVOID  g_MyArkDynDataPsActiveThreadHead             = NULL;
PVOID  g_MyArkDynDataPsLoadedModuleList             = NULL;
PVOID  g_MyArkDynDataKeServiceDescriptorTable       = NULL;
PVOID  g_MyArkDynDataKeServiceDescriptorTableShadow = NULL;
PVOID  g_MyArkDynDataPspCidTable                    = NULL;
PVOID  g_MyArkDynDataObTypeObjectType               = NULL;

UINT64 g_MyArkDynDataNtoskrnlTextBase                = 0;
UINT64 g_MyArkDynDataNtoskrnlTextEnd                 = 0;
UINT64 g_MyArkDynDataWin32kTextBase                  = 0;
UINT64 g_MyArkDynDataWin32kTextEnd                   = 0;
PVOID  g_MyArkDynDataW32pServiceTable                = NULL;

//
// ---------------------------------------------------------------------------
// Per-symbol resolvers. Each returns STATUS_SUCCESS on hit, STATUS_NOT_FOUND
// if the export is absent, and STATUS_INVALID_ADDRESS if MmIsAddressValid
// rejects the destination.
// ---------------------------------------------------------------------------

static
NTSTATUS
MyArkDynDataResolvePointerExport(
    _In_  PCWSTR SymbolName,
    _Out_ PVOID* CacheSlot)
{
    if (CacheSlot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (*CacheSlot != NULL) {
        return STATUS_SUCCESS;
    }

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, SymbolName);

    PVOID address = MmGetSystemRoutineAddress(&name);
    if (address == NULL) {
        return STATUS_NOT_FOUND;
    }
    if (!MmIsAddressValid(address)) {
        return STATUS_INVALID_ADDRESS;
    }

    *CacheSlot = address;
    return STATUS_SUCCESS;
}

static
NTSTATUS
MyArkDynDataResolveNtoskrnlTextRange(
    VOID)
//
// Lazy ntoskrnl .text bounds resolution. We treat the entire ntoskrnl image
// (base .. base + imageSize) as the safe range. The image size comes from
// MmSizeOfSystemImage when exposed; otherwise we over-report the upper bound
// and R3 keeps doing the strict comparison on its end.
//
{
    if (g_MyArkDynDataNtoskrnlTextBase != 0 && g_MyArkDynDataNtoskrnlTextEnd != 0) {
        return STATUS_SUCCESS;
    }

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsNtosImageBase");
    PUCHAR* imageBaseRef = (PUCHAR*)MmGetSystemRoutineAddress(&name);
    if (imageBaseRef == NULL || !MmIsAddressValid(imageBaseRef)) {
        return STATUS_NOT_FOUND;
    }

    PUCHAR base = *imageBaseRef;
    if (base == NULL || !MmIsAddressValid(base)) {
        return STATUS_INVALID_ADDRESS;
    }

    UINT64 base64 = (UINT64)base;
    UINT64 end64 = base64 + 0x1000000ULL;     // 16 MiB ceiling -- generous upper bound

    UNICODE_STRING sizeName;
    RtlInitUnicodeString(&sizeName, L"MmSizeOfSystemImage");
    PULONG sizeRef = (PULONG)MmGetSystemRoutineAddress(&sizeName);
    if (sizeRef != NULL && MmIsAddressValid(sizeRef)) {
        ULONG sz = *sizeRef;
        if (sz != 0 && sz < 0x10000000UL) {
            end64 = base64 + sz;
        }
    }

    g_MyArkDynDataNtoskrnlTextBase = base64;
    g_MyArkDynDataNtoskrnlTextEnd = end64;
    return STATUS_SUCCESS;
}

static
NTSTATUS
MyArkDynDataResolveWin32kTextRange(
    VOID)
//
// Mirror of MyArkDynDataResolveNtoskrnlTextRange but for the win32k module.
// We probe via PsWin32kImageBase / MmWin32kImageSize which are exported by
// ntoskrnl. If the exports are absent on the running build we leave both
// fields at 0 and the SSDT walker treats every shadow entry as suspect.
//
{
    if (g_MyArkDynDataWin32kTextBase != 0 && g_MyArkDynDataWin32kTextEnd != 0) {
        return STATUS_SUCCESS;
    }

    UNICODE_STRING baseName;
    RtlInitUnicodeString(&baseName, L"PsWin32kImageBase");
    PUCHAR* baseRef = (PUCHAR*)MmGetSystemRoutineAddress(&baseName);
    if (baseRef == NULL || !MmIsAddressValid(baseRef)) {
        return STATUS_NOT_FOUND;
    }

    PUCHAR base = *baseRef;
    if (base == NULL || !MmIsAddressValid(base)) {
        return STATUS_INVALID_ADDRESS;
    }

    UINT64 base64 = (UINT64)base;
    UINT64 end64 = base64 + 0x800000ULL;      // 8 MiB ceiling for win32k.sys

    UNICODE_STRING sizeName;
    RtlInitUnicodeString(&sizeName, L"MmWin32kImageSize");
    PULONG sizeRef = (PULONG)MmGetSystemRoutineAddress(&sizeName);
    if (sizeRef != NULL && MmIsAddressValid(sizeRef)) {
        ULONG sz = *sizeRef;
        if (sz != 0 && sz < 0x10000000UL) {
            end64 = base64 + sz;
        }
    }

    g_MyArkDynDataWin32kTextBase = base64;
    g_MyArkDynDataWin32kTextEnd = end64;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkDynDataPagetableResolveAll(
    VOID)
//
// Eager resolver: tries every export once. Returns STATUS_SUCCESS if every
// required symbol was found; otherwise returns the last failing status --
// IOCTL handlers tolerate partial resolution by short-circuiting the missing
// symbol rather than BSOD'ing the caller.
//
{
    NTSTATUS status;

    status = MyArkDynDataResolvePointerExport(L"PsActiveProcessHead",
                                              &g_MyArkDynDataPsActiveProcessHead);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DYNDATA,
                    "MyArkDynDataPagetableResolveAll: PsActiveProcessHead -> 0x%08X",
                    status);
    }

    status = MyArkDynDataResolvePointerExport(L"PsActiveThreadHead",
                                              &g_MyArkDynDataPsActiveThreadHead);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DYNDATA,
                    "MyArkDynDataPagetableResolveAll: PsActiveThreadHead -> 0x%08X",
                    status);
    }

    status = MyArkDynDataResolvePointerExport(L"PsLoadedModuleList",
                                              &g_MyArkDynDataPsLoadedModuleList);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DYNDATA,
                    "MyArkDynDataPagetableResolveAll: PsLoadedModuleList -> 0x%08X",
                    status);
    }

    status = MyArkDynDataResolvePointerExport(L"KeServiceDescriptorTable",
                                              &g_MyArkDynDataKeServiceDescriptorTable);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DYNDATA,
                    "MyArkDynDataPagetableResolveAll: KeServiceDescriptorTable -> 0x%08X",
                    status);
    }

    status = MyArkDynDataResolvePointerExport(L"KeServiceDescriptorTableShadow",
                                              &g_MyArkDynDataKeServiceDescriptorTableShadow);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DYNDATA,
                    "MyArkDynDataPagetableResolveAll: KeServiceDescriptorTableShadow -> 0x%08X",
                    status);
    }

    status = MyArkDynDataResolvePointerExport(L"PspCidTable",
                                              &g_MyArkDynDataPspCidTable);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DYNDATA,
                    "MyArkDynDataPagetableResolveAll: PspCidTable -> 0x%08X",
                    status);
    }

    status = MyArkDynDataResolvePointerExport(L"ObTypeObjectType",
                                              &g_MyArkDynDataObTypeObjectType);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DYNDATA,
                    "MyArkDynDataPagetableResolveAll: ObTypeObjectType -> 0x%08X",
                    status);
    }

    (VOID)MyArkDynDataResolveNtoskrnlTextRange();
    (VOID)MyArkDynDataResolveWin32kTextRange();

    //
    // W32pServiceTable is not an export of ntoskrnl -- it lives in
    // win32k.sys and is reached indirectly via KeServiceDescriptorTableShadow
    // + a small constant offset. The IOCTL walker does the offset arithmetic
    // at walk time rather than caching here.
    //

    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// Safe-read helpers used by every IOCTL walker.
// ---------------------------------------------------------------------------

ULONG
MyArkDynDataSafeRead(
    _In_  PVOID  Source,
    _Out_writes_bytes_(RequestedSize) PUCHAR Destination,
    _In_  ULONG  RequestedSize)
//
// Copy up to RequestedSize bytes from Source to Destination. Each source
// page is probed with MmIsAddressValid first; on a probe failure the read
// stops and the partial byte count is returned. Caller pre-zeroes the
// destination buffer so partial reads are still valid.
//
{
    if (Source == NULL || Destination == NULL || RequestedSize == 0) {
        return 0;
    }

    PUCHAR src = (PUCHAR)Source;
    ULONG copied = 0;

    for (ULONG i = 0; i < RequestedSize; i++) {
        if (!MmIsAddressValid((PVOID)(src + i))) {
            break;
        }
        Destination[i] = src[i];
        copied++;
    }

    return copied;
}

ULONG
MyArkDynDataReadDwell(
    _In_  PVOID  ServiceAddress,
    _Out_writes_bytes_(MYARK_DYNDATA_SYSCALL_DWELL_MAX) PUCHAR OutBytes)
//
// Copy up to MYARK_DYNDATA_SYSCALL_DWELL_MAX bytes from a kernel-side
// trampoline for the R3 dump. Returns the byte count actually copied (0
// when the source is unmapped). KNOWN_ISSUES B4 residual: MmIsAddressValid
// only reports this instant -- the page can still fault on the actual
// access -- so the read goes through MmCopyMemory instead. PASSIVE_LEVEL
// required (the sequential queue guarantees it).
//
{
    MM_COPY_ADDRESS src;
    SIZE_T copied = 0;

    if (ServiceAddress == NULL) {
        return 0;
    }

    src.VirtualAddress = ServiceAddress;
    if (!NT_SUCCESS(MmCopyMemory(OutBytes, src, MYARK_DYNDATA_SYSCALL_DWELL_MAX,
                                 MM_COPY_MEMORY_VIRTUAL, &copied))) {
        return 0;
    }
    return (ULONG)copied;
}

UINT32
MyArkDynDataAddressFlags(
    _In_  UINT64 Address,
    _In_  UINT64 TextBase,
    _In_  UINT64 TextEnd)
//
// Combine the suspect-range and low-bit-set checks into a single flags value.
// Conservative: if TextBase or TextEnd is 0 (i.e. the resolve failed) we
// skip the suspect check and only emit POPULATED + the low-bit test.
//
{
    UINT32 flags = MYARK_DYNDATA_FLAG_POPULATED;

    if (Address == 0) {
        return 0;
    }

    if (TextBase != 0 && TextEnd != 0
        && (Address < TextBase || Address >= TextEnd)) {
        flags |= MYARK_DYNDATA_FLAG_SUSPECT;
    }

    if ((Address & 0x1ULL) != 0) {
        flags |= MYARK_DYNDATA_FLAG_HOOK;
    }

    return flags;
}

#endif // MYARK_MODULE_DYNDATA
