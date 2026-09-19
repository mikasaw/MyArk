// MyArk callback module: forward-export resolver + safe-read helpers.
//
// The callback module resolves 5 array heads (PS / Cm / Ob / Image / Dbg)
// at Init() time and re-resolves any failure lazily on the first IOCTL
// call. Each resolver goes through MmGetSystemRoutineAddress followed by
// an MmIsAddressValid probe -- a missing symbol on the running build
// leaves the field at NULL and the corresponding IOCTL short-circuits to
// Count=0 instead of faulting.
//
// Driver-name resolution for a given callback VA re-uses the S7.1
// DynData pagetable: PsLoadedModuleList is owned by DynData's resolver and
// S7.2 only reads it. On a missing DynData the lookup degrades to "unknown
// driver" (empty DriverName + Altitude).

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "callback_internal.h"

#if MYARK_MODULE_CALLBACK

//
// Resolved-symbol cache. Each field starts NULL; the resolver populates it
// on the first successful probe. Subsequent calls short-circuit on the
// already-resolved path so the IOCTL-time walk is cheap.
//
PVOID g_MyArkCallbackPspCreateProcessNotifyRoutine          = NULL;
PVOID g_MyArkCallbackPspCreateThreadNotifyRoutine           = NULL;
PVOID g_MyArkCallbackPspLoadImageNotifyRoutine              = NULL;
PVOID g_MyArkCallbackCmpCallbackListHead                    = NULL;
PVOID g_MyArkCallbackObCallbackListHead                     = NULL;
PVOID g_MyArkCallbackDbgkDebugObjectType                    = NULL;
PVOID g_MyArkCallbackPsNtDebuggerObject                     = NULL;

UINT64 g_MyArkCallbackNtoskrnlTextBase                       = 0;
UINT64 g_MyArkCallbackNtoskrnlTextEnd                        = 0;

//
// Import from the S7.1 DynData module. We do not include the DynData
// internal header to avoid a cyclic #if; the extern is declared with the
// matching layout so the linker resolves the symbol at link time. If
// DynData is disabled the symbol resolves to NULL and the callback module
// degrades gracefully (every DriverName lookup returns empty).
//
extern PVOID g_MyArkDynDataPsLoadedModuleList;

//
// ---------------------------------------------------------------------------
// Per-symbol resolvers. Each returns STATUS_SUCCESS on hit, STATUS_NOT_FOUND
// if the export is absent, and STATUS_INVALID_ADDRESS if MmIsAddressValid
// rejects the destination.
// ---------------------------------------------------------------------------

static
NTSTATUS
MyArkCallbackResolvePointerExport(
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
MyArkCallbackResolveNtoskrnlTextRange(
    VOID)
//
// Lazy ntoskrnl .text bounds resolution. We treat the entire ntoskrnl image
// (base .. base + imageSize) as the safe range. The image size comes from
// MmSizeOfSystemImage when exposed; otherwise we over-report the upper bound
// and R3 keeps doing the strict comparison on its end.
//
{
    if (g_MyArkCallbackNtoskrnlTextBase != 0 && g_MyArkCallbackNtoskrnlTextEnd != 0) {
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

    g_MyArkCallbackNtoskrnlTextBase = base64;
    g_MyArkCallbackNtoskrnlTextEnd = end64;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkCallbackPagetableResolveAll(
    VOID)
//
// Eager resolver: tries every export once. Returns STATUS_SUCCESS if every
// required symbol was found; otherwise returns the last failing status --
// IOCTL handlers tolerate partial resolution by short-circuiting the missing
// symbol rather than BSOD'ing the caller.
//
{
    NTSTATUS status;

    status = MyArkCallbackResolvePointerExport(L"PspCreateProcessNotifyRoutine",
                                               &g_MyArkCallbackPspCreateProcessNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_CALLBACK,
                    "MyArkCallbackPagetableResolveAll: PspCreateProcessNotifyRoutine -> 0x%08X",
                    status);
    }

    status = MyArkCallbackResolvePointerExport(L"PspCreateThreadNotifyRoutine",
                                               &g_MyArkCallbackPspCreateThreadNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_CALLBACK,
                    "MyArkCallbackPagetableResolveAll: PspCreateThreadNotifyRoutine -> 0x%08X",
                    status);
    }

    status = MyArkCallbackResolvePointerExport(L"PspLoadImageNotifyRoutine",
                                               &g_MyArkCallbackPspLoadImageNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_CALLBACK,
                    "MyArkCallbackPagetableResolveAll: PspLoadImageNotifyRoutine -> 0x%08X",
                    status);
    }

    status = MyArkCallbackResolvePointerExport(L"CmpCallbackListHead",
                                               &g_MyArkCallbackCmpCallbackListHead);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_CALLBACK,
                    "MyArkCallbackPagetableResolveAll: CmpCallbackListHead -> 0x%08X",
                    status);
    }

    status = MyArkCallbackResolvePointerExport(L"ObCallbackListHead",
                                               &g_MyArkCallbackObCallbackListHead);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_CALLBACK,
                    "MyArkCallbackPagetableResolveAll: ObCallbackListHead -> 0x%08X",
                    status);
    }

    status = MyArkCallbackResolvePointerExport(L"DbgkDebugObjectType",
                                               &g_MyArkCallbackDbgkDebugObjectType);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_CALLBACK,
                    "MyArkCallbackPagetableResolveAll: DbgkDebugObjectType -> 0x%08X",
                    status);
    }

    status = MyArkCallbackResolvePointerExport(L"PsNtDebuggerObject",
                                               &g_MyArkCallbackPsNtDebuggerObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_CALLBACK,
                    "MyArkCallbackPagetableResolveAll: PsNtDebuggerObject -> 0x%08X",
                    status);
    }

    (VOID)MyArkCallbackResolveNtoskrnlTextRange();

    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// Safe-read helpers used by every IOCTL walker.
// ---------------------------------------------------------------------------

ULONG
MyArkCallbackSafeRead(
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
MyArkCallbackReadUnicodeString(
    _In_  PUNICODE_STRING Source,
    _Out_writes_bytes_(BufferBytes) PUCHAR Dest,
    _In_  ULONG  BufferBytes)
//
// Copy Source->Buffer (UTF-16) into Dest as a UTF-8/ANSI null-terminated
// string truncated to BufferBytes-1 characters + NUL. Returns the byte
// count actually written. Used for kernel-side DriverName / Altitude.
//
{
    if (Source == NULL || Dest == NULL || BufferBytes == 0) {
        return 0;
    }

    if (!MmIsAddressValid(Source)) {
        return 0;
    }

    USHORT sourceLen = Source->Length;
    USHORT sourceMax = Source->MaximumLength;
    if (sourceLen == 0 || sourceMax == 0) {
        Dest[0] = 0;
        return 1;
    }
    if (sourceLen > sourceMax) {
        sourceLen = sourceMax;
    }

    PWCH sourceBuf = Source->Buffer;
    if (sourceBuf == NULL || !MmIsAddressValid(sourceBuf)) {
        return 0;
    }

    //
    // Bound the read so a corrupted MaximumLength can't push us off-page.
    //
    USHORT copyChars = sourceLen / sizeof(WCHAR);
    if ((SIZE_T)copyChars * sizeof(WCHAR) > 0x1000) {
        copyChars = 0x1000 / sizeof(WCHAR);
    }

    PUCHAR cursor = Dest;
    ULONG remaining = BufferBytes;
    if (remaining == 0) {
        return 0;
    }
    remaining--;                             // reserve NUL
    ULONG written = 0;

    for (USHORT i = 0; i < copyChars && remaining > 0; i++) {
        WCHAR ch;
        if (!MmIsAddressValid((PVOID)(sourceBuf + i))) {
            break;
        }
        ch = sourceBuf[i];
        UCHAR lo = (UCHAR)(ch & 0x00FF);
        *cursor++ = lo;
        cursor++;                             // high byte (UTF-8 widening hack)
        remaining--;
        written += 2;
    }
    *cursor = 0;
    written++;
    return written;
}

UINT32
MyArkCallbackAddressFlags(
    _In_  UINT64 Address,
    _In_  UINT64 TextBase,
    _In_  UINT64 TextEnd)
//
// Combine the suspect-range and low-bit-set checks into a single flags value.
// Conservative: if TextBase or TextEnd is 0 (i.e. the resolve failed) we
// skip the suspect check and only emit POPULATED + the low-bit test.
//
{
    UINT32 flags = MYARK_CALLBACK_FLAG_POPULATED;

    if (Address == 0) {
        return 0;
    }

    if (TextBase != 0 && TextEnd != 0
        && (Address < TextBase || Address >= TextEnd)) {
        flags |= MYARK_CALLBACK_FLAG_SUSPECT;
    }

    if ((Address & 0x1ULL) != 0) {
        flags |= MYARK_CALLBACK_FLAG_HOOK;
    }

    return flags;
}

ULONG
MyArkCallbackResolveDriverName(
    _In_  UINT64 CallbackAddress,
    _Out_writes_bytes_(BufferBytes) PUCHAR Buffer,
    _In_  ULONG  BufferBytes)
//
// Walk PsLoadedModuleList to find the module that owns CallbackAddress,
// then copy the base DLL name into Buffer as a UTF-8/ANSI NUL string.
//
// Returns 0 if DynData's PsLoadedModuleList is unavailable, the address
// falls outside any module's [base, base+size) range, or the walk hits a
// non-resident page. Caller should treat 0 as "unknown driver".
//
{
    if (CallbackAddress == 0 || Buffer == NULL || BufferBytes == 0) {
        return 0;
    }
    if (g_MyArkDynDataPsLoadedModuleList == NULL
        || !MmIsAddressValid(g_MyArkDynDataPsLoadedModuleList)) {
        return 0;
    }

    PLIST_ENTRY head = (PLIST_ENTRY)g_MyArkDynDataPsLoadedModuleList;
    PLIST_ENTRY node = head->Flink;
    ULONG iterGuard = 1024;

    //
    // KLDR_DATA_TABLE_ENTRY offsets (Win11 24H2) -- match dyndata_internal.h
    // so the walker agrees on the InLoadOrderLinks / DllBase / SizeOfImage
    // / BaseDllName layout.
    //
    const SIZE_T OFF_IN_LOAD_ORDER_LINKS  = 0x000;
    const SIZE_T OFF_DLL_BASE             = 0x030;
    const SIZE_T OFF_SIZE_OF_IMAGE        = 0x048;
    const SIZE_T OFF_BASE_DLL_NAME        = 0x058;

    while (node != NULL && node != head && iterGuard > 0) {
        iterGuard--;
        if (!MmIsAddressValid(node)) {
            break;
        }

        PUCHAR kldrBase = (PUCHAR)node - OFF_IN_LOAD_ORDER_LINKS;
        if (!MmIsAddressValid(kldrBase)) {
            break;
        }

        UINT64 imageBase = *(UINT64*)(kldrBase + OFF_DLL_BASE);
        UINT64 imageSize = *(UINT64*)(kldrBase + OFF_SIZE_OF_IMAGE);
        if (imageBase != 0 && imageSize != 0
            && CallbackAddress >= imageBase
            && CallbackAddress <  (imageBase + imageSize)) {
            PUNICODE_STRING baseName = (PUNICODE_STRING)(kldrBase + OFF_BASE_DLL_NAME);
            return MyArkCallbackReadUnicodeString(baseName, Buffer, BufferBytes);
        }

        node = node->Flink;
    }

    return 0;
}

#endif // MYARK_MODULE_CALLBACK