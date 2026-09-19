// MyArk kernel module: FORCE_UNLOAD (R2-5, token+FORCE gated).
//
// Unloads a third-party kernel driver by service-key name:
//   1. Preflight -- the name must be a bare service key (no path, no
//      \\??\\), not MyArkCore itself, and not on the boot-critical
//      blocklist. The image must currently be loaded.
//   2. ZwUnloadDriver on \Registry\Machine\SYSTEM\CurrentControlSet\
//      Services\<name>. Drivers without an Unload routine fail here;
//      that NTSTATUS is reported in-band (a "force" that lies about
//      what left memory would be worse than an honest failure).
//   3. Closed-loop verification -- the loaded-module list (ZwQuerySystem-
//      Information SystemModuleInformation) is re-walked and the output
//      carries WasLoadedBefore / GoneAfter ground truth.
//
// Home note: this is the kernel module's second mutating IOCTL (besides
// PATCH_INLINE_HOOK). The kmod module would have been the natural home,
// but that module is compile-time disabled (its IoDriverListHead walker
// relies on a symbol ntoskrnl does not export on 1903).

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkKernelIoctl.h"
#include "../../../shared/driver/MyArkSafetyToken.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"
#include "../../dispatch/safety_token.h"
#include "kernel_descriptor.h"
#include "kernel_internal.h"

#if MYARK_MODULE_KERNEL

static const PCWSTR g_MyArkForceUnloadBlocklist[] = {
    L"MyArkCore", L"ntoskrnl",   L"hal",
    L"win32k",    L"win32kbase", L"win32kfull",
    L"ci",        L"FLTMGR",     L"ndis",       L"Wdf01000",
    L"WDFLDR",    L"clfs",       L"cng",        L"msrpc",
    L"ksecdd",    L"tcpip",      L"dxgkrnl",    L"dxgmms2",
    L"acpi",      L"pci",        L"disk",       L"classpnp",
    L"volmgr",    L"partmgr",    L"mountmgr",
};

//
// "IsLoaded" probe against SystemModuleInformation: matches the module
// whose file name (path tail) equals the service name case-insensitively.
// Layout mirrors the R2-3 walker: 296-byte x64 entries, ImageBase@16,
// ImageSize@24, FullPathName@40.
//
typedef struct _MYARK_KMOD_SYS_ENTRY {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadCount;
    USHORT  __Unused;
    ULONG   __Pad0;
    UCHAR   FullPathName[256];
} MYARK_KMOD_SYS_ENTRY;

static
BOOLEAN
MyArkKernelModuleIsLoaded(
    _In_ PCWSTR ServiceName)
{
    typedef NTSTATUS (NTAPI *QUERY_FN)(ULONG, PVOID, ULONG, PULONG);
    QUERY_FN query = (QUERY_FN)MmGetSystemRoutineAddress(
        &(UNICODE_STRING)RTL_CONSTANT_STRING(L"ZwQuerySystemInformation"));
    if (query == NULL) {
        return FALSE;
    }

    ULONG needed = 0;
    // The sizing call legitimately returns an error status (INFO_LENGTH_
    // MISMATCH) while filling NeededSize -- only the size is evidence here.
    query(11, NULL, 0, &needed);
    if (needed == 0 || needed > 8 * 1024 * 1024) {
        return FALSE;
    }
    PUCHAR buf = (PUCHAR)MyArkAllocatePool(NonPagedPoolNx, needed, 'MhsK');
    if (buf == NULL) {
        return FALSE;
    }
    NTSTATUS status = query(11, buf, needed, &needed);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, 'MhsK');
        return FALSE;
    }

    ULONG count = *(PULONG)buf;
    BOOLEAN found = FALSE;
    PUCHAR it = buf + 8;
    for (ULONG i = 0; i < count && it + sizeof(MYARK_KMOD_SYS_ENTRY) <= buf + needed; i++) {
        MYARK_KMOD_SYS_ENTRY *m = (MYARK_KMOD_SYS_ENTRY *)it;
        it += sizeof(MYARK_KMOD_SYS_ENTRY);

        PCSTR tail = NULL;
        for (ULONG c = 0; c < sizeof(m->FullPathName) && m->FullPathName[c]; c++) {
            if (m->FullPathName[c] == '\\') {
                tail = (PCSTR)&m->FullPathName[c + 1];
            }
        }
        if (tail == NULL) {
            continue;
        }
        SIZE_T len = strlen(tail);
        SIZE_T want = wcslen(ServiceName);
        BOOLEAN dotSys = FALSE;
        if (len >= 4 && _stricmp(tail + len - 4, ".sys") == 0) {
            len -= 4;                       // compare without the extension
            dotSys = TRUE;
        }
        if (!dotSys || len != want) {
            continue;
        }
        BOOLEAN eq = TRUE;
        for (SIZE_T c = 0; c < len; c++) {
            CHAR a = tail[c];
            WCHAR w = ServiceName[c];
            if (a >= 'A' && a <= 'Z') {
                a = (CHAR)(a - 'A' + 'a');
            }
            if (w >= L'A' && w <= L'Z') {
                w = (WCHAR)(w - L'A' + L'a');
            }
            if ((WCHAR)a != w) {
                eq = FALSE;
                break;
            }
        }
        if (eq) {
            found = TRUE;
            break;
        }
    }

    ExFreePoolWithTag(buf, 'MhsK');
    return found;
}

//
// Bare service-key name check: 1..MAX-1 chars, identifier-like (alnum,
// '_', '-', '.'), no backslash -- this is joined into the service
// registry path, so anything path-shaped is rejected outright.
//
static
NTSTATUS
MyArkKernelValidateServiceName(
    _In_ PCWSTR Name)
{
    SIZE_T len = wcsnlen(Name, MYARK_KERNEL_UNLOAD_NAME_MAX);
    if (len == 0 || len >= MYARK_KERNEL_UNLOAD_NAME_MAX) {
        return STATUS_INVALID_PARAMETER;
    }
    for (SIZE_T i = 0; i < len; i++) {
        WCHAR c = Name[i];
        BOOLEAN ok = (c >= L'0' && c <= L'9')
                     || (c >= L'a' && c <= L'z')
                     || (c >= L'A' && c <= L'Z')
                     || c == L'_' || c == L'-' || c == L'.';
        if (!ok) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkKernelIoctlForceUnload(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PMYARK_KERNEL_FORCE_UNLOAD_INPUT inBuf = NULL;
    size_t inSize = 0;
    NTSTATUS status;

    if (InputBufferLength < sizeof(MYARK_KERNEL_FORCE_UNLOAD_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_KERNEL_FORCE_UNLOAD_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Snapshot inputs (METHOD_BUFFERED: output zero would clobber).
    //
    WCHAR name[MYARK_KERNEL_UNLOAD_NAME_MAX];
    ULONG flags = inBuf->Flags;
    ULONG force = inBuf->Force;
    RtlCopyMemory(name, inBuf->ServiceName, sizeof(name));

    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_KERNEL_OP_FORCE_UNLOAD,
                                      (UINT32)(UINT_PTR)PsGetCurrentProcessId());
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }
    if (!(flags & MYARK_KERNEL_UNLOAD_FLAG_FORCE)
        || force != MYARK_KERNEL_UNLOAD_FORCE_MAGIC) {
        return STATUS_ACCESS_DENIED;
    }

    status = MyArkKernelValidateServiceName(name);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(g_MyArkForceUnloadBlocklist); i++) {
        if (_wcsicmp(name, g_MyArkForceUnloadBlocklist[i]) == 0) {
            return STATUS_ACCESS_DENIED;    // boot-critical image
        }
    }

    BOOLEAN wasLoaded = MyArkKernelModuleIsLoaded(name);

    //
    // Unload via the service registry key. ZwUnloadDriver takes the key
    // path, not a handle; the driver must currently be loaded for it to
    // do anything (else it fails with STATUS_OBJECT_NAME_NOT_FOUND or
    // STATUS_INVALID_PARAMETER depending on build).
    //
    UNICODE_STRING registryPath;
    // 52-char prefix + 63-char name (protocol max) + NUL = 116.
    WCHAR pathBuf[128];
    RtlZeroMemory(pathBuf, sizeof(pathBuf));
    NTSTATUS unloadStatus = STATUS_SUCCESS;
    NTSTATUS build = RtlStringCchPrintfW(pathBuf, RTL_NUMBER_OF(pathBuf),
                                         L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet"
                                         L"\\Services\\%ws", name);
    if (!NT_SUCCESS(build)) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlInitUnicodeString(&registryPath, pathBuf);

    BOOLEAN goneAfter = FALSE;
    if (wasLoaded) {
        unloadStatus = ZwUnloadDriver(&registryPath);
        BOOLEAN probeGone = !MyArkKernelModuleIsLoaded(name);
        if (NT_SUCCESS(unloadStatus) && !probeGone) {
            //
            // The API claimed success but the image is still resident --
            // refuse to report the "0 = confirmed gone" contract.
            //
            unloadStatus = STATUS_UNSUCCESSFUL;
        }
        goneAfter = NT_SUCCESS(unloadStatus) && probeGone;
    }

    PMYARK_KERNEL_FORCE_UNLOAD_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_KERNEL_FORCE_UNLOAD_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    outBuf->Status = wasLoaded
                         ? (goneAfter ? 0 : (UINT32)unloadStatus)
                         : (UINT32)STATUS_NOT_FOUND;
    outBuf->WasLoadedBefore = wasLoaded ? 1 : 0;
    outBuf->GoneAfter = goneAfter ? 1 : 0;
    outBuf->Reserved0 = 0;
    *BytesReturned = sizeof(MYARK_KERNEL_FORCE_UNLOAD_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_KERNEL
