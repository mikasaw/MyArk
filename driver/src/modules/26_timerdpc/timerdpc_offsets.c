// timerdpc offsets: nt base resolution, build profile selection,
// probe-safe readers, owner lookup. All state is resolved lazily on the
// first IOCTL (PASSIVE_LEVEL) and never changes afterwards.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "timerdpc_descriptor.h"
#include "timerdpc_internal.h"

#if MYARK_MODULE_TIMERDPC

#define MYARK_TDP_POOL_TAG 'PDTC'

static const MYARK_TDP_PROFILE g_MyArkTdpProfiles[] = {
    MYARK_TDP_PROFILE_18362,
    MYARK_TDP_PROFILE_22621,
};

const MYARK_TDP_PROFILE* g_MyArkTdpProfile = NULL;
UINT64 g_MyArkTdpNtBase = 0;
UINT64 g_MyArkTdpNtTextBase = 0;
UINT64 g_MyArkTdpNtTextEnd = 0;

static volatile LONG g_MyArkTdpInitDone = 0;

// Declared in ntifs.h (not pulled into this translation unit); documented
// NTSYSAPI export since Vista.
NTSYSAPI
ULONG64
NTAPI
RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID* BaseOfImage);

// Dyndata-owned resolver outputs (same externs the callback/wfp modules
// import). Text bounds gate the NTROUTINE flag; the module list powers
// owner lookup. Both may legitimately be 0 -- rows stay valid, flags
// degrade.
extern UINT64 g_MyArkDynDataNtoskrnlTextBase;
extern UINT64 g_MyArkDynDataNtoskrnlTextEnd;
extern PVOID  g_MyArkDynDataPsLoadedModuleList;

BOOLEAN
MyArkTdpReadU32(_In_ UINT64 Address, _Out_ UINT32* ValueOut)
{
    if (Address == 0
        || !MmIsAddressValid((PVOID)(UINT_PTR)Address)
        || !MmIsAddressValid((PVOID)(UINT_PTR)(Address + 3))) {
        return FALSE;
    }
    *ValueOut = *(PUINT32)(UINT_PTR)Address;
    return TRUE;
}

BOOLEAN
MyArkTdpReadU64(_In_ UINT64 Address, _Out_ UINT64* ValueOut)
{
    UINT32 lo = 0;
    UINT32 hi = 0;
    if (!MyArkTdpReadU32(Address, &lo)
        || !MyArkTdpReadU32(Address + 4, &hi)) {
        return FALSE;
    }
    *ValueOut = (UINT64)lo | ((UINT64)hi << 32);
    return TRUE;
}

//
// ntoskrnl image base via a PC-to-module lookup of an exported routine.
//
static
BOOLEAN
MyArkTdpResolveNtBase(VOID)
{
    UNICODE_STRING name;
    PVOID routine = NULL;
    PVOID base = NULL;

    RtlInitUnicodeString(&name, L"KeSetTimerEx");
    routine = MmGetSystemRoutineAddress(&name);
    if (routine == NULL) {
        return FALSE;
    }
    if (RtlPcToFileHeader(routine, &base) == 0 || base == NULL) {
        return FALSE;
    }
    g_MyArkTdpNtBase = (UINT64)(UINT_PTR)base;
    return TRUE;
}

NTSTATUS
MyArkTdpEnsureInit(VOID)
{
    if (InterlockedCompareExchange(&g_MyArkTdpInitDone, 1, 1) == 1) {
        return (g_MyArkTdpProfile != NULL) ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
    }

    InterlockedExchange(&g_MyArkTdpInitDone, 1);

    RTL_OSVERSIONINFOW info;
    RtlZeroMemory(&info, sizeof(info));
    info.dwOSVersionInfoSize = sizeof(info);
    if (!NT_SUCCESS(RtlGetVersion(&info))) {
        return STATUS_NOT_SUPPORTED;
    }

    if (!MyArkTdpResolveNtBase()) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   MYARK_TRACE_TIMERDPC "nt base unresolvable\n");
        return STATUS_NOT_SUPPORTED;
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(g_MyArkTdpProfiles); i++) {
        const MYARK_TDP_PROFILE* p = &g_MyArkTdpProfiles[i];
        if (info.dwBuildNumber >= p->BuildMin
            && info.dwBuildNumber <= p->BuildMax) {
            g_MyArkTdpProfile = p;
            break;
        }
    }

    g_MyArkTdpNtTextBase = g_MyArkDynDataNtoskrnlTextBase;
    g_MyArkTdpNtTextEnd = g_MyArkDynDataNtoskrnlTextEnd;

    if (g_MyArkTdpProfile == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   MYARK_TRACE_TIMERDPC "no profile for build %d\n",
                   info.dwBuildNumber);
        return STATUS_NOT_SUPPORTED;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_TIMERDPC "build %d nt=%p profile ok\n",
               info.dwBuildNumber, (PVOID)(UINT_PTR)g_MyArkTdpNtBase);
    return STATUS_SUCCESS;
}

ULONG
MyArkTdpOwnerForAddress(_In_ UINT64 Address,
                        _Out_writes_bytes_(OutBytes) PUCHAR Out,
                        _In_ ULONG OutBytes)
//
// BaseDllName of the loaded module containing Address, via the dyndata
// PsLoadedModuleList walk (KLDR offsets shared with 70_dyndata; the
// SIZE_OF_IMAGE offset 0x40 was corrected by the KLDRDIAG probe).
//
{
    PLIST_ENTRY head;
    PLIST_ENTRY node;
    ULONG iterGuard = 512;

    if (Out == NULL || OutBytes == 0) {
        return 0;
    }
    Out[0] = 0;
    if (Address == 0
        || g_MyArkDynDataPsLoadedModuleList == NULL
        || !MmIsAddressValid(g_MyArkDynDataPsLoadedModuleList)) {
        return 0;
    }

    head = (PLIST_ENTRY)g_MyArkDynDataPsLoadedModuleList;
    node = head->Flink;

    while (node != NULL && node != head && iterGuard > 0) {
        PUCHAR kldr;
        UINT64 imageBase = 0;
        UINT64 imageSize = 0;
        PUNICODE_STRING baseName;

        iterGuard--;
        if (!MmIsAddressValid(node)) {
            break;
        }
        kldr = (PUCHAR)node;   // InLoadOrderLinks at offset 0

        if (!MyArkTdpReadU64((UINT64)(kldr + 0x30), &imageBase)
            || !MyArkTdpReadU64((UINT64)(kldr + 0x40), &imageSize)) {
            break;
        }
        if (imageSize != 0
            && Address >= imageBase
            && Address < imageBase + imageSize) {
            baseName = (PUNICODE_STRING)(kldr + 0x58);
            if (MmIsAddressValid(baseName)
                && baseName->Length > 0
                && baseName->Buffer != NULL
                && MmIsAddressValid(baseName->Buffer)) {
                ULONG nameChars = baseName->Length / sizeof(WCHAR);
                ULONG copy = OutBytes - 1;
                if (copy > nameChars) {
                    copy = nameChars;
                }
                for (ULONG i = 0; i < copy; i++) {
                    Out[i] = (UCHAR)baseName->Buffer[i];
                }
                Out[copy] = 0;
                return copy + 1;
            }
            return 0;
        }
        node = node->Flink;
    }
    return 0;
}

#endif // MYARK_MODULE_TIMERDPC
