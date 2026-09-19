// MyArk kernel module: QUERY_DRIVER_INTEGRITY (R2-4, read-only).
//
// Per-CPU snapshot collected on every processor through KeIpiGenericCall
// (the worker runs at IPI_LEVEL and only touches registers: GDT/IDT bases
// from the KPCR -- GdtBase overlays KPCR+0x00, IdtBase sits at +0x38,
// both KDNET-verified on 18362 -- plus the syscall MSRs and CR0/CR4).
//
// Everything that needs memory walks (IDT gate decode, GDT extent,
// UnloadedDrivers registry evidence) happens at PASSIVE_LEVEL on the
// current CPU after the IPI. KVA-shadow note: on Meltdown-mitigated
// systems the IDT stubs and LSTAR live in the shadow trampoline area
// BELOW PsNtosImageBase, so the assessment window starts 4 MiB under
// the image base. PiDDBCacheTable has no stable export -- the field is
// reported as unavailable rather than guessed.

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <intrin.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkKernelIoctl.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"
#include "kernel_descriptor.h"
#include "kernel_internal.h"

#if MYARK_MODULE_KERNEL

#define MYARK_INTEGRITY_WINDOW_BELOW   0x400000ULL   // 4 MiB below base
#define MYARK_INTEGRITY_WINDOW_ABOVE   0x1000000ULL  // 16 MiB above base

#define MYARK_MSR_LSTAR                0xC0000082
#define MYARK_MSR_CSTAR                0xC0000083
#define MYARK_MSR_STAR                 0xC0000081
#define MYARK_MSR_SFMASK               0xC0000084

typedef struct _MYARK_INTEGRITY_CTX {
    PMYARK_KERNEL_CPU_INTEGRITY Cpus;
    ULONG MaxCpu;
    UINT64 WindowBase;
    UINT64 WindowEnd;
} MYARK_INTEGRITY_CTX, *PMYARK_INTEGRITY_CTX;

//
// IPI worker: register-only reads, safe at IPI_LEVEL. Processor index is
// the group-relative number -- exact on single-group machines (all test
// targets). Multi-group hosts would alias same-numbered CPUs onto the
// same rows; untested and unclaimed there.
//
static
ULONG_PTR
NTAPI
MyArkIntegrityIpiWorker(
    _In_ ULONG_PTR Context)
{
    PMYARK_INTEGRITY_CTX ctx = (PMYARK_INTEGRITY_CTX)Context;
    ULONG i = KeGetCurrentProcessorNumber();
    if (i >= ctx->MaxCpu) {
        return 0;
    }

    PMYARK_KERNEL_CPU_INTEGRITY e = &ctx->Cpus[i];
    RtlZeroMemory(e, sizeof(*e));
    e->Processor = i;
    e->GdtBase = __readgsqword(0x00);    // KPCR.GdtBase
    e->IdtBase = __readgsqword(0x38);    // KPCR.IdtBase
    e->Lstar = __readmsr(MYARK_MSR_LSTAR);
    e->Cstar = __readmsr(MYARK_MSR_CSTAR);
    e->Star = __readmsr(MYARK_MSR_STAR);
    e->Sfmask = __readmsr(MYARK_MSR_SFMASK);
    e->Cr0 = __readcr0();
    e->Cr4 = __readcr4();

    UINT32 flags = 0;
    if (e->GdtBase != 0) {
        flags |= MYARK_KERNEL_INTF_GDT_BASE_SANE;
    }
    if (e->IdtBase != 0) {
        flags |= MYARK_KERNEL_INTF_IDT_BASE_SANE;
    }
    if ((e->Lstar >= ctx->WindowBase) && (e->Lstar < ctx->WindowEnd)) {
        flags |= MYARK_KERNEL_INTF_LSTAR_IN_WIN;
    }
    if (((e->Cr0 & 0x80000001ULL) == 0x80000001ULL)
        && ((e->Cr0 & 0x40000000ULL) == 0)) {       // PG|PE set, CD clear
        flags |= MYARK_KERNEL_INTF_CR0_NATIVE;
    }
    e->Flags = flags;
    return 0;
}

//
// Walk the IDT at IdtBase (PASSIVE, current CPU): decode every present
// gate and count the ones outside the integrity window. Returns the
// present-gate count; *OutsideOut receives the outside-window count.
//
static
ULONG
MyArkIntegrityMeasureIdt(
    _In_ UINT64 IdtBase,
    _In_ UINT64 WindowBase,
    _In_ UINT64 WindowEnd,
    _Out_ PULONG OutsideOut)
{
    *OutsideOut = 0;
    ULONG present = 0;

    for (ULONG i = 0; i < 256; i++) {
        UINT64 entry = IdtBase + (UINT64)i * 16;
        UINT8 raw[16];
        MM_COPY_ADDRESS src;
        SIZE_T copied = 0;
        src.VirtualAddress = (PVOID)(UINT_PTR)entry;
        if (!NT_SUCCESS(MmCopyMemory(raw, src, sizeof(raw),
                                     MM_COPY_MEMORY_VIRTUAL, &copied))
            || copied != sizeof(raw)) {
            break;                       // past the live gate array
        }

        UINT16 word4 = *(UINT16 *)&raw[4];
        if ((word4 & 0x8000) == 0) {
            continue;                    // not present
        }
        present++;

        UINT64 handler = (UINT64)*(UINT16 *)&raw[0]
                         | ((UINT64)*(UINT16 *)&raw[6] << 16)
                         | ((UINT64)*(UINT32 *)&raw[8] << 32);
        if (handler < WindowBase || handler >= WindowEnd) {
            *OutsideOut += 1;
        }
    }
    return present;
}

//
// Approximate the GDT extent: walk 8-byte entries from GdtBase until an
// all-zero entry or a sane cap. TSS descriptors are 16 bytes but the
// zero-terminator still bounds the walk; this is a measurement aid, not
// a security verdict.
//
static
ULONG
MyArkIntegrityMeasureGdt(
    _In_ UINT64 GdtBase)
{
    ULONG extent = 0;
    BOOLEAN seen = FALSE;
    for (ULONG i = 0; i < 128; i++) {
        UINT64 entry = GdtBase + (UINT64)i * 8;
        UINT64 raw = 0;
        MM_COPY_ADDRESS src;
        SIZE_T copied = 0;
        src.VirtualAddress = (PVOID)(UINT_PTR)entry;
        if (!NT_SUCCESS(MmCopyMemory(&raw, src, sizeof(raw),
                                     MM_COPY_MEMORY_VIRTUAL, &copied))
            || copied != sizeof(raw)) {
            break;
        }
        if (raw == 0) {
            if (seen) {
                break;              // terminator after live entries
            }
            continue;               // GDT entry 0 is the null descriptor
        }
        seen = TRUE;
        extent = (i + 1) * 8;
    }
    return extent;
}

//
// Enumerate the UnloadedDrivers registry key (Mm's unloaded-driver
// evidence): each value name is a driver file, the 16-byte REG_BINARY
// data starts with the unload FILETIME. Emits up to UnloadedMax entries.
//
static
VOID
MyArkIntegrityReadUnloadedDrivers(
    _Out_writes_(UnloadedMax) PMYARK_KERNEL_UNLOADED_ENTRY Entries,
    _In_ ULONG UnloadedMax,
    _Out_ PULONG EmittedOut,
    _Out_ PULONG TotalOut)
{
    *EmittedOut = 0;
    *TotalOut = 0;

    NTSTATUS status;
    HANDLE key = NULL;
    UNICODE_STRING path = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control"
        L"\\Session Manager\\UnloadedDrivers");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &path,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);
    status = ZwOpenKey(&key, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        return;                         // key absent: no evidence recorded
    }

    UCHAR fullInfo[64];
    ULONG needed = 0;
    status = ZwQueryKey(key, KeyFullInformation, fullInfo,
                        sizeof(fullInfo), &needed);
    if (!NT_SUCCESS(status)) {
        ZwClose(key);
        return;
    }
    ULONG values = ((PKEY_FULL_INFORMATION)fullInfo)->Values;
    *TotalOut = values;

    for (ULONG i = 0; i < values && *EmittedOut < UnloadedMax; i++) {
        UCHAR nameBuf[128];
        ULONG nameLen = 0;
        ULONG result = 0;
        status = ZwEnumerateValueKey(key, i, KeyValueBasicInformation,
                                     nameBuf, sizeof(nameBuf), &result);
        if (status == STATUS_BUFFER_OVERFLOW) {
            continue;              // overlong value name: skip, keep going
        }
        if (!NT_SUCCESS(status)) {
            break;
        }
        PKEY_VALUE_BASIC_INFORMATION basic =
            (PKEY_VALUE_BASIC_INFORMATION)nameBuf;
        nameLen = basic->NameLength / sizeof(WCHAR);

        UCHAR dataBuf[32];
        UNICODE_STRING valueName;
        valueName.Length = (USHORT)basic->NameLength;
        valueName.MaximumLength = (USHORT)basic->NameLength;
        valueName.Buffer = basic->Name;
        status = ZwQueryValueKey(key, &valueName,
                                 KeyValuePartialInformation,
                                 dataBuf, sizeof(dataBuf), &result);
        UINT64 unloadTime = 0;
        if (NT_SUCCESS(status)) {
            PKEY_VALUE_PARTIAL_INFORMATION info =
                (PKEY_VALUE_PARTIAL_INFORMATION)dataBuf;
            if (info->DataLength >= sizeof(UINT64)) {
                unloadTime = *(UINT64 *)info->Data;
            }
        }

        PMYARK_KERNEL_UNLOADED_ENTRY row = &Entries[*EmittedOut];
        RtlZeroMemory(row, sizeof(*row));
        row->UnloadTime = unloadTime;
        ULONG copy = nameLen < 27 ? nameLen : 27;
        RtlCopyMemory(row->Name, basic->Name, copy * sizeof(WCHAR));
        row->Name[27] = L'\0';
        *EmittedOut += 1;
    }

    ZwClose(key);
}

NTSTATUS
MyArkKernelIoctlQueryIntegrity(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PMYARK_KERNEL_INTEGRITY_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    NTSTATUS status = MyArkIoctlFetchOutputBuffer(Request,
        FIELD_OFFSET(MYARK_KERNEL_INTEGRITY_OUTPUT, Cpus),
        (PVOID *)&outBuf,
        &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    MyArkKernelEnsureNtoskrnlBounds();
    UINT64 ntosBase = g_MyArkKernelNtoskrnlTextBase;
    UINT64 ntosEnd = g_MyArkKernelNtoskrnlTextEnd;
    if (ntosBase == 0 || ntosEnd <= ntosBase) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    UINT64 windowBase = ntosBase - MYARK_INTEGRITY_WINDOW_BELOW;
    UINT64 windowEnd = ntosBase + MYARK_INTEGRITY_WINDOW_ABOVE;

    //
    // Cap the CPU array against the output space: header + up to MAX_CPU
    // cpu rows must fit before the unloaded tail.
    //
    ULONG maxCpu = MYARK_KERNEL_INTEGRITY_MAX_CPU;
    {
        ULONG spaceForCpus = (ULONG)((outSize
            - FIELD_OFFSET(MYARK_KERNEL_INTEGRITY_OUTPUT, Cpus))
            / sizeof(MYARK_KERNEL_CPU_INTEGRITY));
        if (spaceForCpus < maxCpu) {
            maxCpu = spaceForCpus;
        }
    }
    if (maxCpu == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
    if (cpuCount > maxCpu) {
        cpuCount = maxCpu;
    }

    PMYARK_KERNEL_CPU_INTEGRITY cpus =
        (PMYARK_KERNEL_CPU_INTEGRITY)MyArkAllocatePool(
            NonPagedPoolNx,
            (SIZE_T)maxCpu * sizeof(MYARK_KERNEL_CPU_INTEGRITY),
            'IhsK');
    if (cpus == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(cpus, (SIZE_T)maxCpu * sizeof(MYARK_KERNEL_CPU_INTEGRITY));

    MYARK_INTEGRITY_CTX ctx;
    ctx.Cpus = cpus;
    ctx.MaxCpu = cpuCount;
    ctx.WindowBase = windowBase;
    ctx.WindowEnd = windowEnd;
    KeIpiGenericCall(MyArkIntegrityIpiWorker, (ULONG_PTR)&ctx);

    //
    // PASSIVE measurements on the current CPU: IDT gate decode + GDT
    // extent (their bases come from cpu0's IPI row).
    //
    ULONG idtOutside = 0;
    ULONG idtPresent = MyArkIntegrityMeasureIdt(cpus[0].IdtBase,
                                                windowBase, windowEnd,
                                                &idtOutside);
    ULONG gdtExtent = MyArkIntegrityMeasureGdt(cpus[0].GdtBase);

    for (ULONG i = 0; i < cpuCount; i++) {
        cpus[i].IdtLimit = idtPresent * 16;
        cpus[i].GdtLimit = gdtExtent;
        cpus[i].IdtOutsideCount = (i == 0) ? idtOutside : 0;
        if (i == 0 && idtPresent > 0 && idtOutside == 0) {
            cpus[i].Flags |= MYARK_KERNEL_INTF_IDT_ALL_IN_WIN;
        }
    }

    //
    // UnloadedDrivers evidence. Capacity: what remains after the CPU rows.
    //
    ULONG unloadedCap = MYARK_KERNEL_UNLOADED_MAX;
    SIZE_T tailRoom = (outSize > (FIELD_OFFSET(MYARK_KERNEL_INTEGRITY_OUTPUT, Cpus)
                                  + (SIZE_T)cpuCount * sizeof(MYARK_KERNEL_CPU_INTEGRITY)))
                          ? outSize - (FIELD_OFFSET(MYARK_KERNEL_INTEGRITY_OUTPUT, Cpus)
                                       + (SIZE_T)cpuCount * sizeof(MYARK_KERNEL_CPU_INTEGRITY))
                          : 0;
    ULONG unloadedRoom = (ULONG)(tailRoom / sizeof(MYARK_KERNEL_UNLOADED_ENTRY));
    if (unloadedCap > unloadedRoom) {
        unloadedCap = unloadedRoom;
    }

    PMYARK_KERNEL_UNLOADED_ENTRY unloaded =
        (PMYARK_KERNEL_UNLOADED_ENTRY)MyArkAllocatePool(
            NonPagedPoolNx,
            (SIZE_T)unloadedCap * sizeof(MYARK_KERNEL_UNLOADED_ENTRY),
            'UhsK');
    ULONG unloadedEmitted = 0;
    ULONG unloadedTotal = 0;
    if (unloaded != NULL) {
        RtlZeroMemory(unloaded,
                      (SIZE_T)unloadedCap * sizeof(MYARK_KERNEL_UNLOADED_ENTRY));
        MyArkIntegrityReadUnloadedDrivers(unloaded, unloadedCap,
                                          &unloadedEmitted, &unloadedTotal);
    }

    UINT32 unloadedOffset = (UINT32)(FIELD_OFFSET(MYARK_KERNEL_INTEGRITY_OUTPUT, Cpus)
                                     + (SIZE_T)cpuCount * sizeof(MYARK_KERNEL_CPU_INTEGRITY));

    outBuf->Size = unloadedOffset
                   + unloadedEmitted * sizeof(MYARK_KERNEL_UNLOADED_ENTRY);
    outBuf->Status = MYARK_KERNEL_INTEGRITY_PIDDB_NA;   // degraded: no PiDDB
    outBuf->ProcessorCount = cpuCount;
    outBuf->UnloadedCount = unloadedEmitted;
    outBuf->UnloadedTotal = unloadedTotal;
    outBuf->Reserved0 = 0;
    outBuf->NtosWindowBase = windowBase;
    outBuf->NtosWindowEnd = windowEnd;
    outBuf->CpuEntryStructSize = sizeof(MYARK_KERNEL_CPU_INTEGRITY);
    outBuf->UnloadedEntryStructSize = sizeof(MYARK_KERNEL_UNLOADED_ENTRY);
    outBuf->UnloadedOffset = unloadedOffset;
    outBuf->Reserved1 = 0;
    RtlCopyMemory(outBuf->Cpus, cpus,
                  (SIZE_T)cpuCount * sizeof(MYARK_KERNEL_CPU_INTEGRITY));
    if (unloaded != NULL && unloadedEmitted > 0) {
        RtlCopyMemory((PUCHAR)outBuf + unloadedOffset, unloaded,
                      (SIZE_T)unloadedEmitted * sizeof(MYARK_KERNEL_UNLOADED_ENTRY));
    }

    if (unloaded != NULL) {
        ExFreePoolWithTag(unloaded, 'UhsK');
    }
    ExFreePoolWithTag(cpus, 'IhsK');

    *BytesReturned = outBuf->Size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_KERNEL
