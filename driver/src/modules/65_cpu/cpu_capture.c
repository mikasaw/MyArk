// MyArk CPU module: per-CPU register snapshot via broadcast IPI (R3-14).
//
// MSR whitelist (read-only): LSTAR 0xC0000082, EFER 0xC0000080, PAT 0x277,
// APIC base 0x1B. The capture callback runs at IPI_LEVEL on every
// processor: only register reads (CR/MSR/SGDT/SIDTR) and stores into the
// preallocated nonpaged output array happen there.

#include <ntddk.h>
#include <intrin.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "cpu_internal.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"

#if MYARK_MODULE_CPU

#define MYARK_CPU_MSR_LSTAR     0xC0000082
#define MYARK_CPU_MSR_EFER      0xC0000080
#define MYARK_CPU_MSR_PAT       0x00000277
#define MYARK_CPU_MSR_APIC_BASE 0x0000001B

//
// Single-group precision: KeGetCurrentProcessorNumber returns a group-relative
// index, so on multi-group hosts (>64 LPs) same-numbered CPUs would alias onto
// the same slot. Untested and unclaimed there -- same caveat as
// 25_kernel/integrity_snapshot.c. Test VMs are single-group.
//
static
ULONG_PTR
MyArkCpuCaptureIpi(
    _In_ PVOID Context)
{
    PMYARK_CPU_SNAPSHOT_OUTPUT out = (PMYARK_CPU_SNAPSHOT_OUTPUT)Context;
    ULONG n = KeGetCurrentProcessorNumber();
    UCHAR gdt[10];
    UCHAR idt[10];
    PMYARK_CPU_PER_CPU slot;

    if (n >= MYARK_CPU_MAX) {
        return 0;
    }
    slot = &out->Cpus[n];

    slot->Cr0 = __readcr0();
    slot->Cr2 = __readcr2();
    slot->Cr3 = __readcr3();
    slot->Cr4 = __readcr4();
    slot->Cr8 = __readcr8();

    _sgdt(gdt);
    RtlCopyMemory(&slot->GdtBase, &gdt[2], sizeof(UINT64));
    RtlCopyMemory(&slot->GdtLimit, &gdt[0], sizeof(UINT16));
    __sidt(idt);
    RtlCopyMemory(&slot->IdtBase, &idt[2], sizeof(UINT64));
    RtlCopyMemory(&slot->IdtLimit, &idt[0], sizeof(UINT16));

    slot->Lstar = __readmsr(MYARK_CPU_MSR_LSTAR);
    slot->Efer = __readmsr(MYARK_CPU_MSR_EFER);
    slot->Pat = __readmsr(MYARK_CPU_MSR_PAT);
    slot->ApicBase = __readmsr(MYARK_CPU_MSR_APIC_BASE);
    slot->ProcessorNumber = (UINT32)n;

    return 0;
}

NTSTATUS
MyArkCpuCaptureSnapshot(
    _Out_ PMYARK_CPU_SNAPSHOT_OUTPUT Output)
{
    int regs[4];
    ULONG count;

    RtlZeroMemory(Output, sizeof(*Output));

    __cpuid(regs, 0);
    Output->CpuidMaxLeaf = (UINT32)regs[0];
    // Vendor string: EBX (little-endian) + EDX + ECX, 12 bytes.
    RtlCopyMemory(Output->Vendor + 0, &regs[1], 4);
    RtlCopyMemory(Output->Vendor + 4, &regs[3], 4);
    RtlCopyMemory(Output->Vendor + 8, &regs[2], 4);
    Output->Vendor[12] = '\0';

    __cpuid(regs, 1);
    Output->FeatureEcx = (UINT32)regs[2];
    Output->FeatureEdx = (UINT32)regs[3];

    count = KeQueryActiveProcessorCount(NULL);
    Output->CpuCount = (count > MYARK_CPU_MAX) ? MYARK_CPU_MAX : count;
    Output->CurrentCpu = (UINT32)KeGetCurrentProcessorNumber();

    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)MyArkCpuCaptureIpi, (ULONG_PTR)Output);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_CPU
