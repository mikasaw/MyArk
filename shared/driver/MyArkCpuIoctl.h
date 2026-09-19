// MyArk CPU/hardware module: shared IOCTL protocol (R3-14).
//
// 0x84A CPU_SNAPSHOT: per-CPU register capture via a broadcast IPI. The
// driver reads a fixed whitelist of model-specific registers (LSTAR/EFER/
// PAT/APIC base) and the control/debug registers plus GDT/IDT bases -- a
// read-only inventory for authorized-environment inspection. No MSR writes,
// no arbitrary MSR addresses.

#pragma once

#include <ntddk.h>

#define MYARK_CPU_MODULE_ID                   0x43505531UL  // 'CPU1' (LE)

#define IOCTL_MYARK_CPU_SNAPSHOT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84A, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_CPU_MAX                         64

typedef struct _MYARK_CPU_PER_CPU {
    UINT64 Cr0;
    UINT64 Cr2;
    UINT64 Cr3;
    UINT64 Cr4;
    UINT64 Cr8;
    UINT64 GdtBase;
    UINT64 GdtLimit;
    UINT64 IdtBase;
    UINT64 IdtLimit;
    UINT64 Lstar;                                // MSR 0xC0000082
    UINT64 Efer;                                 // MSR 0xC0000080
    UINT64 Pat;                                  // MSR 0x277
    UINT64 ApicBase;                             // MSR 0x1B
    UINT32 ProcessorNumber;
    UINT32 Reserved1;
} MYARK_CPU_PER_CPU, *PMYARK_CPU_PER_CPU;

typedef struct _MYARK_CPU_SNAPSHOT_OUTPUT {
    UINT32 CpuCount;                             // captured entries (single-group semantics)
    UINT32 CurrentCpu;                           // advisory: caller's CPU before the IPI (migratable)
    CHAR   Vendor[16];                           // cpuid leaf 0, NUL-padded
    UINT64 FeatureEcx;                           // cpuid leaf 1 ECX
    UINT64 FeatureEdx;                           // cpuid leaf 1 EDX
    UINT32 CpuidMaxLeaf;                         // cpuid leaf 0 EAX
    UINT32 Reserved1;
    UINT64 Reserved64;
    MYARK_CPU_PER_CPU Cpus[MYARK_CPU_MAX];
} MYARK_CPU_SNAPSHOT_OUTPUT, *PMYARK_CPU_SNAPSHOT_OUTPUT;

C_ASSERT(sizeof(MYARK_CPU_PER_CPU) == 112);
C_ASSERT(sizeof(MYARK_CPU_SNAPSHOT_OUTPUT) == 7224);
