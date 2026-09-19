// MyArk memory module: internal-only definitions shared by the R0 source
// files. Anything the R3 client sees lives in
// ``shared/driver/MyArkMemoryIoctl.h``; this header is the within-module
// private vocabulary.
//
// Memory module splits into four sub-files for readability:
//
//   memory_virtual.c    -- MmCopyVirtualMemory + KeStackAttachProcess
//                          cross-process read / write + VAD walk for QUERY_VM
//   memory_physical.c   -- MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) read +
//                          \Device\PhysicalMemory section write, over the
//                          MmGetPhysicalMemoryRanges RAM-only policy
//   memory_pagetable.c  -- hand-rolled x64 4-level page-table walker
//                          (PML4 -> PDPT -> PD -> PT) for TRANSLATE_VA and
//                          QUERY_PT_ENTRY
//   memory_scan.c       -- SCAN_KERNEL_EXECUTABLE and SCAN_KERNEL_MEMORY_EVIDENCE
//   memory_module.c     -- descriptor + Init / Cleanup
//
// Every byte is gated on MYARK_MODULE_MEMORY so a profile that omits the
// macro links nothing into the .sys.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "module_descriptor.h"
#include "../../../shared/driver/MyArkMemoryIoctl.h"

#if MYARK_MODULE_MEMORY

//
// EPROCESS offsets (Win11 24H2 / build 26100.x). S7.1 (DynData) replaces
// these at runtime -- until then the memory module pins to a single Windows
// build so the rest of the module compiles cleanly.
//
//   VadRoot          -- balanced tree root for MMVAD enumeration
//   Pcb              -- KPROCESS base (used to read DirectoryTableBase)
//   DirectoryTableBase -- KPROCESS.DirectoryTableBase (CR3)
//
#define MYARK_OFF_EPROCESS_PCB                         0x000UL  // EPROCESS.Pcb
#define MYARK_OFF_KPROCESS_DIRECTORY_TABLE_BASE        0x028UL  // KPROCESS.DirectoryTableBase
#define MYARK_OFF_EPROCESS_VAD_ROOT                     0x7D8UL  // EPROCESS.VadRoot (24H2)
#define MYARK_OFF_EPROCESS_UNIQUE_PROCESS_ID            0x1D0UL
#define MYARK_OFF_EPROCESS_PEB                          0x7C0UL

//
// MMVAD_SHORT / MMVAD (24H2). The short form is what the VadRoot RB-tree
// stores. The long form (MMVAD) carries the unicode subsection name used
// by mapped/image VADs. Both layout variants exist; for the QUERY_VM
// implementation we read MMVAD_SHORT then upgrade to MMVAD when a long
// form is reachable through the union.
//
//   VadNode          -- balanced tree node embedded in the VAD
//   StartingVpn      -- first VPN (>> 12 gives BaseAddress)
//   EndingVpn        -- last VPN (inclusive)
//   VadType          -- MMVAD.VadType enum (Private/Mapped/Image)
//   Protection       -- Win32 protection bits (NOACCESS/READONLY/etc.)
//   Flags            -- MMVAD_FLAGS (Commit/Reserve, etc.)
//   Name             -- FilePointer + unicode name (MMVAD-only)
//
#define MYARK_OFF_MMVAD_SHORT_VAD_NODE                 0x000UL
#define MYARK_OFF_MMVAD_SHORT_STARTING_VPN             0x018UL  // EndingVpn immediately follows
#define MYARK_OFF_MMVAD_SHORT_VAD_TYPE                 0x040UL
#define MYARK_OFF_MMVAD_SHORT_PROTECTION               0x044UL
#define MYARK_OFF_MMVAD_SHORT_FLAGS                    0x048UL

//
// 4-level paging constants. x64 canonical user / kernel VAs span 48 bits
// across 4 levels; the shifts below match the standard 48-bit paging
// scheme (no LA57 support -- see QUERY_PT_ENTRY for the CR4.LA57 gate).
//
#define MYARK_PT_PTE_SHIFT             12
#define MYARK_PT_PDE_SHIFT             21
#define MYARK_PT_PDPTE_SHIFT           30
#define MYARK_PT_PML4E_SHIFT           39

#define MYARK_PT_ADDR_MASK_48          0x000FFFFFFFFFF000ULL
#define MYARK_PT_PTE_LARGE_MASK        0x000FFFFFFFFFFE00ULL   // 2MB mask (21..51)

#define MYARK_PT_PTE_PRESENT           0x0000000000000001ULL
#define MYARK_PT_PTE_RW                0x0000000000000002ULL
#define MYARK_PT_PTE_USER              0x0000000000000004ULL
#define MYARK_PT_PTE_WRITE_THROUGH     0x0000000000000008ULL
#define MYARK_PT_PTE_CACHE_DISABLE     0x0000000000000010ULL
#define MYARK_PT_PTE_ACCESSED          0x0000000000000020ULL
#define MYARK_PT_PTE_DIRTY             0x0000000000000040ULL
#define MYARK_PT_PTE_LARGE             0x0000000000000080ULL
#define MYARK_PT_PTE_GLOBAL            0x0000000000000100ULL
#define MYARK_PT_PTE_NX                0x8000000000000000ULL

#define MYARK_PT_CR4_LA57              0x0000000000001000ULL

//
// Default caps. Drivers clamp caller-supplied limits to these so a
// malformed input cannot trigger an unbounded allocation.
//
#define MYARK_MEMORY_RW_MAX_BYTES              (4 * 1024 * 1024)   // 4 MiB cap
#define MYARK_MEMORY_RW_DEFAULT_BYTES          (64 * 1024)
#define MYARK_MEMORY_SCAN_DEFAULT_MAX          256
#define MYARK_MEMORY_SCAN_HARD_CAP             8192
#define MYARK_MEMORY_PHYSICAL_DEFAULT_MAX      256
#define MYARK_MEMORY_PHYSICAL_HARD_CAP         4096
#define MYARK_MEMORY_VAD_DEFAULT_MAX           256
#define MYARK_MEMORY_VAD_HARD_CAP              4096

//
// Tracing helper: assign a stable prefix for memory-module lines.
//
#define MYARK_TRACE_MEMORY                     MYARK_TRACE_MODULE

NTSTATUS MyArkMemoryInit(VOID);
VOID     MyArkMemoryCleanup(VOID);

//
// IOCTL handler prototypes. All conform to MYARK_IOCTL_HANDLER.
//
NTSTATUS MyArkMemoryIoctlQueryVm(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkMemoryIoctlReadVm(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkMemoryIoctlWriteVm(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkMemoryIoctlTranslateVa(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkMemoryIoctlQueryPtEntry(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkMemoryIoctlReadPhysical(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkMemoryIoctlWritePhysical(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkMemoryIoctlQueryPhysicalLayout(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkMemoryIoctlScanKernelExecutable(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkMemoryIoctlScanKernelMemoryEvidence(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

//
// Module descriptor exported via g_AllModules[].
//
extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Memory;

#endif // MYARK_MODULE_MEMORY