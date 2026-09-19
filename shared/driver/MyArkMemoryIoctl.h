// MyArk memory module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xB00..0xBFF reserved for the memory module. Core uses
// 0x800..0x8FF, hello 0x900..0x9FF, process 0xA00..0xAFF, so memory sits
// in the next free block. All 10 IOCTLs follow the MyArk METHOD_BUFFERED
// convention (matching the core / hello / process modules).
//
// Memory module pillars:
//
//   virtual     -- MmCopyVirtualMemory + KeStackAttachProcess cross-process
//                  virtual read / write. The QUERY_VM IOCTL surfaces a per-
//                  process VAD-region enumeration by walking EPROCESS.VadRoot
//                  on a per-call basis; S7 kernel_object will replace this
//                  with a VAD-tree walker.
//
//   physical    -- MmMapIoSpace + IoAllocateMdl for paged physical memory.
//                  Some physical pages have MmAllocateContiguousMemory-only
//                  attributes, so the physical module probes for them with
//                  MmAllocatePagesForMdl and falls back when not available.
//
//   pagetable   -- hand-rolled x64 4-level page-table walker. PML4 shift
//                  39 / PDPT shift 30 / PD shift 21 / PT shift 12, with
//                  2MB and 1GB large-page masks (bits 21..51 and 30..51).
//                  LA57 (5-level paging) is intentionally NOT supported;
//                  if CR4.LA57 is set the IOCTLs return STATUS_NOT_SUPPORTED.
//
//   scan        -- SCAN_KERNEL_EXECUTABLE walks kernel .text looking for a
//                  caller-provided byte signature (up to 16 bytes); the
//                  evidence variant walks an arbitrary kernel VA range
//                  comparing each 16-byte window against a UNICODE_STRING
//                  signature with PUNICODE_STRING semantics (case-insensitive
//                  prefix match against unicode memory).
//
// EPROCESS field offsets are hardcoded for Windows 11 24H2 / build
// 26100.x; S7.1 (DynData) will replace them with a runtime-loaded profile.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_MEMORY_MODULE_ID                0x4D454D4DUL  // 'MEMM' ASCII (LE)
#define MYARK_MEMORY_VAD_NAME_MAX              64
#define MYARK_MEMORY_SCAN_SIGNATURE_MAX        16
#define MYARK_MEMORY_SCAN_UNICODE_MAX          64
#define MYARK_MEMORY_VAD_DEFAULT_MAX           256
#define MYARK_MEMORY_VAD_HARD_CAP              4096

//
// 10 IOCTLs (function range 0xB00..0xB09). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_MEMORY_QUERY_VM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB00, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MEMORY_READ_VM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB01, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MEMORY_WRITE_VM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB02, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MEMORY_TRANSLATE_VA \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB03, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MEMORY_QUERY_PT_ENTRY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB04, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MEMORY_READ_PHYSICAL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB05, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MEMORY_WRITE_PHYSICAL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB06, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MEMORY_QUERY_PHYSICAL_LAYOUT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB07, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MEMORY_SCAN_KERNEL_EXECUTABLE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB08, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MEMORY_SCAN_KERNEL_MEMORY_EVIDENCE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB09, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// VAD region classification. VadType tells the table renderer which view
// the region came from (Mm subtype in MMVAD_SHORT.u.VadType on 24H2).
// ---------------------------------------------------------------------------

#define MYARK_MEMORY_VAD_TYPE_PHYSICAL        0x00
#define MYARK_MEMORY_VAD_TYPE_PRIVATE         0x01
#define MYARK_MEMORY_VAD_TYPE_MAPPED          0x02
#define MYARK_MEMORY_VAD_TYPE_IMAGE           0x03

#define MYARK_MEMORY_STATE_COMMIT             0x01
#define MYARK_MEMORY_STATE_RESERVE            0x02
#define MYARK_MEMORY_STATE_FREE               0x04

#define MYARK_MEMORY_PROTECT_MASK             0x000000FFUL

//
// Page-size classification returned by TRANSLATE_VA. Values match the
// page-size encoding the 4-level page-table walker produces.
//
#define MYARK_MEMORY_PAGE_SIZE_4K              0x00001000ULL
#define MYARK_MEMORY_PAGE_SIZE_2M              0x00200000ULL
#define MYARK_MEMORY_PAGE_SIZE_1G              0x40000000ULL

//
// Page-table level codes returned by QUERY_PT_ENTRY.
//
#define MYARK_MEMORY_PT_LEVEL_PML4             1
#define MYARK_MEMORY_PT_LEVEL_PDPT             2
#define MYARK_MEMORY_PT_LEVEL_PD               3
#define MYARK_MEMORY_PT_LEVEL_PT               4

//
// Physical region classification for QUERY_PHYSICAL_LAYOUT.
//
#define MYARK_MEMORY_REGION_LOADER_ENLISTED    0x01
#define MYARK_MEMORY_REGION_BAD                0x02
#define MYARK_MEMORY_REGION_RESERVED           0x03
#define MYARK_MEMORY_REGION_FREE               0x04
#define MYARK_MEMORY_REGION_PHYSICAL           0x05

//
// Default caps. Drivers clamp caller-supplied limits to these so a
// malformed input cannot trigger an unbounded allocation.
//
#define MYARK_MEMORY_RW_MAX_BYTES              (4 * 1024 * 1024)   // 4 MiB cap
#define MYARK_MEMORY_RW_DEFAULT_BYTES          (64 * 1024)
#define MYARK_MEMORY_SCAN_DEFAULT_MAX          256
#define MYARK_MEMORY_SCAN_HARD_CAP             8192
#define MYARK_MEMORY_PHYSICAL_DEFAULT_MAX       256
#define MYARK_MEMORY_PHYSICAL_HARD_CAP          4096

// ---------------------------------------------------------------------------
// QUERY_VM: VAD walk for one process. Output is a variable-length row
// array after a fixed header. Each row is compact (Name[] is the most
// expensive field) so a 64 KiB buffer holds ~250 rows for a typical
// process.
// ---------------------------------------------------------------------------

typedef struct _MYARK_MEMORY_VAD_ENTRY {
    UINT64  BaseAddress;
    UINT64  RegionSize;
    UINT32  Protection;
    UINT32  State;
    UINT32  Type;
    UINT32  VadType;
    WCHAR   Name[MYARK_MEMORY_VAD_NAME_MAX];
} MYARK_MEMORY_VAD_ENTRY, *PMYARK_MEMORY_VAD_ENTRY;

typedef struct _MYARK_MEMORY_QUERY_VM_INPUT {
    UINT32  Pid;
    UINT32  MaxEntries;       // 0 = driver-side default (256)
    UINT32  Flags;
    UINT32  Reserved;
} MYARK_MEMORY_QUERY_VM_INPUT, *PMYARK_MEMORY_QUERY_VM_INPUT;

typedef struct _MYARK_MEMORY_QUERY_VM_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalRegions;
    UINT32  Truncated;
    MYARK_MEMORY_VAD_ENTRY Entries[1];
} MYARK_MEMORY_QUERY_VM_OUTPUT, *PMYARK_MEMORY_QUERY_VM_OUTPUT;

// ---------------------------------------------------------------------------
// READ_VM / WRITE_VM: cross-process virtual memory copy.
//
// The data blob lives at the tail of the struct (Entries[0] is the first
// byte of payload). Caller passes Size; driver clamps to MYARK_MEMORY_RW_*
// caps.
// ---------------------------------------------------------------------------

typedef struct _MYARK_MEMORY_READ_VM_INPUT {
    UINT32  Pid;
    UINT32  Reserved;
    UINT64  Address;
    UINT64  Size;
} MYARK_MEMORY_READ_VM_INPUT, *PMYARK_MEMORY_READ_VM_INPUT;

typedef struct _MYARK_MEMORY_READ_VM_OUTPUT {
    UINT32  Status;
    UINT32  BytesRead;
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT8   Data[1];
} MYARK_MEMORY_READ_VM_OUTPUT, *PMYARK_MEMORY_READ_VM_OUTPUT;

typedef struct _MYARK_MEMORY_WRITE_VM_INPUT {
    UINT32  Pid;
    UINT32  Reserved;
    UINT64  Address;
    UINT64  Size;
    UINT8   Data[1];
} MYARK_MEMORY_WRITE_VM_INPUT, *PMYARK_MEMORY_WRITE_VM_INPUT;

typedef struct _MYARK_MEMORY_WRITE_VM_OUTPUT {
    UINT32  Status;
    UINT32  BytesWritten;
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_MEMORY_WRITE_VM_OUTPUT, *PMYARK_MEMORY_WRITE_VM_OUTPUT;

// ---------------------------------------------------------------------------
// TRANSLATE_VA: virtual -> physical translation for one VA.
//
// PageSize indicates whether the translation hit a 4K, 2M, or 1G page
// (or zero on failure). Status is the NTSTATUS that MmTranslateVirtual-
// Address-style code path produced.
// ---------------------------------------------------------------------------

typedef struct _MYARK_MEMORY_TRANSLATE_VA_INPUT {
    UINT32  Pid;
    UINT32  Reserved;
    UINT64  Va;
} MYARK_MEMORY_TRANSLATE_VA_INPUT, *PMYARK_MEMORY_TRANSLATE_VA_INPUT;

typedef struct _MYARK_MEMORY_TRANSLATE_VA_OUTPUT {
    UINT32  Status;
    UINT32  Reserved;
    UINT64  Pa;
    UINT64  PageSize;
} MYARK_MEMORY_TRANSLATE_VA_OUTPUT, *PMYARK_MEMORY_TRANSLATE_VA_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_PT_ENTRY: full 4-level page-table snapshot for one VA. Output
// holds up to four MYARK_PT_ENTRY rows: PML4E, PDPTE, PDE, PTE. Missing
// levels (LA57 / not-present) are zeroed but counted.
// ---------------------------------------------------------------------------

typedef struct _MYARK_MEMORY_PT_ENTRY {
    UINT64  Value;            // raw 8-byte PTE/PDE/PML4E
    UINT32  Level;            // 1..4
    UINT32  Large;            // 1 = large page (2MB / 1GB)
    UINT64  Pa;               // physical address implied by the entry
    UINT64  NextTablePa;      // for non-leaf: address of next-level table
} MYARK_MEMORY_PT_ENTRY, *PMYARK_MEMORY_PT_ENTRY;

typedef struct _MYARK_MEMORY_QUERY_PT_ENTRY_INPUT {
    UINT32  Pid;
    UINT32  Reserved;
    UINT64  Va;
} MYARK_MEMORY_QUERY_PT_ENTRY_INPUT, *PMYARK_MEMORY_QUERY_PT_ENTRY_INPUT;

typedef struct _MYARK_MEMORY_QUERY_PT_ENTRY_OUTPUT {
    UINT32  Status;
    UINT32  Level;            // deepest level reached
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT64  Pa;
    UINT64  PageSize;
    MYARK_MEMORY_PT_ENTRY Entries[4];
} MYARK_MEMORY_QUERY_PT_ENTRY_OUTPUT, *PMYARK_MEMORY_QUERY_PT_ENTRY_OUTPUT;

// ---------------------------------------------------------------------------
// READ_PHYSICAL / WRITE_PHYSICAL: physical memory copy. Reads use
// MmCopyMemory(MM_COPY_MEMORY_PHYSICAL); writes map the target through the
// \Device\PhysicalMemory section object (64 KiB-aligned view). Neither path
// requires the target PA to be page-aligned.
// ---------------------------------------------------------------------------

typedef struct _MYARK_MEMORY_READ_PHYSICAL_INPUT {
    UINT64  Pa;
    UINT64  Size;
} MYARK_MEMORY_READ_PHYSICAL_INPUT, *PMYARK_MEMORY_READ_PHYSICAL_INPUT;

typedef struct _MYARK_MEMORY_READ_PHYSICAL_OUTPUT {
    UINT32  Status;
    UINT32  BytesRead;
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT8   Data[1];
} MYARK_MEMORY_READ_PHYSICAL_OUTPUT, *PMYARK_MEMORY_READ_PHYSICAL_OUTPUT;

typedef struct _MYARK_MEMORY_WRITE_PHYSICAL_INPUT {
    UINT64  Pa;
    UINT64  Size;
    UINT8   Data[1];
} MYARK_MEMORY_WRITE_PHYSICAL_INPUT, *PMYARK_MEMORY_WRITE_PHYSICAL_INPUT;

typedef struct _MYARK_MEMORY_WRITE_PHYSICAL_OUTPUT {
    UINT32  Status;
    UINT32  BytesWritten;
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_MEMORY_WRITE_PHYSICAL_OUTPUT, *PMYARK_MEMORY_WRITE_PHYSICAL_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_PHYSICAL_LAYOUT: enumerate physical memory regions via
// MmGetPhysicalMemoryRanges. Output is a variable-length row array.
// ---------------------------------------------------------------------------

typedef struct _MYARK_MEMORY_PHYSICAL_REGION {
    UINT64  BasePa;
    UINT64  Size;
    UINT32  Type;
    UINT32  Reserved;
} MYARK_MEMORY_PHYSICAL_REGION, *PMYARK_MEMORY_PHYSICAL_REGION;

typedef struct _MYARK_MEMORY_PHYSICAL_LAYOUT_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT64  TotalPhysical;
    UINT64  Reserved;
    MYARK_MEMORY_PHYSICAL_REGION Entries[1];
} MYARK_MEMORY_PHYSICAL_LAYOUT_OUTPUT, *PMYARK_MEMORY_PHYSICAL_LAYOUT_OUTPUT;

// ---------------------------------------------------------------------------
// SCAN_KERNEL_EXECUTABLE: byte-signature search across a kernel VA range.
// Caller-supplied signature is up to 16 bytes; output lists up to
// MaxResults (clamped) hits with the surrounding bytes captured for
// disassembly-style rendering.
// ---------------------------------------------------------------------------

typedef struct _MYARK_MEMORY_SCAN_KERNEL_INPUT {
    UINT8   Signature[MYARK_MEMORY_SCAN_SIGNATURE_MAX];
    UINT32  SignatureLength;
    UINT64  RangeStart;
    UINT64  RangeEnd;
    UINT32  MaxResults;
    UINT32  Flags;
} MYARK_MEMORY_SCAN_KERNEL_INPUT, *PMYARK_MEMORY_SCAN_KERNEL_INPUT;

typedef struct _MYARK_MEMORY_SCAN_KERNEL_ENTRY {
    UINT64  Address;
    UINT8   SignatureBytes[MYARK_MEMORY_SCAN_SIGNATURE_MAX];
} MYARK_MEMORY_SCAN_KERNEL_ENTRY, *PMYARK_MEMORY_SCAN_KERNEL_ENTRY;

typedef struct _MYARK_MEMORY_SCAN_KERNEL_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  Truncated;
    UINT32  Reserved;
    MYARK_MEMORY_SCAN_KERNEL_ENTRY Entries[1];
} MYARK_MEMORY_SCAN_KERNEL_OUTPUT, *PMYARK_MEMORY_SCAN_KERNEL_OUTPUT;

// ---------------------------------------------------------------------------
// SCAN_KERNEL_MEMORY_EVIDENCE: PUNICODE_STRING-style evidence search.
// Walks the kernel VA range one 16-byte window at a time and reports
// any window whose first chars match the supplied case-insensitive wide
// signature. Output uses a separate entry struct (MatchedChars only --
// caller already knows the signature it sent).
// ---------------------------------------------------------------------------

typedef struct _MYARK_MEMORY_SCAN_EVIDENCE_INPUT {
    UINT32  MaxResults;
    UINT32  Flags;
    UINT64  RangeStart;
    UINT64  RangeEnd;
    WCHAR   Signature[MYARK_MEMORY_SCAN_UNICODE_MAX];
} MYARK_MEMORY_SCAN_EVIDENCE_INPUT, *PMYARK_MEMORY_SCAN_EVIDENCE_INPUT;

typedef struct _MYARK_MEMORY_SCAN_EVIDENCE_ENTRY {
    UINT64  Address;
    UINT32  MatchedChars;
    UINT32  Reserved;
} MYARK_MEMORY_SCAN_EVIDENCE_ENTRY, *PMYARK_MEMORY_SCAN_EVIDENCE_ENTRY;

typedef struct _MYARK_MEMORY_SCAN_EVIDENCE_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  Truncated;
    UINT32  Reserved;
    MYARK_MEMORY_SCAN_EVIDENCE_ENTRY Entries[1];
} MYARK_MEMORY_SCAN_EVIDENCE_OUTPUT, *PMYARK_MEMORY_SCAN_EVIDENCE_OUTPUT;