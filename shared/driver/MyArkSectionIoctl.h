// MyArk section module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xC10..0xC1F reserved for the section module. Process
// uses 0xA00..0xAFF, memory 0xB00..0xBFF, handle 0xC00..0xC0F, so section
// sits in the next free block. All 2 IOCTLs follow the MyArk METHOD_BUFFERED
// convention.
//
// Section module enumerates the global MmControlAreaListHead to surface
// every mapped section in the system. QUERY_PROCESS maps a Pid to the
// sections that process owns (via EPROCESS->SectionObject, when available);
// QUERY_FILE_MAPPINGS lists every ControlArea and its FileObject back-pointer
// so R3 can join the section view with the file view.
//
// Cross-process mapping detection: when a section was mapped into a process
// other than the one that created it, the row is flagged
// MYARK_SECTION_FLAG_REMOTE so R3 can flag it REMOTE_MAPPING_UNSUPPORTED.
// The driver does NOT attempt to enumerate per-process VAD mappings (that
// is a memory-module responsibility) -- only the global ControlArea view.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_SECTION_MODULE_ID             0x4E544353UL  // 'SCTN' ASCII (LE)
#define MYARK_SECTION_NAME_MAX               260
#define MYARK_SECTION_DEFAULT_MAX            256
#define MYARK_SECTION_HARD_CAP               8192

//
// 2 IOCTLs (function range 0xC10..0xC11). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_SECTION_QUERY_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC10, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_SECTION_QUERY_FILE_MAPPINGS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC11, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// QUERY_PROCESS input / output.
//
// Returns the list of ControlAreas a given Pid has touched. The driver
// walks MmControlAreaListHead and inspects the SharedCacheMap / ImageRelocs
// (best-effort) -- Pid attribution for data-only sections is heuristic and
// may report false positives. R3 should treat the result as advisory.
// ---------------------------------------------------------------------------

#define MYARK_SECTION_FLAG_NONE             0x00000000
#define MYARK_SECTION_FLAG_IMAGE            0x00000001   // executable mapping
#define MYARK_SECTION_FLAG_MAPPED_FILE      0x00000002   // data file mapping (CreateFileMapping)
#define MYARK_SECTION_FLAG_PAGEFILE         0x00000004   // backed by paging file only
#define MYARK_SECTION_FLAG_REMOTE           0x00000008   // created in another process (unsupported for follow-up queries)
#define MYARK_SECTION_FLAG_PROTECTED        0x00000010   // protected-process audit hint

typedef struct _MYARK_SECTION_ENTRY {
    UINT64  ControlAreaAddress;                             // kernel VA of the ControlArea
    UINT64  FileObjectAddress;                              // kernel VA of the FileObject (0 for pagefile-backed)
    UINT64  BaseAddress;                                    // first mapped VA in the host process
    UINT64  SizeInBytes;
    UINT32  Pid;                                            // owning process (heuristic for shared sections)
    UINT32  Flags;                                          // MYARK_SECTION_FLAG_* bitmask
    UINT32  Protection;                                     // Win32 protection mask (PAGE_*)
    UINT32  Reserved0;
    WCHAR   Name[MYARK_SECTION_NAME_MAX];                   // file device path or <pagefile>
} MYARK_SECTION_ENTRY, *PMYARK_SECTION_ENTRY;

typedef struct _MYARK_SECTION_QUERY_PROCESS_INPUT {
    UINT32  Pid;                                            // 0 = current process
    UINT32  MaxEntries;                                     // 0 = driver default
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_SECTION_QUERY_PROCESS_INPUT, *PMYARK_SECTION_QUERY_PROCESS_INPUT;

typedef struct _MYARK_SECTION_QUERY_PROCESS_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  RemoteUnsupportedCount;                         // entries flagged MYARK_SECTION_FLAG_REMOTE
    MYARK_SECTION_ENTRY Entries[1];
} MYARK_SECTION_QUERY_PROCESS_OUTPUT, *PMYARK_SECTION_QUERY_PROCESS_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_FILE_MAPPINGS output.
//
// One row per ControlArea on the global MmControlAreaListHead. R3 joins
// this list with the file view (via FileObject->FileName) and renders it
// as a "who has this file mapped" view.
// ---------------------------------------------------------------------------

typedef struct _MYARK_FILE_MAPPING_ENTRY {
    UINT64  ControlAreaAddress;
    UINT64  FileObjectAddress;
    UINT64  SizeInBytes;
    UINT32  ReferenceCount;                                 // ControlArea.NumberOfSectionReferences + NumberOfUserReferences (best-effort)
    UINT32  Flags;                                          // MYARK_SECTION_FLAG_* bitmask
    UINT32  ShareCount;                                     // SectionObjectPointer.SharedCacheMap users (0 if unknown)
    UINT32  Reserved0;
    WCHAR   FilePath[MYARK_SECTION_NAME_MAX];
} MYARK_FILE_MAPPING_ENTRY, *PMYARK_FILE_MAPPING_ENTRY;

typedef struct _MYARK_SECTION_QUERY_FILE_MAPPINGS_INPUT {
    UINT32  MaxEntries;                                     // 0 = driver default
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_SECTION_QUERY_FILE_MAPPINGS_INPUT, *PMYARK_SECTION_QUERY_FILE_MAPPINGS_INPUT;

typedef struct _MYARK_SECTION_QUERY_FILE_MAPPINGS_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved;
    MYARK_FILE_MAPPING_ENTRY Entries[1];
} MYARK_SECTION_QUERY_FILE_MAPPINGS_OUTPUT, *PMYARK_SECTION_QUERY_FILE_MAPPINGS_OUTPUT;
