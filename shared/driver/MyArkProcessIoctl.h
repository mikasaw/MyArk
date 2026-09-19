// MyArk process module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xA00..0xAFF reserved for the process module. Core uses
// 0x800..0x8FF, hello 0x900..0x9FF, so process sits in the next free block.
// All 13 IOCTLs follow the MyArk METHOD_BUFFERED convention (matching the
// core / hello modules).
//
// Cross-view semantics (S6.1 acceptance criteria):
//   public       = NtQuerySystemInformation(SystemProcessInformation)
//   pspecidtable = kernel handle table (PsLookupProcessByProcessId derives from it)
//   active_links = EPROCESS.ActiveProcessLinks traversal
// A process that is in ActiveProcessLinks + PspCidTable but NOT in the public
// view is flagged HIDDEN_VIA_DKOM; DKOM hide preserves the PspCidTable
// record so it remains auditable.
//
// EPROCESS field offsets are hardcoded for Windows 11 24H2 / build 26100.x;
// S7.1 (DynData) will replace them with a runtime-loaded profile. Offsets
// are documented in process_detail.c.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "MyArkSafetyToken.h"

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_PROCESS_MODULE_ID              0x50524F43UL  // 'PROC' ASCII (LE)
#define MYARK_PROCESS_NAME_MAX               64
#define MYARK_PROCESS_PATH_MAX               260
#define MYARK_PROCESS_USER_MAX               64
#define MYARK_PROCESS_IMAGE_FILE_NAME_MAX    16           // EPROCESS.ImageFileName[15] + NUL
#define MYARK_PROCESS_DETAIL_MAX             4096         // cap detail string

//
// Operation codes carried in MYARK_SAFETY_TOKEN.Operation for the process
// module's mutating IOCTLs. Each dispatch validates a caller-supplied
// token bound to (Pid, Operation) exactly like the 87_actions surface.
//
#define MYARK_PROCESS_OP_TERMINATE           0x101
#define MYARK_PROCESS_OP_SUSPEND_RESUME      0x102
#define MYARK_PROCESS_OP_SET_PPL_LEVEL       0x103
#define MYARK_PROCESS_OP_SET_INTEGRITY       0x104
#define MYARK_PROCESS_OP_SET_VISIBILITY      0x105
#define MYARK_PROCESS_OP_SET_SPECIAL_FLAGS   0x106
#define MYARK_PROCESS_OP_DKOM                0x107
#define MYARK_PROCESS_OP_INJECT              0x108

//
// 13 IOCTLs (function range 0xA00..0xA0C). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_PROCESS_ENUM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA00, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_ENUM_THREAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_DETAIL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_DETAIL_RUNTIME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA03, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_CROSSVIEW \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA04, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_TERMINATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA05, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_SUSPEND \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA06, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_SET_PPL_LEVEL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA07, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_SET_INTEGRITY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA08, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_SET_VISIBILITY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA09, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_SET_SPECIAL_FLAGS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0A, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_DKOM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0B, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_PROCESS_INJECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0C, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Source mask used by crossview / enum / detail to mark which views saw the
// row. Bits align with the three-view model.
// ---------------------------------------------------------------------------

#define MYARK_PROCESS_SRC_NONE              0x00
#define MYARK_PROCESS_SRC_PUBLIC            0x01   // ZwQuerySystemInformation
#define MYARK_PROCESS_SRC_PSPCIDTABLE       0x02   // kernel handle table lookup
#define MYARK_PROCESS_SRC_ACTIVE_LINKS      0x04   // ActiveProcessLinks traversal

#define MYARK_PROCESS_HIDDEN_NONE           0x00
#define MYARK_PROCESS_HIDDEN_VIA_DKOM       0x01   // in kernel + active_links, not public

// ---------------------------------------------------------------------------
// Common enum entry shared by ENUM_PROCESS and CROSSVIEW.
//
// Compact record so a 64 KB buffer fits ~400 processes. The detailed record
// below (DETAIL / DETAIL_RUNTIME) carries the wide fields; the enum row is
// what the table renders.
// ---------------------------------------------------------------------------

typedef struct _MYARK_PROCESS_ENTRY {
    UINT32  Pid;
    UINT32  Ppid;
    WCHAR   Name[MYARK_PROCESS_NAME_MAX];      // base name only ("svchost.exe")
    WCHAR   Path[MYARK_PROCESS_PATH_MAX];      // device path (\Device\HarddiskVolumeX\...)
    WCHAR   User[MYARK_PROCESS_USER_MAX];      // NT AUTHORITY\SYSTEM etc., or <unknown>
    UINT32  MemKb;                             // private working set in KB
    UINT8   Ppl;                               // ProtectionLevel (raw byte)
    UINT8   Hidden;                            // MYARK_PROCESS_HIDDEN_* mask
    UINT8   SourceMask;                        // which of the 3 views saw this PID
    UINT8   Reserved;
} MYARK_PROCESS_ENTRY, *PMYARK_PROCESS_ENTRY;

typedef struct _MYARK_PROCESS_ENUM_INPUT {
    UINT32  MaxEntries;                        // 0 = use driver-side cap (default 256)
    UINT32  SourceMask;                        // OR of MYARK_PROCESS_SRC_* the caller wants
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_PROCESS_ENUM_INPUT, *PMYARK_PROCESS_ENUM_INPUT;

typedef struct _MYARK_PROCESS_ENUM_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;                         // total unique PIDs across all requested views
    UINT32  HiddenCount;                       // count of rows flagged HIDDEN_VIA_DKOM
    MYARK_PROCESS_ENTRY Entries[1];            // variable length
} MYARK_PROCESS_ENUM_OUTPUT, *PMYARK_PROCESS_ENUM_OUTPUT;

// ---------------------------------------------------------------------------
// ENUM_THREAD: list threads for one process.
//
// Caller passes a Pid; the driver walks EPROCESS.ThreadListHead and returns
// every ETHREAD.UniqueThread + the minimal state snapshot.
// ---------------------------------------------------------------------------

typedef struct _MYARK_THREAD_ENTRY {
    UINT32  Tid;
    UINT32  OwnerPid;
    UINT32  State;                             // KTHREAD_STATE (Running/Ready/Waiting/...)
    UINT32  Priority;
    UINT32  WaitReason;                        // KWAIT_REASON (only meaningful when Waiting)
    UINT64  CreateTime;                       // KeQuerySystemTime timestamp at thread create
} MYARK_THREAD_ENTRY, *PMYARK_THREAD_ENTRY;

typedef struct _MYARK_PROCESS_ENUM_THREAD_INPUT {
    UINT32  Pid;
    UINT32  MaxEntries;
} MYARK_PROCESS_ENUM_THREAD_INPUT, *PMYARK_PROCESS_ENUM_THREAD_INPUT;

typedef struct _MYARK_PROCESS_ENUM_THREAD_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  OwnerPid;                          // echoes the input Pid
    UINT32  Reserved;
    MYARK_THREAD_ENTRY Entries[1];
} MYARK_PROCESS_ENUM_THREAD_OUTPUT, *PMYARK_PROCESS_ENUM_THREAD_OUTPUT;

// ---------------------------------------------------------------------------
// DETAIL: one process, deep field dump.
//
// EPROCESS offsets hardcoded for Win11 24H2 (build 26100.x) -- see
// process_detail.c for the canonical offsets. Buffer must be at least
// sizeof(MYARK_PROCESS_DETAIL) bytes; the trailing Fields[] blob captures
// any future additions without breaking the wire format.
// ---------------------------------------------------------------------------

typedef struct _MYARK_PROCESS_DETAIL {
    UINT32  Pid;
    UINT32  Ppid;
    UINT32  Flags2;                            // EPROCESS.Flags2 (Debug/Protected/etc.)
    UINT32  Ppl;                               // PS_PROTECTION.Level (raw byte)
    UINT32  SignatureLevel;
    UINT32  SectionSignatureLevel;
    UINT32  Protection;                        // PS_PROTECTION.Flags
    UINT32  ExitStatus;                        // Peb-based reported exit status (0 if alive)
    UINT64  CreateTime;                        // EPROCESS.CreateTime
    UINT64  KernelTime;                        // KUSER_SHARED_DATA-equivalent ticks
    UINT64  UserTime;
    UINT32  HandleCount;                       // from Ob reference trace (best-effort)
    UINT32  ThreadCount;                       // EPROCESS.ActiveThreads
    UINT32  BasePriority;
    UINT32  AffinityMask;
    UINT32  UniqueProcessIdOffset;                // offset that produced Pid (debug aid)
    UINT32  ImageFileNameOffset;
    UINT32  ActiveProcessLinksOffset;
    UINT32  InheritedFromUniqueProcessIdOffset;
    UINT32  PebOffset;
    UINT32  ThreadListHeadOffset;
    UINT64  EProcessKernelAddress;                       // kernel virtual address of EPROCESS
    WCHAR   Name[MYARK_PROCESS_NAME_MAX];
    WCHAR   Path[MYARK_PROCESS_PATH_MAX];
    WCHAR   User[MYARK_PROCESS_USER_MAX];
    CHAR    ImageFileName[MYARK_PROCESS_IMAGE_FILE_NAME_MAX];
} MYARK_PROCESS_DETAIL, *PMYARK_PROCESS_DETAIL;

// ---------------------------------------------------------------------------
// DETAIL_RUNTIME: extra runtime stats that cost more to compute.
//
// Returned as a single struct. Drivers fill what they can; the rest stays 0.
// ---------------------------------------------------------------------------

typedef struct _MYARK_PROCESS_DETAIL_RUNTIME {
    UINT32  Pid;
    UINT32  Reserved0;
    UINT64  PeakWorkingSetSize;
    UINT64  WorkingSetSize;
    UINT64  QuotaPeakPagedPoolUsage;
    UINT64  QuotaPagedPoolUsage;
    UINT64  QuotaPeakNonPagedPoolUsage;
    UINT64  QuotaNonPagedPoolUsage;
    UINT64  PagefileUsage;
    UINT64  PeakPagefileUsage;
    UINT32  PrivatePageCount;
    UINT32  Reserved1;
    UINT64  CycleTime;                         // CPU cycles consumed
} MYARK_PROCESS_DETAIL_RUNTIME, *PMYARK_PROCESS_DETAIL_RUNTIME;

// ---------------------------------------------------------------------------
// CROSSVIEW: same row as enum but SourceMask tells which of the 3 views saw
// the PID. Output format identical to ENUM so the R3 parser can reuse code.
// ---------------------------------------------------------------------------

typedef struct _MYARK_PROCESS_CROSSVIEW_INPUT {
    UINT32  Pid;                               // 0 = every PID; non-zero = filter to that PID
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_PROCESS_CROSSVIEW_INPUT, *PMYARK_PROCESS_CROSSVIEW_INPUT;

typedef struct _MYARK_PROCESS_CROSSVIEW_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  PublicOnly;                        // PIDs in public view but not in kernel
    UINT32  HiddenCount;                       // PIDs flagged HIDDEN_VIA_DKOM
    MYARK_PROCESS_ENTRY Entries[1];
} MYARK_PROCESS_CROSSVIEW_OUTPUT, *PMYARK_PROCESS_CROSSVIEW_OUTPUT;

// ---------------------------------------------------------------------------
// Mutating IOCTLs (TERMINATE / SUSPEND / SET_PPL_LEVEL / SET_INTEGRITY /
// SET_VISIBILITY / SET_SPECIAL_FLAGS / DKOM / INJECT).
//
// Each takes a small Input struct and returns a status struct. The driver
// performs the requested operation; status reflects whether R3 fallback (when
// available) succeeded. S8.1 actions module adds R3-first / R0-fallback
// chaining; S6.1 driver covers the R0 side only and the dedicated DKOM IOCTL
// exposes hide/unhide + audit directly.
// ---------------------------------------------------------------------------

typedef struct _MYARK_PROCESS_TERMINATE_INPUT {
    MYARK_SAFETY_TOKEN  Token;                         // HMAC-signed, see MyArkSafetyToken.h
    UINT32  Pid;
    UINT32  ExitCode;
    UINT32  Force;                             // non-zero = skip graceful path
    UINT32  Reserved;
} MYARK_PROCESS_TERMINATE_INPUT, *PMYARK_PROCESS_TERMINATE_INPUT;

typedef struct _MYARK_PROCESS_TERMINATE_OUTPUT {
    UINT32  Pid;
    UINT32  Status;                            // NTSTATUS
    UINT32  UsedR0Fallback;
    UINT32  Reserved;
} MYARK_PROCESS_TERMINATE_OUTPUT, *PMYARK_PROCESS_TERMINATE_OUTPUT;

typedef struct _MYARK_PROCESS_SUSPEND_INPUT {
    MYARK_SAFETY_TOKEN  Token;                         // HMAC-signed, see MyArkSafetyToken.h
    UINT32  Pid;
    UINT32  Resume;                            // 0 = suspend, non-zero = resume
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_PROCESS_SUSPEND_INPUT, *PMYARK_PROCESS_SUSPEND_INPUT;

typedef struct _MYARK_PROCESS_SUSPEND_OUTPUT {
    UINT32  Pid;
    UINT32  Suspended;                         // 1 = suspended, 0 = resumed
    UINT32  Status;
    UINT32  Reserved;
} MYARK_PROCESS_SUSPEND_OUTPUT, *PMYARK_PROCESS_SUSPEND_OUTPUT;

typedef struct _MYARK_PROCESS_SET_PPL_INPUT {
    MYARK_SAFETY_TOKEN  Token;                         // HMAC-signed, see MyArkSafetyToken.h
    UINT32  Pid;
    UINT8   Level;                             // PS_PROTECTION.Level byte
    UINT8   Audit;                             // PS_PROTECTION.Audit bit
    UINT8   Type;                              // PS_PROTECTION.Type field
    UINT8   Reserved;
    UINT32  Reserved0;
} MYARK_PROCESS_SET_PPL_INPUT, *PMYARK_PROCESS_SET_PPL_INPUT;

typedef struct _MYARK_PROCESS_SET_PPL_OUTPUT {
    UINT32  Pid;
    UINT32  Status;
    UINT32  PreviousLevel;
    UINT32  Reserved;
} MYARK_PROCESS_SET_PPL_OUTPUT, *PMYARK_PROCESS_SET_PPL_OUTPUT;

typedef struct _MYARK_PROCESS_SET_INTEGRITY_INPUT {
    MYARK_SAFETY_TOKEN  Token;                         // HMAC-signed, see MyArkSafetyToken.h
    UINT32  Pid;
    UINT32  IntegrityLevel;                    // SECURITY_MANDATORY_*_RID
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_PROCESS_SET_INTEGRITY_INPUT, *PMYARK_PROCESS_SET_INTEGRITY_INPUT;

typedef struct _MYARK_PROCESS_SET_INTEGRITY_OUTPUT {
    UINT32  Pid;
    UINT32  Status;
    UINT32  PreviousIntegrity;
    UINT32  Reserved;
} MYARK_PROCESS_SET_INTEGRITY_OUTPUT, *PMYARK_PROCESS_SET_INTEGRITY_OUTPUT;

typedef struct _MYARK_PROCESS_SET_VISIBILITY_INPUT {
    MYARK_SAFETY_TOKEN  Token;                         // HMAC-signed, see MyArkSafetyToken.h
    UINT32  Pid;
    UINT32  Hide;                              // 0 = restore, non-zero = hide (DKOM)
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_PROCESS_SET_VISIBILITY_INPUT, *PMYARK_PROCESS_SET_VISIBILITY_INPUT;

typedef struct _MYARK_PROCESS_SET_VISIBILITY_OUTPUT {
    UINT32  Pid;
    UINT32  Status;
    UINT32  Hidden;                            // resulting visibility state
    UINT32  Reserved;
} MYARK_PROCESS_SET_VISIBILITY_OUTPUT, *PMYARK_PROCESS_SET_VISIBILITY_OUTPUT;

typedef struct _MYARK_PROCESS_SET_SPECIAL_FLAGS_INPUT {
    MYARK_SAFETY_TOKEN  Token;                         // HMAC-signed, see MyArkSafetyToken.h
    UINT32  Pid;
    UINT32  FlagsMask;                         // EPROCESS.Flags2 bits to modify
    UINT32  FlagsValue;                        // bits to set/clear under the mask
    UINT32  Reserved;
} MYARK_PROCESS_SET_SPECIAL_FLAGS_INPUT, *PMYARK_PROCESS_SET_SPECIAL_FLAGS_INPUT;

typedef struct _MYARK_PROCESS_SET_SPECIAL_FLAGS_OUTPUT {
    UINT32  Pid;
    UINT32  Status;
    UINT32  PreviousFlags;
    UINT32  Reserved;
} MYARK_PROCESS_SET_SPECIAL_FLAGS_OUTPUT, *PMYARK_PROCESS_SET_SPECIAL_FLAGS_OUTPUT;

typedef struct _MYARK_PROCESS_DKOM_INPUT {
    MYARK_SAFETY_TOKEN  Token;                         // HMAC-signed, see MyArkSafetyToken.h
    UINT32  Pid;
    UINT32  Action;                            // 0 = restore, 1 = hide
    UINT32  Flags;                             // bit 0 = preserve PspCidTable record (always 1)
    UINT32  Reserved;
} MYARK_PROCESS_DKOM_INPUT, *PMYARK_PROCESS_DKOM_INPUT;

typedef struct _MYARK_PROCESS_DKOM_OUTPUT {
    UINT32  Pid;
    UINT32  Status;
    UINT32  Hidden;
    UINT32  Reserved;
} MYARK_PROCESS_DKOM_OUTPUT, *PMYARK_PROCESS_DKOM_OUTPUT;

typedef struct _MYARK_PROCESS_INJECT_INPUT {
    MYARK_SAFETY_TOKEN  Token;                         // HMAC-signed, see MyArkSafetyToken.h
    UINT32  Pid;
    UINT32  Method;                            // 0 = APC user, 1 = APC kernel
    UINT32  Reserved0;
    UINT32  Reserved1;
    WCHAR   DllPath[MYARK_PROCESS_PATH_MAX];   // target DLL path
} MYARK_PROCESS_INJECT_INPUT, *PMYARK_PROCESS_INJECT_INPUT;

typedef struct _MYARK_PROCESS_INJECT_OUTPUT {
    UINT32  Pid;
    UINT32  Status;
    UINT32  UsedR0Fallback;
    UINT32  Reserved;
} MYARK_PROCESS_INJECT_OUTPUT, *PMYARK_PROCESS_INJECT_OUTPUT;

//
// ---------------------------------------------------------------------------
// R3-4 (0xA0D): PspCidTable full-table walk + three-source hidden-process
// report, read-only. The walk enumerates every process/thread object the
// kernel's CID handle table knows about -- including processes hidden from
// EPROCESS.ActiveProcessLinks by DKOM -- and joins each process entry
// against the ActiveProcessLinks membership set to flag HIDDEN rows.
//
// Tier C build profile (KDNET-verified 2026-09-17):
//   18362/18363: PspCidTable = nt + 0x574530, ImageFileName = 0x450
//   22621/22631: PspCidTable = nt + 0xD1EC30, ImageFileName = 0x5A8
// Entry decode (both builds): stride 16, index = Cid / 4,
//   object = (entry >> 16) | 0xFFFF000000000000 (packed EPROCESS/ETHREAD).
// Process/thread split via exported ObGetObjectType (resolves through the
//   header's ObjectType pointer, no per-build type constants needed).
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_PROCESS_QUERY_CIDTABLE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0D, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_CID_NAME_MAX                   16
#define MYARK_CID_STATUS_OK                  0x00000000UL
#define MYARK_CID_STATUS_NO_PROFILE          0x00000001UL  // build w/o profile
#define MYARK_CID_STATUS_NO_ACTIVE_WALK      0x00000002UL  // offsets unresolved

#define MYARK_CID_FLAG_PROCESS               0x00000001UL
#define MYARK_CID_FLAG_THREAD                0x00000002UL
#define MYARK_CID_FLAG_HIDDEN                0x00000004UL  // not in ActiveProcessLinks
#define MYARK_CID_FLAG_TRUNCATED             0x00000008UL  // set on last row: table cut

typedef struct _MYARK_CID_ENTRY {
    UINT32  Cid;
    UINT32  Flags;                                 // MYARK_CID_FLAG_*
    UINT64  Object;                                // EPROCESS / ETHREAD
    CHAR    Name[MYARK_CID_NAME_MAX];              // ImageFileName (process rows)
} MYARK_CID_ENTRY, *PMYARK_CID_ENTRY;

typedef struct _MYARK_CID_QUERY_OUTPUT {
    UINT32  Count;                                 // process rows in Entries[]
    UINT32  Status;                                // MYARK_CID_STATUS_*
    UINT32  ThreadTotal;                           // threads seen in the table
    UINT32  EntryStructSize;
    MYARK_CID_ENTRY Entries[1];                    // variable-length tail
} MYARK_CID_QUERY_OUTPUT, *PMYARK_CID_QUERY_OUTPUT;

C_ASSERT(sizeof(MYARK_CID_ENTRY) == 32);
C_ASSERT(sizeof(MYARK_CID_QUERY_OUTPUT) == 48);