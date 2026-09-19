// MyArk HWID module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x750..0x751 reserved for the HWID (hardware ID
// spoof / MajorFunction inspection) module (S7.3). HWID is read-only
// for S7.3: the IOCTL set inspects MajorFunction tables on the running
// build. The replace IOCTLs are reserved for the S7.3-fix stage and
// return STATUS_NOT_IMPLEMENTED on dispatch.
//
// The 2 IOCTLs:
//
//   0x750  ENUMERATE_MJ      - Walk driver MajorFunction tables
//   0x751  REPLACE_MJ        - Replace one slot (reserved; S7.3-fix)
//
// All 2 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_HWID_MODULE_ID                  0x48574944UL  // 'HWID' ASCII (LE)
#define MYARK_HWID_NAME_MAX                   64
#define MYARK_HWID_HARD_CAP                   64

//
// 2 IOCTLs (function range 0x750..0x751). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_HWID_ENUMERATE_MJ \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x750, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_HWID_REPLACE_MJ \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x751, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// ENUMERATE_MJ input: optional filter (0 = all drivers).
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_HWID_ENUMERATE_MJ_INPUT {
    UINT32  DriverIndexHint;                      // 0 = from beginning
    UINT32  Reserved;
    UINT64  Reserved2;
} MYARK_HWID_ENUMERATE_MJ_INPUT, *PMYARK_HWID_ENUMERATE_MJ_INPUT;

//
// ENUMERATE_MJ output: each driver + its current 28 MajorFunction entries.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_HWID_MJ_ENTRY {
    WCHAR   DriverName[MYARK_HWID_NAME_MAX];
    UINT64  MajorFunction[28];                    // IRP_MJ_*
} MYARK_HWID_MJ_ENTRY, *PMYARK_HWID_MJ_ENTRY;

typedef struct _MYARK_HWID_ENUMERATE_MJ_OUTPUT {
    UINT32  Count;
    UINT32  Reserved;
    MYARK_HWID_MJ_ENTRY Entries[1];
} MYARK_HWID_ENUMERATE_MJ_OUTPUT, *PMYARK_HWID_ENUMERATE_MJ_OUTPUT;

//
// REPLACE_MJ input (reserved; S7.3-fix).
// ---------------------------------------------------------------------------
typedef struct _MYARK_HWID_REPLACE_MJ_INPUT {
    WCHAR   DriverName[MYARK_HWID_NAME_MAX];
    UINT32  MajorFunctionCode;                    // IRP_MJ_*
    UINT64  NewAddress;
} MYARK_HWID_REPLACE_MJ_INPUT, *PMYARK_HWID_REPLACE_MJ_INPUT;

// ---------------------------------------------------------------------------
// R3-1 (T-B): HWID spoof subdivision.
//
// 0x752 QUERY_SPOOF_STATUS - per-class spoof state snapshot (read-only,
//                            no token).
// 0x753 SET_SPOOF_CONFIG   - per-class DRY_RUN / APPLY / RESTORE. Always
//                            SAFETY_TOKEN gated (op MYARK_HWID_OP_SPOOF_CONFIG).
//
// Mechanism: APPLY attaches completion routines on the target device
// stacks (disk serial + mountmgr UniqueId + VPD 0x83 identifiers on
// \Device\HarddiskN\Partition0, partition GUID on
// \Device\HarddiskN\Partition0..32, GPU serial via a CmCallback value
// rewrite under the display class key) that rewrite the query response
// buffers in flight. The original values are probed from below the
// attachment point into a kernel-side cache at APPLY time; RESTORE
// detaches and re-probes to prove the hardware values came back.
//
// R3-1b additions:
//   class 5 (ARP): nsiproxy (\Device\Nsi) completion rewrite of the
//           neighbor-table enumerate responses. RESTORE semantics differ
//           by design: the real kernel neighbor table is never modified
//           (only in-flight responses), so the driver just detaches and
//           the caller re-queries to prove the original MAC is back.
//   class 6 (DEVICE_ID): STORAGE_DEVICE_ID_DESCRIPTOR (SCSI VPD page
//           0x83) identifier rewrite on the same disk stack.
//   action 3 (CAPTURE, class ARP only): arm/disarm a passive NSI request
//           capture ring; 0x754 reads the tuples + last enumerate dump.
//           Bring-up tool for pinning per-build NSI layouts (Tier C).
// ---------------------------------------------------------------------------

#include "MyArkSafetyToken.h"

#define IOCTL_MYARK_HWID_QUERY_SPOOF_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x752, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_HWID_SET_SPOOF_CONFIG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x753, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// R3-1b (0x754): passive NSI capture readback (class-ARP bring-up tool).
// Token gated with the same operation id as 0x753; read-only.
//
#define IOCTL_MYARK_HWID_QUERY_SPOOF_CAPTURE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x754, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// SAFETY_TOKEN.Operation for 0x753.
//
#define MYARK_HWID_OP_SPOOF_CONFIG            0x31505357UL  // 'WSP1' ASCII (LE)

//
// Spoof classes (MYARK_HWID_SPOOF_SET_INPUT.Class).
//
#define MYARK_HWID_SPOOF_CLASS_DISK_SERIAL    1   // StorageDeviceProperty serial
#define MYARK_HWID_SPOOF_CLASS_PARTITION_GUID 2   // GPT PartitionId (+layout)
#define MYARK_HWID_SPOOF_CLASS_MOUNTMGR_UID   3   // StorageDeviceUniqueIdProperty
#define MYARK_HWID_SPOOF_CLASS_GPU_SERIAL     4   // display-class registry rewrite
#define MYARK_HWID_SPOOF_CLASS_ARP            5   // nsiproxy neighbor-table rewrite
#define MYARK_HWID_SPOOF_CLASS_DEVICE_ID      6   // VPD 0x83 identifiers (R3-1b)
#define MYARK_HWID_SPOOF_CLASS_COUNT          6

//
// 0x753 Action codes.
//
#define MYARK_HWID_SPOOF_ACTION_DRY_RUN       0   // probe + preview only
#define MYARK_HWID_SPOOF_ACTION_APPLY         1   // attach + rewrite
#define MYARK_HWID_SPOOF_ACTION_RESTORE       2   // detach + verify original
#define MYARK_HWID_SPOOF_ACTION_CAPTURE       3   // ARP only: arm/stop NSI capture

//
// 0x753 input Flags.
//
#define MYARK_HWID_SPOOF_FLAG_UI_CONFIRMED    0x00000001UL
#define MYARK_HWID_SPOOF_FLAG_FORCE           0x00000002UL
#define MYARK_HWID_SPOOF_FLAG_CAPTURE_START   0x00000004UL  // CAPTURE action only

//
// Per-class status bits (MYARK_HWID_SPOOF_CLASS_STATUS.Flags).
//
#define MYARK_HWID_SPOOF_ST_ACTIVE            0x00000001UL
#define MYARK_HWID_SPOOF_ST_SPOOF_SET         0x00000002UL
#define MYARK_HWID_SPOOF_ST_CACHE_VALID       0x00000004UL
#define MYARK_HWID_SPOOF_ST_ATTACHED          0x00000008UL
#define MYARK_HWID_SPOOF_ST_UNSUPPORTED       0x00000010UL

//
// Spoof value payload cap. ASCII for the string classes; for
// MYARK_HWID_SPOOF_CLASS_PARTITION_GUID ValueSize must be exactly 16
// (raw GUID bytes); for MYARK_HWID_SPOOF_CLASS_ARP ValueSize must be
// exactly 10: Value[0..3] = neighbor IPv4 (network byte order),
// Value[4..9] = replacement MAC (6 bytes).
//
#define MYARK_HWID_SPOOF_VALUE_MAX_BYTES      128

typedef struct _MYARK_HWID_SPOOF_SET_INPUT {
    MYARK_SAFETY_TOKEN Token;                    // op = MYARK_HWID_OP_SPOOF_CONFIG
    UINT32 Class;                                // MYARK_HWID_SPOOF_CLASS_*
    UINT32 Action;                               // MYARK_HWID_SPOOF_ACTION_*
    UINT32 Flags;                                // MYARK_HWID_SPOOF_FLAG_*
    UINT32 DiskIndex;                            // target disk (default 0)
    UINT32 ValueSize;                            // bytes in Value[]
    UINT32 Reserved1;
    UINT64 Reserved64;
    UINT8  Value[MYARK_HWID_SPOOF_VALUE_MAX_BYTES];
} MYARK_HWID_SPOOF_SET_INPUT, *PMYARK_HWID_SPOOF_SET_INPUT;

//
// Preview block: Real = value a query returns right now (DRY_RUN: the
// untouched hardware value; APPLY: the cached original; RESTORE: the
// post-restore re-probe). Spoof = the value that would be / was / had
// been written.
//
typedef struct _MYARK_HWID_SPOOF_PREVIEW {
    UINT32 RealLen;
    UINT32 SpoofLen;
    UINT32 Status;                               // in-band NTSTATUS of the class op
    UINT32 Reserved1;
    UINT8  Real[MYARK_HWID_SPOOF_VALUE_MAX_BYTES];
    UINT8  Spoof[MYARK_HWID_SPOOF_VALUE_MAX_BYTES];
} MYARK_HWID_SPOOF_PREVIEW, *PMYARK_HWID_SPOOF_PREVIEW;

typedef struct _MYARK_HWID_SPOOF_SET_OUTPUT {
    UINT32 Status;                               // overall NTSTATUS
    UINT32 Applied;                              // 1 when the class is now active
    UINT32 RewrittenCount;                       // lifetime rewrites for the class
    UINT32 AttachedCount;                        // stacks currently filtered
    MYARK_HWID_SPOOF_PREVIEW Preview;
} MYARK_HWID_SPOOF_SET_OUTPUT, *PMYARK_HWID_SPOOF_SET_OUTPUT;

typedef struct _MYARK_HWID_SPOOF_CLASS_STATUS {
    UINT32 Class;
    UINT32 Flags;                                // MYARK_HWID_SPOOF_ST_*
    UINT32 SpoofLen;
    UINT32 CacheLen;
    UINT32 RewrittenCount;
    UINT32 AttachedCount;
    UINT32 QueryCount;                           // successful device-controls seen on the class filters
    UINT32 LastStatus;                           // last APPLY/RESTORE/rewrite status
} MYARK_HWID_SPOOF_CLASS_STATUS, *PMYARK_HWID_SPOOF_CLASS_STATUS;

typedef struct _MYARK_HWID_SPOOF_STATUS_OUTPUT {
    UINT32 Count;                                // == MYARK_HWID_SPOOF_CLASS_COUNT
    UINT32 Reserved1;
    UINT64 Reserved64;
    MYARK_HWID_SPOOF_CLASS_STATUS Classes[MYARK_HWID_SPOOF_CLASS_COUNT];
} MYARK_HWID_SPOOF_STATUS_OUTPUT, *PMYARK_HWID_SPOOF_STATUS_OUTPUT;

//
// 0x754 capture readback (R3-1b bring-up tool). While the class-ARP
// capture is armed the driver records the last
// MYARK_HWID_CAPTURE_MAX_TUPLES device-controls seen on \Device\Nsi
// (code + sizes + first input bytes) and keeps the first
// MYARK_HWID_CAPTURE_DUMP_BYTES of the most recent enumerate-shaped
// response (Sequence increments per dump refresh). IN_BYTES is 128 so a
// full NSI_PARAMS request (80/104/112 bytes on 1903) fits -- the pair
// offsets differ per opcode and need the whole request to pin down.
//
#define MYARK_HWID_CAPTURE_MAGIC             0x48574350UL  // 'HWCP'
#define MYARK_HWID_CAPTURE_MAX_TUPLES        8
#define MYARK_HWID_CAPTURE_IN_BYTES          128
#define MYARK_HWID_CAPTURE_DUMP_BYTES        4096

typedef struct _MYARK_HWID_CAPTURE_TUPLE {
    UINT32 IoctlCode;
    UINT32 InLen;
    UINT32 OutLen;
    UINT32 Reserved;
    UINT8  Input[MYARK_HWID_CAPTURE_IN_BYTES];
} MYARK_HWID_CAPTURE_TUPLE, *PMYARK_HWID_CAPTURE_TUPLE;

typedef struct _MYARK_HWID_CAPTURE_OUTPUT {
    UINT32 Magic;
    UINT32 Armed;
    UINT32 TupleCount;
    UINT32 DumpLen;
    UINT64 Sequence;
    MYARK_HWID_CAPTURE_TUPLE Tuples[MYARK_HWID_CAPTURE_MAX_TUPLES];
    UINT8  Dump[MYARK_HWID_CAPTURE_DUMP_BYTES];
    // R3-1b bring-up diagnostics (round 9b): early-return counters.
    UINT32 DiagNotCaller;
    UINT32 DiagInFail;
    UINT32 DiagNotBig;
    UINT32 DiagBig;
} MYARK_HWID_CAPTURE_OUTPUT, *PMYARK_HWID_CAPTURE_OUTPUT;

C_ASSERT(sizeof(MYARK_HWID_SPOOF_SET_INPUT) == 232);
C_ASSERT(sizeof(MYARK_HWID_SPOOF_PREVIEW) == 272);
C_ASSERT(sizeof(MYARK_HWID_SPOOF_SET_OUTPUT) == 288);
C_ASSERT(sizeof(MYARK_HWID_SPOOF_CLASS_STATUS) == 32);
C_ASSERT(sizeof(MYARK_HWID_SPOOF_STATUS_OUTPUT) == 208);
C_ASSERT(sizeof(MYARK_HWID_CAPTURE_TUPLE) == 144);
C_ASSERT(sizeof(MYARK_HWID_CAPTURE_OUTPUT) == 5288);