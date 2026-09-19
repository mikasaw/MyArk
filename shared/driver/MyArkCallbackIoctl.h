// MyArk callback module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x710..0x71E + R3-9 0x723/0x724 reserved for the callback module (S7.2 + R2-6 + R2-11).
// The callback module provides a read-only inspection surface for the five
// Windows kernel callback registration arrays (Ps/Cm/Ob/Image/Dbg). For
// S7.2 the IOCTL set is intentionally enumeration-only; the higher-risk
// REMOVE/RESTORE operations are reserved for a follow-up stage so the
// release can land without a payload-modification story.
//
// The 17 IOCTLs:
//
//   0x710  QUERY_PS      - PsCreateProcessNotifyEx / PsSetCreateThreadNotifyEx /
//                          PsSetLoadImageNotifyRoutine array
//   0x711  QUERY_CM      - CmRegisterCallback (registry) array
//   0x712  QUERY_OB      - ObRegisterCallbacks (process / thread handle) array
//   0x713  QUERY_IMAGE   - PsSetLoadImageNotifyRoutine array
//   0x714  QUERY_DBG     - DbgkDebugObjectType / kernel debugger object array
//   0x715  ENUMERATE     - All 5 callback arrays as a single result (R3 cache fill)
//   0x716  REMOVE        - Remove a registered callback by index (reserved; S7.2-fix)
//   0x717  RESTORE       - Restore a previously-removed callback (reserved; S7.2-fix)
//   0x718  BACKUP        - Snapshot of every registered callback (reserved; S7.2-fix)
//   0x719  STATS         - Total callback counts per category
//
// All 17 IOCTLs use the MyArk METHOD_BUFFERED convention. For S7.2 the
// REMOVE/RESTORE/BACKUP IOCTLs return STATUS_NOT_IMPLEMENTED so the wiring
// exists end-to-end but no mutating path is reachable from R3.

#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "MyArkSafetyToken.h"

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_CALLBACK_MODULE_ID              0x43424C4BUL  // 'CBLK' ASCII (LE)
#define MYARK_CALLBACK_NAME_MAX                64
#define MYARK_CALLBACK_PATH_MAX                260
#define MYARK_CALLBACK_DRIVER_NAME_MAX         32

//
// Hard caps (defensive: callers can override via Input but never ask for
// an unbounded buffer).
//
#define MYARK_CALLBACK_PS_HARD_CAP             64
#define MYARK_CALLBACK_CM_HARD_CAP             64
#define MYARK_CALLBACK_OB_HARD_CAP             64
#define MYARK_CALLBACK_IMAGE_HARD_CAP          64
#define MYARK_CALLBACK_DBG_HARD_CAP            32

//
// 17 IOCTLs (function range 0x710..0x71B). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_CALLBACK_QUERY_PS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x710, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_QUERY_CM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x711, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_QUERY_OB \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x712, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_QUERY_IMAGE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x713, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_QUERY_DBG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x714, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_ENUMERATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x715, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_REMOVE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x716, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_RESTORE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x717, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_BACKUP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x718, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x719, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_SET_RULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71A, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_RUNTIME_STATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71B, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Callback category / flag bits shared across the QUERY_* outputs.
// ---------------------------------------------------------------------------

//
// MYARK_CALLBACK_CATEGORY_* identifies which kernel array the row came from.
// The values double as bit positions in the CATEGORY_MASK used by the
// ENUMERATE IOCTL.
//
#define MYARK_CALLBACK_CATEGORY_PS             0x01
#define MYARK_CALLBACK_CATEGORY_CM             0x02
#define MYARK_CALLBACK_CATEGORY_OB             0x04
#define MYARK_CALLBACK_CATEGORY_IMAGE          0x08
#define MYARK_CALLBACK_CATEGORY_DBG            0x10

//
// MYARK_CALLBACK_FLAG_* report the row's relation to ntoskrnl .text.
//   POPULATED = the underlying entry was non-null at walk time
//   SUSPECT   = address outside the resolved kernel .text range
//   HOOK      = low-bit set or trampoline present (best-effort)
//   UNSIGNED  = the callback driver is not test-signed (informational)
//   ALTITUDE  = Altitude string present (Cm / Ob specific)
//
#define MYARK_CALLBACK_FLAG_NONE               0x00000000
#define MYARK_CALLBACK_FLAG_POPULATED          0x00000001
#define MYARK_CALLBACK_FLAG_SUSPECT            0x00000002
#define MYARK_CALLBACK_FLAG_HOOK               0x00000004
#define MYARK_CALLBACK_FLAG_UNSIGNED           0x00000008
#define MYARK_CALLBACK_FLAG_ALTITUDE           0x00000010

//
// MYARK_CALLBACK_PS_SUBTYPE_* identifies the PS sub-array the row came
// from. PROCESS = PsCreateProcessNotifyEx, THREAD = PsSetCreateThreadNotifyEx,
// IMAGE = PsSetLoadImageNotifyRoutine. The QUERY_PS IOCTL returns rows from
// all three sub-arrays in order: PROCESS, then THREAD, then IMAGE.
//
#define MYARK_CALLBACK_PS_SUBTYPE_PROCESS      0x01
#define MYARK_CALLBACK_PS_SUBTYPE_THREAD       0x02
#define MYARK_CALLBACK_PS_SUBTYPE_IMAGE        0x03

//
// MYARK_CALLBACK_OB_OPERATION_* identifies the ObRegisterCallbacks op the
// row is associated with. The QUERY_OB IOCTL returns rows from both
// process-handle and thread-handle sub-arrays.
//
#define MYARK_CALLBACK_OB_OPERATION_PROCESS    0x01
#define MYARK_CALLBACK_OB_OPERATION_THREAD     0x02

//
// MYARK_CALLBACK_DBG_SUBTYPE_* identifies the Dbg sub-array the row came
// from. KDEBUG_OBJECT = DbgkDebugObjectType, BOUND = bound debug object
// table (PsNtDebuggerObject / friends).
//
#define MYARK_CALLBACK_DBG_SUBTYPE_DEBUG       0x01
#define MYARK_CALLBACK_DBG_SUBTYPE_BOUND       0x02

// ---------------------------------------------------------------------------
// QUERY_PS: PsSet*NotifyRoutine array. Each row covers one callback slot.
// ---------------------------------------------------------------------------

typedef struct _MYARK_CALLBACK_PS_ENTRY {
    UINT32  Index;                                         // index in the PS array
    UINT32  SubType;                                       // MYARK_CALLBACK_PS_SUBTYPE_*
    UINT32  Flags;                                         // MYARK_CALLBACK_FLAG_*
    UINT32  Reserved0;
    UINT64  Callback;                                      // kernel VA (informational)
    UINT8   DriverName[MYARK_CALLBACK_DRIVER_NAME_MAX];    // owning driver (when known)
} MYARK_CALLBACK_PS_ENTRY, *PMYARK_CALLBACK_PS_ENTRY;

typedef struct _MYARK_CALLBACK_QUERY_PS_INPUT {
    UINT32  MaxEntries;
    UINT32  SubTypeMask;                                   // bit 1=PROCESS, bit 2=THREAD, bit 3=IMAGE (0=all)
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_CALLBACK_QUERY_PS_INPUT, *PMYARK_CALLBACK_QUERY_PS_INPUT;

typedef struct _MYARK_CALLBACK_QUERY_PS_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  PspCreateProcessNotifyRoutine;                 // resolved pointer (0 = unresolvable)
    UINT64  PspCreateThreadNotifyRoutine;                  // resolved pointer (0 = unresolvable)
    UINT64  PspLoadImageNotifyRoutine;                     // resolved pointer (0 = unresolvable)
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_CALLBACK_PS_ENTRY Entries[1];
} MYARK_CALLBACK_QUERY_PS_OUTPUT, *PMYARK_CALLBACK_QUERY_PS_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_CM: CmRegisterCallback (registry) array.
// ---------------------------------------------------------------------------

typedef struct _MYARK_CALLBACK_CM_ENTRY {
    UINT32  Index;                                         // index in the Cm array
    UINT32  Flags;                                         // MYARK_CALLBACK_FLAG_*
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT64  Callback;                                      // kernel VA (informational)
    UINT64  Cookie;                                        // Cm callback cookie (when known)
    UINT8   DriverName[MYARK_CALLBACK_DRIVER_NAME_MAX];
    UINT8   Altitude[MYARK_CALLBACK_NAME_MAX];             // Cm altitude string (when present)
} MYARK_CALLBACK_CM_ENTRY, *PMYARK_CALLBACK_CM_ENTRY;

typedef struct _MYARK_CALLBACK_QUERY_CM_INPUT {
    UINT32  MaxEntries;
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_CALLBACK_QUERY_CM_INPUT, *PMYARK_CALLBACK_QUERY_CM_INPUT;

typedef struct _MYARK_CALLBACK_QUERY_CM_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  CmpCallbackListHead;                           // resolved pointer (0 = unresolvable)
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_CALLBACK_CM_ENTRY Entries[1];
} MYARK_CALLBACK_QUERY_CM_OUTPUT, *PMYARK_CALLBACK_QUERY_CM_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_OB: ObRegisterCallbacks (process / thread handle) array.
// ---------------------------------------------------------------------------

typedef struct _MYARK_CALLBACK_OB_ENTRY {
    UINT32  Index;                                         // index in the Ob array
    UINT32  Operation;                                     // MYARK_CALLBACK_OB_OPERATION_*
    UINT32  Flags;                                         // MYARK_CALLBACK_FLAG_*
    UINT32  Reserved0;
    UINT64  Callback;                                      // kernel VA (PreOperation routine)
    UINT64  Altitude;                                      // kernel VA (informational)
    UINT64  Cookie;                                        // Ob callback cookie (when known)
    UINT8   DriverName[MYARK_CALLBACK_DRIVER_NAME_MAX];
    UINT8   AltitudeString[MYARK_CALLBACK_NAME_MAX];       // Ob altitude string (when present)
} MYARK_CALLBACK_OB_ENTRY, *PMYARK_CALLBACK_OB_ENTRY;

typedef struct _MYARK_CALLBACK_QUERY_OB_INPUT {
    UINT32  MaxEntries;
    UINT32  OperationMask;                                 // bit 1=PROCESS, bit 2=THREAD (0=both)
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_CALLBACK_QUERY_OB_INPUT, *PMYARK_CALLBACK_QUERY_OB_INPUT;

typedef struct _MYARK_CALLBACK_QUERY_OB_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  ObCallbackListHead;                            // resolved pointer (0 = unresolvable)
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_CALLBACK_OB_ENTRY Entries[1];
} MYARK_CALLBACK_QUERY_OB_OUTPUT, *PMYARK_CALLBACK_QUERY_OB_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_IMAGE: PsSetLoadImageNotifyRoutine array (mirrors QUERY_PS IMAGE).
// ---------------------------------------------------------------------------

typedef struct _MYARK_CALLBACK_IMAGE_ENTRY {
    UINT32  Index;                                         // index in the image-notify array
    UINT32  Flags;                                         // MYARK_CALLBACK_FLAG_*
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT64  Callback;                                      // kernel VA (informational)
    UINT8   DriverName[MYARK_CALLBACK_DRIVER_NAME_MAX];
} MYARK_CALLBACK_IMAGE_ENTRY, *PMYARK_CALLBACK_IMAGE_ENTRY;

typedef struct _MYARK_CALLBACK_QUERY_IMAGE_INPUT {
    UINT32  MaxEntries;
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_CALLBACK_QUERY_IMAGE_INPUT, *PMYARK_CALLBACK_QUERY_IMAGE_INPUT;

typedef struct _MYARK_CALLBACK_QUERY_IMAGE_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  PspLoadImageNotifyRoutine;                     // resolved pointer (0 = unresolvable)
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_CALLBACK_IMAGE_ENTRY Entries[1];
} MYARK_CALLBACK_QUERY_IMAGE_OUTPUT, *PMYARK_CALLBACK_QUERY_IMAGE_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_DBG: DbgkDebugObjectType + bound debugger object table.
// ---------------------------------------------------------------------------

typedef struct _MYARK_CALLBACK_DBG_ENTRY {
    UINT32  Index;                                         // index in the Dbg array
    UINT32  SubType;                                       // MYARK_CALLBACK_DBG_SUBTYPE_*
    UINT32  Flags;                                         // MYARK_CALLBACK_FLAG_*
    UINT32  Reserved0;
    UINT64  Object;                                        // kernel VA (informational)
    UINT8   DriverName[MYARK_CALLBACK_DRIVER_NAME_MAX];
} MYARK_CALLBACK_DBG_ENTRY, *PMYARK_CALLBACK_DBG_ENTRY;

typedef struct _MYARK_CALLBACK_QUERY_DBG_INPUT {
    UINT32  MaxEntries;
    UINT32  SubTypeMask;                                   // bit 1=DEBUG, bit 2=BOUND (0=both)
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_CALLBACK_QUERY_DBG_INPUT, *PMYARK_CALLBACK_QUERY_DBG_INPUT;

typedef struct _MYARK_CALLBACK_QUERY_DBG_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  DbgkDebugObjectType;                           // resolved pointer (0 = unresolvable)
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_CALLBACK_DBG_ENTRY Entries[1];
} MYARK_CALLBACK_QUERY_DBG_OUTPUT, *PMYARK_CALLBACK_QUERY_DBG_OUTPUT;

// ---------------------------------------------------------------------------
// ENUMERATE: dump all 5 callback arrays in one call. Each OUTPUT entry has
// a Category bit so R3 can route the row into its table; per-category
// counts are exposed so the caller can size follow-up per-category queries.
// ---------------------------------------------------------------------------

typedef struct _MYARK_CALLBACK_ENUM_ENTRY {
    UINT32  Category;                                      // MYARK_CALLBACK_CATEGORY_*
    UINT32  SubType;                                       // category-specific (PS/DBG/OB)
    UINT32  Index;                                         // index within the source array
    UINT32  Flags;                                         // MYARK_CALLBACK_FLAG_*
    UINT64  Callback;                                      // kernel VA (informational)
    UINT64  Cookie;                                        // category-specific (Cm / Ob)
    UINT8   DriverName[MYARK_CALLBACK_DRIVER_NAME_MAX];
    UINT8   Altitude[MYARK_CALLBACK_NAME_MAX];             // Cm / Ob altitude string (when present)
} MYARK_CALLBACK_ENUM_ENTRY, *PMYARK_CALLBACK_ENUM_ENTRY;

typedef struct _MYARK_CALLBACK_ENUMERATE_INPUT {
    UINT32  MaxEntries;
    UINT32  CategoryMask;                                  // bit 1=PS, bit 2=CM, bit 4=OB, bit 8=IMAGE, bit 16=DBG
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_CALLBACK_ENUMERATE_INPUT, *PMYARK_CALLBACK_ENUMERATE_INPUT;

typedef struct _MYARK_CALLBACK_ENUMERATE_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT32  PsCount;
    UINT32  CmCount;
    UINT32  ObCount;
    UINT32  ImageCount;
    UINT32  DbgCount;
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_CALLBACK_ENUM_ENTRY Entries[1];
} MYARK_CALLBACK_ENUMERATE_OUTPUT, *PMYARK_CALLBACK_ENUMERATE_OUTPUT;

// ---------------------------------------------------------------------------
// REMOVE / RESTORE / BACKUP are reserved for the S7.2-fix stage. For S7.2
// the IOCTLs are wired through the dispatch table so R3 can probe them but
// the handlers return STATUS_NOT_IMPLEMENTED.
// ---------------------------------------------------------------------------

typedef struct _MYARK_CALLBACK_REMOVE_INPUT {
    UINT32  Category;                                      // MYARK_CALLBACK_CATEGORY_*
    UINT32  Index;                                         // index within the source array
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_CALLBACK_REMOVE_INPUT, *PMYARK_CALLBACK_REMOVE_INPUT;

typedef struct _MYARK_CALLBACK_REMOVE_OUTPUT {
    UINT32  Size;
    UINT32  Status;                                        // reserved (0)
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_CALLBACK_REMOVE_OUTPUT, *PMYARK_CALLBACK_REMOVE_OUTPUT;

typedef struct _MYARK_CALLBACK_RESTORE_INPUT {
    UINT32  Category;                                      // MYARK_CALLBACK_CATEGORY_*
    UINT32  Index;                                         // index within the source array
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_CALLBACK_RESTORE_INPUT, *PMYARK_CALLBACK_RESTORE_INPUT;

typedef struct _MYARK_CALLBACK_RESTORE_OUTPUT {
    UINT32  Size;
    UINT32  Status;                                        // reserved (0)
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_CALLBACK_RESTORE_OUTPUT, *PMYARK_CALLBACK_RESTORE_OUTPUT;

typedef struct _MYARK_CALLBACK_BACKUP_INPUT {
    UINT32  MaxEntries;
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_CALLBACK_BACKUP_INPUT, *PMYARK_CALLBACK_BACKUP_INPUT;

typedef struct _MYARK_CALLBACK_BACKUP_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  BackupBlob;                                    // opaque kernel-VA (informational)
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_CALLBACK_ENUM_ENTRY Entries[1];
} MYARK_CALLBACK_BACKUP_OUTPUT, *PMYARK_CALLBACK_BACKUP_OUTPUT;

// ---------------------------------------------------------------------------
// STATS: per-category totals + grand total. No variable-length entries.
// ---------------------------------------------------------------------------

typedef struct _MYARK_CALLBACK_STATS_OUTPUT {
    UINT32  Size;
    UINT32  PsCount;
    UINT32  CmCount;
    UINT32  ObCount;
    UINT32  ImageCount;
    UINT32  DbgCount;
    UINT32  TotalCount;
    UINT32  Reserved0;
} MYARK_CALLBACK_STATS_OUTPUT, *PMYARK_CALLBACK_STATS_OUTPUT;

// ---------------------------------------------------------------------------
// Process-creation rule engine (R2-6). The driver registers a
// PsSetCreateProcessNotifyRoutineEx callback at module init; every
// process creation is matched against an in-memory rule table (image
// file name, case-insensitive) with two actions:
//   DENY     -- Info->CreationStatus = STATUS_ACCESS_DENIED (the create
//               call fails in user space with ERROR_ACCESS_DENIED)
//   LOG_ONLY -- the match is counted only
// The engine must be enabled before rules fire (RUNTIME_STATE). Rules
// and counters live in nonpaged storage guarded by an exclusive/shared
// spin lock (shared on the notify path, exclusive on rule mutation).
// ---------------------------------------------------------------------------

#define MYARK_CALLBACK_RULE_MAX               32
#define MYARK_CALLBACK_RULE_NAME_CHARS        64

#define MYARK_CALLBACK_RULE_ACTION_DENY       1
#define MYARK_CALLBACK_RULE_ACTION_LOG_ONLY   2

// SET_RULES Operation values.
#define MYARK_CALLBACK_RULES_OP_SET           1   // add or replace a rule
#define MYARK_CALLBACK_RULES_OP_REMOVE        2   // remove one rule
#define MYARK_CALLBACK_RULES_OP_CLEAR         3   // remove every rule

// SAFETY_TOKEN operations (distinct namespace: 'CBR1'/'CBR2').
#define MYARK_CALLBACK_OP_SET_RULES           0x31524243UL
#define MYARK_CALLBACK_OP_RUNTIME_STATE       0x32524243UL

// RUNTIME_STATE Mode values.
#define MYARK_CALLBACK_STATE_QUERY            0   // no token needed
#define MYARK_CALLBACK_STATE_ENABLE           1   // token
#define MYARK_CALLBACK_STATE_DISABLE          2   // token

typedef struct _MYARK_CALLBACK_SET_RULES_INPUT {
    MYARK_SAFETY_TOKEN Token;                        // op = MYARK_CALLBACK_OP_SET_RULES
    UINT32  Operation;                               // MYARK_CALLBACK_RULES_OP_*
    UINT32  RuleAction;                              // MYARK_CALLBACK_RULE_ACTION_*
    WCHAR   ImageName[MYARK_CALLBACK_RULE_NAME_CHARS]; // file name only, no path
} MYARK_CALLBACK_SET_RULES_INPUT, *PMYARK_CALLBACK_SET_RULES_INPUT;

typedef struct _MYARK_CALLBACK_SET_RULES_OUTPUT {
    UINT32  Status;                                  // 0 = applied
    UINT32  ActiveRules;
} MYARK_CALLBACK_SET_RULES_OUTPUT, *PMYARK_CALLBACK_SET_RULES_OUTPUT;

typedef struct _MYARK_CALLBACK_RUNTIME_STATE_INPUT {
    MYARK_SAFETY_TOKEN Token;                        // op = MYARK_CALLBACK_OP_RUNTIME_STATE (only for ENABLE/DISABLE)
    UINT32  Mode;                                    // MYARK_CALLBACK_STATE_*
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_CALLBACK_RUNTIME_STATE_INPUT, *PMYARK_CALLBACK_RUNTIME_STATE_INPUT;

typedef struct _MYARK_CALLBACK_RUNTIME_STATE_OUTPUT {
    UINT32  Enabled;
    UINT32  ActiveRules;
    UINT32  TotalMatched;                            // all rules, both actions
    UINT32  TotalDenied;                             // DENY matches
} MYARK_CALLBACK_RUNTIME_STATE_OUTPUT, *PMYARK_CALLBACK_RUNTIME_STATE_OUTPUT;

// ---------------------------------------------------------------------------
// ASK_USER interactive process-creation decisions (R2-11). A rule with
// action ASK parks the CREATING thread inside the PsSetCreateProcessNotify
// RoutineEx callback on a per-slot KEVENT with a hard 5 s timeout (fail
// open) while R3 inspects and resolves it:
//
//   ASK_WAIT    (0x71C)  non-blocking snapshot of pending slots + counters.
//                        Never parks a WDF request -- the R2-11 postmortem
//                        showed a parked poll request starves the driver's
//                        sequential queue and freezes every IOCTL.
//   ASK_ANSWER  (0x71D)  token-gated resolve by sequence (ALLOW / DENY).
//   ASK_CANCEL  (0x71E)  token-gated flush of every pending slot (fail open).
//
// The creating thread holds no spin lock while waiting; a timeout answers
// ALLOW so a dead or slow manager can never wedge process creation
// system-wide.
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_CALLBACK_ASK_WAIT     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71C, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_ASK_ANSWER     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71D, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CALLBACK_ASK_CANCEL     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71E, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_CALLBACK_RULE_ACTION_ASK        3

// SAFETY_TOKEN operations (namespace continues 'CBR3'/'CBR4').
#define MYARK_CALLBACK_OP_ASK_ANSWER          0x33524243UL  // 'CBR3' ASCII (LE)
#define MYARK_CALLBACK_OP_ASK_CANCEL          0x34524243UL  // 'CBR4' ASCII (LE)

#define MYARK_CALLBACK_ASK_MAX_PENDING        8
#define MYARK_CALLBACK_ASK_NAME_CHARS         64
#define MYARK_CALLBACK_ASK_TIMEOUT_MS         5000

#define MYARK_CALLBACK_ASK_DECISION_ALLOW     0
#define MYARK_CALLBACK_ASK_DECISION_DENY      1

typedef struct _MYARK_CALLBACK_ASK_ENTRY {
    UINT64  Sequence;                            // monotonic, starts at 1
    UINT64  ParentId;                            // creating process
    UINT64  ProcessId;                           // process being created
    UINT32  NameChars;                           // image name chars incl. NUL
    UINT32  Reserved0;
    WCHAR   Name[MYARK_CALLBACK_ASK_NAME_CHARS]; // image file name (tail)
} MYARK_CALLBACK_ASK_ENTRY, *PMYARK_CALLBACK_ASK_ENTRY;

typedef struct _MYARK_CALLBACK_ASK_WAIT_OUTPUT {
    UINT32  Status;                              // 0 = polled
    UINT32  PendingCount;                        // entries in this batch
    UINT32  TotalAsked;                          // cumulative park count
    UINT32  TotalDenied;                         // answered DENY
    UINT32  TotalTimedOut;                       // 5 s timeout (answered ALLOW)
    UINT32  TotalDropped;                        // no free slot (answered ALLOW)
    UINT32  EntryStructSize;
    UINT32  Reserved0;
    MYARK_CALLBACK_ASK_ENTRY Entries[MYARK_CALLBACK_ASK_MAX_PENDING];
} MYARK_CALLBACK_ASK_WAIT_OUTPUT, *PMYARK_CALLBACK_ASK_WAIT_OUTPUT;

typedef struct _MYARK_CALLBACK_ASK_ANSWER_INPUT {
    MYARK_SAFETY_TOKEN Token;                    // op = MYARK_CALLBACK_OP_ASK_ANSWER
    UINT64  Sequence;                            // target slot sequence
    UINT32  Decision;                            // MYARK_CALLBACK_ASK_DECISION_*
    UINT32  Reserved0;
} MYARK_CALLBACK_ASK_ANSWER_INPUT, *PMYARK_CALLBACK_ASK_ANSWER_INPUT;

typedef struct _MYARK_CALLBACK_ASK_ANSWER_OUTPUT {
    UINT32  Status;                              // 0 = resolved (NOT_FOUND = unknown/stale seq)
    UINT32  PendingCount;                        // remaining pending after this answer
} MYARK_CALLBACK_ASK_ANSWER_OUTPUT, *PMYARK_CALLBACK_ASK_ANSWER_OUTPUT;

typedef struct _MYARK_CALLBACK_ASK_CANCEL_INPUT {
    MYARK_SAFETY_TOKEN Token;                    // op = MYARK_CALLBACK_OP_ASK_CANCEL
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_CALLBACK_ASK_CANCEL_INPUT, *PMYARK_CALLBACK_ASK_CANCEL_INPUT;

typedef struct _MYARK_CALLBACK_ASK_CANCEL_OUTPUT {
    UINT32  Status;                              // 0 = flushed
    UINT32  Flushed;                             // slots resolved fail-open
} MYARK_CALLBACK_ASK_CANCEL_OUTPUT, *PMYARK_CALLBACK_ASK_CANCEL_OUTPUT;

// ---------------------------------------------------------------------------
// R3-9: ObCallbacks STRIP_ACCESS (0x71F/0x720).
//
// 0x71F: SAFETY_TOKEN-gated ADD/REMOVE/CLEAR of PIDs in the handle-open
//        protection list. When a listed PID is the target of an
//        ObRegisterCallbacks pre-operation for PsProcessType, dangerous
//        rights (TERMINATE/CREATE_THREAD/VM_*/DUP_HANDLE/SUSPEND_RESUME)
//        are stripped from the desired access mask -- the opener still gets
//        a valid handle (QUERY/SYNCHRONIZE survive) but cannot kill, write
//        or inject.
// 0x720: read-only inventory (registered flag, PID list, per-slot strip
//        counters).
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_CALLBACK_OB_PROTECT_SET     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x723, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_CALLBACK_OB_PROTECT_STATUS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x724, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_CALLBACK_OP_OB_PROTECT_SET        0x35524243UL  // 'CBR5' ASCII (LE)

#define MYARK_CALLBACK_OB_PROTECT_ACTION_ADD    1
#define MYARK_CALLBACK_OB_PROTECT_ACTION_REMOVE 2
#define MYARK_CALLBACK_OB_PROTECT_ACTION_CLEAR  3

#define MYARK_CALLBACK_OB_PROTECT_MAX           16

typedef struct _MYARK_CALLBACK_OB_PROTECT_SET_INPUT {
    MYARK_SAFETY_TOKEN Token;                    // op = MYARK_CALLBACK_OP_OB_PROTECT_SET
    UINT32  Action;                              // MYARK_CALLBACK_OB_PROTECT_ACTION_*
    UINT32  Pid;                                 // ADD/REMOVE only
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_CALLBACK_OB_PROTECT_SET_INPUT, *PMYARK_CALLBACK_OB_PROTECT_SET_INPUT;

typedef struct _MYARK_CALLBACK_OB_PROTECT_SET_OUTPUT {
    UINT32  Status;                              // in-band NTSTATUS
    UINT32  Applied;                             // 1 = list changed
    UINT32  Count;                               // list size after the call
    UINT32  Reserved1;
} MYARK_CALLBACK_OB_PROTECT_SET_OUTPUT, *PMYARK_CALLBACK_OB_PROTECT_SET_OUTPUT;

typedef struct _MYARK_CALLBACK_OB_PROTECT_STATUS_OUTPUT {
    UINT32  Status;
    UINT32  Registered;                          // 1 = ObCallbacks armed
    UINT32  Count;
    UINT32  Reserved1;
    UINT64  TotalStrips;                         // lifetime (never cleared by REMOVE/CLEAR)
    UINT64  StripCount[MYARK_CALLBACK_OB_PROTECT_MAX]; // per-slot hit counts
    UINT32  Pids[MYARK_CALLBACK_OB_PROTECT_MAX];
    UINT32  Reserved2;
} MYARK_CALLBACK_OB_PROTECT_STATUS_OUTPUT, *PMYARK_CALLBACK_OB_PROTECT_STATUS_OUTPUT;

C_ASSERT(sizeof(MYARK_CALLBACK_OB_PROTECT_SET_INPUT) == 88);
C_ASSERT(sizeof(MYARK_CALLBACK_OB_PROTECT_SET_OUTPUT) == 16);
C_ASSERT(sizeof(MYARK_CALLBACK_OB_PROTECT_STATUS_OUTPUT) == 224);
