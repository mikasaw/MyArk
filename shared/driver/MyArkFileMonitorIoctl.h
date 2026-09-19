// MyArk file-monitor module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x815..0x817 reserved for the file monitor (ROADMAP R2-7).
// The module registers a minifilter with FLTMGR from MyArkCore's own
// DriverEntry context (kernel-service load, not fltmgr auto-load) and
// samples completed IRP_MJ_CREATE / IRP_MJ_SET_INFORMATION (disposition)
// operations into a fixed ring buffer. User mode arms the monitor with a
// DOS path prefix, drains recorded events and reads counters; nothing in
// the path of a file operation ever blocks on the consumer.
//
// CONTROL is token-gated (MYARK_FILEMON_OP_CONTROL, 'FMR1' namespace).
// DRAIN / STATUS are read-only and open to any caller. All three use the
// MyArk METHOD_BUFFERED convention (see shared/driver/MyArkIoctl.h).

#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "MyArkSafetyToken.h"


// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_FILEMON_MODULE_ID              0x464D4F4EUL  // 'FMON' ASCII (LE)

//
// 3 IOCTLs (function range 0x815..0x817). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_FILEMON_CONTROL          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_FILEMON_DRAIN            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_FILEMON_STATUS           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Limits + event encoding.
// ---------------------------------------------------------------------------

#define MYARK_FILEMON_PATH_CHARS             260   // prefix / event path cap, incl. NUL

// SAFETY_TOKEN operation (distinct namespace, one per mutating surface).
#define MYARK_FILEMON_OP_CONTROL             0x31524D46UL  // 'FMR1' ASCII (LE)

// Event types.
#define MYARK_FILEMON_TYPE_CREATE            1     // IRP_MJ_CREATE completed
#define MYARK_FILEMON_TYPE_DELETE            2     // disposition (delete) completed

// Event flags.
#define MYARK_FILEMON_FLAG_DELETE_ON_CLOSE   0x00000001  // CREATE carried FILE_DELETE_ON_CLOSE

// CONTROL input.
#define MYARK_FILEMON_CONTROL_FLAG_NONE      0x00000000
#define MYARK_FILEMON_ENABLE_OFF             0
#define MYARK_FILEMON_ENABLE_ON              1

// ---------------------------------------------------------------------------
// CONTROL.
//
// Token-gated. Enable=1 arms sampling for file operations whose normalized
// NT path equals / lies below the DOS PathPrefix (case-insensitive,
// component-aligned). The prefix must be absolute ("C:\dir\sub" or
// "\??\C:\dir\sub"); the drive letter is stripped and only the sub-path is
// compared against the event name, so recorded paths stay in normalized NT
// form ("\Device\HarddiskVolumeN\..."). Enable=0 disarms; Status/Enabled
// report the in-band outcome (transport failures still surface as win32
// errors from DeviceIoControl).
// ---------------------------------------------------------------------------

typedef struct _MYARK_FILEMON_CONTROL_INPUT {
    MYARK_SAFETY_TOKEN Token;                    // op = MYARK_FILEMON_OP_CONTROL
    UINT32  Enable;                              // MYARK_FILEMON_ENABLE_*
    UINT32  Flags;                               // reserved, must be 0
    WCHAR   PathPrefix[MYARK_FILEMON_PATH_CHARS];
} MYARK_FILEMON_CONTROL_INPUT, *PMYARK_FILEMON_CONTROL_INPUT;

typedef struct _MYARK_FILEMON_CONTROL_OUTPUT {
    UINT32  Status;                              // in-band NTSTATUS
    UINT32  Enabled;                             // resulting state (0/1)
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_FILEMON_CONTROL_OUTPUT, *PMYARK_FILEMON_CONTROL_OUTPUT;

// ---------------------------------------------------------------------------
// DRAIN.
//
// Copies buffered events out in FIFO order and consumes them. MaxEvents=0
// means "as many as the output buffer holds"; the driver additionally caps
// one call at MYARK_FILEMON_DRAIN_MAX_EVENTS. Remaining lets the consumer
// loop until it reaches zero. Events hold the full normalized NT path,
// truncated to MYARK_FILEMON_PATH_CHARS when longer (such events are also
// counted as skipped and never recorded).
// ---------------------------------------------------------------------------

#define MYARK_FILEMON_DRAIN_MAX_EVENTS       64

typedef struct _MYARK_FILEMON_DRAIN_INPUT {
    UINT32  MaxEvents;                           // 0 = fill the buffer (cap applies)
    UINT32  Reserved1;
} MYARK_FILEMON_DRAIN_INPUT, *PMYARK_FILEMON_DRAIN_INPUT;

typedef struct _MYARK_FILEMON_EVENT {
    UINT64  Sequence;                            // monotonic, starts at 1
    UINT64  Timestamp;                           // interrupt time at completion
    UINT32  ProcessId;                           // requester
    UINT32  Type;                                // MYARK_FILEMON_TYPE_*
    UINT32  Flags;                               // MYARK_FILEMON_FLAG_*
    UINT32  DesiredAccess;                       // CREATE: requested access
    UINT32  CreateDisposition;                   // CREATE: (Options >> 24) & 0xFF
    UINT32  Status;                              // completed IRP status (0 = ok)
    UINT32  PathChars;                           // path length incl. NUL
    WCHAR   Path[MYARK_FILEMON_PATH_CHARS];      // normalized NT path
    UINT32  Reserved2;   // explicit tail pad: keeps sizeof 8-aligned (568) with
                         // no hidden padding, so R3 stride math stays trivial
} MYARK_FILEMON_EVENT, *PMYARK_FILEMON_EVENT;

// Wire-compatibility guard: R3 parses events with a fixed 568-byte stride
// (see scripts/verify_core.py). The explicit Reserved2 tail keeps this
// struct exactly 8-aligned with no hidden padding; fail the build if the
// layout ever drifts.
C_ASSERT(sizeof(MYARK_FILEMON_EVENT) == 568);

typedef struct _MYARK_FILEMON_DRAIN_OUTPUT {
    UINT32  Count;                               // events in this batch
    UINT32  Remaining;                           // still buffered afterwards
    UINT32  TotalRecorded;                       // cumulative since load
    UINT32  TotalDropped;                        // cumulative ring-overflow drops
    UINT32  Registered;                          // minifilter registered OK
    UINT32  Enabled;                             // sampling armed right now
    UINT32  VolumesAttached;                     // disk volumes the instance attached to
    UINT32  Skipped;                             // name-query/oversize/IRQL skips
    MYARK_FILEMON_EVENT Events[1];               // Count entries valid
} MYARK_FILEMON_DRAIN_OUTPUT, *PMYARK_FILEMON_DRAIN_OUTPUT;

// ---------------------------------------------------------------------------
// STATUS.
//
// Read-only snapshot of the monitor state. No input.
// ---------------------------------------------------------------------------

typedef struct _MYARK_FILEMON_STATUS_OUTPUT {
    UINT32  Status;                              // 0 = queried
    UINT32  Registered;                          // minifilter registered OK
    UINT32  Enabled;                             // sampling armed
    UINT32  Buffered;                            // events currently queued
    UINT32  TotalRecorded;                       // cumulative since load
    UINT32  TotalDropped;                        // ring-overflow drops
    UINT32  VolumesAttached;                     // disk volumes attached
    UINT32  Skipped;                             // name-query/oversize/IRQL skips
    UINT32  StartStage;                          // 0 ok; 1 alloc; 2 instances key;
                                                 // 3 FltRegisterFilter; 4 FltStartFiltering
    UINT32  StartStatus;                         // NTSTATUS of the failed stage
} MYARK_FILEMON_STATUS_OUTPUT, *PMYARK_FILEMON_STATUS_OUTPUT;

// ---------------------------------------------------------------------------
// R3-7: system minifilter inventory (0x818) + sampler bypass PIDs (0x819).
//
// 0x818 is read-only and walks every registered minifilter via
// FltEnumerateFilters / FltGetFilterInformation(FilterFullInformation).
// 0x819 manages the sampler's bypass list: events whose requester PID is
// on the list are dropped before the name query (BypassDrops counts them).
// ADD/REMOVE/CLEAR are SAFETY_TOKEN gated (op MYARK_FILEMON_OP_BYPASS_PID);
// ACTION_QUERY is read-only.
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_FILEMON_ENUM_FILTERS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_FILEMON_BYPASS_PID       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_FILEMON_OP_BYPASS_PID          0x31504246UL  // 'FBP1' ASCII (LE)

#define MYARK_FILEMON_MAX_FILTERS            32
#define MYARK_FILEMON_FILTER_NAME_CHARS      64
#define MYARK_FILEMON_ALTITUDE_CHARS         24
#define MYARK_FILEMON_BYPASS_MAX             16

// 0x819 actions.
#define MYARK_FILEMON_BYPASS_ACTION_QUERY    0
#define MYARK_FILEMON_BYPASS_ACTION_ADD      1
#define MYARK_FILEMON_BYPASS_ACTION_REMOVE   2
#define MYARK_FILEMON_BYPASS_ACTION_CLEAR    3

typedef struct _MYARK_FILEMON_FILTER_ENTRY {
    UINT32 NameChars;                            // WCHARs, excluding NUL
    UINT32 AltitudeChars;                        // WCHARs, excluding NUL
    UINT32 InstanceCount;                        // instances across all volumes
    UINT32 Reserved1;
    WCHAR  Name[MYARK_FILEMON_FILTER_NAME_CHARS];
    WCHAR  Altitude[MYARK_FILEMON_ALTITUDE_CHARS];
} MYARK_FILEMON_FILTER_ENTRY, *PMYARK_FILEMON_FILTER_ENTRY;

typedef struct _MYARK_FILEMON_ENUM_OUTPUT {
    UINT32 Count;                                // entries filled
    UINT32 Truncated;                            // 1 = more filters than cap
    UINT32 Reserved1;
    UINT32 Reserved2;
    MYARK_FILEMON_FILTER_ENTRY Entries[MYARK_FILEMON_MAX_FILTERS];
} MYARK_FILEMON_ENUM_OUTPUT, *PMYARK_FILEMON_ENUM_OUTPUT;

typedef struct _MYARK_FILEMON_BYPASS_INPUT {
    MYARK_SAFETY_TOKEN Token;                    // op = MYARK_FILEMON_OP_BYPASS_PID
    UINT32  Action;                              // MYARK_FILEMON_BYPASS_ACTION_*
    UINT32  Pid;                                 // ADD/REMOVE only
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_FILEMON_BYPASS_INPUT, *PMYARK_FILEMON_BYPASS_INPUT;

typedef struct _MYARK_FILEMON_BYPASS_OUTPUT {
    UINT32  Status;                              // in-band NTSTATUS
    UINT32  Applied;                             // 1 = the list changed
    UINT32  Count;                               // list size after the call
    UINT32  Reserved1;
    UINT64  BypassDrops;                         // lifetime bypassed events
    UINT32  Pids[MYARK_FILEMON_BYPASS_MAX];
    UINT32  Reserved2;
} MYARK_FILEMON_BYPASS_OUTPUT, *PMYARK_FILEMON_BYPASS_OUTPUT;

C_ASSERT(sizeof(MYARK_FILEMON_FILTER_ENTRY) == 192);
C_ASSERT(sizeof(MYARK_FILEMON_ENUM_OUTPUT) == 6160);
C_ASSERT(sizeof(MYARK_FILEMON_BYPASS_INPUT) == 88);
C_ASSERT(sizeof(MYARK_FILEMON_BYPASS_OUTPUT) == 96);
