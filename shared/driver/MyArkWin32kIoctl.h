// MyArk win32k module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x770..0x773. Win32k inspection is read-only:
//   0x770  ENUMERATE_GUI_THREADS - S7.3 stub (Count=0)
//   0x771  ENUMERATE_HOOKS       - S7.3 stub (Count=0)
//   0x772  ENUM_USER_HANDLES     - R3-10a: caller-process USER handle
//                                  table via user32!gSharedInfo (Tier B)
//   0x773  ENUM_TIMERS           - R3-10b-iii: session window/thread
//                                  timers via win32kbase!gTimerHashTable
//                                  (Tier B: session base from the module
//                                  list, node offsets KDNET-calibrated)
//
// All IOCTLs use the MyArk METHOD_BUFFERED convention. Threat model note:
// 0x772/0x773 dereference caller-context session data (gSharedInfo /
// gTimerHashTable), but only through a guarded reader inside the caller's
// own context -- the device SDDL (SYSTEM+Admins) matches the rest of the
// forensic surface.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_WIN32K_MODULE_ID                0x574E324BUL  // 'WN2K' ASCII (LE)
#define MYARK_WIN32K_THREAD_NAME_MAX          64
#define MYARK_WIN32K_HARD_CAP                 64

//
// 2 IOCTLs (function range 0x770..0x771). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_WIN32K_ENUMERATE_GUI_THREADS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x770, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_WIN32K_ENUMERATE_HOOKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x771, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// ENUMERATE_GUI_THREADS output: GUI thread descriptors.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_WIN32K_GUI_THREAD_ENTRY {
    UINT32  ThreadId;
    UINT32  ProcessId;
    UINT64  ThreadAddress;
    UINT64  MessageQueueAddress;
    UINT32  Flags;                                // bit0 = has-window, bit1 = has-monitor
    UINT32  Reserved;
    WCHAR   ThreadName[MYARK_WIN32K_THREAD_NAME_MAX];
} MYARK_WIN32K_GUI_THREAD_ENTRY, *PMYARK_WIN32K_GUI_THREAD_ENTRY;

typedef struct _MYARK_WIN32K_GUI_THREADS_OUTPUT {
    UINT32  Count;
    UINT32  Reserved;
    MYARK_WIN32K_GUI_THREAD_ENTRY Entries[1];
} MYARK_WIN32K_GUI_THREADS_OUTPUT, *PMYARK_WIN32K_GUI_THREADS_OUTPUT;

//
// ENUMERATE_HOOKS output: discovered win32k hooks (syscall table entries).
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_WIN32K_HOOK_ENTRY {
    UINT32  SyscallIndex;
    UINT32  Flags;                                // bit0 = hooked
    UINT64  OriginalAddress;
    UINT64  CurrentAddress;
    WCHAR   ModuleName[MYARK_WIN32K_THREAD_NAME_MAX];
} MYARK_WIN32K_HOOK_ENTRY, *PMYARK_WIN32K_HOOK_ENTRY;

typedef struct _MYARK_WIN32K_HOOKS_OUTPUT {
    UINT32  Count;
    UINT32  Reserved;
    MYARK_WIN32K_HOOK_ENTRY Entries[1];
} MYARK_WIN32K_HOOKS_OUTPUT, *PMYARK_WIN32K_HOOKS_OUTPUT;

// ---------------------------------------------------------------------------
// 0x772 ENUM_USER_HANDLES (R3-10a).
//
// Walks the caller-process USER handle table through user32!gSharedInfo
// (resolved via the caller's PEB->Ldr module list + user32 export table --
// Tier B, no win32k internal offsets). One row per live handle entry
// {index, kernel object (win32k session space), user mirror, type, flags}.
// Covers windows / menus / icons / hooks / call procedures / accelerator
// tables ... session-wide. Must run in the context of a GUI process (the
// IOCTL caller), PASSIVE_LEVEL.
//
// Type ids are the classic win32k TYPE_* values (TYPE_FREE=0, TYPE_WINDOW=1,
// TYPE_MENU=2, TYPE_ICON=3, TYPE_SETWINDOWPOS=4, TYPE_HOOK=5, ...).
// Calibrated on 1903/22631 user-mapped aheList (HeEntrySize=32): USHORT
// type @24, unique/generation @26; the kernel pointer field @0 is masked
// to 0 in the user copy. Liveness = type in 1..0x40; a freed slot can
// retain stale generation bytes, so any-nonzero is NOT a live test.
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_WIN32K_ENUM_USER_HANDLES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x772, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_WIN32K_HANDLE_CAP               2048

typedef struct _MYARK_WIN32K_USER_HANDLE_ENTRY {
    UINT32  Index;                               // slot index in aheList
    UINT32  Type;                                // win32k TYPE_* raw value
    UINT32  Flags;                               // HANDLEENTRY.bFlags raw
    UINT32  Reserved;
    UINT64  KernelObject;                        // HANDLEENTRY.pHead (win32k)
    UINT64  UserPointer;                         // HANDLEENTRY.pUser
} MYARK_WIN32K_USER_HANDLE_ENTRY, *PMYARK_WIN32K_USER_HANDLE_ENTRY;

typedef struct _MYARK_WIN32K_USER_HANDLES_OUTPUT {
    UINT32  Count;                               // rows written
    UINT32  DiagStatus;                          // NTSTATUS of deepest failure
    UINT64  SharedInfo;                          // user32!gSharedInfo VA
    UINT64  AheList;                             // handle table base
    UINT32  HeEntrySize;                         // measured 32 (16/24/32 accepted)
    UINT32  ScannedSlots;                        // slots scanned before stop
    UINT32  Truncated;                           // 1 = live rows beyond CAP
    UINT32  Reserved;
    UINT64  Win32kBase;                          // win32kbase session base (0 = unresolved)
    UINT64  KernelAheList;                       // KERNEL handle table (real pHead; 0 = unresolved)
    UINT64  KernelPsi;                           // kernel SERVERINFO pointer
    UINT32  PsiMatch;                            // 1 = kernel psi == user copy psi
    UINT32  Reserved2;
    MYARK_WIN32K_USER_HANDLE_ENTRY Entries[MYARK_WIN32K_HANDLE_CAP];
} MYARK_WIN32K_USER_HANDLES_OUTPUT, *PMYARK_WIN32K_USER_HANDLES_OUTPUT;

// ---------------------------------------------------------------------------
// 0x773 ENUM_TIMERS (R3-10b-iii).
//
// Walks the session timer hash table win32kbase!gTimerHashTable (64
// LIST_ENTRY buckets, 1 KB -- KDNET-calibrated) in the caller's session
// context and reports one row
// per TIMER node: window timers (SetTimer(hwnd, id, ms, proc)) AND thread
// timers (SetTimer(NULL, ...)), including internal system timers -- the
// surface rootkit- and malware-timer forensics cares about.
//
// The session base comes from SystemModuleInformation (win32k trio listed
// there, same route as 0x772's kernel table); gTimerHashTable sits at a
// per-build RVA (KDNET-calibrated: 18362/18363 = 0x215de0). TIMER node
// offsets (sizeof = 0xA0) were calibrated on 1903 by dumping nodes for
// probe timers with known ids (double-sample: nID 0x4343/0x4444 found at
// +0x90, elapse 10000 at +0x58, shared pti at +0x48, shared window at
// +0x88); the verifier re-validates the calibrated build at run time
// with its own marker timers.
//
// Build gating: on builds without a differential TIMER calibration
// (22631: the table at RVA 0x288320 links non-TIMER pool tags) the IOCTL
// refuses cleanly with DiagStatus = STATUS_NOT_IMPLEMENTED and Count = 0
// instead of fabricating rows from another build's offsets.
//
// Membership semantics (KDNET-proven, 1903): a TIMER node's hash
// membership churns -- nodes link/unlink across ticks while armed, a
// fired timer with an undispatched WM_TIMER drops out, and nodes killed
// via KillTimer can linger. 0x773 reports the table AS IT IS (raw
// values); forensic consumers must treat it as a churny window onto
// timer state, not a complete registry of every SetTimer.
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_WIN32K_ENUM_TIMERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x773, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_WIN32K_TIMER_CAP                256

typedef struct _MYARK_WIN32K_TIMER_ENTRY {
    UINT32  Index;                               // ordinal in this report
    UINT32  TimerId;                             // TIMER.nID (raw, any value)
    UINT32  ElapseMs;                            // TIMER.uElapse
    UINT32  Flags;                               // TIMER dword @+0x60 (raw)
    UINT64  Pti;                                 // owning PTHREADINFO
    UINT64  TimerProc;                           // user-mode proc (0 = none)
    UINT64  Window;                              // kernel PWND (0 = thread timer)
    UINT64  Node;                                // TIMER node kernel VA
} MYARK_WIN32K_TIMER_ENTRY, *PMYARK_WIN32K_TIMER_ENTRY;

typedef struct _MYARK_WIN32K_TIMERS_OUTPUT {
    UINT32  Count;                               // rows written
    UINT32  DiagStatus;                          // NTSTATUS of deepest failure
    UINT64  TimerHashTable;                      // kernel gTimerHashTable VA
    UINT64  SessionBase;                         // win32kbase session base
    UINT32  BucketCount;                         // always 64 (1 KB table)
    UINT32  NodeSize;                            // calibrated sizeof(TIMER)
    UINT32  ScannedBuckets;                      // buckets walked before stop
    UINT32  Truncated;                           // 1 = live rows beyond CAP
    UINT64  TimerHashRva;                        // profile RVA used (diag)
    UINT32  Reserved2;                           // resolver stage breadcrumb
    UINT32  Reserved3;
    UINT64  Reserved4;
    MYARK_WIN32K_TIMER_ENTRY Entries[MYARK_WIN32K_TIMER_CAP];
} MYARK_WIN32K_TIMERS_OUTPUT, *PMYARK_WIN32K_TIMERS_OUTPUT;
