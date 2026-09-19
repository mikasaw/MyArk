// MyArk win32k module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x770..0x774. Win32k inspection is read-only:
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
// function range 0x770..0x774. Method/Access match the rest
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
//
// R3-10b-iv: when the desktop-heap kernel base is derivable for the
// build (currently 18362/18363: W32PROCESS+0x7f8 -> descriptor, base =
// *(desc-0x28), KDNET-calibrated) and the per-row self-check passes, the
// row KernelObject carries the TRUE kernel object pointer (heap base +
// record offset, verified against the object's own handle field).
// Otherwise it stays 0/masked exactly as the user copy reads.
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
    UINT32  PsiMatch;                            // bit0 = kernel psi == user copy psi;
                                                 // bit1 = desktop-heap base derived AND
                                                 // >=1 row self-validated against it
                                                 // (W32P candidate scan, rows hdr-checked)
    UINT32  Reserved2;                           // DIAG breadcrumb: resolver
                                                 // stage 1..6, or 0x100|hstage
                                                 // for heap-derivation failure
                                                 // (0x11 no W32PROCESS,
                                                 // 0x12 no structural candidate,
                                                 // 0x13 candidates but 0 rows
                                                 // validated, 0x14 scan aborted);
                                                 // 0x0 = scan not run (no
                                                 // profile row) or derivation
                                                 // proven (see PsiMatch bit1)
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

// ---------------------------------------------------------------------------
// 0x774 ENUM_EVENTHOOKS (R3-10c).
//
// Walks the session WinEvent hook list win32kbase!gpWinEventHooks in the
// caller's session context and reports one row per registered
// SetWinEventHook: the filter (EventMin/EventMax), the user-mode callback,
// the process/thread scoping, and the hook's USER handle (type 15 row in
// the 0x772 table). Forensic value: WinEvent surveillance is a common
// monitoring/persistence primitive and these rows are the only place the
// filter/callback pairing is visible.
//
// List semantics (KDNET-calibrated, 1903): gpWinEventHooks points at the
// most recently registered EVENTHOOK; nodes chain via a single next
// pointer @+0x18, NULL-terminated (LIFO). Node offsets (see
// win32k_walker.c) were calibrated on 1903 with three probe hooks carrying
// distinctive event-range pairs; the verifier re-validates them at run
// time with its own marker hooks, exactly like the 0x773 timer offsets.
//
// Build gating: without a differential EVENTHOOK calibration the IOCTL
// refuses cleanly with DiagStatus = STATUS_NOT_IMPLEMENTED and Count = 0.
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_WIN32K_ENUM_EVENTHOOKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x774, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_WIN32K_EVENTHOOK_CAP            256

typedef struct _MYARK_WIN32K_EVENTHOOK_ENTRY {
    UINT32  Index;                               // ordinal in this report
    UINT32  EventMin;                            // filter low event
    UINT32  EventMax;                            // filter high event
    UINT32  FlagsInternal;                       // dword @+0x28 (dwFlags
                                                 // re-encoding; raw, diag)
    UINT32  IdProcess;                           // raw (0xFFFFFFFF = all)
    UINT32  IdThread;                            // raw (0 = all)
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT64  Handle;                              // USER handle (0x772 type 15)
    UINT64  Callback;                            // user-mode WinEventProc
    UINT64  Node;                                // EVENTHOOK node kernel VA
    UINT64  Reserved2;
} MYARK_WIN32K_EVENTHOOK_ENTRY, *PMYARK_WIN32K_EVENTHOOK_ENTRY;

typedef struct _MYARK_WIN32K_EVENTHOOKS_OUTPUT {
    UINT32  Count;                               // rows written
    UINT32  DiagStatus;                          // NTSTATUS of deepest failure
    UINT64  ListHead;                            // kernel gpWinEventHooks VA
    UINT64  SessionBase;                         // win32kbase session base
    UINT32  NodeSize;                            // calibrated node size (diag)
    UINT32  Truncated;                           // 1 = live rows beyond CAP
    UINT64  WinEventHooksRva;                    // profile RVA used (diag)
    UINT32  Reserved2;                           // resolver stage breadcrumb
    UINT32  Reserved3;
    UINT64  Reserved4;
    MYARK_WIN32K_EVENTHOOK_ENTRY Entries[MYARK_WIN32K_EVENTHOOK_CAP];
} MYARK_WIN32K_EVENTHOOKS_OUTPUT, *PMYARK_WIN32K_EVENTHOOKS_OUTPUT;
