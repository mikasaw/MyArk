// MyArk win32k module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x770..0x772. Win32k inspection is read-only:
//   0x770  ENUMERATE_GUI_THREADS - S7.3 stub (Count=0)
//   0x771  ENUMERATE_HOOKS       - S7.3 stub (Count=0)
//   0x772  ENUM_USER_HANDLES     - R3-10a: caller-process USER handle
//                                  table via user32!gSharedInfo (Tier B)
//
// All IOCTLs use the MyArk METHOD_BUFFERED convention. Threat model note:
// 0x772 dereferences caller-supplied user data (gSharedInfo/aheList), but
// only through a guarded reader inside the caller's own context -- the
// device SDDL (SYSTEM+Admins) matches the rest of the forensic surface.

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
