// MyArk win32k module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x770..0x771 reserved for the win32k module (S7.3).
// Win32k inspection is read-only for S7.3: the IOCTL set enumerates
// GUI threads and any registered win32k hooks on the running build.
// Mutation IOCTLs are reserved for the S7.3-fix stage.
//
// The 2 IOCTLs:
//
//   0x770  ENUMERATE_GUI_THREADS - List all GUI threads
//   0x771  ENUMERATE_HOOKS       - List win32k hooks (syscall table)
//
// All 2 IOCTLs use the MyArk METHOD_BUFFERED convention.

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