// MyArk keyboard module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xC50..0xC5F reserved for the keyboard module. This
// module is borderline -- it reads win32k private structures (which is
// normally a [3]-class operation); the issue body keeps it in [2] because
// the semantic is "read", and the win32k.sys mapping is best-effort.
//
// The keyboard module reads (read-only):
//
//   ENUM_HOTKEYS        -- RegisterHotKey targets registered by every
//                          GUI thread (via thread info aphkStart)
//   ENUM_HOOKS          -- WH_KEYBOARD_LL / WH_MOUSE_LL hooks via
//                          tagHOOK->phkNext chain (depth 1024 hard cap)
//
// Win32k private struct offsets (tagTHREADINFO->aphkStart,
// tagHOOK->phkNext) shift between Windows builds; we hard-code the
// offsets for Win11 24H2 / build 26100.x and explicitly mark this
// module as TODO for cross-build portability (see plan v3 [S6.10] risk).
// When the offsets are wrong every entry comes back as STATUS_NOT_FOUND
// or the chain breaks early; R3 surfaces this as "no hooks" rather
// than silently returning zero.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL codes.
// ---------------------------------------------------------------------------

#define MYARK_KEYBOARD_MODULE_ID            0x4442594BUL  // 'KYBD' ASCII (LE)
#define MYARK_KEYBOARD_HOTKEY_DESC_MAX       64
#define MYARK_KEYBOARD_HOOK_MODULE_MAX       64
#define MYARK_KEYBOARD_HOTKEY_DEFAULT_MAX    64
#define MYARK_KEYBOARD_HOOK_DEFAULT_MAX      64
#define MYARK_KEYBOARD_HOOK_CHAIN_HARD_CAP   1024

//
// 2 IOCTLs (function range 0xC50..0xC51). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_KEYBOARD_ENUM_HOTKEYS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC50, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_KEYBOARD_ENUM_HOOKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC51, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// ENUM_HOTKEYS output: one row per (Tid, hotkey id) pair.
//
// The driver scans every GUI thread's tagTHREADINFO->aphkStart[] array;
// each non-zero slot is an active hotkey registration. The hotkey id is
// the index, the description is the registered atom name (best-effort
// resolution via UserGetAtomName -- empty string if the atom was deleted).
// ---------------------------------------------------------------------------

typedef struct _MYARK_HOTKEY_ENTRY {
    UINT32  Tid;                                            // owning thread
    UINT32  Pid;                                            // owning process (best-effort)
    UINT32  HotkeyId;                                       // slot index in aphkStart
    UINT32  VirtualKey;                                     // VK_*
    UINT32  Modifiers;                                      // MOD_ALT / MOD_CONTROL / MOD_SHIFT / MOD_WIN / MOD_NOREPEAT
    UINT32  Reserved0;
    WCHAR   Description[MYARK_KEYBOARD_HOTKEY_DESC_MAX];    // atom name (best-effort)
} MYARK_HOTKEY_ENTRY, *PMYARK_HOTKEY_ENTRY;

typedef struct _MYARK_KEYBOARD_ENUM_HOTKEYS_INPUT {
    UINT32  MaxEntries;                                     // 0 = driver default
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_KEYBOARD_ENUM_HOTKEYS_INPUT, *PMYARK_KEYBOARD_ENUM_HOTKEYS_INPUT;

typedef struct _MYARK_KEYBOARD_ENUM_HOTKEYS_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved;
    MYARK_HOTKEY_ENTRY Entries[1];
} MYARK_KEYBOARD_ENUM_HOTKEYS_OUTPUT, *PMYARK_KEYBOARD_ENUM_HOTKEYS_OUTPUT;

// ---------------------------------------------------------------------------
// ENUM_HOOKS output: one row per tagHOOK entry on the chain.
//
// Hook type comes from the WH_* constants. The owning thread tid is the
// thread that installed the hook (tagHOOK->head.ptid). The module name
// is best-effort from tagHOOK->head.lpfn -> PsLoadedModuleList reverse
// lookup; it is empty when the function lives outside any known module.
// ---------------------------------------------------------------------------

#define MYARK_HOOK_FLAG_NONE                0x00000000
#define MYARK_HOOK_FLAG_GLOBAL              0x00000001   // WH_*_LL or WH_CALLWNDPROC etc.
#define MYARK_HOOK_FLAG_ANSI                0x00000002   // WH_CALLWNDPROC vs WH_CALLWNDPROCRET etc.
#define MYARK_HOOK_FLAG_SUSPECT             0x00000004   // hook function outside known module

typedef struct _MYARK_HOOK_ENTRY {
    UINT64  HookObjectAddress;                              // kernel VA of the tagHOOK
    UINT64  FunctionAddress;                                // user-mode callback address
    UINT32  HookType;                                       // WH_KEYBOARD_LL etc.
    UINT32  Flags;                                          // MYARK_HOOK_FLAG_*
    UINT32  OwningTid;
    UINT32  Reserved0;
    WCHAR   ModuleName[MYARK_KEYBOARD_HOOK_MODULE_MAX];     // best-effort; empty on miss
} MYARK_HOOK_ENTRY, *PMYARK_HOOK_ENTRY;

typedef struct _MYARK_KEYBOARD_ENUM_HOOKS_INPUT {
    UINT32  MaxEntries;                                     // 0 = driver default
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_KEYBOARD_ENUM_HOOKS_INPUT, *PMYARK_KEYBOARD_ENUM_HOOKS_INPUT;

typedef struct _MYARK_KEYBOARD_ENUM_HOOKS_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  ChainDepthMax;                                  // longest chain we walked before the hard cap
    UINT32  Reserved;
    MYARK_HOOK_ENTRY Entries[1];
} MYARK_KEYBOARD_ENUM_HOOKS_OUTPUT, *PMYARK_KEYBOARD_ENUM_HOOKS_OUTPUT;
