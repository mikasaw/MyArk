// MyArk keyboard module: within-module offsets + helpers.
//
// Win32k private structs. The offsets below target Windows 11 24H2 /
// build 26100.x. S7.1 (DynData) replaces these with runtime-loaded
// profiles.
//
// ETHREAD layout (24H2):
//   0x060 Tcb           (KTHREAD)
//   0x1A8 Win32Thread   (PETHREAD->Tcb.Win32Thread pointer)
//   ... offset varies between builds; 0x1A8 is best-effort.
//
// tagTHREADINFO layout (24H2, win32kfull.sys):
//   0x090 aphkStart     -- HHOOK[] array (16 entries)
//
// tagHOOK layout (24H2, win32kfull.sys):
//   0x018 head          -- _THRDESKHEAD (next = phkNext, tid, ...)
//   0x020 phkNext       -- next tagHOOK in the chain
//   0x04c iHook         -- WH_* type
//
// These offsets are subject to shift across builds. When they are wrong
// the walk returns STATUS_NOT_FOUND or the chain breaks early; R3
// surfaces this as "no hooks visible".

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "../../../shared/driver/MyArkKeyboardIoctl.h"

#if MYARK_MODULE_KEYBOARD

//
// ETHREAD.Tcb.Win32Thread offset -- best-effort for 24H2.
//
#define MYARK_OFF_ETHREAD_WIN32_THREAD         0x1A8UL

//
// tagTHREADINFO.aphkStart offset (24H2).
//
#define MYARK_OFF_TI_APHK_START                0x090UL

//
// tagHOOK.head + tagHOOK.phkNext offsets (24H2).
//
#define MYARK_OFF_HOOK_HEAD_NEXT               0x020UL
#define MYARK_OFF_HOOK_HEAD_TID                0x018UL
#define MYARK_OFF_HOOK_TYPE                    0x04CUL
#define MYARK_OFF_HOOK_FUNCTION                0x02CUL

//
// Maximum depth of the hook chain we are willing to walk -- defensive
// cap so a malicious chain can't hang the dispatcher.
//
#define MYARK_KEYBOARD_HOOK_CHAIN_LIMIT        1024UL

#define MYARK_TRACE_KEYBOARD                   MYARK_TRACE_MODULE

#endif // MYARK_MODULE_KEYBOARD
