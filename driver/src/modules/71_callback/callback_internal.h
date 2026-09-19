// MyArk callback module: internal offsets + helpers (compile-time only).
//
// PS / Cm / Ob / Image / Dbg callback-array offsets are pinned to Windows
// 11 24H2 / build 26100.x. The S7.2 release does not mutate any of the
// structures -- the IOCTL set is read-only -- so the only resolved pointers
// we cache are the array heads themselves. Driver-name resolution is best-
// effort (PsGetDriverImageInfoFromVfptr-style walk) and silently degrades
// to "unknown" when the loader state is too cold to read.
//
// Suppressions (kept local to this header):
//   4201 -- unnamed struct/union (LIST_ENTRY and friends are standard)
//   4214 -- non-int bitfield (Cm / Ob callback cookie union uses non-int)

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "module_descriptor.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkCallbackIoctl.h"

#if MYARK_MODULE_CALLBACK

#pragma warning(push)
#pragma warning(disable: 4201 4214)

//
// Tracing helper: assign a stable prefix for callback-module lines.
//
#define MYARK_TRACE_CALLBACK                  MYARK_TRACE_MODULE

//
// ---------------------------------------------------------------------------
// PS callback array bounds (Win11 24H2 / build 26100.x). The PS array is
// three parallel arrays of PCREATE_PROCESS_NOTIFY_ROUTINE_EX-style slots;
// each array's slot count is hardcoded at link time and the dispatch
// tables point at the array head.
// ---------------------------------------------------------------------------
//

#define MYARK_CALLBACK_PS_PROCESS_SLOTS       64
#define MYARK_CALLBACK_PS_THREAD_SLOTS        64
#define MYARK_CALLBACK_PS_IMAGE_SLOTS         64

//
// ---------------------------------------------------------------------------
// Cm callback list head offset (Win11 24H2). The Cm callback registry uses
// a singly-linked list of CALLBACK_OBJECT items rooted at CmpCallbackListHead.
// Each CALLBACK_OBJECT holds an Altitude string + the actual callback
// function pointer + the cookie that the kernel hands to registered
// callers.
// ---------------------------------------------------------------------------
//

#define MYARK_CALLBACK_CM_LIST_HEAD_OFFSET    0x000UL  // resolved via MmGetSystemRoutineAddress

//
// ---------------------------------------------------------------------------
// Ob callback list head offset (Win11 24H2). ObRegisterCallbacks allocates
// a CALLBACK_OBJECT per registration; the list is rooted at ObCallbackListHead.
// ---------------------------------------------------------------------------
//

#define MYARK_CALLBACK_OB_LIST_HEAD_OFFSET    0x000UL  // resolved via MmGetSystemRoutineAddress

//
// ---------------------------------------------------------------------------
// Image notify array head (Win11 24H2). PspLoadImageNotifyRoutine points
// at the first slot of a 64-slot array; the QUERY_IMAGE walker reads up to
// IMAGE_SLOTS rows from it.
// ---------------------------------------------------------------------------
//

#define MYARK_CALLBACK_IMAGE_SLOTS            64

//
// ---------------------------------------------------------------------------
// DbgkDebugObjectType + debugger object list (Win11 24H2). DbgkDebugObjectType
// is exported by ntoskrnl and points at the OBJECT_TYPE for debug objects.
// The bound debugger table is a flat array of 4 KDEBUG_OBJECT pointers.
// ---------------------------------------------------------------------------
//

#define MYARK_CALLBACK_DBG_BOUND_SLOTS        4

//
// ---------------------------------------------------------------------------
// Forward decls for kernel exports not in the public WDK headers.
//
struct _CALLBACK_OBJECT;
typedef struct _CALLBACK_OBJECT *PCALLBACK_OBJECT;

//
// Forward-export resolver state for the 5 array heads.
//
extern PVOID g_MyArkCallbackPspCreateProcessNotifyRoutine;
extern PVOID g_MyArkCallbackPspCreateThreadNotifyRoutine;
extern PVOID g_MyArkCallbackPspLoadImageNotifyRoutine;
extern PVOID g_MyArkCallbackCmpCallbackListHead;
extern PVOID g_MyArkCallbackObCallbackListHead;
extern PVOID g_MyArkCallbackDbgkDebugObjectType;
extern PVOID g_MyArkCallbackPsNtDebuggerObject;

extern UINT64 g_MyArkCallbackNtoskrnlTextBase;
extern UINT64 g_MyArkCallbackNtoskrnlTextEnd;

//
// Forward-export resolver: called from MyArkCallbackInit, also lazy on each
// IOCTL handler that needs a particular symbol. The lazy path probes each
// uninitialised field and stops on the first failure.
//
NTSTATUS
MyArkCallbackPagetableResolveAll(
    VOID);

//
// Safe read helper used by every IOCTL walker. Returns the number of bytes
// actually copied (capped at RequestedSize) -- 0 if the source pointer is
// not resident.
//
ULONG
MyArkCallbackSafeRead(
    _In_  PVOID Source,
    _Out_writes_bytes_(RequestedSize) PUCHAR Destination,
    _In_  ULONG RequestedSize);

//
// Copy a UNICODE_STRING into a UTF-8 byte buffer with NUL terminator.
// Used for kernel-side DriverName / Altitude rendering.
//
ULONG
MyArkCallbackReadUnicodeString(
    _In_  PUNICODE_STRING Source,
    _Out_writes_bytes_(BufferBytes) PUCHAR Dest,
    _In_  ULONG  BufferBytes);

//
// Convert a kernel VA to its ntoskrnl .text relative flag. Returns the
// MYARK_CALLBACK_FLAG_* bits the walker should attach to a row.
//
UINT32
MyArkCallbackAddressFlags(
    _In_  UINT64 Address,
    _In_  UINT64 TextBase,
    _In_  UINT64 TextEnd);

//
// Best-effort driver-name lookup for a given callback kernel VA. Walks the
// PsLoadedModuleList to find the module that owns the address; on success
// writes the base DLL name into the UTF-8 buffer and returns the byte
// count copied (0 = unknown driver).
//
// The PsLoadedModuleList pointer is imported from the dyndata module via
// an extern -- S7.1 already resolves it; S7.2 only reads.
//
ULONG
MyArkCallbackResolveDriverName(
    _In_  UINT64 CallbackAddress,
    _Out_writes_bytes_(BufferBytes) PUCHAR Buffer,
    _In_  ULONG  BufferBytes);

#pragma warning(pop)

//
// Process-creation rule engine (callback_rules.c, R2-6).
//
NTSTATUS
MyArkRulesInit(
    VOID);

VOID
MyArkRulesCleanup(
    VOID);

VOID
MyArkRulesProcessNotify(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO Info);

//
// ObCallbacks STRIP_ACCESS (callback_obprotect.c, R3-9).
//
NTSTATUS
MyArkObProtInit(
    VOID);

NTSTATUS
MyArkObProtArm(
    VOID);

VOID
MyArkObProtDisarm(
    VOID);

NTSTATUS
MyArkObProtSet(
    _In_ UINT32 Action,
    _In_ UINT32 Pid,
    _Out_ PMYARK_CALLBACK_OB_PROTECT_SET_OUTPUT Output);

NTSTATUS
MyArkObProtFillStatus(
    _Out_ PMYARK_CALLBACK_OB_PROTECT_STATUS_OUTPUT Output);

//
// Process-creation rule engine (callback_rules.c, R2-6).
//
VOID
MyArkAskInit(
    VOID);

VOID
MyArkAskFailOpenAll(
    VOID);

BOOLEAN
MyArkAskPark(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_reads_(NameChars) PCWSTR Name,
    _In_ USHORT NameChars);

#endif // MYARK_MODULE_CALLBACK