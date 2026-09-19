// MyArk keyboard module: IOCTL handlers.
//
// win32k private struct access. The offsets are pinned to Win11 24H2;
// cross-build portability is a S7 (DynData) concern.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkKeyboardIoctl.h"
#include "keyboard_descriptor.h"
#include "keyboard_internal.h"

#if MYARK_MODULE_KEYBOARD

NTSTATUS
PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD* Thread);

static
PVOID
MyArkKeyboardGetWin32ThreadInfo(
    _In_ PETHREAD Thread)
//
// Resolve ETHREAD.Tcb.Win32Thread. Returns NULL if the thread has no
// GUI context.
//
{
    if (Thread == NULL || !MmIsAddressValid(Thread)) {
        return NULL;
    }
    PVOID win32Thread = *(PVOID*)((PUCHAR)Thread + MYARK_OFF_ETHREAD_WIN32_THREAD);
    if (win32Thread == NULL || !MmIsAddressValid(win32Thread)) {
        return NULL;
    }
    return win32Thread;
}

static
ULONG
MyArkKeyboardWalkHotkeys(
    _Out_writes_(MaxEntries) PMYARK_HOTKEY_ENTRY OutEntries,
    _In_  ULONG MaxEntries,
    _Out_ PULONG TotalSeenOut)
//
// Walk every ETHREAD (via PsLookupThreadByThreadId is too heavy; we use
// the system thread list -- the kernel keeps one in PsActiveProcessHead's
// threads). For this stage we emit a single best-effort row per thread
// that has a non-empty aphkStart array.
//
{
    //
    // The kernel does not export a "list all threads" API. We use a
    // conservative approach: for each thread on the current process we
    // inspect the array; cross-process is left for S7.
    //
    // Walking all threads via undocumented PsEnumThreadByThreadCost is
    // also out of scope here -- R3 owns the cross-process view.
    //
    *TotalSeenOut = 0;

    HANDLE threadId = PsGetCurrentThreadId();
    PETHREAD thread = NULL;
    if (!NT_SUCCESS(PsLookupThreadByThreadId(threadId, &thread))) {
        return 0;
    }

    PVOID ti = MyArkKeyboardGetWin32ThreadInfo(thread);
    if (ti == NULL) {
        ObDereferenceObject(thread);
        return 0;
    }

    PUCHAR aphkBase = (PUCHAR)ti + MYARK_OFF_TI_APHK_START;
    if (!MmIsAddressValid(aphkBase)) {
        ObDereferenceObject(thread);
        return 0;
    }

    //
    // aphkStart is a HHOOK array of 16 entries. A non-NULL slot is an
    // active hotkey registration. We do not dereference the slot -- the
    // HHOOK is a pointer to a tagHOOK and the tagHOOK struct is large.
    //
    PVOID* slots = (PVOID*)aphkBase;
    ULONG written = 0;
    for (ULONG i = 0; i < 16 && written < MaxEntries; i++) {
        if (slots[i] == NULL) {
            continue;
        }

        PMYARK_HOTKEY_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->Tid = HandleToULong(threadId);
        row->Pid = HandleToULong(PsGetCurrentProcessId());
        row->HotkeyId = i;
        row->VirtualKey = 0;
        row->Modifiers = 0;
        RtlStringCbCopyW(row->Description, sizeof(row->Description), L"<hotkey>");
        written++;
    }

    *TotalSeenOut = written;
    ObDereferenceObject(thread);
    return written;
}

static
ULONG
MyArkKeyboardWalkHooks(
    _Out_writes_(MaxEntries) PMYARK_HOOK_ENTRY OutEntries,
    _In_  ULONG MaxEntries,
    _Out_ PULONG ChainDepthMax)
//
// Walk a hook chain starting from a known entry point. We accept the
// current thread's tagTHREADINFO->aphkStart[WH_KEYBOARD_LL] as the start
// of the global chain -- actually that's per-thread, so the real chain
// starts from gpWinEventHooks (which is unexported). For this stage we
// simply walk the current thread's chain and return what we see -- R3
// joins per-thread views.
//
{
    *ChainDepthMax = 0;

    HANDLE threadId = PsGetCurrentThreadId();
    PETHREAD thread = NULL;
    if (!NT_SUCCESS(PsLookupThreadByThreadId(threadId, &thread))) {
        return 0;
    }

    PVOID ti = MyArkKeyboardGetWin32ThreadInfo(thread);
    if (ti == NULL) {
        ObDereferenceObject(thread);
        return 0;
    }

    //
    // The first slot of aphkStart (index 0) is the head of the LL chain
    // in some build configurations; in others the chain head is at the
    // WH_KEYBOARD_LL slot directly. Without verification we just walk
    // whatever slot is non-NULL.
    //
    PUCHAR aphkBase = (PUCHAR)ti + MYARK_OFF_TI_APHK_START;
    if (!MmIsAddressValid(aphkBase)) {
        ObDereferenceObject(thread);
        return 0;
    }

    PVOID* slots = (PVOID*)aphkBase;
    ULONG written = 0;
    ULONG deepest = 0;

    for (ULONG slot = 0; slot < 16 && written < MaxEntries; slot++) {
        PVOID hook = slots[slot];
        ULONG depth = 0;

        while (hook != NULL
               && depth < MYARK_KEYBOARD_HOOK_CHAIN_LIMIT
               && written < MaxEntries) {

            if (!MmIsAddressValid(hook)) {
                break;
            }

            PMYARK_HOOK_ENTRY row = &OutEntries[written];
            RtlZeroMemory(row, sizeof(*row));
            row->HookObjectAddress = (UINT64)hook;
            row->OwningTid = HandleToULong(threadId);
            row->HookType  = *(PUINT32)((PUCHAR)hook + MYARK_OFF_HOOK_TYPE);
            row->FunctionAddress = *(PUINT64)((PUCHAR)hook + MYARK_OFF_HOOK_FUNCTION);
            row->Flags = MYARK_HOOK_FLAG_GLOBAL;
            written++;
            depth++;

            PVOID next = *(PVOID*)((PUCHAR)hook + MYARK_OFF_HOOK_HEAD_NEXT);
            if (next == hook) {
                break;       // self-loop defensive guard
            }
            hook = next;
        }

        if (depth > deepest) {
            deepest = depth;
        }
    }

    *ChainDepthMax = deepest;
    ObDereferenceObject(thread);
    return written;
}

NTSTATUS
MyArkKeyboardIoctlEnumHotkeys(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_KEYBOARD_ENUM_HOTKEYS_INPUT      inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_KEYBOARD_ENUM_HOTKEYS_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_KEYBOARD_ENUM_HOTKEYS_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_KEYBOARD_ENUM_HOTKEYS_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_KEYBOARD_ENUM_HOTKEYS_OUTPUT out = (PMYARK_KEYBOARD_ENUM_HOTKEYS_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_KEYBOARD_ENUM_HOTKEYS_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_KEYBOARD_ENUM_HOTKEYS_OUTPUT, Entries[0]))
                               / sizeof(MYARK_HOTKEY_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_KEYBOARD_HOOK_DEFAULT_MAX) {
        maxEntries = MYARK_KEYBOARD_HOOK_DEFAULT_MAX;
    }

    ULONG totalSeen = 0;
    ULONG written = MyArkKeyboardWalkHotkeys(out->Entries, maxEntries, &totalSeen);

    out->Size      = (UINT32)(FIELD_OFFSET(MYARK_KEYBOARD_ENUM_HOTKEYS_OUTPUT, Entries[0])
                              + written * sizeof(MYARK_HOTKEY_ENTRY));
    out->Count     = written;
    out->TotalSeen = totalSeen;
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkKeyboardIoctlEnumHooks(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_KEYBOARD_ENUM_HOOKS_INPUT        inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_KEYBOARD_ENUM_HOOKS_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_KEYBOARD_ENUM_HOOKS_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_KEYBOARD_ENUM_HOOKS_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_KEYBOARD_ENUM_HOOKS_OUTPUT out = (PMYARK_KEYBOARD_ENUM_HOOKS_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, FIELD_OFFSET(MYARK_KEYBOARD_ENUM_HOOKS_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                                - FIELD_OFFSET(MYARK_KEYBOARD_ENUM_HOOKS_OUTPUT, Entries[0]))
                               / sizeof(MYARK_HOOK_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_KEYBOARD_HOOK_CHAIN_HARD_CAP) {
        maxEntries = MYARK_KEYBOARD_HOOK_CHAIN_HARD_CAP;
    }

    ULONG deepest = 0;
    ULONG written = MyArkKeyboardWalkHooks(out->Entries, maxEntries, &deepest);

    out->Size           = (UINT32)(FIELD_OFFSET(MYARK_KEYBOARD_ENUM_HOOKS_OUTPUT, Entries[0])
                                   + written * sizeof(MYARK_HOOK_ENTRY));
    out->Count          = written;
    out->ChainDepthMax  = deepest;
    *BytesReturned      = out->Size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_KEYBOARD
