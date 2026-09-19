// MyArk actions module: 7 IOCTL handlers.
//
// Each handler follows the MyArk IOCTL convention: fetch input/output
// buffers via MyArkIoctlFetch* helpers, validate the input size, then
// call MyArkActionsValidateToken to gate the action. In Mode A (this
// build) the destructive code path is intentionally a no-op -- the
// handler acks the request with MYARK_ACTION_RESULT_DEFERRED so R3
// sees a well-formed result. The VM verification stage (S8.1-VM,
// run by the user in the Hyper-V guest) exercises the destructive
// code path against a sandboxed process; the structure here stays
// frozen so VM verification can drop in real NtTerminateProcess /
// NtCreateThreadEx / MmCopyVirtualMemory calls without disturbing the
// public IOCTL surface.
//
// All 7 handlers emit a TraceEvents line on dispatch so the driver log
// shows every action request even when the R3 path takes the call
// instead of the driver.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkActionsIoctl.h"
#include "actions_descriptor.h"
#include "actions_internal.h"

#if MYARK_MODULE_ACTIONS

//
// ---------------------------------------------------------------------------
// KILL_PROCESS: kill a process by PID. R3 fallback is TerminateProcess
// (win32); R0 is NtTerminateProcess. Both paths require the safety
// token gate.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkActionsIoctlKillProcess(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_ACTION_KILL_INPUT                  inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_ACTION_KILL_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_ACTION_KILL_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_ACTION_KILL_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_ACTION_KILL_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // METHOD_BUFFERED: input and output share one SystemBuffer, so the
    // token MUST be validated before the output header zeroes the shared
    // buffer (zeroing first wiped the token and denied every action).
    //
    status = MyArkActionsValidateToken(&inBuf->Token,
                                        MYARK_ACTION_OP_KILL_PROCESS,
                                        inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_KILL_OUTPUT));
        PMYARK_ACTION_KILL_OUTPUT out = (PMYARK_ACTION_KILL_OUTPUT)outBuf;
        MyArkActionsInitOutputHeader(&out->Header,
                                      MYARK_ACTION_RESULT_DENIED_NO_TOKEN,
                                      MYARK_ACTION_TIER_R0,
                                      "kill_process denied: bad safety token");
        out->Pid = inBuf->Pid;
        out->ExitCode = inBuf->ExitCode;
        *BytesReturned = sizeof(MYARK_ACTION_KILL_OUTPUT);
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_KILL_OUTPUT));
    PMYARK_ACTION_KILL_OUTPUT out = (PMYARK_ACTION_KILL_OUTPUT)outBuf;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_ACTIONS,
                "MyArkActionsIoctlKillProcess: pid=%lu exit=%lu (deferred R0 in Mode A)",
                (unsigned long)inBuf->Pid,
                (unsigned long)inBuf->ExitCode);

    MyArkActionsInitOutputHeader(&out->Header,
                                  MYARK_ACTION_RESULT_DEFERRED,
                                  MYARK_ACTION_TIER_DEFERRED,
                                  "kill_process ack (R0 deferred)");
    out->Pid = inBuf->Pid;
    out->ExitCode = inBuf->ExitCode;
    *BytesReturned = sizeof(MYARK_ACTION_KILL_OUTPUT);
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// TERMINATE_THREAD: kill a single thread inside a process.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkActionsIoctlTerminateThread(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                       status;
    PMYARK_ACTION_TERMINATE_THREAD_INPUT           inBuf = NULL;
    size_t                                         inSize = 0;
    PVOID                                          outBuf = NULL;
    size_t                                         outSize = 0;

    if (InputBufferLength < sizeof(MYARK_ACTION_TERMINATE_THREAD_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_ACTION_TERMINATE_THREAD_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_ACTION_TERMINATE_THREAD_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_ACTION_TERMINATE_THREAD_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkActionsValidateToken(&inBuf->Token,
                                        MYARK_ACTION_OP_TERMINATE_THREAD,
                                        inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_TERMINATE_THREAD_OUTPUT));
        PMYARK_ACTION_TERMINATE_THREAD_OUTPUT out = (PMYARK_ACTION_TERMINATE_THREAD_OUTPUT)outBuf;
        MyArkActionsInitOutputHeader(&out->Header,
                                      MYARK_ACTION_RESULT_DENIED_NO_TOKEN,
                                      MYARK_ACTION_TIER_R0,
                                      "terminate_thread denied: bad safety token");
        out->Pid = inBuf->Pid;
        out->Tid = inBuf->Tid;
        *BytesReturned = sizeof(MYARK_ACTION_TERMINATE_THREAD_OUTPUT);
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_TERMINATE_THREAD_OUTPUT));
    PMYARK_ACTION_TERMINATE_THREAD_OUTPUT out = (PMYARK_ACTION_TERMINATE_THREAD_OUTPUT)outBuf;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_ACTIONS,
                "MyArkActionsIoctlTerminateThread: pid=%lu tid=%lu (deferred R0 in Mode A)",
                (unsigned long)inBuf->Pid,
                (unsigned long)inBuf->Tid);

    MyArkActionsInitOutputHeader(&out->Header,
                                  MYARK_ACTION_RESULT_DEFERRED,
                                  MYARK_ACTION_TIER_DEFERRED,
                                  "terminate_thread ack (R0 deferred)");
    out->Pid = inBuf->Pid;
    out->Tid = inBuf->Tid;
    out->ExitCode = inBuf->ExitCode;
    *BytesReturned = sizeof(MYARK_ACTION_TERMINATE_THREAD_OUTPUT);
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// INJECT_DLL: load a DLL into a process. R3 fallback is
// CreateRemoteThread (win32); R0 is NtCreateThreadEx.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkActionsIoctlInjectDll(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_ACTION_INJECT_DLL_INPUT          inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_ACTION_INJECT_DLL_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_ACTION_INJECT_DLL_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_ACTION_INJECT_DLL_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_ACTION_INJECT_DLL_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkActionsValidateToken(&inBuf->Token,
                                        MYARK_ACTION_OP_INJECT_DLL,
                                        inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_INJECT_DLL_OUTPUT));
        PMYARK_ACTION_INJECT_DLL_OUTPUT out = (PMYARK_ACTION_INJECT_DLL_OUTPUT)outBuf;
        MyArkActionsInitOutputHeader(&out->Header,
                                      MYARK_ACTION_RESULT_DENIED_NO_TOKEN,
                                      MYARK_ACTION_TIER_R0,
                                      "inject_dll denied: bad safety token");
        out->Pid = inBuf->Pid;
        *BytesReturned = sizeof(MYARK_ACTION_INJECT_DLL_OUTPUT);
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_INJECT_DLL_OUTPUT));
    PMYARK_ACTION_INJECT_DLL_OUTPUT out = (PMYARK_ACTION_INJECT_DLL_OUTPUT)outBuf;

    //
    // DllPath rides raw in the input buffer and may not be NUL-terminated;
    // RtlInitUnicodeString would strlen past the end of the buffered IO
    // buffer, so validate the terminator before touching it as a string.
    //
    size_t dllPathBytes = 0;
    status = RtlStringCbLengthW(inBuf->DllPath, sizeof(inBuf->DllPath), &dllPathBytes);
    if (!NT_SUCCESS(status)) {
        MyArkActionsInitOutputHeader(&out->Header,
                                      MYARK_ACTION_RESULT_DENIED,
                                      MYARK_ACTION_TIER_R0,
                                      "inject_dll denied: DllPath not NUL-terminated");
        out->Pid = inBuf->Pid;
        *BytesReturned = sizeof(MYARK_ACTION_INJECT_DLL_OUTPUT);
        return STATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING dllPath;
    RtlInitUnicodeString(&dllPath, inBuf->DllPath);
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_ACTIONS,
                "MyArkActionsIoctlInjectDll: pid=%lu path=%wZ (deferred R0 in Mode A)",
                (unsigned long)inBuf->Pid,
                &dllPath);

    MyArkActionsInitOutputHeader(&out->Header,
                                  MYARK_ACTION_RESULT_DEFERRED,
                                  MYARK_ACTION_TIER_DEFERRED,
                                  "inject_dll ack (R0 deferred)");
    out->Pid = inBuf->Pid;
    out->RemoteThreadHandle = 0;
    *BytesReturned = sizeof(MYARK_ACTION_INJECT_DLL_OUTPUT);
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// DUMP_MEMORY: copy (Address, Size) bytes out of the target process
// into the caller's output buffer. R0 is MmCopyVirtualMemory; R3 is
// ReadProcessMemory. The Size is clamped to MYARK_ACTION_DUMP_MAX_BYTES
// to keep the output struct size bounded.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkActionsIoctlDumpMemory(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_ACTION_DUMP_MEMORY_INPUT           inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_ACTION_DUMP_MEMORY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_ACTION_DUMP_MEMORY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_ACTION_DUMP_MEMORY_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_ACTION_DUMP_MEMORY_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkActionsValidateToken(&inBuf->Token,
                                        MYARK_ACTION_OP_DUMP_MEMORY,
                                        inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_DUMP_MEMORY_OUTPUT));
        PMYARK_ACTION_DUMP_MEMORY_OUTPUT out = (PMYARK_ACTION_DUMP_MEMORY_OUTPUT)outBuf;
        MyArkActionsInitOutputHeader(&out->Header,
                                      MYARK_ACTION_RESULT_DENIED_NO_TOKEN,
                                      MYARK_ACTION_TIER_R0,
                                      "dump_memory denied: bad safety token");
        out->Pid = inBuf->Pid;
        *BytesReturned = sizeof(MYARK_ACTION_DUMP_MEMORY_OUTPUT);
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_DUMP_MEMORY_OUTPUT));
    PMYARK_ACTION_DUMP_MEMORY_OUTPUT out = (PMYARK_ACTION_DUMP_MEMORY_OUTPUT)outBuf;

    UINT64 requested = inBuf->Size;
    if (requested > MYARK_ACTION_DUMP_MAX_BYTES) {
        requested = MYARK_ACTION_DUMP_MAX_BYTES;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_ACTIONS,
                "MyArkActionsIoctlDumpMemory: pid=%lu addr=0x%llX size=%llu (deferred R0 in Mode A)",
                (unsigned long)inBuf->Pid,
                (unsigned long long)inBuf->Address,
                (unsigned long long)requested);

    MyArkActionsInitOutputHeader(&out->Header,
                                  MYARK_ACTION_RESULT_DEFERRED,
                                  MYARK_ACTION_TIER_DEFERRED,
                                  "dump_memory ack (R0 deferred)");
    out->Pid = inBuf->Pid;
    out->Address = inBuf->Address;
    out->BytesReturned = 0;
    *BytesReturned = sizeof(MYARK_ACTION_DUMP_MEMORY_OUTPUT);
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// SET_TOKEN: assign a primary or impersonation token to a process.
// R0-only -- SeAssignPrimaryTokenPrivilege requires SeSinglePrivilegeCheck.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkActionsIoctlSetToken(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_ACTION_SET_TOKEN_INPUT           inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_ACTION_SET_TOKEN_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_ACTION_SET_TOKEN_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_ACTION_SET_TOKEN_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_ACTION_SET_TOKEN_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkActionsValidateToken(&inBuf->Token,
                                        MYARK_ACTION_OP_SET_TOKEN,
                                        inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_SET_TOKEN_OUTPUT));
        PMYARK_ACTION_SET_TOKEN_OUTPUT out = (PMYARK_ACTION_SET_TOKEN_OUTPUT)outBuf;
        MyArkActionsInitOutputHeader(&out->Header,
                                      MYARK_ACTION_RESULT_DENIED_NO_TOKEN,
                                      MYARK_ACTION_TIER_R0,
                                      "set_token denied: bad safety token");
        out->Pid = inBuf->Pid;
        out->TokenType = inBuf->TokenType;
        *BytesReturned = sizeof(MYARK_ACTION_SET_TOKEN_OUTPUT);
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_SET_TOKEN_OUTPUT));
    PMYARK_ACTION_SET_TOKEN_OUTPUT out = (PMYARK_ACTION_SET_TOKEN_OUTPUT)outBuf;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_ACTIONS,
                "MyArkActionsIoctlSetToken: pid=%lu token_type=%lu (deferred R0 in Mode A)",
                (unsigned long)inBuf->Pid,
                (unsigned long)inBuf->TokenType);

    MyArkActionsInitOutputHeader(&out->Header,
                                  MYARK_ACTION_RESULT_DEFERRED,
                                  MYARK_ACTION_TIER_DEFERRED,
                                  "set_token ack (R0 deferred)");
    out->Pid = inBuf->Pid;
    out->TokenType = inBuf->TokenType;
    *BytesReturned = sizeof(MYARK_ACTION_SET_TOKEN_OUTPUT);
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// HIDE_PROCESS: DKOM unlink from ActiveProcessLinks. R0-only.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkActionsIoctlHideProcess(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_ACTION_HIDE_PROCESS_INPUT          inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_ACTION_HIDE_PROCESS_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_ACTION_HIDE_PROCESS_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_ACTION_HIDE_PROCESS_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_ACTION_HIDE_PROCESS_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkActionsValidateToken(&inBuf->Token,
                                        MYARK_ACTION_OP_HIDE_PROCESS,
                                        inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_HIDE_PROCESS_OUTPUT));
        PMYARK_ACTION_HIDE_PROCESS_OUTPUT out = (PMYARK_ACTION_HIDE_PROCESS_OUTPUT)outBuf;
        MyArkActionsInitOutputHeader(&out->Header,
                                      MYARK_ACTION_RESULT_DENIED_NO_TOKEN,
                                      MYARK_ACTION_TIER_R0,
                                      "hide_process denied: bad safety token");
        out->Pid = inBuf->Pid;
        *BytesReturned = sizeof(MYARK_ACTION_HIDE_PROCESS_OUTPUT);
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_HIDE_PROCESS_OUTPUT));
    PMYARK_ACTION_HIDE_PROCESS_OUTPUT out = (PMYARK_ACTION_HIDE_PROCESS_OUTPUT)outBuf;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_ACTIONS,
                "MyArkActionsIoctlHideProcess: pid=%lu (deferred R0 in Mode A; DKOM unlink is destructive)",
                (unsigned long)inBuf->Pid);

    MyArkActionsInitOutputHeader(&out->Header,
                                  MYARK_ACTION_RESULT_DEFERRED,
                                  MYARK_ACTION_TIER_DEFERRED,
                                  "hide_process ack (R0 deferred)");
    out->Pid = inBuf->Pid;
    *BytesReturned = sizeof(MYARK_ACTION_HIDE_PROCESS_OUTPUT);
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// PROTECT_PROCESS: mark a process so subsequent TerminateProcess from
// R3 fails. R0-only; uses the PS_PROTECTION field on EPROCESS when
// available, otherwise PspSet.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkActionsIoctlProtectProcess(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                       status;
    PMYARK_ACTION_PROTECT_PROCESS_INPUT            inBuf = NULL;
    size_t                                         inSize = 0;
    PVOID                                          outBuf = NULL;
    size_t                                         outSize = 0;

    if (InputBufferLength < sizeof(MYARK_ACTION_PROTECT_PROCESS_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_ACTION_PROTECT_PROCESS_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_ACTION_PROTECT_PROCESS_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_ACTION_PROTECT_PROCESS_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkActionsValidateToken(&inBuf->Token,
                                        MYARK_ACTION_OP_PROTECT_PROCESS,
                                        inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_PROTECT_PROCESS_OUTPUT));
        PMYARK_ACTION_PROTECT_PROCESS_OUTPUT out = (PMYARK_ACTION_PROTECT_PROCESS_OUTPUT)outBuf;
        MyArkActionsInitOutputHeader(&out->Header,
                                      MYARK_ACTION_RESULT_DENIED_NO_TOKEN,
                                      MYARK_ACTION_TIER_R0,
                                      "protect_process denied: bad safety token");
        out->Pid = inBuf->Pid;
        out->Flags = inBuf->Flags;
        *BytesReturned = sizeof(MYARK_ACTION_PROTECT_PROCESS_OUTPUT);
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(outBuf, sizeof(MYARK_ACTION_PROTECT_PROCESS_OUTPUT));
    PMYARK_ACTION_PROTECT_PROCESS_OUTPUT out = (PMYARK_ACTION_PROTECT_PROCESS_OUTPUT)outBuf;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_ACTIONS,
                "MyArkActionsIoctlProtectProcess: pid=%lu flags=0x%X (deferred R0 in Mode A)",
                (unsigned long)inBuf->Pid,
                (unsigned long)inBuf->Flags);

    MyArkActionsInitOutputHeader(&out->Header,
                                  MYARK_ACTION_RESULT_DEFERRED,
                                  MYARK_ACTION_TIER_DEFERRED,
                                  "protect_process ack (R0 deferred)");
    out->Pid = inBuf->Pid;
    out->Flags = inBuf->Flags;
    *BytesReturned = sizeof(MYARK_ACTION_PROTECT_PROCESS_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_ACTIONS
