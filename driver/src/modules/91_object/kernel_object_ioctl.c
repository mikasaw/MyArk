// kernel-object module R0 IOCTL handlers (R3-4b).
//
// 0x910 ENUM_DIRECTORY - validate the requested path, walk it, ship rows.
// 0x911 IPC_SUMMARY    - one-shot walk of \Device\NamedPipe and
//                        \Device\MailSlot (the "IPC 摘要" panel).
//
// Both are read-only namespace queries via the exported Zw surface, so
// neither is SAFETY_TOKEN-gated (the token only guards mutating IOCTLs).

#include "myark_config.h"
#include "kernel_object_descriptor.h"
#include "kernel_object_internal.h"
#include "../../dispatch/ioctl_helpers.h"

#if MYARK_MODULE_KERNEL_OBJECT

// Trailing backslashes are load-bearing: the bare device name opens the
// NPFS/MSFS *control* handle (create-pipe entry point) which rejects every
// directory query; the root directory requires the trailing "\".
static const WCHAR g_MyArkKobjPipePath[] = L"\\Device\\NamedPipe\\";
static const WCHAR g_MyArkKobjMailslotPath[] = L"\\Device\\MailSlot\\";

//
// Input path validation: absolute object-manager path, NUL-terminated
// within the declared length, no interior NUL, no wildcards. Returns
// STATUS_INVALID_PARAMETER on any violation.
//
static NTSTATUS
MyArkKobjValidatePathInput(
    _In_ const MYARK_KOBJ_DIRECTORY_INPUT* Input)
{
    ULONG i;
    ULONG len = Input->PathLength;

    if (len < 2 || len > MYARK_KOBJ_PATH_MAX) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Input->DirectoryPath[len - 1] != L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    if (Input->DirectoryPath[0] != L'\\') {
        return STATUS_INVALID_PARAMETER;    // object paths are absolute
    }
    for (i = 0; i < len - 1; i++) {
        WCHAR c = Input->DirectoryPath[i];
        if (c == L'\0') {
            return STATUS_INVALID_PARAMETER;    // interior NUL
        }
        if (c == L'*' || c == L'?') {
            return STATUS_INVALID_PARAMETER;    // wildcards meaningless here
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkKobjIoctlEnumerateDirectory(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS status;
    PMYARK_KOBJ_DIRECTORY_INPUT in_buf;
    PMYARK_KOBJ_DIRECTORY_OUTPUT out_buf;
    WCHAR localPath[MYARK_KOBJ_PATH_MAX];
    size_t out_size = sizeof(MYARK_KOBJ_DIRECTORY_OUTPUT);

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_KOBJ_DIRECTORY_INPUT) ||
        OutputBufferLength < out_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_KOBJ_DIRECTORY_INPUT),
                                        (PVOID*)&in_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkKobjValidatePathInput(in_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // METHOD_BUFFERED aliases the input and output in ONE SystemBuffer:
    // copying the path out first keeps it intact when out_buf is written.
    RtlCopyMemory(localPath, in_buf->DirectoryPath, sizeof(localPath));

    status = MyArkIoctlFetchOutputBuffer(Request, out_size, (PVOID*)&out_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(out_buf, out_size);
    {
        ULONG count = 0;
        ULONG truncated = 0;
        NTSTATUS openStatus = (NTSTATUS)0;
        NTSTATUS walkStatus = (NTSTATUS)0;

        status = MyArkKobjQueryDirectory(localPath,
                                         out_buf->Entries,
                                         MYARK_KOBJ_DIR_CAP,
                                         &count,
                                         &truncated,
                                         &openStatus,
                                         &walkStatus);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        out_buf->Count = count;
        out_buf->Flags = truncated ? MYARK_KOBJ_DIR_FLAG_TRUNCATED : 0;
        out_buf->OpenStatus = (UINT32)openStatus;
        out_buf->WalkStatus = (UINT32)walkStatus;
    }

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkKobjIoctlIpcSummary(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS status;
    PMYARK_KOBJ_IPC_SUMMARY_OUTPUT out_buf;
    size_t out_size = sizeof(MYARK_KOBJ_IPC_SUMMARY_OUTPUT);

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < out_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchOutputBuffer(Request, out_size, (PVOID*)&out_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(out_buf, out_size);
    {
        ULONG pipeCount = 0;
        ULONG pipeTruncated = 0;
        NTSTATUS pipeStatus = (NTSTATUS)0;
        NTSTATUS pipeWalk = (NTSTATUS)0;
        ULONG slotCount = 0;
        ULONG slotTruncated = 0;
        NTSTATUS slotStatus = (NTSTATUS)0;
        NTSTATUS slotWalk = (NTSTATUS)0;

        // \Device\NamedPipe and \Device\MailSlot are NPFS/MSFS DEVICE
        // objects, not object-manager directories -- ZwOpenDirectoryObject
        // answers STATUS_INVALID_PARAMETER on them. The namespace is
        // enumerated as a directory FILE instead.
        status = MyArkKobjQueryFileDirectory(g_MyArkKobjPipePath,
                                             L"NamedPipe",
                                             out_buf->Pipes,
                                             MYARK_KOBJ_PIPE_CAP,
                                             &pipeCount,
                                             &pipeTruncated,
                                             &pipeStatus,
                                             &pipeWalk);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = MyArkKobjQueryFileDirectory(g_MyArkKobjMailslotPath,
                                             L"MailSlot",
                                             out_buf->Mailslots,
                                             MYARK_KOBJ_MAILSLOT_CAP,
                                             &slotCount,
                                             &slotTruncated,
                                             &slotStatus,
                                             &slotWalk);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        out_buf->PipeCount = pipeCount;
        out_buf->PipeFlags = pipeTruncated ? MYARK_KOBJ_IPC_PIPE_TRUNCATED : 0;
        out_buf->PipeOpenStatus = (UINT32)pipeStatus;
        out_buf->PipeWalkStatus = (UINT32)pipeWalk;
        out_buf->MailslotCount = slotCount;
        out_buf->MailslotFlags = slotTruncated ? MYARK_KOBJ_IPC_MAILSLOT_TRUNCATED : 0;
        out_buf->MailslotOpenStatus = (UINT32)slotStatus;
        out_buf->MailslotWalkStatus = (UINT32)slotWalk;
    }

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_KERNEL_OBJECT
