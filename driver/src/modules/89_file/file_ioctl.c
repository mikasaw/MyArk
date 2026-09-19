// MyArk file module: IOCTL handlers.
//
// DELETE_PATH (token-gated): three-tier delete chain --
//   1. plain disposition (delete-on-close) for unshared files,
//   2. FORCE flag -> FileDispositionInformationEx with POSIX semantics +
//      image-section check, so mapped/locked files can still be removed,
//   3. fall back to plain disposition retry when EX is unsupported.
// QUERY_FILE_INFO: open with FILE_READ_ATTRIBUTES and merge
// FILE_BASIC_INFORMATION + FILE_STANDARD_INFORMATION.
//
// Shared-buffer ordering: both handlers finish every Zw* operation before
// fetching the 4-byte status output (whose zero cannot disturb inputs that
// were already snapshotted into locals).

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkFileIoctl.h"
#include "../../../shared/driver/MyArkSafetyToken.h"
#include "../../dispatch/safety_token.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"
#include "file_internal.h"
#include "file_descriptor.h"

#if MYARK_MODULE_FILE

const WCHAR MyArkFileDosPrefix[] = L"\\??\\";

NTSTATUS
MyArkFileValidatePath(
    _In_ PCWSTR Path,
    _Out_ WCHAR LocalCopy[MYARK_FILE_PATH_CHARS])
{
    SIZE_T len;

    if (Path == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    len = wcsnlen(Path, MYARK_FILE_PATH_CHARS);
    if (len == 0 || len >= MYARK_FILE_PATH_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }

    if (_wcsnicmp(Path, MyArkFileDosPrefix, RTL_NUMBER_OF(MyArkFileDosPrefix) - 1) != 0) {
        return STATUS_ACCESS_DENIED;  // UNC (\\??)\UNC and device paths rejected
    }

    RtlCopyMemory(LocalCopy, Path, len * sizeof(WCHAR));
    LocalCopy[len] = L'\0';
    return STATUS_SUCCESS;
}

static
NTSTATUS
MyArkFileValidateToken(
    _In_ PMYARK_SAFETY_TOKEN Token,
    _In_ UINT32 Operation)
{
    return MyArkSafetyTokenValidate(Token,
                                    Operation,
                                    (UINT32)(UINT_PTR)PsGetCurrentProcessId());
}

//
// DELETE_PATH (token-gated). Three-tier chain:
//   tier 1: plain disposition -- works for files opened with share-delete
//   tier 2: EX disposition with POSIX semantics + image-section force
//   tier 3: plain disposition retry (EX unsupported on this filesystem)
//
NTSTATUS
MyArkFileIoctlDeletePath(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_FILE_DELETE_PATH_INPUT inBuf = NULL;
    size_t                        inSize = 0;
    NTSTATUS                      status;
    WCHAR                         path[MYARK_FILE_PATH_CHARS];
    HANDLE                        fileHandle = NULL;
    OBJECT_ATTRIBUTES             oa;
    UNICODE_STRING                pathUs;
    IO_STATUS_BLOCK               iosb;
    BOOLEAN                       force;
    NTSTATUS                      opStatus;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < sizeof(MYARK_FILE_DELETE_PATH_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_FILE_DELETE_PATH_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkFileValidateToken(&inBuf->Token,
                                    MYARK_FILE_OP_DELETE_PATH);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    force = (inBuf->Flags & MYARK_FILE_DELETE_FLAG_FORCE) != 0;

    RtlCopyMemory(path, inBuf->Path, sizeof(path));

    status = MyArkFileValidatePath(path, path);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&pathUs, path);
    InitializeObjectAttributes(&oa,
                               &pathUs,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    //
    // Tier 1: open for delete with full sharing so an unshared target
    // (nothing holds it) deletes cleanly.
    //
    status = ZwOpenFile(&fileHandle,
                        DELETE | FILE_READ_ATTRIBUTES,
                        &oa,
                        &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(status)) {
        //
        // Only retry as a directory when the target actually is one;
        // otherwise surface the original failure (sharing violation,
        // name not found, ...) instead of masking it with 267.
        //
        if (status != STATUS_FILE_IS_A_DIRECTORY) {
            return status;
        }
        status = ZwOpenFile(&fileHandle,
                            DELETE | FILE_READ_ATTRIBUTES,
                            &oa,
                            &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    {
        FILE_DISPOSITION_INFORMATION disposition;
        disposition.DeleteFile = TRUE;
        opStatus = ZwSetInformationFile(fileHandle,
                                        &iosb,
                                        &disposition,
                                        sizeof(disposition),
                                        FileDispositionInformation);
    }

    //
    // Tier 2: FORCE -- retry with FileDispositionInformationEx (POSIX
    // semantics + image-section flag). POSIX changes same-handle delete
    // rules; it does NOT bypass sharing violations of other handles.
    //
    if (!NT_SUCCESS(opStatus) && force) {
        FILE_DISPOSITION_INFORMATION_EX dispositionEx;
        dispositionEx.Flags = FILE_DISPOSITION_DELETE
                            | FILE_DISPOSITION_POSIX_SEMANTICS
                            | FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK;

        ZwClose(fileHandle);
        fileHandle = NULL;

        status = ZwOpenFile(&fileHandle,
                            DELETE | FILE_READ_ATTRIBUTES,
                            &oa,
                            &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_NON_DIRECTORY_FILE);
        if (NT_SUCCESS(status)) {
            opStatus = ZwSetInformationFile(fileHandle,
                                            &iosb,
                                            &dispositionEx,
                                            sizeof(dispositionEx),
                                            FileDispositionInformationEx);

            //
            // Tier 3: EX unsupported (old filesystem) -- plain retry.
            //
            if (!NT_SUCCESS(opStatus)) {
                FILE_DISPOSITION_INFORMATION plain;
                plain.DeleteFile = TRUE;
                opStatus = ZwSetInformationFile(fileHandle,
                                                &iosb,
                                                &plain,
                                                sizeof(plain),
                                                FileDispositionInformation);
            }
        }
    }

    if (fileHandle) {
        ZwClose(fileHandle);
    }

    //
    // FinishStatus-style in-band result: fetch the 4-byte output and
    // report the operation status there.
    //
    {
        PVOID outBuf = NULL;
        size_t outSize = 0;
        status = MyArkIoctlFetchOutputBuffer(Request,
                                             sizeof(MYARK_FILE_STATUS_OUTPUT),
                                             &outBuf,
                                             &outSize);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlZeroMemory(outBuf, sizeof(MYARK_FILE_STATUS_OUTPUT));
        ((PMYARK_FILE_STATUS_OUTPUT)outBuf)->Status = (UINT32)opStatus;
        *BytesReturned = sizeof(MYARK_FILE_STATUS_OUTPUT);
    }

    return STATUS_SUCCESS;
}

//
// QUERY_FILE_INFO.
//
NTSTATUS
MyArkFileIoctlQueryInfo(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_FILE_QUERY_INFO_INPUT  inBuf = NULL;
    PMYARK_FILE_QUERY_INFO_OUTPUT outBuf = NULL;
    size_t                        inSize = 0;
    NTSTATUS                      status;
    WCHAR                         path[MYARK_FILE_PATH_CHARS];
    HANDLE                        fileHandle = NULL;
    OBJECT_ATTRIBUTES             oa;
    UNICODE_STRING                pathUs;
    IO_STATUS_BLOCK               iosb;
    FILE_BASIC_INFORMATION        basic = { 0 };
    FILE_STANDARD_INFORMATION     standard = { 0 };

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_FILE_QUERY_INFO_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_FILE_QUERY_INFO_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(path, inBuf->Path, sizeof(path));

    if (OutputBufferLength < sizeof(MYARK_FILE_QUERY_INFO_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_FILE_QUERY_INFO_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outBuf, sizeof(*outBuf));

    status = MyArkFileValidatePath(path, path);
    if (!NT_SUCCESS(status)) {
        outBuf->Status = (UINT32)status;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&pathUs, path);
    InitializeObjectAttributes(&oa,
                               &pathUs,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    status = ZwOpenFile(&fileHandle,
                        FILE_READ_ATTRIBUTES,
                        &oa,
                        &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        0);
    if (!NT_SUCCESS(status)) {
        outBuf->Status = (UINT32)status;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    status = ZwQueryInformationFile(fileHandle,
                                    &iosb,
                                    &basic,
                                    sizeof(basic),
                                    FileBasicInformation);
    if (NT_SUCCESS(status)) {
        status = ZwQueryInformationFile(fileHandle,
                                        &iosb,
                                        &standard,
                                        sizeof(standard),
                                        FileStandardInformation);
    }
    ZwClose(fileHandle);

    if (!NT_SUCCESS(status)) {
        outBuf->Status = (UINT32)status;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    outBuf->Status = (UINT32)STATUS_SUCCESS;
    outBuf->Attributes = basic.FileAttributes;
    outBuf->AllocationSize = standard.AllocationSize.QuadPart;
    outBuf->EndOfFile = standard.EndOfFile.QuadPart;
    outBuf->CreationTime = basic.CreationTime.QuadPart;
    outBuf->LastAccessTime = basic.LastAccessTime.QuadPart;
    outBuf->LastWriteTime = basic.LastWriteTime.QuadPart;
    *BytesReturned = sizeof(*outBuf);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_FILE
