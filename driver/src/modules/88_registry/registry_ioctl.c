// MyArk registry module: IOCTL handlers.
//
// R0 registry access over the documented Zw* surface, restricted to the
// \Registry\Machine and \Registry\User roots (a minimal-root policy).
// Read/enumerate IOCTLs are open; every mutating IOCTL carries a
// SAFETY_TOKEN that must validate before the operation runs.
//
// METHOD_BUFFERED ordering notes per handler:
//   * READ_VALUE: the 524-byte output shares the SystemBuffer with the
//     640-byte input, so the path/name are copied into locals before the
//     output fetch zeroes them.
//   * ENUM_KEY: the key is OPENED (and the total subkey count queried)
//     before the output fetch; enumeration then writes straight into the
//     output buffer using only the handle.
//   * Mutating IOCTLs: the 4-byte Status output only overlaps the token's
//     Magic field, and the token is validated before anything is zeroed.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkRegistryIoctl.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"
#include "../../../shared/driver/MyArkSafetyToken.h"
#include "../../dispatch/safety_token.h"
#include "registry_internal.h"
#include "registry_descriptor.h"

#if MYARK_MODULE_REGISTRY

const WCHAR MyArkRegRootMachine[] = L"\\Registry\\Machine";
const WCHAR MyArkRegRootUser[]    = L"\\Registry\\User";

//
// The path must use the NT registry format and live under one of the two
// allowed roots. Path is copied into LocalCopy with a forced terminator so
// callers can build UNICODE_STRINGs against a stable buffer.
//
NTSTATUS
MyArkRegistryValidatePath(
    _In_ PCWSTR Path,
    _Out_ WCHAR LocalCopy[MYARK_REGISTRY_KEY_PATH_CHARS])
{
    SIZE_T len;

    if (Path == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    len = wcsnlen(Path, MYARK_REGISTRY_KEY_PATH_CHARS);
    if (len == 0 || len >= MYARK_REGISTRY_KEY_PATH_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }

    if (_wcsnicmp(Path, MyArkRegRootMachine, RTL_NUMBER_OF(MyArkRegRootMachine) - 1) != 0
        && _wcsnicmp(Path, MyArkRegRootUser, RTL_NUMBER_OF(MyArkRegRootUser) - 1) != 0) {
        return STATUS_ACCESS_DENIED;
    }

    //
    // Root-boundary check: "\Registry\MachineX" must not pass as
    // "\Registry\Machine". The character after the root is the separator
    // or the end of the path.
    //
    for (ULONG rootIdx = 0; rootIdx < 2; rootIdx++) {
        PCWSTR root = (rootIdx == 0) ? MyArkRegRootMachine : MyArkRegRootUser;
        SIZE_T rootLen = RTL_NUMBER_OF(MyArkRegRootMachine) - 1;
        SIZE_T rootLenUser = RTL_NUMBER_OF(MyArkRegRootUser) - 1;
        SIZE_T thisLen = (rootIdx == 0) ? rootLen : rootLenUser;
        if (_wcsnicmp(Path, root, thisLen) == 0) {
            WCHAR next = Path[thisLen];
            if (next != L'\\' && next != L'\0') {
                return STATUS_ACCESS_DENIED;
            }
            break;
        }
    }

    RtlCopyMemory(LocalCopy, Path, len * sizeof(WCHAR));
    LocalCopy[len] = L'\0';
    return STATUS_SUCCESS;
}

//
// Registry value/key NAMES arrive as fixed WCHAR[64] arrays without a
// guaranteed terminator. RtlInitUnicodeString would run wcslen past the
// buffer on a hostile full-width name, so every name is pre-checked
// (repo precedent: 87_actions uses the same guard, review 2026-09-15).
//
NTSTATUS
MyArkRegistryCheckNameTerminated(
    _In_ const WCHAR *Name)
{
    for (ULONG i = 0; i < MYARK_REGISTRY_VALUE_NAME_CHARS; i++) {
        if (Name[i] == L'\0') {
            return STATUS_SUCCESS;
        }
    }
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS
MyArkRegistryOpenKey(
    _In_ PCWSTR NtPath,
    _In_ ACCESS_MASK Access,
    _Out_ PHANDLE Handle)
{
    UNICODE_STRING pathUs;
    OBJECT_ATTRIBUTES oa;

    RtlInitUnicodeString(&pathUs, NtPath);
    InitializeObjectAttributes(&oa,
                               &pathUs,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    return ZwOpenKey(Handle, Access, &oa);
}

//
// Token gate shared by all mutating IOCTLs. Runs on the raw input BEFORE
// any output buffer fetch zeroes shared bytes.
//
static
NTSTATUS
MyArkRegistryValidateToken(
    _In_ PMYARK_SAFETY_TOKEN Token,
    _In_ UINT32 Operation)
{
    return MyArkSafetyTokenValidate(Token,
                                    Operation,
                                    (UINT32)(UINT_PTR)PsGetCurrentProcessId());
}

static
NTSTATUS
MyArkRegistryFinishStatus(
    _In_ WDFREQUEST Request,
    _In_ NTSTATUS OperationStatus,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

//
// READ_VALUE.
//
NTSTATUS
MyArkRegistryIoctlReadValue(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_REGISTRY_READ_INPUT   inBuf = NULL;
    PMYARK_REGISTRY_READ_OUTPUT  outBuf = NULL;
    size_t                       inSize = 0;
    NTSTATUS                     status;
    WCHAR                        keyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    WCHAR                        valueName[MYARK_REGISTRY_VALUE_NAME_CHARS];
    HANDLE                       keyHandle = NULL;
    PUCHAR                       infoBuf = NULL;
    ULONG                        infoSize = 0;
    ULONG                        resultLen = 0;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_REGISTRY_READ_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_REGISTRY_READ_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Snapshot path/name before the output fetch (524-byte output zeroes
    // the shared SystemBuffer including these fields).
    //
    RtlCopyMemory(keyPath, inBuf->KeyPath, sizeof(keyPath));
    RtlCopyMemory(valueName, inBuf->ValueName, sizeof(valueName));

    if (OutputBufferLength < sizeof(MYARK_REGISTRY_READ_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_REGISTRY_READ_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outBuf, sizeof(*outBuf));

    status = MyArkRegistryCheckNameTerminated(valueName);
    if (!NT_SUCCESS(status)) {
        outBuf->Status = (UINT32)STATUS_INVALID_PARAMETER;
        *BytesReturned = FIELD_OFFSET(MYARK_REGISTRY_READ_OUTPUT, Data);
        return STATUS_SUCCESS;
    }

    status = MyArkRegistryValidatePath(keyPath, keyPath);
    if (!NT_SUCCESS(status)) {
        outBuf->Status = (UINT32)status;
        *BytesReturned = FIELD_OFFSET(MYARK_REGISTRY_READ_OUTPUT, Data);
        return STATUS_SUCCESS;
    }

    status = MyArkRegistryOpenKey(keyPath, KEY_QUERY_VALUE, &keyHandle);
    if (!NT_SUCCESS(status)) {
        outBuf->Status = (UINT32)status;
        *BytesReturned = FIELD_OFFSET(MYARK_REGISTRY_READ_OUTPUT, Data);
        return STATUS_SUCCESS;
    }

    infoSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MYARK_REGISTRY_DATA_MAX;
    infoBuf = (PUCHAR)MyArkAllocatePool(PagedPool, infoSize, 'GERS');
    if (infoBuf == NULL) {
        ZwClose(keyHandle);
        outBuf->Status = (UINT32)STATUS_INSUFFICIENT_RESOURCES;
        *BytesReturned = FIELD_OFFSET(MYARK_REGISTRY_READ_OUTPUT, Data);
        return STATUS_SUCCESS;
    }

    for (;;) {
        UNICODE_STRING valueNameUs;

        RtlInitUnicodeString(&valueNameUs, valueName);
        status = ZwQueryValueKey(keyHandle,
                                 &valueNameUs,
                                 KeyValuePartialInformation,
                                 infoBuf,
                                 infoSize,
                                 &resultLen);
        if (NT_SUCCESS(status) || status != STATUS_BUFFER_OVERFLOW) {
            break;
        }

        // Grow once with the size the kernel reported, then re-query.
        ExFreePoolWithTag(infoBuf, 'GERS');
        infoBuf = NULL;  // tail release must not double-free this block
        if (resultLen == 0 || resultLen > 64 * 1024) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        infoBuf = (PUCHAR)MyArkAllocatePool(PagedPool, resultLen, 'GERS');
        if (infoBuf == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        infoSize = resultLen;
    }

    if (NT_SUCCESS(status)) {
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)infoBuf;
        ULONG copyLen = info->DataLength;

        if (copyLen > MYARK_REGISTRY_DATA_MAX) {
            copyLen = MYARK_REGISTRY_DATA_MAX;
            outBuf->Status = (UINT32)STATUS_BUFFER_TOO_SMALL;
        }
        outBuf->Type = info->Type;
        outBuf->DataSize = copyLen;
        RtlCopyMemory(outBuf->Data, info->Data, copyLen);
    } else {
        outBuf->Status = (UINT32)status;
    }

    //
    // Unconditional release: every exit past the allocation lands here
    // (review blocker -- the earlier revision leaked the query buffer).
    //
    if (infoBuf) {
        ExFreePoolWithTag(infoBuf, 'GERS');
    }
    ZwClose(keyHandle);

    if (outBuf->Status == 0 && outBuf->DataSize != 0) {
        outBuf->Status = (UINT32)STATUS_SUCCESS;
    }
    *BytesReturned = sizeof(MYARK_REGISTRY_READ_OUTPUT);
    return STATUS_SUCCESS;
}

//
// ENUM_KEY: batched subkey name enumeration.
//
NTSTATUS
MyArkRegistryIoctlEnumKey(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_REGISTRY_ENUM_INPUT  inBuf = NULL;
    PMYARK_REGISTRY_ENUM_OUTPUT outBuf = NULL;
    size_t                      inSize = 0;
    NTSTATUS                    status;
    WCHAR                       keyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    UINT32                      startIndex;
    UINT32                      maxEntries;
    HANDLE                      keyHandle = NULL;
    UCHAR                       fullInfoBuffer[512];
    ULONG                       resultLen = 0;
    PKEY_FULL_INFORMATION       fullInfo;
    ULONG                       i;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_REGISTRY_ENUM_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < sizeof(MYARK_REGISTRY_ENUM_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_REGISTRY_ENUM_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Open + total-subkey query BEFORE the output fetch: both only need
    // the path, and the 2 KB output zero would otherwise wipe it.
    //
    RtlCopyMemory(keyPath, inBuf->KeyPath, sizeof(keyPath));
    startIndex = inBuf->StartIndex;
    maxEntries = inBuf->MaxEntries;
    if (maxEntries > MYARK_REGISTRY_ENUM_MAX_ENTRIES) {
        maxEntries = MYARK_REGISTRY_ENUM_MAX_ENTRIES;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_REGISTRY_ENUM_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outBuf, sizeof(*outBuf));

    status = MyArkRegistryValidatePath(keyPath, keyPath);
    if (!NT_SUCCESS(status)) {
        outBuf->Status = (UINT32)status;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    status = MyArkRegistryOpenKey(keyPath, KEY_READ, &keyHandle);
    if (!NT_SUCCESS(status)) {
        outBuf->Status = (UINT32)status;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    status = ZwQueryKey(keyHandle,
                        KeyFullInformation,
                        fullInfoBuffer,
                        sizeof(fullInfoBuffer),
                        &resultLen);
    if (!NT_SUCCESS(status)) {
        ZwClose(keyHandle);
        outBuf->Status = (UINT32)status;
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    fullInfo = (PKEY_FULL_INFORMATION)fullInfoBuffer;
    outBuf->TotalSubkeys = fullInfo->SubKeys;

    if (startIndex >= outBuf->TotalSubkeys || maxEntries == 0) {
        outBuf->Status = (UINT32)STATUS_SUCCESS;
        outBuf->NextIndex = startIndex;
        ZwClose(keyHandle);
        *BytesReturned = sizeof(*outBuf);
        return STATUS_SUCCESS;
    }

    for (i = 0; i < maxEntries; i++) {
        ULONG index = startIndex + i;
        UCHAR basicBuffer[256];
        PKEY_BASIC_INFORMATION basic = (PKEY_BASIC_INFORMATION)basicBuffer;
        ULONG nameChars;

        status = ZwEnumerateKey(keyHandle,
                                index,
                                KeyBasicInformation,
                                basicBuffer,
                                sizeof(basicBuffer),
                                &resultLen);
        if (!NT_SUCCESS(status)) {
            break; // past the last subkey (or transient) -- stop filling
        }

        nameChars = basic->NameLength / sizeof(WCHAR);
        if (nameChars > MYARK_REGISTRY_VALUE_NAME_CHARS - 1) {
            nameChars = MYARK_REGISTRY_VALUE_NAME_CHARS - 1;
        }
        RtlCopyMemory(outBuf->Names[outBuf->Returned].Name,
                      basic->Name,
                      nameChars * sizeof(WCHAR));
        outBuf->Names[outBuf->Returned].Name[nameChars] = L'\0';
        outBuf->Returned++;
    }

    outBuf->NextIndex = startIndex + outBuf->Returned;
    outBuf->Status = (UINT32)STATUS_SUCCESS;
    ZwClose(keyHandle);
    *BytesReturned = sizeof(*outBuf);
    return STATUS_SUCCESS;
}

//
// SET_VALUE (token-gated).
//
NTSTATUS
MyArkRegistryIoctlSetValue(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_REGISTRY_SET_VALUE_INPUT inBuf = NULL;
    size_t                          inSize = 0;
    NTSTATUS                        status;
    WCHAR                           keyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    WCHAR                           valueName[MYARK_REGISTRY_VALUE_NAME_CHARS];
    UINT32                          valueType;
    UINT32                          dataSize;
    HANDLE                          keyHandle = NULL;
    UNICODE_STRING                  valueNameUs;

    UNREFERENCED_PARAMETER(Device);

    //
    // Variable-tail payload (WRITE_PHYSICAL idiom): the IOCTL length is
    // authoritative. Minimum = fixed fields + at least 1 payload byte;
    // the in-struct DataSize field is informational only.
    //
    if (InputBufferLength < FIELD_OFFSET(MYARK_REGISTRY_SET_VALUE_INPUT, Data) + 1) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < sizeof(MYARK_REGISTRY_STATUS_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        InputBufferLength,
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Token gate FIRST (actions-module pattern): a failed token returns a
    // plain ACCESS_DENIED before anything else runs.
    //
    status = MyArkRegistryValidateToken(&inBuf->Token,
                                        MYARK_REGISTRY_OP_SET_VALUE);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    RtlCopyMemory(keyPath, inBuf->KeyPath, sizeof(keyPath));
    RtlCopyMemory(valueName, inBuf->ValueName, sizeof(valueName));
    valueType = inBuf->ValueType;
    dataSize = (UINT32)(InputBufferLength - FIELD_OFFSET(MYARK_REGISTRY_SET_VALUE_INPUT, Data));
    if (dataSize > MYARK_REGISTRY_DATA_MAX) {
        dataSize = MYARK_REGISTRY_DATA_MAX;
    }

    status = MyArkRegistryCheckNameTerminated(valueName);
    if (!NT_SUCCESS(status)) {
        return STATUS_INVALID_PARAMETER;
    }

    status = MyArkRegistryValidatePath(keyPath, keyPath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryOpenKey(keyPath, KEY_SET_VALUE, &keyHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&valueNameUs, valueName);
    status = ZwSetValueKey(keyHandle,
                           &valueNameUs,
                           0,
                           valueType,
                           (PVOID)inBuf->Data,
                           dataSize);
    ZwClose(keyHandle);

    //
    // Target failures surface in-band (STATUS_OUTPUT.Status) exactly like
    // the other five mutating handlers; policy denials stay IOCTL-level.
    //
    NTSTATUS opStatus = status;
    status = MyArkRegistryFinishStatus(Request,
                                       opStatus,
                                       OutputBufferLength,
                                       BytesReturned);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return STATUS_SUCCESS;
}

//
// Shared tail for the mutating IOCTLs whose operation already ran: fetch
// the 4-byte status output and finish.
//
static
NTSTATUS
MyArkRegistryFinishStatus(
    _In_ WDFREQUEST Request,
    _In_ NTSTATUS OperationStatus,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_REGISTRY_STATUS_OUTPUT outBuf = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_REGISTRY_STATUS_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    outBuf->Status = (UINT32)OperationStatus;
    *BytesReturned = sizeof(*outBuf);
    return STATUS_SUCCESS;
}

//
// DELETE_VALUE (token-gated).
//
NTSTATUS
MyArkRegistryIoctlDeleteValue(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_REGISTRY_DELETE_VALUE_INPUT inBuf = NULL;
    size_t                             inSize = 0;
    NTSTATUS                           status;
    WCHAR                              keyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    WCHAR                              valueName[MYARK_REGISTRY_VALUE_NAME_CHARS];
    HANDLE                             keyHandle = NULL;
    UNICODE_STRING                     valueNameUs;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < sizeof(MYARK_REGISTRY_DELETE_VALUE_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_REGISTRY_DELETE_VALUE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryValidateToken(&inBuf->Token,
                                        MYARK_REGISTRY_OP_DELETE_VALUE);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    RtlCopyMemory(keyPath, inBuf->KeyPath, sizeof(keyPath));
    RtlCopyMemory(valueName, inBuf->ValueName, sizeof(valueName));

    status = MyArkRegistryCheckNameTerminated(valueName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryValidatePath(keyPath, keyPath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryOpenKey(keyPath, KEY_SET_VALUE, &keyHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&valueNameUs, valueName);
    status = ZwDeleteValueKey(keyHandle, &valueNameUs);
    ZwClose(keyHandle);

    return MyArkRegistryFinishStatus(Request,
                                     status,
                                     OutputBufferLength,
                                     BytesReturned);
}

//
// CREATE_KEY (token-gated). Non-volatile; intermediate keys are NOT
// auto-created -- the caller builds the path level by level.
//
NTSTATUS
MyArkRegistryIoctlCreateKey(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_REGISTRY_CREATE_KEY_INPUT inBuf = NULL;
    size_t                           inSize = 0;
    NTSTATUS                         status;
    WCHAR                            keyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    HANDLE                           keyHandle = NULL;
    ULONG                            disposition = 0;
    OBJECT_ATTRIBUTES                oa;
    UNICODE_STRING                   pathUs;
    NTSTATUS                         opStatus;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < sizeof(MYARK_REGISTRY_CREATE_KEY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_REGISTRY_CREATE_KEY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryValidateToken(&inBuf->Token,
                                        MYARK_REGISTRY_OP_CREATE_KEY);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    RtlCopyMemory(keyPath, inBuf->KeyPath, sizeof(keyPath));

    status = MyArkRegistryValidatePath(keyPath, keyPath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&pathUs, keyPath);
    InitializeObjectAttributes(&oa,
                               &pathUs,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    opStatus = ZwCreateKey(&keyHandle,
                           KEY_READ,
                           &oa,
                           0,
                           NULL,
                           REG_OPTION_NON_VOLATILE,
                           &disposition);
    if (NT_SUCCESS(opStatus)) {
        ZwClose(keyHandle);
    }

    return MyArkRegistryFinishStatus(Request,
                                     opStatus,
                                     OutputBufferLength,
                                     BytesReturned);
}

//
// DELETE_KEY (token-gated). Fails with STATUS_CANNOT_DELETE while the key
// still has subkeys -- by design, no recursive delete.
//
NTSTATUS
MyArkRegistryIoctlDeleteKey(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_REGISTRY_DELETE_KEY_INPUT inBuf = NULL;
    size_t                           inSize = 0;
    NTSTATUS                         status;
    WCHAR                            keyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    HANDLE                           keyHandle = NULL;
    NTSTATUS                         opStatus;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < sizeof(MYARK_REGISTRY_DELETE_KEY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_REGISTRY_DELETE_KEY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryValidateToken(&inBuf->Token,
                                        MYARK_REGISTRY_OP_DELETE_KEY);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    RtlCopyMemory(keyPath, inBuf->KeyPath, sizeof(keyPath));

    status = MyArkRegistryValidatePath(keyPath, keyPath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryOpenKey(keyPath, DELETE, &keyHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    opStatus = ZwDeleteKey(keyHandle);
    ZwClose(keyHandle);

    return MyArkRegistryFinishStatus(Request,
                                     opStatus,
                                     OutputBufferLength,
                                     BytesReturned);
}

//
// RENAME_VALUE (token-gated). Registry values have no rename primitive:
// query old -> delete old -> write new under the new name. A failure after
// the delete is reported (the value is gone) -- R3 retries by writing the
// old payload under the old name.
//
NTSTATUS
MyArkRegistryIoctlRenameValue(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_REGISTRY_RENAME_VALUE_INPUT inBuf = NULL;
    size_t                             inSize = 0;
    NTSTATUS                           status;
    WCHAR                              keyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    WCHAR                              oldName[MYARK_REGISTRY_VALUE_NAME_CHARS];
    WCHAR                              newName[MYARK_REGISTRY_VALUE_NAME_CHARS];
    HANDLE                             keyHandle = NULL;
    PUCHAR                             infoBuf = NULL;
    ULONG                              infoSize = 0;
    ULONG                              resultLen = 0;
    UINT32                             valueType = 0;
    NTSTATUS                           opStatus;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < sizeof(MYARK_REGISTRY_RENAME_VALUE_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_REGISTRY_RENAME_VALUE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryValidateToken(&inBuf->Token,
                                        MYARK_REGISTRY_OP_RENAME_VALUE);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    RtlCopyMemory(keyPath, inBuf->KeyPath, sizeof(keyPath));
    RtlCopyMemory(oldName, inBuf->OldName, sizeof(oldName));
    RtlCopyMemory(newName, inBuf->NewName, sizeof(newName));

    status = MyArkRegistryValidatePath(keyPath, keyPath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryCheckNameTerminated(oldName);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkRegistryCheckNameTerminated(newName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryOpenKey(keyPath, KEY_QUERY_VALUE | KEY_SET_VALUE, &keyHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Snapshot the old value (type + payload) before deleting it.
    //
    infoSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MYARK_REGISTRY_DATA_MAX;
    infoBuf = (PUCHAR)MyArkAllocatePool(PagedPool, infoSize, 'GERS');
    if (infoBuf == NULL) {
        ZwClose(keyHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    {
        UNICODE_STRING oldNameUs;
        PKEY_VALUE_PARTIAL_INFORMATION info;

        RtlInitUnicodeString(&oldNameUs, oldName);
        status = ZwQueryValueKey(keyHandle,
                                 &oldNameUs,
                                 KeyValuePartialInformation,
                                 infoBuf,
                                 infoSize,
                                 &resultLen);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(infoBuf, 'GERS');
            ZwClose(keyHandle);
            return status;
        }
        info = (PKEY_VALUE_PARTIAL_INFORMATION)infoBuf;
        valueType = info->Type;
        if (info->DataLength > MYARK_REGISTRY_DATA_MAX) {
            ExFreePoolWithTag(infoBuf, 'GERS');
            ZwClose(keyHandle);
            return STATUS_BUFFER_TOO_SMALL;
        }

        opStatus = ZwDeleteValueKey(keyHandle, &oldNameUs);
        if (!NT_SUCCESS(opStatus)) {
            ExFreePoolWithTag(infoBuf, 'GERS');
            ZwClose(keyHandle);
            return opStatus;
        }

        {
            UNICODE_STRING newNameUs;
            RtlInitUnicodeString(&newNameUs, newName);
            opStatus = ZwSetValueKey(keyHandle,
                                     &newNameUs,
                                     0,
                                     valueType,
                                     info->Data,
                                     info->DataLength);
        }
    }

    if (infoBuf) {
        ExFreePoolWithTag(infoBuf, 'GERS');
    }
    ZwClose(keyHandle);

    return MyArkRegistryFinishStatus(Request,
                                     opStatus,
                                     OutputBufferLength,
                                     BytesReturned);
}

//
// RENAME_KEY (token-gated).
//
NTSTATUS
MyArkRegistryIoctlRenameKey(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_REGISTRY_RENAME_KEY_INPUT inBuf = NULL;
    size_t                           inSize = 0;
    NTSTATUS                         status;
    WCHAR                            keyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    WCHAR                            newName[MYARK_REGISTRY_VALUE_NAME_CHARS];
    HANDLE                           keyHandle = NULL;
    UNICODE_STRING                   newNameUs;
    NTSTATUS                         opStatus;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < sizeof(MYARK_REGISTRY_RENAME_KEY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_REGISTRY_RENAME_KEY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryValidateToken(&inBuf->Token,
                                        MYARK_REGISTRY_OP_RENAME_KEY);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    RtlCopyMemory(keyPath, inBuf->KeyPath, sizeof(keyPath));
    RtlCopyMemory(newName, inBuf->NewName, sizeof(newName));

    status = MyArkRegistryValidatePath(keyPath, keyPath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryCheckNameTerminated(newName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRegistryOpenKey(keyPath, DELETE, &keyHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&newNameUs, newName);
    opStatus = ZwRenameKey(keyHandle, &newNameUs);
    ZwClose(keyHandle);

    return MyArkRegistryFinishStatus(Request,
                                     opStatus,
                                     OutputBufferLength,
                                     BytesReturned);
}

#endif // MYARK_MODULE_REGISTRY
