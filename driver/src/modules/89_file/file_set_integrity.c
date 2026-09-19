// MyArk file module: file integrity label (R2-10).
//
// QUERY_FILE_INTEGRITY (0xE13, read-only): returns the first mandatory
// label ACE (S-1-16-<rid> + policy mask) of an existing file, parsed
// kernel-side from ZwQuerySecurityObject(LABEL_SECURITY_INFORMATION).
//
// SET_FILE_INTEGRITY (0xE12): DEFERRED. The ZwSetSecurityObject write of
// a hand-assembled label SD wedges the guest exec channel irrecoverably
// (even with an ACL_REVISION_DS SACL and an exact-size label ACE --
// observed 2026-09-16, KNOWN_ISSUES). The handler returns
// STATUS_NOT_SUPPORTED (win32 50) -- distinct from the win32 1 an
// unregistered IOCTL produces -- and the deferred body is preserved
// under #if 0 for the dedicated KDNET debugging round.

#include <ntifs.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkFileIoctl.h"
#include "../../../shared/driver/MyArkSafetyToken.h"
#include "../../dispatch/safety_token.h"
#include "file_internal.h"
#include "file_descriptor.h"

#if MYARK_MODULE_FILE

//
// SYSTEM_MANDATORY_LABEL SID: S-1-16-{0, rid}. Revision 1, identifier
// authority 16, one 32-bit subauthority (12 bytes total).
//
#define MYARK_LABEL_SID_REVISION          1
#define MYARK_LABEL_SID_SUBAUTHORITY_COUNT 1
#define MYARK_LABEL_ACE_TYPE              0x11   // SYSTEM_MANDATORY_LABEL_ACE
#define MYARK_LABEL_ACE_FLAGS             0x00
#define MYARK_SECURITY_DESCRIPTOR_REVISION 1

#define MYARK_SE_SACL_PRESENT             0x00000010UL

NTSTATUS
MyArkFileIoctlSetIntegrity(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(BytesReturned);

    //
    // DEFERRED: the label write wedges the guest (see file header).
    // STATUS_NOT_SUPPORTED (win32 50) keeps this distinguishable from an
    // unregistered IOCTL (win32 1).
    //
    return STATUS_NOT_SUPPORTED;
}

#if 0  // deferred SET implementation (Se wedge, see KNOWN_ISSUES)
NTSTATUS
MyArkFileIoctlSetIntegrityDeferred(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PMYARK_FILE_SET_INTEGRITY_INPUT inBuf = NULL;
    size_t inSize = 0;
    NTSTATUS status;

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_FILE_SET_INTEGRITY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WCHAR path[MYARK_FILE_PATH_CHARS];
    ULONG level = inBuf->Level;
    ULONG flags = inBuf->Flags;
    RtlCopyMemory(path, inBuf->Path, sizeof(path));

    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_FILE_OP_SET_INTEGRITY,
                                      (UINT32)(UINT_PTR)PsGetCurrentProcessId());
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    if (level != MYARK_FILE_INTEGRITY_LEVEL_LOW
        && level != MYARK_FILE_INTEGRITY_LEVEL_MEDIUM
        && level != MYARK_FILE_INTEGRITY_LEVEL_HIGH
        && level != MYARK_FILE_INTEGRITY_LEVEL_SYSTEM) {
        return STATUS_INVALID_PARAMETER;
    }

    status = MyArkFileValidatePath(path, path);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UINT8 sd[MYARK_LABEL_SD_SIZE_PLACEHOLDER];
    (void)sd;
    return STATUS_NOT_SUPPORTED;
}
#endif

NTSTATUS
MyArkFileIoctlQueryIntegrity(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PMYARK_FILE_QUERY_INTEGRITY_INPUT inBuf = NULL;
    size_t inSize = 0;
    NTSTATUS status;

    if (InputBufferLength < sizeof(MYARK_FILE_QUERY_INTEGRITY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_FILE_QUERY_INTEGRITY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WCHAR path[MYARK_FILE_PATH_CHARS];
    RtlCopyMemory(path, inBuf->Path, sizeof(path));
    status = MyArkFileValidatePath(path, path);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UNICODE_STRING pathUs;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    RtlInitUnicodeString(&pathUs, path);
    InitializeObjectAttributes(&oa, &pathUs,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);
    HANDLE file = NULL;
    status = ZwOpenFile(&file,
                        // Mandatory-label reads are special-cased to
                        // READ_CONTROL since Vista -- ACCESS_SYSTEM_
                        // SECURITY would demand SeSecurityPrivilege.
                        READ_CONTROL,
                        &oa, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UCHAR labelBuf[128];
    ULONG needed = 0;
    status = ZwQuerySecurityObject(file, LABEL_SECURITY_INFORMATION,
                                   labelBuf, sizeof(labelBuf), &needed);
    ZwClose(file);
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }

    UINT32 found = 0;
    UINT32 rid = 0;
    UINT32 mask = 0;
    USHORT control = *(USHORT *)&labelBuf[2];
    USHORT saclOffset = *(USHORT *)&labelBuf[12];
    if ((control & MYARK_SE_SACL_PRESENT) != 0 && saclOffset != 0
        && saclOffset + 8 <= sizeof(labelBuf)) {
        PUCHAR acl = labelBuf + saclOffset;
        USHORT aceCount = *(USHORT *)&acl[4];
        USHORT off = 8;
        for (USHORT i = 0; i < aceCount; i++) {
            if (saclOffset + off + 8 > sizeof(labelBuf)) {
                break;
            }
            PUCHAR ace = acl + off;
            USHORT aceSize = *(USHORT *)&ace[2];
            if (aceSize < 4) {
                break;      // malformed/zero-size ACE: bounded walk
            }
            if (ace[0] == MYARK_LABEL_ACE_TYPE
                && saclOffset + off + 20 <= sizeof(labelBuf)) {
                mask = *(ULONG *)&ace[4];
                //
                // SYSTEM_MANDATORY_LABEL_ACE: header(4) + mask(4) + SID(12,
                // S-1-16-<rid>). SubAuthority[0] sits at ACE+16; the real
                // ACE size is 20 bytes (review 2026-09-16: the +20 offset
                // previously read past the SID).
                //
                rid = *(ULONG *)&ace[16];
                found = 1;
                break;
            }
            off += aceSize;
        }
    }

    PMYARK_FILE_QUERY_INTEGRITY_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_FILE_QUERY_INTEGRITY_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    outBuf->Status = 0;
    outBuf->LabelFound = found;
    outBuf->Level = rid;
    outBuf->Flags = mask;
    *BytesReturned = sizeof(MYARK_FILE_QUERY_INTEGRITY_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_FILE
