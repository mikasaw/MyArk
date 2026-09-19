// MyArk kernel-object module: internal constants + walker prototype.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "myark_config.h"

#if MYARK_MODULE_KERNEL_OBJECT

#include "../../../shared/driver/MyArkKernelObjectIoctl.h"

#define MYARK_TRACE_KOBJ "[kobj] "
#define MYARK_KOBJ_POOL_TAG 'JBOk'          // 'KOBJ' reversed

//
// The ZwOpenDirectoryObject/ZwQueryDirectoryObject pair and
// OBJECT_DIRECTORY_INFORMATION are declared in ntifs.h, which this
// translation unit intentionally does not pull in (the rest of the driver
// builds against ntddk+wdf only). Local mirror declarations; layout matches
// the documented ntifs.h shapes.
//

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenDirectoryObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_ PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING FileName,
    _In_ BOOLEAN RestartScan);

typedef struct _MYARK_KOBJ_DIR_INFO {
    UNICODE_STRING Name;                     // points into the query buffer
    UNICODE_STRING TypeName;
} MYARK_KOBJ_DIR_INFO, *PMYARK_KOBJ_DIR_INFO;

C_ASSERT(sizeof(MYARK_KOBJ_DIR_INFO) == 2 * sizeof(UNICODE_STRING));

//
// Mirror of FILE_NAMES_INFORMATION (ntifs.h). NPFS/MSFS roots are DEVICE
// objects -- opening them without the trailing backslash yields a control
// handle that rejects directory queries with STATUS_INVALID_PARAMETER, and
// the query itself must carry a non-NULL "*" pattern (NPFS has no default
// template). "\Device\NamedPipe\" + pattern is the one combination that
// enumerates (verified user- and kernel-mode, see CRASH_DEBUG_LOG).
//
typedef struct _MYARK_KOBJ_FILE_NAMES_INFO {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;                    // bytes, excluding the NUL
    WCHAR FileName[1];
} MYARK_KOBJ_FILE_NAMES_INFO, *PMYARK_KOBJ_FILE_NAMES_INFO;

#define MYARK_KOBJ_FNI_HEADER_SIZE 12
#define MYARK_KOBJ_QUERY_BUFFER    4096

//
// Walk one object-manager directory (ZwOpenDirectoryObject path), filling
// Rows[0..Capacity). Read-only; every step goes through the exported Zw
// surface, so no build profile applies.
//
NTSTATUS
MyArkKobjQueryDirectory(
    _In_ PCWSTR Path,
    _Out_writes_all_(Capacity) MYARK_KOBJ_ENTRY* Rows,
    _In_ ULONG Capacity,
    _Out_ PULONG CountOut,
    _Out_ PULONG TruncatedOut,
    _Out_ NTSTATUS* OpenStatusOut,
    _Out_ NTSTATUS* WalkStatusOut);

//
// Walk a filesystem directory root (ZwCreateFile + ZwQueryDirectoryFile
// path) -- used for \Device\NamedPipe\ and \Device\MailSlot\. TypeNameOut
// is stamped into every row ("NamedPipe" / "MailSlot").
//
NTSTATUS
MyArkKobjQueryFileDirectory(
    _In_ PCWSTR Path,
    _In_ PCWSTR TypeNameOut,
    _Out_writes_all_(Capacity) MYARK_KOBJ_ENTRY* Rows,
    _In_ ULONG Capacity,
    _Out_ PULONG CountOut,
    _Out_ PULONG TruncatedOut,
    _Out_ NTSTATUS* OpenStatusOut,
    _Out_ NTSTATUS* WalkStatusOut);

#endif // MYARK_MODULE_KERNEL_OBJECT
