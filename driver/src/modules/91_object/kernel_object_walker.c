// kernel-object module: object-directory walker (R3-4b).
//
// Reads one object-manager directory through the exported Zw surface:
// ZwOpenDirectoryObject(DIRECTORY_QUERY) + a ReturnSingleEntry loop of
// ZwQueryDirectoryObject. No unexported offsets, no raw pointer decode --
// the same code runs unchanged on 18362..22631 and any future build.
//
// Per-call state is 256 bytes (one OBJECT_DIRECTORY_INFORMATION); strings
// point into that buffer, so each row is copied out before the next query.
// Everything is PASSIVE_LEVEL by construction (Zw* file-object-based calls
// require it, and the KMDF queue dispatches at PASSIVE).

#include "myark_config.h"
#include "kernel_object_internal.h"
#include "Trace.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"

#if MYARK_MODULE_KERNEL_OBJECT

//
// Copy a UNICODE_STRING into a fixed WCHAR row field, clamping to
// (FieldMax - 1) chars + NUL. Object names longer than the cap are
// truncated (kept as a row rather than dropped -- the summary tolerates
// truncated names, NPFS instance names are the long case).
//
static VOID
MyArkKobjCopyName(
    _Out_writes_(FieldMax) WCHAR* Dest,
    _In_ ULONG FieldMax,
    _In_ PCUNICODE_STRING Source)
{
    ULONG chars = Source->Length / sizeof(WCHAR);

    if (chars > FieldMax - 1) {
        chars = FieldMax - 1;
    }
    if (chars > 0 && Source->Buffer != NULL) {
        RtlCopyMemory(Dest, Source->Buffer, chars * sizeof(WCHAR));
    }
    Dest[chars] = L'\0';
}

NTSTATUS
MyArkKobjQueryDirectory(
    _In_ PCWSTR Path,
    _Out_writes_all_(Capacity) MYARK_KOBJ_ENTRY* Rows,
    _In_ ULONG Capacity,
    _Out_ PULONG CountOut,
    _Out_ PULONG TruncatedOut,
    _Out_ NTSTATUS* OpenStatusOut,
    _Out_ NTSTATUS* WalkStatusOut)
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES attr;
    HANDLE dirHandle = NULL;
    PMYARK_KOBJ_DIR_INFO info;
    ULONG context = 0;
    ULONG returned = 0;
    ULONG count = 0;
    ULONG truncated = 0;
    NTSTATUS status;

    *CountOut = 0;
    *TruncatedOut = 0;
    *OpenStatusOut = (NTSTATUS)0;
    *WalkStatusOut = (NTSTATUS)0;

    if (Capacity == 0 || Capacity > MYARK_KOBJ_DIR_CAP) {
        return STATUS_INVALID_PARAMETER;
    }

    // DECLARE_CONST_UNICODE_STRING cannot be used here: it sizes the string
    // from `sizeof(buffer)`, which is 8 for a PCWSTR parameter. The caller
    // passes a bounded (<= PATH_MAX) runtime buffer, so wcslen is safe.
    RtlInitUnicodeString(&path, Path);
    InitializeObjectAttributes(&attr,
                               &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    status = ZwOpenDirectoryObject(&dirHandle, DIRECTORY_QUERY, &attr);
    if (!NT_SUCCESS(status)) {
        *OpenStatusOut = status;
        // Reported through OpenStatus rather than a failing IOCTL: the
        // IPC summary must stay one-shot when one of its two subjects
        // (e.g. MailSlot) is unavailable on a hardened build.
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   MYARK_TRACE_KOBJ "open %ws failed 0x%08X\n", Path, status);
        return STATUS_SUCCESS;
    }

    // The single-entry record AND its strings must fit in one buffer; a
    // bare 32-byte OBJECT_DIRECTORY_INFORMATION is rejected with
    // STATUS_BUFFER_TOO_SMALL.
    info = (PMYARK_KOBJ_DIR_INFO)MyArkAllocatePool(
        NonPagedPoolNx, MYARK_KOBJ_QUERY_BUFFER, MYARK_KOBJ_POOL_TAG);
    if (info == NULL) {
        ZwClose(dirHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (;;) {
        RtlZeroMemory(info, MYARK_KOBJ_QUERY_BUFFER);
        status = ZwQueryDirectoryObject(dirHandle,
                                        info,
                                        MYARK_KOBJ_QUERY_BUFFER,
                                        TRUE,           // ReturnSingleEntry
                                        (count == 0 && !truncated),  // RestartScan
                                        &context,
                                        &returned);
        *WalkStatusOut = status;
        if (!NT_SUCCESS(status)) {
            // STATUS_NO_MORE_ENTRIES is the normal end; anything else
            // stops the walk with whatever rows were collected.
            break;
        }
        if (info->Name.Length == 0 || info->Name.Buffer == NULL) {
            break;      // defensive: terminator row
        }

        if (count >= Capacity) {
            truncated = 1;
            break;
        }

        MyArkKobjCopyName(Rows[count].Name, MYARK_KOBJ_NAME_MAX, &info->Name);
        MyArkKobjCopyName(Rows[count].TypeName, MYARK_KOBJ_TYPE_MAX,
                          &info->TypeName);
        count += 1;
    }

    ExFreePoolWithTag(info, MYARK_KOBJ_POOL_TAG);
    ZwClose(dirHandle);

    *CountOut = count;
    *TruncatedOut = truncated;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkKobjQueryFileDirectory(
    _In_ PCWSTR Path,
    _In_ PCWSTR TypeNameOut,
    _Out_writes_all_(Capacity) MYARK_KOBJ_ENTRY* Rows,
    _In_ ULONG Capacity,
    _Out_ PULONG CountOut,
    _Out_ PULONG TruncatedOut,
    _Out_ NTSTATUS* OpenStatusOut,
    _Out_ NTSTATUS* WalkStatusOut)
{
    UNICODE_STRING path;
    UNICODE_STRING pattern;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE dirHandle = NULL;
    PUCHAR queryBuffer;
    UNICODE_STRING typeName;
    ULONG count = 0;
    ULONG truncated = 0;
    BOOLEAN restart = TRUE;
    ULONG batches = 0;
    NTSTATUS status;

    *CountOut = 0;
    *TruncatedOut = 0;
    *OpenStatusOut = (NTSTATUS)0;
    *WalkStatusOut = (NTSTATUS)0;

    if (Capacity == 0 || Capacity > MYARK_KOBJ_DIR_CAP) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&path, Path);
    RtlInitUnicodeString(&pattern, L"*");
    InitializeObjectAttributes(&attr,
                               &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    //
    // Path must be the device name WITH a trailing backslash (the root
    // directory) and the open must NOT use FILE_DIRECTORY_FILE: opening
    // \Device\NamedPipe bare yields the control-device handle, which
    // answers every directory query with STATUS_INVALID_PARAMETER.
    // SYNCHRONIZE + FILE_SYNCHRONOUS_IO_NONALERT make the handle
    // synchronous so ZwQueryDirectoryFile can never return PENDING with
    // an undefined iosb.Information.
    //
    status = ZwCreateFile(&dirHandle,
                          FILE_LIST_DIRECTORY | SYNCHRONIZE,
                          &attr,
                          &iosb,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN,
                          FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);
    if (!NT_SUCCESS(status)) {
        *OpenStatusOut = status;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   MYARK_TRACE_KOBJ "fs-open %ws failed 0x%08X\n", Path, status);
        return STATUS_SUCCESS;      // one-shot summary: report in-band
    }

    queryBuffer = (PUCHAR)MyArkAllocatePool(
        NonPagedPoolNx, MYARK_KOBJ_QUERY_BUFFER, MYARK_KOBJ_POOL_TAG);
    if (queryBuffer == NULL) {
        ZwClose(dirHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitUnicodeString(&typeName, TypeNameOut);

    for (;;) {
        PMYARK_KOBJ_FILE_NAMES_INFO rec;
        ULONG offset = 0;

        // Defensive cap: a compliant FS answers every successful batch
        // with Information > 0, so progress is guaranteed; without this a
        // malformed always-empty success answer would spin forever.
        if (++batches > 128) {
            break;
        }

        status = ZwQueryDirectoryFile(dirHandle,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &iosb,
                                      queryBuffer,
                                      MYARK_KOBJ_QUERY_BUFFER,
                                      FileNamesInformation,
                                      FALSE,            // full batch
                                      &pattern,
                                      restart);
        *WalkStatusOut = status;
        if (!NT_SUCCESS(status)) {
            break;      // STATUS_NO_MORE_FILES is the normal end
        }
        restart = FALSE;

        rec = (PMYARK_KOBJ_FILE_NAMES_INFO)queryBuffer;
        for (;;) {
            ULONG chars;

            if (count >= Capacity) {
                truncated = 1;
                break;
            }
            // Upper bounds first: the fixed header AND a full entry must
            // stay inside both the returned span and the pool buffer --
            // NextEntryOffset chains are kernel data, treat as untrusted.
            if (offset + MYARK_KOBJ_FNI_HEADER_SIZE > (ULONG)iosb.Information ||
                offset + MYARK_KOBJ_FNI_HEADER_SIZE > MYARK_KOBJ_QUERY_BUFFER) {
                break;  // defensive: truncated/malformed batch
            }

            chars = rec->FileNameLength / sizeof(WCHAR);
            if (chars > MYARK_KOBJ_NAME_MAX - 1) {
                chars = MYARK_KOBJ_NAME_MAX - 1;
            }
            // Clamp to what the batch span can actually back: a malformed
            // FileNameLength must not read past the returned data.
            if (offset + MYARK_KOBJ_FNI_HEADER_SIZE + chars * sizeof(WCHAR)
                > (ULONG)iosb.Information) {
                ULONG avail = (ULONG)iosb.Information
                              - offset - MYARK_KOBJ_FNI_HEADER_SIZE;
                chars = avail / sizeof(WCHAR);
                if (chars > MYARK_KOBJ_NAME_MAX - 1) {
                    chars = MYARK_KOBJ_NAME_MAX - 1;
                }
            }
            RtlCopyMemory(Rows[count].Name, rec->FileName,
                          chars * sizeof(WCHAR));
            Rows[count].Name[chars] = L'\0';
            MyArkKobjCopyName(Rows[count].TypeName, MYARK_KOBJ_TYPE_MAX,
                              &typeName);
            count += 1;

            if (rec->NextEntryOffset == 0) {
                break;
            }
            offset += rec->NextEntryOffset;
            rec = (PMYARK_KOBJ_FILE_NAMES_INFO)(queryBuffer + offset);
        }

        if (truncated) {
            break;
        }
    }

    ExFreePoolWithTag(queryBuffer, MYARK_KOBJ_POOL_TAG);
    ZwClose(dirHandle);

    *CountOut = count;
    *TruncatedOut = truncated;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_KERNEL_OBJECT
