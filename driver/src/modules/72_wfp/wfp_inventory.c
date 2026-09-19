// wfp inventory (R3-15): system network-filter inventory, read-only.
//
// 0x8A2 ENUM_NDIS_FILTERS - every NDIS filter instance installed on the
//     system, enumerated from the NetService network class
//     (HKLM\SYSTEM\CCS\Control\Network\{4D36E975-...}) via documented
//     Zw* registry APIs at PASSIVE_LEVEL. One row per (service,
//     instance): the filter service name ("ms_lltdio", "wfplwfs", ...),
//     the instance GUID, and the friendly name from Connection\Name.
//     Honest limitation: the *live per-adapter attach order* is only
//     visible to INF-installed NDIS filter drivers -- a runtime
//     protocol registration never receives bind notifications
//     (verified on 1903: BindAdapterEx is never called for an
//     INF-less protocol, even after NdisReEnumerateProtocolBindings).
//
// 0x8A3 ENUM_CALLOUT_DRIVERS - every loaded driver whose PE import
//     table references fwpkclnt.sys (WFP callout capable) and/or
//     ndis.sys. Walks the same PsLoadedModuleList the dyndata module
//     resolves, reading only via address-valid-gated probes. A driver
//     whose import directory cannot be parsed is emitted with
//     FLAG_PARSE_FAILED instead of being skipped, so the row count
//     always accounts for the whole module list.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

#include "Trace.h"
#include "myark_config.h"
#include "wfp_descriptor.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../../shared/driver/MyArkWfpIoctl.h"

#if MYARK_MODULE_WFP

#define MYARK_TRACE_WFP_INV "[wfp-inv] "

#define MYARK_WFP_NDIS_GUID_CHARS  40   // WCHARs of the local GUID scratch buffer
#define MYARK_WFP_NDIS_GUID_BYTES  40   // bytes copied into CHAR InstanceGuid[40]

//
// KLDR_DATA_TABLE_ENTRY offsets (same build data as 70_dyndata;
// SizeOfImage@0x40 verified by the KLDRDIAG probe, 2026-09-16).
//
#define MYARK_WFP_KLDR_IN_LOAD_ORDER_LINKS   0x000UL
#define MYARK_WFP_KLDR_DLL_BASE              0x030UL
#define MYARK_WFP_KLDR_SIZE_OF_IMAGE         0x040UL
#define MYARK_WFP_KLDR_BASE_DLL_NAME         0x058UL

// ---------------------------------------------------------------------------
// UTF-16 -> UTF-8/ANSI copy (low byte), bounded and NUL-terminated.
// ---------------------------------------------------------------------------

static
ULONG
MyArkWfpInvCopyWchar(
    _In_reads_(SourceChars) const WCHAR* Source,
    _In_   ULONG   SourceChars,
    _Out_writes_bytes_(BufferBytes) PUCHAR Dest,
    _In_   ULONG   BufferBytes)
{
    if (Source == NULL || Dest == NULL || BufferBytes == 0) {
        return 0;
    }
    ULONG copy = BufferBytes - 1;
    if (copy > SourceChars) {
        copy = SourceChars;
    }
    for (ULONG i = 0; i < copy; i++) {
        Dest[i] = (UCHAR)Source[i];
    }
    Dest[copy] = 0;
    return copy;
}

// ---------------------------------------------------------------------------
// Bounded probe reads for the PE import walk (driver image memory).
// ---------------------------------------------------------------------------

static
BOOLEAN
MyArkWfpInvReadU8(_In_ PUCHAR Address, _Out_ PUCHAR ValueOut)
{
    if (Address == NULL || !MmIsAddressValid(Address)) {
        return FALSE;
    }
    *ValueOut = *Address;
    return TRUE;
}

static
BOOLEAN
MyArkWfpInvReadU16(_In_ PUCHAR Address, _Out_ PUSHORT ValueOut)
{
    if (Address == NULL || !MmIsAddressValid(Address) || !MmIsAddressValid(Address + 1)) {
        return FALSE;
    }
    *ValueOut = *(PUSHORT)Address;
    return TRUE;
}

static
BOOLEAN
MyArkWfpInvReadU32(_In_ PUCHAR Address, _Out_ PUINT32 ValueOut)
{
    if (Address == NULL
        || !MmIsAddressValid(Address)
        || !MmIsAddressValid(Address + 3)) {
        return FALSE;
    }
    *ValueOut = *(PUINT32)Address;
    return TRUE;
}

// ---------------------------------------------------------------------------
// 0x8A2: NetService class registry walk.
// ---------------------------------------------------------------------------

#define MYARK_WFP_NETSERVICE_CLASS \
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Network" \
    L"\\{4D36E975-E325-11CE-BFC1-08002BE10318}"

//
// Read <service>\<instance>\Connection : Name (REG_SZ) into an ANSI
// buffer. Missing value -> empty string (a missing key/value is an
// inventory observation, not an error).
//
static
VOID
MyArkWfpInvReadFriendlyName(
    _In_  PUNICODE_STRING ClassPath,
    _In_  PCWSTR ServiceName,
    _In_  ULONG  ServiceChars,
    _In_  PCWSTR InstanceGuid,
    _In_  ULONG  GuidChars,
    _Out_writes_bytes_(BufferBytes) PUCHAR Dest,
    _In_  ULONG  BufferBytes)
{
    WCHAR path[300];
    UNICODE_STRING uni;
    OBJECT_ATTRIBUTES attrs;
    HANDLE key = NULL;
    UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 128 * sizeof(WCHAR)];
    ULONG needed = 0;
    NTSTATUS status;

    if (BufferBytes == 0 || Dest == NULL) {
        return;
    }
    Dest[0] = 0;

    status = RtlStringCchPrintfW(path, RTL_NUMBER_OF(path),
                                 L"%wZ\\%.*s\\%.*s\\Connection",
                                 ClassPath,
                                 (int)ServiceChars, ServiceName,
                                 (int)GuidChars, InstanceGuid);
    if (!NT_SUCCESS(status)) {
        return;
    }

    RtlInitUnicodeString(&uni, path);
    InitializeObjectAttributes(&attrs, &uni,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &attrs))) {
        return;
    }

    RtlInitUnicodeString(&uni, L"Name");
    if (NT_SUCCESS(ZwQueryValueKey(key, &uni, KeyValuePartialInformation,
                                   buf, sizeof(buf), &needed))) {
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        if (info->Type == REG_SZ && info->DataLength >= sizeof(WCHAR)) {
            ULONG chars = info->DataLength / sizeof(WCHAR);
            if (chars > 0 && ((PWCHAR)info->Data)[chars - 1] == L'\0') {
                chars--;
            }
            MyArkWfpInvCopyWchar((PWCHAR)info->Data, chars, Dest, BufferBytes);
        }
    }
    ZwClose(key);
}

//
// Read one REG_SZ value into a WCHAR buffer. Returns chars written
// (0 when the key/value is missing or not a string).
//
static
ULONG
MyArkWfpInvReadRegString(
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName,
    _Out_writes_(OutChars) WCHAR *Out,
    _In_ ULONG  OutChars)
{
    UNICODE_STRING uni;
    OBJECT_ATTRIBUTES attrs;
    HANDLE key = NULL;
    UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 128 * sizeof(WCHAR)];
    ULONG needed = 0;

    if (Out == NULL || OutChars == 0) {
        return 0;
    }
    Out[0] = L'\0';

    RtlInitUnicodeString(&uni, KeyPath);
    InitializeObjectAttributes(&attrs, &uni,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &attrs))) {
        return 0;
    }

    ULONG chars = 0;
    RtlInitUnicodeString(&uni, ValueName);
    if (NT_SUCCESS(ZwQueryValueKey(key, &uni, KeyValuePartialInformation,
                                   buf, sizeof(buf), &needed))) {
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        if (info->Type == REG_SZ && info->DataLength >= sizeof(WCHAR)) {
            chars = info->DataLength / sizeof(WCHAR);
            if (chars > 0 && ((PWCHAR)info->Data)[chars - 1] == L'\0') {
                chars--;
            }
            if (chars >= OutChars) {
                chars = OutChars - 1;
            }
            RtlCopyMemory(Out, info->Data, chars * sizeof(WCHAR));
            Out[chars] = L'\0';
        }
    }
    ZwClose(key);
    return chars;
}

static
NTSTATUS
MyArkWfpInvEnumNdisFilters(
    _Out_writes_bytes_(OutSize) PUCHAR OutBuf,
    _In_  SIZE_T  OutSize,
    _Out_ PULONG  BytesReturned)
{
    NTSTATUS status;
    UNICODE_STRING uniClass;
    UNICODE_STRING uni;
    OBJECT_ATTRIBUTES attrs;
    HANDLE classKey = NULL;
    UCHAR subBuf[sizeof(KEY_BASIC_INFORMATION) + 128 * sizeof(WCHAR)];
    ULONG needed = 0;
    ULONG maxEntries;
    ULONG written = 0;
    SIZE_T headSize = FIELD_OFFSET(MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT, Entries[0]);

    PMYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT out =
        (PMYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT)OutBuf;

    maxEntries = (ULONG)((OutSize - headSize) / sizeof(MYARK_WFP_NDIS_FILTER_ENTRY));

    //
    // uniClass stays pinned to the class literal for the whole walk; the
    // reusable `uni` is re-initialised before every ZwOpenKey. Never
    // format FROM `uni` INTO a buffer that `uni` points at (overlap).
    //
    RtlInitUnicodeString(&uniClass, MYARK_WFP_NETSERVICE_CLASS);
    InitializeObjectAttributes(&attrs, &uniClass,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwOpenKey(&classKey, KEY_READ, &attrs);
    if (!NT_SUCCESS(status)) {
        // Class key absent: an empty-but-successful inventory.
        out->Count = 0;
        out->EntryStructSize = (UINT32)sizeof(MYARK_WFP_NDIS_FILTER_ENTRY);
        *BytesReturned = (ULONG)headSize;
        return STATUS_SUCCESS;
    }

    for (ULONG s = 0; s < MYARK_WFP_CDRIVER_HARD_CAP; s++) {
        PKEY_BASIC_INFORMATION svcInfo = (PKEY_BASIC_INFORMATION)subBuf;
        status = ZwEnumerateKey(classKey, s, KeyBasicInformation,
                                subBuf, sizeof(subBuf), &needed);
        if (status == STATUS_NO_MORE_ENTRIES || status == STATUS_INVALID_PARAMETER_2) {
            break;
        }
        if (!NT_SUCCESS(status)) {
            continue;
        }

        WCHAR svcName[MYARK_WFP_NDIS_NAME_MAX];
        ULONG svcChars = svcInfo->NameLength / sizeof(WCHAR);
        if (svcChars == 0 || svcChars >= RTL_NUMBER_OF(svcName)) {
            continue;
        }
        RtlCopyMemory(svcName, svcInfo->Name, svcChars * sizeof(WCHAR));
        svcName[svcChars] = L'\0';

        WCHAR svcPath[300];
        if (!NT_SUCCESS(RtlStringCchPrintfW(svcPath, RTL_NUMBER_OF(svcPath),
                                            L"%wZ\\%.*s",
                                            &uniClass, (int)svcChars, svcName))) {
            continue;
        }

        HANDLE svcKey = NULL;
        RtlInitUnicodeString(&uni, svcPath);
        InitializeObjectAttributes(&attrs, &uni,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL, NULL);
        if (!NT_SUCCESS(ZwOpenKey(&svcKey, KEY_READ, &attrs))) {
            continue;
        }

        ULONG instancesFound = 0;

        for (ULONG i = 0; i < MYARK_WFP_CDRIVER_HARD_CAP && written < maxEntries; i++) {
            PKEY_BASIC_INFORMATION instInfo = (PKEY_BASIC_INFORMATION)subBuf;
            status = ZwEnumerateKey(svcKey, i, KeyBasicInformation,
                                    subBuf, sizeof(subBuf), &needed);
            if (status == STATUS_NO_MORE_ENTRIES || status == STATUS_INVALID_PARAMETER_2) {
                break;
            }
            if (!NT_SUCCESS(status)) {
                continue;
            }

            WCHAR instGuid[MYARK_WFP_NDIS_GUID_CHARS];
            ULONG instChars = instInfo->NameLength / sizeof(WCHAR);
            if (instChars == 0 || instChars >= RTL_NUMBER_OF(instGuid)) {
                continue;
            }
            RtlCopyMemory(instGuid, instInfo->Name, instChars * sizeof(WCHAR));
            instGuid[instChars] = L'\0';

            PMYARK_WFP_NDIS_FILTER_ENTRY row = &out->Entries[written];
            RtlZeroMemory(row, sizeof(*row));
            MyArkWfpInvCopyWchar(svcName, svcChars,
                                 (PUCHAR)row->ServiceName,
                                 MYARK_WFP_NDIS_NAME_MAX);
            MyArkWfpInvCopyWchar(instGuid, instChars,
                                 (PUCHAR)row->InstanceGuid,
                                 MYARK_WFP_NDIS_GUID_BYTES);
            MyArkWfpInvReadFriendlyName(&uniClass, svcName, svcChars,
                                        instGuid, instChars,
                                        (PUCHAR)row->FriendlyName,
                                        MYARK_WFP_NDIS_NAME_MAX);
            written++;
            instancesFound++;
        }

        //
        // Win11 26100+ layout: the class carries GUID-named install
        // records with ComponentId / Ndi\Service values instead of the
        // legacy service\instance\Connection tree. Emit one row per
        // record with ServiceName=ComponentId, InstanceGuid=record name.
        //
        if (instancesFound == 0 && written < maxEntries) {
            WCHAR compId[MYARK_WFP_NDIS_NAME_MAX];
            ULONG compChars = MyArkWfpInvReadRegString(svcPath, L"ComponentId",
                                                       compId, RTL_NUMBER_OF(compId));
            if (compChars > 0) {
                PMYARK_WFP_NDIS_FILTER_ENTRY row = &out->Entries[written];
                RtlZeroMemory(row, sizeof(*row));
                MyArkWfpInvCopyWchar(compId, compChars,
                                     (PUCHAR)row->ServiceName,
                                     MYARK_WFP_NDIS_NAME_MAX);
                MyArkWfpInvCopyWchar(svcName, svcChars,
                                     (PUCHAR)row->InstanceGuid,
                                     MYARK_WFP_NDIS_GUID_BYTES);
                written++;
            }
        }

        ZwClose(svcKey);

        if (written >= maxEntries) {
            break;
        }
    }

    ZwClose(classKey);

    out->Count = written;
    out->EntryStructSize = (UINT32)sizeof(MYARK_WFP_NDIS_FILTER_ENTRY);
    *BytesReturned = (ULONG)(headSize + (SIZE_T)written * sizeof(MYARK_WFP_NDIS_FILTER_ENTRY));
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkWfpIoctlEnumNdisFilters(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    NTSTATUS status;
    PVOID    outBuf = NULL;
    SIZE_T   outSize = 0;
    SIZE_T   headSize = FIELD_OFFSET(MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT, Entries[0]);

    if (OutputBufferLength < headSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request, headSize, &outBuf, &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, headSize);

    ULONG bytesReturned = 0;
    status = MyArkWfpInvEnumNdisFilters((PUCHAR)outBuf, outSize, &bytesReturned);
    *BytesReturned = bytesReturned;
    return status;
}

// ---------------------------------------------------------------------------
// 0x8A3 helpers: does this image import <dll name>? Bounded walk of the
// PE32+ import directory; only DWORD RVAs are involved (identical layout
// for the import directory of PE32 and PE32+).
// ---------------------------------------------------------------------------

static
BOOLEAN
MyArkWfpInvImageImportsDll(
    _In_  PUCHAR  NameVa,
    _In_  PCSTR   DllName)
{
    CHAR    name[32];
    ULONG   nameLen = 0;

    while (nameLen < RTL_NUMBER_OF(name) - 1) {
        UCHAR ch = 0;
        if (!MyArkWfpInvReadU8(NameVa + nameLen, &ch)) {
            return FALSE;
        }
        if (ch == 0) {
            break;
        }
        name[nameLen++] = (CHAR)ch;
    }
    name[nameLen] = 0;

    return _stricmp(name, DllName) == 0;
}

static
BOOLEAN
MyArkWfpInvCheckImports(
    _In_  PUCHAR  ImageBase,
    _In_  UINT32  ImportDirRva,
    _In_  UINT32  SizeOfImage,
    _Out_ PBOOLEAN FwpCapable,
    _Out_ PBOOLEAN NdisCapable)
{
    *FwpCapable = FALSE;
    *NdisCapable = FALSE;

    if (ImportDirRva == 0 || ImportDirRva >= SizeOfImage) {
        return FALSE;
    }

    PUCHAR desc = ImageBase + ImportDirRva;

    for (ULONG i = 0; i < 64; i++) {
        UINT32 originalFirstThunk = 0;
        UINT32 nameRva = 0;
        UINT32 firstThunk = 0;

        if (!MyArkWfpInvReadU32(desc + i * 20 + 0, &originalFirstThunk)
            || !MyArkWfpInvReadU32(desc + i * 20 + 12, &nameRva)
            || !MyArkWfpInvReadU32(desc + i * 20 + 16, &firstThunk)) {
            return FALSE;
        }
        if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0) {
            break;                       // null descriptor terminates the table
        }
        if (nameRva == 0 || nameRva >= SizeOfImage) {
            continue;
        }

        if (MyArkWfpInvImageImportsDll(ImageBase + nameRva, "fwpkclnt.sys")) {
            *FwpCapable = TRUE;
        } else if (MyArkWfpInvImageImportsDll(ImageBase + nameRva, "ndis.sys")) {
            *NdisCapable = TRUE;
        }
        if (*FwpCapable && *NdisCapable) {
            break;
        }
    }

    return TRUE;
}

// ---------------------------------------------------------------------------
// 0x8A3 handler.
// ---------------------------------------------------------------------------

// PsLoadedModuleList head, resolved by the 70_dyndata resolver
// (same extern the 71_callback walker imports).
extern PVOID g_MyArkDynDataPsLoadedModuleList;

NTSTATUS
MyArkWfpIoctlEnumCalloutDrivers(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    NTSTATUS status;
    PVOID    outBuf = NULL;
    SIZE_T   outSize = 0;
    SIZE_T   headSize = FIELD_OFFSET(MYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT, Entries[0]);

    if (OutputBufferLength < headSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request, headSize, &outBuf, &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT out =
        (PMYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT)outBuf;
    RtlZeroMemory(outBuf, headSize);
    out->PsLoadedModuleList = (UINT64)(UINT_PTR)g_MyArkDynDataPsLoadedModuleList;

    ULONG maxEntries = (ULONG)((outSize - headSize) / sizeof(MYARK_WFP_CALLOUT_DRIVER_ENTRY));
    ULONG written = 0;
    ULONG totalSeen = 0;
    ULONG iterGuard = MYARK_WFP_CDRIVER_HARD_CAP;

    if (g_MyArkDynDataPsLoadedModuleList == NULL
        || !MmIsAddressValid(g_MyArkDynDataPsLoadedModuleList)) {
        out->Count = 0;
        out->TotalSeen = 0;
        out->EntryStructSize = (UINT32)sizeof(MYARK_WFP_CALLOUT_DRIVER_ENTRY);
        *BytesReturned = headSize;
        return STATUS_SUCCESS;
    }

    PLIST_ENTRY head = (PLIST_ENTRY)g_MyArkDynDataPsLoadedModuleList;
    PLIST_ENTRY node = head->Flink;

    while (node != NULL && node != head && iterGuard > 0
           && totalSeen < MYARK_WFP_CDRIVER_HARD_CAP) {
        iterGuard--;

        if (!MmIsAddressValid(node)) {
            break;
        }

        PUCHAR kldrBase = (PUCHAR)node - MYARK_WFP_KLDR_IN_LOAD_ORDER_LINKS;
        if (!MmIsAddressValid(kldrBase)) {
            break;
        }

        UINT64 imageBase = 0;
        UINT64 imageSize = 0;
        if (!MyArkWfpInvReadU32(kldrBase + MYARK_WFP_KLDR_DLL_BASE, (PUINT32)&imageBase)
            || !MyArkWfpInvReadU32(kldrBase + MYARK_WFP_KLDR_DLL_BASE + 4,
                                   (PUINT32)((PUCHAR)&imageBase + 4))
            || !MyArkWfpInvReadU32(kldrBase + MYARK_WFP_KLDR_SIZE_OF_IMAGE,
                                   (PUINT32)&imageSize)) {
            break;
        }

        //
        // One row per module, always: parse failures carry
        // FLAG_PARSE_FAILED instead of dropping the row.
        //
        PMYARK_WFP_CALLOUT_DRIVER_ENTRY row;
        if (written < maxEntries) {
            row = &out->Entries[written];
            RtlZeroMemory(row, sizeof(*row));
        } else {
            row = NULL;                   // counted but not stored
        }

        if (row != NULL) {
            row->ImageBase = imageBase;
            row->ImageSize = imageSize;

            PUNICODE_STRING baseName =
                (PUNICODE_STRING)(kldrBase + MYARK_WFP_KLDR_BASE_DLL_NAME);
            if (MmIsAddressValid(baseName)) {
                USHORT nameChars = baseName->Length / sizeof(WCHAR);
                if (baseName->Buffer != NULL && nameChars > 0
                    && MmIsAddressValid(baseName->Buffer)) {
                    if (nameChars > MYARK_WFP_CDRIVER_NAME_MAX - 1) {
                        nameChars = MYARK_WFP_CDRIVER_NAME_MAX - 1;
                    }
                    MyArkWfpInvCopyWchar(baseName->Buffer, nameChars,
                                         (PUCHAR)row->Name,
                                         MYARK_WFP_CDRIVER_NAME_MAX);
                }
            }
        }

        BOOLEAN fwpCapable = FALSE;
        BOOLEAN ndisCapable = FALSE;
        BOOLEAN parsed = FALSE;

        PUCHAR base = (PUCHAR)(UINT_PTR)imageBase;
        if (imageBase != 0 && imageSize != 0 && imageSize <= 64 * 1024 * 1024
            && MmIsAddressValid(base)) {

            UINT32 e_lfanew = 0;
            if (MyArkWfpInvReadU32(base + 0x3C, &e_lfanew)
                && e_lfanew > 0 && e_lfanew < 0x400) {

                PUCHAR nt = base + e_lfanew;
                UINT32 peSignature = 0;
                if (MyArkWfpInvReadU32(nt, &peSignature) && peSignature == 0x00004550) {

                    USHORT magic = 0;
                    PUCHAR optHdr = nt + 24;
                    if (MyArkWfpInvReadU16(optHdr, &magic) && magic == 0x20B) {   // PE32+

                        UINT32 importDirRva = 0;
                        //
                        // DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] lives
                        // at optional-header offset 0x78 on PE32+ (0x70 is
                        // the EXPORT directory -- reading it instead makes
                        // the walk false-positive off export-name strings,
                        // caught in R3-15 acceptance review).
                        //
                        if (MyArkWfpInvReadU32(optHdr + 0x78, &importDirRva)) {
                            parsed = MyArkWfpInvCheckImports(base,
                                                             importDirRva,
                                                             (UINT32)imageSize,
                                                             &fwpCapable,
                                                             &ndisCapable);
                        }
                    }
                }
            }
        }

        if (row != NULL) {
            if (!parsed) {
                row->Flags |= MYARK_WFP_CDRIVER_FLAG_PARSE_FAILED;
            }
            if (fwpCapable) {
                row->Flags |= MYARK_WFP_CDRIVER_FLAG_WFP_CAPABLE;
            }
            if (ndisCapable) {
                row->Flags |= MYARK_WFP_CDRIVER_FLAG_NDIS_CAPABLE;
            }
            written++;
        }

        totalSeen++;
        node = node->Flink;
    }

    out->Count = written;
    out->TotalSeen = totalSeen;
    out->EntryStructSize = (UINT32)sizeof(MYARK_WFP_CALLOUT_DRIVER_ENTRY);
    *BytesReturned = headSize + (SIZE_T)written * sizeof(MYARK_WFP_CALLOUT_DRIVER_ENTRY);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_WFP
