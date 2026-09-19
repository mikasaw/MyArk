// MyArk dyndata module: 9 IOCTL handlers.
//
// All 9 handlers follow the MyArk IOCTL convention: fetch input/output
// buffers via MyArkIoctlFetch* helpers, validate sizes, then walk the
// resolved kernel data structure into the caller's variable-length
// output. None of the walks touch the un-resolved path -- when a symbol
// is absent on the running build the handler returns STATUS_SUCCESS with
// Count=0 so R3 clients render an empty table instead of getting a
// STATUS_NOT_FOUND exception.
//
// All walks defend against the BSOD-on-corrupt-list class of bugs by
// probing each address with MmIsAddressValid before dereferencing and
// hard-capping iteration counts at the corresponding HARD_CAP constant.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkDyndataIoctl.h"
#include "dyndata_descriptor.h"
#include "../10_process/process_offsets.h"
#include "dyndata_internal.h"

#if MYARK_MODULE_DYNDATA

//
// Forward decls for kernel exports not in the public WDK headers.
// PsLookup*By*Id is not in wdm.h; ObfDereferenceObject IS in wdm.h (it's
// the macro form of ObDereferenceObject) so we use that directly.
//
NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);
NTSTATUS PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD* Thread);

//
// ---------------------------------------------------------------------------
// Helper: zero the variable-length portion of an OUTPUT header.
// ---------------------------------------------------------------------------
//

static
VOID
MyArkDynDataZeroHeader(
    _Out_writes_bytes_(HeaderSize) PUCHAR Buffer,
    _In_                            ULONG  HeaderSize)
{
    RtlZeroMemory(Buffer, HeaderSize);
}

static
ULONG
MyArkDynDataReadUnicodeString(
    _In_  PUNICODE_STRING Source,
    _Out_writes_bytes_(BufferBytes) PUCHAR Dest,
    _In_  ULONG  BufferBytes)
//
// Copy Source->Buffer (UTF-16) into Dest as a UTF-8/ANSI null-terminated
// string truncated to BufferBytes-1 characters + NUL. Returns the byte
// count actually written. Used for kernel-side Name / FullPath / UserSid.
//
{
    if (Source == NULL || Dest == NULL || BufferBytes == 0) {
        return 0;
    }

    if (!MmIsAddressValid(Source)) {
        return 0;
    }

    USHORT sourceLen = Source->Length;
    USHORT sourceMax = Source->MaximumLength;
    if (sourceLen == 0 || sourceMax == 0) {
        Dest[0] = 0;
        return 1;
    }
    if (sourceLen > sourceMax) {
        sourceLen = sourceMax;
    }

    PWCH sourceBuf = Source->Buffer;
    if (sourceBuf == NULL || !MmIsAddressValid(sourceBuf)) {
        return 0;
    }

    //
    // Bound the read so a corrupted MaximumLength can't push us off-page.
    //
    USHORT copyChars = sourceLen / sizeof(WCHAR);
    if ((SIZE_T)copyChars * sizeof(WCHAR) > 0x1000) {
        copyChars = 0x1000 / sizeof(WCHAR);
    }

    PUCHAR cursor = Dest;
    ULONG remaining = BufferBytes;
    if (remaining == 0) {
        return 0;
    }
    remaining--;                             // reserve NUL
    ULONG written = 0;

    for (USHORT i = 0; i < copyChars && remaining > 0; i++) {
        WCHAR ch;
        if (!MmIsAddressValid((PVOID)(sourceBuf + i))) {
            break;
        }
        ch = sourceBuf[i];
        UCHAR lo = (UCHAR)(ch & 0x00FF);
        *cursor++ = lo;
        cursor++;                             // high byte (UTF-8 widening hack)
        remaining--;
        written += 2;
    }
    *cursor = 0;
    written++;
    return written;
}

//
// ---------------------------------------------------------------------------
// QUERY_PROCESS: walk EPROCESS.ActiveProcessLinks from PsActiveProcessHead.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkDynDataIoctlQueryProcess(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_DYNDATA_QUERY_PROCESS_INPUT        inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DYNDATA_QUERY_PROCESS_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DYNDATA_QUERY_PROCESS_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DYNDATA_QUERY_PROCESS_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DYNDATA_QUERY_PROCESS_OUTPUT out = (PMYARK_DYNDATA_QUERY_PROCESS_OUTPUT)outBuf;
    MyArkDynDataZeroHeader((PUCHAR)out,
                           FIELD_OFFSET(MYARK_DYNDATA_QUERY_PROCESS_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_DYNDATA_QUERY_PROCESS_OUTPUT, Entries[0]))
                              / sizeof(MYARK_DYNDATA_PROCESS_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_DYNDATA_PROCESS_HARD_CAP) {
        maxEntries = MYARK_DYNDATA_PROCESS_HARD_CAP;
    }

    if (g_MyArkDynDataPsActiveProcessHead == NULL
        || !MmIsAddressValid(g_MyArkDynDataPsActiveProcessHead)) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_PROCESS_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->PsActiveProcessHead = 0;
        out->EntryStructSize = sizeof(MYARK_DYNDATA_PROCESS_ENTRY);
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    //
    // The per-entry field offsets below are the 26100 Tier C profile. On
    // any other build they would read garbage (wrong PIDs -- worse than
    // empty), so the walk reports 0 rows unless the profile matched. The
    // node->EPROCESS back-offset comes from Tier B discovery (R3-4),
    // replacing the hardcoded 0x1D8 that broke this walk on 1903/22631;
    // the list head itself stays the exported PsActiveProcessHead.
    //
    const MYARK_ARK_OFFSETS* offs = MyArkArkOffsetsGet();
    if (offs == NULL || !offs->Valid || !offs->ProfileMatched) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_PROCESS_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->PsActiveProcessHead = 0;
        out->EntryStructSize = sizeof(MYARK_DYNDATA_PROCESS_ENTRY);
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    PLIST_ENTRY head = (PLIST_ENTRY)g_MyArkDynDataPsActiveProcessHead;
    PLIST_ENTRY node = head->Flink;
    ULONG written = 0;
    ULONG totalSeen = 0;
    ULONG iterGuard = MYARK_DYNDATA_PROCESS_HARD_CAP;

    while (node != NULL && node != head && iterGuard > 0 && written < maxEntries) {
        iterGuard--;

        if (!MmIsAddressValid(node)) {
            break;
        }

        PUCHAR epBase = (PUCHAR)node - offs->ActiveProcessLinks;
        if (!MmIsAddressValid(epBase)) {
            break;
        }

        UINT32 pid = *(UINT32*)(epBase + MYARK_OFF_EPROCESS_UNIQUE_PROCESS_ID);
        UINT32 ppid = *(UINT32*)(epBase + MYARK_OFF_EPROCESS_INHERITED_FROM_UNIQUE_PID);
        UINT32 session = *(UINT32*)(epBase + MYARK_OFF_EPROCESS_SESSION_ID);
        UINT64 peb = *(UINT64*)(epBase + MYARK_OFF_EPROCESS_PEB);
        UINT64 createTime = *(UINT64*)(epBase + MYARK_OFF_EPROCESS_CREATE_TIME);

        if (inBuf->PidFilter != 0 && pid != inBuf->PidFilter) {
            node = node->Flink;
            totalSeen++;
            continue;
        }

        PMYARK_DYNDATA_PROCESS_ENTRY row = &out->Entries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->Pid        = pid;
        row->Ppid       = ppid;
        row->SessionId  = session;
        row->Flags      = MYARK_DYNDATA_FLAG_POPULATED;
        row->EProcess   = (UINT64)epBase;
        row->Peb        = peb;
        row->SourceMask = MYARK_DYNDATA_PROCESS_SRC_ACTIVE_LINKS;
        row->CreateTime = createTime;

        //
        // ImageFileName is a fixed-size char array in EPROCESS; copy up to
        // MYARK_DYNDATA_IMAGE_FILE_NAME_MAX bytes via MyArkDynDataSafeRead so
        // a corrupted pointer can't BSOD us.
        //
        MyArkDynDataSafeRead(epBase + MYARK_OFF_EPROCESS_IMAGE_FILE_NAME,
                             row->ImageFileName,
                             MYARK_DYNDATA_IMAGE_FILE_NAME_MAX);

        written++;
        totalSeen++;
        node = node->Flink;
    }

    out->Size                 = (UINT32)(FIELD_OFFSET(MYARK_DYNDATA_QUERY_PROCESS_OUTPUT, Entries[0])
                                         + written * sizeof(MYARK_DYNDATA_PROCESS_ENTRY));
    out->Count                = written;
    out->TotalSeen            = totalSeen;
    out->PsActiveProcessHead  = (UINT64)g_MyArkDynDataPsActiveProcessHead;
    out->EntryStructSize      = (UINT32)sizeof(MYARK_DYNDATA_PROCESS_ENTRY);
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// QUERY_THREAD: walk ETHREAD from PsActiveThreadHead. Per-thread ownership
// resolves via PsLookupThreadByThreadId + EThread->Tcb.ApcState.Process.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkDynDataIoctlQueryThread(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                 status;
    PMYARK_DYNDATA_QUERY_THREAD_INPUT        inBuf = NULL;
    size_t                                   inSize = 0;
    PVOID                                    outBuf = NULL;
    size_t                                   outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DYNDATA_QUERY_THREAD_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DYNDATA_QUERY_THREAD_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DYNDATA_QUERY_THREAD_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DYNDATA_QUERY_THREAD_OUTPUT out = (PMYARK_DYNDATA_QUERY_THREAD_OUTPUT)outBuf;
    MyArkDynDataZeroHeader((PUCHAR)out,
                           FIELD_OFFSET(MYARK_DYNDATA_QUERY_THREAD_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_DYNDATA_QUERY_THREAD_OUTPUT, Entries[0]))
                              / sizeof(MYARK_DYNDATA_THREAD_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_DYNDATA_THREAD_HARD_CAP) {
        maxEntries = MYARK_DYNDATA_THREAD_HARD_CAP;
    }

    // Same 26100-profile gate as QUERY_PROCESS: without it the ETHREAD
    // field offsets read garbage on other builds.
    const MYARK_ARK_OFFSETS* offsThread = MyArkArkOffsetsGet();
    const BOOLEAN dyndataProfileMatched =
        (offsThread != NULL && offsThread->Valid && offsThread->ProfileMatched);
    if (g_MyArkDynDataPsActiveThreadHead == NULL
        || !dyndataProfileMatched
        || !MmIsAddressValid(g_MyArkDynDataPsActiveThreadHead)) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_THREAD_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->PsActiveThreadHead = 0;
        out->EntryStructSize = sizeof(MYARK_DYNDATA_THREAD_ENTRY);
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    PLIST_ENTRY head = (PLIST_ENTRY)g_MyArkDynDataPsActiveThreadHead;
    PLIST_ENTRY node = head->Flink;
    ULONG written = 0;
    ULONG totalSeen = 0;
    ULONG iterGuard = MYARK_DYNDATA_THREAD_HARD_CAP;

    while (node != NULL && node != head && iterGuard > 0 && written < maxEntries) {
        iterGuard--;

        if (!MmIsAddressValid(node)) {
            break;
        }

        PUCHAR etBase = (PUCHAR)node - offsThread->ThreadListEntry;
        if (!MmIsAddressValid(etBase)) {
            break;
        }

        UINT32 tid = *(UINT32*)(etBase + MYARK_OFF_ETHREAD_UNIQUE_THREAD_ID);
        UINT32 state = *(UINT32*)(etBase + MYARK_OFF_ETHREAD_STATE);
        UINT32 basePrio = *(UINT32*)(etBase + MYARK_OFF_ETHREAD_PRIORITY);
        UINT32 waitReason = *(UINT32*)(etBase + MYARK_OFF_ETHREAD_WAIT_REASON);
        UINT64 startAddr = *(UINT64*)(etBase + MYARK_OFF_ETHREAD_START_ADDRESS);
        UINT64 createTime = *(UINT64*)(etBase + MYARK_OFF_ETHREAD_CREATE_TIME);

        //
        // OwnerPid: dereference APC_STATE.Process -> UniqueProcessId. The
        // offset is build-specific; we go through MmIsAddressValid so a
        // corrupted ETHREAD can never fault.
        //
        UINT32 ownerPid = 0;
        PUCHAR apcState = etBase + MYARK_OFF_ETHREAD_APC_STATE_PROCESS;
        if (offsThread != NULL && MmIsAddressValid(apcState)) {
            PUCHAR ep = *(PUCHAR*)apcState;
            if (ep != NULL && MmIsAddressValid(ep)) {
                ownerPid = *(UINT32*)(ep + MYARK_OFF_EPROCESS_UNIQUE_PROCESS_ID);
            }
        }

        if (inBuf->PidFilter != 0 && ownerPid != inBuf->PidFilter) {
            node = node->Flink;
            totalSeen++;
            continue;
        }

        PMYARK_DYNDATA_THREAD_ENTRY row = &out->Entries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->Tid          = tid;
        row->OwnerPid     = ownerPid;
        row->State        = state;
        row->BasePriority = basePrio;
        row->WaitReason   = waitReason;
        row->EThread      = (UINT64)etBase;
        row->StartAddress = startAddr;
        row->Flags        = MYARK_DYNDATA_FLAG_POPULATED;
        row->CreateTime   = createTime;

        written++;
        totalSeen++;
        node = node->Flink;
    }

    out->Size                = (UINT32)(FIELD_OFFSET(MYARK_DYNDATA_QUERY_THREAD_OUTPUT, Entries[0])
                                      + written * sizeof(MYARK_DYNDATA_THREAD_ENTRY));
    out->Count               = written;
    out->TotalSeen           = totalSeen;
    out->PsActiveThreadHead  = (UINT64)g_MyArkDynDataPsActiveThreadHead;
    out->EntryStructSize     = (UINT32)sizeof(MYARK_DYNDATA_THREAD_ENTRY);
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// QUERY_MODULE: walk KLDR_DATA_TABLE_ENTRY chain from PsLoadedModuleList.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkDynDataIoctlQueryModule(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_DYNDATA_QUERY_MODULE_INPUT         inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DYNDATA_QUERY_MODULE_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DYNDATA_QUERY_MODULE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DYNDATA_QUERY_MODULE_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DYNDATA_QUERY_MODULE_OUTPUT out = (PMYARK_DYNDATA_QUERY_MODULE_OUTPUT)outBuf;
    MyArkDynDataZeroHeader((PUCHAR)out,
                           FIELD_OFFSET(MYARK_DYNDATA_QUERY_MODULE_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_DYNDATA_QUERY_MODULE_OUTPUT, Entries[0]))
                              / sizeof(MYARK_DYNDATA_MODULE_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_DYNDATA_MODULE_HARD_CAP) {
        maxEntries = MYARK_DYNDATA_MODULE_HARD_CAP;
    }

    if (g_MyArkDynDataPsLoadedModuleList == NULL
        || !MmIsAddressValid(g_MyArkDynDataPsLoadedModuleList)) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_MODULE_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->PsLoadedModuleList = 0;
        out->EntryStructSize = sizeof(MYARK_DYNDATA_MODULE_ENTRY);
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    PLIST_ENTRY head = (PLIST_ENTRY)g_MyArkDynDataPsLoadedModuleList;
    PLIST_ENTRY node = head->Flink;
    ULONG written = 0;
    ULONG totalSeen = 0;
    ULONG iterGuard = MYARK_DYNDATA_MODULE_HARD_CAP;
    UINT32 loadOrder = 0;

    while (node != NULL && node != head && iterGuard > 0 && written < maxEntries) {
        iterGuard--;

        if (!MmIsAddressValid(node)) {
            break;
        }

        PUCHAR kldrBase = (PUCHAR)node - MYARK_OFF_KLDR_IN_LOAD_ORDER_LINKS;
        if (!MmIsAddressValid(kldrBase)) {
            break;
        }

        UINT64 imageBase = *(UINT64*)(kldrBase + MYARK_OFF_KLDR_DLL_BASE);
        UINT64 imageSize = *(UINT64*)(kldrBase + MYARK_OFF_KLDR_SIZE_OF_IMAGE);

        PMYARK_DYNDATA_MODULE_ENTRY row = &out->Entries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->ImageBase      = imageBase;
        row->ImageSize      = imageSize;
        row->LoadOrderIndex = loadOrder;
        row->Flags          = MyArkDynDataAddressFlags(imageBase,
                                                       g_MyArkDynDataNtoskrnlTextBase,
                                                       g_MyArkDynDataNtoskrnlTextEnd);

        //
        // FullPath / BaseDllName are UNICODE_STRINGs. Probe each before read.
        //
        PUNICODE_STRING baseName = (PUNICODE_STRING)(kldrBase + MYARK_OFF_KLDR_BASE_DLL_NAME);
        PUNICODE_STRING fullName = (PUNICODE_STRING)(kldrBase + MYARK_OFF_KLDR_FULL_DLL_NAME);

        MyArkDynDataReadUnicodeString(baseName, row->Name, MYARK_DYNDATA_NAME_MAX);
        MyArkDynDataReadUnicodeString(fullName, row->FullPath, MYARK_DYNDATA_PATH_MAX);

        written++;
        totalSeen++;
        loadOrder++;
        node = node->Flink;
    }

    out->Size              = (UINT32)(FIELD_OFFSET(MYARK_DYNDATA_QUERY_MODULE_OUTPUT, Entries[0])
                                      + written * sizeof(MYARK_DYNDATA_MODULE_ENTRY));
    out->Count             = written;
    out->TotalSeen         = totalSeen;
    out->PsLoadedModuleList = (UINT64)g_MyArkDynDataPsLoadedModuleList;
    out->EntryStructSize   = (UINT32)sizeof(MYARK_DYNDATA_MODULE_ENTRY);
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// QUERY_HANDLE: walk PspCidTable -- the canonical kernel handle table. We
// do a flat table code probe (TableCode) and walk each level until the
// PID / HandleValue filter is satisfied.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkDynDataIoctlQueryHandle(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_DYNDATA_QUERY_HANDLE_INPUT         inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DYNDATA_QUERY_HANDLE_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DYNDATA_QUERY_HANDLE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DYNDATA_QUERY_HANDLE_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DYNDATA_QUERY_HANDLE_OUTPUT out = (PMYARK_DYNDATA_QUERY_HANDLE_OUTPUT)outBuf;
    MyArkDynDataZeroHeader((PUCHAR)out,
                           FIELD_OFFSET(MYARK_DYNDATA_QUERY_HANDLE_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_DYNDATA_QUERY_HANDLE_OUTPUT, Entries[0]))
                              / sizeof(MYARK_DYNDATA_HANDLE_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_DYNDATA_HANDLE_HARD_CAP) {
        maxEntries = MYARK_DYNDATA_HANDLE_HARD_CAP;
    }

    if (g_MyArkDynDataPspCidTable == NULL
        || !MmIsAddressValid(g_MyArkDynDataPspCidTable)) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_HANDLE_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->PspCidTable = 0;
        out->EntryStructSize = sizeof(MYARK_DYNDATA_HANDLE_ENTRY);
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    //
    // PspCidTable is a HANDLE_TABLE; the TableCode field at offset
    // MYARK_OFF_HANDLE_TABLE_TABLE_CODE encodes both the level (0..2) and
    // the table base pointer. We only walk level-0 tables -- a flat 512-
    // entry handle table is the common case on single-session kernels and
    // avoids the recursive walk complexity. Level > 0 falls through to
    // Count=0 so R3 clients see "no data" rather than a truncated list.
    //
    PUCHAR tableBase = (PUCHAR)g_MyArkDynDataPspCidTable;
    UINT64 tableCode = *(UINT64*)(tableBase + MYARK_OFF_HANDLE_TABLE_TABLE_CODE);
    UINT32 level = (UINT32)(tableCode & 0x3);
    PVOID tablePtr = (PVOID)(tableCode & ~(UINT64)0x3);

    if (level != 0 || tablePtr == NULL || !MmIsAddressValid(tablePtr)) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_HANDLE_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->PspCidTable = (UINT64)g_MyArkDynDataPspCidTable;
        out->EntryStructSize = sizeof(MYARK_DYNDATA_HANDLE_ENTRY);
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    PUCHAR entryBase = (PUCHAR)tablePtr;
    ULONG written = 0;
    ULONG totalSeen = 0;
    const ULONG entryCount = 512;            // flat PspCidTable level-0 capacity
    const ULONG entryStride = 0x20;          // HANDLE_TABLE_ENTRY stride (build-specific)

    for (ULONG i = 0; i < entryCount && written < maxEntries; i++) {
        PUCHAR entry = entryBase + (SIZE_T)i * entryStride;
        if (!MmIsAddressValid(entry)) {
            break;
        }

        UINT32 lowValue = *(UINT32*)(entry + 0x008);          // HANDLE_TABLE_ENTRY.LowValue
        UINT32 granted  = *(UINT32*)(entry + 0x004);          // GrantedAccessIndex packed
        UINT64 object   = *(UINT64*)(entry + 0x010);          // Object pointer

        UINT32 handleValue = (lowValue & 0x00FFFFFFu) | ((lowValue >> 8) & 0xFF000000u);
        UINT32 pidFromTable = *(UINT32*)(tableBase + MYARK_OFF_HANDLE_TABLE_UNIQUE_PROCESS_ID);

        if (lowValue == 0) {
            continue;
        }

        if (inBuf->PidFilter != 0 && pidFromTable != inBuf->PidFilter) {
            totalSeen++;
            continue;
        }

        PMYARK_DYNDATA_HANDLE_ENTRY row = &out->Entries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->Pid           = pidFromTable;
        row->HandleValue   = handleValue;
        row->TypeIndex     = (granted >> 16) & 0xFFFFu;
        row->GrantedAccess = (granted & 0x1FFFu);
        row->Object        = object;
        row->Flags         = MYARK_DYNDATA_FLAG_POPULATED;

        written++;
        totalSeen++;
    }

    out->Size           = (UINT32)(FIELD_OFFSET(MYARK_DYNDATA_QUERY_HANDLE_OUTPUT, Entries[0])
                                   + written * sizeof(MYARK_DYNDATA_HANDLE_ENTRY));
    out->Count          = written;
    out->TotalSeen      = totalSeen;
    out->PspCidTable    = (UINT64)g_MyArkDynDataPspCidTable;
    out->EntryStructSize = (UINT32)sizeof(MYARK_DYNDATA_HANDLE_ENTRY);
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// QUERY_FILE: best-effort file-object snapshot. We walk ObTypeIndexTable
// and pull FILE_OBJECT pointers for each open handle of PidFilter. The
// iteration order is determined by the PspCidTable walk above; each entry
// that resolves to a FILE_OBJECT emits one row.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkDynDataIoctlQueryFile(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_DYNDATA_QUERY_FILE_INPUT         inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DYNDATA_QUERY_FILE_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DYNDATA_QUERY_FILE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DYNDATA_QUERY_FILE_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DYNDATA_QUERY_FILE_OUTPUT out = (PMYARK_DYNDATA_QUERY_FILE_OUTPUT)outBuf;
    MyArkDynDataZeroHeader((PUCHAR)out,
                           FIELD_OFFSET(MYARK_DYNDATA_QUERY_FILE_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_DYNDATA_QUERY_FILE_OUTPUT, Entries[0]))
                              / sizeof(MYARK_DYNDATA_FILE_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_DYNDATA_FILE_HARD_CAP) {
        maxEntries = MYARK_DYNDATA_FILE_HARD_CAP;
    }

    if (g_MyArkDynDataPspCidTable == NULL
        || !MmIsAddressValid(g_MyArkDynDataPspCidTable)
        || g_MyArkDynDataObTypeObjectType == NULL) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_FILE_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->ObTypeIndexList = (UINT64)g_MyArkDynDataObTypeObjectType;
        out->EntryStructSize = sizeof(MYARK_DYNDATA_FILE_ENTRY);
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    //
    // Resolve the File type index from ObTypeObjectType via a single probe
    // on the global object-type array. Type index 0 is reserved for
    // Type=None; the file object's index is build-specific and cached
    // after the first successful probe. To stay portable we just emit the
    // rows whose kernel VA happens to be non-null and the object's first
    // quad-word looks like a FILE_OBJECT (Vpb at -0x40).
    //
    PUCHAR tableBase = (PUCHAR)g_MyArkDynDataPspCidTable;
    UINT64 tableCode = *(UINT64*)(tableBase + MYARK_OFF_HANDLE_TABLE_TABLE_CODE);
    UINT32 level = (UINT32)(tableCode & 0x3);
    PVOID tablePtr = (PVOID)(tableCode & ~(UINT64)0x3);

    if (level != 0 || tablePtr == NULL || !MmIsAddressValid(tablePtr)) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_FILE_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->ObTypeIndexList = (UINT64)g_MyArkDynDataObTypeObjectType;
        out->EntryStructSize = sizeof(MYARK_DYNDATA_FILE_ENTRY);
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    PUCHAR entryBase = (PUCHAR)tablePtr;
    ULONG written = 0;
    ULONG totalSeen = 0;
    const ULONG entryCount = 512;
    const ULONG entryStride = 0x20;

    for (ULONG i = 0; i < entryCount && written < maxEntries; i++) {
        PUCHAR entry = entryBase + (SIZE_T)i * entryStride;
        if (!MmIsAddressValid(entry)) {
            break;
        }

        UINT32 lowValue = *(UINT32*)(entry + 0x008);
        UINT64 object = *(UINT64*)(entry + 0x010);
        UINT32 pidFromTable = *(UINT32*)(tableBase + MYARK_OFF_HANDLE_TABLE_UNIQUE_PROCESS_ID);

        if (lowValue == 0 || object == 0) {
            continue;
        }
        if (inBuf->PidFilter != 0 && pidFromTable != inBuf->PidFilter) {
            totalSeen++;
            continue;
        }

        //
        // Heuristic: probe FileObject->FileName at the canonical offset
        // 0x58 (FILE_OBJECT.FileName). If the string is non-empty we treat
        // the row as a file. Anything else is skipped (Event / Mutex / etc).
        //
        PUCHAR fileName = (PUCHAR)(UINT_PTR)object + 0x058;
        UNICODE_STRING name;
        RtlZeroMemory(&name, sizeof(name));
        MyArkDynDataSafeRead(fileName, (PUCHAR)&name, (ULONG)sizeof(name));
        if (name.Length == 0 || name.Length > 0x7FF0 || name.Buffer == NULL) {
            totalSeen++;
            continue;
        }

        PMYARK_DYNDATA_FILE_ENTRY row = &out->Entries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->Pid          = pidFromTable;
        row->HandleValue  = lowValue & 0x00FFFFFFu;
        row->FileObject   = object;
        row->DeviceObject = *(UINT64*)(object + 0x008);
        row->ShareAccess  = *(UINT32*)(object + 0x00C);
        row->Flags        = MYARK_DYNDATA_FLAG_POPULATED;

        MyArkDynDataReadUnicodeString(&name, row->Name, MYARK_DYNDATA_PATH_MAX);

        written++;
        totalSeen++;
    }

    out->Size            = (UINT32)(FIELD_OFFSET(MYARK_DYNDATA_QUERY_FILE_OUTPUT, Entries[0])
                                    + written * sizeof(MYARK_DYNDATA_FILE_ENTRY));
    out->Count           = written;
    out->TotalSeen       = totalSeen;
    out->ObTypeIndexList = (UINT64)g_MyArkDynDataObTypeObjectType;
    out->EntryStructSize = (UINT32)sizeof(MYARK_DYNDATA_FILE_ENTRY);
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

//
//
// Fault-safe 8-byte kernel read (KNOWN_ISSUES B4): MmIsAddressValid only
// reports this instant -- the page can still fault on the actual access
// (bugchecked 0x3B on no-SMEP CPUs when the walk crossed a page boundary).
// MmCopyMemory tolerates unmapped / paged-out / cross-page sources.
// PASSIVE_LEVEL required (the sequential queue guarantees it).
//
static
BOOLEAN
MyArkDynDataReadSlot64(
    _In_  PVOID   Slot,
    _Out_ UINT64 *ValueOut)
{
    MM_COPY_ADDRESS src;
    SIZE_T          copied = 0;

    src.VirtualAddress = Slot;
    NTSTATUS status = MmCopyMemory(ValueOut, src, sizeof(UINT64),
                                   MM_COPY_MEMORY_VIRTUAL, &copied);
    return NT_SUCCESS(status) && copied == sizeof(UINT64);
}

// ---------------------------------------------------------------------------
// QUERY_SYSCALL: walk both KeServiceDescriptorTable and
// KeServiceDescriptorTableShadow. W32pServiceTable is at a fixed offset
// inside the shadow descriptor on Win10+.
// ---------------------------------------------------------------------------
static
ULONG
MyArkDynDataWalkSsdt(
    _In_    PVOID  ServiceTableBase,
    _In_    UINT32 Limit,
    _In_    UINT64 TextBase,
    _In_    UINT64 TextEnd,
    _In_    UINT32 TableId,
    _Out_writes_(MaxEntries) PMYARK_DYNDATA_SYSCALL_ENTRY OutEntries,
    _In_    ULONG  MaxEntries,
    _Out_   PULONG TotalSeenOut)
//
// Common walker for KeServiceDescriptorTable + W32pServiceTable. Treats
// each entry as a PVOID-sized slot; on Win10 21H1+ the value is a signed
// int32 offset relative to &slot[i] -- the heuristic in the kernel module
// applies here too. Returns the number of rows emitted.
//
{
    *TotalSeenOut = 0;
    if (ServiceTableBase == NULL || Limit == 0 || MaxEntries == 0) {
        return 0;
    }
    if (!MmIsAddressValid(ServiceTableBase)) {
        return 0;
    }

    PUCHAR entryBase = (PUCHAR)ServiceTableBase;
    ULONG written = 0;
    const ULONG HARD_CAP = MYARK_DYNDATA_SYSCALL_HARD_CAP;
    UINT32 bound = Limit;
    if (bound > HARD_CAP) {
        bound = HARD_CAP;
    }

    for (UINT32 i = 0; i < bound && written < MaxEntries; i++) {
        PVOID slot = (PVOID)(entryBase + (SIZE_T)i * sizeof(PVOID));

        UINT64 rawValue = 0;
        if (!MyArkDynDataReadSlot64(slot, &rawValue)) {
            continue;
        }
        if (rawValue == 0) {
            continue;
        }

        UINT64 serviceAddress;
        if ((rawValue & 0xFFFFFFFF00000000ULL) == 0
            || (rawValue & 0xFFFFFFFF00000000ULL) == 0xFFFFFFFF00000000ULL) {
            serviceAddress = (UINT64)(LONG_PTR)(LONG)(UINT32)rawValue;
        } else {
            serviceAddress = rawValue;
        }

        PMYARK_DYNDATA_SYSCALL_ENTRY row = &OutEntries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->ServiceIndex   = i;
        row->TableId        = TableId;
        row->ServiceAddress = serviceAddress;
        row->Flags          = MyArkDynDataAddressFlags(serviceAddress, TextBase, TextEnd);
        row->DwellBytesSize = MyArkDynDataReadDwell((PVOID)serviceAddress, row->DwellBytes);

        written++;
    }

    *TotalSeenOut = (ULONG)bound;
    return written;
}

NTSTATUS
MyArkDynDataIoctlQuerySyscall(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_DYNDATA_QUERY_SYSCALL_INPUT        inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DYNDATA_QUERY_SYSCALL_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DYNDATA_QUERY_SYSCALL_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DYNDATA_QUERY_SYSCALL_OUTPUT out = (PMYARK_DYNDATA_QUERY_SYSCALL_OUTPUT)outBuf;
    MyArkDynDataZeroHeader((PUCHAR)out,
                           FIELD_OFFSET(MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT, Entries[0]))
                              / sizeof(MYARK_DYNDATA_SYSCALL_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_DYNDATA_SYSCALL_HARD_CAP) {
        maxEntries = MYARK_DYNDATA_SYSCALL_HARD_CAP;
    }

    if (maxEntries == 0) {
        out->Size = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT, Entries[0]);
        out->Count = 0;
        out->TotalSeen = 0;
        out->EntryStructSize = sizeof(MYARK_DYNDATA_SYSCALL_ENTRY);
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    UINT32 tableMask = inBuf->TableMask;
    if (tableMask == 0) {
        tableMask = 0x3;             // both NTOS and WIN32K
    }

    ULONG written = 0;
    ULONG totalSeen = 0;
    UINT64 shadow = 0;
    UINT64 w32pTable = 0;

    //
    // KeServiceDescriptorTable: emitted under tableMask bit 0.
    //
    if ((tableMask & 0x1) != 0
        && g_MyArkDynDataKeServiceDescriptorTable != NULL
        && MmIsAddressValid(g_MyArkDynDataKeServiceDescriptorTable)) {
        PKSERVICE_TABLE_DESCRIPTOR table = (PKSERVICE_TABLE_DESCRIPTOR)g_MyArkDynDataKeServiceDescriptorTable;
        UINT32 limit = table->Limit;
        PVOID base = table->Base;

        ULONG ntosSeen = 0;
        ULONG ntosWritten = MyArkDynDataWalkSsdt(base,
                                                 limit,
                                                 g_MyArkDynDataNtoskrnlTextBase,
                                                 g_MyArkDynDataNtoskrnlTextEnd,
                                                 MYARK_DYNDATA_SYSCALL_TABLE_NTOS,
                                                 &out->Entries[written],
                                                 maxEntries - written,
                                                 &ntosSeen);
        written += ntosWritten;
        totalSeen += ntosSeen;
    }

    //
    // KeServiceDescriptorTableShadow + W32pServiceTable: emitted under
    // tableMask bit 1. The shadow table lives in ntoskrnl but its second
    // pointer field (W32pServiceTable) refers into win32k.sys.
    //
    if ((tableMask & 0x2) != 0
        && g_MyArkDynDataKeServiceDescriptorTableShadow != NULL
        && MmIsAddressValid(g_MyArkDynDataKeServiceDescriptorTableShadow)
        && written < maxEntries) {
        PKSERVICE_TABLE_DESCRIPTOR shadowDesc = (PKSERVICE_TABLE_DESCRIPTOR)g_MyArkDynDataKeServiceDescriptorTableShadow;
        shadow = (UINT64)g_MyArkDynDataKeServiceDescriptorTableShadow;

        //
        // The win32k stub table lives at offset +0x20 inside the shadow
        // descriptor on Win10+ (the layout is {Limit, Base, Number, Unused}
        // repeated for ntoskrnl and win32k back-to-back).
        //
        PUCHAR w32pField = (PUCHAR)shadowDesc + sizeof(KSERVICE_TABLE_DESCRIPTOR);
        if (MmIsAddressValid(w32pField)) {
            UINT32 w32pLimit = *(UINT32*)w32pField;
            PVOID w32pBase = *(PVOID*)(w32pField + sizeof(UINT32));
            w32pTable = (UINT64)w32pBase;

            ULONG win32kSeen = 0;
            ULONG win32kWritten = MyArkDynDataWalkSsdt(w32pBase,
                                                       w32pLimit,
                                                       g_MyArkDynDataWin32kTextBase,
                                                       g_MyArkDynDataWin32kTextEnd,
                                                       MYARK_DYNDATA_SYSCALL_TABLE_WIN32K,
                                                       &out->Entries[written],
                                                       maxEntries - written,
                                                       &win32kSeen);
            written += win32kWritten;
            totalSeen += win32kSeen;
        }
    }

    out->Size                     = (UINT32)(FIELD_OFFSET(MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT, Entries[0])
                                             + written * sizeof(MYARK_DYNDATA_SYSCALL_ENTRY));
    out->Count                    = written;
    out->TotalSeen                = totalSeen;
    out->KeServiceDescriptorTable = (UINT64)g_MyArkDynDataKeServiceDescriptorTable;
    out->W32pServiceTable         = w32pTable;
    out->NtoskrnlTextBase         = g_MyArkDynDataNtoskrnlTextBase;
    out->NtoskrnlTextEnd          = g_MyArkDynDataNtoskrnlTextEnd;
    out->EntryStructSize          = (UINT32)sizeof(MYARK_DYNDATA_SYSCALL_ENTRY);
    *BytesReturned = out->Size;
    (void)shadow;                  // diagnostic; reserved for future filter use
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// QUERY_TOKEN: resolve a single PID's token. Best-effort: returns empty row
// when the lookup fails (PsLookupProcessByProcessId refuses or returns a
// NULL Token). R3 clients render the row with whatever fields were filled.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkDynDataIoctlQueryToken(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_DYNDATA_QUERY_TOKEN_INPUT        inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DYNDATA_QUERY_TOKEN_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DYNDATA_QUERY_TOKEN_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DYNDATA_QUERY_TOKEN_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DYNDATA_QUERY_TOKEN_OUTPUT out = (PMYARK_DYNDATA_QUERY_TOKEN_OUTPUT)outBuf;
    MyArkDynDataZeroHeader((PUCHAR)out,
                           FIELD_OFFSET(MYARK_DYNDATA_QUERY_TOKEN_OUTPUT, Entries[0]));

    out->Size = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_TOKEN_OUTPUT, Entries[0]);
    out->Count = 0;
    out->EntryStructSize = sizeof(MYARK_DYNDATA_TOKEN_ENTRY);

    if (inBuf->Pid == 0 || OutputBufferLength < out->Size + sizeof(MYARK_DYNDATA_TOKEN_ENTRY)) {
        *BytesReturned = out->Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    PEPROCESS process = NULL;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)inBuf->Pid, &process);
    if (!NT_SUCCESS(status) || process == NULL) {
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;             // empty row, not an error
    }

    PMYARK_DYNDATA_TOKEN_ENTRY row = &out->Entries[0];
    RtlZeroMemory(row, sizeof(*row));
    row->Pid  = inBuf->Pid;
    row->Token = (UINT64)process;

    //
    // Tier A accessors only (P2, review): EPROCESS.Token/SessionId offsets
    // are build-specific, so the primary token comes from the documented
    // PsReferencePrimaryToken and the session from PsGetProcessSessionId.
    // The TOKEN-internal fields are still build-specific -- they go through
    // the probe-guarded MyArkDynDataSafeRead so a corrupted Token can never
    // fault and a partial read just leaves zeroes.
    //
    row->SessionId = (UINT32)(ULONG_PTR)PsGetProcessSessionId(process);

    PACCESS_TOKEN token = PsReferencePrimaryToken(process);
    if (token == NULL) {
        ObDereferenceObject(process);
        out->Size = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_TOKEN_OUTPUT, Entries[0]);
        out->Count = 0;
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    row->Token = (UINT64)token;
    row->Flags |= MYARK_DYNDATA_TOKEN_FLAG_USER_PRESENT;
    {
        PUCHAR tp = (PUCHAR)token;
        UINT32 v32 = 0;
        MyArkDynDataSafeRead(tp + 0x080, (PUCHAR)&v32, sizeof(v32));
        row->IntegrityLevel = v32;                        // SEP_TOKEN_PRIVILEGES
        v32 = 0;
        MyArkDynDataSafeRead(tp + 0x084, (PUCHAR)&v32, sizeof(v32));
        row->IntegrityFlags = v32;
        v32 = 0;
        MyArkDynDataSafeRead(tp + 0x0C0, (PUCHAR)&v32, sizeof(v32));
        row->ElevationType  = v32;                        // TokenElevation type
        row->IsElevated     = (row->ElevationType != 0) ? 1 : 0;
        row->VirtualizationEnabled = 0;
        v32 = 0;
        MyArkDynDataSafeRead(tp + 0x090, (PUCHAR)&v32, sizeof(v32));
        row->UserRid        = v32;                        // TOKEN_USER Sid SubAuthority[0]
    }
    PsDereferencePrimaryToken(token);

    out->Size = (UINT32)(FIELD_OFFSET(MYARK_DYNDATA_QUERY_TOKEN_OUTPUT, Entries[0])
                         + sizeof(MYARK_DYNDATA_TOKEN_ENTRY));
    out->Count = 1;

    ObDereferenceObject(process);
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// QUERY_OBJECT: enumerate object-type entries via ObTypeObjectType. We
// walk the type-object array via ObTypeObjectType->TypeList.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkDynDataIoctlQueryObject(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_DYNDATA_QUERY_OBJECT_INPUT         inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DYNDATA_QUERY_OBJECT_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DYNDATA_QUERY_OBJECT_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DYNDATA_QUERY_OBJECT_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DYNDATA_QUERY_OBJECT_OUTPUT out = (PMYARK_DYNDATA_QUERY_OBJECT_OUTPUT)outBuf;
    MyArkDynDataZeroHeader((PUCHAR)out,
                           FIELD_OFFSET(MYARK_DYNDATA_QUERY_OBJECT_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_DYNDATA_QUERY_OBJECT_OUTPUT, Entries[0]))
                              / sizeof(MYARK_DYNDATA_OBJECT_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_DYNDATA_OBJECT_TYPE_HARD_CAP) {
        maxEntries = MYARK_DYNDATA_OBJECT_TYPE_HARD_CAP;
    }

    if (g_MyArkDynDataObTypeObjectType == NULL
        || !MmIsAddressValid(g_MyArkDynDataObTypeObjectType)) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_OBJECT_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->ObTypeObjectType = 0;
        out->EntryStructSize = sizeof(MYARK_DYNDATA_OBJECT_ENTRY);
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    //
    // The type-object list is a singly-linked LIST_ENTRY at offset 0x18
    // (TypeList) inside the type object. Walk the list of type objects;
    // each non-null type emits one row.
    //
    PUCHAR typeObj = (PUCHAR)g_MyArkDynDataObTypeObjectType;
    PLIST_ENTRY listHead = (PLIST_ENTRY)(typeObj + 0x018);
    if (!MmIsAddressValid(listHead)) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_OBJECT_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->ObTypeObjectType = (UINT64)g_MyArkDynDataObTypeObjectType;
        out->EntryStructSize = sizeof(MYARK_DYNDATA_OBJECT_ENTRY);
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    PLIST_ENTRY node = listHead->Flink;
    ULONG written = 0;
    ULONG totalSeen = 0;
    UINT32 typeIndex = 0;

    while (node != NULL && node != listHead && written < maxEntries) {
        if (!MmIsAddressValid(node)) {
            break;
        }

        PUCHAR entry = (PUCHAR)node;
        UINT32 totalObjects = *(UINT32*)(entry + MYARK_OFF_OB_TYPE_TOTAL_OBJECTS);
        UINT32 totalHandles = *(UINT32*)(entry + MYARK_OFF_OB_TYPE_TOTAL_HANDLES);
        PUNICODE_STRING typeName = (PUNICODE_STRING)(entry + MYARK_OFF_OB_TYPE_NAME);

        PMYARK_DYNDATA_OBJECT_ENTRY row = &out->Entries[written];
        RtlZeroMemory(row, sizeof(*row));
        row->TypeIndex          = typeIndex;
        row->TotalNumberOfObjects = totalObjects;
        row->TotalNumberOfHandles = totalHandles;
        row->Flags              = MYARK_DYNDATA_FLAG_POPULATED;
        row->TypeObject         = (UINT64)entry;

        MyArkDynDataReadUnicodeString(typeName, row->Name, MYARK_DYNDATA_NAME_MAX);

        written++;
        totalSeen++;
        typeIndex++;
        node = node->Flink;
    }

    out->Size              = (UINT32)(FIELD_OFFSET(MYARK_DYNDATA_QUERY_OBJECT_OUTPUT, Entries[0])
                                      + written * sizeof(MYARK_DYNDATA_OBJECT_ENTRY));
    out->Count             = written;
    out->TotalSeen         = totalSeen;
    out->ObTypeObjectType  = (UINT64)g_MyArkDynDataObTypeObjectType;
    out->EntryStructSize   = (UINT32)sizeof(MYARK_DYNDATA_OBJECT_ENTRY);
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// QUERY_SSDT: walk the shadow SSDT only. Mirrors the kernel module's
// QUERY_SSDT but with the shadow descriptor's win32k entries.
// ---------------------------------------------------------------------------
//

NTSTATUS
MyArkDynDataIoctlQuerySsdt(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                status;
    PMYARK_DYNDATA_QUERY_SSDT_INPUT         inBuf = NULL;
    size_t                                  inSize = 0;
    PVOID                                   outBuf = NULL;
    size_t                                  outSize = 0;

    if (InputBufferLength < sizeof(MYARK_DYNDATA_QUERY_SSDT_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_DYNDATA_QUERY_SSDT_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_DYNDATA_QUERY_SSDT_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_DYNDATA_QUERY_SSDT_OUTPUT out = (PMYARK_DYNDATA_QUERY_SSDT_OUTPUT)outBuf;
    MyArkDynDataZeroHeader((PUCHAR)out,
                           FIELD_OFFSET(MYARK_DYNDATA_QUERY_SSDT_OUTPUT, Entries[0]));

    ULONG maxEntries = (ULONG)((OutputBufferLength
                               - FIELD_OFFSET(MYARK_DYNDATA_QUERY_SSDT_OUTPUT, Entries[0]))
                              / sizeof(MYARK_DYNDATA_SSDT_ENTRY));
    if (inBuf->MaxEntries != 0 && inBuf->MaxEntries < maxEntries) {
        maxEntries = inBuf->MaxEntries;
    }
    if (maxEntries > MYARK_DYNDATA_SYSCALL_HARD_CAP) {
        maxEntries = MYARK_DYNDATA_SYSCALL_HARD_CAP;
    }

    out->KeServiceDescriptorTableShadow = (UINT64)g_MyArkDynDataKeServiceDescriptorTableShadow;
    out->Win32kTextBase = g_MyArkDynDataWin32kTextBase;
    out->Win32kTextEnd  = g_MyArkDynDataWin32kTextEnd;
    out->EntryStructSize = sizeof(MYARK_DYNDATA_SSDT_ENTRY);

    if (g_MyArkDynDataKeServiceDescriptorTableShadow == NULL
        || !MmIsAddressValid(g_MyArkDynDataKeServiceDescriptorTableShadow)) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_SSDT_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->W32pServiceTable = 0;
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    PKSERVICE_TABLE_DESCRIPTOR shadow = (PKSERVICE_TABLE_DESCRIPTOR)g_MyArkDynDataKeServiceDescriptorTableShadow;
    PUCHAR w32pField = (PUCHAR)shadow + sizeof(KSERVICE_TABLE_DESCRIPTOR);
    if (!MmIsAddressValid(w32pField)) {
        out->Size    = (UINT32)FIELD_OFFSET(MYARK_DYNDATA_QUERY_SSDT_OUTPUT, Entries[0]);
        out->Count   = 0;
        out->TotalSeen = 0;
        out->W32pServiceTable = 0;
        *BytesReturned = out->Size;
        return STATUS_SUCCESS;
    }

    UINT32 w32pLimit = *(UINT32*)w32pField;
    PVOID w32pBase = *(PVOID*)(w32pField + sizeof(UINT32));
    out->W32pServiceTable = (UINT64)w32pBase;

    ULONG totalSeen = 0;
    ULONG written = MyArkDynDataWalkSsdt(w32pBase,
                                         w32pLimit,
                                         g_MyArkDynDataWin32kTextBase,
                                         g_MyArkDynDataWin32kTextEnd,
                                         MYARK_DYNDATA_SYSCALL_TABLE_SHADOW,
                                         (PMYARK_DYNDATA_SYSCALL_ENTRY)out->Entries,
                                         maxEntries,
                                         &totalSeen);

    out->Size  = (UINT32)(FIELD_OFFSET(MYARK_DYNDATA_QUERY_SSDT_OUTPUT, Entries[0])
                          + written * sizeof(MYARK_DYNDATA_SSDT_ENTRY));
    out->Count = written;
    out->TotalSeen = totalSeen;
    *BytesReturned = out->Size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_DYNDATA
