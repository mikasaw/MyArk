// MyArk file-monitor module: minifilter core (R2-7).
//
// FLTMGR normally loads minifilters itself at boot from the service's
// Instances key. MyArkCore is a plain kernel service instead, so this module
// (a) makes sure the Instances key exists (idempotent ZwCreateKey from
// DriverEntry context) and (b) registers the filter itself via
// FltRegisterFilter. Post-op callbacks sample completed CREATE /
// disposition operations into a fixed non-paged ring; consumers drain via
// IOCTL and never influence file-operation latency beyond the gate compare.
//
// Callback discipline (R2-11 lesson): no waiting, no parking, no IOCTL-time
// work inside callbacks. The only lock is a spin lock held for slot math;
// the file-name buffer is touched strictly at <= APC_LEVEL (composed into a
// stack copy) before the lock is taken.

#include <fltKernel.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "../../framework/core_globals.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"
#include "filemon_internal.h"
#if MYARK_MODULE_REDIRECT
// R2-9: the redirect engine serves its FILE rules from this filter's
// pre-create (one filter per driver object, so the hook rides along).
FLT_PREOP_CALLBACK_STATUS MyArkRedirectFilePreCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects);
#endif

#if MYARK_MODULE_FILE_MONITOR

MYARK_FILEMON_STATE g_MyArkFileMon;

#define FILEMON_RING_MASK   (MYARK_FILEMON_RING_EVENTS - 1)

#define FILEMON_ALTITUDE               L"389998"
#define FILEMON_INSTANCE_NAME          L"MyArkCore Default Instance"
#define FILEMON_INSTANCE_SUBKEY        L"\\MyArkCore Default Instance"
#define FILEMON_INSTANCES_SUBKEY       L"\\Instances"
#define FILEMON_DEFAULT_INSTANCE_VALUE L"DefaultInstance"
#define FILEMON_ALTITUDE_VALUE         L"Altitude"
#define FILEMON_FLAGS_VALUE            L"Flags"

VOID
MyArkFileMonRecordEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ UINT32 Type,
    _In_ UINT32 Flags,
    _In_ UINT32 DesiredAccess,
    _In_ UINT32 CreateDisposition,
    _In_ UINT32 Status);

// ---------------------------------------------------------------------------
// Post-op callbacks.
// ---------------------------------------------------------------------------

NTSTATUS
MyArkFileMonFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags);

static
FLT_PREOP_CALLBACK_STATUS
MyArkFileMonPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

#if MYARK_MODULE_REDIRECT
    (VOID)MyArkRedirectFilePreCreate(Data, FltObjects);
#else
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
#endif
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static
FLT_POSTOP_CALLBACK_STATUS
MyArkFileMonPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    ULONG options;
    ULONG desiredAccess;
    UINT32 eventFlags;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    //
    // During instance detach FLTMGR drains outstanding post-ops with a
    // marker flag; nothing in that pass should be recorded.
    //
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    options = Data->Iopb->Parameters.Create.Options;
    desiredAccess = 0;
    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }

    eventFlags = 0;
    if ((options & FILE_DELETE_ON_CLOSE) != 0) {
        eventFlags |= MYARK_FILEMON_FLAG_DELETE_ON_CLOSE;
    }

    MyArkFileMonRecordEvent(Data,
                            MYARK_FILEMON_TYPE_CREATE,
                            eventFlags,
                            desiredAccess,
                            (options >> 24) & 0xFF,
                            (UINT32)Data->IoStatus.Status);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

static
FLT_POSTOP_CALLBACK_STATUS
MyArkFileMonPostSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    ULONG fileClass;
    BOOLEAN deleting = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    fileClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (fileClass == FileDispositionInformation) {
        PFILE_DISPOSITION_INFORMATION info =
            (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        deleting = (info != NULL && info->DeleteFile);
    } else if (fileClass == FileDispositionInformationEx) {
        PFILE_DISPOSITION_INFORMATION_EX info =
            (PFILE_DISPOSITION_INFORMATION_EX)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        deleting = (info != NULL && (info->Flags & FILE_DISPOSITION_DELETE) != 0);
    }

    if (deleting) {
        MyArkFileMonRecordEvent(Data,
                                MYARK_FILEMON_TYPE_DELETE,
                                0,
                                0,
                                0,
                                (UINT32)Data->IoStatus.Status);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

static
NTSTATUS
MyArkFileMonInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    //
    // Attach only to local disk file systems; network/CD volumes carry no
    // signal for this monitor and would widen the sampling surface for no
    // test value.
    //
    if (VolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM) {
        InterlockedIncrement(&g_MyArkFileMon.VolumesAttached);
        return STATUS_SUCCESS;
    }
    return STATUS_FLT_DO_NOT_ATTACH;
}

// ---------------------------------------------------------------------------
// Event recording.
// ---------------------------------------------------------------------------

//
// Gate + path materialization, run at <= APC_LEVEL while the name
// information buffer is still owned: match the normalized name's post-volume
// part against the armed prefix (uppercase, component-aligned) and copy the
// full path into a stack buffer so the spin lock section never touches the
// name allocation.
//
static
BOOLEAN
MyArkFileMonGateAndCopy(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Out_writes_(MYARK_FILEMON_PATH_CHARS) PWCHAR PathOut,
    _Out_ UINT32* PathChars)
{
    PCWSTR tail;
    ULONG totalChars;
    ULONG volumeChars;
    UINT32 prefixChars;
    UINT32 i;

    prefixChars = g_MyArkFileMon.PrefixSubChars;
    totalChars = NameInfo->Name.Length / sizeof(WCHAR);
    volumeChars = NameInfo->Volume.Length / sizeof(WCHAR);

    if (totalChars < volumeChars || totalChars - volumeChars < prefixChars) {
        return FALSE;
    }

    tail = NameInfo->Name.Buffer + volumeChars;
    for (i = 0; i < prefixChars; i++) {
        if (RtlUpcaseUnicodeChar(tail[i]) != g_MyArkFileMon.PrefixSubUc[i]) {
            return FALSE;
        }
    }
    if (totalChars - volumeChars > prefixChars) {
        WCHAR boundary = RtlUpcaseUnicodeChar(tail[prefixChars]);
        if (boundary != L'\\') {
            return FALSE;  // "\dir" must not match "\dirx"
        }
    }
    // else: exact prefix hit (the monitored directory itself) -- record it.

    if (totalChars >= MYARK_FILEMON_PATH_CHARS) {
        InterlockedIncrement(&g_MyArkFileMon.Skipped);  // oversize path
        return FALSE;
    }

    RtlCopyMemory(PathOut, NameInfo->Name.Buffer, totalChars * sizeof(WCHAR));
    PathOut[totalChars] = L'\0';
    *PathChars = (UINT32)totalChars + 1;
    return TRUE;
}

VOID
MyArkFileMonRecordEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ UINT32 Type,
    _In_ UINT32 Flags,
    _In_ UINT32 DesiredAccess,
    _In_ UINT32 CreateDisposition,
    _In_ UINT32 Status)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    WCHAR pathCopy[MYARK_FILEMON_PATH_CHARS];
    UINT32 pathChars = 0;
    UINT64 timestamp;
    KIRQL oldIrql;
    KIRQL snapIrql;
    BOOLEAN enabled;
    BOOLEAN bypassed;
    PMYARK_FILEMON_EVENT slot;
    NTSTATUS st;

    //
    // Disarmed: leave without touching any counter, so Skipped stays a pure
    // sampling-loss metric for the armed window.
    //
    KeAcquireSpinLock(&g_MyArkFileMon.StateLock, &snapIrql);
    enabled = g_MyArkFileMon.Enabled;
    bypassed = FALSE;
    if (enabled) {
        // R3-7 bypass: drop listed requesters before the (expensive) name
        // query. Linear scan over <= 16 entries under the lock. Only runs
        // while armed so BypassDrops stays an armed-window metric.
        ULONG pid = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
        UINT32 i;
        for (i = 0; i < g_MyArkFileMon.BypassCount; i++) {
            if (g_MyArkFileMon.BypassPids[i] == (UINT32)pid) {
                g_MyArkFileMon.BypassDrops++;
                bypassed = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&g_MyArkFileMon.StateLock, snapIrql);
    if (bypassed || !enabled) {
        return;
    }

    //
    // FltGetFileNameInformation is a <= APC_LEVEL API; beyond that (fast-io
    // and some paging paths) the event is skipped and counted instead.
    //
    if (KeGetCurrentIrql() > APC_LEVEL) {
        InterlockedIncrement(&g_MyArkFileMon.Skipped);
        return;
    }

    st = FltGetFileNameInformation(Data,
                                   FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                   &nameInfo);
    if (!NT_SUCCESS(st)) {
        InterlockedIncrement(&g_MyArkFileMon.Skipped);
        return;
    }

    st = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(st)) {
        FltReleaseFileNameInformation(nameInfo);
        InterlockedIncrement(&g_MyArkFileMon.Skipped);
        return;
    }

    if (!MyArkFileMonGateAndCopy(nameInfo, pathCopy, &pathChars)) {
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    timestamp = KeQueryInterruptTime();

    KeAcquireSpinLock(&g_MyArkFileMon.StateLock, &oldIrql);
    if (!g_MyArkFileMon.Enabled) {
        KeReleaseSpinLock(&g_MyArkFileMon.StateLock, oldIrql);
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    if (g_MyArkFileMon.Buffered >= MYARK_FILEMON_RING_EVENTS) {
        g_MyArkFileMon.TotalDropped++;  // ring full: drop the new event
    } else {
        slot = &g_MyArkFileMon.Ring[g_MyArkFileMon.WriteIdx];
        g_MyArkFileMon.NextSequence++;
        slot->Sequence = g_MyArkFileMon.NextSequence;
        slot->Timestamp = timestamp;
        slot->ProcessId = (UINT32)(UINT_PTR)FltGetRequestorProcessId(Data);
        slot->Type = Type;
        slot->Flags = Flags;
        slot->DesiredAccess = DesiredAccess;
        slot->CreateDisposition = CreateDisposition;
        slot->Status = Status;
        slot->PathChars = pathChars;
        RtlCopyMemory(slot->Path, pathCopy, pathChars * sizeof(WCHAR));
        g_MyArkFileMon.WriteIdx = (g_MyArkFileMon.WriteIdx + 1) & FILEMON_RING_MASK;
        g_MyArkFileMon.Buffered++;
        g_MyArkFileMon.TotalRecorded++;
    }
    KeReleaseSpinLock(&g_MyArkFileMon.StateLock, oldIrql);

    FltReleaseFileNameInformation(nameInfo);
}

//
// FLTMGR owns DriverObject->DriverUnload once FltRegisterFilter succeeds,
// so the WDF EvtDriverUnload never runs and this callback is the real
// driver unload: it performs the FULL module teardown (other modules,
// IOCTL table, safety token) and then unregisters the filter (canonical
// minifilter pattern). Guarded against double invocation.
//
static LONG g_FilterUnloadHandled = 0;

NTSTATUS
MyArkFileMonFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (InterlockedExchange(&g_FilterUnloadHandled, 1) == 0) {
        g_MyArkFileMon.Enabled = FALSE;
        MyArkCoreRunModuleTeardown();
    }
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// FLTMGR registration: post-op sampling of CREATE + disposition changes.
// The filter's unload is owned by module Cleanup (FltUnregisterFilter), so
// no FilterUnloadCallback is offered and fltmc cannot pull it out.
// ---------------------------------------------------------------------------

static const FLT_CONTEXT_REGISTRATION g_MyArkFileMonContexts[] = {
    FLT_CONTEXT_END
};

static const FLT_OPERATION_REGISTRATION g_MyArkFileMonCallbacks[] = {
    { IRP_MJ_CREATE,           0, MyArkFileMonPreCreate, MyArkFileMonPostCreate },
    { IRP_MJ_SET_INFORMATION,  0, NULL, MyArkFileMonPostSetInfo },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION g_MyArkFileMonRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    g_MyArkFileMonContexts,
    g_MyArkFileMonCallbacks,
    MyArkFileMonFilterUnload,
    MyArkFileMonInstanceSetup,
    NULL,                        // InstanceQueryTeardownCallback
    NULL,                        // InstanceTeardownStartCallback
    NULL,                        // InstanceTeardownCompleteCallback
    NULL,                        // GenerateFileNameCallback
    NULL,                        // NormalizeNameComponentCallback
    NULL                         // NormalizeNameComponentCleanupCallback
};

// ---------------------------------------------------------------------------
// Instances key + lifecycle.
// ---------------------------------------------------------------------------

NTSTATUS
MyArkFileMonEnsureInstancesKey(
    VOID)
{
    WCHAR pathBuf[512];
    UNICODE_STRING pathUs;
    OBJECT_ATTRIBUTES oa;
    HANDLE instancesKey = NULL;
    HANDLE instanceKey = NULL;
    ULONG disposition;
    NTSTATUS status;
    SIZE_T baseBytes;

    UNICODE_STRING defaultInstanceValue = RTL_CONSTANT_STRING(FILEMON_DEFAULT_INSTANCE_VALUE);
    UNICODE_STRING altitudeValue = RTL_CONSTANT_STRING(FILEMON_ALTITUDE_VALUE);
    UNICODE_STRING flagsValue = RTL_CONSTANT_STRING(FILEMON_FLAGS_VALUE);

    if (g_MyArkCoreServiceKey.Buffer == NULL || g_MyArkCoreServiceKey.Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    baseBytes = g_MyArkCoreServiceKey.Length;
    if (baseBytes + sizeof(FILEMON_INSTANCES_SUBKEY) +
        wcslen(FILEMON_INSTANCE_NAME) * sizeof(WCHAR) + sizeof(WCHAR) > sizeof(pathBuf)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(pathBuf, g_MyArkCoreServiceKey.Buffer, baseBytes);
    RtlCopyMemory((PUCHAR)pathBuf + baseBytes,
                  FILEMON_INSTANCES_SUBKEY,
                  sizeof(FILEMON_INSTANCES_SUBKEY));

    //
    // <ServiceKey>\Instances with DefaultInstance pointing at the child key.
    // Idempotent: after sc stop / sc start the key already exists.
    //
    RtlInitUnicodeString(&pathUs, pathBuf);
    InitializeObjectAttributes(&oa,
                               &pathUs,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    status = ZwCreateKey(&instancesKey,
                         KEY_CREATE_SUB_KEY | KEY_SET_VALUE,
                         &oa,
                         0,
                         NULL,
                         REG_OPTION_NON_VOLATILE,
                         &disposition);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_FILEMON,
                    "FileMon: create Instances key failed: 0x%08X",
                    status);
        return status;
    }

    ZwSetValueKey(instancesKey,
                  &defaultInstanceValue,
                  0,
                  REG_SZ,
                  (PVOID)FILEMON_INSTANCE_NAME,
                  (ULONG)(wcslen(FILEMON_INSTANCE_NAME) + 1) * sizeof(WCHAR));

    //
    // Overwrite the NUL that terminated "<ServiceKey>\Instances" and append
    // the instance subkey with its own leading separator: the final path is
    // "<ServiceKey>\Instances\MyArkCore Default Instance".
    //
    RtlCopyMemory((PUCHAR)pathBuf + baseBytes + sizeof(FILEMON_INSTANCES_SUBKEY) - sizeof(WCHAR),
                  FILEMON_INSTANCE_SUBKEY,
                  sizeof(FILEMON_INSTANCE_SUBKEY));

    RtlInitUnicodeString(&pathUs, pathBuf);
    InitializeObjectAttributes(&oa,
                               &pathUs,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    status = ZwCreateKey(&instanceKey,
                         KEY_SET_VALUE,
                         &oa,
                         0,
                         NULL,
                         REG_OPTION_NON_VOLATILE,
                         &disposition);
    if (NT_SUCCESS(status)) {
        ZwSetValueKey(instanceKey,
                      &altitudeValue,
                      0,
                      REG_SZ,
                      (PVOID)FILEMON_ALTITUDE,
                      (ULONG)(wcslen(FILEMON_ALTITUDE) + 1) * sizeof(WCHAR));
        {
            ULONG zeroFlags = 0;
            ZwSetValueKey(instanceKey,
                          &flagsValue,
                          0,
                          REG_DWORD,
                          &zeroFlags,
                          sizeof(ULONG));
        }
        ZwClose(instanceKey);
    } else {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_FILEMON,
                    "FileMon: create instance key failed: 0x%08X",
                    status);
    }

    ZwClose(instancesKey);

    //
    // A missing instance key is survivable (instances attach per-volume; the
    // filter itself still registers and STATUS reports the attachment count).
    //
    return STATUS_SUCCESS;
}

VOID
MyArkFileMonStart(
    VOID)
{
    SIZE_T ringBytes = sizeof(MYARK_FILEMON_EVENT) * MYARK_FILEMON_RING_EVENTS;
    NTSTATUS status;

    RtlZeroMemory(&g_MyArkFileMon, sizeof(g_MyArkFileMon));
    KeInitializeSpinLock(&g_MyArkFileMon.StateLock);

    g_MyArkFileMon.Ring = MyArkAllocatePool(NonPagedPoolNx, ringBytes, MYARK_FILEMON_POOL_TAG);
    if (g_MyArkFileMon.Ring == NULL) {
        g_MyArkFileMon.StartStage = 1;
        g_MyArkFileMon.StartStatus = (UINT32)STATUS_INSUFFICIENT_RESOURCES;
        return;
    }
    RtlZeroMemory(g_MyArkFileMon.Ring, ringBytes);

    status = MyArkFileMonEnsureInstancesKey();
    if (!NT_SUCCESS(status)) {
        g_MyArkFileMon.StartStage = 2;
        g_MyArkFileMon.StartStatus = (UINT32)status;
        return;
    }

    status = FltRegisterFilter(g_MyArkCoreDriverObject,
                               &g_MyArkFileMonRegistration,
                               &g_MyArkFileMon.Filter);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_FILEMON,
                    "FileMon: FltRegisterFilter failed: 0x%08X",
                    status);
        g_MyArkFileMon.StartStage = 3;
        g_MyArkFileMon.StartStatus = (UINT32)status;
        return;
    }
    g_MyArkFileMon.Registered = TRUE;

    //
    // Existing volumes are announced during this call; InstanceSetup counts
    // the disk attachments. A failure here is rare and non-fatal for the
    // monitor surface (STATUS still reports Registered=1, Attached=0).
    //
    status = FltStartFiltering(g_MyArkFileMon.Filter);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_FILEMON,
                    "FileMon: FltStartFiltering failed: 0x%08X",
                    status);
        g_MyArkFileMon.StartStage = 4;
        g_MyArkFileMon.StartStatus = (UINT32)status;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_FILEMON,
                "FileMon: filter registered, %d events buffered",
                (int)g_MyArkFileMon.Buffered);
}

VOID
MyArkFileMonStop(
    VOID)
{
    g_MyArkFileMon.Enabled = FALSE;

    if (g_MyArkFileMon.Filter != NULL) {
        FltUnregisterFilter(g_MyArkFileMon.Filter);
        g_MyArkFileMon.Filter = NULL;
        g_MyArkFileMon.Registered = FALSE;
    }

    if (g_MyArkFileMon.Ring != NULL) {
        ExFreePoolWithTag(g_MyArkFileMon.Ring, MYARK_FILEMON_POOL_TAG);
        g_MyArkFileMon.Ring = NULL;
    }
}

// ---------------------------------------------------------------------------
// IOCTL-backed operations.
// ---------------------------------------------------------------------------

static
BOOLEAN
MyArkFileMonParsePrefix(
    _In_ PCWSTR PathPrefix,
    _Out_writes_(MYARK_FILEMON_PATH_CHARS) PWCHAR SubUc,
    _Out_ UINT16* SubChars)
{
    SIZE_T len;
    SIZE_T start = 0;
    SIZE_T subStart;
    SIZE_T i;

    len = wcsnlen(PathPrefix, MYARK_FILEMON_PATH_CHARS);
    if (len == 0 || len >= MYARK_FILEMON_PATH_CHARS) {
        return FALSE;
    }

    if (len >= 4 &&
        PathPrefix[0] == L'\\' && PathPrefix[1] == L'?' &&
        PathPrefix[2] == L'?' && PathPrefix[3] == L'\\') {
        start = 4;
    }

    //
    // Expect "X:" with an alphabetic drive letter; everything from the
    // following separator on becomes the NT sub-path ("\..."). "C:\" alone
    // is legal and degenerates to an empty sub-path (match whole volume).
    //
    if (len - start < 2) {
        return FALSE;
    }
    {
        WCHAR driveLetter = PathPrefix[start];
        BOOLEAN alpha = ((driveLetter >= L'a' && driveLetter <= L'z') ||
                         (driveLetter >= L'A' && driveLetter <= L'Z'));
        if (!alpha || PathPrefix[start + 1] != L':') {
            return FALSE;
        }
    }
    subStart = start + 2;
    if (subStart < len && PathPrefix[subStart] != L'\\') {
        return FALSE;
    }

    for (i = 0; subStart + i < len; i++) {
        WCHAR ch = PathPrefix[subStart + i];
        if (ch == L'/') {
            ch = L'\\';  // accept forward slashes, normalize like the FS does
        }
        SubUc[i] = RtlUpcaseUnicodeChar(ch);
    }
    while (i > 0 && SubUc[i - 1] == L'\\') {
        i--;  // a trailing separator would break component-boundary matching
    }
    SubUc[i] = L'\0';
    *SubChars = (UINT16)i;
    return TRUE;
}

NTSTATUS
MyArkFileMonControl(
    _In_ UINT32 Enable,
    _In_ PCWSTR PathPrefix,
    _Out_ PMYARK_FILEMON_CONTROL_OUTPUT Output)
{
    WCHAR subUc[MYARK_FILEMON_PATH_CHARS];
    UINT16 subChars = 0;
    KIRQL oldIrql;

    RtlZeroMemory(Output, sizeof(*Output));

    if (Enable == MYARK_FILEMON_ENABLE_OFF) {
        KeAcquireSpinLock(&g_MyArkFileMon.StateLock, &oldIrql);
        g_MyArkFileMon.Enabled = FALSE;
        g_MyArkFileMon.PrefixSubChars = 0;
        RtlZeroMemory(g_MyArkFileMon.PrefixSubUc, sizeof(g_MyArkFileMon.PrefixSubUc));
        KeReleaseSpinLock(&g_MyArkFileMon.StateLock, oldIrql);

        Output->Status = (UINT32)STATUS_SUCCESS;
        Output->Enabled = MYARK_FILEMON_ENABLE_OFF;
        return STATUS_SUCCESS;
    }

    if (Enable != MYARK_FILEMON_ENABLE_ON) {
        Output->Status = (UINT32)STATUS_INVALID_PARAMETER;
        Output->Enabled = MYARK_FILEMON_ENABLE_OFF;
        return STATUS_SUCCESS;
    }

    if (!g_MyArkFileMon.Registered) {
        Output->Status = (UINT32)STATUS_DEVICE_NOT_READY;
        Output->Enabled = MYARK_FILEMON_ENABLE_OFF;
        return STATUS_SUCCESS;
    }

    if (!MyArkFileMonParsePrefix(PathPrefix, subUc, &subChars)) {
        Output->Status = (UINT32)STATUS_INVALID_PARAMETER;
        Output->Enabled = MYARK_FILEMON_ENABLE_OFF;
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&g_MyArkFileMon.StateLock, &oldIrql);
    RtlCopyMemory(g_MyArkFileMon.PrefixSubUc, subUc, (subChars + 1) * sizeof(WCHAR));
    g_MyArkFileMon.PrefixSubChars = subChars;
    g_MyArkFileMon.Enabled = TRUE;
    KeReleaseSpinLock(&g_MyArkFileMon.StateLock, oldIrql);

    Output->Status = (UINT32)STATUS_SUCCESS;
    Output->Enabled = MYARK_FILEMON_ENABLE_ON;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkFileMonDrain(
    _In_ UINT32 MaxEvents,
    _Out_ PMYARK_FILEMON_DRAIN_OUTPUT Output,
    _In_ SIZE_T OutputBytes,
    _Out_ size_t* BytesReturned)
{
    SIZE_T headerBytes = sizeof(MYARK_FILEMON_DRAIN_OUTPUT) - sizeof(MYARK_FILEMON_EVENT);
    UINT32 fit;
    UINT32 want;
    UINT32 copied = 0;
    KIRQL oldIrql;

    if (OutputBytes < headerBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    fit = (UINT32)((OutputBytes - headerBytes) / sizeof(MYARK_FILEMON_EVENT));
    want = (MaxEvents == 0) ? fit : MaxEvents;
    if (want > fit) {
        want = fit;
    }
    if (want > MYARK_FILEMON_DRAIN_MAX_EVENTS) {
        want = MYARK_FILEMON_DRAIN_MAX_EVENTS;
    }

    KeAcquireSpinLock(&g_MyArkFileMon.StateLock, &oldIrql);
    while (copied < want && g_MyArkFileMon.Buffered > 0) {
        RtlCopyMemory(&Output->Events[copied],
                      &g_MyArkFileMon.Ring[g_MyArkFileMon.ReadIdx],
                      sizeof(MYARK_FILEMON_EVENT));
        g_MyArkFileMon.ReadIdx = (g_MyArkFileMon.ReadIdx + 1) & FILEMON_RING_MASK;
        g_MyArkFileMon.Buffered--;
        copied++;
    }
    Output->Count = copied;
    Output->Remaining = g_MyArkFileMon.Buffered;
    Output->TotalRecorded = (UINT32)g_MyArkFileMon.TotalRecorded;
    Output->TotalDropped = (UINT32)g_MyArkFileMon.TotalDropped;
    Output->Registered = g_MyArkFileMon.Registered ? 1 : 0;
    Output->Enabled = g_MyArkFileMon.Enabled ? 1 : 0;
    Output->VolumesAttached = (UINT32)g_MyArkFileMon.VolumesAttached;
    Output->Skipped = (UINT32)g_MyArkFileMon.Skipped;
    KeReleaseSpinLock(&g_MyArkFileMon.StateLock, oldIrql);

    *BytesReturned = headerBytes + (SIZE_T)copied * sizeof(MYARK_FILEMON_EVENT);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkFileMonQueryStatus(
    _Out_ PMYARK_FILEMON_STATUS_OUTPUT Output)
{
    KIRQL oldIrql;

    RtlZeroMemory(Output, sizeof(*Output));

    KeAcquireSpinLock(&g_MyArkFileMon.StateLock, &oldIrql);
    Output->Status = (UINT32)STATUS_SUCCESS;
    Output->Registered = g_MyArkFileMon.Registered ? 1 : 0;
    Output->Enabled = g_MyArkFileMon.Enabled ? 1 : 0;
    Output->Buffered = g_MyArkFileMon.Buffered;
    Output->TotalRecorded = (UINT32)g_MyArkFileMon.TotalRecorded;
    Output->TotalDropped = (UINT32)g_MyArkFileMon.TotalDropped;
    Output->VolumesAttached = (UINT32)g_MyArkFileMon.VolumesAttached;
    Output->Skipped = (UINT32)g_MyArkFileMon.Skipped;
    Output->StartStage = g_MyArkFileMon.StartStage;
    Output->StartStatus = g_MyArkFileMon.StartStatus;
    KeReleaseSpinLock(&g_MyArkFileMon.StateLock, oldIrql);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// R3-7: bypass-PID list + system minifilter inventory.
// ---------------------------------------------------------------------------

NTSTATUS
MyArkFileMonBypass(
    _In_ UINT32 Action,
    _In_ UINT32 Pid,
    _Out_ PMYARK_FILEMON_BYPASS_OUTPUT Output)
{
    KIRQL  oldIrql;
    UINT32 i;
    UINT32 j;

    RtlZeroMemory(Output, sizeof(*Output));

    KeAcquireSpinLock(&g_MyArkFileMon.StateLock, &oldIrql);

    Output->BypassDrops = g_MyArkFileMon.BypassDrops;
    Output->Count = g_MyArkFileMon.BypassCount;
    RtlCopyMemory(Output->Pids,
                  g_MyArkFileMon.BypassPids,
                  g_MyArkFileMon.BypassCount * sizeof(UINT32));

    switch (Action) {
    case MYARK_FILEMON_BYPASS_ACTION_QUERY:
        Output->Applied = 0;
        break;

    case MYARK_FILEMON_BYPASS_ACTION_ADD:
        if (Pid == 0) {
            // 0 = "no requester" (system threads): listing it would mute
            // every kernel-side event. System (4) stays allowed.
            KeReleaseSpinLock(&g_MyArkFileMon.StateLock, oldIrql);
            Output->Status = (UINT32)STATUS_INVALID_PARAMETER;
            return STATUS_INVALID_PARAMETER;
        }
        for (i = 0; i < g_MyArkFileMon.BypassCount; i++) {
            if (g_MyArkFileMon.BypassPids[i] == Pid) {
                break;                          // already listed
            }
        }
        if (i < g_MyArkFileMon.BypassCount) {
            Output->Applied = 0;
        } else if (g_MyArkFileMon.BypassCount >= MYARK_FILEMON_BYPASS_MAX) {
            KeReleaseSpinLock(&g_MyArkFileMon.StateLock, oldIrql);
            Output->Status = (UINT32)STATUS_INSUFFICIENT_RESOURCES;
            return STATUS_INSUFFICIENT_RESOURCES;
        } else {
            g_MyArkFileMon.BypassPids[g_MyArkFileMon.BypassCount] = Pid;
            g_MyArkFileMon.BypassCount++;
            Output->Applied = 1;
            Output->Count = g_MyArkFileMon.BypassCount;
            RtlCopyMemory(Output->Pids,
                          g_MyArkFileMon.BypassPids,
                          g_MyArkFileMon.BypassCount * sizeof(UINT32));
        }
        break;

    case MYARK_FILEMON_BYPASS_ACTION_REMOVE:
        for (i = 0; i < g_MyArkFileMon.BypassCount; i++) {
            if (g_MyArkFileMon.BypassPids[i] == Pid) {
                break;
            }
        }
        if (i >= g_MyArkFileMon.BypassCount) {
            Output->Applied = 0;
        } else {
            for (j = i; j + 1 < g_MyArkFileMon.BypassCount; j++) {
                g_MyArkFileMon.BypassPids[j] = g_MyArkFileMon.BypassPids[j + 1];
            }
            g_MyArkFileMon.BypassCount--;
            Output->Applied = 1;
            Output->Count = g_MyArkFileMon.BypassCount;
            RtlCopyMemory(Output->Pids,
                          g_MyArkFileMon.BypassPids,
                          g_MyArkFileMon.BypassCount * sizeof(UINT32));
        }
        break;

    case MYARK_FILEMON_BYPASS_ACTION_CLEAR:
        Output->Applied = (g_MyArkFileMon.BypassCount != 0) ? 1 : 0;
        g_MyArkFileMon.BypassCount = 0;
        Output->Count = 0;
        break;

    default:
        KeReleaseSpinLock(&g_MyArkFileMon.StateLock, oldIrql);
        Output->Status = (UINT32)STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    KeReleaseSpinLock(&g_MyArkFileMon.StateLock, oldIrql);
    Output->Status = (UINT32)STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

//
//
// Copy one ASI string (USHORT length/offset pair, relative to the record
// start) into the fixed entry: truncating at cap-1 WCHARs, NUL-terminated.
//
// Local mirror of FILTER_AGGREGATE_STANDARD_INFORMATION's minifilter
// branch (km/user headers disagree on the union member naming; the record
// layout itself is fixed: NextEntryOffset@0, Flags@4, minifilter payload
// @8, USHORT name/altitude length+offset pairs at 20..26).
typedef struct _MYARK_ASI_MINI {
    ULONG  NextEntryOffset;                      // @0
    ULONG  Flags;                                // @4 (FLTFL_ASI_*)
    ULONG  MiniFlags;                            // @8
    ULONG  FrameID;                              // @12
    ULONG  NumberOfInstances;                    // @16
    USHORT FilterNameLength;                     // @20 (bytes)
    USHORT FilterNameBufferOffset;               // @22
    USHORT FilterAltitudeLength;                 // @24 (bytes)
    USHORT FilterAltitudeBufferOffset;           // @26
} MYARK_ASI_MINI, *PMYARK_ASI_MINI;

C_ASSERT(FIELD_OFFSET(MYARK_ASI_MINI, FilterNameLength) == 20);

static
VOID
MyArkFileMonCopyAsiString(
    _Out_ WCHAR* Dst,
    _In_ ULONG DstChars,
    _In_ PUCHAR Record,
    _In_ USHORT OffsetBytes,
    _In_ USHORT LengthBytes,
    _Out_ PULONG CharsOut)
{
    ULONG chars = LengthBytes / sizeof(WCHAR);

    if (OffsetBytes == 0 || LengthBytes == 0) {
        Dst[0] = L'\0';
        *CharsOut = 0;
        return;
    }
    if (chars >= DstChars) {
        chars = DstChars - 1;
    }
    RtlCopyMemory(Dst, Record + OffsetBytes, chars * sizeof(WCHAR));
    Dst[chars] = L'\0';
    *CharsOut = chars;
}

NTSTATUS
MyArkFileMonEnumFilters(
    _Out_ PMYARK_FILEMON_ENUM_OUTPUT Output)
{
    PFLT_FILTER* filters = NULL;
    ULONG        count = 0;
    ULONG        returned = 0;
    ULONG        i;
    NTSTATUS     status;

    RtlZeroMemory(Output, sizeof(*Output));

    // Two-phase: NULL/0 answers with the registered-filter count.
    status = FltEnumerateFilters(NULL, 0, &count);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        if (NT_SUCCESS(status)) {
            return STATUS_SUCCESS;            // degenerate: zero filters
        }
        return status;
    }
    if (count == 0) {
        return STATUS_SUCCESS;
    }

    filters = (PFLT_FILTER*)MyArkAllocatePool(
        NonPagedPoolNx,
        (SIZE_T)count * sizeof(PFLT_FILTER),
        MYARK_FILEMON_POOL_TAG);
    if (filters == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = FltEnumerateFilters(filters, count, &returned);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(filters, MYARK_FILEMON_POOL_TAG);
        return status;
    }

    Output->Truncated = (returned > MYARK_FILEMON_MAX_FILTERS) ? 1 : 0;
    if (returned > MYARK_FILEMON_MAX_FILTERS) {
        returned = MYARK_FILEMON_MAX_FILTERS;
    }
    Output->Count = 0;      // filled per-entry below (legacy = skipped)

    for (i = 0; i < returned; i++) {
        ULONG needed = 0;
        PMYARK_ASI_MINI asi;

        //
        // FltGetFilterInformation does NOT do a NULL-buffer size query for
        // FiltersAggregateStandardInformation (it answers STATUS_SUCCESS
        // with BytesReturned=0). Use one generous fixed buffer instead --
        // filter name + altitude are far below 1 KiB on any real system.
        //
        ULONG cap = 2048;
        asi = (PMYARK_ASI_MINI)MyArkAllocatePool(
            NonPagedPoolNx, cap, MYARK_FILEMON_POOL_TAG);
        if (asi == NULL) {
            FltObjectDereference(filters[i]);   // keep the enum refcount even
            continue;
        }

        status = FltGetFilterInformation(filters[i],
                                         FilterAggregateStandardInformation,
                                         asi,
                                         cap,
                                         &needed);
        if (NT_SUCCESS(status)
            && (asi->Flags & FLTFL_ASI_IS_MINIFILTER) != 0) {
            PMYARK_FILEMON_FILTER_ENTRY entry =
                &Output->Entries[Output->Count];
            MyArkFileMonCopyAsiString(
                entry->Name, MYARK_FILEMON_FILTER_NAME_CHARS,
                (PUCHAR)asi,
                asi->FilterNameBufferOffset,
                asi->FilterNameLength,
                (PULONG)&entry->NameChars);
            MyArkFileMonCopyAsiString(
                entry->Altitude, MYARK_FILEMON_ALTITUDE_CHARS,
                (PUCHAR)asi,
                asi->FilterAltitudeBufferOffset,
                asi->FilterAltitudeLength,
                (PULONG)&entry->AltitudeChars);
            entry->InstanceCount = asi->NumberOfInstances;
            Output->Count++;                 // only minifilters take slots
        }
        ExFreePoolWithTag(asi, MYARK_FILEMON_POOL_TAG);

        FltObjectDereference(filters[i]);
    }

    ExFreePoolWithTag(filters, MYARK_FILEMON_POOL_TAG);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_FILE_MONITOR
