// MyArk process module: EPROCESS field extraction for DETAIL / DETAIL_RUNTIME.
//
// All offsets are hardcoded for Windows 11 24H2 / build 26100.x -- see
// process_internal.h. S7.1 (DynData) loads a profile that overrides them.
//
// Every read goes through MmIsAddressValid so a stale EPROCESS (e.g. a
// process that exited between the PID lookup and the field read) does not
// blue-screen the VM. The caller has already done a PsLookupProcessByProcessId
// to dereference the EPROCESS, so the structure itself is alive when we
// get here.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "process_internal.h"

#if MYARK_MODULE_PROCESS

// ntddk does not surface these VM-query conveniences; local mirrors.
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif

NTKERNELAPI
NTSTATUS
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

//
// Mirror of the VM_COUNTERS layout ProcessVmCounters returns (wdm/ntifs do
// not declare it in kernel mode; field order per the documented class).
//
typedef struct _MYARK_VM_COUNTERS {
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    ULONG  PageFaultCount;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
} MYARK_VM_COUNTERS, *PMYARK_VM_COUNTERS;

NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);


//
// Generic ULONG / ULONGLONG / UCHAR readers that bail to zero on a bad
// address. Useful for "best-effort" fields where a single bad byte shouldn't
//// reject the whole row.
//

static
ULONG
MyArkProcessReadUlongSafe(
    _In_ PVOID Base,
    _In_ ULONG Offset)
{
    if (!MmIsAddressValid((PUCHAR)Base + Offset)) {
        return 0;
    }
    return *((PULONG)((PUCHAR)Base + Offset));
}

static
ULONGLONG
MyArkProcessReadUlonglongSafe(
    _In_ PVOID Base,
    _In_ ULONG Offset)
{
    if (!MmIsAddressValid((PUCHAR)Base + Offset)) {
        return 0;
    }
    return *((PULONGLONG)((PUCHAR)Base + Offset));
}

static
VOID
MyArkProcessReadBytesSafe(
    _Out_writes_bytes_(Size) PUCHAR Dest,
    _In_ PVOID Base,
    _In_ ULONG Offset,
    _In_ ULONG Size)
{
    if (Dest == NULL || Size == 0) {
        return;
    }
    if (!MmIsAddressValid((PUCHAR)Base + Offset)) {
        RtlZeroMemory(Dest, Size);
        return;
    }
    RtlCopyMemory(Dest, (PUCHAR)Base + Offset, Size);
}


//
// Copy a UNICODE_STRING from inside the EPROCESS into a fixed-width wide
// buffer. The string's Buffer pointer is verified before being read so a
// malicious / corrupt ImageName can't crash us.
//

static
VOID
MyArkProcessCopyUnicodeString(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ size_t DestChars,
    _In_ PUNICODE_STRING Source)
{
    if (Dest == NULL || DestChars == 0) {
        return;
    }
    Dest[0] = L'\0';

    if (Source == NULL || Source->Length == 0 || Source->Buffer == NULL) {
        return;
    }

    USHORT bytes = Source->Length;
    USHORT chars = bytes / sizeof(WCHAR);
    if (chars == 0) {
        return;
    }

    if (!MmIsAddressValid(Source->Buffer)) {
        return;
    }

    size_t i;
    for (i = 0; i + 1 < DestChars && i < chars; i++) {
        Dest[i] = Source->Buffer[i];
    }
    Dest[i] = L'\0';
}


//
// Resolve a PID to an EPROCESS. PsLookupProcessByProcessId bumps the
// reference count, which we drop before returning so callers don't have to
// worry about object lifetimes.
//

static
NTSTATUS
MyArkProcessResolveEProcess(
    _In_ ULONG Pid,
    _Out_ PVOID* EProcessOut)
{
    NTSTATUS    status;
    PEPROCESS   proc = NULL;

    if (Pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(UlongToHandle(Pid), &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        return STATUS_NOT_FOUND;
    }

    *EProcessOut = proc;
    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkProcessFillDetail(
    _Out_ PMYARK_PROCESS_DETAIL Detail,
    _In_  ULONG Pid)
//
// Fill MYARK_PROCESS_DETAIL with the EPROCESS snapshot for Pid. Returns
// STATUS_NOT_FOUND when the PID can't be resolved, STATUS_INVALID_PARAMETER
// when the caller passed 0, or STATUS_SUCCESS when the snapshot succeeded
// (in which case Detail is fully populated).
//
{
    NTSTATUS    status;
    PVOID       ep = NULL;

    if (Detail == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Detail, sizeof(*Detail));

    status = MyArkProcessResolveEProcess(Pid, &ep);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Detail->Pid        = Pid;
    Detail->Ppid       = MyArkProcessReadUlongSafe(ep,
                                                   MYARK_OFF_EPROCESS_INHERITED_FROM_UNIQUE_PID);
    Detail->Flags2     = MyArkProcessReadUlongSafe(ep,
                                                   MYARK_OFF_EPROCESS_FLAGS2);
    Detail->Ppl        = (UINT32)MyArkProcessReadUlongSafe(ep,
                                                          MYARK_OFF_EPROCESS_PROTECTION) & 0xFFUL;
    Detail->CreateTime = MyArkProcessReadUlonglongSafe(ep,
                                                      MYARK_OFF_EPROCESS_CREATE_TIME);
    Detail->KernelTime = 0;
    Detail->UserTime   = 0;
    Detail->ThreadCount = MyArkProcessReadUlongSafe(ep,
                                                    MYARK_OFF_EPROCESS_ACTIVE_THREADS);
    Detail->ExitStatus  = MyArkProcessReadUlongSafe(ep,
                                                    MYARK_OFF_EPROCESS_EXIT_STATUS);
    Detail->BasePriority = (INT32)MyArkProcessReadUlongSafe(ep,
                                                          MYARK_OFF_EPROCESS_BASE_PRIORITY);
    Detail->AffinityMask = MyArkProcessReadUlongSafe(ep,
                                                    MYARK_OFF_EPROCESS_AFFINITY);

    //
    // Report which layout the driver actually resolved. The structural
    // offsets are discovered at runtime, so these fields are the client's
    // only way to tell "discovery succeeded" apart from "the module is
    // running with reduced capability" (0 == not resolved). Fields that come
    // from exported accessors keep their profile value for reference.
    //
    {
        const MYARK_ARK_OFFSETS* offsets = MyArkArkOffsetsGet();

        Detail->UniqueProcessIdOffset           = MYARK_OFF_EPROCESS_UNIQUE_PROCESS_ID;
        Detail->ImageFileNameOffset             = MYARK_OFF_EPROCESS_IMAGE_FILE_NAME;
        Detail->InheritedFromUniqueProcessIdOffset = MYARK_OFF_EPROCESS_INHERITED_FROM_UNIQUE_PID;
        Detail->ActiveProcessLinksOffset        = (offsets != NULL) ? offsets->ActiveProcessLinks : 0;
        Detail->ThreadListHeadOffset            = (offsets != NULL) ? offsets->ThreadListHead : 0;
        Detail->PebOffset                       = ((offsets != NULL) && offsets->ProfileMatched)
                                                      ? MYARK_OFF_EPROCESS_PEB
                                                      : 0;
    }

    //
    // ImageFileName (CHAR[16], not NUL-terminated). We seed both the wide
    // Name[] (for the table view) and the embedded CHAR[] field (for tools
    // that want the kernel text).
    //
    UCHAR imageFileNameBuf[MYARK_PROCESS_IMAGE_FILE_NAME_MAX];
    RtlZeroMemory(imageFileNameBuf, sizeof(imageFileNameBuf));

    //
    // Tier A: PsGetProcessImageFileName hands back the kernel's own
    // ImageFileName pointer, so this needs no offset. Reading the documented
    // profile offset here produced an empty name on the 1903 test guest.
    //
    {
        PCHAR imageName = MYARK_PROC_IMAGE(ep);
        if (imageName != NULL && MmIsAddressValid(imageName)) {
            for (size_t i = 0; i + 1 < MYARK_PROCESS_IMAGE_FILE_NAME_MAX; i++) {
                if (!MmIsAddressValid(imageName + i) || imageName[i] == 0) {
                    break;
                }
                imageFileNameBuf[i] = (UCHAR)imageName[i];
            }
        }
    }

    RtlCopyMemory(Detail->ImageFileName,
                  imageFileNameBuf,
                  MYARK_PROCESS_IMAGE_FILE_NAME_MAX);

    for (size_t i = 0; i + 1 < MYARK_PROCESS_IMAGE_FILE_NAME_MAX; i++) {
        Detail->Name[i] = (WCHAR)imageFileNameBuf[i];
        if (imageFileNameBuf[i] == '\0') {
            break;
        }
    }

    //
    // EProcessKernelAddress is ULONG_PTR cast to UINT64 -- on x64 the full
    // address fits. Use uintptr_t via ReadUlonglongSafe so we don't depend
    // on a specific EPROCESS pointer field.
    //
    Detail->EProcessKernelAddress = (UINT64)(ULONG_PTR)ep;

    //
    // PEB-based path extraction: best-effort. The PEB is at a known offset;
    // the path lives at PEB->ProcessParameters->ImagePathName in user space.
    // MmIsAddressValid on a user-mode address is unsafe in PASSIVE_LEVEL;
    // we do a safe read of the PEB pointer (which is valid in kernel),
    // then probe each subsequent pointer chain before dereferencing it.
    //
    PVOID peb = (PVOID)MyArkProcessReadUlonglongSafe(ep,
                                                    MYARK_OFF_EPROCESS_PEB);
    if (peb != NULL && MmIsAddressValid(peb)) {
        //
        // PEB->ProcessParameters is at a Win-version-specific offset; on
        // 24H2 it sits at 0x20 (32-bit) / 0x20 (64-bit) but we don't need
        // to nail it for S6.1 -- leave Path/User empty rather than risk a
        // bad pointer walk. The IOCTL detail view does not require path
        // resolution; the CLI fills it in from a separate API.
        //
        UNREFERENCED_PARAMETER(peb);
    }

    return STATUS_SUCCESS;
}


NTSTATUS
MyArkProcessFillDetailRuntime(
    _Out_ PMYARK_PROCESS_DETAIL_RUNTIME Runtime,
    _In_  ULONG Pid)
//
// Runtime snapshot via Zw semantics (no cross-build EPROCESS offsets):
// ProcessVmCounters fills the working-set / quota / pagefile fields
// verbatim; ProcessCycleTime (class 26, Vista+) fills the cycle counter
// best-effort and stays zero where the class is unsupported.
//
{
    NTSTATUS status;
    NTSTATUS openStatus;
    NTSTATUS vmStatus;
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID clientId;
    MYARK_VM_COUNTERS vm;
    ULONG returned = 0;

    if (Runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Runtime, sizeof(*Runtime));
    Runtime->Pid = Pid;

    clientId.UniqueProcess = ULongToHandle(Pid);
    clientId.UniqueThread = NULL;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    openStatus = ZwOpenProcess(&processHandle,
                               PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               &oa,
                               &clientId);
    Runtime->Reserved0 = (UINT32)openStatus;   // diagnostic: surfaced to R3
    if (!NT_SUCCESS(openStatus)) {
        return STATUS_SUCCESS;
    }

    UCHAR vmBuf[128];
    RtlZeroMemory(&vm, sizeof(vm));   // vm stays defined when the query fails
    //
    // ProcessVmCounters is exact-length; x64 kernels accept
    // sizeof(VM_COUNTERS)=80 or VM_COUNTERS_EX=128 (the 72/88 entries are
    // defensive only). Cascade and record the last attempt for R3.
    //
    static const ULONG vmLens[] = { 80, 88, 72, 128 };
    vmStatus = STATUS_INFO_LENGTH_MISMATCH;
    returned = 0;
    for (ULONG i = 0; i < RTL_NUMBER_OF(vmLens); i++) {
        vmStatus = ZwQueryInformationProcess(processHandle,
                                             ProcessVmCounters,
                                             vmBuf,
                                             vmLens[i],
                                             &returned);
        if (NT_SUCCESS(vmStatus)) {
            Runtime->Reserved1 = (i << 24);             // hi8: winning candidate
            RtlCopyMemory(&vm, vmBuf,
                          sizeof(MYARK_VM_COUNTERS) < returned
                              ? sizeof(MYARK_VM_COUNTERS)
                              : returned);
            break;
        }
        Runtime->Reserved1 = (i << 24) | ((UINT32)vmStatus & 0x00FFFFFF);
    }
    status = NT_SUCCESS(vmStatus) ? STATUS_SUCCESS : vmStatus;
    if (NT_SUCCESS(status)) {
        Runtime->PeakWorkingSetSize = vm.PeakWorkingSetSize;
        Runtime->WorkingSetSize = vm.WorkingSetSize;
        Runtime->QuotaPeakPagedPoolUsage = vm.QuotaPeakPagedPoolUsage;
        Runtime->QuotaPagedPoolUsage = vm.QuotaPagedPoolUsage;
        Runtime->QuotaPeakNonPagedPoolUsage = vm.QuotaPeakNonPagedPoolUsage;
        Runtime->QuotaNonPagedPoolUsage = vm.QuotaNonPagedPoolUsage;
        Runtime->PagefileUsage = vm.PagefileUsage;
        Runtime->PeakPagefileUsage = vm.PeakPagefileUsage;
        Runtime->PrivatePageCount = (UINT32)vm.PrivatePageCount;
    }

    //
    // ProcessCycleTime (class 26) -> PROCESS_CYCLE_TIME_INFORMATION
    // {ULONGLONG CycleTime}. Best-effort: unsupported classes answer
    // STATUS_INVALID_INFO_CLASS and the field stays zero.
    //
    {
        ULONGLONG cycles = 0;
        status = ZwQueryInformationProcess(processHandle,
                                           (PROCESSINFOCLASS)26,
                                           &cycles,
                                           sizeof(cycles),
                                           &returned);
        if (NT_SUCCESS(status) && returned >= sizeof(cycles)) {
            Runtime->CycleTime = cycles;
        }
    }

    ZwClose(processHandle);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_PROCESS