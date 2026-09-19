// MyArk redirect module: R2-9 file/registry redirect engine.
//
// Two rule kinds, both EXACT matches, armed only while rules are set
// (default-inactive surface):
//   FILE -- served from the R2-7 minifilter's IRP_MJ_CREATE pre-op. The
//           source rule is resolved at set time into a full NT path
//           ("\DEVICE\HARDDISK...\DIR\SRC"); on a match the pre-op swaps
//           FILE_OBJECT->FileName to the target's volume-relative
//           remainder ("\DIR\SHADOW"), so the filesystem opens the shadow
//           file instead. The original FileName buffer is intentionally
//           not freed (object-manager owned; bounded by rule-hit count).
//   REG  -- CmRegisterCallbackEx around NtQueryValueKey. Swapping
//           CompleteName in the pre-open callback is NOT honored on this
//           Windows build (the path is parsed before the callback runs --
//           observed 18362: the swap was counted but the open read the
//           original key), so the redirect happens at the value level:
//           RegNtPreQueryValueKey matches the key path + value name and
//           parks the caller's output buffer in CallContext;
//           RegNtPostQueryValueKey rewrites KEY_VALUE_PARTIAL/FULL_
//           INFORMATION with the shadow data. The Cm callback is
//           registered only while REG rules are armed, so an inactive
//           module costs registry traffic nothing.
//
// Locking: rules live behind an EX_SPIN_LOCK (shared lookups, exclusive
// replace). Both acquires raise IRQL, so NO pool allocation happens while
// held -- matches copy the hit into stack buffers and allocate after
// release (worst case a just-cleared rule still serves one redirect).
// Commit/teardown additionally hold a KMUTEX (PASSIVE) because
// CmRegisterCallbackEx/Unregister must run below APC_LEVEL.

#include <fltKernel.h>
#include <wdf.h>
#include <ntddk.h>
#include "Trace.h"
#include "myark_config.h"
#include "../../framework/core_globals.h"
#include "../../../shared/driver/MyArkRedirectIoctl.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"
#include "redirect_internal.h"

#if MYARK_MODULE_REDIRECT

#define MYARK_TRACE_REDIRECT "[redirect] "

#define RENG_POOL_TAG                0x44455252  // 'RRED'
#define REDIR_DEVICE_MAX_CHARS       384
#define REDIR_CM_ALTITUDE            L"389997"

typedef struct _MYARK_REDIRECT_RULE_ENTRY {
    UINT32  Kind;                             // MYARK_REDIRECT_RULE_KIND_*
    UINT16  SourceChars;                      // WCHARs incl. NUL
    UINT16  AuxChars;                         // FILE: target-rel chars / REG: value-name chars
    UINT16  DataChars;                        // REG: shadow data chars (incl. NUL); 0 for FILE
    WCHAR   SourceUc[MYARK_REDIRECT_RULE_CHARS];       // FILE: full NT path / REG: NT key path
    WCHAR   AuxUc[MYARK_REDIRECT_RULE_CHARS];          // FILE: volume-rel target / REG: value name
    WCHAR   TargetDeviceUc[MYARK_REDIRECT_RULE_CHARS]; // FILE: volume device prefix
    WCHAR   DataW[MYARK_REDIRECT_RULE_CHARS];          // REG: shadow data (raw case)
} MYARK_REDIRECT_RULE_ENTRY, *PMYARK_REDIRECT_RULE_ENTRY;

//
// Per-query context parked in REG_QUERY_VALUE_KEY_INFORMATION.CallContext
// and freed in the paired post callback.
//
typedef struct _MYARK_REDIRECT_QUERY_CTX {
    PVOID   KeyValueInformation;               // caller output buffer
    PULONG  ResultLength;                      // caller result-length out
    ULONG   BufferLength;                      // caller output buffer capacity
    ULONG   DataBytes;                         // shadow data bytes (incl. NULs)
    ULONG   Class;                             // KEY_VALUE_INFORMATION_CLASS
    WCHAR   Data[MYARK_REDIRECT_RULE_CHARS];   // shadow data (raw case)
} MYARK_REDIRECT_QUERY_CTX, *PMYARK_REDIRECT_QUERY_CTX;

static EX_SPIN_LOCK               g_RulesLock;
static MYARK_REDIRECT_RULE_ENTRY  g_Rules[MYARK_REDIRECT_MAX_RULES];
static UINT32                     g_RuleCount;
static LONG                       g_FileHits;
static LONG                       g_RegHits;
static LONG                       g_PreCalls;     // diagnostic: pre-callback entries
static LONG                       g_CtxAllocs;    // diagnostic: contexts parked
static LONG                       g_CmState;      // 0 = down, 1 = registered
static LARGE_INTEGER              g_CmCookie;
static PMYARK_REDIRECT_RULE_ENTRY g_Staged;
static UINT32                     g_StagedCount;
static KMUTEX                     g_EngineMutex;

// ---------------------------------------------------------------------------
// String helpers.
// ---------------------------------------------------------------------------

static
VOID
RedirUpcaseInto(
    _Out_writes_(DstCch) PWCHAR Dst,
    _In_ SIZE_T DstCch,
    _In_ PCWSTR Src,
    _Out_ UINT16* SrcChars)
{
    SIZE_T len = wcsnlen(Src, DstCch - 1);
    SIZE_T i;

    for (i = 0; i < len; i++) {
        Dst[i] = RtlUpcaseUnicodeChar(Src[i]);
    }
    Dst[len] = L'\0';
    *SrcChars = (UINT16)(len + 1);
}

//
// Appends the uppercased remainder of a DOS path (everything after the
// "X:" prefix) to an in-progress uppercase buffer, ensuring a single
// leading separator. *Len is the current character count (excluding NUL)
// and is advanced.
//
static
BOOLEAN
RedirAppendDosRest(
    _Out_writes_(DstCch) PWCHAR Dst,
    _In_ SIZE_T DstCch,
    _Inout_ SIZE_T* Len,
    _In_ PCWSTR DosPath,
    _In_ SIZE_T PrefixChars)
{
    PCWSTR rest = DosPath + PrefixChars;
    SIZE_T restLen = wcsnlen(rest, MYARK_REDIRECT_RULE_CHARS);
    SIZE_T i;

    if (restLen > 0 && rest[0] != L'\\') {
        return FALSE;  // "C:x" is not a path this engine accepts
    }
    if (restLen == 0) {
        rest = L"\\";
        restLen = 1;
    }
    if (*Len + restLen + 1 > DstCch) {
        return FALSE;
    }
    for (i = 0; i < restLen; i++) {
        Dst[*Len + i] = RtlUpcaseUnicodeChar(rest[i]);
    }
    *Len += restLen;
    Dst[*Len] = L'\0';
    return TRUE;
}

static
BOOLEAN
RedirSamePath(
    _In_ PCUNICODE_STRING A,
    _In_ PCWSTR BUppercased)
{
    UNICODE_STRING bUs;

    RtlInitUnicodeString(&bUs, BUppercased);
    return RtlEqualUnicodeString(A, &bUs, TRUE);
}

//
// Resolves the drive of a DOS path ("C:\dir\x", optional "\??\" prefix)
// through its "\GLOBAL??\C:" / "\??\C:" symbolic link. Returns the NT
// device prefix and the number of leading input chars consumed ("X:" plus
// any "\??\").
//
static
NTSTATUS
RedirResolveDosDevice(
    _In_ PCWSTR DosPath,
    _Out_writes_(DeviceCch) PWCHAR DeviceOut,
    _In_ SIZE_T DeviceCch,
    _Out_ SIZE_T* PrefixChars)
{
    SIZE_T start = 0;
    SIZE_T len = wcsnlen(DosPath, MYARK_REDIRECT_RULE_CHARS);
    UNICODE_STRING linkUs;
    OBJECT_ATTRIBUTES oa;
    HANDLE linkHandle = NULL;
    NTSTATUS status;
    UCHAR objBuf[sizeof(UNICODE_STRING) + REDIR_DEVICE_MAX_CHARS * sizeof(WCHAR)];
    PUNICODE_STRING objUs;
    ULONG i;
    ULONG returned = 0;
    PCWSTR candidates[2] = { L"\\GLOBAL??\\", L"\\??\\" };

    if (len >= 4 && DosPath[0] == L'\\' && DosPath[1] == L'?' &&
        DosPath[2] == L'?' && DosPath[3] == L'\\') {
        start = 4;
    }
    if (len - start < 2 || DosPath[start + 1] != L':') {
        return STATUS_INVALID_PARAMETER;
    }
    *PrefixChars = start + 2;

    for (i = 0; i < 2 && linkHandle == NULL; i++) {
        WCHAR full[24];
        SIZE_T plen = wcslen(candidates[i]);

        if (plen + 3 > RTL_NUMBER_OF(full)) {
            continue;
        }
        RtlCopyMemory(full, candidates[i], plen * sizeof(WCHAR));
        full[plen] = DosPath[start];
        full[plen + 1] = L':';
        full[plen + 2] = L'\0';

        RtlInitUnicodeString(&linkUs, full);
        InitializeObjectAttributes(&oa,
                                   &linkUs,
                                   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                   NULL,
                                   NULL);
        status = ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &oa);
        if (!NT_SUCCESS(status)) {
            linkHandle = NULL;
        }
    }

    if (linkHandle == NULL) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    RtlZeroMemory(objBuf, sizeof(objBuf));
    objUs = (PUNICODE_STRING)objBuf;
    objUs->MaximumLength = REDIR_DEVICE_MAX_CHARS * sizeof(WCHAR);
    objUs->Buffer = (PWCHAR)(objBuf + sizeof(UNICODE_STRING));
    status = ZwQuerySymbolicLinkObject(linkHandle, objUs, &returned);
    ZwClose(linkHandle);
    if (!NT_SUCCESS(status) || objUs->Length == 0 ||
        objUs->Length / sizeof(WCHAR) >= DeviceCch) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(DeviceOut, objUs->Buffer, objUs->Length);
    DeviceOut[objUs->Length / sizeof(WCHAR)] = L'\0';
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Rule staging + commit.
// ---------------------------------------------------------------------------

static
NTSTATUS
RedirStageOne(
    _Out_ PMYARK_REDIRECT_RULE_ENTRY Entry,
    _In_ const MYARK_REDIRECT_RULE* Rule)
{
    WCHAR device[REDIR_DEVICE_MAX_CHARS];
    WCHAR device2[REDIR_DEVICE_MAX_CHARS];
    SIZE_T srcPrefix = 0, tgtPrefix = 0;
    SIZE_T len;
    UINT16 chars = 0;
    NTSTATUS status;

    RtlZeroMemory(Entry, sizeof(*Entry));

    if (Rule->Flags != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Rule->Kind == MYARK_REDIRECT_RULE_KIND_FILE) {
        status = RedirResolveDosDevice(Rule->Source, device, RTL_NUMBER_OF(device), &srcPrefix);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = RedirResolveDosDevice(Rule->Target, device2, RTL_NUMBER_OF(device2), &tgtPrefix);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        //
        // FILE_OBJECT->FileName is volume-relative after the swap, so the
        // target must live on the same volume as the source.
        //
        {
            UNICODE_STRING d1, d2;

            RtlInitUnicodeString(&d1, device);
            RtlInitUnicodeString(&d2, device2);
            if (!RtlEqualUnicodeString(&d1, &d2, TRUE)) {
                return STATUS_NOT_SAME_DEVICE;
            }
        }

        Entry->Kind = MYARK_REDIRECT_RULE_KIND_FILE;

        RedirUpcaseInto(Entry->SourceUc, MYARK_REDIRECT_RULE_CHARS, device, &chars);
        len = (SIZE_T)chars - 1;
        if (!RedirAppendDosRest(Entry->SourceUc, MYARK_REDIRECT_RULE_CHARS, &len,
                                Rule->Source, srcPrefix)) {
            return STATUS_INVALID_PARAMETER;
        }
        Entry->SourceChars = (UINT16)(len + 1);

        RedirUpcaseInto(Entry->TargetDeviceUc, MYARK_REDIRECT_RULE_CHARS, device, &chars);

        len = 0;
        if (!RedirAppendDosRest(Entry->AuxUc, MYARK_REDIRECT_RULE_CHARS, &len,
                                Rule->Target, tgtPrefix)) {
            return STATUS_INVALID_PARAMETER;
        }
        Entry->AuxChars = (UINT16)(len + 1);
        return STATUS_SUCCESS;
    }

    if (Rule->Kind == MYARK_REDIRECT_RULE_KIND_REG) {
        if (Rule->Source[0] != L'\\') {
            return STATUS_INVALID_PARAMETER;  // full NT key path required
        }
        if (Rule->Target[0] == L'\0' || Rule->Data[0] == L'\0') {
            return STATUS_INVALID_PARAMETER;  // value name + data required
        }
        Entry->Kind = MYARK_REDIRECT_RULE_KIND_REG;
        RedirUpcaseInto(Entry->SourceUc, MYARK_REDIRECT_RULE_CHARS, Rule->Source,
                        &Entry->SourceChars);
        RedirUpcaseInto(Entry->AuxUc, MYARK_REDIRECT_RULE_CHARS, Rule->Target,
                        &Entry->AuxChars);
        //
        // Value DATA preserves its original case (only paths/names are
        // uppercased for matching).
        //
        {
            SIZE_T dlen = wcsnlen(Rule->Data, MYARK_REDIRECT_RULE_CHARS - 1);

            RtlCopyMemory(Entry->DataW, Rule->Data, (dlen + 1) * sizeof(WCHAR));
            Entry->DataChars = (UINT16)(dlen + 1);
        }
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_PARAMETER;
}

NTSTATUS
MyArkRedirectStageRules(
    _In_ const MYARK_REDIRECT_RULE* Rules,
    _In_ UINT32 Count,
    _In_ UINT32 Flags)
{
    PMYARK_REDIRECT_RULE_ENTRY staged = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 i;

    if ((Flags & MYARK_REDIRECT_SET_FLAG_CLEAR_ALL) != 0) {
        Count = 0;  // explicit clear wins over any listed rules
    } else if (Count > MYARK_REDIRECT_MAX_RULES) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Count > 0) {
        staged = MyArkAllocatePool(NonPagedPoolNx,
                                   sizeof(MYARK_REDIRECT_RULE_ENTRY) * Count,
                                   RENG_POOL_TAG);
        if (staged == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(staged, sizeof(MYARK_REDIRECT_RULE_ENTRY) * Count);

        for (i = 0; i < Count; i++) {
            status = RedirStageOne(&staged[i], &Rules[i]);
            if (!NT_SUCCESS(status)) {
                ExFreePoolWithTag(staged, RENG_POOL_TAG);
                return status;
            }
        }
    }

    //
    // A prior un-committed stage would leak here; the IOCTL handler always
    // commits immediately after staging, so NULL is the expected state.
    //
    if (g_Staged != NULL) {
        ExFreePoolWithTag(g_Staged, RENG_POOL_TAG);
    }
    g_Staged = staged;
    g_StagedCount = Count;
    return STATUS_SUCCESS;
}

//
// Registers/unregisters the Cm callback to match the REG-rule state.
// Called with g_EngineMutex held (PASSIVE), rules lock RELEASED.
//
static
NTSTATUS
RedirEnsureCmCallback(
    _In_ BOOLEAN RegRulesArmed)
{
    NTSTATUS status;

    if (RegRulesArmed && g_CmState == 0) {
        UNICODE_STRING altitude = RTL_CONSTANT_STRING(REDIR_CM_ALTITUDE);

        if (g_MyArkCoreDriverObject == NULL) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        status = CmRegisterCallbackEx(MyArkRedirectCmCallback,
                                      &altitude,
                                      g_MyArkCoreDriverObject,
                                      NULL,
                                      &g_CmCookie,
                                      NULL);
        if (NT_SUCCESS(status)) {
            g_CmState = 1;
            return STATUS_SUCCESS;
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   MYARK_TRACE_REDIRECT "CmRegisterCallbackEx failed: 0x%08X\n",
                   status);
        return status;
    }

    if (!RegRulesArmed && g_CmState == 1) {
        status = CmUnRegisterCallback(g_CmCookie);
        if (NT_SUCCESS(status)) {
            g_CmState = 0;
            return STATUS_SUCCESS;
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   MYARK_TRACE_REDIRECT "CmUnRegisterCallback failed: 0x%08X\n",
                   status);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
MyArkRedirectCommitRules(
    _Out_ PUINT32 Accepted,
    _Out_ PUINT32 FileRules,
    _Out_ PUINT32 RegRules)
{
    UINT32 fileRules = 0;
    UINT32 regRules = 0;
    UINT32 i;
    KIRQL oldIrql;
    NTSTATUS waitStatus;
    NTSTATUS status;

    waitStatus = KeWaitForSingleObject(&g_EngineMutex,
                                       Executive,
                                       KernelMode,
                                       FALSE,
                                       NULL);
    if (!NT_SUCCESS(waitStatus)) {
        return waitStatus;
    }

    oldIrql = ExAcquireSpinLockExclusive(&g_RulesLock);

    if (g_Staged != NULL) {
        RtlCopyMemory(g_Rules, g_Staged,
                      sizeof(MYARK_REDIRECT_RULE_ENTRY) * g_StagedCount);
        g_RuleCount = g_StagedCount;
        ExFreePoolWithTag(g_Staged, RENG_POOL_TAG);
        g_Staged = NULL;
    } else {
        g_RuleCount = 0;
    }

    //
    // Hits reset with each arm/clear so verify assertions start from a
    // known counter state ("restore after close" returns to zero traffic).
    //
    g_FileHits = 0;
    g_RegHits = 0;
    g_PreCalls = 0;
    g_CtxAllocs = 0;

    for (i = 0; i < g_RuleCount; i++) {
        if (g_Rules[i].Kind == MYARK_REDIRECT_RULE_KIND_FILE) {
            fileRules++;
        } else {
            regRules++;
        }
    }

    ExReleaseSpinLockExclusive(&g_RulesLock, oldIrql);

    //
    // A failed Cm registration must surface to the caller (the REG rules
    // would otherwise arm silently without any callback to serve them).
    //
    status = RedirEnsureCmCallback(regRules > 0);

    KeReleaseMutex(&g_EngineMutex, FALSE);

    *Accepted = g_RuleCount;
    *FileRules = fileRules;
    *RegRules = regRules;
    return status;
}

VOID
MyArkRedirectEngineTeardown(
    VOID)
{
    KIRQL oldIrql;

    KeWaitForSingleObject(&g_EngineMutex, Executive, KernelMode, FALSE, NULL);

    oldIrql = ExAcquireSpinLockExclusive(&g_RulesLock);
    g_RuleCount = 0;
    g_FileHits = 0;
    g_RegHits = 0;
    ExReleaseSpinLockExclusive(&g_RulesLock, oldIrql);

    RedirEnsureCmCallback(FALSE);

    KeReleaseMutex(&g_EngineMutex, FALSE);

    if (g_Staged != NULL) {
        ExFreePoolWithTag(g_Staged, RENG_POOL_TAG);
        g_Staged = NULL;
    }
    g_StagedCount = 0;
}

VOID
MyArkRedirectEngineInit(
    VOID)
{
    KeInitializeMutex(&g_EngineMutex, 0);
    g_RuleCount = 0;
    g_FileHits = 0;
    g_RegHits = 0;
    g_CmState = 0;
    g_Staged = NULL;
    g_StagedCount = 0;
}

VOID
MyArkRedirectQueryStatus(
    _Out_ PMYARK_REDIRECT_STATUS_OUTPUT Output)
{
    KIRQL oldIrql;
    UINT32 i;

    RtlZeroMemory(Output, sizeof(*Output));

    oldIrql = ExAcquireSpinLockShared(&g_RulesLock);
    Output->Status = (UINT32)STATUS_SUCCESS;
    for (i = 0; i < g_RuleCount; i++) {
        if (g_Rules[i].Kind == MYARK_REDIRECT_RULE_KIND_FILE) {
            Output->FileRules++;
        } else {
            Output->RegRules++;
        }
    }
    Output->FileHits = (UINT32)g_FileHits;
    Output->RegHits = (UINT32)g_RegHits;
    Output->CmRegistered = (g_CmState == 1) ? 1u : 0u;
    Output->Reserved1 = (UINT32)g_PreCalls;   // diagnostic: pre-callback entries
    Output->Reserved2 = (UINT32)g_CtxAllocs;  // diagnostic: contexts parked
    ExReleaseSpinLockShared(&g_RulesLock, oldIrql);
}

// ---------------------------------------------------------------------------
// FILE side: IRP_MJ_CREATE pre-op (called from the R2-7 minifilter).
// ---------------------------------------------------------------------------

FLT_PREOP_CALLBACK_STATUS
MyArkRedirectFilePreCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    WCHAR relCopy[MYARK_REDIRECT_RULE_CHARS];
    USHORT relBytes = 0;
    UINT32 i;
    BOOLEAN matched = FALSE;
    KIRQL oldIrql;

    //
    // Lock-free fast path: no rules armed means no work for any create on
    // the system. Benign against a concurrent commit (worst case a create
    // just misses the newest rule).
    //
    if (g_RuleCount == 0) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    if (FltObjects == NULL || FltObjects->FileObject == NULL) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    if (!NT_SUCCESS(FltGetFileNameInformation(Data,
                                             FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
                                             &nameInfo))) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    if (!NT_SUCCESS(FltParseFileNameInformation(nameInfo))) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    //
    // Match under the shared lock, copying the hit's target into a stack
    // buffer; the pool allocation for the replacement name happens after
    // release (EX_SPIN_LOCK acquires raise IRQL).
    //
    oldIrql = ExAcquireSpinLockShared(&g_RulesLock);
    for (i = 0; i < g_RuleCount; i++) {
        PMYARK_REDIRECT_RULE_ENTRY entry = &g_Rules[i];

        if (entry->Kind != MYARK_REDIRECT_RULE_KIND_FILE) {
            continue;
        }
        if (!RedirSamePath(&nameInfo->Name, entry->SourceUc)) {
            continue;
        }
        relBytes = (USHORT)((entry->AuxChars - 1) * sizeof(WCHAR));
        RtlCopyMemory(relCopy, entry->AuxUc, entry->AuxChars * sizeof(WCHAR));
        matched = TRUE;
        break;
    }
    ExReleaseSpinLockShared(&g_RulesLock, oldIrql);

    if (matched) {
        PUNICODE_STRING newName;

        newName = (PUNICODE_STRING)MyArkAllocatePool(
            PagedPool, sizeof(UNICODE_STRING) + (SIZE_T)relBytes + sizeof(WCHAR),
            RENG_POOL_TAG);
        if (newName != NULL) {
            newName->Buffer = (PWCHAR)(newName + 1);
            newName->Length = relBytes;
            newName->MaximumLength = (USHORT)(relBytes + sizeof(WCHAR));
            RtlCopyMemory(newName->Buffer, relCopy, (SIZE_T)relBytes + sizeof(WCHAR));

            //
            // Swap the create target to the shadow path (volume-relative).
            // The replaced FileName buffer belongs to the object manager's
            // name capture; it is deliberately left in place (leak bounded
            // by rule hits, test-gated surface).
            //
            FltObjects->FileObject->FileName = *newName;
            //
            // The whole block (struct + buffer) must stay alive: the file
            // object's new Buffer points INSIDE it. Freed never -- the leak
            // is bounded by rule hits (documented model, shared with the
            // replaced object-manager buffer).
            //
            InterlockedIncrement(&g_FileHits);
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// ---------------------------------------------------------------------------
// REG side: CmCallback around NtQueryValueKey, registered only while REG
// rules are armed.
// ---------------------------------------------------------------------------

static
VOID
RedirQueryPre(
    _In_ PREG_QUERY_VALUE_KEY_INFORMATION Info)
{
    UCHAR rootBuf[sizeof(UNICODE_STRING) + 384 * sizeof(WCHAR)];
    PUNICODE_STRING rootUs;
    WCHAR keyPath[MYARK_REDIRECT_RULE_CHARS];
    ULONG returned = 0;
    SIZE_T rootChars, k, nameChars;
    BOOLEAN matched = FALSE;
    UINT32 i;
    KIRQL oldIrql;
    PMYARK_REDIRECT_QUERY_CTX ctx;
    NTSTATUS status;

    //
    // Fast gate: only Partial/Full carry the {Type, DataLength, Data}
    // prefix this engine rewrites.
    //
    if (Info->KeyValueInformationClass != KeyValuePartialInformation &&
        Info->KeyValueInformationClass != KeyValueFullInformation) {
        return;
    }
    if (Info->KeyValueInformation == NULL || Info->ResultLength == NULL ||
        Info->ValueName == NULL || Info->Object == NULL) {
        return;
    }
    InterlockedIncrement(&g_PreCalls);

    rootUs = (PUNICODE_STRING)rootBuf;
    status = ObQueryNameString(Info->Object,
                               (POBJECT_NAME_INFORMATION)rootBuf,
                               sizeof(rootBuf),
                               &returned);
    if (!NT_SUCCESS(status) || rootUs->Length == 0 ||
        rootUs->Length / sizeof(WCHAR) >= RTL_NUMBER_OF(keyPath)) {
        return;
    }

    //
    // The queried object IS the key: its full path comes straight from the
    // object name; uppercase in place for rule matching.
    //
    rootChars = rootUs->Length / sizeof(WCHAR);
    RtlCopyMemory(keyPath, rootUs->Buffer, rootUs->Length);
    for (k = 0; k < rootChars; k++) {
        keyPath[k] = RtlUpcaseUnicodeChar(keyPath[k]);
    }
    keyPath[rootChars] = L'\0';

    //
    // Match under the shared lock; copy the shadow data out (stack), then
    // allocate the post-callback context after release.
    //
    {
        UNICODE_STRING keyUs;

        RtlInitUnicodeString(&keyUs, keyPath);
        oldIrql = ExAcquireSpinLockShared(&g_RulesLock);
        for (i = 0; i < g_RuleCount; i++) {
            PMYARK_REDIRECT_RULE_ENTRY entry = &g_Rules[i];

            if (entry->Kind != MYARK_REDIRECT_RULE_KIND_REG ||
                !RedirSamePath(&keyUs, entry->SourceUc)) {
                continue;
            }
            nameChars = (SIZE_T)entry->AuxChars - 1;
            if (Info->ValueName->Length / sizeof(WCHAR) != nameChars ||
                _wcsnicmp(Info->ValueName->Buffer, entry->AuxUc, nameChars) != 0) {
                continue;
            }
            matched = TRUE;
            break;
        }
        if (matched) {
            RtlCopyMemory(keyPath + 0, g_Rules[i].DataW,
                          g_Rules[i].DataChars * sizeof(WCHAR));
        }
        ExReleaseSpinLockShared(&g_RulesLock, oldIrql);
    }
    if (!matched) {
        return;
    }

    ctx = (PMYARK_REDIRECT_QUERY_CTX)MyArkAllocatePool(
        PagedPool, sizeof(MYARK_REDIRECT_QUERY_CTX), RENG_POOL_TAG);
    if (ctx == NULL) {
        return;
    }
    ctx->KeyValueInformation = Info->KeyValueInformation;
    ctx->ResultLength = Info->ResultLength;
    ctx->BufferLength = Info->Length;
    ctx->Class = (ULONG)Info->KeyValueInformationClass;
    //
    // REG_SZ payload convention: DataLength includes the terminating NUL.
    //
    ctx->DataBytes = (ULONG)((wcsnlen(keyPath, MYARK_REDIRECT_RULE_CHARS - 1) + 1)
                             * sizeof(WCHAR));
    RtlCopyMemory(ctx->Data, keyPath, ctx->DataBytes);

    InterlockedIncrement(&g_CtxAllocs);
    Info->CallContext = ctx;  // rewritten + freed in the post callback
}

NTSTATUS
MyArkRedirectCmCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID NotificationClassRaw,
    _In_ PVOID Argument2)
{
    REG_NOTIFY_CLASS notificationClass = (REG_NOTIFY_CLASS)(ULONG_PTR)NotificationClassRaw;

    UNREFERENCED_PARAMETER(CallbackContext);

    switch (notificationClass) {
    case RegNtPreQueryValueKey:
        //
        // The armed-rules gate is pre-side only: the post side must always
        // handle its CallContext (rules can be cleared between a matched
        // pre and its paired post -- commit/teardown zero the count before
        // CmUnregisterCallback drains in-flight callbacks).
        //
        if (g_RuleCount != 0) {
            RedirQueryPre((PREG_QUERY_VALUE_KEY_INFORMATION)Argument2);
        }
        break;

    case RegNtPostQueryValueKey: {
        PREG_POST_OPERATION_INFORMATION post = (PREG_POST_OPERATION_INFORMATION)Argument2;
        PMYARK_REDIRECT_QUERY_CTX ctx;
        PKEY_VALUE_PARTIAL_INFORMATION partial;
        PKEY_VALUE_FULL_INFORMATION full;

        if (post == NULL || post->CallContext == NULL) {
            break;
        }
        ctx = (PMYARK_REDIRECT_QUERY_CTX)post->CallContext;

        if (NT_SUCCESS(post->Status)) {
            if (ctx->Class == (ULONG)KeyValuePartialInformation) {
                partial = (PKEY_VALUE_PARTIAL_INFORMATION)ctx->KeyValueInformation;
                if (ctx->DataBytes + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)
                    <= (ULONG)ctx->BufferLength) {
                    partial->Type = REG_SZ;
                    partial->DataLength = ctx->DataBytes;
                    RtlCopyMemory(partial->Data, ctx->Data, ctx->DataBytes);
                    *ctx->ResultLength =
                        FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + ctx->DataBytes;
                    InterlockedIncrement(&g_RegHits);
                } else {
                    //
                    // Shadow data does not fit the caller's buffer (sized
                    // after the original value): report the required size so
                    // the caller reallocates and retries.
                    //
                    *ctx->ResultLength =
                        FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + ctx->DataBytes;
                    post->ReturnStatus = STATUS_BUFFER_OVERFLOW;
                }
            } else {
                full = (PKEY_VALUE_FULL_INFORMATION)ctx->KeyValueInformation;
                if (ctx->DataBytes + full->DataOffset <= (ULONG)ctx->BufferLength) {
                    full->Type = REG_SZ;
                    full->DataLength = ctx->DataBytes;
                    RtlCopyMemory((PUCHAR)full + full->DataOffset, ctx->Data, ctx->DataBytes);
                    *ctx->ResultLength = full->DataOffset + ctx->DataBytes;
                    InterlockedIncrement(&g_RegHits);
                } else {
                    *ctx->ResultLength = full->DataOffset + ctx->DataBytes;
                    post->ReturnStatus = STATUS_BUFFER_OVERFLOW;
                }
            }
        }

        //
        // The paired free runs unconditionally -- even when the rules were
        // cleared between pre and post (P1-1).
        //
        ExFreePoolWithTag(ctx, RENG_POOL_TAG);
        post->CallContext = NULL;
        break;
    }

    default:
        break;
    }

    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_REDIRECT
