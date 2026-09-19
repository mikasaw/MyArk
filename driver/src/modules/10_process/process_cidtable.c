// process R0: PspCidTable full-table walk (R3-4).
//
// PspCidTable is the kernel's CID handle table -- every process and
// thread with a live PID/TID has an entry here, INCLUDING processes
// hidden from EPROCESS.ActiveProcessLinks by DKOM (unlinking does not
// remove the CID entry: Terminate/Open by ID would break). This file
// walks the table, decodes the packed entries, splits process/thread
// rows by ObGetObjectType (exported, resolves through the header's
// ObjectType pointer -- no per-build type constants), and joins the
// process rows against the ActiveProcessLinks membership set to flag
// hidden processes.
//
// Tier C build profile (KDNET-verified 2026-09-17, see
// tests/CRASH_DEBUG_LOG.md): entry decode and OBJECT_HEADER offsets are
// identical on 18362 and 22621; only the PspCidTable nt offset and the
// ImageFileName offset differ.
//
// All target reads go through MmIsAddressValid-gated probes; a corrupt
// table degrades to fewer rows / a clean stop, never a fault.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "process_descriptor.h"
#include "process_internal.h"
#include "process_offsets.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../../shared/driver/MyArkProcessIoctl.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"

#if MYARK_MODULE_PROCESS

// Declared in ntifs.h (not pulled into this translation unit); documented
// NTSYSAPI export since Vista.
NTSYSAPI
ULONG64
NTAPI
RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID* BaseOfImage);

NTSYSAPI
PVOID
NTAPI
ObGetObjectType(_In_ PVOID Object);

#define MYARK_CID_POOL_TAG 'DICT'

//
// Tier C: PspCidTable nt-relative offsets (KDNET-verified).
//
typedef struct _MYARK_CID_PROFILE {
    ULONG BuildMin;
    ULONG BuildMax;
    ULONG PspCidTable;         // nt data offset of the PHANDLE_TABLE
    ULONG ImageFileName;       // EPROCESS.ImageFileName
    ULONG DirectoryPages;      // non-null pages in the level-1 directory
} MYARK_CID_PROFILE;

static const MYARK_CID_PROFILE g_MyArkCidProfiles[] = {
    { 18362, 18363, 0x574530UL, 0x450UL, 64UL },
    { 22621, 22631, 0xD1EC30UL, 0x5A8UL, 64UL },
};

//
// Build-stable constants (asserted live on 18362 + 22621).
//
#define MYARK_CID_HT_TABLECODE        0x08UL
#define MYARK_CID_ENTRY_STRIDE        16UL
#define MYARK_CID_KERNEL_PREFIX       0xFFFF000000000000ULL
#define MYARK_CID_MAX_INDEX           65536UL   // 256K CIDs
#define MYARK_CID_ACTIVE_CAP          8192UL    // membership set capacity
//
// Level-1 page geometry: a table page is 0x1000 bytes and one
// HANDLE_TABLE_ENTRY is 16 bytes on these builds -> 256 entries per
// page. The first cut used 512 (8-byte assumption) and read chunk
// N+1's entries for chunk N -- valid-looking objects at wrong CIDs.
//
#define MYARK_CID_PAGE_ENTRIES        256UL     // 0x1000 / 16

static BOOLEAN MyArkCidReadU8(_In_ UINT64 Address, _Out_ UINT8* ValueOut)
{
    if (Address == 0 || !MmIsAddressValid((PVOID)(UINT_PTR)Address)) {
        return FALSE;
    }
    *ValueOut = *(PUCHAR)(UINT_PTR)Address;
    return TRUE;
}

static BOOLEAN MyArkCidReadU64(_In_ UINT64 Address, _Out_ UINT64* ValueOut)
{
    if (Address == 0
        || !MmIsAddressValid((PVOID)(UINT_PTR)Address)
        || !MmIsAddressValid((PVOID)(UINT_PTR)(Address + 7))) {
        return FALSE;
    }
    *ValueOut = *(PUINT64)(UINT_PTR)Address;
    return TRUE;
}

//
// ntoskrnl image base via PC-to-module lookup of an exported routine.
//
static BOOLEAN MyArkCidResolveNtBase(_Out_ UINT64* BaseOut)
{
    UNICODE_STRING name;
    PVOID routine = NULL;
    PVOID base = NULL;

    RtlInitUnicodeString(&name, L"NtCreateFile");
    routine = MmGetSystemRoutineAddress(&name);
    if (routine == NULL) {
        return FALSE;
    }
    if (RtlPcToFileHeader(routine, &base) == 0 || base == NULL) {
        return FALSE;
    }
    *BaseOut = (UINT64)(UINT_PTR)base;
    return TRUE;
}

static const MYARK_CID_PROFILE* MyArkCidSelectProfile(ULONG Build)
{
    for (ULONG i = 0; i < RTL_NUMBER_OF(g_MyArkCidProfiles); i++) {
        if (Build >= g_MyArkCidProfiles[i].BuildMin
            && Build <= g_MyArkCidProfiles[i].BuildMax) {
            return &g_MyArkCidProfiles[i];
        }
    }
    return NULL;
}

NTSTATUS
MyArkProcessIoctlQueryCidTable(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS status;
    PVOID outBuf = NULL;
    SIZE_T outSize = 0;
    SIZE_T headSize = FIELD_OFFSET(MYARK_CID_QUERY_OUTPUT, Entries[0]);
    PMYARK_CID_QUERY_OUTPUT out;
    const MYARK_CID_PROFILE* profile = NULL;
    UINT64 ntBase = 0;
    UINT64 sysProc = 0;
    PVOID procObjectType = NULL;
    ULONG activeCount = 0;
    UINT64* activeSet = NULL;
    ULONG maxEntries;
    ULONG written = 0;
    ULONG threadTotal = 0;
    ULONG cidStatus = MYARK_CID_STATUS_OK;
    const MYARK_ARK_OFFSETS* offsets = NULL;
    ULONG linksOffset;
    ULONG build = 0;
    RTL_OSVERSIONINFOW info;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < headSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request, headSize, &outBuf, &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    out = (PMYARK_CID_QUERY_OUTPUT)outBuf;
    maxEntries = (ULONG)((outSize - headSize) / sizeof(MYARK_CID_ENTRY));
    RtlZeroMemory(outBuf, headSize);
    out->EntryStructSize = (UINT32)sizeof(MYARK_CID_ENTRY);

    RtlZeroMemory(&info, sizeof(info));
    info.dwOSVersionInfoSize = sizeof(info);
    if (!NT_SUCCESS(RtlGetVersion(&info))) {
        out->Status = MYARK_CID_STATUS_NO_PROFILE;
        *BytesReturned = headSize;
        return STATUS_SUCCESS;
    }
    build = info.dwBuildNumber;

    profile = MyArkCidSelectProfile(build);
    if (profile == NULL || !MyArkCidResolveNtBase(&ntBase)) {
        out->Status = MYARK_CID_STATUS_NO_PROFILE;
        *BytesReturned = headSize;
        return STATUS_SUCCESS;
    }

    //
    // Process OBJECT_TYPE, derived at runtime via ObGetObjectType on the
    // exported System EPROCESS -- no per-build type index constants.
    //
    sysProc = (UINT64)(UINT_PTR)PsInitialSystemProcess;
    if (sysProc == 0) {
        out->Status = MYARK_CID_STATUS_NO_PROFILE;
        *BytesReturned = headSize;
        return STATUS_SUCCESS;
    }
    procObjectType = ObGetObjectType((PVOID)(UINT_PTR)sysProc);
    if (procObjectType == NULL) {
        out->Status = MYARK_CID_STATUS_NO_PROFILE;
        *BytesReturned = headSize;
        return STATUS_SUCCESS;
    }

    //
    // Membership set: every EPROCESS reachable through ActiveProcessLinks
    // (source A). The walk follows Flink pointers from the System seed;
    // each Flink lands on the NEXT process's ActiveProcessLinks field, so
    // EPROCESS = FlinkAddress - linksOffset. System itself is included.
    // Pool-backed, freed on exit. membershipWalkOk gates the HIDDEN flag
    // so a failed walk can't mislabel every visible process as hidden.
    //
    BOOLEAN membershipWalkOk = FALSE;
    activeSet = (UINT64*)MyArkAllocatePool(NonPagedPoolNx,
                                           MYARK_CID_ACTIVE_CAP * sizeof(UINT64),
                                           MYARK_CID_POOL_TAG);
    if (activeSet != NULL) {
        offsets = MyArkArkOffsetsGet();
        if (offsets != NULL && offsets->Valid && sysProc != 0) {
            linksOffset = offsets->ActiveProcessLinks;
            activeSet[activeCount++] = sysProc;

            UINT64 cur = sysProc + linksOffset;   // &System->ActiveProcessLinks
            ULONG guard = 4096;
            while (guard > 0 && activeCount < MYARK_CID_ACTIVE_CAP) {
                UINT64 flink;
                guard--;
                if (!MyArkCidReadU64(cur, &flink)
                    || flink == 0
                    || (flink & MYARK_CID_KERNEL_PREFIX) != MYARK_CID_KERNEL_PREFIX) {
                    break;
                }
                UINT64 eproc = flink - linksOffset;
                if (eproc == sysProc) {
                    break;                       // wrapped the circle
                }
                activeSet[activeCount++] = eproc;
                cur = flink;                     // next LIST_ENTRY address
            }
            membershipWalkOk = TRUE;
        }
    }

    if (!membershipWalkOk) {
        cidStatus = MYARK_CID_STATUS_NO_ACTIVE_WALK;    // rows keep flowing
    }

    //
    // Walk the CID table (source B).
    //
    {
        UINT64 ht = 0;
        UINT64 tableCode = 0;
        ULONG level = 0;
        UINT64 dir = 0;

        if (!MyArkCidReadU64(ntBase + profile->PspCidTable, &ht) || ht == 0
            || !MyArkCidReadU64(ht + MYARK_CID_HT_TABLECODE, &tableCode)
            || tableCode == 0) {
            if (activeSet != NULL) {
                ExFreePoolWithTag(activeSet, MYARK_CID_POOL_TAG);
            }
            out->Status = MYARK_CID_STATUS_NO_PROFILE;
            *BytesReturned = headSize;
            return STATUS_SUCCESS;
        }

        level = (ULONG)(tableCode & 3);
        dir = tableCode & ~3ULL;

        if (level >= 2) {
            // Level 2 (dir of dirs): not present on any supported build.
            if (activeSet != NULL) {
                ExFreePoolWithTag(activeSet, MYARK_CID_POOL_TAG);
            }
            out->Status = MYARK_CID_STATUS_NO_PROFILE;
            *BytesReturned = headSize;
            return STATUS_SUCCESS;
        }

        ULONG dirPages = (level == 0) ? 1 : profile->DirectoryPages;
        ULONG entriesPerPage = MYARK_CID_PAGE_ENTRIES;   // 0x1000 / 16, both levels

        for (ULONG chunk = 0; chunk < dirPages; chunk++) {
            UINT64 page = dir;
            if (level == 1) {
                UINT64 pagePtr = 0;
                if (!MyArkCidReadU64(dir + (UINT64)chunk * sizeof(UINT64),
                                     &pagePtr)
                    || pagePtr == 0) {
                    break;                       // no more table pages
                }
                page = pagePtr;
            }

            for (ULONG slot = 0; slot < entriesPerPage; slot++) {
                ULONG idx = chunk * entriesPerPage + slot;
                UINT64 entryAddr = page + (UINT64)slot * MYARK_CID_ENTRY_STRIDE;
                UINT64 entry = 0;
                UINT64 obj = 0;
                    UINT32 cid = (UINT32)(idx * 4);

                if (!MyArkCidReadU64(entryAddr, &entry) || entry == 0) {
                    continue;                    // free entry: skip
                }

                obj = (entry >> 16) | MYARK_CID_KERNEL_PREFIX;
                if ((obj & MYARK_CID_KERNEL_PREFIX) != MYARK_CID_KERNEL_PREFIX) {
                    continue;                    // non-canonical: skip
                }
                if (!MmIsAddressValid((PVOID)(UINT_PTR)obj)) {
                    continue;                    // stale/corrupt entry: skip
                }

                //
                // Type discrimination via exported ObGetObjectType: the
                // OBJECT_HEADER.TypeIndex byte may be per-build obfuscated
                // (encoded on some builds), but ObGetObjectType resolves
                // through the header's ObjectType pointer and is stable.
                //
                {
                    PVOID typeObj = ObGetObjectType((PVOID)(UINT_PTR)obj);
                    if (typeObj != procObjectType) {
                        threadTotal++;
                        continue;
                    }
                }

                //
                // Process row: emit + membership join (source A vs B).
                //
                if (written < maxEntries) {
                    PMYARK_CID_ENTRY row = &out->Entries[written];
                    BOOLEAN inActive = FALSE;
                    RtlZeroMemory(row, sizeof(*row));
                    row->Cid = cid;
                    row->Object = obj;
                    row->Flags = MYARK_CID_FLAG_PROCESS;
                    if (membershipWalkOk) {
                        for (ULONG i = 0; i < activeCount; i++) {
                            if (activeSet[i] == obj) {
                                inActive = TRUE;
                                break;
                            }
                        }
                        if (!inActive) {
                            row->Flags |= MYARK_CID_FLAG_HIDDEN;
                        }
                    }
                    {
                        CHAR name[MYARK_CID_NAME_MAX];
                        ULONG n = 0;
                        for (ULONG i = 0; i < MYARK_CID_NAME_MAX - 1; i++) {
                            UINT8 ch = 0;
                            if (!MyArkCidReadU8(obj + profile->ImageFileName + i,
                                                &ch) || ch == 0) {
                                break;
                            }
                            name[i] = (CHAR)ch;
                            n = i + 1;
                        }
                        for (ULONG i = 0; i < n; i++) {
                            row->Name[i] = name[i];
                        }
                        row->Name[MYARK_CID_NAME_MAX - 1] = 0;
                    }
                    written++;
                }
            }
        }
    }

    if (activeSet != NULL) {
        ExFreePoolWithTag(activeSet, MYARK_CID_POOL_TAG);
    }

    out->Count = written;
    out->Status = cidStatus;
    out->ThreadTotal = threadTotal;
    out->EntryStructSize = (UINT32)sizeof(MYARK_CID_ENTRY);
    *BytesReturned = (ULONG)(headSize + (SIZE_T)written * sizeof(MYARK_CID_ENTRY));
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_PROCESS
