// MyArk memory module: hand-rolled x64 4-level page-table walker.
//
// Implements TRANSLATE_VA and QUERY_PT_ENTRY. Walks PML4 -> PDPT -> PD -> PT
// using CR3 (DirectoryTableBase) read from the target KPROCESS, with each
// table read wrapped in MmIsAddressValid so a stale pointer (e.g. an exited
// process) cannot blue-screen the VM.
//
// LA57 (5-level paging) is intentionally NOT supported: if CR4.LA57 is set
// on the current CPU, the walker returns STATUS_NOT_SUPPORTED. S7 will
// revisit this when DynData profiles it.
//
// Each table entry is mirrored into a MYARK_MEMORY_PT_ENTRY so the
// QUERY_PT_ENTRY output can render the entire translation chain in one
// buffer (useful for diagnosing large-page misuse, e.g. a 2MB PTE that
// shadows a private allocation the user expected to be 4K).

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "memory_module.h"

#if MYARK_MODULE_MEMORY

//
// Read a single 64-bit entry from a page table.
//
// Uses MmCopyMemory with MM_COPY_MEMORY_PHYSICAL, the documented way to read
// arbitrary physical memory. MmMapIoSpace (the previous approach) returned
// NULL for every page-table page on the test guest -- it refuses RAM pages
// on modern builds -- which silently produced PML4E=0 and a bogus
// STATUS_NOT_FOUND for every translate request. The copy is bounded to one
// entry, page-table PFNs are never written, and a failure leaves the entry
// zero (caller reports "not present") instead of faulting.
//
static
UINT64
MyArkMemoryReadTableEntrySafe(
    _In_ UINT64 TablePa,
    _In_ ULONG  Index)
{
    MM_COPY_ADDRESS source;
    UINT64          value   = 0;
    SIZE_T          copied  = 0;
    NTSTATUS        status;

    source.PhysicalAddress.QuadPart =
        (LONGLONG)(TablePa + (UINT64)(Index & 0x1FF) * sizeof(UINT64));

    status = MmCopyMemory(&value,
                          source,
                          sizeof(value),
                          MM_COPY_MEMORY_PHYSICAL,
                          &copied);
    if (!NT_SUCCESS(status) || copied != sizeof(value)) {
        return 0;
    }
    return value;
}


//
// Run the page-table walk for a single VA. `entries` must point to an
// array of at least 4 MYARK_MEMORY_PT_ENTRY slots. *Level is the deepest
// level reached (1..4), *Pa is the resulting physical address, *PageSize
// is the page size in bytes (4K / 2M / 1G) or 0 on failure.
//
// LA57 is rejected with STATUS_NOT_SUPPORTED so future DynData work has
// a single point to extend.
//
static
NTSTATUS
MyArkMemoryWalkPageTable(
    _In_ UINT64 Cr3,
    _In_ UINT64 Va,
    _Out_writes_(4) PMYARK_MEMORY_PT_ENTRY Entries,
    _Out_ PULONG Level,
    _Out_ PUINT64 Pa,
    _Out_ PUINT64 PageSize)
{
    ULONG   pml4eIndex;
    ULONG   pdpteIndex;
    ULONG   pdeIndex;
    ULONG   pteIndex;
    UINT64  pml4e;
    UINT64  pdpte;
    UINT64  pde;
    UINT64  pte;
    UINT64  currentTablePa = Cr3 & MYARK_PT_ADDR_MASK_48;
    UINT64  currentPa = 0;

    *Level = 0;
    *Pa = 0;
    *PageSize = 0;
    RtlZeroMemory(Entries, sizeof(MYARK_MEMORY_PT_ENTRY) * 4);

    //
    // LA57 gate. The 5-level paging bit is in CR4 and there is no clean
    // way to inspect it without reading CR4 directly; _ReadStatusReg /
    // __readcr4 are MSVC intrinsics that work in kernel mode.
    //
    UINT64 cr4 = (UINT64)__readcr4();
    if ((cr4 & MYARK_PT_CR4_LA57) != 0) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_MEMORY,
                    "MyArkMemoryWalkPageTable: LA57 (5-level paging) not supported (CR4=0x%llX)",
                    cr4);
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Sanity: Cr3 must be page-aligned and non-zero. MmMapIoSpace would
    // happily take any address but the resulting kernel VA is meaningless.
    //
    if ((Cr3 & 0xFFF) != 0 || Cr3 == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // PML4E (level 1). Index bits 47:39 of the VA. Entry points to the
    // PDPT physical address; bits 51:12 are the address, lower bits are
    // flags.
    //
    pml4eIndex = (ULONG)((Va >> MYARK_PT_PML4E_SHIFT) & 0x1FF);
    pml4e = MyArkMemoryReadTableEntrySafe(currentTablePa, pml4eIndex);
    Entries[0].Value        = pml4e;
    Entries[0].Level        = MYARK_MEMORY_PT_LEVEL_PML4;
    Entries[0].Pa           = pml4e & MYARK_PT_ADDR_MASK_48;
    Entries[0].NextTablePa  = Entries[0].Pa;
    Entries[0].Large        = 0;

    if ((pml4e & MYARK_PT_PTE_PRESENT) == 0) {
        *Level = MYARK_MEMORY_PT_LEVEL_PML4;
        return STATUS_NOT_FOUND;
    }
    currentTablePa = pml4e & MYARK_PT_ADDR_MASK_48;

    //
    // PDPTE (level 2). Index bits 38:30. If the PS bit is set, the
    // entry is a 1GB page and the walk stops here.
    //
    pdpteIndex = (ULONG)((Va >> MYARK_PT_PDPTE_SHIFT) & 0x1FF);
    pdpte = MyArkMemoryReadTableEntrySafe(currentTablePa, pdpteIndex);
    Entries[1].Value        = pdpte;
    Entries[1].Level        = MYARK_MEMORY_PT_LEVEL_PDPT;
    Entries[1].Pa           = pdpte & MYARK_PT_PTE_LARGE_MASK;  // 1G mask
    Entries[1].NextTablePa  = pdpte & MYARK_PT_ADDR_MASK_48;
    Entries[1].Large        = (UINT32)((pdpte & MYARK_PT_PTE_LARGE) != 0);

    if ((pdpte & MYARK_PT_PTE_PRESENT) == 0) {
        *Level = MYARK_MEMORY_PT_LEVEL_PDPT;
        return STATUS_NOT_FOUND;
    }
    if ((pdpte & MYARK_PT_PTE_LARGE) != 0) {
        //
        // 1GB page: physical address bits 51:30 combined with VA bits
        // 29:0 give the final PA.
        //
        *Level = MYARK_MEMORY_PT_LEVEL_PDPT;
        *Pa = (pdpte & MYARK_PT_PTE_LARGE_MASK) | (Va & 0x3FFFFFFFULL);
        *PageSize = MYARK_MEMORY_PAGE_SIZE_1G;
        return STATUS_SUCCESS;
    }
    currentTablePa = pdpte & MYARK_PT_ADDR_MASK_48;

    //
    // PDE (level 3). Index bits 29:21. PS=1 means 2MB page.
    //
    pdeIndex = (ULONG)((Va >> MYARK_PT_PDE_SHIFT) & 0x1FF);
    pde = MyArkMemoryReadTableEntrySafe(currentTablePa, pdeIndex);
    Entries[2].Value        = pde;
    Entries[2].Level        = MYARK_MEMORY_PT_LEVEL_PD;
    Entries[2].Pa           = pde & MYARK_PT_PTE_LARGE_MASK;   // 2MB mask
    Entries[2].NextTablePa  = pde & MYARK_PT_ADDR_MASK_48;
    Entries[2].Large        = (UINT32)((pde & MYARK_PT_PTE_LARGE) != 0);

    if ((pde & MYARK_PT_PTE_PRESENT) == 0) {
        *Level = MYARK_MEMORY_PT_LEVEL_PD;
        return STATUS_NOT_FOUND;
    }
    if ((pde & MYARK_PT_PTE_LARGE) != 0) {
        *Level = MYARK_MEMORY_PT_LEVEL_PD;
        *Pa = (pde & MYARK_PT_PTE_LARGE_MASK) | (Va & 0x1FFFFFULL);
        *PageSize = MYARK_MEMORY_PAGE_SIZE_2M;
        return STATUS_SUCCESS;
    }
    currentTablePa = pde & MYARK_PT_ADDR_MASK_48;

    //
    // PTE (level 4). Index bits 20:12. Final page-table level: PA bits
    // 51:12 plus VA bits 11:0.
    //
    pteIndex = (ULONG)((Va >> MYARK_PT_PTE_SHIFT) & 0x1FF);
    pte = MyArkMemoryReadTableEntrySafe(currentTablePa, pteIndex);
    Entries[3].Value        = pte;
    Entries[3].Level        = MYARK_MEMORY_PT_LEVEL_PT;
    Entries[3].Pa           = pte & MYARK_PT_ADDR_MASK_48;
    Entries[3].NextTablePa  = 0;
    Entries[3].Large        = 0;

    if ((pte & MYARK_PT_PTE_PRESENT) == 0) {
        *Level = MYARK_MEMORY_PT_LEVEL_PT;
        return STATUS_NOT_FOUND;
    }

    *Level = MYARK_MEMORY_PT_LEVEL_PT;
    *Pa = (pte & MYARK_PT_ADDR_MASK_48) | (Va & 0xFFFULL);
    *PageSize = MYARK_MEMORY_PAGE_SIZE_4K;
    UNREFERENCED_PARAMETER(currentPa);
    return STATUS_SUCCESS;
}


//
// IOCTL_MYARK_MEMORY_TRANSLATE_VA handler. Resolves the target PID to
// its EPROCESS (so we can read its DirectoryTableBase) and runs the page-
// table walk; on success returns the resulting physical address + page
// size, on failure returns the walker NTSTATUS.
//
NTSTATUS
MyArkMemoryIoctlTranslateVa(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_MEMORY_TRANSLATE_VA_INPUT  inBuf  = NULL;
    PMYARK_MEMORY_TRANSLATE_VA_OUTPUT outBuf = NULL;
    size_t                           inSize  = 0;
    PEPROCESS                         proc    = NULL;
    NTSTATUS                         status;
    UINT64                           cr3     = 0;
    MYARK_MEMORY_PT_ENTRY            entries[4];
    ULONG                            level   = 0;
    UINT64                           pa      = 0;
    UINT64                           pageSize = 0;

    UNREFERENCED_PARAMETER(Device);

    if (OutputBufferLength < sizeof(MYARK_MEMORY_TRANSLATE_VA_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (InputBufferLength < sizeof(MYARK_MEMORY_TRANSLATE_VA_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_MEMORY_TRANSLATE_VA_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // METHOD_BUFFERED shares one SystemBuffer: snapshot Pid / Va now, before
    // the output header is zeroed below (zeroing first wiped both fields).
    //
    const ULONG  pid = inBuf->Pid;
    const UINT64 va  = inBuf->Va;
    inBuf = NULL;

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_MEMORY_TRANSLATE_VA_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, sizeof(*outBuf));

    //
    // Special case: Pid == 0 (or 0xFFFFFFFF) means "walk the current
    // process's VA", i.e. use CR3 directly. Otherwise resolve the target
    // PID and read its DirectoryTableBase.
    //
    if (pid == 0 || pid == 0xFFFFFFFFUL) {
        cr3 = (UINT64)__readcr3();
    } else {
        status = PsLookupProcessByProcessId(UlongToHandle(pid), &proc);
        if (!NT_SUCCESS(status) || proc == NULL) {
            outBuf->Status = (UINT32)STATUS_NOT_FOUND;
            *BytesReturned = sizeof(*outBuf);
            return STATUS_SUCCESS;
        }
        //
        // DirectoryTableBase is a ULONG_PTR at MYARK_OFF_KPROCESS_DIRECTORY_TABLE_BASE
        // measured from the KPROCESS base (== EPROCESS.Pcb). MmIsAddressValid gates
        // the read so a stale EPROCESS doesn't crash us.
        //
        PVOID kproc = (PUCHAR)proc + MYARK_OFF_EPROCESS_PCB;
        if (!MmIsAddressValid((PUCHAR)kproc + MYARK_OFF_KPROCESS_DIRECTORY_TABLE_BASE)) {
            ObDereferenceObject(proc);
            outBuf->Status = (UINT32)STATUS_UNSUCCESSFUL;
            *BytesReturned = sizeof(*outBuf);
            return STATUS_SUCCESS;
        }
        cr3 = *(PULONG_PTR)((PUCHAR)kproc + MYARK_OFF_KPROCESS_DIRECTORY_TABLE_BASE);
        ObDereferenceObject(proc);
    }

    status = MyArkMemoryWalkPageTable(cr3,
                                      va,
                                      entries,
                                      &level,
                                      &pa,
                                      &pageSize);
    outBuf->Status   = (UINT32)status;
    outBuf->Pa       = pa;
    outBuf->PageSize = pageSize;

    *BytesReturned = sizeof(*outBuf);

    TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_MEMORY,
                "TranslateVa pid=%lu va=0x%llX -> pa=0x%llX page=%llu (status=0x%08X)",
                (unsigned long)pid,
                (unsigned long long)va,
                (unsigned long long)pa,
                (unsigned long long)pageSize,
                status);

    return STATUS_SUCCESS;
}


//
// IOCTL_MYARK_MEMORY_QUERY_PT_ENTRY handler. Returns all four page-table
// entries for one VA, plus the resolved PA / page size. Useful for
// diagnosing why a TRANSLATE_VA succeeded but the underlying PTE looked
// suspicious.
//
NTSTATUS
MyArkMemoryIoctlQueryPtEntry(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_MEMORY_QUERY_PT_ENTRY_INPUT  inBuf  = NULL;
    PMYARK_MEMORY_QUERY_PT_ENTRY_OUTPUT outBuf = NULL;
    size_t                              inSize  = 0;
    PEPROCESS                            proc    = NULL;
    NTSTATUS                            status;
    UINT64                              cr3     = 0;
    MYARK_MEMORY_PT_ENTRY               entries[4];
    ULONG                               level   = 0;
    UINT64                              pa      = 0;
    UINT64                              pageSize = 0;

    UNREFERENCED_PARAMETER(Device);

    if (OutputBufferLength < sizeof(MYARK_MEMORY_QUERY_PT_ENTRY_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (InputBufferLength < sizeof(MYARK_MEMORY_QUERY_PT_ENTRY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_MEMORY_QUERY_PT_ENTRY_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // METHOD_BUFFERED shares one SystemBuffer: snapshot Pid / Va now, before
    // the output header is zeroed below (zeroing first wiped both fields).
    //
    const ULONG  pid = inBuf->Pid;
    const UINT64 va  = inBuf->Va;
    inBuf = NULL;

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_MEMORY_QUERY_PT_ENTRY_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, sizeof(*outBuf));

    if (pid == 0 || pid == 0xFFFFFFFFUL) {
        cr3 = (UINT64)__readcr3();
    } else {
        status = PsLookupProcessByProcessId(UlongToHandle(pid), &proc);
        if (!NT_SUCCESS(status) || proc == NULL) {
            outBuf->Status = (UINT32)STATUS_NOT_FOUND;
            *BytesReturned = sizeof(*outBuf);
            return STATUS_SUCCESS;
        }
        PVOID kproc = (PUCHAR)proc + MYARK_OFF_EPROCESS_PCB;
        if (!MmIsAddressValid((PUCHAR)kproc + MYARK_OFF_KPROCESS_DIRECTORY_TABLE_BASE)) {
            ObDereferenceObject(proc);
            outBuf->Status = (UINT32)STATUS_UNSUCCESSFUL;
            *BytesReturned = sizeof(*outBuf);
            return STATUS_SUCCESS;
        }
        cr3 = *(PULONG_PTR)((PUCHAR)kproc + MYARK_OFF_KPROCESS_DIRECTORY_TABLE_BASE);
        ObDereferenceObject(proc);
    }

    status = MyArkMemoryWalkPageTable(cr3,
                                      va,
                                      entries,
                                      &level,
                                      &pa,
                                      &pageSize);

    outBuf->Status   = (UINT32)status;
    outBuf->Level    = level;
    outBuf->Pa       = pa;
    outBuf->PageSize = pageSize;
    RtlCopyMemory(outBuf->Entries,
                  entries,
                  sizeof(entries));

    *BytesReturned = sizeof(*outBuf);

    TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_MEMORY,
                "QueryPtEntry pid=%lu va=0x%llX -> level=%lu pa=0x%llX (status=0x%08X)",
                (unsigned long)pid,
                (unsigned long long)va,
                (unsigned long)level,
                (unsigned long long)pa,
                status);

    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_MEMORY