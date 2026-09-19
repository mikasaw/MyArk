// MyArk kernel module: ENUM_IAT_EAT_HOOKS (R2-2, read-only).
//
// Attaches to the target process, parses the PE headers at ModuleBase and
// walks the export table (EAT) and the import address table (IAT):
//   EAT -- an AddressOfFunctions entry whose RVA leaves the image (or is
//          >= SizeOfImage) is a patched export. RVAs inside the export
//          directory itself are forwarder strings, not hooks.
//   IAT -- a resolved FirstThunk entry whose target is NOT image-backed
//          (ZwQueryVirtualMemory reports MEM_PRIVATE) is a hook candidate;
//          NULL slots (delay-load leftovers) are skipped entirely.
// Only hook candidates are emitted; every walked entry feeds the totals so
// R3 can distinguish "clean table" from "did not walk".
//
// Safety: all target reads go through MmCopyMemory (fault-tolerant for
// user pages, protected-process pages simply read-fail and shrink the
// totals); PASSIVE_LEVEL is guaranteed by the sequential queue. The
// process reference is released on every path.

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkKernelIoctl.h"
#include "kernel_descriptor.h"
#include "kernel_internal.h"

#if MYARK_MODULE_KERNEL

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif

// wdm.h defines some but not all winnt memory-type constants; fill the gap.
#ifndef MEM_PRIVATE
#define MEM_PRIVATE 0x20000
#endif
#ifndef MEM_MAPPED
#define MEM_MAPPED  0x40000
#endif
#ifndef MEM_IMAGE
#define MEM_IMAGE   0x1000000
#endif

//
// Fault-tolerant read of Size bytes from the (attached) target address
// space. MmCopyMemory in the attached context resolves user VAs against
// the target process and never raises.
//
static
BOOLEAN
MyArkIatEatRead(
    _In_ PVOID  Va,
    _Out_writes_bytes_(Size) PVOID Out,
    _In_ SIZE_T Size)
{
    MM_COPY_ADDRESS src;
    SIZE_T copied = 0;

    src.VirtualAddress = Va;
    NTSTATUS status = MmCopyMemory(Out, src, Size,
                                   MM_COPY_MEMORY_VIRTUAL, &copied);
    return NT_SUCCESS(status) && copied == Size;
}

//
// Minimal PE32/PE32+ header probe. Returns SizeOfImage and the two data
// directories the walk needs (EXPORT = 0, IAT = 12, IMPORT = 1).
//
typedef struct _MYARK_IATEAT_PE_INFO {
    UINT32 SizeOfImage;
    UINT32 ExportDirRva;
    UINT32 ExportDirSize;
    UINT32 ImportDirRva;
    UINT32 ImportDirSize;
} MYARK_IATEAT_PE_INFO, *PMYARK_IATEAT_PE_INFO;

static
NTSTATUS
MyArkIatEatParsePe(
    _In_ UINT64 Base,
    _Out_ PMYARK_IATEAT_PE_INFO Info)
{
    RtlZeroMemory(Info, sizeof(*Info));

    ULONG e_lfanew = 0;
    if (!MyArkIatEatRead((PVOID)(UINT_PTR)(Base + 0x3C),
                         &e_lfanew, sizeof(e_lfanew))
        || e_lfanew == 0 || e_lfanew > 0x1000000) {
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }

    ULONG signature = 0;
    if (!MyArkIatEatRead((PVOID)(UINT_PTR)(Base + e_lfanew),
                         &signature, sizeof(signature))
        || signature != 0x00004550UL) {  // 'PE\0\0'
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }

    UINT64 opt = Base + e_lfanew + 24;
    USHORT magic = 0;
    if (!MyArkIatEatRead((PVOID)(UINT_PTR)opt, &magic, sizeof(magic))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ULONG imageSize = 0;
    ULONG dataDirOffset;
    if (magic == 0x20B) {            // PE32+
        dataDirOffset = 112;
    } else if (magic == 0x10B) {     // PE32
        dataDirOffset = 96;
    } else {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (!MyArkIatEatRead((PVOID)(UINT_PTR)(opt + 56),
                         &imageSize, sizeof(imageSize))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ULONG dirs[4];  // [0]=export rva [1]=export size [2]=import rva [3]=import size
    if (!MyArkIatEatRead((PVOID)(UINT_PTR)(opt + dataDirOffset),
                         dirs, sizeof(dirs))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    Info->SizeOfImage = imageSize;
    Info->ExportDirRva = dirs[0];
    Info->ExportDirSize = dirs[1];
    Info->ImportDirRva = dirs[2];
    Info->ImportDirSize = dirs[3];
    if (imageSize == 0) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    return STATUS_SUCCESS;
}

//
// Emitted-entry sink shared by both walkers -- caps against MaxEntries
// and writes straight into the METHOD_BUFFERED output (kernel pool,
// unaffected by the process attach).
//
typedef struct _MYARK_IATEAT_SINK {
    PMYARK_KERNEL_IATEAT_ENTRY Entries;
    ULONG MaxEntries;
    ULONG Emitted;
    ULONG TotalHooks;
} MYARK_IATEAT_SINK, *PMYARK_IATEAT_SINK;

static
VOID
MyArkIatEatEmit(
    _In_ PMYARK_IATEAT_SINK Sink,
    _In_ UINT64 SlotVa,
    _In_ UINT64 CurrentTarget,
    _In_ UINT32 Kind)
{
    if (Sink->Emitted < Sink->MaxEntries) {
        PMYARK_KERNEL_IATEAT_ENTRY row = &Sink->Entries[Sink->Emitted];
        row->SlotVa = SlotVa;
        row->CurrentTarget = CurrentTarget;
        row->Kind = Kind;
        row->Reserved0 = 0;
        row->Reserved1 = 0;
        row->Reserved2 = 0;
        Sink->Emitted++;
    }
    Sink->TotalHooks++;
}

static
BOOLEAN
MyArkIatEatWalkEat(
    _In_ UINT64 Base,
    _In_ PMYARK_IATEAT_PE_INFO Pe,
    _Inout_ PMYARK_IATEAT_SINK Sink,
    _Out_ PULONG TotalEAT)
//
// Returns FALSE when the export array ended early (unreadable tail):
// totals are then partial and the caller must not report a clean walk.
//
{
    *TotalEAT = 0;
    if (Pe->ExportDirRva == 0 || Pe->ExportDirSize == 0) {
        return TRUE;
    }

    //
    // IMAGE_EXPORT_DIRECTORY: NumberOfFunctions at +0x14, AddressOfFunctions
    // at +0x1C.
    //
    ULONG dirFields[8];
    if (!MyArkIatEatRead((PVOID)(UINT_PTR)(Base + Pe->ExportDirRva),
                         dirFields, sizeof(dirFields))) {
        return FALSE;
    }
    ULONG numberOfFunctions = dirFields[5];       // +0x14
    ULONG addressOfFunctionsRva = dirFields[7];   // +0x1C
    if (numberOfFunctions == 0 || addressOfFunctionsRva == 0) {
        return TRUE;
    }
    if (numberOfFunctions > 0x100000) {           // sanity bound (1M funcs)
        numberOfFunctions = 0x100000;
    }

    for (ULONG i = 0; i < numberOfFunctions; i++) {
        ULONG funcRva = 0;
        if (!MyArkIatEatRead((PVOID)(UINT_PTR)(Base + addressOfFunctionsRva
                                               + (UINT64)i * sizeof(ULONG)),
                             &funcRva, sizeof(funcRva))) {
            return FALSE;  // unreadable array tail -- totals are partial
        }
        if (funcRva == 0) {
            continue;
        }
        (*TotalEAT)++;

        UINT64 funcVa = Base + funcRva;
        BOOLEAN forwarder = (funcRva >= Pe->ExportDirRva
                             && funcRva < Pe->ExportDirRva + Pe->ExportDirSize);
        if (!forwarder && (funcRva >= Pe->SizeOfImage)) {
            MyArkIatEatEmit(Sink, funcVa, funcVa, MYARK_KERNEL_IATEAT_KIND_EAT);
        }
    }
    return TRUE;
}

//
// Image-backed check for an IAT target. ZwQueryVirtualMemory is resolved
// once per boot; when unavailable the check answers "image-backed"
// (conservative: no hook candidate) so a missing export cannot silently
// manufacture findings.
//
static
BOOLEAN
MyArkIatEatTargetIsImageBacked(
    _In_ HANDLE ProcessHandle,
    _In_ UINT64 Target)
{
    static NTSTATUS (NTAPI *queryVm)(HANDLE, PVOID, LONG, PVOID, SIZE_T, PSIZE_T) = NULL;
    static BOOLEAN resolved = FALSE;

    if (!resolved) {
        queryVm = (NTSTATUS (NTAPI *)(HANDLE, PVOID, LONG, PVOID, SIZE_T, PSIZE_T))
            MmGetSystemRoutineAddress(
                &(UNICODE_STRING)RTL_CONSTANT_STRING(L"ZwQueryVirtualMemory"));
        resolved = TRUE;
    }
    if (queryVm == NULL) {
        return TRUE;
    }

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T returned = 0;
    NTSTATUS status = queryVm(ProcessHandle,
                              (PVOID)(UINT_PTR)Target,
                              0,                // MemoryBasicInformation
                              &mbi,
                              sizeof(mbi),
                              &returned);
    if (!NT_SUCCESS(status)) {
        return FALSE;   // unmapped target: hook candidate
    }
    return mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED;
}static
BOOLEAN
MyArkIatEatWalkIat(
    _In_ UINT64 Base,
    _In_ HANDLE ProcessHandle,
    _In_ PMYARK_IATEAT_PE_INFO Pe,
    _Inout_ PMYARK_IATEAT_SINK Sink,
    _Out_ PULONG TotalIAT)
//
// Same partial-walk contract as the EAT walker.
//
{
    *TotalIAT = 0;
    if (Pe->ImportDirRva == 0 || Pe->ImportDirSize == 0) {
        return TRUE;
    }

    //
    // IMAGE_IMPORT_DESCRIPTOR (20 B): OriginalFirstThunk / TimeDateStamp /
    // ForwarderChain / Name / FirstThunk. Terminated by an all-zero entry.
    //
    ULONG maxDescriptors = 4096;
    ULONG descRva = Pe->ImportDirRva;
    while (descRva != 0 && maxDescriptors-- > 0) {
        ULONG desc[5];
        if (!MyArkIatEatRead((PVOID)(UINT_PTR)(Base + descRva),
                             desc, sizeof(desc))) {
            return FALSE;
        }
        if (desc[0] == 0 && desc[3] == 0 && desc[4] == 0) {
            return TRUE;  // terminator
        }

        ULONG intRva = desc[0];
        ULONG iatRva = desc[4];
        ULONG maxThunks = 65536;
        while (intRva != 0 && iatRva != 0 && maxThunks-- > 0) {
            UINT64 intThunk = 0;
            UINT64 iatValue = 0;
            if (!MyArkIatEatRead((PVOID)(UINT_PTR)(Base + intRva),
                                 &intThunk, sizeof(intThunk))
                || !MyArkIatEatRead((PVOID)(UINT_PTR)(Base + iatRva),
                                    &iatValue, sizeof(iatValue))) {
                return FALSE;
            }
            if (intThunk == 0) {
                break;  // end of this descriptor's thunk arrays
            }

            if ((intThunk & 0x8000000000000000ULL) == 0 && iatValue != 0) {
                (*TotalIAT)++;
                UINT64 slotVa = Base + iatRva;
                if (!MyArkIatEatTargetIsImageBacked(ProcessHandle, iatValue)) {
                    MyArkIatEatEmit(Sink, slotVa, iatValue,
                                    MYARK_KERNEL_IATEAT_KIND_IAT);
                }
            }

            intRva += sizeof(UINT64);
            iatRva += sizeof(UINT64);
        }

        descRva += 20;  // sizeof(IMAGE_IMPORT_DESCRIPTOR)
    }
    return TRUE;
}

NTSTATUS
MyArkKernelIoctlEnumIatEat(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PMYARK_KERNEL_ENUM_IATEAT_INPUT inBuf = NULL;
    size_t inSize = 0;
    NTSTATUS status;

    if (InputBufferLength < sizeof(MYARK_KERNEL_ENUM_IATEAT_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_KERNEL_ENUM_IATEAT_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Snapshot inputs (METHOD_BUFFERED: the output zero would clobber).
    //
    UINT32 pid = inBuf->Pid;
    UINT32 flags = inBuf->Flags;
    UINT64 moduleBase = inBuf->ModuleBase;
    ULONG maxEntries = inBuf->MaxEntries;
    if (maxEntries == 0 || maxEntries > MYARK_KERNEL_IATEAT_HARD_CAP) {
        maxEntries = MYARK_KERNEL_IATEAT_DEFAULT_MAX;
        if (maxEntries > MYARK_KERNEL_IATEAT_HARD_CAP) {
            maxEntries = MYARK_KERNEL_IATEAT_HARD_CAP;
        }
    }
    {
        ULONG spaceForEntries = (ULONG)((OutputBufferLength
            - FIELD_OFFSET(MYARK_KERNEL_ENUM_IATEAT_OUTPUT, Entries))
            / sizeof(MYARK_KERNEL_IATEAT_ENTRY));
        if (spaceForEntries < maxEntries) {
            maxEntries = spaceForEntries;
        }
    }

    if ((flags & (MYARK_KERNEL_IATEAT_FLAG_EAT | MYARK_KERNEL_IATEAT_FLAG_IAT)) == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    //
    // Note: ModuleBase is expected to be a USER-mode image (ntdll.dll and
    // friends) -- no system-range check here, unlike the kernel-write
    // PATCH path. A garbage base is rejected by the PE parse (MZ/PE
    // signature + directory bounds), and MmCopyMemory makes every read
    // fault-tolerant.
    //

    //
    // Resolve the target process (0 = caller). Everything else happens in
    // its address space behind KeStackAttachProcess.
    //
    PEPROCESS process = NULL;
    if (pid == 0) {
        process = PsGetCurrentProcess();
        if (process != NULL) {
            ObReferenceObject(process);
        }
    } else {
        status = PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &process);
        if (!NT_SUCCESS(status)) {
            return STATUS_NOT_FOUND;
        }
    }
    if (process == NULL) {
        return STATUS_NOT_FOUND;
    }

    PMYARK_KERNEL_ENUM_IATEAT_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_KERNEL_ENUM_IATEAT_OUTPUT, Entries),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }

    ULONG totalEAT = 0;
    ULONG totalIAT = 0;
    BOOLEAN walkComplete = TRUE;
    MYARK_IATEAT_SINK sink;
    sink.Entries = outBuf->Entries;
    sink.MaxEntries = maxEntries;
    sink.Emitted = 0;
    sink.TotalHooks = 0;

    KAPC_STATE apcState;
    NTSTATUS walkStatus;

    KeStackAttachProcess(process, &apcState);

    MYARK_IATEAT_PE_INFO pe;
    walkStatus = MyArkIatEatParsePe(moduleBase, &pe);
    if (!NT_SUCCESS(walkStatus)) {
        //
        // Not a mapped PE at ModuleBase -- a hard parameter error, not a
        // partial result: detach and reject.
        //
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        return walkStatus;
    }

    if (flags & MYARK_KERNEL_IATEAT_FLAG_EAT) {
        walkComplete &= MyArkIatEatWalkEat(moduleBase, &pe, &sink, &totalEAT);
    }
    if (flags & MYARK_KERNEL_IATEAT_FLAG_IAT) {
        HANDLE processHandle = NULL;
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID cid;
        cid.UniqueProcess = (HANDLE)(UINT_PTR)pid;
        cid.UniqueThread = NULL;
        InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        if (pid == 0) {
            processHandle = NtCurrentProcess();
        } else if (!NT_SUCCESS(ZwOpenProcess(&processHandle,
                                             PROCESS_QUERY_INFORMATION,
                                             &oa, &cid))) {
            processHandle = NULL;
        }

        if (processHandle != NULL) {
            walkComplete &= MyArkIatEatWalkIat(moduleBase, processHandle,
                                               &pe, &sink, &totalIAT);
            if (processHandle != NtCurrentProcess()) {
                ZwClose(processHandle);
            }
        }
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    outBuf->Size = (UINT32)(FIELD_OFFSET(MYARK_KERNEL_ENUM_IATEAT_OUTPUT, Entries)
                            + sink.Emitted * sizeof(MYARK_KERNEL_IATEAT_ENTRY));
    outBuf->Status = walkComplete ? 0 : MYARK_KERNEL_IATEAT_STATUS_PARTIAL;
    outBuf->Count = sink.Emitted;
    outBuf->TotalHooks = sink.TotalHooks;
    outBuf->TotalEAT = totalEAT;
    outBuf->TotalIAT = totalIAT;
    outBuf->ModuleBase = moduleBase;
    outBuf->ImageSize = pe.SizeOfImage;
    outBuf->EntryStructSize = (UINT32)sizeof(MYARK_KERNEL_IATEAT_ENTRY);

    *BytesReturned = outBuf->Size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_KERNEL
