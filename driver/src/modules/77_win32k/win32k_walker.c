// win32k walker (R3-10a): USER handle table enumeration.
//
// Reads the CALLER-process user32!gSharedInfo without touching any win32k
// internal offset:
//
//   PsGetProcessPeb -> Ldr.InLoadOrderModuleLinks -> user32.dll base
//       -> user32 export table -> "gSharedInfo" RVA
//       -> SHAREDINFO {psi, aheList, HeEntrySize}
//       -> HANDLEENTRY[] walk (32-byte records, type-field liveness)
//
// Every memory access goes through one guarded reader; any failure
// degrades to fewer rows / a diagnostic NTSTATUS, never a fault. The walk
// runs in the IOCTL caller's process context (KMDF queue, PASSIVE_LEVEL)
// so the caller's user VAs and its session's win32k space are visible.
// READ-ONLY probe.

#include "myark_config.h"
#include "win32k_internal.h"
#include "Trace.h"

#if MYARK_MODULE_WIN32K

//
// One guarded read for both user and session-space addresses. Caller
// context at PASSIVE_LEVEL makes the __try probe legal for user VAs.
//
static BOOLEAN MyArkWin32kRead(
    _In_ PVOID Address,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length)
{
    BOOLEAN ok = FALSE;

    __try {
        RtlCopyMemory(Buffer, Address, Length);
        ok = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
    return ok;
}

static BOOLEAN MyArkWin32kReadU16(_In_ PVOID Address, _Out_ UINT16* Value)
{
    return MyArkWin32kRead(Address, Value, sizeof(UINT16));
}

static BOOLEAN MyArkWin32kReadU32(_In_ PVOID Address, _Out_ UINT32* Value)
{
    return MyArkWin32kRead(Address, Value, sizeof(UINT32));
}

static BOOLEAN MyArkWin32kReadU64(_In_ PVOID Address, _Out_ UINT64* Value)
{
    return MyArkWin32kRead(Address, Value, sizeof(UINT64));
}

//
// Case-insensitive compare of a UTF-16 name (in caller user VA) against a
// fixed ASCII name, e.g. module base name "user32.dll".
//
static BOOLEAN MyArkWin32kNameEquals(
    _In_ PVOID NameBuffer,
    _In_ ULONG NameChars,
    _In_ PCSTR Ascii)
{
    WCHAR stack[32];
    ULONG i;

    if (NameChars == 0 || NameChars > 31) {
        return FALSE;
    }
    if (!MyArkWin32kRead(NameBuffer, stack, NameChars * sizeof(WCHAR))) {
        return FALSE;
    }
    for (i = 0; i < NameChars; i++) {
        WCHAR c = stack[i];
        WCHAR want = (WCHAR)(UCHAR)Ascii[i];
        if (c >= L'A' && c <= L'Z') {
            c = (WCHAR)(c + (L'a' - L'A'));
        }
        if (want >= L'A' && want <= L'Z') {
            want = (WCHAR)(want + (L'a' - L'A'));
        }
        if (c != want) {
            return FALSE;
        }
    }
    return Ascii[NameChars] == '\0';
}

//
// Locate the caller's user32.dll base from PEB->Ldr InLoadOrderModuleLinks.
//
static BOOLEAN MyArkWin32kFindUser32(_Out_ UINT64* User32Base)
{
    PVOID peb;
    UINT64 ldr = 0;
    UINT64 linkHead = 0;
    UINT64 node;
    ULONG steps;

    *User32Base = 0;
    peb = PsGetProcessPeb(PsGetCurrentProcess());
    if (peb == NULL) {
        return FALSE;
    }
    if (!MyArkWin32kReadU64((PVOID)((UINT64)(UINT_PTR)peb
                                    + MYARK_WIN32K_PEB_LDR_OFFSET),
                            &ldr)
        || ldr == 0) {
        return FALSE;
    }
    if (!MyArkWin32kReadU64(
            (PVOID)(ldr + MYARK_WIN32K_LDR_INLOADORDER_OFFSET),
            &linkHead)
        || linkHead == 0) {
        return FALSE;
    }

    node = linkHead;
    for (steps = 0; steps < 256; steps++) {
        UINT64 entry;
        UINT64 dllBase = 0;
        UINT64 nameBuf = 0;
        UINT16 nameLen = 0;

        if (!MyArkWin32kReadU64((PVOID)(UINT_PTR)node, &node)) {
            return FALSE;
        }
        if (node == 0 || node == linkHead) {
            break;
        }
        entry = node;

        if (!MyArkWin32kReadU64(
                (PVOID)(entry + MYARK_WIN32K_LDR_ENTRY_DLLBASE),
                &dllBase)
            || dllBase == 0) {
            continue;
        }
        if (!MyArkWin32kRead(
                (PVOID)(entry + MYARK_WIN32K_LDR_ENTRY_BASEDLLNAME),
                &nameLen, sizeof(nameLen))) {
            continue;
        }
        if (!MyArkWin32kRead(
                (PVOID)(entry + MYARK_WIN32K_LDR_ENTRY_BASEDLLNAME + 8),
                &nameBuf, sizeof(nameBuf))) {
            continue;
        }
        if (nameBuf == 0) {
            continue;
        }
        if (MyArkWin32kNameEquals((PVOID)(UINT_PTR)nameBuf,
                                  (ULONG)(nameLen / sizeof(WCHAR)),
                                  "user32.dll")) {
            *User32Base = dllBase;
            return TRUE;
        }
    }
    return FALSE;
}

//
// Walk user32's export table for the DATA export "gSharedInfo"; return its
// absolute VA. Linear name scan with a hard cap (user32 exports ~1.7k names).
//
static BOOLEAN MyArkWin32kResolveSharedInfo(
    _In_ UINT64 User32Base,
    _Out_ UINT64* SharedInfoVa)
{
    UINT32 eLfanew = 0;
    UINT32 signature = 0;
    UINT16 magic = 0;
    ULONG dataDirOffset;
    UINT32 exportRva = 0;
    UINT64 exportDir;
    UINT32 numberOfNames = 0;
    UINT32 addressOfNames = 0;
    UINT32 addressOfOrdinals = 0;
    UINT32 addressOfFunctions = 0;
    UINT32 i;

    *SharedInfoVa = 0;
    if (!MyArkWin32kReadU32((PVOID)(User32Base + 0x3C), &eLfanew)
        || eLfanew == 0 || eLfanew > 0x1000000) {
        return FALSE;
    }
    if (!MyArkWin32kReadU32((PVOID)(User32Base + eLfanew), &signature)
        || signature != 0x00004550UL) {          // 'PE\0\0'
        return FALSE;
    }
    if (!MyArkWin32kReadU16((PVOID)(User32Base + eLfanew + 24), &magic)) {
        return FALSE;
    }
    dataDirOffset = (magic == 0x20B) ? 112 : 96;
    if (!MyArkWin32kReadU32(
            (PVOID)(User32Base + eLfanew + 24 + dataDirOffset),
            &exportRva)
        || exportRva == 0) {
        return FALSE;
    }

    exportDir = User32Base + exportRva;
    if (!MyArkWin32kReadU32((PVOID)(exportDir + 0x18), &numberOfNames)
        || numberOfNames == 0 || numberOfNames > 0x10000) {
        return FALSE;
    }
    if (!MyArkWin32kReadU32((PVOID)(exportDir + 0x20), &addressOfNames)
        || !MyArkWin32kReadU32((PVOID)(exportDir + 0x24),
                               &addressOfOrdinals)
        || !MyArkWin32kReadU32((PVOID)(exportDir + 0x1C),
                               &addressOfFunctions)) {
        return FALSE;
    }

    for (i = 0; i < numberOfNames; i++) {
        UINT32 nameRva = 0;
        UINT32 ordinalIndex = 0;
        UINT32 functionRva = 0;
        CHAR name[16];

        if (!MyArkWin32kReadU32(
                (PVOID)(User32Base + addressOfNames + (UINT64)i * 4),
                &nameRva)
            || nameRva == 0) {
            continue;
        }
        if (!MyArkWin32kRead((PVOID)(User32Base + nameRva),
                             name, sizeof(name))) {
            continue;
        }
        name[15] = '\0';
        if (strcmp(name, "gSharedInfo") != 0) {
            continue;
        }
        if (!MyArkWin32kReadU32(
                (PVOID)(User32Base + addressOfOrdinals + (UINT64)i * 2),
                &ordinalIndex)) {
            return FALSE;
        }
        ordinalIndex &= 0xFFFF;
        if (!MyArkWin32kReadU32(
                (PVOID)(User32Base + addressOfFunctions
                        + (UINT64)ordinalIndex * 4),
                &functionRva)
            || functionRva == 0) {
            return FALSE;
        }
        *SharedInfoVa = User32Base + functionRva;
        return TRUE;
    }
    return FALSE;
}

NTSTATUS
MyArkWin32kEnumUserHandles(
    _Out_ PMYARK_WIN32K_USER_HANDLES_OUTPUT Out,
    _In_  ULONG                             MaxEntries)
{
    NTSTATUS diag = STATUS_SUCCESS;
    UINT64 user32Base = 0;
    UINT64 sharedInfo = 0;
    UINT64 psi = 0;
    UINT64 aheList = 0;
    UINT32 heEntrySize = 0;
    ULONG index;
    ULONG freeRun = 0;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->HeEntrySize = 0;               // 0 = unknown until read

    if (!MyArkWin32kFindUser32(&user32Base) || user32Base == 0) {
        Out->DiagStatus = (UINT32)STATUS_NOT_FOUND;
        return STATUS_SUCCESS;
    }
    if (!MyArkWin32kResolveSharedInfo(user32Base, &sharedInfo)
        || sharedInfo == 0) {
        Out->DiagStatus = (UINT32)STATUS_NOT_FOUND;
        return STATUS_SUCCESS;
    }
    Out->SharedInfo = sharedInfo;

    // SHAREDINFO {psi @0x00, aheList @0x08, HeEntrySize @0x10}.
    if (!MyArkWin32kReadU64((PVOID)sharedInfo, &psi)
        || !MyArkWin32kReadU64((PVOID)(sharedInfo + 8), &aheList)
        || !MyArkWin32kReadU32((PVOID)(sharedInfo + 0x10), &heEntrySize)) {
        Out->DiagStatus = (UINT32)STATUS_ACCESS_VIOLATION;
        return STATUS_SUCCESS;
    }
    Out->AheList = aheList;
    Out->HeEntrySize = heEntrySize;
    if (psi == 0 || aheList == 0
        || (heEntrySize != 16 && heEntrySize != 24 && heEntrySize != 32)) {
        Out->DiagStatus = (UINT32)STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    for (index = 0; index < MYARK_WIN32K_HE_MAX_SLOTS; index++) {
        UCHAR raw[32];
        UINT64 head;
        UINT64 user;
        UINT32 type;
        UINT32 flags;

        if (!MyArkWin32kRead((PVOID)(aheList + (UINT64)index * heEntrySize),
                             raw, heEntrySize)) {
            diag = STATUS_ACCESS_VIOLATION;
            break;
        }

        if (heEntrySize >= 24) {
            // Calibrated on 1903/22631: USHORT type @24 (classic TYPE_*
            // numbering, e.g. 8 = accelerator table, confirmed by
            // create/destroy diff), USHORT unique/generation @26, the
            // kernel pointer field @0 is masked to 0 in the user-mapped
            // copy and a freed slot can retain stale gen bytes at 26 --
            // liveness MUST test the type field, not any-nonzero.
            type = *(UINT16*)(raw + 24);
            flags = *(UINT16*)(raw + 26);
        } else {
            type = *(UINT16*)(raw + 12);
            flags = *(UINT16*)(raw + 14);
        }

        if (type == 0 || type > 0x40) {
            freeRun++;
            if (freeRun >= MYARK_WIN32K_HE_FREE_TAIL) {
                break;      // free tail = table end
            }
            continue;
        }
        freeRun = 0;

        if (Out->Count >= MaxEntries) {
            Out->Truncated = 1;
            continue;       // keep scanning for the free tail anyway
        }

        head = *(UINT64*)(raw + 0);
        user = *(UINT64*)(raw + 8);

        Out->Entries[Out->Count].Index = index;
        Out->Entries[Out->Count].Type = type;
        Out->Entries[Out->Count].Flags = flags;
        Out->Entries[Out->Count].Reserved = 0;
        Out->Entries[Out->Count].KernelObject = head;
        Out->Entries[Out->Count].UserPointer = user;
        Out->Count += 1;
    }

    Out->ScannedSlots = index;  // slots scanned before stop (diag)
    Out->DiagStatus = (UINT32)diag;
    // The user-mapped aheList region ends on a page boundary before the
    // free-tail heuristic can fire; a read fault after we already have
    // rows IS the clean table end, not a failure.
    if (diag == STATUS_ACCESS_VIOLATION && Out->Count > 0) {
        Out->DiagStatus = (UINT32)STATUS_SUCCESS;
    }
    // Walk failures are reported in-band via DiagStatus (rows stay valid);
    // a failing NTSTATUS here would only hide the partial data.
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_WIN32K
