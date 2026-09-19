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
#include "../../../shared/driver/MyArkPoolAlloc.h"

#if MYARK_MODULE_WIN32K

//
// One guarded read for both user and session-space addresses. Caller
// context at PASSIVE_LEVEL makes the __try probe legal for user VAs.
//
//
// Guarded reader. __try/RtlCopyMemory is only fault-safe for USER
// addresses: a KERNEL address whose PTE cannot be resolved bugchecks
// 0x50 inside the copy -- the exception handler never runs (KDNET round
// 18c crash: the W32PROCESS heap-base scan dereferenced a stale kernel
// pointer). Kernel/session targets therefore get the house-standard
// MmIsAddressValid gate first (same residual as the dyndata/callback
// walkers, KNOWN_ISSUES B4), user targets keep the pure guarded copy.
// PASSIVE_LEVEL, caller context only.
//
static BOOLEAN MyArkWin32kRead(
    _In_ PVOID Address,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length)
{
    BOOLEAN ok = FALSE;

    if (Address == NULL || Length == 0) {
        return FALSE;
    }
    if ((UINT64)(UINT_PTR)Address >= 0xFFFF800000000000ULL
        && !MmIsAddressValid(Address)) {
        return FALSE;
    }
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

//
// win32kbase session-base profile (KDNET-calibrated, see CRASH_DEBUG_LOG
// R3-10b-i/ii). RVA of the KERNEL gSharedInfo inside win32kbase.sys.
// A zero RVA row = not yet calibrated (the resolver refuses, output
// falls back to the user-copy fields).
//
// Desktop-heap base candidates per enum call (KDNET round 18c: explorer
// carried a real Default-desktop object plus a junk pair-shaped block;
// 8 slots cover both real desktops with margin).
#define MYARK_WIN32K_HEAP_MAX_CAND 8

typedef struct _MYARK_WIN32KBASE_PROFILE {
    ULONG BuildMin;
    ULONG BuildMax;
    ULONG GSharedInfoRva;
    // KDNET rounds 18-18c (1903): desktop-heap kernel base derivation.
    // The caller's W32PROCESS is scanned over HeapScanBytes for pointers
    // to kernel desktop objects; an object qualifies when its +0x10 /
    // +0x18 qwords form a (base, base+size) desktop-heap pair. A process
    // can carry several real desktops (Default, Winlogon, service) and
    // junk that passes the pair test -- each row picks its base via the
    // per-row hdr self-check, so candidates never fabricate row values.
    // Zero HeapScanBytes = heap derivation not calibrated for the build.
    ULONG HeapScanBytes;
} MYARK_WIN32KBASE_PROFILE;

static const MYARK_WIN32KBASE_PROFILE g_MyArkWin32kBaseProfiles[] = {
    // KDNET-calibrated 2026-09-19 (rounds 8/18c)
    { 18362, 18363, 0x213750, 0x800 },
    // 22631: gSharedInfo RVA calibrated (round 8). The HeapScanBytes
    // window was never KDNET-calibrated -- it was validated live: the
    // per-row hdr self-check keeps the output honest (bit1 only sets on
    // a proven row) and the guarded reader carries the memory safety,
    // so the verify suite doubles as the calibration probe. Measured
    // 22631: desktop heaps live in a different region than 1903 (high
    // kernel VA, not session pool) -- the region-agnostic candidate
    // filter adapts; 696 rows validated. rsv2 failure crumbs
    // 0x111/0x112/0x113/0x114 (see MyArkWin32kIoctl.h); bit1 set with
    // rsv2 0 = proven derivation.
    { 22621, 22631, 0x285e80, 0x800 },
};

static const MYARK_WIN32KBASE_PROFILE*
MyArkWin32kBaseProfileForBuild(
    _In_ ULONG Build)
{
    ULONG i;
    for (i = 0; i < ARRAYSIZE(g_MyArkWin32kBaseProfiles); i++) {
        if (Build >= g_MyArkWin32kBaseProfiles[i].BuildMin
            && Build <= g_MyArkWin32kBaseProfiles[i].BuildMax
            && g_MyArkWin32kBaseProfiles[i].GSharedInfoRva != 0) {
            return &g_MyArkWin32kBaseProfiles[i];
        }
    }
    return NULL;
}

//
// RTL_PROCESS_MODULE_INFORMATION mirror (verified against the 1903 list,
// same shape as the 25_kernel shadow-SSDT walker uses).
//
typedef struct _MYARK_WIN32K_SYS_MODULE_ENTRY {
    HANDLE  Section;            // +0
    PVOID   MappedBase;         // +8
    PVOID   ImageBase;          // +16
    ULONG   ImageSize;          // +24
    ULONG   Flags;              // +28
    USHORT  LoadCount;          // +32
    USHORT  __Unused;           // +34
    ULONG   __Pad0;             // +36
    UCHAR   FullPathName[256];  // +40 (296-byte stride)
} MYARK_WIN32K_SYS_MODULE_ENTRY;

//
// Resolve the WIN32KBASE session base: the session driver trio appears in
// SystemModuleInformation (unlike PsLoadedModuleList -- see 25_kernel's
// shadow-SSDT walker). Find every "win32kbase.sys" ImageBase.
//
// Session-driver copies exist PER SESSION, so a multi-session host lists
// several candidates and a blind first-match may belong to a foreign
// session -- whose VAs are not mapped in the caller's address space and
// fail every guarded read. Callers must therefore validate candidates
// against live data (see MyArkWin32kResolveSessionBase / the 0x774
// walker) instead of trusting the first hit.
//
#define MYARK_WIN32K_SESSION_BASE_MAX 8

static ULONG
MyArkWin32kFindSessionImageCandidates(
    _Out_ UINT64* Bases,
    _In_  ULONG   MaxBases,
    _Out_ UINT32* Stage)
{
    typedef NTSTATUS (NTAPI *QUERY_FN)(ULONG, PVOID, ULONG, PULONG);
    QUERY_FN query;
    UNICODE_STRING name;
    ULONG needed = 0;
    NTSTATUS status;
    PUCHAR buf = NULL;
    ULONG count;
    ULONG i;
    ULONG found = 0;

    *Stage = 0;

    RtlInitUnicodeString(&name, L"ZwQuerySystemInformation");
    query = (QUERY_FN)MmGetSystemRoutineAddress(&name);
    if (query == NULL) {
        *Stage = 1;
        return 0;
    }

    status = query(11, NULL, 0, &needed);
    if (needed < 8 || needed > 4 * 1024 * 1024) {
        *Stage = 2;
        return 0;
    }
    buf = (PUCHAR)MyArkAllocatePool(NonPagedPoolNx, needed,
                                    MYARK_WIN32K_POOL_TAG);
    if (buf == NULL) {
        *Stage = 3;
        return 0;
    }
    status = query(11, buf, needed, &needed);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, MYARK_WIN32K_POOL_TAG);
        *Stage = 4;
        return 0;
    }

    count = *(PULONG)buf;
    {
        PUCHAR it = buf + 8;
        for (i = 0; i < count
                    && it + sizeof(MYARK_WIN32K_SYS_MODULE_ENTRY) <= buf + needed;
             i++) {
            MYARK_WIN32K_SYS_MODULE_ENTRY* m =
                (MYARK_WIN32K_SYS_MODULE_ENTRY*)it;
            it += sizeof(MYARK_WIN32K_SYS_MODULE_ENTRY);

            PCSTR tail = NULL;
            ULONG c;
            for (c = 0; c < sizeof(m->FullPathName) && m->FullPathName[c]; c++) {
                if (m->FullPathName[c] == '\\') {
                    tail = (PCSTR)&m->FullPathName[c + 1];
                }
            }
            if (tail == NULL) {
                continue;
            }
            if (_stricmp(tail, "win32kbase.sys") == 0
                && m->ImageBase != NULL
                && found < MaxBases) {
                BOOLEAN dupe = FALSE;
                ULONG k;
                for (k = 0; k < found; k++) {
                    if (Bases[k] == (UINT64)(UINT_PTR)m->ImageBase) {
                        dupe = TRUE;
                        break;
                    }
                }
                if (!dupe) {
                    Bases[found++] = (UINT64)(UINT_PTR)m->ImageBase;
                }
            }
        }
    }
    ExFreePoolWithTag(buf, MYARK_WIN32K_POOL_TAG);

    if (found == 0) {
        *Stage = 5;
        return 0;
    }
    return found;
}

//
// Resolve the KERNEL handle table for the CALLER's session: iterate every
// win32kbase candidate and take the first whose gSharedInfo validates
// against live data. A foreign session's copy fails the guarded reads
// (its session VAs are not mapped in the caller's address space), which
// is exactly the cross-session filter -- no explicit session id needed.
//
static BOOLEAN
MyArkWin32kResolveSessionBase(
    _In_ const MYARK_WIN32KBASE_PROFILE* Profile,
    _In_ UINT32 HeEntrySize,
    _Out_ UINT64* Win32kBase,
    _Out_ UINT64* KernelAheList,
    _Out_ UINT64* KernelPsi,
    _Out_ UINT32* Stage)
{
    UINT64 bases[MYARK_WIN32K_SESSION_BASE_MAX];
    ULONG candCount;
    ULONG i;

    *Win32kBase = 0;
    *KernelAheList = 0;
    *KernelPsi = 0;

    candCount = MyArkWin32kFindSessionImageCandidates(bases,
                                                      MYARK_WIN32K_SESSION_BASE_MAX,
                                                      Stage);
    if (candCount == 0) {
        return FALSE;
    }

    for (i = 0; i < candCount; i++) {
        UINT64 kgSharedInfo = bases[i] + Profile->GSharedInfoRva;
        UINT64 psi = 0;
        UINT64 aheList = 0;
        UINT32 heSize = 0;

        if (!MyArkWin32kReadU64((PVOID)kgSharedInfo, &psi)
            || !MyArkWin32kReadU64((PVOID)(kgSharedInfo + 8), &aheList)
            || !MyArkWin32kReadU32((PVOID)(kgSharedInfo + 0x10), &heSize)
            || heSize == 0 || heSize > 64
            // kernel/user are separate SHAREDINFO instances (psi mismatch
            // finding) -- their strides must still agree, else the
            // kernel-record walk below would read misaligned data.
            || heSize != HeEntrySize
            || psi == 0 || aheList == 0
            || aheList < 0xFFFF800000000000ULL) {
            continue;       // foreign-session or garbage copy: try next
        }
        *Win32kBase = bases[i];
        *KernelAheList = aheList;
        *KernelPsi = psi;
        return TRUE;
    }

    *Stage = 6;     // candidates existed but none validated for this session
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
    UINT64 kAheWalk = 0;
    UINT64 heapBases[MYARK_WIN32K_HEAP_MAX_CAND];
    ULONG heapBaseCount = 0;
    ULONG heapValidated = 0;
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

    //
    // R3-10b-ii: resolve the KERNEL handle table through the win32kbase
    // session base. Optional capability -- unresolved (un-calibrated
    // build) leaves the kernel fields at 0 and the user-copy walk stays
    // authoritative. PsiMatch is the runtime self-check: the kernel
    // gSharedInfo.psi must equal the user copy's psi.
    //
    {
        RTL_OSVERSIONINFOW os;
        const MYARK_WIN32KBASE_PROFILE* profile;

        RtlZeroMemory(&os, sizeof(os));
        os.dwOSVersionInfoSize = sizeof(os);
        if (NT_SUCCESS(RtlGetVersion(&os))) {
            profile = MyArkWin32kBaseProfileForBuild(os.dwBuildNumber);
            if (profile != NULL) {
                UINT64 w32kBase = 0;
                UINT64 kAhe = 0;
                UINT64 kPsi = 0;
                UINT32 stage = 0;
                if (MyArkWin32kResolveSessionBase(profile, heEntrySize,
                                                  &w32kBase,
                                                  &kAhe, &kPsi, &stage)) {
                    // Measured 1903: kernel gSharedInfo.psi and the user
                    // copy's psi are DIFFERENT SERVERINFO instances -- the
                    // mismatch is a finding, not a failure. Report both.
                    Out->Win32kBase = w32kBase;
                    Out->KernelAheList = kAhe;
                    Out->KernelPsi = kPsi;
                    Out->PsiMatch = (kPsi == psi) ? 1 : 0;
                    kAheWalk = kAhe;

                    // R3-10b-iv: derive candidate desktop-heap kernel
                    // bases for the caller by scanning its W32PROCESS.
                    // KDNET rounds 18-18c (1903): kernel desktop objects
                    // carry (base @+0x10, base+size @+0x18); the scan
                    // keeps every structurally-valid pair, interactive
                    // and service desktops alike. The old fixed chain
                    // (W32P+0x7f8 / -0x28) measured 3/30 ahe-row matches
                    // on explorer -- it latched the Winlogon-desktop
                    // heap -- so no fixed offset is trusted here. Rows
                    // below pick a candidate per object via the hdr
                    // self-check; PsiMatch bit1 only sets when >=1 row
                    // actually validates.
                    if (profile->HeapScanBytes != 0) {
                        PVOID w32p = PsGetProcessWin32Process(
                            PsGetCurrentProcess());
                        if (w32p == NULL) {
                            Out->Reserved2 = 0x100 | 0x11;  // no W32PROCESS
                        } else {
                            UCHAR chunk[512];
                            ULONG off;
                            BOOLEAN scanAbort = FALSE;
                            for (off = 0;
                                 off < profile->HeapScanBytes
                                 && heapBaseCount
                                    < MYARK_WIN32K_HEAP_MAX_CAND;
                                 off += sizeof(chunk)) {
                                ULONG n = profile->HeapScanBytes - off;
                                ULONG i;
                                if (n > sizeof(chunk)) {
                                    n = sizeof(chunk);
                                }
                                if (!MyArkWin32kRead(
                                        (PVOID)((UINT64)(UINT_PTR)w32p
                                                + off),
                                        chunk, n)) {
                                    scanAbort = TRUE;
                                    break;
                                }
                                // The 32-byte shape read happens at the
                                // absolute pointer v, not in-chunk -- the
                                // only in-chunk bound is the qword load.
                                for (i = 0;
                                     i + 8 <= n
                                     && heapBaseCount
                                        < MYARK_WIN32K_HEAP_MAX_CAND;
                                     i += 8) {
                                    UINT64 v = *(UINT64*)(chunk + i);
                                    UINT64 pair[4];
                                    ULONG ci;
                                    BOOLEAN dupe = FALSE;
                                    if (v < 0xFFFF800000000000ULL
                                        || (v & 7) != 0) {
                                        continue;
                                    }
                                    // Real pool objects carry a pool header
                                    // (>=16B), so a page-aligned kernel
                                    // pointer is a VA/size/mapping value,
                                    // not an object (KDNET 18c crash: the
                                    // junk pointer that faulted was exactly
                                    // one of these).
                                    if ((v & 0xFFF) == 0) {
                                        continue;
                                    }
                                    if (v >= (UINT64)(UINT_PTR)w32p
                                        && v < (UINT64)(UINT_PTR)w32p
                                               + profile->HeapScanBytes) {
                                        continue;   // points into itself
                                    }
                                    if (!MyArkWin32kRead(
                                            (PVOID)(UINT_PTR)v,
                                            pair, sizeof(pair))) {
                                        continue;
                                    }
                                    if (pair[2] < 0xFFFF800000000000ULL
                                        || pair[3] < 0xFFFF800000000000ULL
                                        || pair[3] <= pair[2]
                                        || pair[3] - pair[2] > 0x4000000ULL
                                        || (pair[2] >> 28)
                                           != (pair[3] >> 28)
                                        // junk shape: self-referential
                                        // pool block ({v+8, v+0x18})
                                        || (pair[2] == v + 8
                                            && pair[3] == v + 0x18)) {
                                        continue;
                                    }
                                    for (ci = 0; ci < heapBaseCount; ci++) {
                                        if (heapBases[ci] == pair[2]) {
                                            dupe = TRUE;
                                            break;
                                        }
                                    }
                                    if (!dupe) {
                                        heapBases[heapBaseCount++] = pair[2];
                                    }
                                }
                            }
                            if (heapBaseCount == 0) {
                                // 0x12 = scanned clean, no structural
                                // candidate; 0x14 = chunk read aborted
                                // (unrelated failure mode, keep apart).
                                Out->Reserved2 = 0x100
                                    | (scanAbort ? 0x14 : 0x12);
                            }
                        }
                    }
                } else {
                    Out->Reserved2 = stage;   // DIAG breadcrumb
                }
            }
        }
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

        // R3-10b-iv: with desktop-heap base candidates derived, the
        // KERNEL aheList record at the same slot holds the object's heap
        // offset (record@0). Every win32k desktop-heap object starts with
        // its own handle (tagHEAD.h) -- fill KernelObject only when some
        // candidate base + offset actually carries this row's handle,
        // trying each candidate (multi-desktop processes) until one
        // matches, so a wrong or junk base can never fabricate a value.
        // Gate: gen@26 decoding assumes the calibrated 32-byte stride.
        if (heapBaseCount != 0 && kAheWalk != 0 && heEntrySize == 32) {
            UCHAR kraw[32];
            if (MyArkWin32kRead((PVOID)(kAheWalk + (UINT64)index * heEntrySize),
                                kraw, heEntrySize)) {
                UINT32 koff = *(UINT32*)(kraw + 0);
                UINT16 kgen = *(UINT16*)(kraw + 26);
                if (koff != 0) {
                    ULONG ci;
                    for (ci = 0; ci < heapBaseCount; ci++) {
                        UINT64 kobj = heapBases[ci] + koff;
                        UINT64 hdr = 0;
                        if (MyArkWin32kRead((PVOID)(UINT_PTR)kobj, &hdr,
                                            sizeof(hdr)) &&
                            (hdr & 0xFFFFFFFFULL) ==
                                (UINT32)(index | ((UINT32)kgen << 16))) {
                            Out->Entries[Out->Count].KernelObject = kobj;
                            heapValidated++;
                            break;
                        }
                    }
                }
            }
        }

        Out->Count += 1;
    }

    // PsiMatch bit1: honest "heap base derived" = at least one row was
    // self-validated against a candidate base (KDNET round 18c: pair-shaped
    // junk exists, so structure alone must not claim success).
    if (heapValidated != 0) {
        Out->PsiMatch |= 2;
    } else if (heapBaseCount != 0) {
        Out->Reserved2 = 0x100 | 0x13;  // candidates, zero rows validated
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

//
// win32kbase!gTimerHashTable RVA profile (KDNET-calibrated, see
// CRASH_DEBUG_LOG R3-10b-iii). Zero RVA row = not yet calibrated.
//
typedef struct _MYARK_WIN32K_TIMER_PROFILE {
    ULONG BuildMin;
    ULONG BuildMax;
    ULONG GTimerHashTableRva;
} MYARK_WIN32K_TIMER_PROFILE;

static const MYARK_WIN32K_TIMER_PROFILE g_MyArkWin32kTimerProfiles[] = {
    { 18362, 18363, 0x215de0 },
    // 22621/22631: KDNET round 8 calibrated a gTimerHashTable RVA
    // (0x288320) and round 13 walked it live -- but the linked structures
    // carry non-TIMER pool tags ("Wnf "/"Ntfc"/"Rspp") where 1903 has
    // "Usmt", so the node layout there is NOT the calibrated 0xA0 TIMER
    // shape. The build stays gated out until a 22631-specific
    // differential calibration lands (R3-10b-iii follow-up); serving
    // 1903 offsets there would fabricate rows.
    { 22621, 22631, 0 },
};

static const MYARK_WIN32K_TIMER_PROFILE*
MyArkWin32kTimerProfileForBuild(_In_ ULONG Build)
{
    ULONG i;
    for (i = 0; i < ARRAYSIZE(g_MyArkWin32kTimerProfiles); i++) {
        if (Build >= g_MyArkWin32kTimerProfiles[i].BuildMin
            && Build <= g_MyArkWin32kTimerProfiles[i].BuildMax
            && g_MyArkWin32kTimerProfiles[i].GTimerHashTableRva != 0) {
            return &g_MyArkWin32kTimerProfiles[i];
        }
    }
    return NULL;
}

//
// TIMER node field offsets. KDNET-calibrated on 1903 (CRASH_DEBUG_LOG
// R3-10b-iii): sizeof(TIMER) = 0xA0, owning PTHREADINFO @0x48, user-mode
// pTimerProc @0x50, uElapse ms @0x58, flags dword @0x60, kernel PWND @0x88
// (0 = thread timer), nID @0x90 -- double-sample confirmed (probe timers
// 0x4343/0x4444 at +0x90, elapse 10000 at +0x58, shared pti/window).
// Run-time revalidation: verify_core plants its own marker timers and
// asserts they come back through 0x773, so a layout drift on another
// build fails the test instead of yielding silently wrong rows.
//
#define MYARK_WIN32K_TIMER_SIZE            0xA0
#define MYARK_WIN32K_TIMER_OFF_PTI         0x48
#define MYARK_WIN32K_TIMER_OFF_PROC        0x50
#define MYARK_WIN32K_TIMER_OFF_ELAPSE      0x58
#define MYARK_WIN32K_TIMER_OFF_FLAGS       0x60
#define MYARK_WIN32K_TIMER_OFF_WINDOW      0x88
#define MYARK_WIN32K_TIMER_OFF_NID         0x90
// KDNET-calibrated (2026-09-19): the table spans 1 KB = 64 LIST_ENTRY
// buckets. With a 32-bucket walk everything hashing into 32..63 silently
// vanished -- probe timers showed up as a stable "2 of 5" subset.
#define MYARK_WIN32K_TIMER_HASH_BUCKETS    64
#define MYARK_WIN32K_TIMER_BUCKET_HOPS     512     // loop safety cap

NTSTATUS
MyArkWin32kEnumTimers(
    _Out_ PMYARK_WIN32K_TIMERS_OUTPUT Out,
    _In_  ULONG                       MaxEntries)
{
    NTSTATUS diag = STATUS_SUCCESS;
    RTL_OSVERSIONINFOW os;
    const MYARK_WIN32K_TIMER_PROFILE* profile;
    UINT64 sessionBase = 0;
    UINT64 hashTable = 0;
    ULONG bucket;

    RtlZeroMemory(Out, sizeof(*Out));

    RtlZeroMemory(&os, sizeof(os));
    os.dwOSVersionInfoSize = sizeof(os);
    if (!NT_SUCCESS(RtlGetVersion(&os))) {
        Out->DiagStatus = (UINT32)STATUS_NOT_SUPPORTED;
        return STATUS_SUCCESS;
    }
    profile = MyArkWin32kTimerProfileForBuild(os.dwBuildNumber);
    if (profile == NULL) {
        // Not calibrated for this build (zero-RVA row or no row): refuse
        // cleanly instead of serving another build's node offsets.
        Out->DiagStatus = (UINT32)STATUS_NOT_IMPLEMENTED;
        return STATUS_SUCCESS;
    }
    Out->TimerHashRva = profile->GTimerHashTableRva;

    {
        // Cross-session filter: keep the candidate whose table lives in
        // the CALLER's session (foreign-session VAs fail the guarded read
        // or carry a non-canonical head).
        UINT64 bases[MYARK_WIN32K_SESSION_BASE_MAX];
        UINT32 cstage = 0;
        ULONG candCount = MyArkWin32kFindSessionImageCandidates(
            bases, MYARK_WIN32K_SESSION_BASE_MAX, &cstage);
        ULONG ci;
        BOOLEAN resolved = FALSE;
        if (candCount == 0) {
            Out->Reserved2 = cstage;        // DIAG breadcrumb
            Out->DiagStatus = (UINT32)STATUS_NOT_FOUND;
            return STATUS_SUCCESS;
        }
        for (ci = 0; ci < candCount && !resolved; ci++) {
            UINT64 candTable = bases[ci] + profile->GTimerHashTableRva;
            UINT64 head0 = 0;
            if (MyArkWin32kReadU64((PVOID)candTable, &head0)
                && (head0 == 0
                    || head0 >= 0xFFFF800000000000ULL)) {
                sessionBase = bases[ci];
                resolved = TRUE;
            }
        }
        if (!resolved) {
            Out->Reserved2 = 6;   // candidates but none validates
            Out->DiagStatus = (UINT32)STATUS_NOT_FOUND;
            return STATUS_SUCCESS;
        }
    }
    Out->SessionBase = sessionBase;
    hashTable = sessionBase + profile->GTimerHashTableRva;
    Out->TimerHashTable = hashTable;
    Out->BucketCount = MYARK_WIN32K_TIMER_HASH_BUCKETS;
    Out->NodeSize = MYARK_WIN32K_TIMER_SIZE;

    for (bucket = 0; bucket < MYARK_WIN32K_TIMER_HASH_BUCKETS; bucket++) {
        UINT64 bucketAddr = hashTable + (UINT64)bucket * 16;
        UINT64 node = 0;
        ULONG hops;

        Out->ScannedBuckets = bucket + 1;

        if (!MyArkWin32kReadU64((PVOID)bucketAddr, &node)) {
            diag = STATUS_ACCESS_VIOLATION;
            break;
        }

        for (hops = 0;
             node != bucketAddr && node != 0 && hops < MYARK_WIN32K_TIMER_BUCKET_HOPS;
             hops++) {
            UCHAR raw[MYARK_WIN32K_TIMER_SIZE];
            UINT64 next;

            if (node < 0xFFFF800000000000ULL) {
                break;                      // non-canonical Flink: stop bucket
            }
            if (!MyArkWin32kRead((PVOID)node, raw, sizeof(raw))) {
                diag = STATUS_ACCESS_VIOLATION;
                break;
            }
            next = *(UINT64*)(raw + 0);

            if (Out->Count < MaxEntries) {
                PMYARK_WIN32K_TIMER_ENTRY e = &Out->Entries[Out->Count];
                e->Index = Out->Count;
                e->TimerId = *(UINT32*)(raw + MYARK_WIN32K_TIMER_OFF_NID);
                e->ElapseMs = *(UINT32*)(raw + MYARK_WIN32K_TIMER_OFF_ELAPSE);
                e->Flags = *(UINT32*)(raw + MYARK_WIN32K_TIMER_OFF_FLAGS);
                e->Pti = *(UINT64*)(raw + MYARK_WIN32K_TIMER_OFF_PTI);
                e->TimerProc = *(UINT64*)(raw + MYARK_WIN32K_TIMER_OFF_PROC);
                e->Window = *(UINT64*)(raw + MYARK_WIN32K_TIMER_OFF_WINDOW);
                e->Node = node;
                Out->Count += 1;
            } else {
                Out->Truncated = 1;
            }

            node = next;
        }
        if (diag != STATUS_SUCCESS) {
            break;
        }
    }

    Out->DiagStatus = (UINT32)diag;
    // Same in-band convention as 0x772: a fault mid-walk after rows were
    // produced means "partial enumeration", which is still useful
    // forensic data -- report success with what we got.
    if (diag == STATUS_ACCESS_VIOLATION && Out->Count > 0) {
        Out->DiagStatus = (UINT32)STATUS_SUCCESS;
    }
    return STATUS_SUCCESS;
}

//
// win32kbase!gpWinEventHooks RVA profile (KDNET-calibrated, see
// CRASH_DEBUG_LOG R3-10c). Zero RVA row = not yet calibrated.
//
typedef struct _MYARK_WIN32K_EVENTHOOK_PROFILE {
    ULONG BuildMin;
    ULONG BuildMax;
    ULONG GpWinEventHooksRva;
} MYARK_WIN32K_EVENTHOOK_PROFILE;

static const MYARK_WIN32K_EVENTHOOK_PROFILE
g_MyArkWin32kEventHookProfiles[] = {
    // KDNET round 20b/20c (2026-09-20): symbol-resolved live, base
    // 0xFFFFFF08D4FB0000 this boot.
    { 18362, 18363, 0x219200 },
    // 22621/22631: gated until a differential EVENTHOOK calibration
    // lands -- same policy as the 0x773 timer table there.
    { 22621, 22631, 0 },
};

static const MYARK_WIN32K_EVENTHOOK_PROFILE*
MyArkWin32kEventHookProfileForBuild(_In_ ULONG Build)
{
    ULONG i;
    for (i = 0; i < ARRAYSIZE(g_MyArkWin32kEventHookProfiles); i++) {
        if (Build >= g_MyArkWin32kEventHookProfiles[i].BuildMin
            && Build <= g_MyArkWin32kEventHookProfiles[i].BuildMax
            && g_MyArkWin32kEventHookProfiles[i].GpWinEventHooksRva != 0) {
            return &g_MyArkWin32kEventHookProfiles[i];
        }
    }
    return NULL;
}

//
// EVENTHOOK node field offsets. KDNET-calibrated on 1903 (CRASH_DEBUG_LOG
// R3-10c) with three probe hooks carrying distinctive event-range pairs:
// USER handle @0x00 (0x772 type-15 row), next pointer @0x18 (singly
// linked, LIFO, NULL-terminated), EventMin/EventMax dwords @0x20/0x24,
// internal flags dword @0x28 (probe dwFlags 0x2/0x0 measured as 0x4/0x0),
// user-mode WinEventProc @0x40, idProcess @0x48 (0 registered as
// 0xFFFFFFFF = all), idThread @0x50. Run-time revalidation: verify_core
// registers its own marker hooks and asserts they come back through
// 0x774, so a layout drift fails the test instead of yielding silently
// wrong rows.
//
#define MYARK_WIN32K_EVENTHOOK_SIZE         0x60
#define MYARK_WIN32K_EVENTHOOK_OFF_NEXT     0x18
#define MYARK_WIN32K_EVENTHOOK_OFF_EMIN     0x20
#define MYARK_WIN32K_EVENTHOOK_OFF_INTERNAL 0x28
#define MYARK_WIN32K_EVENTHOOK_OFF_PROC     0x40
#define MYARK_WIN32K_EVENTHOOK_OFF_IDPROCESS 0x48
#define MYARK_WIN32K_EVENTHOOK_OFF_IDTHREAD 0x50
#define MYARK_WIN32K_EVENTHOOK_MAX_HOPS     1024    // loop safety cap

NTSTATUS
MyArkWin32kEnumEventHooks(
    _Out_ PMYARK_WIN32K_EVENTHOOKS_OUTPUT Out,
    _In_  ULONG                           MaxEntries)
{
    NTSTATUS diag = STATUS_SUCCESS;
    RTL_OSVERSIONINFOW os;
    const MYARK_WIN32K_EVENTHOOK_PROFILE* profile;
    UINT64 sessionBase = 0;
    UINT64 listHead = 0;
    UINT64 node = 0;
    ULONG hops;

    RtlZeroMemory(Out, sizeof(*Out));

    RtlZeroMemory(&os, sizeof(os));
    os.dwOSVersionInfoSize = sizeof(os);
    if (!NT_SUCCESS(RtlGetVersion(&os))) {
        Out->DiagStatus = (UINT32)STATUS_NOT_SUPPORTED;
        return STATUS_SUCCESS;
    }
    profile = MyArkWin32kEventHookProfileForBuild(os.dwBuildNumber);
    if (profile == NULL) {
        // Not calibrated for this build (zero-RVA row or no row): refuse
        // cleanly instead of serving another build's node offsets.
        Out->DiagStatus = (UINT32)STATUS_NOT_IMPLEMENTED;
        return STATUS_SUCCESS;
    }
    Out->WinEventHooksRva = profile->GpWinEventHooksRva;

    {
        // Cross-session filter: keep the candidate whose hook-list head
        // READS as live data in the caller's address space (foreign-
        // session VAs fail the guarded read or carry a junk head).
        UINT64 bases[MYARK_WIN32K_SESSION_BASE_MAX];
        UINT32 cstage = 0;
        ULONG candCount = MyArkWin32kFindSessionImageCandidates(
            bases, MYARK_WIN32K_SESSION_BASE_MAX, &cstage);
        ULONG ci;
        BOOLEAN resolved = FALSE;
        if (candCount == 0) {
            Out->Reserved2 = cstage;        // DIAG breadcrumb
            Out->DiagStatus = (UINT32)STATUS_NOT_FOUND;
            return STATUS_SUCCESS;
        }
        for (ci = 0; ci < candCount && !resolved; ci++) {
            UINT64 candHead = bases[ci] + profile->GpWinEventHooksRva;
            UINT64 first = 0;
            if (MyArkWin32kReadU64((PVOID)candHead, &first)
                && (first == 0
                    || first >= 0xFFFF800000000000ULL)) {
                sessionBase = bases[ci];
                resolved = TRUE;
            }
        }
        if (!resolved) {
            Out->Reserved2 = 6;   // candidates but none validates
            Out->DiagStatus = (UINT32)STATUS_NOT_FOUND;
            return STATUS_SUCCESS;
        }
    }
    Out->SessionBase = sessionBase;
    listHead = sessionBase + profile->GpWinEventHooksRva;
    Out->ListHead = listHead;
    Out->NodeSize = MYARK_WIN32K_EVENTHOOK_SIZE;

    if (!MyArkWin32kReadU64((PVOID)listHead, &node)) {
        Out->DiagStatus = (UINT32)STATUS_ACCESS_VIOLATION;
        return STATUS_SUCCESS;
    }

    for (hops = 0; node != 0 && hops < MYARK_WIN32K_EVENTHOOK_MAX_HOPS;
         hops++) {
        UCHAR raw[MYARK_WIN32K_EVENTHOOK_SIZE];
        UINT64 next;

        if (node < 0xFFFF800000000000ULL) {
            break;                      // non-canonical next: stop list
        }
        if (!MyArkWin32kRead((PVOID)node, raw, sizeof(raw))) {
            diag = STATUS_ACCESS_VIOLATION;
            break;
        }
        next = *(UINT64*)(raw + MYARK_WIN32K_EVENTHOOK_OFF_NEXT);

        if (Out->Count < MaxEntries) {
            PMYARK_WIN32K_EVENTHOOK_ENTRY e = &Out->Entries[Out->Count];
            e->Index = Out->Count;
            e->EventMin = *(UINT32*)(raw + MYARK_WIN32K_EVENTHOOK_OFF_EMIN);
            e->EventMax = *(UINT32*)(raw + MYARK_WIN32K_EVENTHOOK_OFF_EMIN
                                     + 4);
            e->FlagsInternal =
                *(UINT32*)(raw + MYARK_WIN32K_EVENTHOOK_OFF_INTERNAL);
            e->IdProcess =
                *(UINT32*)(raw + MYARK_WIN32K_EVENTHOOK_OFF_IDPROCESS);
            e->IdThread =
                *(UINT32*)(raw + MYARK_WIN32K_EVENTHOOK_OFF_IDTHREAD);
            // USER handle: 32-bit value, zero-extended (the
            // upper dword of the field is always zero on 1903).
            e->Handle = *(UINT32*)(raw + 0);
            e->Callback = *(UINT64*)(raw + MYARK_WIN32K_EVENTHOOK_OFF_PROC);
            e->Node = node;
            Out->Count += 1;
        } else {
            Out->Truncated = 1;
        }

        node = next;
    }

    Out->DiagStatus = (UINT32)diag;
    // Same in-band convention as 0x772/0x773: a fault mid-walk after rows
    // were produced is a partial-but-useful enumeration.
    if (diag == STATUS_ACCESS_VIOLATION && Out->Count > 0) {
        Out->DiagStatus = (UINT32)STATUS_SUCCESS;
    }
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_WIN32K
