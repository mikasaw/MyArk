// MyArk "kernel" module: shared IOCTL protocol.
//
// Function range 0xC70..0xC7F reserved for the kernel-side inspector
// (SSDT / IDT / inline-hook / CPU / Timer-DPC / driver-integrity walks).
// All entries use the MyArk METHOD_BUFFERED convention.
//
// Note: this header deliberately ships 1 IOCTL (QUERY_SSDT) in S6.4 to
// satisfy the acceptance criterion `myark-cli kernel query-ssdt`. The
// remaining kernel-side IOCTLs (ShadowSSDT, IDT, inline-hook, MSR, DPC,
// driver-integrity) are deferred to a follow-up issue once the detailed
// struct spec lands -- the previous S6.4 partial delivery stated
// "the issue body lists [kernel] in the 8-module title but doesn't
// provide the detailed IOCTL breakdown", and the prior delivery chose
// not to invent the spec. This module participates in the same gated
// build and runtime-registry plumbing as the other 7 S6.4 modules.

#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "MyArkSafetyToken.h"

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_KERNEL_MODULE_ID              0x4E524E4BUL  // 'KRNL' ASCII (LE)
#define MYARK_KERNEL_NAME_MAX                64
#define MYARK_KERNEL_SSDT_DEFAULT_MAX       512
#define MYARK_KERNEL_SSDT_HARD_CAP          4096

//
// S6.4 ships 1 IOCTL (function range 0xC70). More will land in S6.x follow-up.
//
#define IOCTL_MYARK_KERNEL_QUERY_SSDT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC70, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// QUERY_SSDT output: one row per SSDT entry.
//
// Each row carries the kernel VA of the kernel-side service routine plus
// the ordinal index (NtCreateFile etc.), the dwell bytes (8 bytes from the
// kernel-side trampoline), and a SOCK-style flag bit. R3 flags entries
// outside the ntoskrnl .text range as suspect -- this is the standard
// "SSDT hook check" primitive that ships in every ARK tool.
//
// The walker resolves KeServiceDescriptorTable at IOCTL time via
// MmGetSystemRoutineAddress (the symbol is exported but not declared in
// any public WDK 28000 header; the redirect-thunk in nt!KiSystemServiceStart
// also works as a secondary probe).
// ---------------------------------------------------------------------------

#define MYARK_KERNEL_SSDT_FLAG_NONE         0x00000000
#define MYARK_KERNEL_SSDT_FLAG_POPULATED    0x00000001   // ServiceTable[index] != NULL
#define MYARK_KERNEL_SSDT_FLAG_SUSPECT      0x00000002   // address outside ntoskrnl .text
#define MYARK_KERNEL_SSDT_FLAG_HOOK         0x00000004   // user-bit set or thunk present

typedef struct _MYARK_KERNEL_SSDT_ENTRY {
    UINT64  ServiceAddress;                                // kernel VA of Nt* routine
    UINT32  ServiceIndex;                                  // ordinal (NtCreateFile = 0x??)
    UINT32  Flags;                                         // MYARK_KERNEL_SSDT_FLAG_*
    UINT32  DwellBytesSize;                                // bytes copied (up to 8)
    UINT8   DwellBytes[8];                                 // trampoline sniff
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_KERNEL_SSDT_ENTRY, *PMYARK_KERNEL_SSDT_ENTRY;

typedef struct _MYARK_KERNEL_QUERY_SSDT_INPUT {
    UINT32  MaxEntries;                                    // 0 = driver default
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_KERNEL_QUERY_SSDT_INPUT, *PMYARK_KERNEL_QUERY_SSDT_INPUT;

typedef struct _MYARK_KERNEL_QUERY_SSDT_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved;
    UINT64  KeServiceDescriptorTable;                      // resolved address (0 = unresolvable)
    UINT64  NtoskrnlTextBase;                              // start of ntoskrnl .text (suspect range lower bound)
    UINT64  NtoskrnlTextEnd;                               // end of ntoskrnl .text (suspect range upper bound)
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_KERNEL_SSDT_ENTRY Entries[1];
} MYARK_KERNEL_QUERY_SSDT_OUTPUT, *PMYARK_KERNEL_QUERY_SSDT_OUTPUT;

// ---------------------------------------------------------------------------
// SCAN_INLINE_HOOKS (R1-4): byte-pattern scan of the ntoskrnl image for
// inline-hook jump stubs. Classes: E9 (near jmp rel32), EB (short jmp
// rel8), FF25 (indirect jmp [rip+rel32]). A candidate is emitted only when
// the jump target lands OUTSIDE the ntoskrnl image range -- intra-module
// jumps are normal compiler output and are not hooks. Read-only.
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_KERNEL_SCAN_INLINE_HOOKS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE20, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_KERNEL_HOOK_HARD_CAP          256
#define MYARK_KERNEL_HOOK_CLASS_E9          1   // jmp rel32
#define MYARK_KERNEL_HOOK_CLASS_EB          2   // jmp rel8
#define MYARK_KERNEL_HOOK_CLASS_FF25        3   // jmp [rip+rel32]

typedef struct _MYARK_KERNEL_HOOK_ENTRY {
    UINT64  HookAddress;                             // address of the stub byte
    UINT64  JumpTarget;                              // resolved target (0 = indirect, unresolved)
    UINT32  Class;                                   // MYARK_KERNEL_HOOK_CLASS_*
    UINT32  Reserved0;
} MYARK_KERNEL_HOOK_ENTRY, *PMYARK_KERNEL_HOOK_ENTRY;

typedef struct _MYARK_KERNEL_SCAN_HOOKS_INPUT {
    UINT32  MaxEntries;                              // 0 = driver default (256)
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_KERNEL_SCAN_HOOKS_INPUT, *PMYARK_KERNEL_SCAN_HOOKS_INPUT;

typedef struct _MYARK_KERNEL_SCAN_HOOKS_OUTPUT {
    UINT32  Size;
    UINT32  Count;                                   // entries emitted
    UINT32  TotalHooks;                              // all candidates found (may exceed Count)
    UINT32  BytesScannedKb;                          // scanned range size in KB
    UINT64  NtoskrnlTextBase;                        // scanned range start
    UINT64  NtoskrnlTextEnd;                         // scanned range end
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_KERNEL_HOOK_ENTRY Entries[1];
} MYARK_KERNEL_SCAN_HOOKS_OUTPUT, *PMYARK_KERNEL_SCAN_HOOKS_OUTPUT;

// ---------------------------------------------------------------------------
// PATCH_INLINE_HOOK (R2-1): restore original bytes over a hook stub found
// by SCAN_INLINE_HOOKS. The caller supplies the stub address, the bytes it
// expects to find there (from the scan / QUERY_PATCH_TARGET dwell) and the
// original bytes to write back. The write goes through an MDL alias of the
// (read-only) code page. Token-gated and FORCE-flagged; without both the
// request is rejected with STATUS_ACCESS_DENIED. Byte range must stay
// within one page and inside a loaded kernel image (RtlPcToFileHeader).
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_KERNEL_PATCH_INLINE_HOOK     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_KERNEL_QUERY_PATCH_TARGET    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE22, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_KERNEL_PATCH_BYTE_MAX          16
#define MYARK_KERNEL_PATCH_FORCE_MAGIC       0x43524F46UL  // 'FORC' ASCII (LE)

// SAFETY_TOKEN operation carried by PATCH_INLINE_HOOK tokens. Distinct
// from the file/registry op namespaces ('1'..) so a token signed for one
// mutating surface cannot authorize kernel-memory patching.
#define MYARK_KERNEL_OP_PATCH_HOOK           0x314E524BUL  // 'KRN1' ASCII (LE)

typedef struct _MYARK_KERNEL_PATCH_HOOK_INPUT {
    MYARK_SAFETY_TOKEN Token;                        // op = MYARK_KERNEL_OP_PATCH_HOOK
    UINT64  HookAddress;                             // stub VA (kernel image range)
    UINT32  ByteCount;                               // 1..MYARK_KERNEL_PATCH_BYTE_MAX
    UINT32  Force;                                   // must equal MYARK_KERNEL_PATCH_FORCE_MAGIC
    UINT8   ExpectedBytes[MYARK_KERNEL_PATCH_BYTE_MAX];  // pre-write dwell check
    UINT8   RestoreBytes[MYARK_KERNEL_PATCH_BYTE_MAX];   // bytes written back
} MYARK_KERNEL_PATCH_HOOK_INPUT, *PMYARK_KERNEL_PATCH_HOOK_INPUT;

typedef struct _MYARK_KERNEL_PATCH_HOOK_OUTPUT {
    UINT32  Status;                                  // 0 = patched
    UINT32  BytesPatched;
    UINT8   PriorBytes[MYARK_KERNEL_PATCH_BYTE_MAX]; // dwell read before the write
    UINT64  ModuleBase;                              // image containing HookAddress
} MYARK_KERNEL_PATCH_HOOK_OUTPUT, *PMYARK_KERNEL_PATCH_HOOK_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_PATCH_TARGET (R2-1): report the driver's own never-called probe
// function -- a product-inert patch target inside the MyArkCore image used
// by the regression to drive the full expected-check -> MDL write ->
// restore cycle without touching live ntoskrnl code. Read-only.
// ---------------------------------------------------------------------------

typedef struct _MYARK_KERNEL_PATCH_TARGET_INPUT {
    UINT32  Reserved0;
} MYARK_KERNEL_PATCH_TARGET_INPUT, *PMYARK_KERNEL_PATCH_TARGET_INPUT;

typedef struct _MYARK_KERNEL_PATCH_TARGET_OUTPUT {
    UINT32  Size;
    UINT32  Status;
    UINT64  TargetVa;                                // probe function VA
    UINT64  ModuleBase;                              // MyArkCore image base
    UINT32  ByteCount;                               // recommended patch width
    UINT32  Reserved1;
    UINT8   CurrentBytes[MYARK_KERNEL_PATCH_BYTE_MAX];   // live dwell at TargetVa
} MYARK_KERNEL_PATCH_TARGET_OUTPUT, *PMYARK_KERNEL_PATCH_TARGET_OUTPUT;

// ---------------------------------------------------------------------------
// ENUM_IAT_EAT_HOOKS (R2-2): read-only IAT/EAT hook enumeration for a user
// process module. The driver attaches to the target process, parses the PE
// headers at ModuleBase and walks:
//   EAT -- every AddressOfFunctions entry must point inside the image;
//          an out-of-image RVA is a patched export (hook). Forwarded
//          exports (RVA inside the export directory) are normal.
//   IAT -- every resolved FirstThunk entry must land in image-backed
//          memory (ZwQueryVirtualMemory Type MEM_IMAGE/MEM_MAPPED);
//          a private-pool target is a hook candidate.
// Only hook candidates are emitted (bounded); totals cover every walked
// entry so R3 can assert "scanned a real table" via TotalEAT/TotalIAT.
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_KERNEL_ENUM_IAT_EAT          CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE23, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_KERNEL_IATEAT_FLAG_EAT         0x00000001
#define MYARK_KERNEL_IATEAT_FLAG_IAT         0x00000002
#define MYARK_KERNEL_IATEAT_KIND_EAT         1
#define MYARK_KERNEL_IATEAT_KIND_IAT         2
#define MYARK_KERNEL_IATEAT_HARD_CAP         512
#define MYARK_KERNEL_IATEAT_DEFAULT_MAX      128

// Output Status: 0 = complete walk, MYARK_KERNEL_IATEAT_STATUS_PARTIAL =
// a table array ended early (unreadable tail) and the totals are partial.
#define MYARK_KERNEL_IATEAT_STATUS_PARTIAL   1

typedef struct _MYARK_KERNEL_ENUM_IATEAT_INPUT {
    UINT32  Pid;                                     // 0 = caller process
    UINT32  Flags;                                   // MYARK_KERNEL_IATEAT_FLAG_*
    UINT64  ModuleBase;                              // user module base (ntdll etc.)
    UINT32  MaxEntries;                              // 0 = driver default (128)
    UINT32  Reserved0;
} MYARK_KERNEL_ENUM_IATEAT_INPUT, *PMYARK_KERNEL_ENUM_IATEAT_INPUT;

typedef struct _MYARK_KERNEL_IATEAT_ENTRY {
    UINT64  SlotVa;                                  // IAT slot VA / export function VA
    UINT64  CurrentTarget;                           // value read at the slot
    UINT32  Kind;                                    // MYARK_KERNEL_IATEAT_KIND_*
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_KERNEL_IATEAT_ENTRY, *PMYARK_KERNEL_IATEAT_ENTRY;

typedef struct _MYARK_KERNEL_ENUM_IATEAT_OUTPUT {
    UINT32  Size;
    UINT32  Status;                                  // 0 = complete walk
    UINT32  Count;                                   // entries emitted (hooked)
    UINT32  TotalHooks;
    UINT32  TotalEAT;                                // export functions walked
    UINT32  TotalIAT;                                // import thunks walked
    UINT64  ModuleBase;                              // echoed
    UINT32  ImageSize;                               // from the PE optional header
    UINT32  EntryStructSize;
    MYARK_KERNEL_IATEAT_ENTRY Entries[1];
} MYARK_KERNEL_ENUM_IATEAT_OUTPUT, *PMYARK_KERNEL_ENUM_IATEAT_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_SHADOW_SSDT (R2-3): read-only walk of the win32k (shadow) service
// table. The shadow DESCRIPTOR table lives in the ntoskrnl image
// (KeServiceDescriptorTableShadow, not exported): the driver scans the
// ntoskrnl image for the adjacent descriptor pair -- [0] native (Base and
// Args inside ntoskrnl), [1] win32k (Base/Args inside the union of every
// loaded win32k* module) -- using the KDNET-verified field layout
// (Base@+0, zero@+8, Limit@+0x10, Args@+0x18). [1] is walked with the
// same row format as QUERY_SSDT; the suspect range is the win32k module
// union instead of ntoskrnl.
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_KERNEL_QUERY_SHADOW_SSDT     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE24, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_KERNEL_SHADOW_HARD_CAP         2048
#define MYARK_KERNEL_SHADOW_LIMIT_MIN        0x100   // nt table ~0x1C7, win32k ~0x2C0+
#define MYARK_KERNEL_SHADOW_LIMIT_MAX        0x4000

typedef struct _MYARK_KERNEL_QUERY_SHADOW_INPUT {
    UINT32  MaxEntries;                              // 0 = driver default
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_KERNEL_QUERY_SHADOW_INPUT, *PMYARK_KERNEL_QUERY_SHADOW_INPUT;

typedef struct _MYARK_KERNEL_QUERY_SHADOW_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  TableLimit;                              // descriptor Limit field
    UINT64  ShadowTableBase;                         // descriptor address in win32k image
    UINT64  Win32kBase;                              // module image base
    UINT32  Win32kSize;                              // module image size
    UINT32  EntryStructSize;                         // = sizeof(SSDT_ENTRY)
    MYARK_KERNEL_SSDT_ENTRY Entries[1];
} MYARK_KERNEL_QUERY_SHADOW_OUTPUT, *PMYARK_KERNEL_QUERY_SHADOW_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_DRIVER_INTEGRITY (R2-4): read-only per-CPU integrity snapshot --
// GDT/IDT bases and measured limits, syscall MSRs (LSTAR/CSTAR/STAR/SFMASK),
// CR0/CR4 -- collected on every processor via KeIpiGenericCall, plus the
// UnloadedDrivers registry evidence. All assessment windows are widened
// 4 MiB BELOW the ntoskrnl base: on KVA-shadow systems the IDT stubs and
// LSTAR live in the shadow trampoline area below PsNtosImageBase
// (KDNET-verified on 18362). PiDDBCacheTable has no stable export; this
// build reports PiDDB as unavailable (Status flag) instead of guessing.
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_KERNEL_QUERY_INTEGRITY       CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE25, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_KERNEL_INTEGRITY_MAX_CPU       64
#define MYARK_KERNEL_UNLOADED_MAX            16

// Per-CPU Flags bits.
#define MYARK_KERNEL_INTF_LSTAR_IN_WIN       0x00000001  // LSTAR in the nt window
#define MYARK_KERNEL_INTF_IDT_ALL_IN_WIN     0x00000002  // every present IDT gate in window
#define MYARK_KERNEL_INTF_CR0_NATIVE         0x00000004  // PG|PE set, CD clear
#define MYARK_KERNEL_INTF_GDT_BASE_SANE      0x00000008  // GDT base nonzero
#define MYARK_KERNEL_INTF_IDT_BASE_SANE      0x00000010  // IDT base nonzero

// Output Status values.
#define MYARK_KERNEL_INTEGRITY_OK            0
#define MYARK_KERNEL_INTEGRITY_PIDDB_NA      1           // degraded: no PiDDB

typedef struct _MYARK_KERNEL_CPU_INTEGRITY {
    UINT32  Processor;
    UINT32  Flags;                                   // MYARK_KERNEL_INTF_*
    UINT64  GdtBase;
    UINT32  GdtLimit;                                // measured on CPU0
    UINT32  Reserved0;
    UINT64  IdtBase;
    UINT32  IdtLimit;                                // measured on CPU0
    UINT32  IdtOutsideCount;                         // gates outside the window
    UINT64  Lstar;                                   // MSR 0xC0000082
    UINT64  Cstar;                                   // MSR 0xC0000083
    UINT64  Star;                                    // MSR 0xC0000081
    UINT64  Sfmask;                                  // MSR 0xC0000084
    UINT64  Cr0;
    UINT64  Cr4;
} MYARK_KERNEL_CPU_INTEGRITY, *PMYARK_KERNEL_CPU_INTEGRITY;

typedef struct _MYARK_KERNEL_UNLOADED_ENTRY {
    UINT64  UnloadTime;                              // FILETIME from the value data
    WCHAR   Name[28];                                // truncated value name
} MYARK_KERNEL_UNLOADED_ENTRY, *PMYARK_KERNEL_UNLOADED_ENTRY;

typedef struct _MYARK_KERNEL_INTEGRITY_OUTPUT {
    UINT32  Size;
    UINT32  Status;                                  // MYARK_KERNEL_INTEGRITY_*
    UINT32  ProcessorCount;
    UINT32  UnloadedCount;                           // emitted (capped)
    UINT32  UnloadedTotal;                           // values in the registry key
    UINT32  Reserved0;
    UINT64  NtosWindowBase;                          // ntosBase - 4 MiB
    UINT64  NtosWindowEnd;                           // ntosBase + 16 MiB
    UINT32  CpuEntryStructSize;
    UINT32  UnloadedEntryStructSize;
    UINT32  UnloadedOffset;                          // byte offset of Unloaded[]
    UINT32  Reserved1;
    MYARK_KERNEL_CPU_INTEGRITY Cpus[1];
    // followed by MYARK_KERNEL_UNLOADED_ENTRY Unloaded[UnloadedCount]
} MYARK_KERNEL_INTEGRITY_OUTPUT, *PMYARK_KERNEL_INTEGRITY_OUTPUT;


// ---------------------------------------------------------------------------
// FORCE_UNLOAD (R2-5): token+FORCE gated unload of a third-party kernel
// driver by service-key name. Preflight refuses MyArkCore itself and a
// static boot-critical blocklist; the unload goes through ZwUnloadDriver
// on the service registry path, then the loaded-module list is re-walked
// so the output carries ground truth about whether the image actually
// left memory (a driver without an Unload routine cannot leave -- that
// failure is reported in-band, not papered over).
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_KERNEL_FORCE_UNLOAD          CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE26, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_KERNEL_OP_FORCE_UNLOAD         0x324B524EUL  // 'NRK2' ASCII (LE)
#define MYARK_KERNEL_UNLOAD_FLAG_FORCE       0x00000001    // must be set
#define MYARK_KERNEL_UNLOAD_FORCE_MAGIC      0x43524F46UL  // 'FORC' ASCII (LE)
#define MYARK_KERNEL_UNLOAD_NAME_MAX         64

// Output Status: 0 = unloaded and confirmed gone; else the in-band
// NTSTATUS of the chain (STATUS_NOT_FOUND when the image was not loaded).

typedef struct _MYARK_KERNEL_FORCE_UNLOAD_INPUT {
    MYARK_SAFETY_TOKEN Token;                        // op = MYARK_KERNEL_OP_FORCE_UNLOAD
    UINT32  Flags;                                   // must include MYARK_KERNEL_UNLOAD_FLAG_FORCE
    UINT32  Force;                                   // must equal MYARK_KERNEL_UNLOAD_FORCE_MAGIC
    WCHAR   ServiceName[MYARK_KERNEL_UNLOAD_NAME_MAX]; // service-key name, no path
} MYARK_KERNEL_FORCE_UNLOAD_INPUT, *PMYARK_KERNEL_FORCE_UNLOAD_INPUT;

typedef struct _MYARK_KERNEL_FORCE_UNLOAD_OUTPUT {
    UINT32  Status;
    UINT32  WasLoadedBefore;                         // image in the module list pre-unload
    UINT32  GoneAfter;                               // module list no longer shows it
    UINT32  Reserved0;
} MYARK_KERNEL_FORCE_UNLOAD_OUTPUT, *PMYARK_KERNEL_FORCE_UNLOAD_OUTPUT;
