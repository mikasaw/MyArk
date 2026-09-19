// MyArk kernel-object module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x910..0x911. Both IOCTLs are read-only walks of the
// object-manager namespace via the exported Zw* directory surface
// (ZwOpenDirectoryObject + ZwQueryDirectoryObject), so they carry no
// per-build profile and no raw-pointer decode:
//
//   0x910  ENUM_DIRECTORY - list one object directory ({name, type} rows)
//   0x911  IPC_SUMMARY    - combined \Device\NamedPipe + \Device\MailSlot
//                           walk (R3-4b "IPC 摘要")
//
// Typical ENUM_DIRECTORY subjects: "\" (namespace root), "\ObjectTypes"
// (every object type name = the kernel-object summary), "\Device",
// "\BaseNamedObjects", "\KernelObjects", "\Driver".
//
// Both IOCTLs use the MyArk METHOD_BUFFERED convention and are read-only,
// so they are NOT SAFETY_TOKEN-gated (the token only guards mutating
// IOCTLs).

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

// 'KOBJ' ASCII (LE) -- mirrors MYARK_MODULE_ID_KERNEL_OBJECT in
// MyArkPluginApi.h. MyArkPluginApi.h is NOT included here: it carries its
// own _MYARK_MODULE_DESCRIPTOR copy for the R3/plugin side, which would
// collide with module_descriptor.h in kernel TUs.
#define MYARK_KOBJ_MODULE_ID                   0x4B4F424AUL

//
// 2 IOCTLs (function range 0x910..0x911).
//
#define IOCTL_MYARK_KOBJ_ENUM_DIRECTORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_KOBJ_IPC_SUMMARY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Row shape shared by both IOCTLs.
// ---------------------------------------------------------------------------

// Object names can exceed these caps (NPFS instance names are long); the
// driver clamps to (MAX-1) WCHARs + NUL instead of dropping the row. Type
// names are short on every build ("File", "ALPC Port", "Directory", ...).
#define MYARK_KOBJ_NAME_MAX                    64
#define MYARK_KOBJ_TYPE_MAX                    32

#define MYARK_KOBJ_DIR_CAP                     256
#define MYARK_KOBJ_PIPE_CAP                    256
#define MYARK_KOBJ_MAILSLOT_CAP                64

// Input path cap (WCHARs including the NUL). "\Device\NamedPipe" needs 19.
#define MYARK_KOBJ_PATH_MAX                    96

typedef struct _MYARK_KOBJ_ENTRY {
    WCHAR Name[MYARK_KOBJ_NAME_MAX];
    WCHAR TypeName[MYARK_KOBJ_TYPE_MAX];
} MYARK_KOBJ_ENTRY, *PMYARK_KOBJ_ENTRY;

// ---------------------------------------------------------------------------
// 0x910 ENUM_DIRECTORY.
// ---------------------------------------------------------------------------

typedef struct _MYARK_KOBJ_DIRECTORY_INPUT {
    // WCHAR count of DirectoryPath including the NUL terminator (2..MAX).
    UINT32 PathLength;
    UINT32 Reserved;
    WCHAR  DirectoryPath[MYARK_KOBJ_PATH_MAX];
} MYARK_KOBJ_DIRECTORY_INPUT, *PMYARK_KOBJ_DIRECTORY_INPUT;

#define MYARK_KOBJ_DIR_FLAG_TRUNCATED          0x1UL  // cap hit, rows dropped

typedef struct _MYARK_KOBJ_DIRECTORY_OUTPUT {
    UINT32 Count;
    UINT32 Flags;                                // MYARK_KOBJ_DIR_FLAG_*
    UINT32 OpenStatus;                           // ZwOpenDirectoryObject status
    UINT32 WalkStatus;                           // TEMP DIAG: last query status
    MYARK_KOBJ_ENTRY Entries[MYARK_KOBJ_DIR_CAP];
} MYARK_KOBJ_DIRECTORY_OUTPUT, *PMYARK_KOBJ_DIRECTORY_OUTPUT;

// ---------------------------------------------------------------------------
// 0x911 IPC_SUMMARY.
// ---------------------------------------------------------------------------

#define MYARK_KOBJ_IPC_PIPE_TRUNCATED          0x1UL
#define MYARK_KOBJ_IPC_MAILSLOT_TRUNCATED      0x1UL

typedef struct _MYARK_KOBJ_IPC_SUMMARY_OUTPUT {
    UINT32 PipeCount;
    UINT32 PipeFlags;                            // MYARK_KOBJ_IPC_PIPE_*
    UINT32 PipeOpenStatus;
    UINT32 MailslotCount;
    UINT32 MailslotFlags;                        // MYARK_KOBJ_IPC_MAILSLOT_*
    UINT32 MailslotOpenStatus;
    UINT32 PipeWalkStatus;                       // TEMP DIAG
    UINT32 MailslotWalkStatus;                   // TEMP DIAG
    MYARK_KOBJ_ENTRY Pipes[MYARK_KOBJ_PIPE_CAP];
    MYARK_KOBJ_ENTRY Mailslots[MYARK_KOBJ_MAILSLOT_CAP];
} MYARK_KOBJ_IPC_SUMMARY_OUTPUT, *PMYARK_KOBJ_IPC_SUMMARY_OUTPUT;
