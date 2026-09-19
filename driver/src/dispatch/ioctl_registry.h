// MyArk Core Driver: global IOCTL dispatch table.
//
// g_IoctlTable is the runtime lookup table that maps an incoming IOCTL
// code to a handler. Each module contributes zero or more MYARK_IOCTL_ENTRY
// entries during its Init(); MyArkIoctlRegistryAdd() copies them in and
// rejects any IOCTL code that collides with an already-registered one.
//
// Lookup is O(g_IoctlCount) which is acceptable while MYARK_MAX_IOCTLS=256.
// A future stage can swap in a hash table without changing callers.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "MyArkCoreIoctl.h"

#define MYARK_MAX_IOCTLS                  256

typedef NTSTATUS (*MYARK_IOCTL_HANDLER)(
    _In_     WDFDEVICE  Device,
    _In_     WDFREQUEST Request,
    _In_     size_t     InputBufferLength,
    _In_     size_t     OutputBufferLength,
    _Out_    size_t*    BytesReturned);

typedef struct _MYARK_IOCTL_ENTRY {
    ULONG                IoctlCode;
    MYARK_IOCTL_HANDLER  Handler;
    PCSTR                Name;
    ULONG                RequiredCapability;
    ULONG                Flags;
} MYARK_IOCTL_ENTRY, *PMYARK_IOCTL_ENTRY;

extern MYARK_IOCTL_ENTRY g_IoctlTable[MYARK_MAX_IOCTLS];
extern UINT32            g_IoctlCount;

NTSTATUS  MyArkIoctlRegistryInit(VOID);
NTSTATUS  MyArkIoctlRegistryAdd(_In_reads_(Count) PMYARK_IOCTL_ENTRY Entries,
                                _In_ UINT32 Count);
PMYARK_IOCTL_ENTRY MyArkIoctlFind(_In_ ULONG IoctlCode);
VOID      MyArkIoctlRegistryReset(VOID);