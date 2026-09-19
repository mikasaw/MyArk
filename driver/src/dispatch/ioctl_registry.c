// MyArk Core Driver: global IOCTL dispatch table implementation.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "ioctl_registry.h"

//
// Storage is zero-initialised by the loader; we still call RtlZeroMemory on
// init to make the "empty table" state obvious in debugger dumps and to
// guard against any future relocation / driver-image edits that bypass the
// zero init.
//
MYARK_IOCTL_ENTRY g_IoctlTable[MYARK_MAX_IOCTLS];
UINT32            g_IoctlCount = 0;

NTSTATUS
MyArkIoctlRegistryInit(
    VOID)
{
    RtlZeroMemory(g_IoctlTable, sizeof(g_IoctlTable));
    g_IoctlCount = 0;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DISPATCH,
                "MyArkIoctlRegistryInit: table cleared");

    return STATUS_SUCCESS;
}

NTSTATUS
MyArkIoctlRegistryAdd(
    _In_reads_(Count) PMYARK_IOCTL_ENTRY Entries,
    _In_ UINT32 Count)
{
    UINT32 i;

    if (Entries == NULL || Count == 0) {
        return STATUS_SUCCESS;
    }

    for (i = 0; i < Count; i++) {
        ULONG                  ioctlCode = Entries[i].IoctlCode;
        MYARK_IOCTL_HANDLER    handler    = Entries[i].Handler;
        PCSTR                  name       = Entries[i].Name;

        if (handler == NULL) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        MYARK_TRACE_DISPATCH,
                        "MyArkIoctlRegistryAdd: entry %u (%s) has NULL handler",
                        i, name ? name : "?");
            continue;
        }

        if (g_IoctlCount >= MYARK_MAX_IOCTLS) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        MYARK_TRACE_DISPATCH,
                        "MyArkIoctlRegistryAdd: table full at %u entries",
                        g_IoctlCount);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (MyArkIoctlFind(ioctlCode) != NULL) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        MYARK_TRACE_DISPATCH,
                        "MyArkIoctlRegistryAdd: duplicate IOCTL 0x%08lX (%s)",
                        ioctlCode,
                        name ? name : "?");
            return STATUS_DUPLICATE_OBJECTID;
        }

        g_IoctlTable[g_IoctlCount] = Entries[i];
        g_IoctlCount++;

        TraceEvents(TRACE_LEVEL_INFORMATION,
                    MYARK_TRACE_DISPATCH,
                    "MyArkIoctlRegistryAdd: registered 0x%08lX (%s)",
                    ioctlCode,
                    name ? name : "?");
    }

    return STATUS_SUCCESS;
}

PMYARK_IOCTL_ENTRY
MyArkIoctlFind(
    _In_ ULONG IoctlCode)
{
    for (UINT32 i = 0; i < g_IoctlCount; i++) {
        if (g_IoctlTable[i].IoctlCode == IoctlCode) {
            return &g_IoctlTable[i];
        }
    }
    return NULL;
}

VOID
MyArkIoctlRegistryReset(
    VOID)
{
    RtlZeroMemory(g_IoctlTable, sizeof(g_IoctlTable));
    g_IoctlCount = 0;
}