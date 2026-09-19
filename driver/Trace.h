// MyArk Core Driver tracing.
//
// S1.3 skeleton uses KdPrintEx-based traces. Migrate to WPP when the IOCTL
// dispatch / per-module tracing grows past simple driver-load logs.

#pragma once

#include <ntddk.h>

#define TRACE_LEVEL_ERROR           0
#define TRACE_LEVEL_WARNING         1
#define TRACE_LEVEL_INFORMATION     2
#define TRACE_LEVEL_VERBOSE         3

#define MYARK_TRACE_DRIVER          0x00000001UL
#define MYARK_TRACE_DEVICE          0x00000002UL
#define MYARK_TRACE_QUEUE           0x00000004UL
#define MYARK_TRACE_DISPATCH        0x00000008UL
#define MYARK_TRACE_MODULE          0x00000010UL

static __forceinline ULONG
MyArkKdLevelFor(_In_ ULONG Level)
{
    if (Level == TRACE_LEVEL_ERROR)   return DPFLTR_ERROR_LEVEL;
    if (Level == TRACE_LEVEL_WARNING) return DPFLTR_WARNING_LEVEL;
    return DPFLTR_TRACE_LEVEL;
}

static __forceinline PCSTR
MyArkTraceTagFor(_In_ ULONG Flag)
{
    switch (Flag) {
    case MYARK_TRACE_DEVICE:   return "[MyArkCore:DEV ] ";
    case MYARK_TRACE_QUEUE:    return "[MyArkCore:Q   ] ";
    case MYARK_TRACE_DISPATCH: return "[MyArkCore:DISP] ";
    case MYARK_TRACE_MODULE:   return "[MyArkCore:MOD ] ";
    default:                   return "[MyArkCore:DRV ] ";
    }
}

#define TraceEvents(Level, Flag, Fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, \
               MyArkKdLevelFor(Level), \
               "%s" Fmt "\n", \
               MyArkTraceTagFor(Flag), \
               __VA_ARGS__)

#define WPP_INIT_TRACING(DriverObject, RegistryPath) ((VOID)0)
#define WPP_CLEANUP_TRACING(DriverObject)             ((VOID)0)
