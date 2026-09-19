// MyArk capability module: internal helpers.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "module_descriptor.h"
#include "../../../shared/driver/MyArkCapabilityIoctl.h"

#if MYARK_MODULE_CAPABILITY

#pragma warning(push)
#pragma warning(disable: 4201)

#define MYARK_TRACE_CAPABILITY                MYARK_TRACE_MODULE

//
// Copy one descriptor's module name (UTF-8) into the UTF-16 destination
// buffer. Truncates gracefully when the source is longer than the
// destination; the resulting WCHAR count never exceeds MYARK_CAPABILITY_NAME_MAX.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
MyArkCapabilityCopyModuleName(
    _Out_writes_(MYARK_CAPABILITY_NAME_MAX) PWCHAR  Destination,
    _In_                                      PCSTR  Source);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
MyArkCapabilityEmitOne(
    _Out_writes_(MYARK_CAPABILITY_HARD_CAP) PMYARK_CAPABILITY_MODULE_ENTRY Destination,
    _In_                                     PMYARK_MODULE_DESCRIPTOR       Source,
    _In_                                     UINT32                          Index);

#pragma warning(pop)

#endif // MYARK_MODULE_CAPABILITY