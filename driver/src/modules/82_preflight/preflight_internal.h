// MyArk preflight module: internal helpers.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "../../../shared/driver/MyArkPreflightIoctl.h"

#if MYARK_MODULE_PREFLIGHT

#define MYARK_TRACE_PREFLIGHT                MYARK_TRACE_MODULE

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MyArkPreflightCollectKernelInfo(
    _Out_ PMYARK_PREFLIGHT_HEALTH_OUTPUT Out);

#endif // MYARK_MODULE_PREFLIGHT