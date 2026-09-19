// MyArk trust module: internal helpers.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "../../../shared/driver/MyArkTrustIoctl.h"

#if MYARK_MODULE_TRUST

#define MYARK_TRACE_TRUST                    MYARK_TRACE_MODULE

#endif // MYARK_MODULE_TRUST