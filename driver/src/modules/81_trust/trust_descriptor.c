// MyArk trust module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkTrustIoctl.h"
#include "trust_descriptor.h"
#include "trust_internal.h"

#if MYARK_MODULE_TRUST

static MYARK_IOCTL_ENTRY g_TrustIoctls[] = {
    {
        IOCTL_MYARK_TRUST_VERIFY_PE,
        MyArkTrustIoctlVerifyPe,
        "IOCTL_MYARK_TRUST_VERIFY_PE",
        0,
        0
    },
    {
        IOCTL_MYARK_TRUST_VERIFY_CATALOG,
        MyArkTrustIoctlVerifyCatalog,
        "IOCTL_MYARK_TRUST_VERIFY_CATALOG",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Trust = {
    "trust",                                        // ModuleName
    "Trust - PE / catalog signature verification (2 IOCTLs)",
    MYARK_TRUST_MODULE_ID,                         // ModuleId ('TRUS')
    RTL_NUMBER_OF(g_TrustIoctls),                   // IoctlCount
    g_TrustIoctls,                                  // Ioctls
    MyArkTrustInit,                                 // Init
    MyArkTrustCleanup,                              // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkTrustInit(
    void)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_TRUST,
                "MyArkTrustInit: trust module linked (%lu IOCTLs)",
                (unsigned long)g_MyArkModule_Trust.IoctlCount);
    return STATUS_SUCCESS;
}

VOID
MyArkTrustCleanup(
    void)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_TRUST,
                "MyArkTrustCleanup: trust module torn down");
}

#endif // MYARK_MODULE_TRUST