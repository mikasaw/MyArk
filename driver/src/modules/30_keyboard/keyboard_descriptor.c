// MyArk keyboard module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkKeyboardIoctl.h"
#include "keyboard_descriptor.h"
#include "keyboard_internal.h"

#if MYARK_MODULE_KEYBOARD

static MYARK_IOCTL_ENTRY g_KeyboardIoctls[] = {
    {
        IOCTL_MYARK_KEYBOARD_ENUM_HOTKEYS,
        MyArkKeyboardIoctlEnumHotkeys,
        "IOCTL_MYARK_KEYBOARD_ENUM_HOTKEYS",
        0,
        0
    },
    {
        IOCTL_MYARK_KEYBOARD_ENUM_HOOKS,
        MyArkKeyboardIoctlEnumHooks,
        "IOCTL_MYARK_KEYBOARD_ENUM_HOOKS",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Keyboard = {
    "keyboard",                                    // ModuleName
    "Keyboard module - win32k tagTHREADINFO+tagHOOK walker (2 IOCTL)",
    MYARK_KEYBOARD_MODULE_ID,                      // ModuleId ('KYBD')
    RTL_NUMBER_OF(g_KeyboardIoctls),                // IoctlCount
    g_KeyboardIoctls,                               // Ioctls
    MyArkKeyboardInit,                              // Init
    MyArkKeyboardCleanup,                           // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkKeyboardInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_KEYBOARD,
                "MyArkKeyboardInit: keyboard module linked (%lu IOCTL)",
                (unsigned long)g_MyArkModule_Keyboard.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkKeyboardCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_KEYBOARD,
                "MyArkKeyboardCleanup: keyboard module torn down");
}

#endif // MYARK_MODULE_KEYBOARD
