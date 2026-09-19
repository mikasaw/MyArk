// MyArk Core Driver: OS build gate for hardcoded kernel-struct offsets.
//
// The 10_process / 11_thread modules walk EPROCESS / ETHREAD through byte
// offsets extracted from Windows 11 24H2 (build 26100; 25H2 shares them
// via the 26200 enablement package). On any other build those offsets are
// garbage -- dereferencing them silently corrupts or blue-screens. Modules
// that use such offsets MUST call MyArkOsBuildSupported() in their Init
// and refuse to load when it returns FALSE, so the loader skips them
// cleanly (R3 sees the module absent from `driver modules`) instead of
// reading wrong memory.

#pragma once

#include <ntddk.h>

#define MYARK_MIN_SUPPORTED_BUILD   26100
#define MYARK_MAX_SUPPORTED_BUILD   26299

__forceinline BOOLEAN
MyArkOsBuildSupported(
    VOID)
{
    RTL_OSVERSIONINFOW info;

    RtlZeroMemory(&info, sizeof(info));
    info.dwOSVersionInfoSize = sizeof(info);

    if (!NT_SUCCESS(RtlGetVersion(&info))) {
        return FALSE;   // unknown OS: fail closed
    }

    return info.dwBuildNumber >= MYARK_MIN_SUPPORTED_BUILD &&
           info.dwBuildNumber <= MYARK_MAX_SUPPORTED_BUILD;
}
