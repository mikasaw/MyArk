// MyArk Core Driver: declaration of the EvtIoDeviceControl handler.

#pragma once

#include <ntddk.h>
#include <wdf.h>

VOID MyArkCoreEvtIoDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode);