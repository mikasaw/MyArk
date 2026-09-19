// MyArk CPU module: internal types + capture API.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "myark_config.h"
#include "../../../shared/driver/MyArkCpuIoctl.h"

#if MYARK_MODULE_CPU

#define MYARK_TRACE_CPU "[cpu] "

// Runs the broadcast capture into Output (nonpaged). The per-CPU writer
// executes at IPI_LEVEL on each processor; only register reads and writes
// to the nonpaged output array happen there.
NTSTATUS
MyArkCpuCaptureSnapshot(
    _Out_ PMYARK_CPU_SNAPSHOT_OUTPUT Output);

// IOCTL handler (cpu_ioctl.c).
NTSTATUS
MyArkCpuIoctlSnapshot(
    _In_ WDFDEVICE  Device,
    _In_ WDFREQUEST Request,
    _In_ size_t     InputBufferLength,
    _In_ size_t     OutputBufferLength,
    _Out_ size_t*   BytesReturned);

#endif // MYARK_MODULE_CPU
