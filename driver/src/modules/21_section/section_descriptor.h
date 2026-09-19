// MyArk section module: descriptor + Init / Cleanup + IOCTL table.
//
// Walks the global MmControlAreaListHead to surface every mapped section
// in the system. QUERY_PROCESS reports the sections owned by a single
// process (heuristic); QUERY_FILE_MAPPINGS lists every ControlArea + its
// backing FileObject.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_SECTION

NTSTATUS MyArkSectionInit(VOID);
VOID     MyArkSectionCleanup(VOID);

NTSTATUS MyArkSectionIoctlQueryProcess(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkSectionIoctlQueryFileMappings(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Section;

#endif // MYARK_MODULE_SECTION
