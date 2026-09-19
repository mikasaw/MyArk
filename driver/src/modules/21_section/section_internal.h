// MyArk section module: within-module offsets + helpers.
//
// CONTROL_AREA (24H2) layout -- hardcoded offsets for Windows 11 24H2.
// S7.1 (DynData) replaces these with a runtime-loaded profile.
//
//   0x00  ListEntry           -- MmControlAreaListHead linkage
//   0x10  SectionObject       -- PVOID to the SECTION
//   0x18  NumberOfSectionReferences
//   0x1C  NumberOfUserReferences
//   0x20  Flags               -- bit 0 = Image, bit 1 = MappedFile, bit 2 = Pagefile, ...
//   0x28  FileObject          -- backing file (NULL for pagefile)
//   0x30  SizeInBytes         // Actually 'SectionSize' (LARGE_INTEGER, 8 bytes)
//
// FILE_OBJECT layout -- also 24H2-hardcoded:
//   0x30  FileName            -- UNICODE_STRING (length + buffer)
//   0x58  SectionObjectPointer

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "../../../shared/driver/MyArkSectionIoctl.h"

#if MYARK_MODULE_SECTION

#define MYARK_OFF_CA_LIST_ENTRY              0x000UL
#define MYARK_OFF_CA_SECTION_OBJECT         0x010UL
#define MYARK_OFF_CA_SECTION_REFS           0x018UL
#define MYARK_OFF_CA_USER_REFS              0x01CUL
#define MYARK_OFF_CA_FLAGS                  0x020UL
#define MYARK_OFF_CA_FILE_OBJECT            0x028UL
#define MYARK_OFF_CA_SECTION_SIZE_LOW       0x030UL   // LARGE_INTEGER.QuadPart (low dword)
#define MYARK_OFF_CA_SHARED_CACHE_MAP       0x040UL   // SharedCacheMap (cache section only)

#define MYARK_CA_FLAG_IMAGE                 0x00000001UL
#define MYARK_CA_FLAG_MAPPED_FILE           0x00000002UL
#define MYARK_CA_FLAG_PAGEFILE              0x00000004UL
#define MYARK_CA_FLAG_PHYSICAL              0x00000008UL

#define MYARK_OFF_FO_FILENAME               0x030UL   // UNICODE_STRING (8 bytes total: Length + MaxLength + Buffer)
#define MYARK_OFF_FO_SECTION_OBJECT_PTR     0x058UL

//
// Global list head. Exported by ntoskrnl.exe but not declared in any
// public WDK header. Resolved at runtime via MmGetSystemRoutineAddress
// in MyArkSectionInit.
//
extern PLIST_ENTRY g_MyArkSectionMmControlAreaListHead;

#define MYARK_TRACE_SECTION                 MYARK_TRACE_MODULE

#endif // MYARK_MODULE_SECTION
