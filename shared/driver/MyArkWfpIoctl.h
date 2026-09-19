// MyArk WFP module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x720..0x722 reserved for the WFP (Windows Filtering
// Platform) module (S7.3). WFP inspection is read-only: the IOCTL set
// enumerates the active callouts / layers on the running build. The
// ADD / REMOVE IOCTLs are reserved for a follow-up stage (S7.3-fix) and
// return STATUS_NOT_IMPLEMENTED on dispatch so the wiring exists end-
// to-end but no mutating path is reachable.
//
// The 3 IOCTLs:
//
//   0x720  ENUMERATE_CALLOUTS - All registered FWPS_CALLOUT entries
//   0x721  ADD_CALLOUT        - Register a callout (reserved; S7.3-fix)
//   0x722  REMOVE_CALLOUT     - Deregister a callout (reserved; S7.3-fix)
//
// All 3 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_WFP_MODULE_ID                  0x57465000UL  // 'WFP\0' ASCII (LE)
#define MYARK_WFP_NAME_MAX                   64
#define MYARK_WFP_LAYER_GUID_MAX             40
#define MYARK_WFP_CALLOUT_HARD_CAP           128

//
// 3 IOCTLs (function range 0x720..0x722). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_WFP_ENUMERATE_CALLOUTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x720, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_WFP_ADD_CALLOUT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x721, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_WFP_REMOVE_CALLOUT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x722, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// ---------------------------------------------------------------------------
// ENUMERATE_CALLOUTS: list every registered FWPS_CALLOUT. Each row carries
// the callout key GUID (16 bytes), the associated layer GUID, and the
// flags. The driver resolves callouts at Init() time via
// FwpsCalloutEnumerate; rows are emitted into the caller's output buffer.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_WFP_CALLOUT_ENTRY {
    UINT8   CalloutKey[16];                       // FWPS_CALLOUT calloutKey
    UINT8   ApplicableLayer[16];                  // GUID of the layer
    UINT32  Flags;                                // FWPS_CALLOUT flags
    UINT32  Reserved;
    WCHAR   CalloutName[MYARK_WFP_NAME_MAX];      // UTF-16 best-effort name
} MYARK_WFP_CALLOUT_ENTRY, *PMYARK_WFP_CALLOUT_ENTRY;

typedef struct _MYARK_WFP_ENUMERATE_CALLOUTS_OUTPUT {
    UINT32  Count;
    UINT32  Reserved;
    MYARK_WFP_CALLOUT_ENTRY Entries[1];           // variable-length tail
} MYARK_WFP_ENUMERATE_CALLOUTS_OUTPUT, *PMYARK_WFP_ENUMERATE_CALLOUTS_OUTPUT;

//
// ADD_CALLOUT / REMOVE_CALLOUT input struct (reserved; S7.3-fix).
// ---------------------------------------------------------------------------
typedef struct _MYARK_WFP_CALLOUT_OP_INPUT {
    UINT8   CalloutKey[16];
    UINT8   ApplicableLayer[16];
    UINT32  Flags;
    UINT32  Reserved;
} MYARK_WFP_CALLOUT_OP_INPUT, *PMYARK_WFP_CALLOUT_OP_INPUT;

//
// ---------------------------------------------------------------------------
// R3-15 (2026-09-16): system network-filter inventory, both halves of the
// "who can touch my packets" question, read-only:
//
//   0x8A2  ENUM_NDIS_FILTERS     - every NDIS filter instance installed on
//                                  the system, from the NetService network
//                                  class (documented Zw registry walk):
//                                  service name, instance GUID, friendly
//                                  name. The live per-adapter attach order
//                                  is only visible to INF-installed filter
//                                  drivers and is intentionally out of
//                                  scope (a runtime registration never
//                                  receives bind notifications).
//   0x8A3  ENUM_CALLOUT_DRIVERS  - every loaded driver whose PE import
//                                  table references fwpkclnt.sys (WFP
//                                  callout capable) and/or ndis.sys, via
//                                  the established PsLoadedModuleList walk.
//                                  Best-effort: a driver whose import
//                                  directory cannot be parsed is listed
//                                  with FLAG_PARSE_FAILED, never skipped.
//
// 0x720..0x722 remain the callout add/remove scaffold. Both new IOCTLs
// use the MyArk METHOD_BUFFERED convention.
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_WFP_ENUM_NDIS_FILTERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_WFP_ENUM_CALLOUT_DRIVERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_WFP_NDIS_NAME_MAX              64
#define MYARK_WFP_NDIS_GUID_MAX              40
#define MYARK_WFP_NDIS_HARD_CAP              128
#define MYARK_WFP_CDRIVER_NAME_MAX           64
#define MYARK_WFP_CDRIVER_HARD_CAP           256

//
// 0x8A2 output row. All strings are ANSI renderings of the UTF-16
// registry names (low byte, NUL-terminated): non-ASCII friendly names
// (localized connection names) are intentionally mangled. Layout scope:
// legacy class\<service>\<instance>\Connection rows on 1903..22631;
// Win11 26100+ GUID-named install records are emitted with
// ServiceName=ComponentId, InstanceGuid=record key name.
//
typedef struct _MYARK_WFP_NDIS_FILTER_ENTRY {
    CHAR    ServiceName[MYARK_WFP_NDIS_NAME_MAX];   // e.g. "ms_lltdio"
    CHAR    InstanceGuid[MYARK_WFP_NDIS_GUID_MAX];  // instance key name
    CHAR    FriendlyName[MYARK_WFP_NDIS_NAME_MAX];  // Connection\Name (may be "")
} MYARK_WFP_NDIS_FILTER_ENTRY, *PMYARK_WFP_NDIS_FILTER_ENTRY;

typedef struct _MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT {
    UINT32  Count;                                 // rows in Entries[]
    UINT32  EntryStructSize;
    UINT32  Reserved;
    UINT32  Reserved2;
    MYARK_WFP_NDIS_FILTER_ENTRY Entries[1];        // variable-length tail
} MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT, *PMYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT;

//
// 0x8A3 output row flags.
//
#define MYARK_WFP_CDRIVER_FLAG_WFP_CAPABLE      0x00000001UL  // fwpkclnt.sys
#define MYARK_WFP_CDRIVER_FLAG_NDIS_CAPABLE     0x00000002UL  // ndis.sys
#define MYARK_WFP_CDRIVER_FLAG_PARSE_FAILED     0x00000004UL  // unreadable PE

typedef struct _MYARK_WFP_CALLOUT_DRIVER_ENTRY {
    UINT64  ImageBase;
    UINT64  ImageSize;
    UINT32  Flags;
    UINT32  Reserved;
    CHAR    Name[MYARK_WFP_CDRIVER_NAME_MAX];
} MYARK_WFP_CALLOUT_DRIVER_ENTRY, *PMYARK_WFP_CALLOUT_DRIVER_ENTRY;

typedef struct _MYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT {
    UINT32  Count;                                 // rows in Entries[]
    UINT32  TotalSeen;                             // modules walked
    UINT32  EntryStructSize;
    UINT32  Reserved;
    UINT64  PsLoadedModuleList;                    // 0 when unresolved
    MYARK_WFP_CALLOUT_DRIVER_ENTRY Entries[1];     // variable-length tail
} MYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT, *PMYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT;

C_ASSERT(sizeof(MYARK_WFP_NDIS_FILTER_ENTRY) == 64 + 40 + 64);
C_ASSERT(sizeof(MYARK_WFP_CALLOUT_DRIVER_ENTRY) == 16 + 4 + 4 + 64);
C_ASSERT(sizeof(MYARK_WFP_ENUM_NDIS_FILTERS_OUTPUT) == 16 + sizeof(MYARK_WFP_NDIS_FILTER_ENTRY));
C_ASSERT(sizeof(MYARK_WFP_ENUM_CALLOUT_DRIVERS_OUTPUT) == 24 + sizeof(MYARK_WFP_CALLOUT_DRIVER_ENTRY));
