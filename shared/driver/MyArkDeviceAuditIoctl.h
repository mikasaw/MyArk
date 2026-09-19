// MyArk device-audit module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xC40..0xC4F reserved for device-audit. Process 0xA00..
// 0xAFF, memory 0xB00..0xBFF, handle 0xC00..0xC0F, section 0xC10..0xC1F,
// kernel-module 0xC20..0xC2F, storage 0xC30..0xC3F -- so device-audit sits
// at 0xC40. All 5 IOCTLs follow the MyArk METHOD_BUFFERED convention.
//
// Five surfaces:
//   DEVICE_STACK       -- per-DO attached device list (top to bottom)
//   USB_TOPOLOGY       -- USBHUB / USBPORT stack under each USB root hub
//   GPU_DISPLAY         -- display adapter DOs (Dxgk* family)
//   INPUT_STACK        -- keyboard / mouse class driver stacks
//   WATCHDOG            -- WDI / WDT-related timer handles
//
// The driver does NOT actually open or IOCTL into the device -- every entry
// is a kernel-VA / driver-name tuple that R3 can correlate with public
// Win32 enumeration (SetupDi, DXGI, raw input, etc.).

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_DEVAUDIT_MODULE_ID            0x41564544UL  // 'DEVA' ASCII (LE)
#define MYARK_DEVAUDIT_NAME_MAX              64
#define MYARK_DEVAUDIT_PATH_MAX              260
#define MYARK_DEVAUDIT_DEFAULT_MAX           64
#define MYARK_DEVAUDIT_HARD_CAP              2048

//
// 5 IOCTLs (function range 0xC40..0xC44). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_DEVICE_AUDIT_QUERY_DEVICE_STACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC40, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DEVICE_AUDIT_QUERY_USB_TOPOLOGY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC41, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DEVICE_AUDIT_QUERY_GPU_DISPLAY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC42, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DEVICE_AUDIT_QUERY_INPUT_STACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC43, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DEVICE_AUDIT_QUERY_WATCHDOG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC44, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Common device entry: kernel VA + driver name + device-name fragment.
// ---------------------------------------------------------------------------

#define MYARK_DEV_FLAG_NONE                 0x00000000
#define MYARK_DEV_FLAG_PDO                  0x00000001   // physical device object (bus)
#define MYARK_DEV_FLAG_FDO                  0x00000002   // functional device object
#define MYARK_DEV_FLAG_FILTER               0x00000004   // filter DO
#define MYARK_DEV_FLAG_ATTACHED             0x00000008   // already attached to another (de-dup hint)
#define MYARK_DEV_FLAG_HIDDEN               0x00000010   // no symbolic link + no driver name

typedef struct _MYARK_DEVICE_ENTRY {
    UINT64  DeviceObjectAddress;
    UINT64  AttachedToAddress;                              // 0 if not attached
    UINT32  Flags;                                          // MYARK_DEV_FLAG_*
    UINT32  StackDepth;                                     // 0 = top of stack
    WCHAR   DriverName[MYARK_DEVAUDIT_NAME_MAX];
    WCHAR   DeviceName[MYARK_DEVAUDIT_PATH_MAX];
} MYARK_DEVICE_ENTRY, *PMYARK_DEVICE_ENTRY;

typedef struct _MYARK_DEVAUDIT_INPUT {
    UINT32  MaxEntries;                                     // 0 = driver default
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_DEVAUDIT_INPUT, *PMYARK_DEVAUDIT_INPUT;

typedef struct _MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved;
    MYARK_DEVICE_ENTRY Entries[1];
} MYARK_DEVAUDIT_DEVICE_STACK_OUTPUT, *PMYARK_DEVAUDIT_DEVICE_STACK_OUTPUT;

// ---------------------------------------------------------------------------
// USB topology: one row per USBHUB / USBPORT DO. R3 joins with SetupDi
// public data to render the tree.
// ---------------------------------------------------------------------------

#define MYARK_USB_FLAG_NONE                 0x00000000
#define MYARK_USB_FLAG_ROOT_HUB             0x00000001   // PCI-e root hub
#define MYARK_USB_FLAG_EXTERNAL_HUB         0x00000002
#define MYARK_USB_FLAG_DEVICE               0x00000004   // leaf device
#define MYARK_USB_FLAG_SUSPECT              0x00000008   // extra filter above USBHUB

typedef struct _MYARK_USB_TOPOLOGY_ENTRY {
    UINT64  DeviceObjectAddress;
    UINT32  Flags;                                          // MYARK_USB_FLAG_*
    UINT32  Depth;                                          // 0 = root hub, 1 = first tier, ...
    WCHAR   DriverName[MYARK_DEVAUDIT_NAME_MAX];
    WCHAR   DeviceName[MYARK_DEVAUDIT_PATH_MAX];
} MYARK_USB_TOPOLOGY_ENTRY, *PMYARK_USB_TOPOLOGY_ENTRY;

typedef struct _MYARK_DEVAUDIT_USB_TOPOLOGY_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  RootHubCount;
    UINT32  TotalSeen;
    MYARK_USB_TOPOLOGY_ENTRY Entries[1];
} MYARK_DEVAUDIT_USB_TOPOLOGY_OUTPUT, *PMYARK_DEVAUDIT_USB_TOPOLOGY_OUTPUT;

// ---------------------------------------------------------------------------
// GPU / display: Dxgk* family DOs.
// ---------------------------------------------------------------------------

typedef struct _MYARK_GPU_DISPLAY_ENTRY {
    UINT64  DeviceObjectAddress;
    UINT32  AdapterIndex;                                   // 0 = primary
    UINT32  Flags;                                          // MYARK_DEV_FLAG_*
    WCHAR   DriverName[MYARK_DEVAUDIT_NAME_MAX];
    WCHAR   DeviceName[MYARK_DEVAUDIT_PATH_MAX];
} MYARK_GPU_DISPLAY_ENTRY, *PMYARK_GPU_DISPLAY_ENTRY;

typedef struct _MYARK_DEVAUDIT_GPU_DISPLAY_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved;
    MYARK_GPU_DISPLAY_ENTRY Entries[1];
} MYARK_DEVAUDIT_GPU_DISPLAY_OUTPUT, *PMYARK_DEVAUDIT_GPU_DISPLAY_OUTPUT;

// ---------------------------------------------------------------------------
// Input stack: KBDCLASS / MOUCLASS and their upper / lower filters.
// ---------------------------------------------------------------------------

#define MYARK_INPUT_FLAG_NONE               0x00000000
#define MYARK_INPUT_FLAG_KEYBOARD           0x00000001
#define MYARK_INPUT_FLAG_MOUSE              0x00000002
#define MYARK_INPUT_FLAG_HID                0x00000004
#define MYARK_INPUT_FLAG_RAW                0x00000008

typedef struct _MYARK_INPUT_STACK_ENTRY {
    UINT64  DeviceObjectAddress;
    UINT32  Flags;                                          // MYARK_INPUT_FLAG_*
    UINT32  StackDepth;
    WCHAR   DriverName[MYARK_DEVAUDIT_NAME_MAX];
    WCHAR   DeviceName[MYARK_DEVAUDIT_PATH_MAX];
} MYARK_INPUT_STACK_ENTRY, *PMYARK_INPUT_STACK_ENTRY;

typedef struct _MYARK_DEVAUDIT_INPUT_STACK_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  KeyboardCount;
    UINT32  MouseCount;
    UINT32  TotalSeen;
    UINT32  Reserved;
    MYARK_INPUT_STACK_ENTRY Entries[1];
} MYARK_DEVAUDIT_INPUT_STACK_OUTPUT, *PMYARK_DEVAUDIT_INPUT_STACK_OUTPUT;

// ---------------------------------------------------------------------------
// Watchdog: timer-based watchdog devices. The driver matches on the
// \\Device\\Watchdog* naming convention (and a few other heuristics).
// ---------------------------------------------------------------------------

typedef struct _MYARK_WATCHDOG_ENTRY {
    UINT64  DeviceObjectAddress;
    UINT64  TimerObjectAddress;                             // best-effort (0 if not found)
    UINT32  Flags;                                          // MYARK_DEV_FLAG_*
    UINT32  Reserved0;
    WCHAR   DriverName[MYARK_DEVAUDIT_NAME_MAX];
    WCHAR   DeviceName[MYARK_DEVAUDIT_PATH_MAX];
} MYARK_WATCHDOG_ENTRY, *PMYARK_WATCHDOG_ENTRY;

typedef struct _MYARK_DEVAUDIT_WATCHDOG_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved;
    MYARK_WATCHDOG_ENTRY Entries[1];
} MYARK_DEVAUDIT_WATCHDOG_OUTPUT, *PMYARK_DEVAUDIT_WATCHDOG_OUTPUT;
