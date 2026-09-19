// MyArk Core Driver: shared-memory section protocol.
//
// Some modules ship data too large to copy through the standard IOCTL
// METHOD_BUFFERED path (memory dumps, process working-set snapshots, full
// registry hive walks). For those, the driver maps a named kernel section
// that both R0 and R3 map at a well-known address; R3 reads/writes the
// mapping directly and only uses IOCTLs for the rendezvous.
//
// The section name carries a per-module tag so two modules never collide.
// The protocol here is small on purpose: just the names, the layout
// header that lives at offset 0 of every section, and the lock primitive
// used to coordinate producer/consumer across the boundary.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

//
// Section names. The kernel prefix ("\\BaseNamedObjects\\") and the R3
// prefix ("Local\\") are kept in the macro so a caller never has to know
// which side of the boundary they're on.
//
#define MYARK_SECTION_KERNEL_PREFIX        L"\\BaseNamedObjects\\"
#define MYARK_SECTION_USER_PREFIX          L"Local\\"
#define MYARK_SECTION_NAME_FORMAT          L"MyArk_%s_%u"   // ModuleName, InstanceId

//
// Layout header that sits at offset 0 of every MyArk section. Producers
// (R0) fill in ProducerId and Generation before signaling; consumers (R3)
// spin-wait on Generation until it changes, then trust the rest of the
// payload. Generation must advance by exactly 1 per produce cycle.
//
typedef struct _MYARK_SECTION_HEADER {
    UINT32  Magic;             // 'M','A','S','H' as a 32-bit little-endian
    UINT32  Size;              // total payload size including this header
    UINT32  ProducerId;        // MYARK_MODULE_ID_* of the writer
    UINT32  Generation;        // monotonic, wraps at 0xFFFFFFFF
    UINT32  PayloadOffset;     // offset to first byte of payload
    UINT32  PayloadSize;       // size of payload in bytes
} MYARK_SECTION_HEADER, *PMYARK_SECTION_HEADER;

#define MYARK_SECTION_MAGIC                0x4853414DUL  // 'MASH'

//
// Lock primitive. Producer and consumer coordinate via this 32-bit word
// (the consumer's spin is short -- under 1ms in steady state, longer is
// considered a stuck producer). Atomics are used because both sides map
// the same physical page; volatile + InterlockedXxx is the contract.
//
typedef struct _MYARK_SECTION_LOCK {
    volatile UINT32  State;    // 0 = idle, 1 = producer writing, 2 = ready
    volatile UINT32  Reserved;
} MYARK_SECTION_LOCK, *PMYARK_SECTION_LOCK;

#define MYARK_SECTION_LOCK_IDLE            0
#define MYARK_SECTION_LOCK_WRITING         1
#define MYARK_SECTION_LOCK_READY           2

//
// Build the kernel-side section name from a module name (ASCII) and
// instance id. The caller is responsible for the UNICODE_STRING buffer.
//
static __inline VOID MyArkSectionBuildKernelName(
    _Out_ UNICODE_STRING* Destination,
    _In_z_ PCSTR ModuleName,
    _In_ UINT32 InstanceId)
{
    WCHAR  buffer[64];
    RtlStringCchPrintfW(buffer, 64, MYARK_SECTION_NAME_FORMAT,
                         ModuleName, InstanceId);
    RtlInitUnicodeString(Destination, buffer);
}
