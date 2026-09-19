// MyArk shared pool-allocation wrapper.
//
// The WDK 10.0.28000 marks ExAllocatePoolWithTag deprecated in favor of
// ExAllocatePool2, but ExAllocatePool2 is only exported by ntoskrnl from
// Windows 11 (build 22000) onward. This driver must also load on
// Windows 10 1904x (only the process/thread modules are build-gated), so
// every allocation goes through this wrapper, which silences the C4996
// deprecation locally and keeps the down-level requirement documented in
// exactly one place.

#pragma once

#include <ntddk.h>

__drv_allocatesMem(Mem)
_Post_maybenull_ __inline
PVOID
MyArkAllocatePool(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag)
{
#pragma warning(push)
#pragma warning(disable: 4996)  // ExAllocatePoolWithTag: down-level load requirement (see above).
    return ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
#pragma warning(pop)
}
