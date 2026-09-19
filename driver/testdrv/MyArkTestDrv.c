// MyArkTestDrv: minimal unload-capable WDM driver used as the R2-5
// FORCE_UNLOAD acceptance target. No device, no IOCTLs -- it exists so
// the regression can install, load, unload and delete a disposable
// kernel driver without touching MyArkCore or any boot-critical image.

#include <ntddk.h>

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}
