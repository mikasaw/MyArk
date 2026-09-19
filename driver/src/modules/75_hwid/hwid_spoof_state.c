// MyArk hwid module: R3-1 spoof engine state + attachment plumbing.
//
// The dispatch router: the driver object's MajorFunction table is owned
// by WDF after WdfDriverCreate. Filter device objects created for the
// spoof attachments receive IRPs through the same table, so at first
// attach the router wraps every major: IRPs aimed at a filter DO
// (recognized by the 'HWFE' extension) take the filter path (remove
// lock, optional completion routine, pass down); everything else goes
// to the saved WDF handler untouched. The router is removed when the
// last attachment detaches.

#include "hwid_spoof_internal.h"
#include "../../framework/core_globals.h"

#if MYARK_MODULE_HWID

#define MYARK_TRACE_SPOOF "[hwid-spoof] "

static EX_SPIN_LOCK               g_MyArkHwidSpoofLock;
static MYARK_HWID_SPOOF_CLASS_STATE g_MyArkHwidSpoofClasses[MYARK_HWID_SPOOF_CLASS_COUNT];

ULONG
MyArkHwidSpoofLockShared(VOID)
{
    return (ULONG)ExAcquireSpinLockShared(&g_MyArkHwidSpoofLock);
}

VOID
MyArkHwidSpoofUnlockShared(_In_ ULONG OldIrql)
{
    ExReleaseSpinLockShared(&g_MyArkHwidSpoofLock, (KIRQL)OldIrql);
}

ULONG
MyArkHwidSpoofLockExclusive(VOID)
{
    return (ULONG)ExAcquireSpinLockExclusive(&g_MyArkHwidSpoofLock);
}

VOID
MyArkHwidSpoofUnlockExclusive(_In_ ULONG OldIrql)
{
    ExReleaseSpinLockExclusive(&g_MyArkHwidSpoofLock, (KIRQL)OldIrql);
}

// Dispatch-router plumbing (guarded by g_MyArkHwidRouterLock).
static EX_SPIN_LOCK   g_MyArkHwidRouterLock;
static ULONG          g_MyArkHwidRouterRefs = 0;
static PDRIVER_DISPATCH g_MyArkHwidRouterOriginal[IRP_MJ_MAXIMUM_FUNCTION + 1];

static DRIVER_DISPATCH MyArkHwidSpoofDispatchRouter;
static IO_COMPLETION_ROUTINE MyArkHwidSpoofPassComplete;
static IO_COMPLETION_ROUTINE MyArkHwidSpoofControlComplete;

PMYARK_HWID_SPOOF_CLASS_STATE
MyArkHwidSpoofClassState(_In_ UINT32 Class)
{
    if (Class == 0 || Class > MYARK_HWID_SPOOF_CLASS_COUNT) {
        return NULL;
    }
    return &g_MyArkHwidSpoofClasses[Class - 1];
}

NTSTATUS
MyArkHwidSpoofEngineInit(VOID)
{
    ULONG i;

    RtlZeroMemory(&g_MyArkHwidSpoofClasses, sizeof(g_MyArkHwidSpoofClasses));
    RtlZeroMemory(&g_MyArkHwidRouterOriginal, sizeof(g_MyArkHwidRouterOriginal));
    g_MyArkHwidRouterRefs = 0;
    for (i = 0; i < MYARK_HWID_SPOOF_CLASS_COUNT; i++) {
        g_MyArkHwidSpoofClasses[i].Class = i + 1;
    }
    return STATUS_SUCCESS;
}

//
// Router: only filter DOs created by this engine carry the 'HWFE'
// extension; everything else (including the WDF control device) goes to
// the saved handler.
//
static
NTSTATUS
MyArkHwidSpoofDispatchRouter(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP        Irp)
{
    PMYARK_HWID_FILTER_EXT ext;
    PIO_STACK_LOCATION     slot;
    PDRIVER_DISPATCH       original;

    ext = (PMYARK_HWID_FILTER_EXT)DeviceObject->DeviceExtension;
    if (ext == NULL || ext->Magic != MYARK_HWID_FILTER_EXT_MAGIC) {
        slot = IoGetCurrentIrpStackLocation(Irp);
        original = (slot->MajorFunction <= IRP_MJ_MAXIMUM_FUNCTION)
                       ? g_MyArkHwidRouterOriginal[slot->MajorFunction]
                       : NULL;
        if (original == NULL) {
            // Should not happen: router majors always have a saved handler.
            Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        return original(DeviceObject, Irp);
    }

    IoAcquireRemoveLock(&ext->RemoveLock, Irp);

    slot = IoGetCurrentIrpStackLocation(Irp);
    if (ext->Class == MYARK_HWID_SPOOF_CLASS_ARP) {
        // ARP class: capture context + control completion on EVERY major
        // (bring-up instrumentation showed zero device-controls reaching
        // the filter; non-device-control tuples locate where traffic goes).
        PVOID captured = MyArkHwidArpCaptureRequestContext(ext, Irp, slot);
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               MyArkHwidSpoofControlComplete,
                               captured,
                               TRUE, TRUE, TRUE);
    } else if (slot->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        PVOID captured = MyArkHwidCaptureQueryContext(ext, Irp, slot);
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               MyArkHwidSpoofControlComplete,
                               captured,
                               TRUE, TRUE, TRUE);
    } else {
        // Pass down; release the lock from a stack completion.
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               MyArkHwidSpoofPassComplete,
                               ext,
                               TRUE, TRUE, TRUE);
    }

    return IoCallDriver(ext->TargetDevice, Irp);
}

static
NTSTATUS
MyArkHwidSpoofPassComplete(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP        Irp,
    _In_opt_ PVOID      Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }
    if (Context != NULL) {
        // Context is the FILTER EXTENSION, not the lock itself: release
        // through the RemoveLock member. Casting Context to PIO_REMOVE_LOCK
        // releases a lock "at ext+0" (the Magic field) and bugchecks 0xA in
        // KeSetEvent (MEMORY_0128.DMP / MEMORY_0205.DMP, same hash).
        IoReleaseRemoveLock(&((PMYARK_HWID_FILTER_EXT)Context)->RemoveLock, Irp);
    }
    return STATUS_SUCCESS;
}

//
// DEVICE_CONTROL completion: counters run here (post-op), then the lock
// the dispatch acquired is released. The actual buffer rewrite lives in
// hwid_spoof_disk.c and is invoked only for successful queries while the
// owning class is active.
//
static
NTSTATUS
MyArkHwidSpoofControlComplete(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP        Irp,
    _In_opt_ PVOID      Context)
{
    PMYARK_HWID_FILTER_EXT ext;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }

    ext = MyArkHwidExtFromContext(Context);
    if (ext->Class == MYARK_HWID_SPOOF_CLASS_ARP) {
        MyArkHwidArpControlComplete(ext, Context, Irp);
    } else {
        MyArkHwidRewriteControlBuffer(Context, Irp);
    }
    MyArkHwidFreeQueryContext(Context);

    IoReleaseRemoveLock(&ext->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

//
// Install the router on every major the first time (refs 0 -> 1) and
// remove it when the last attachment goes away. The saved handler is
// captured per major only once.
//
static
NTSTATUS
MyArkHwidSpoofRouterAcquire(VOID)
{
    PDRIVER_OBJECT driverObject = g_MyArkCoreDriverObject;
    ULONG          major;
    KIRQL          oldIrql;

    if (driverObject == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    oldIrql = ExAcquireSpinLockExclusive(&g_MyArkHwidRouterLock);
    if (g_MyArkHwidRouterRefs == 0) {
        for (major = 0; major <= IRP_MJ_MAXIMUM_FUNCTION; major++) {
            g_MyArkHwidRouterOriginal[major] = driverObject->MajorFunction[major];
            driverObject->MajorFunction[major] = MyArkHwidSpoofDispatchRouter;
        }
    }
    g_MyArkHwidRouterRefs++;
    ExReleaseSpinLockExclusive(&g_MyArkHwidRouterLock, oldIrql);
    return STATUS_SUCCESS;
}

static
VOID
MyArkHwidSpoofRouterRelease(VOID)
{
    PDRIVER_OBJECT driverObject = g_MyArkCoreDriverObject;
    ULONG          major;
    KIRQL          oldIrql;

    if (driverObject == NULL) {
        return;
    }

    oldIrql = ExAcquireSpinLockExclusive(&g_MyArkHwidRouterLock);
    if (g_MyArkHwidRouterRefs > 0) {
        g_MyArkHwidRouterRefs--;
        if (g_MyArkHwidRouterRefs == 0) {
            for (major = 0; major <= IRP_MJ_MAXIMUM_FUNCTION; major++) {
                driverObject->MajorFunction[major] = g_MyArkHwidRouterOriginal[major];
                g_MyArkHwidRouterOriginal[major] = NULL;
            }
        }
    }
    ExReleaseSpinLockExclusive(&g_MyArkHwidRouterLock, oldIrql);
}

//
// Attach one filter DO on top of the named target. Returns the extension
// (owned by the caller's attachment array). PASSIVE_LEVEL only.
//
static
NTSTATUS
MyArkHwidSpoofAttachOne(
    _In_  ULONG                    Class,
    _In_  PUNICODE_STRING          TargetName,
    _In_  ULONG                    TargetKind,
    _In_  ULONG                    TargetIndex,
    _Out_ PMYARK_HWID_FILTER_EXT*  ExtOut)
{
    PMYARK_HWID_FILTER_EXT ext = NULL;
    PDEVICE_OBJECT         baseDevice = NULL;
    PFILE_OBJECT           fileObject = NULL;
    PDEVICE_OBJECT         filterDo = NULL;
    PDEVICE_OBJECT         attachedTo = NULL;
    NTSTATUS               status;

    *ExtOut = NULL;

    status = IoGetDeviceObjectPointer(TargetName,
                                      FILE_READ_ATTRIBUTES,
                                      &fileObject,
                                      &baseDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateDevice(g_MyArkCoreDriverObject,
                            sizeof(MYARK_HWID_FILTER_EXT),
                            NULL,                    // unnamed filter DO
                            baseDevice->DeviceType,
                            0,
                            FALSE,
                            &filterDo);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(fileObject);
        return status;
    }

    ext = (PMYARK_HWID_FILTER_EXT)filterDo->DeviceExtension;
    RtlZeroMemory(ext, sizeof(*ext));
    ext->Magic = MYARK_HWID_FILTER_EXT_MAGIC;
    ext->Class = Class;
    ext->TargetKind = TargetKind;
    ext->TargetIndex = TargetIndex;
    ext->FilterDo = filterDo;
    // MUST happen before IoAttachDeviceToDeviceStackSafe: attaching
    // publishes the DO into the stack and completions (e.g. partmgr
    // finishing WMI system-control IRPs directly) can run against this
    // extension immediately -- a zeroed lock bugchecked 0xA at DISPATCH
    // in MyArkHwidSpoofPassComplete (MEMORY_0128.DMP, 2026-09-17).
    IoInitializeRemoveLock(&ext->RemoveLock, MYARK_HWID_FILTER_EXT_MAGIC, 0, 0);

    // Mirror the buffering strategy of the target stack.
    filterDo->Flags |= (baseDevice->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO));
    filterDo->AlignmentRequirement = baseDevice->AlignmentRequirement;
    filterDo->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoAttachDeviceToDeviceStackSafe(filterDo,
                                             baseDevice,
                                             &attachedTo);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(filterDo);
        ObDereferenceObject(fileObject);
        return status;
    }

    ext->TargetDevice = attachedTo;
    ext->TargetFileObject = fileObject;

    *ExtOut = ext;
    return STATUS_SUCCESS;
}

//
// Detach one filter DO. Waits for in-flight IRPs before deleting.
// PASSIVE_LEVEL only.
//
static
VOID
MyArkHwidSpoofDetachOne(
    _In_ PMYARK_HWID_FILTER_EXT Ext)
{
    IoReleaseRemoveLockAndWait(&Ext->RemoveLock, Ext->FilterDo);

    if (Ext->TargetDevice != NULL) {
        IoDetachDevice(Ext->TargetDevice);
        Ext->TargetDevice = NULL;
    }
    if (Ext->TargetFileObject != NULL) {
        ObDereferenceObject(Ext->TargetFileObject);
        Ext->TargetFileObject = NULL;
    }
    if (Ext->FilterDo != NULL) {
        IoDeleteDevice(Ext->FilterDo);
        Ext->FilterDo = NULL;
    }
}

//
// Detach every attachment of one class. Releases one router reference
// per detached attachment so callers never touch the refcount. Caller
// holds the exclusive class lock.
//
VOID
MyArkHwidSpoofDetachClassLocked(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State)
{
    ULONG i;

    State->Active = FALSE;
    for (i = 0; i < MYARK_HWID_SPOOF_MAX_ATTACH; i++) {
        if (State->Attachments[i] != NULL) {
            MyArkHwidSpoofDetachOne(State->Attachments[i]);
            State->Attachments[i] = NULL;
            MyArkHwidSpoofRouterRelease();
        }
    }
    State->AttachedCount = 0;
}

//
// Attach helper used by the disk engine: acquires the router once per
// class activation.
//
NTSTATUS
MyArkHwidSpoofAttachTarget(
    _In_    ULONG                            Class,
    _In_    PUNICODE_STRING                  TargetName,
    _In_    ULONG                            TargetKind,
    _In_    ULONG                            TargetIndex,
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE    State)
{
    PMYARK_HWID_FILTER_EXT ext = NULL;
    NTSTATUS               status;
    ULONG                  slot;
    KIRQL                  oldIrql;

    status = MyArkHwidSpoofRouterAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkHwidSpoofAttachOne(Class, TargetName, TargetKind, TargetIndex, &ext);
    if (!NT_SUCCESS(status)) {
        MyArkHwidSpoofRouterRelease();
        return status;
    }

    oldIrql = ExAcquireSpinLockExclusive(&g_MyArkHwidSpoofLock);
    for (slot = 0; slot < MYARK_HWID_SPOOF_MAX_ATTACH; slot++) {
        if (State->Attachments[slot] == NULL) {
            State->Attachments[slot] = ext;
            break;
        }
    }
    if (slot == MYARK_HWID_SPOOF_MAX_ATTACH) {
        ExReleaseSpinLockExclusive(&g_MyArkHwidSpoofLock, oldIrql);
        MyArkHwidSpoofDetachOne(ext);
        MyArkHwidSpoofRouterRelease();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    State->AttachedCount++;
    ExReleaseSpinLockExclusive(&g_MyArkHwidSpoofLock, oldIrql);

    return STATUS_SUCCESS;
}

VOID
MyArkHwidSpoofEngineTeardown(VOID)
{
    ULONG i;

    for (i = 0; i < MYARK_HWID_SPOOF_CLASS_COUNT; i++) {
        PMYARK_HWID_SPOOF_CLASS_STATE state = &g_MyArkHwidSpoofClasses[i];

        if (state->AttachedCount != 0) {
            MyArkHwidSpoofDetachClassLocked(state);
        }
        state->Active = FALSE;
        state->CacheValid = FALSE;
        if (i + 1 == MYARK_HWID_SPOOF_CLASS_ARP) {
            // P2 (review): teardown must clear the capture-armed flag so
            // 0x754 cannot report armed=1 after the engine is gone.
            MyArkHwidSpoofArpCaptureStop(state);
        }
    }
}

#endif // MYARK_MODULE_HWID
