// MyArk Core Driver: process-wide globals shared between framework and
// modules.
//
// Module Init()/Cleanup() take no parameters, so anything a module needs
// from DriverEntry must be parked here. g_MyArkCoreDriverObject is captured
// before MyArkModuleLoaderLoadAll() runs; the file-monitor module needs it
// for FltRegisterFilter (minifilters register against the WDM driver
// object, which WDF does not expose to module code). g_MyArkCoreServiceKey
// is a deep copy of DriverEntry's RegistryPath (the WDM DRIVER_OBJECT does
// not carry it as a member); the file-monitor module appends "\Instances"
// to it when provisioning FLTMGR instance configuration.

#pragma once

#include <ntddk.h>

extern PDRIVER_OBJECT g_MyArkCoreDriverObject;

#define MYARK_CORE_SERVICE_KEY_CHARS 512

extern WCHAR g_MyArkCoreServiceKeyBuffer[MYARK_CORE_SERVICE_KEY_CHARS];
extern UNICODE_STRING g_MyArkCoreServiceKey;

VOID
MyArkCoreRunModuleTeardown(
    VOID);
