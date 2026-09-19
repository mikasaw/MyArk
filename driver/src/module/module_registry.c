// MyArk Core Driver: module registry storage + lookup helpers.
//
// g_AllModules is built at link time: every module .c file is wrapped in
// `#if MYARK_MODULE_<NAME>` and contributes its descriptor pointer.
//
// MyArkModuleRegistryInit walks the static array once and caches the count.
// Lookup helpers iterate the array; with MYARK_MAX_MODULES=32 the linear scan
// is cheaper than maintaining a hash table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "module_registry.h"
#include "myark_config.h"
#if MYARK_MODULE_HELLO
#include "../modules/00_hello/hello_descriptor.h"
#endif
#if MYARK_MODULE_MEMORY
#include "../modules/12_memory/memory_module.h"
#endif
#if MYARK_MODULE_PROCESS
#include "../modules/10_process/process_descriptor.h"
#endif
#if MYARK_MODULE_THREAD
#include "../modules/11_thread/thread_descriptor.h"
#endif
#if MYARK_MODULE_HANDLE
#include "../modules/20_handle/handle_descriptor.h"
#endif
#if MYARK_MODULE_SECTION
#include "../modules/21_section/section_descriptor.h"
#endif
#if MYARK_MODULE_KMODULE
#include "../modules/22_kmod/kmod_descriptor.h"
#endif
#if MYARK_MODULE_KERNEL
#include "../modules/25_kernel/kernel_descriptor.h"
#endif
#if MYARK_MODULE_DYNDATA
#include "../modules/70_dyndata/dyndata_descriptor.h"
#endif
#if MYARK_MODULE_CPU
#include "../modules/65_cpu/cpu_descriptor.h"
#endif
#if MYARK_MODULE_TIMERDPC
#include "../modules/26_timerdpc/timerdpc_descriptor.h"
#endif
#if MYARK_MODULE_CALLBACK
#include "../modules/71_callback/callback_descriptor.h"
#endif
#if MYARK_MODULE_STORAGE
#include "../modules/23_storage/storage_descriptor.h"
#endif
#if MYARK_MODULE_DEVICE_AUDIT
#include "../modules/24_device_audit/devaudit_descriptor.h"
#endif
#if MYARK_MODULE_KEYBOARD
#include "../modules/30_keyboard/keyboard_descriptor.h"
#endif
#if MYARK_MODULE_DEBUG_OUTPUT
#include "../modules/31_debug_output/dbgout_descriptor.h"
#endif
#if MYARK_MODULE_CAPABILITY
#include "../modules/84_capability/capability_descriptor.h"
#endif
#if MYARK_MODULE_PREFLIGHT
#include "../modules/82_preflight/preflight_descriptor.h"
#endif
#if MYARK_MODULE_SAFETY
#include "../modules/86_safety/safety_descriptor.h"
#endif
#if MYARK_MODULE_SECURITY_AUDIT
#include "../modules/83_security_audit/secaudit_descriptor.h"
#endif
#if MYARK_MODULE_TRUST
#include "../modules/81_trust/trust_descriptor.h"
#endif
#if MYARK_MODULE_KERNEL_EXT
#include "../modules/85_kernel_ext/kernel_ext_descriptor.h"
#endif
#if MYARK_MODULE_HWID
#include "../modules/75_hwid/hwid_descriptor.h"
#endif
#if MYARK_MODULE_ALPC
#include "../modules/79_alpc/alpc_descriptor.h"
#endif
#if MYARK_MODULE_WSL
#include "../modules/78_wsl/wsl_descriptor.h"
#endif
#if MYARK_MODULE_WIN32K
#include "../modules/77_win32k/win32k_descriptor.h"
#endif
#if MYARK_MODULE_AUTHENTICATION
#include "../modules/80_authentication/authentication_descriptor.h"
#endif
#if MYARK_MODULE_BUGCHECK
#include "../modules/76_bugcheck/bugcheck_descriptor.h"
#endif
#if MYARK_MODULE_WFP
#include "../modules/72_wfp/wfp_descriptor.h"
#endif
#if MYARK_MODULE_MUTATION
#include "../modules/73_mutation/mutation_descriptor.h"
#endif
#if MYARK_MODULE_REDIRECT
#include "../modules/74_redirect/redirect_descriptor.h"
#endif
#if MYARK_MODULE_ACTIONS
#include "../modules/87_actions/actions_descriptor.h"
#endif
#if MYARK_MODULE_REGISTRY
#include "../modules/88_registry/registry_descriptor.h"
#endif
#if MYARK_MODULE_FILE
#include "../modules/89_file/file_descriptor.h"
#endif
#if MYARK_MODULE_FILE_MONITOR
#include "../modules/90_filemon/filemon_descriptor.h"
#endif

//
// Compile-time module roster. Each MYARK_MODULE_<NAME> define lives in the
// active build profile (config/myark_*.h).
//
MYARK_MODULE_DESCRIPTOR* g_AllModules[MYARK_MAX_MODULES + 1] = {
#if MYARK_MODULE_CPU
    &g_MyArkModule_Cpu,
#endif
#if MYARK_MODULE_TIMERDPC
    &g_MyArkModule_TimerDpc,
#endif
#if MYARK_MODULE_HELLO
    &g_MyArkModule_Hello,
#endif
#if MYARK_MODULE_MEMORY
    &g_MyArkModule_Memory,
#endif
#if MYARK_MODULE_PROCESS
    &g_MyArkModule_Process,
#endif
#if MYARK_MODULE_THREAD
    &g_MyArkModule_Thread,
#endif
#if MYARK_MODULE_HANDLE
    &g_MyArkModule_Handle,
#endif
#if MYARK_MODULE_SECTION
    &g_MyArkModule_Section,
#endif
#if MYARK_MODULE_KMODULE
    &g_MyArkModule_Kmod,
#endif
#if MYARK_MODULE_KERNEL
    &g_MyArkModule_Kernel,
#endif
#if MYARK_MODULE_DYNDATA
    &g_MyArkModule_DynData,
#endif
#if MYARK_MODULE_CALLBACK
    &g_MyArkModule_Callback,
#endif
#if MYARK_MODULE_STORAGE
    &g_MyArkModule_Storage,
#endif
#if MYARK_MODULE_DEVICE_AUDIT
    &g_MyArkModule_DeviceAudit,
#endif
#if MYARK_MODULE_KEYBOARD
    &g_MyArkModule_Keyboard,
#endif
#if MYARK_MODULE_DEBUG_OUTPUT
    &g_MyArkModule_DebugOutput,
#endif
#if MYARK_MODULE_CAPABILITY
    &g_MyArkModule_Capability,
#endif
#if MYARK_MODULE_PREFLIGHT
    &g_MyArkModule_Preflight,
#endif
#if MYARK_MODULE_SAFETY
    &g_MyArkModule_Safety,
#endif
#if MYARK_MODULE_SECURITY_AUDIT
    &g_MyArkModule_SecurityAudit,
#endif
#if MYARK_MODULE_TRUST
    &g_MyArkModule_Trust,
#endif
#if MYARK_MODULE_KERNEL_EXT
    &g_MyArkModule_KernelExt,
#endif
#if MYARK_MODULE_HWID
    &g_MyArkModule_Hwid,
#endif
#if MYARK_MODULE_ALPC
    &g_MyArkModule_Alpc,
#endif
#if MYARK_MODULE_WSL
    &g_MyArkModule_Wsl,
#endif
#if MYARK_MODULE_WIN32K
    &g_MyArkModule_Win32k,
#endif
#if MYARK_MODULE_AUTHENTICATION
    &g_MyArkModule_Authentication,
#endif
#if MYARK_MODULE_BUGCHECK
    &g_MyArkModule_Bugcheck,
#endif
#if MYARK_MODULE_WFP
    &g_MyArkModule_Wfp,
#endif
#if MYARK_MODULE_MUTATION
    &g_MyArkModule_Mutation,
#endif
#if MYARK_MODULE_REDIRECT
    &g_MyArkModule_Redirect,
#endif
#if MYARK_MODULE_ACTIONS
    &g_MyArkModule_Actions,
#endif
#if MYARK_MODULE_REGISTRY
    &g_MyArkModule_Registry,
#endif
#if MYARK_MODULE_FILE
    &g_MyArkModule_File,
#endif
#if MYARK_MODULE_FILE_MONITOR
    &g_MyArkModule_FileMonitor,
#endif
    NULL
};

UINT32 g_ModuleCount = 0;

NTSTATUS
MyArkModuleRegistryInit(
    VOID)
{
    UINT32 count = 0;

    while (count < MYARK_MAX_MODULES && g_AllModules[count] != NULL) {
        count++;
    }

    g_ModuleCount = count;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MODULE,
                "MyArkModuleRegistryInit: %u module descriptor(s) linked",
                count);

    return STATUS_SUCCESS;
}

VOID
MyArkModuleRegistryCleanup(
    VOID)
{
    //
    // Walk descriptors in reverse order so dependencies unwind in LIFO order.
    // Only modules that successfully Initialized get a Cleanup call.
    //
    for (INT32 i = (INT32)g_ModuleCount - 1; i >= 0; i--) {
        PMYARK_MODULE_DESCRIPTOR module = g_AllModules[i];
        if (module == NULL) {
            continue;
        }
        if (module->Initialized && module->Cleanup != NULL) {
            module->Cleanup();
            module->Initialized = FALSE;
        }
    }

    g_ModuleCount = 0;
}

PMYARK_MODULE_DESCRIPTOR
MyArkModuleFindByName(
    _In_ PCSTR Name)
{
    ANSI_STRING nameAnsi;

    if (Name == NULL) {
        return NULL;
    }

    RtlInitAnsiString(&nameAnsi, Name);

    for (UINT32 i = 0; i < g_ModuleCount; i++) {
        PMYARK_MODULE_DESCRIPTOR module = g_AllModules[i];
        ANSI_STRING moduleAnsi;

        if (module == NULL || module->ModuleName == NULL) {
            continue;
        }

        RtlInitAnsiString(&moduleAnsi, module->ModuleName);
        if (RtlCompareString(&moduleAnsi, &nameAnsi, TRUE) == 0) {
            return module;
        }
    }

    return NULL;
}

PMYARK_MODULE_DESCRIPTOR
MyArkModuleFindById(
    _In_ UINT32 ModuleId)
{
    for (UINT32 i = 0; i < g_ModuleCount; i++) {
        PMYARK_MODULE_DESCRIPTOR module = g_AllModules[i];
        if (module == NULL) {
            continue;
        }
        if (module->ModuleId == ModuleId) {
            return module;
        }
    }

    return NULL;
}
