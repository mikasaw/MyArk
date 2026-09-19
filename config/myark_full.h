// MyArk build profile: full
// All 36 module gates enabled (1 core + 35 functional, incl. core/hello).
// Default profile used by `make.bat full` and the default `make.bat` (no arg).

#pragma once

// Core infrastructure (always enabled)
#define MYARK_MODULE_CORE              1

// S4 mechanism smoke module
#define MYARK_MODULE_HELLO             1

// Functional modules (30)
#define MYARK_MODULE_PROCESS           1
#define MYARK_MODULE_THREAD            1
#define MYARK_MODULE_MEMORY            1
#define MYARK_MODULE_CPU              1
#define MYARK_MODULE_TIMERDPC         1
#define MYARK_MODULE_REGISTRY          1
#define MYARK_MODULE_FILE              1
#define MYARK_MODULE_FILE_MONITOR      1
#define MYARK_MODULE_KERNEL            1
#define MYARK_MODULE_KERNEL_OBJECT     1
#define MYARK_MODULE_CALLBACK          1
#define MYARK_MODULE_DYNDATA           1
#define MYARK_MODULE_CAPABILITY        1
#define MYARK_MODULE_HANDLE            1
#define MYARK_MODULE_SECTION           1
#define MYARK_MODULE_ALPC              1
#define MYARK_MODULE_NETWORK           1
#define MYARK_MODULE_KEYBOARD          1
#define MYARK_MODULE_HWID              1
#define MYARK_MODULE_WFP               1
#define MYARK_MODULE_MUTATION          1
#define MYARK_MODULE_REDIRECT          1
#define MYARK_MODULE_DEBUG_OUTPUT      1
#define MYARK_MODULE_BUGCHECK          1
#define MYARK_MODULE_SAFETY            1
#define MYARK_MODULE_TRUST             1
#define MYARK_MODULE_PREFLIGHT         1
#define MYARK_MODULE_SECURITY_AUDIT    1
#define MYARK_MODULE_STORAGE           1
#define MYARK_MODULE_DEVICE_AUDIT      1
#define MYARK_MODULE_WIN32K            1
#define MYARK_MODULE_WSL               1
#define MYARK_MODULE_AUTHENTICATION    1
#define MYARK_MODULE_KERNEL_EXT        1
#define MYARK_MODULE_ACTIONS           1