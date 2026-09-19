// MyArk build profile: safety-audit
// Read-only modules suitable for offline security auditing.
// Used by `make.bat safety-audit`.

#pragma once

#define MYARK_MODULE_CORE              1
#define MYARK_MODULE_PROCESS           1
#define MYARK_MODULE_REGISTRY          1
#define MYARK_MODULE_FILE              1
#define MYARK_MODULE_KERNEL            1
#define MYARK_MODULE_SAFETY            1
#define MYARK_MODULE_SECURITY_AUDIT    1

// All other modules default to 0 (not defined).