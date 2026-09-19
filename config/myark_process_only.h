// MyArk build profile: process-only
// Core + process only. S6.1 foundation module smoke test.

#pragma once

#define MYARK_MODULE_CORE              1
#define MYARK_MODULE_PROCESS           1

// All other modules default to 0 (not defined).