// MyArk build profile: mini
// Core + hello only. Used for S4 module-mechanism smoke test.
// `make.bat mini` should produce a tiny .sys with only MYARK_MODULE_HELLO
// descriptors in the IOCTL registry; R3 should report only the "hello" tab.

#pragma once

#define MYARK_MODULE_CORE              1
#define MYARK_MODULE_HELLO             1

// All other modules default to 0 (not defined).