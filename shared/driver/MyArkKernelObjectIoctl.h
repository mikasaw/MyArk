// MyArk kernel-object module: shared IOCTL protocol placeholder.
//
// TODO(MyArk-S6.x): populate this header with the kernel-object module's
// IOCTL definitions (object type enumeration, handle table walks, name
// resolution). Each IOCTL must reserve a function code in this module's
// allotted range (see plan v3) and any input/output structs must use the
// buffer conventions documented in shared/driver/MyArkIoctl.h.
//
// Until that lands, this placeholder is enough for MyArkCore to compile
// and link: S4's module mechanism only needs the descriptor symbol and
// the ioctl count, both of which the module's own .c file declares.

#pragma once
