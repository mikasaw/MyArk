// MyArk Core Driver: build-profile selector.
//
// The active profile (e.g. myark_full.h, myark_mini.h) is supplied by the
// build system via the MYARK_CONFIG_HEADER preprocessor macro. This wrapper
// stringifies the token and forces the C preprocessor to parse it as a
// header-name token before #include sees it.

#pragma once

#ifndef MYARK_CONFIG_HEADER
#define MYARK_CONFIG_HEADER myark_full.h
#endif

#define MYARK_HEADER_STR2(x) #x
#define MYARK_HEADER_STR(x)  MYARK_HEADER_STR2(x)

#include MYARK_HEADER_STR(MYARK_CONFIG_HEADER)
