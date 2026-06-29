#pragma once

#include "include/GitVersion.h"

#define IOFTPD_VERSION_MAJOR 8
#define IOFTPD_VERSION_MINOR 1
#define IOFTPD_VERSION_PATCH 0
#define IOFTPD_VERSION_BUILD IOFTPD_GIT_COMMIT_COUNT

// String helpers
#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)

#define IOFTPD_VERSION_STRING \
    STRINGIFY(IOFTPD_VERSION_MAJOR) "." \
    STRINGIFY(IOFTPD_VERSION_MINOR) "." \
    STRINGIFY(IOFTPD_VERSION_PATCH) "." \
    STRINGIFY(IOFTPD_VERSION_BUILD)

// Release builds: clean "Major.Minor.Patch" — no hash, no build count.
// Debug/Purify builds: "Major.Minor.Patch-hash" — hash for crash diagnosis,
//                      no build count (we never need it).
#ifdef RELEASE_BUILD
#define IOFTPD_VERSION_FULL \
    STRINGIFY(IOFTPD_VERSION_MAJOR) "." \
    STRINGIFY(IOFTPD_VERSION_MINOR) "." \
    STRINGIFY(IOFTPD_VERSION_PATCH)
#else
#define IOFTPD_VERSION_FULL \
    STRINGIFY(IOFTPD_VERSION_MAJOR) "." \
    STRINGIFY(IOFTPD_VERSION_MINOR) "." \
    STRINGIFY(IOFTPD_VERSION_PATCH) \
    IOFTPD_GIT_SUFFIX
#endif
// FILEVERSION quad 4th component: always 0 — build count is not used.
#define IOFTPD_VERSION_BUILD_RC 0
