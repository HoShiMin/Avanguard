#pragma once

#ifdef FEATURE_ALLOW_SYSTEM_MODULES
namespace Sfc {
    BOOL InitializeSfc();
    BOOL IsSystemFile(LPCWSTR Path);
}
#endif