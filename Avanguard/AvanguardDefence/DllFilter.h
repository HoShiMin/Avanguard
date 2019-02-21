#pragma once

#ifdef FEATURE_DLL_FILTER
namespace DllFilter {
    BOOL EnableDllFilter();
    VOID DisableDllFilter();
    BOOL IsAddressInKnownModule(PVOID Address);
}
#endif