#pragma once

#ifdef FEATURE_DLL_FILTER
namespace DllFilter {
    BOOL EnableDllFilter(BOOL InitialCollectModulesInfo);
    VOID DisableDllFilter();
    VOID CollectModulesInfo();
    BOOL IsAddressInKnownModule(PVOID Address);
#ifdef _STRING_
    std::wstring GetModuleName(HMODULE hModule);
#endif
#ifdef _SET_
    VOID FindChangedModules(__out std::set<HMODULE>& ChangedModules);
#endif
}
#endif