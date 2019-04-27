#pragma once

#ifdef FEATURE_MEMORY_FILTER
namespace MemoryFilter {
    BOOL EnableMemoryFilter(BOOL InitialCollectMemoryInfo);
    VOID DisableMemoryFilter();
    VOID CollectMemoryInfo();
    BOOL IsMemoryKnown(LPCVOID Address);
#ifdef _VECTOR_
    struct MEMORY_REGION_INFO {
        PVOID BaseAddress;
        SIZE_T Size;
        MEMORY_REGION_INFO(PVOID BaseAddress, SIZE_T Size) {
            this->BaseAddress = BaseAddress;
            this->Size = Size;
        }
    };
    VOID FindUnknownMemoryRegions(__out std::vector<MEMORY_REGION_INFO>& UnknownRegions);
#endif
    VOID BeginMemoryUpdate();
    VOID EndMemoryUpdate();
    VOID AddKnownMemoryBase(LPCVOID AllocationBase);
    VOID AddKnownMemory(LPCVOID Address);
}
#endif