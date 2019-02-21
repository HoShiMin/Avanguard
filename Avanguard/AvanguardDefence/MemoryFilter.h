#pragma once

#ifdef FEATURE_MEMORY_FILTER
namespace MemoryFilter {
    BOOL EnableMemoryFilter();
    VOID DisableMemoryFilter();
    BOOL IsMemoryKnown(LPCVOID Address);
}
#endif