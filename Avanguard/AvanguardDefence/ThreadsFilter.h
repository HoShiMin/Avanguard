#pragma once

#ifdef FEATURE_THREADS_FILTER
namespace ThreadsFilter {
    BOOL EnableThreadsFilter();
    VOID DisableThreadsFilter();
}
#endif