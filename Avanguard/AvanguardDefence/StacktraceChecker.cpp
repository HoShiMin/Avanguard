#include "AvnDefinitions.h"
#ifdef FEATURE_STACKTRACE_CHECK

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#ifdef FEATURE_DLL_FILTER
    #include "DllFilter.h"
    #ifdef FEATURE_WINDOWS_HOOKS_FILTER
        #include "WindowsHooksFilter.h"
    #endif
#endif

#ifdef FEATURE_MEMORY_FILTER
    #include "MemoryFilter.h"
#endif

#include "StacktraceChecker.h"

namespace StacktraceChecker {
    STACKTRACE_CHECK_RESULT CheckStackTrace(OPTIONAL OUT PVOID* UnknownFrame)
    {
        if (UnknownFrame) *UnknownFrame = NULL;

        PVOID Trace[8];
        WORD Captured = CaptureStackBackTrace(1, sizeof(Trace) / sizeof(*Trace), Trace, NULL);
        if (!Captured) return stError;

        for (WORD i = 0; i < Captured; ++i) {
#ifdef FEATURE_DLL_FILTER
            if (!DllFilter::IsAddressInKnownModule(Trace[i])) {
#ifdef FEATURE_MEMORY_FILTER
                if (!MemoryFilter::IsMemoryKnown(Trace[i])) {
                    if (UnknownFrame) *UnknownFrame = Trace[i];
                    return stUnknownMemory;
                }
#else
                if (UnknownFrame) *UnknownFrame = Trace[i];
                return stUnknownModule;
#endif
            }
#ifdef FEATURE_WINDOWS_HOOKS_FILTER
            if (WinHooksFilter::IsWinHookOrigin(Trace[i])) {
                if (UnknownFrame) *UnknownFrame = Trace[i];
                return stWindowsHooks;
            }
#endif
#elif defined FEATURE_MEMORY_FILTER
            if (!MemoryFilter::IsMemoryKnown(Trace[i])) {
                if (UnknownFrame) *UnknownFrame = Trace[i];
                return stUnknownMemory;
            }
#endif
        }

        return stValid;
    }
}

#endif