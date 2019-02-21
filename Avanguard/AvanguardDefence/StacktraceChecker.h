#pragma once

#ifdef FEATURE_STACKTRACE_CHECK
namespace StacktraceChecker {

    enum STACKTRACE_CHECK_RESULT {
        stValid,
        stUnknownModule,
        stUnknownMemory,
        stWindowsHooks,
        stError
    };

    STACKTRACE_CHECK_RESULT CheckStackTrace(OPTIONAL OUT PVOID* UnknownFrame = NULL);
}
#endif
