#pragma once

#define ENABLE_LOGGING /* Enable logging to the ***-AvnLog.log file */
#ifdef ENABLE_LOGGING
    #define ENABLE_CONSOLE_OUTPUT /* Duplicate log output to stdout */
#endif

#define STATIC_LOAD_AUTOSTART /* Autostart immediately after loading (only for static loading) */

#define FEATURE_APP_INIT_DLLS /* Against of AppInit_DLLs injections */
#define FEATURE_THREADS_FILTER /* Against of remote threads creation */
#define FEATURE_DLL_FILTER /* To detect unknown or modified modules */
#define FEATURE_MEMORY_FILTER /* Required for a JIT support */
#define FEATURE_APC_FILTER /* Against of APC-based injections */
#define FEATURE_TIMERED_CHECKINGS /* Find modified modules and unknown memory by timer */

#ifdef FEATURE_TIMERED_CHECKINGS
    #define TIMERED_CHECKINGS_INTERVAL (1000)
#endif

#if defined FEATURE_DLL_FILTER || defined FEATURE_MEMORY_FILTER
    #define FEATURE_STACKTRACE_CHECK /* Check for unknown modules/memory call stack entries */
    #ifdef FEATURE_STACKTRACE_CHECK
        #define FEATURE_WINDOWS_HOOKS_FILTER /* Cancel of windows hooks based injections */
        #ifdef FEATURE_WINDOWS_HOOKS_FILTER
            #define FEATURE_ALLOW_SYSTEM_MODULES /* Allow to inject all system modules by windows hooks */
        #endif
        #define FEATURE_CONTEXTS_FILTER /* Against of contexts steal */
    #endif
#endif