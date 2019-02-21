#pragma once

#ifdef __cplusplus
    #ifdef AVANGUARD_EXPORTS
        // We're building this library:
        #define AVN_EXPORT extern "C" __declspec(dllexport)
    #else
        // We're using this library:
        #define AVN_EXPORT extern "C" __declspec(dllimport)
    #endif
#else
    #ifdef AVANGUARD_EXPORTS
        // We're building this library:
        #define AVN_EXPORT __declspec(dllexport)
    #else
        // We're using this library:
        #define AVN_EXPORT __declspec(dllimport)
    #endif
#endif

typedef struct {
} AVN_API, *PAVN_API;

AVN_EXPORT PAVN_API Stub;