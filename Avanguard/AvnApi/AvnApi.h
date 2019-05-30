#pragma once

#include <ThreatTypes.h>

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
    bool(__stdcall* IsStaticLoaded)();
    bool(__stdcall* IsEnabled)();
    bool(__stdcall* Start)();
    void(__stdcall* Stop)();
    void(__stdcall* Lock)();
    void(__stdcall* Unlock)();
    void(__stdcall* Subscribe)(ThreatTypes::_ThreatNotifier Notifier);
    void(__stdcall* Unsubscribe)(ThreatTypes::_ThreatNotifier Notifier);
} AVN_API, *PAVN_API;

AVN_EXPORT PAVN_API Stub;