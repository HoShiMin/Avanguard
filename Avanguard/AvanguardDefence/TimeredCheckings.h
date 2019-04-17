#pragma once

#ifdef FEATURE_TIMERED_CHECKINGS
namespace TimeredCheckings {
    BOOL EnableTimeredCheckings();
    VOID DisableTimeredCheckings();
    VOID LockCheckTimer();
    VOID UnlockCheckTimer();
}
#endif