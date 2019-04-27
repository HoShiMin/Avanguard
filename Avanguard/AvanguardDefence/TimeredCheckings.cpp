#include "AvnDefinitions.h"
#ifdef FEATURE_TIMERED_CHECKINGS

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include "NativeAPI.h"

#include "Locks.h"

#include <string>
#include "Logger.h"

#include "ThreatsHandler.h"

#ifdef FEATURE_DLL_FILTER
#include <set>
#include "DllFilter.h"
#endif

#ifdef FEATURE_MEMORY_FILTER
#include <vector>
#include "MemoryFilter.h"
#endif

#include "TimeredCheckings.h"

namespace TimeredCheckings {
    static struct {
        HANDLE hTimerQueue;
        HANDLE hTimer;
        RWLock Lock;
    } TimerInfo = {};

#ifdef FEATURE_DLL_FILTER
    static VOID FindChangedModules()
    {
        std::set<HMODULE> ChangedModules;
        DllFilter::FindChangedModules(ChangedModules);
        for (HMODULE hModule : ChangedModules) {
            std::wstring DllName = DllFilter::GetModuleName(hModule);
            switch (Notifier::ReportModifiedModule(hModule, DllName.c_str())) {
            case Notifier::tdAllow:
                continue;
            case Notifier::tdBlockOrIgnore:
            case Notifier::tdBlockOrTerminate:
            case Notifier::tdTerminate:
                __fastfail(0);
                break;
            }
        }
    }
#endif

#ifdef FEATURE_MEMORY_FILTER
    static VOID FindUnknownMemory()
    {
        std::vector<MemoryFilter::MEMORY_REGION_INFO> UnknownRegions;
        MemoryFilter::FindUnknownMemoryRegions(UnknownRegions);
        for (const auto& Region : UnknownRegions) {
            switch (Notifier::ReportUnknownMemory(Region.BaseAddress, Region.Size)) {
            case Notifier::tdAllow:
                continue;
            case Notifier::tdBlockOrIgnore:
            case Notifier::tdBlockOrTerminate:
            case Notifier::tdTerminate:
                __fastfail(0);
                break;
            }
        }
    }
#endif

    static VOID CheckProcessState()
    {
#ifdef FEATURE_DLL_FILTER
        FindChangedModules();
#endif
#ifdef FEATURE_MEMORY_FILTER
        FindUnknownMemory();
#endif
    }

    static VOID CALLBACK TimerCallback(PVOID Parameter, BOOLEAN TimerOrWaitFired)
    {
        TimerInfo.Lock.LockShared();
        CheckProcessState();
        TimerInfo.Lock.UnlockShared();
    }

    BOOL EnableTimeredCheckings()
    {
        if (TimerInfo.hTimerQueue && TimerInfo.hTimer) return TRUE;

        if (!TimerInfo.hTimerQueue) {
            if (!NT_SUCCESS(RtlCreateTimerQueue(&TimerInfo.hTimerQueue)))
                return FALSE;
        }

        NTSTATUS Status = RtlCreateTimer(
            TimerInfo.hTimerQueue,
            &TimerInfo.hTimer,
            TimerCallback,
            NULL,
            TIMERED_CHECKINGS_INTERVAL,
            TIMERED_CHECKINGS_INTERVAL,
            WT_EXECUTELONGFUNCTION
        );

        if (!NT_SUCCESS(Status)) {
            DisableTimeredCheckings();
            return FALSE;
        }

        return TRUE;
    }

    VOID DisableTimeredCheckings()
    {
        if (TimerInfo.hTimerQueue && TimerInfo.hTimer) {
            RtlDeleteTimer(TimerInfo.hTimerQueue, TimerInfo.hTimer, INVALID_HANDLE_VALUE);
        }

        if (TimerInfo.hTimerQueue) {
            RtlDeleteTimerQueue(TimerInfo.hTimerQueue);
        }

        TimerInfo.hTimer = NULL;
        TimerInfo.hTimerQueue = NULL;
    }

    VOID LockCheckTimer()
    {
        TimerInfo.Lock.LockExclusive();
    }

    VOID UnlockCheckTimer()
    {
        TimerInfo.Lock.UnlockExclusive();
    }
}

#endif // FEATURE_TIMERED_CHECKINGS