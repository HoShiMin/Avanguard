#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include "ThreatsHandler.h"

#include "Locks.h"
#include <set>

namespace Notifier {

    class ThreatReporter final {
    private:
        mutable RWLock Lock;
        std::set<_ThreatNotifier> Notifiers;
    public:
        ThreatReporter(const ThreatReporter&) = delete;
        ThreatReporter(ThreatReporter&&) = delete;
        ThreatReporter& operator = (const ThreatReporter&) = delete;
        ThreatReporter& operator = (ThreatReporter&&) = delete;
        ~ThreatReporter() = default;

        ThreatReporter() : Lock(), Notifiers() {}

        void Subscribe(_ThreatNotifier Notifier) {
            Lock.LockExclusive();
            Notifiers.emplace(Notifier);
            Lock.UnlockExclusive();
        }

        void Unsubscribe(_ThreatNotifier Notifier) {
            Lock.LockExclusive();
            Notifiers.erase(Notifier);
            Lock.UnlockExclusive();
        }

        void ClearSubscriptions() {
            Lock.LockExclusive();
            Notifiers.clear();
            Lock.UnlockExclusive();
        }

        THREAT_DECISION Report(THREAT_INFO* Info) const {
            THREAT_DECISION Decision = tdAllow;
            Lock.LockShared();
            for (const auto& Notifier : Notifiers) {
                if ((Decision = Notifier(Info)) == tdTerminate) __fastfail(0);
                if (Decision != tdAllow) break;
            }
            Lock.UnlockShared();
            return Decision;
        }
    };

    static ThreatReporter Reporter;

    void Subscribe(_ThreatNotifier Notifier) {
        Reporter.Subscribe(Notifier);
    }

    void Unsubscribe(_ThreatNotifier Notifier) {
        Reporter.Unsubscribe(Notifier);
    }

    void ClearSubscriptions(_ThreatNotifier Notifier) {
        Reporter.ClearSubscriptions();
    }

    THREAT_DECISION Report(THREAT_INFO* Info) {
        return Reporter.Report(Info);
    }

    THREAT_DECISION Report(THREAT_TYPE Type, void* ThreatInfo) {
        THREAT_INFO Info;
        Info.Info.ThreatInfo = ThreatInfo;
        Info.Type = Type;
        return Report(&Info);
    }

    THREAT_DECISION ReportRemoteThread(void* EntryPoint, void* Argument) {
        THREAD_INFO ThreatInfo;
        ThreatInfo.EntryPoint = EntryPoint;
        ThreatInfo.Argument = Argument;
        return Report(ttRemoteThread, &ThreatInfo);
    }

    THREAT_DECISION ReportThreadInUnknownModule(void* EntryPoint, void* Argument) {
        THREAD_INFO ThreatInfo;
        ThreatInfo.EntryPoint = EntryPoint;
        ThreatInfo.Argument = Argument;
        return Report(ttThreadInUnknownModule, &ThreatInfo);
    }

    THREAT_DECISION ReportThreadInUnknownMemory(void* EntryPoint, void* Argument) {
        THREAD_INFO ThreatInfo;
        ThreatInfo.EntryPoint = EntryPoint;
        ThreatInfo.Argument = Argument;
        return Report(ttThreadInUnknownMemory, &ThreatInfo);
    }

    THREAT_DECISION ReportUnknownOriginModload(void* UnknownFrame, const wchar_t* Path) {
        UNKNOWN_ORIGIN_MODLOAD_INFO ThreatInfo;
        ThreatInfo.UnknownFrame = UnknownFrame;
        ThreatInfo.Path = Path;
        return Report(ttUnknownOriginModload, &ThreatInfo);
    }

    THREAT_DECISION ReportWinHooks(const wchar_t* Path) {
        WIN_HOOKS_INFO ThreatInfo;
        ThreatInfo.Path = Path;
        return Report(ttWinHooks, &ThreatInfo);
    }

    THREAT_DECISION ReportAppInit(const wchar_t* Path) {
        APP_INIT_INFO ThreatInfo;
        ThreatInfo.Path = Path;
        return Report(ttAppInit, &ThreatInfo);
    }

    THREAT_DECISION ReportApc(void* ApcRoutine, void* Argument) {
        APC_INFO ThreatInfo;
        ThreatInfo.ApcRoutine = ApcRoutine;
        ThreatInfo.Argument = Argument;
        return Report(ttApc, &ThreatInfo);
    }

    THREAT_DECISION ReportContextSteal(void* UnknownMemory) {
        CONTEXT_STEAL_INFO ThreatInfo;
        ThreatInfo.UnknownMemory = UnknownMemory;
        return Report(ttContextSteal, &ThreatInfo);
    }

    THREAT_DECISION ReportModifiedModule(void* ModuleBase, const wchar_t* Name) {
        MODIFIED_MODULE_INFO ThreatInfo;
        ThreatInfo.ModuleBase = ModuleBase;
        ThreatInfo.Name = Name;
        return Report(ttModifiedModule, &ThreatInfo);
    }

    THREAT_DECISION ReportUnknownMemory(void* AllocationBase, size_t Size) {
        UNKNOWN_MEMORY_INFO ThreatInfo;
        ThreatInfo.AllocationBase = AllocationBase;
        ThreatInfo.Size = Size;
        return Report(ttUnknownMemory, &ThreatInfo);
    }
}