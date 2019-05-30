#pragma once

#include <ThreatTypes.h>

namespace Notifier {
    using namespace ThreatTypes;

    void Subscribe(_ThreatNotifier Notifier);
    void Unsubscribe(_ThreatNotifier Notifier);
    void ClearSubscriptions(_ThreatNotifier Notifier);
    THREAT_DECISION Report(THREAT_INFO* Info);
    THREAT_DECISION Report(THREAT_TYPE Type, void* ThreatInfo);
    THREAT_DECISION ReportRemoteThread(void* EntryPoint, void* Argument);
    THREAT_DECISION ReportThreadInUnknownModule(void* EntryPoint, void* Argument);
    THREAT_DECISION ReportThreadInUnknownMemory(void* EntryPoint, void* Argument);
    THREAT_DECISION ReportUnknownOriginModload(void* UnknownFrame, const wchar_t* Path);
    THREAT_DECISION ReportWinHooks(const wchar_t* Path);
    THREAT_DECISION ReportAppInit(const wchar_t* Path);
    THREAT_DECISION ReportApc(void* ApcRoutine, void* Argument);
    THREAT_DECISION ReportContextSteal(void* UnknownMemory);
    THREAT_DECISION ReportModifiedModule(void* ModuleBase, const wchar_t* Name);
    THREAT_DECISION ReportUnknownMemory(void* AllocationBase, size_t Size);
}