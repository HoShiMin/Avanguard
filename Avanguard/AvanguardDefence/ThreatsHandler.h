#pragma once

namespace Notifier {
    enum THREAT_TYPE {
        ttRemoteThread,
        ttThreadInUnknownModule,
        ttThreadInUnknownMemory,
        ttUnknownOriginModload,
        ttWinHooks,
        ttAppInit,
        ttApc,
        ttContextSteal,
        ttModifiedModule,
        ttUnknownMemory,
        ttUnknown
    };

    struct THREAD_INFO {
        void* EntryPoint;
        void* Argument;
    };

    struct UNKNOWN_ORIGIN_MODLOAD_INFO {
        void* UnknownFrame;
        const wchar_t* Path;
    };

    struct WIN_HOOKS_INFO {
        const wchar_t* Path;
    };

    struct APP_INIT_INFO {
        const wchar_t* Path;
    };

    struct APC_INFO {
        void* ApcRoutine;
        void* Argument;
    };

    struct CONTEXT_STEAL_INFO {
        void* UnknownMemory;
    };

    struct MODIFIED_MODULE_INFO {
        void* ModuleBase;
        const wchar_t* Name;
    };

    struct UNKNOWN_MEMORY_INFO {
        void* AllocationBase;
        size_t Size;
    };

    struct THREAT_INFO {
        union {
            THREAD_INFO* RemoteThreadInfo;
            THREAD_INFO* ThreadInUnknownModuleInfo;
            THREAD_INFO* ThreadInUnknownMemoryInfo;
            UNKNOWN_ORIGIN_MODLOAD_INFO* UnknownOriginModloadInfo;
            WIN_HOOKS_INFO* WinHooksInfo;
            APP_INIT_INFO* AppInitInfo;
            APC_INFO* ApcInfo;
            CONTEXT_STEAL_INFO* ContextStealInfo;
            MODIFIED_MODULE_INFO* ModifiedModuleInfo;
            UNKNOWN_MEMORY_INFO* UnknownMemoryInfo;
            void* ThreatInfo;
        } Info;
        THREAT_TYPE Type;
    };

    enum THREAT_DECISION {
        tdAllow,
        tdTerminate,
        tdBlockOrIgnore,
        tdBlockOrTerminate,
    };

    typedef THREAT_DECISION(__stdcall *_ThreatNotifier)(THREAT_INFO* Info);

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