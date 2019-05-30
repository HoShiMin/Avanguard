#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>

#include <string>

#include "./AvanguardDefence/AvnGlobals.h"
#include "./AvanguardDefence/AvnDefinitions.h"
#include "./AvanguardDefence/NativeAPI.h"

#include "./AvanguardDefence/AppInitDLLs.h"
#include "./AvanguardDefence/ThreadsFilter.h"
#include "./AvanguardDefence/SfcWrapper.h"
#include "./AvanguardDefence/DllFilter.h"
#include "./AvanguardDefence/WindowsHooksFilter.h"
#include "./AvanguardDefence/MemoryFilter.h"
#include "./AvanguardDefence/ContextsFilter.h"
#include "./AvanguardDefence/ApcFilter.h"
#include "./AvanguardDefence/TimeredCheckings.h"
#include "./AvanguardDefence/ThreatsHandler.h"
#include "./AvanguardDefence/Logger.h"

#include <HookLib.h>

#pragma comment(lib, "ntdll.lib")

#pragma comment(lib, "Zydis.lib")
#pragma comment(lib, "HookLib.lib")
#pragma comment(lib, "t1ha-static.lib")

static Notifier::THREAT_DECISION CALLBACK ThreatNotifier(Notifier::THREAT_INFO* Info)
{
    return Notifier::tdBlockOrIgnore;
}

static VOID AvnInitialize()
{
    if (AvnGlobals.Flags.IsAvnInitialized) return;

    Log(L"[v] Avn late phase initialization...");

#ifdef FEATURE_THREADS_FILTER
    if (ThreadsFilter::EnableThreadsFilter())
        Log(L"[v] Threads filter enabled!");
    else
        Log(L"[x] Threads filter initialization error!");
#endif

#ifdef FEATURE_DLL_FILTER
#ifdef FEATURE_WINDOWS_HOOKS_FILTER
    WinHooksFilter::InitializeWinHooksFilter();
#endif

#ifdef FEATURE_ALLOW_SYSTEM_MODULES
    if (Sfc::InitializeSfc())
        Log(L"[v] Sfc initialized!");
    else
        Log(L"[x] Sfc initialization error!");
#endif

    if (DllFilter::EnableDllFilter(FALSE))
        Log(L"[v] Dll filter enabled!");
    else
        Log(L"[x] Dll filter initialization error!");
#endif

#ifdef FEATURE_MEMORY_FILTER
    if (MemoryFilter::EnableMemoryFilter(FALSE))
        Log(L"[v] Memory filter enabled!");
    else
        Log(L"[x] Memory filter initialization error!");
#endif

#ifdef FEATURE_CONTEXTS_FILTER
    if (ContextsFilter::EnableContextsFilter())
        Log(L"[v] Contexts filter enabled!");
    else
        Log(L"[x] Contexts filter initialization error!");
#endif

#ifdef FEATURE_APC_FILTER
    if (ApcFilter::EnableApcFilter())
        Log(L"[v] APC filter enabled!");
    else
        Log(L"[x] APC filter initialization error!");
#endif

#ifdef FEATURE_DLL_FILTER
    DllFilter::CollectModulesInfo();
#endif

#ifdef FEATURE_MEMORY_FILTER
    MemoryFilter::CollectMemoryInfo();
#endif

#ifdef FEATURE_TIMERED_CHECKINGS
    if (TimeredCheckings::EnableTimeredCheckings())
        Log(L"[v] Timered checkings enabled!");
    else
        Log(L"[x] Timered checkings initialization error!");
#endif

    Notifier::Subscribe(ThreatNotifier);

    AvnGlobals.Flags.IsAvnInitialized = TRUE;
    Log(L"[v] Avn initialized!");
}

static VOID AvnStartDefence()
{
    AvnInitialize();
}

static VOID AvnStopDefence()
{
#ifdef FEATURE_TIMERED_CHECKINGS
    TimeredCheckings::DisableTimeredCheckings();
#endif

#ifdef FEATURE_APC_FILTER
    ApcFilter::DisableApcFilter();
#endif

#ifdef FEATURE_CONTEXTS_FILTER
    ContextsFilter::DisableContextsFilter();
#endif

#ifdef FEATURE_MEMORY_FILTER
    MemoryFilter::DisableMemoryFilter();
#endif

#ifdef FEATURE_DLL_FILTER
    DllFilter::DisableDllFilter();
#endif

#ifdef FEATURE_THREADS_FILTER
    ThreadsFilter::DisableThreadsFilter();
#endif

    Log(L"[v] Avn stopped. Good bye!");
}

#ifdef STATIC_LOAD_AUTOSTART
static VOID NTAPI ApcInitialization(
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
) {
    AvnStartDefence();
}
#endif

static VOID AvnInitStub(HMODULE hModule, BOOLEAN IsStaticLoaded)
{
#ifdef ENABLE_LOGGING
    InitializeLogging();
#endif

    Log(L"[v] Avn started, early phase initialization...");

    AvnGlobals.hModules.hAvn = hModule;
    AvnGlobals.Flags.IsAvnStaticLoaded = IsStaticLoaded;

    // hModules initialization:
    AvnGlobals.hModules.hNtdll = _GetModuleHandle(L"ntdll.dll");
    AvnGlobals.hModules.hKernelBase = _GetModuleHandle(L"kernelbase.dll");
    AvnGlobals.hModules.hKernel32 = _GetModuleHandle(L"kernel32.dll");

#ifdef FEATURE_APP_INIT_DLLS
    // We must initialize it here, before the user32.dll loading:
    if (AppInitDlls::DisableAppInitDlls())
        Log(L"[v] AppInit_DLLs successfully disabled!");
    else
        Log(L"[x] Disabling AppInit_DLLs error!");
#endif

#ifdef STATIC_LOAD_AUTOSTART
    if (IsStaticLoaded) {
        NtQueueApcThread(
            NtCurrentThread(),
            ApcInitialization,
            NULL,
            NULL,
            0
        );
    }
#endif
}

static VOID AvnDeinit()
{
    AvnStopDefence();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PCONTEXT lpContext)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        AvnInitStub(hModule, lpContext != NULL);
        break;
    case DLL_PROCESS_DETACH:
        AvnDeinit();
        break;
    }

    return TRUE;
}