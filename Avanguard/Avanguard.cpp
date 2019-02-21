#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>

#include <string>

#include "./AvanguardDefence/AvnGlobals.h"
#include "./AvanguardDefence/AvnDefinitions.h"
#include "./AvanguardDefence/NativeAPI.h"

#include "./AvanguardDefence/ThreadsFilter.h"
#include "./AvanguardDefence/SfcWrapper.h"
#include "./AvanguardDefence/DllFilter.h"
#include "./AvanguardDefence/MemoryFilter.h"

#include "./AvanguardDefence/Logger.h"

#include <HookLib.h>

#pragma comment(lib, "ntdll.lib")

#pragma comment(lib, "Zydis.lib")
#pragma comment(lib, "HookLib.lib")
#pragma comment(lib, "t1ha-static.lib")

static VOID AvnInitialize()
{
    if (AvnGlobals.Flags.IsAvnInitialized) return;

#ifdef ENABLE_LOGGING
    InitializeLogging();
#endif

    Log(L"[v] Avn started, initialization...");

    // hModules initialization:
    AvnGlobals.hModules.hNtdll = _GetModuleHandle(L"ntdll.dll");
    AvnGlobals.hModules.hKernelBase = _GetModuleHandle(L"kernelbase.dll");
    AvnGlobals.hModules.hKernel32 = _GetModuleHandle(L"kernel32.dll");

#ifdef FEATURE_THREADS_FILTER
    if (ThreadsFilter::EnableThreadsFilter())
        Log(L"[v] Threads filter initialized!");
    else
        Log(L"[x] Threads filter initialization error!");
#endif

#ifdef FEATURE_DLL_FILTER
#ifdef FEATURE_ALLOW_SYSTEM_MODULES
    if (Sfc::InitializeSfc())
        Log(L"[v] Sfc initialized!");
    else
        Log(L"[x] Sfc initialization error!");
#endif

    if (DllFilter::EnableDllFilter())
        Log(L"[v] Dll filter initialized!");
    else
        Log(L"[x] Dll filter initialization error!");
#endif

#ifdef FEATURE_MEMORY_FILTER
    if (MemoryFilter::EnableMemoryFilter())
        Log(L"[v] Memory filter initialized!");
    else
        Log(L"[x] Memory filter initialization error!");
#endif

    AvnGlobals.Flags.IsAvnInitialized = TRUE;
    Log(L"[v] Avn initialized!");
}

static VOID AvnStartDefence()
{
    AvnInitialize();
}

static VOID AvnStopDefence()
{
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
    AvnGlobals.hModules.hAvn = hModule;
    AvnGlobals.Flags.IsAvnStaticLoaded = IsStaticLoaded;
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