#include "AvnDefinitions.h"
#ifdef FEATURE_APP_INIT_DLLS

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <HookLib.h>

#include "ThreatsHandler.h"
#include "AvnGlobals.h"

#include <string>
#include "Logger.h"

namespace AppInitDlls {

    DeclareHook(VOID, WINAPI, LoadAppInitDlls) 
    {
        switch (Notifier::ReportAppInit(NULL)) {
        case Notifier::tdAllow:
            Log(L"[v] LoadAppInitDLLs allowed by external decision");
            return CallOriginal(LoadAppInitDlls)();
        case Notifier::tdBlockOrIgnore:
        case Notifier::tdBlockOrTerminate:
            Log(L"[x] LoadAppInitDLLs denied (skipped) by external decision");
            return;
        case Notifier::tdTerminate:
            Log(L"[x] LoadAppInitDLLs caused fastfail by external decision");
            __fastfail(0);
            break;
        }
        return;
    }

    BOOL DisableAppInitDlls()
    {
        if (IsHookEnabled(LoadAppInitDlls)) return TRUE;
        LPCVOID pLoadAppInitDlls = _GetProcAddress(AvnGlobals.hModules.hKernel32, "LoadAppInitDlls");
        if (!pLoadAppInitDlls) return FALSE;
        SetHookTarget(LoadAppInitDlls, pLoadAppInitDlls);
        return EnableHook(LoadAppInitDlls);
    }
}
#endif