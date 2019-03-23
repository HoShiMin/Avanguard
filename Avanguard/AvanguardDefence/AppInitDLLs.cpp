#include "AvnDefinitions.h"
#ifdef FEATURE_APP_INIT_DLLS

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <HookLib.h>

#include "AvnGlobals.h"

namespace AppInitDlls {

    DeclareHook(VOID, WINAPI, LoadAppInitDlls) 
    {
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