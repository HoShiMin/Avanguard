#include "AvnDefinitions.h"
#ifdef FEATURE_CONTEXTS_FILTER

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>

#include "NativeAPI.h"
#include <HookLib.h>

#include "AvnGlobals.h"
#include "StacktraceChecker.h"

#include "ContextsFilter.h"

namespace ContextsFilter {

    static BOOL IsContextSwitchAllowed()
    {
        switch (StacktraceChecker::CheckStackTrace()) {
        case StacktraceChecker::stValid:
        case StacktraceChecker::stError: // To avoid a false detections
        case StacktraceChecker::stWindowsHooks:
            return TRUE;
        default:
            return FALSE;
        }
    }

    DeclareHook(NTSTATUS, NTAPI, NtContinue, PCONTEXT Context, BOOL TestAlert)
    {
        if (IsContextSwitchAllowed())
            return CallOriginal(NtContinue)(Context, TestAlert);
        else
            return STATUS_UNSUCCESSFUL;
    }

    DeclareHook(NTSTATUS, NTAPI, NtSetContextThread, HANDLE hThread, PCONTEXT Context)
    {
        if (IsContextSwitchAllowed())
            return CallOriginal(NtSetContextThread)(hThread, Context);
        else
            return STATUS_UNSUCCESSFUL;
    }

    BOOL EnableContextsFilter()
    {
        if (IsHookEnabled(NtContinue) || IsHookEnabled(NtSetContextThread)) return TRUE;
        SetHookTarget(NtContinue, _GetProcAddress(AvnGlobals.hModules.hNtdll, "NtContinue"));
        SetHookTarget(NtSetContextThread, _GetProcAddress(AvnGlobals.hModules.hNtdll, "NtSetContextThread"));
        BOOL Status = EnableHook(NtContinue) && EnableHook(NtSetContextThread);
        if (!Status) DisableContextsFilter();
        return Status;
    }

    VOID DisableContextsFilter()
    {
        DisableHook(NtContinue);
        DisableHook(NtSetContextThread);
    }
}

#endif