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

#include "ThreatsHandler.h"

#include "ContextsFilter.h"

#include <string>
#include "Logger.h"

namespace ContextsFilter {

    static BOOL IsContextSwitchAllowed()
    {
        PVOID UnknownFrame = NULL;
        switch (StacktraceChecker::CheckStackTrace(&UnknownFrame)) {
        case StacktraceChecker::stValid:
        case StacktraceChecker::stError: // To avoid a false detections
        case StacktraceChecker::stWindowsHooks:
            return TRUE;
        default:
            switch (Notifier::ReportContextSteal(UnknownFrame)) {
            case Notifier::tdAllow:
                Log(L"[v] Context switch allowed by external decision");
                return TRUE;
            case Notifier::tdBlockOrIgnore:
            case Notifier::tdBlockOrTerminate:
                Log(L"[x] Context switch denied by external decision");
                return FALSE;
            case Notifier::tdTerminate:
                Log(L"[x] Context switch causes fastfail by external decision");
                __fastfail(0);
                break;
            }
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