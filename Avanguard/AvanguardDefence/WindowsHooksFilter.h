#pragma once

#ifdef FEATURE_WINDOWS_HOOKS_FILTER
namespace WinHooksFilter {
    BOOL InitializeWinHooksFilter();
    BOOL IsWinHookOrigin(PVOID FramePtr);
}
#endif