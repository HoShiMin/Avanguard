#pragma once

#ifdef FEATURE_WINDOWS_HOOKS_FILTER
namespace WinHooksFilter {
    BOOL Initialize();
    BOOL IsWinHookOrigin(PVOID FramePtr);
}
#endif