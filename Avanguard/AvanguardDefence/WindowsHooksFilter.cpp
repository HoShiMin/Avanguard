#include "AvnDefinitions.h"
#ifdef FEATURE_WINDOWS_HOOKS_FILTER

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <vector>
#include <algorithm>

#include <winternl.h>
#include <ntstatus.h>

#include "NativeAPI.h"

namespace WinHooksFilter {
    static struct {
        PVOID ClientLoadLibrary;
        std::vector<PVOID> Callbacks;
        BOOL Initialized;
    } FilterData = {};

    static inline PVOID* GetKernelCallbacksTable()
    {
        return reinterpret_cast<PebTeb::PPEB>(__peb())->KernelCallbackTable;
    }

    BOOL Initialize()
    {
        if (FilterData.Initialized) return TRUE;
        PVOID* KernelCallbacksTable = GetKernelCallbacksTable();
        if (!KernelCallbacksTable) return FALSE;

        HMODULE hUser32 = GetModuleHandle(L"user32.dll");
        if (!hUser32) return FALSE;

        FilterData.Callbacks.reserve(128);
        PVOID CallbackModBase = NULL;
        for (unsigned i = 0; RtlPcToFileHeader(KernelCallbacksTable[i], &CallbackModBase) == hUser32; ++i)
        {
            FilterData.Callbacks.emplace_back(KernelCallbacksTable[i]);
        }

        std::sort(FilterData.Callbacks.begin(), FilterData.Callbacks.end());
        FilterData.Initialized = TRUE;
        return TRUE;
    }

    static inline BOOL IsInFunction(PVOID Ptr, PVOID FuncBase)
    {
        return reinterpret_cast<PBYTE>(Ptr) >= reinterpret_cast<PBYTE>(FuncBase)
            && reinterpret_cast<PBYTE>(Ptr) < (reinterpret_cast<PBYTE>(FuncBase) + 256);
    }

    BOOL IsWinHookOrigin(PVOID FramePtr)
    {
        if (!FilterData.Initialized && !Initialize())
            return FALSE;

        if (FilterData.ClientLoadLibrary)
            return IsInFunction(FramePtr, FilterData.ClientLoadLibrary);

        if (FilterData.Callbacks.empty()
            || reinterpret_cast<PBYTE>(FramePtr) < reinterpret_cast<PBYTE>(FilterData.Callbacks[0])
            || reinterpret_cast<PBYTE>(FramePtr) > reinterpret_cast<PBYTE>(FilterData.Callbacks[FilterData.Callbacks.size() - 1])
        ) return FALSE;

        for (const auto& Callback : FilterData.Callbacks) {
            if (IsInFunction(FramePtr, Callback)) {
                FilterData.ClientLoadLibrary = Callback;
                FilterData.Callbacks.clear();
                return TRUE;
            }
        }

        return FALSE;
    }
}

#endif