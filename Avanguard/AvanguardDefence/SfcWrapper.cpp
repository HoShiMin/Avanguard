#include "AvnDefinitions.h"
#ifdef FEATURE_ALLOW_SYSTEM_MODULES
#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

namespace Sfc {
    static BOOL(WINAPI *_SfcIsFileProtected)(HANDLE RpcHandle, LPCWSTR Path) = NULL;
    
    BOOL InitializeSfc()
    {
        if (_SfcIsFileProtected) return TRUE;
        static LPCWSTR SfcLibName = L"Sfc.dll";
        HMODULE hSfc = GetModuleHandle(SfcLibName);
        if (!hSfc) hSfc = LoadLibrary(SfcLibName);
        if (!hSfc) return FALSE;
        _SfcIsFileProtected = reinterpret_cast<decltype(_SfcIsFileProtected)>(GetProcAddress(hSfc, "SfcIsFileProtected"));
        return _SfcIsFileProtected != NULL;
    }

    BOOL IsSystemFile(LPCWSTR Path) {
        if (!InitializeSfc()) return FALSE;
        return _SfcIsFileProtected(NULL, Path);
    }
}
#endif