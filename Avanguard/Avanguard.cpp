#include <Windows.h>

#pragma comment(lib, "ntdll.lib")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PCONTEXT lpContext)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}