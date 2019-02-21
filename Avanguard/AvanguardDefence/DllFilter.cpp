#include "AvnDefinitions.h"
#ifdef FEATURE_DLL_FILTER

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>

#include "NativeAPI.h"
#include "AvnGlobals.h"
#include "Locks.h"

#include <HookLib.h>

#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "StringsAPI.h"

#include "Logger.h"

#include <PEAnalyzer.h>
#include <t1ha.h>

#ifdef FEATURE_STACKTRACE_CHECK
    #include "StacktraceChecker.h"
    #ifdef FEATURE_ALLOW_SYSTEM_MODULES
        #include "SfcWrapper.h"
    #endif
#endif

namespace DllFilter {

    class KnownModulesStorage final {
    public:
        typedef struct {
            HMODULE Base;
            UINT64 Hash;
            ULONG Size;
            std::wstring Name;
        } MODULE_INFO;
    private:
        mutable RWLock Lock;
        std::map<HMODULE, MODULE_INFO> Modules;
        static UINT64 CalcModuleHash(HMODULE hModule) {
            try {
                UINT64 Hash = 0;
                PEAnalyzer pe(hModule, FALSE);
                const auto& Sections = pe.GetSectionsInfo();
                for (const auto& Section : Sections) {
                    ULONG Type = Section.Characteristics;
                    if ((Type & IMAGE_SCN_CNT_CODE) || (Type & IMAGE_SCN_MEM_EXECUTE)) {
                        Hash ^= t1ha0(reinterpret_cast<PBYTE>(hModule) + Section.OffsetInMemory, Section.SizeInMemory, 0x1EE7C0DE);
                    }
                }
                return Hash;
            }
            catch (...) {
                return 0; // We're unable to analyze this module
            }
        }
        static UINT64 CalcModuleHashSafe(HMODULE hModule) {
            __try {
                return CalcModuleHash(hModule);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return 0;
            }
        }
        static VOID EnumModules(BOOL(*Callback)(PebTeb::PLDR_MODULE Module, PVOID Arg), PVOID Arg) {
            const auto Peb = reinterpret_cast<PebTeb::PPEB>(__peb());
            PebTeb::PPEB_LDR_DATA LdrData = Peb->Ldr;
            const auto Header = &LdrData->InLoadOrderModuleList;
            for (
                auto Module = reinterpret_cast<PebTeb::PLDR_MODULE>(Header->Flink);
                ;
                Module = reinterpret_cast<PebTeb::PLDR_MODULE>(Module->InLoadOrderModuleList.Flink)
            ) {
                if (!Callback(Module, Arg) || Module->InLoadOrderModuleList.Flink == Header) break;
            }
        }
        static BOOL EnumModulesSafe(BOOL(*Callback)(PebTeb::PLDR_MODULE Module, PVOID Arg), PVOID Arg) {
            __try {
                EnumModules(Callback, Arg);
                return TRUE;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return FALSE;
            }
        }
        static BOOL EnumModulesCallback(PebTeb::PLDR_MODULE Module, PVOID Arg) {
            if (!Module || !Module->BaseAddress || !Arg) return FALSE; // Breaking an enumeration
            auto Local = reinterpret_cast<std::map<HMODULE, MODULE_INFO>*>(Arg);
            
            MODULE_INFO Info = {};
            Info.Base = reinterpret_cast<HMODULE>(Module->BaseAddress);
            Info.Hash = CalcModuleHashSafe(Info.Base);
            Info.Size = Module->SizeOfImage;
            
            LPCWSTR Path = NULL;
            ULONG PathLengthInBytes = 0;
            if (Module->FullDllName.Buffer && Module->FullDllName.Length) {
                Path = Module->FullDllName.Buffer;
                PathLengthInBytes = Module->FullDllName.Length;
            }
            else if (Module->BaseDllName.Buffer && Module->BaseDllName.Length) {
                Path = Module->BaseDllName.Buffer;
                PathLengthInBytes = Module->BaseDllName.Length;
            }

            if (Path && PathLengthInBytes) {
                Info.Name.resize(PathLengthInBytes / sizeof(WCHAR));
                memcpy(std::data(Info.Name), Path, PathLengthInBytes);
            }

            Local->emplace(Info.Base, Info);
            return TRUE; // Continue an enumeration
        }
    public:
        KnownModulesStorage(const KnownModulesStorage&) = delete;
        KnownModulesStorage(KnownModulesStorage&&) = delete;
        KnownModulesStorage& operator = (const KnownModulesStorage&) = delete;
        KnownModulesStorage& operator = (KnownModulesStorage&&) = delete;

        KnownModulesStorage() : Lock(), Modules() {}
        ~KnownModulesStorage() = default;

        VOID Collect() {
            std::map<HMODULE, MODULE_INFO> Local;
            EnumModulesSafe(EnumModulesCallback, &Local);
            Lock.LockExclusive();
            Modules.swap(Local);
            Lock.UnlockExclusive();
        }
        VOID Clear() {
            Lock.LockExclusive();
            Modules.clear();
            Lock.UnlockExclusive();
        }
        VOID Add(HMODULE hModule, ULONG Size, OPTIONAL PCUNICODE_STRING Name) {
            if (!hModule || !Size) return;
            MODULE_INFO Info = {};
            Info.Base = hModule;
            Info.Hash = CalcModuleHashSafe(hModule);
            Info.Size = Size;
            if (Name && Name->Buffer && Name->Length) {
                Info.Name.resize(Name->Length / sizeof(WCHAR));
                memcpy(std::data(Info.Name), Name->Buffer, Name->Length);
            }
            Lock.LockExclusive();
            Modules.emplace(hModule, Info);
            Lock.UnlockExclusive();
        }
        VOID Remove(HMODULE hModule) {
            if (!hModule) return;
            Lock.LockExclusive();
            Modules.erase(hModule);
            Lock.UnlockExclusive();
        }
        BOOL IsModulePresent(HMODULE hModule) const {
            Lock.LockShared();
            BOOL IsPresent = Modules.find(hModule) != Modules.end();
            Lock.UnlockShared();
            return IsPresent;
        }
        HMODULE GetModuleBase(PVOID Address) const {
            HMODULE hModule = NULL;
            Lock.LockShared();
            for (const auto& Module : Modules) {
                if (Module.first > Address) break;
                if (
                    static_cast<PBYTE>(Address) >= reinterpret_cast<PBYTE>(Module.second.Base) &&
                    static_cast<PBYTE>(Address) < (reinterpret_cast<PBYTE>(Module.second.Base) + Module.second.Size)
                ) {
                    hModule = Module.second.Base;
                    break;
                }
            }
            Lock.UnlockShared();
            return hModule;
        }
        BOOL IsAddressInKnownModule(PVOID Address) const {
            return GetModuleBase(Address) != NULL;
        }
        BOOL IsModuleValid(HMODULE hModule) const {
            if (!hModule) return FALSE;
            Lock.LockShared();
            const auto Module = Modules.find(hModule);
            BOOL IsValid = Module != Modules.end();
            if (IsValid) IsValid = Module->second.Hash == CalcModuleHashSafe(hModule);
            Lock.UnlockShared();
            return IsValid;
        }
        VOID RehashModule(HMODULE hModule) {
            if (!hModule) return;
            Lock.LockExclusive();
            auto Module = Modules.find(hModule);
            if (Module != Modules.end()) {
                Module->second.Hash = CalcModuleHashSafe(hModule);
            }
            Lock.UnlockExclusive();
        }
    };

#ifdef FEATURE_WINDOWS_HOOKS_FILTER
    class IgnoredModulesStorage final {
    private:
        mutable RWLock Lock;
        std::unordered_set<std::wstring> Modules;
    public:
        IgnoredModulesStorage(const IgnoredModulesStorage&) = delete;
        IgnoredModulesStorage(IgnoredModulesStorage&&) = delete;
        IgnoredModulesStorage& operator = (const IgnoredModulesStorage&) = delete;
        IgnoredModulesStorage& operator = (IgnoredModulesStorage&&) = delete;

        IgnoredModulesStorage() : Lock(), Modules() {}
        ~IgnoredModulesStorage() = default;

        VOID Add(const std::wstring& ModuleName) {
            Lock.LockExclusive();
            Modules.emplace(ModuleName);
            Lock.UnlockExclusive();
        }

        BOOL IsIgnored(const std::wstring& ModuleName) {
            Lock.LockShared();
            BOOL Ignored = Modules.find(ModuleName) != Modules.end();
            Lock.UnlockShared();
            return Ignored;
        }
    };
#endif

    static struct {
        _LdrRegisterDllNotification LdrRegisterDllNotification;
        _LdrUnregisterDllNotification LdrUnregisterDllNotification;
        PVOID Cookie;
        KnownModulesStorage KnownModules;
#ifdef FEATURE_WINDOWS_HOOKS_FILTER
        IgnoredModulesStorage IgnoredModules;
#endif
    } FilterData = {};

    DeclareHook(
        NTSTATUS, NTAPI, LdrLoadDll, 
        OPTIONAL IN PWCHAR PathToFile,
        IN PULONG Flags,
        IN PUNICODE_STRING ModuleFileName,
        OUT PHANDLE ModuleHandle
    ) {
#if defined ENABLE_LOGGING || defined FEATURE_ALLOW_SYSTEM_MODULES
        using namespace StringsAPI;
        std::wstring ModuleName = UnicodeStringToString(ModuleFileName);
#endif

#ifdef FEATURE_WINDOWS_HOOKS_FILTER
        if (FilterData.IgnoredModules.IsIgnored(ModuleName)) {
            return STATUS_NOT_FOUND;
        }
#endif

        Log(std::wstring(L"[i] Attempt to load library: ") + (!ModuleName.empty() ? ModuleName : L"UNKNOWN"));

#ifdef FEATURE_STACKTRACE_CHECK
        // Check the stacktrace to detect a __ClientLoadLibrary (windows hooks) or unknown module/memory:
        {
            using namespace StacktraceChecker;
            STACKTRACE_CHECK_RESULT CheckResult = CheckStackTrace();
            if (CheckResult != stValid) {
                switch (CheckResult) {
                case stUnknownModule:
                    Log(L"[x] Unknown caller module for LdrLoadLibrary, cancelled");
                    break;
                case stUnknownMemory:
                    Log(L"[x] Unknown caller memory for LdrLoadLibrary, cancelled");
                    break;
#ifdef FEATURE_WINDOWS_HOOKS_FILTER
                case stWindowsHooks:
#ifdef FEATURE_ALLOW_SYSTEM_MODULES
                    if (Sfc::IsSystemFile(ModuleName.c_str())) {
                        Log(L"[v] LdrLoadLibrary called from windows hooks handler, but allowed due to loading a system file: " + ModuleName);
                        return CallOriginal(LdrLoadDll)(PathToFile, Flags, ModuleFileName, ModuleHandle);
                    }
#endif
                    FilterData.IgnoredModules.Add(ModuleName);
                    Log(L"[x] LdrLoadLibrary called from windows hooks handler, cancelled");
                    break;
#endif
                }
                if (ModuleHandle) *ModuleHandle = NULL;
                return STATUS_NOT_FOUND;
            }
        }
#endif

        return CallOriginal(LdrLoadDll)(PathToFile, Flags, ModuleFileName, ModuleHandle);
    }

    static VOID CALLBACK DllNotificationRoutine(
        IN ULONG Reason, // LDR_DLL_NOTIFICATION_REASON_***
        IN PLDR_DLL_NOTIFICATION_DATA Data,
        IN OPTIONAL PVOID Context
    ) {
        PCUNICODE_STRING Path = NULL;
        if (Data->FullDllName && Data->FullDllName->Buffer && Data->FullDllName->Length) {
            Path = Data->FullDllName;
        }
        else if (Data->BaseDllName && Data->BaseDllName->Buffer && Data->BaseDllName->Length) {
            Path = Data->BaseDllName;
        }

#ifdef ENABLE_LOGGING
        if (Path) {
            std::wstring DllName(Path->Length / sizeof(WCHAR), NULL);
            memcpy(std::data(DllName), Path->Buffer, Path->Length);
            DllName.resize(wcslen(DllName.c_str()));
            switch (Reason) {
            case LDR_DLL_NOTIFICATION_REASON_LOADED:
                Log(L"[i] Dll loaded: " + DllName);
                break;
            case LDR_DLL_NOTIFICATION_REASON_UNLOADED:
                Log(L"[i] Dll unloaded: " + DllName);
                break;
            }
        }
#endif

        switch (Reason) {
        case LDR_DLL_NOTIFICATION_REASON_LOADED: {
            FilterData.KnownModules.Add(reinterpret_cast<HMODULE>(Data->DllBase), Data->SizeOfImage, Path);
            break;
        }
        case LDR_DLL_NOTIFICATION_REASON_UNLOADED: {
            FilterData.KnownModules.Remove(reinterpret_cast<HMODULE>(Data->DllBase));
            break;
        }
        }
    }

    BOOL EnableDllFilter()
    {
        if (FilterData.Cookie) return TRUE;

        // Initializing all loaded modules:
        FilterData.KnownModules.Collect();

        if (!FilterData.LdrRegisterDllNotification) {
            FilterData.LdrRegisterDllNotification = reinterpret_cast<_LdrRegisterDllNotification>(
                _GetProcAddress(AvnGlobals.hModules.hNtdll, "LdrRegisterDllNotification")
            );
        }

        if (!FilterData.LdrUnregisterDllNotification) {
            FilterData.LdrUnregisterDllNotification = reinterpret_cast<_LdrUnregisterDllNotification>(
                _GetProcAddress(AvnGlobals.hModules.hNtdll, "LdrUnregisterDllNotification")
            );
        }

        if (!FilterData.LdrRegisterDllNotification || !FilterData.LdrUnregisterDllNotification) {
            Log(L"[x] Unable to initialize Ldr***DllNotification");
            return FALSE;
        }

        NTSTATUS Status = FilterData.LdrRegisterDllNotification(
            0, 
            DllNotificationRoutine,
            NULL,
            &FilterData.Cookie
        );

        if (!NT_SUCCESS(Status) || !FilterData.Cookie) {
            Log(L"[x] Unable to register Dll notification");
            return FALSE;
        }

        SetHookTarget(LdrLoadDll, _GetProcAddress(AvnGlobals.hModules.hNtdll, "LdrLoadDll"));
        return EnableHook(LdrLoadDll);
    }

    VOID DisableDllFilter()
    {
        DisableHook(LdrLoadDll);
        if (!FilterData.Cookie) return;
        FilterData.LdrUnregisterDllNotification(FilterData.Cookie);
        FilterData.Cookie = NULL;
    }

    BOOL IsAddressInKnownModule(PVOID Address)
    {
        return FilterData.KnownModules.IsAddressInKnownModule(Address);
    }
}
#endif