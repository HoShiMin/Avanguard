#include "AvnDefinitions.h"
#ifdef FEATURE_MEMORY_FILTER

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>

#include "Locks.h"
#include "NativeAPI.h"
#include "HookLib.h"

#include <unordered_set>

#include "AvnGlobals.h"

#include "MemoryFilter.h"

namespace MemoryFilter {

    class MemoryStorage {
    private:
        mutable RWLock Lock;
        std::unordered_set<LPCVOID> Bases;
    public:
        MemoryStorage(const MemoryStorage&) = delete;
        MemoryStorage(MemoryStorage&&) = delete;
        MemoryStorage& operator = (const MemoryStorage&) = delete;
        MemoryStorage& operator = (MemoryStorage&&) = delete;

        MemoryStorage() : Lock(), Bases() {}
        ~MemoryStorage() = default;

        static BOOL GetMemoryInfo(IN LPCVOID Address, OUT PMEMORY_BASIC_INFORMATION Info) {
            if (!Info) return FALSE;
            SIZE_T ResultLength = 0;
            return NT_SUCCESS(NtQueryVirtualMemory(
                NtCurrentProcess(),
                const_cast<PVOID>(Address),
                MemoryBasicInformation,
                Info,
                sizeof(*Info),
                &ResultLength
            ));
        }

        static BOOL IsProtectExecutable(ULONG Protect) {
            return Protect & PAGE_EXECUTE
                || Protect & PAGE_EXECUTE_READ
                || Protect & PAGE_EXECUTE_READWRITE
                || Protect & PAGE_EXECUTE_WRITECOPY;
        }

        static PVOID GetAllocationBase(LPCVOID Address) {
            MEMORY_BASIC_INFORMATION Info;
            if (GetMemoryInfo(Address, &Info))
                return Info.AllocationBase;
            return NULL;
        }

        VOID AddBase(LPCVOID AllocationBase) {
            Lock.LockExclusive();
            Bases.emplace(AllocationBase);
            Lock.UnlockExclusive();
        }

        VOID AddBaseByAddress(LPCVOID Address) {
            MEMORY_BASIC_INFORMATION Info;
            if (!GetMemoryInfo(Address, &Info)) return;
            if (!IsProtectExecutable(Info.Protect) && !IsProtectExecutable(Info.AllocationProtect)) return;
            AddBase(Info.AllocationBase);
        }

        VOID RemoveBase(LPCVOID AllocationBase) {
            Lock.LockExclusive();
            Bases.erase(AllocationBase);
            Lock.UnlockExclusive();
        }

        VOID RemoveBaseByAddress(LPCVOID Address) {
            RemoveBase(GetAllocationBase(Address));
        }

        BOOL IsMemoryPresent(LPCVOID Address) const {
            LPCVOID Base = GetAllocationBase(Address);
            if (!Base) return FALSE;
            Lock.LockShared();
            BOOL IsPresent = Bases.find(Base) != Bases.end();
            Lock.UnlockShared();
            return IsPresent;
        }

        VOID Collect() {
            MEMORY_BASIC_INFORMATION Info;
            LPCVOID BaseAddress = NULL;
            Lock.LockExclusive();
            Bases.clear();
            while (GetMemoryInfo(BaseAddress, &Info)) {
                if (IsProtectExecutable(Info.Protect)) {
                    Bases.emplace(Info.AllocationBase);
                }
                BaseAddress = reinterpret_cast<const unsigned char*>(BaseAddress) + Info.RegionSize;
            }
            Lock.UnlockExclusive();
        }

        VOID Clear() {
            Lock.LockExclusive();
            Bases.clear();
            Lock.UnlockExclusive();
        }
    };

    static struct {
        MemoryStorage Storage;
        ULONG Pid;
        BOOLEAN Enabled;
    } FilterData = {};

    DeclareHook(
        NTSTATUS, NTAPI, NtAllocateVirtualMemory,
        IN HANDLE ProcessHandle,
        IN OUT PVOID* BaseAddress,
        IN ULONG_PTR ZeroBits,
        IN OUT PSIZE_T RegionSize,
        IN ULONG AllocationType,
        IN ULONG Protect
    ) {
        NTSTATUS Status = CallOriginal(NtAllocateVirtualMemory)(
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            RegionSize,
            AllocationType,
            Protect
        );

        if (NT_SUCCESS(Status)
            && (ProcessHandle == NtCurrentProcess() || GetProcessId(ProcessHandle) == FilterData.Pid)
            && (AllocationType & MEM_RESERVE)
            && MemoryStorage::IsProtectExecutable(Protect)
        ) {
            FilterData.Storage.AddBase(*BaseAddress);
        }

        return Status;
    }

    DeclareHook(
        NTSTATUS, NTAPI, NtProtectVirtualMemory,
        IN HANDLE ProcessHandle,
        IN OUT PVOID* BaseAddress,
        IN OUT PULONG NumberOfBytesToProtect,
        IN ULONG NewAccessProtection,
        OUT PULONG OldAccessProtection
    ) {
        NTSTATUS Status = CallOriginal(NtProtectVirtualMemory)(
            ProcessHandle,
            BaseAddress,
            NumberOfBytesToProtect,
            NewAccessProtection,
            OldAccessProtection
        );

        if (NT_SUCCESS(Status)
            && (ProcessHandle == NtCurrentProcess() || GetProcessId(ProcessHandle) == FilterData.Pid)
            && (MemoryStorage::IsProtectExecutable(NewAccessProtection) || (MemoryStorage::IsProtectExecutable(*OldAccessProtection)))
        ) {
            MEMORY_BASIC_INFORMATION Info;
            if (MemoryStorage::GetMemoryInfo(*BaseAddress, &Info)) {
                FilterData.Storage.AddBase(Info.AllocationBase);
            }
        }

        return Status;
    }

    DeclareHook(
        NTSTATUS, NTAPI, NtFreeVirtualMemory,
        IN HANDLE ProcessHandle,
        IN OUT PVOID* BaseAddress,
        IN OUT PSIZE_T RegionSize,
        IN ULONG FreeType
    ) {
        NTSTATUS Status = CallOriginal(NtFreeVirtualMemory)(
            ProcessHandle,
            BaseAddress,
            RegionSize,
            FreeType
        );

        if (NT_SUCCESS(Status)
            && (ProcessHandle == NtCurrentProcess() || GetProcessId(ProcessHandle) == FilterData.Pid)
            && FreeType == MEM_RELEASE
        ) {
            FilterData.Storage.RemoveBaseByAddress(*BaseAddress);
        }

        return Status;
    }

    BOOL EnableMemoryFilter()
    {
        if (FilterData.Enabled) return TRUE;

        FilterData.Pid = __pid();
        FilterData.Storage.Collect();
        
        SetHookTarget(NtAllocateVirtualMemory, _GetProcAddress(AvnGlobals.hModules.hNtdll, "NtAllocateVirtualMemory"));
        SetHookTarget(NtProtectVirtualMemory, _GetProcAddress(AvnGlobals.hModules.hNtdll, "NtProtectVirtualMemory"));
        SetHookTarget(NtFreeVirtualMemory, _GetProcAddress(AvnGlobals.hModules.hNtdll, "NtFreeVirtualMemory"));

        FilterData.Enabled = EnableHook(NtAllocateVirtualMemory)
            && EnableHook(NtProtectVirtualMemory)
            && EnableHook(NtFreeVirtualMemory);

        if (!FilterData.Enabled)
            DisableMemoryFilter();

        return FilterData.Enabled;
    }

    VOID DisableMemoryFilter()
    {
        DisableHook(NtAllocateVirtualMemory);
        DisableHook(NtProtectVirtualMemory);
        DisableHook(NtFreeVirtualMemory);
        FilterData.Storage.Clear();
        FilterData.Enabled = FALSE;
    }

    BOOL IsMemoryKnown(LPCVOID Address) {
        if (!FilterData.Enabled) return TRUE;
        return FilterData.Storage.IsMemoryPresent(Address);
    }
}
#endif