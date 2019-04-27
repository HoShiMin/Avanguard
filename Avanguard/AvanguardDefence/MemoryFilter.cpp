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

#include <vector>
#include <unordered_set>

#include "AvnGlobals.h"

#include "MemoryFilter.h"

namespace MemoryFilter {

    class MemoryStorage {
    private:
        mutable RWLock Lock;
        mutable RWLock UpdateAndCheckLock;
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
            return IsAllocationBasePresent(Base);
        }

        BOOL IsAllocationBasePresent(LPCVOID AllocationBase) const {
            BeginCheck();
            Lock.LockShared();
            BOOL IsPresent = Bases.find(AllocationBase) != Bases.end();
            Lock.UnlockShared();
            EndCheck();
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

        VOID FindUnknownMemoryRegions(__out std::vector<MEMORY_REGION_INFO>& UnknownRegions) const {
            UnknownRegions.clear();
            MEMORY_BASIC_INFORMATION Info;
            LPCVOID BaseAddress = NULL;
            BeginCheck();
            Lock.LockShared();
            while (GetMemoryInfo(BaseAddress, &Info)) {
                if (IsProtectExecutable(Info.Protect) && Bases.find(Info.AllocationBase) == Bases.end()) {
                    UnknownRegions.emplace_back(Info.AllocationBase, Info.RegionSize);
                }
                BaseAddress = reinterpret_cast<const unsigned char*>(BaseAddress) + Info.RegionSize;
            }
            Lock.UnlockShared();
            EndCheck();
        }

        VOID BeginUpdate() {
            UpdateAndCheckLock.LockShared();
        }

        VOID EndUpdate() {
            UpdateAndCheckLock.UnlockShared();
        }

        VOID BeginCheck() const {
            UpdateAndCheckLock.LockExclusive();
        }

        VOID EndCheck() const {
            UpdateAndCheckLock.UnlockExclusive();
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
        if (MemoryStorage::IsProtectExecutable(Protect)) {
            FilterData.Storage.BeginUpdate();

            NTSTATUS Status = CallOriginal(NtAllocateVirtualMemory)(
                ProcessHandle,
                BaseAddress,
                ZeroBits,
                RegionSize,
                AllocationType,
                Protect
            );

            if (NT_SUCCESS(Status) 
                && (AllocationType & MEM_COMMIT)
                && (ProcessHandle == NtCurrentProcess() || GetProcessId(ProcessHandle) == FilterData.Pid)
            ) {
                FilterData.Storage.AddBase(*BaseAddress);
            }

            FilterData.Storage.EndUpdate();
            return Status;
        }
        else {
            return CallOriginal(NtAllocateVirtualMemory)(
                ProcessHandle,
                BaseAddress,
                ZeroBits,
                RegionSize,
                AllocationType,
                Protect
            );
        }
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
            && (MemoryStorage::IsProtectExecutable(NewAccessProtection) || (MemoryStorage::IsProtectExecutable(*OldAccessProtection)))
            && (ProcessHandle == NtCurrentProcess() || GetProcessId(ProcessHandle) == FilterData.Pid)
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
            && FreeType == MEM_RELEASE
            && (ProcessHandle == NtCurrentProcess() || GetProcessId(ProcessHandle) == FilterData.Pid)
        ) {
            FilterData.Storage.RemoveBaseByAddress(*BaseAddress);
        }

        return Status;
    }

    enum SECTION_INHERIT {
        ViewShare,
        ViewUnmap
    };

    DeclareHook(
        NTSTATUS, NTAPI, NtMapViewOfSection,
        IN HANDLE SectionHandle,
        IN HANDLE ProcessHandle,
        IN OUT PVOID* BaseAddress,
        IN ULONG_PTR ZeroBits,
        IN SIZE_T CommitSize,
        IN OUT OPTIONAL PLARGE_INTEGER SectionOffset,
        IN OUT PSIZE_T ViewSize,
        IN SECTION_INHERIT InheritDisposition,
        IN ULONG AllocationType,
        IN ULONG Win32Protect
    ) {
        if (MemoryStorage::IsProtectExecutable(Win32Protect)) {
            FilterData.Storage.BeginUpdate();

            NTSTATUS Status = CallOriginal(NtMapViewOfSection)(
                SectionHandle,
                ProcessHandle,
                BaseAddress,
                ZeroBits,
                CommitSize,
                SectionOffset,
                ViewSize,
                InheritDisposition,
                AllocationType,
                Win32Protect
            );

            if (NT_SUCCESS(Status)
                && (ProcessHandle == NtCurrentProcess() || GetProcessId(ProcessHandle) == FilterData.Pid)
            ) {
                FilterData.Storage.AddBase(*BaseAddress);
            }

            FilterData.Storage.EndUpdate();

            return Status;
        }
        else {
            return CallOriginal(NtMapViewOfSection)(
                SectionHandle,
                ProcessHandle,
                BaseAddress,
                ZeroBits,
                CommitSize,
                SectionOffset,
                ViewSize,
                InheritDisposition,
                AllocationType,
                Win32Protect
            );
        }
    }

    DeclareHook(
        NTSTATUS, NTAPI, NtUnmapViewOfSection,
        IN HANDLE ProcessHandle,
        IN OPTIONAL PVOID BaseAddress
    ) {
        NTSTATUS Status = CallOriginal(NtUnmapViewOfSection)(ProcessHandle, BaseAddress);
        if (NT_SUCCESS(Status)
            && (ProcessHandle == NtCurrentProcess() || GetProcessId(ProcessHandle) == FilterData.Pid)
        ) {
            FilterData.Storage.RemoveBase(BaseAddress);
        }
        return Status;
    }

    BOOL EnableMemoryFilter(BOOL InitialCollectMemoryInfo)
    {
        if (FilterData.Enabled) return TRUE;

        FilterData.Pid = __pid();
        
        SetHookTarget(NtAllocateVirtualMemory, _GetProcAddress(AvnGlobals.hModules.hNtdll, "NtAllocateVirtualMemory"));
        SetHookTarget(NtProtectVirtualMemory, _GetProcAddress(AvnGlobals.hModules.hNtdll, "NtProtectVirtualMemory"));
        SetHookTarget(NtFreeVirtualMemory, _GetProcAddress(AvnGlobals.hModules.hNtdll, "NtFreeVirtualMemory"));
        SetHookTarget(NtMapViewOfSection, _GetProcAddress(AvnGlobals.hModules.hNtdll, "NtMapViewOfSection"));
        SetHookTarget(NtUnmapViewOfSection, _GetProcAddress(AvnGlobals.hModules.hNtdll, "NtUnmapViewOfSection"));

        FilterData.Enabled = EnableHook(NtAllocateVirtualMemory)
            && EnableHook(NtProtectVirtualMemory)
            && EnableHook(NtFreeVirtualMemory)
            && EnableHook(NtMapViewOfSection)
            && EnableHook(NtUnmapViewOfSection);

        if (InitialCollectMemoryInfo)
            FilterData.Storage.Collect();

        if (!FilterData.Enabled)
            DisableMemoryFilter();

        return FilterData.Enabled;
    }

    VOID DisableMemoryFilter()
    {
        DisableHook(NtAllocateVirtualMemory);
        DisableHook(NtProtectVirtualMemory);
        DisableHook(NtFreeVirtualMemory);
        DisableHook(NtMapViewOfSection);
        DisableHook(NtUnmapViewOfSection);
        FilterData.Storage.Clear();
        FilterData.Enabled = FALSE;
    }

    VOID CollectMemoryInfo()
    {
        FilterData.Storage.Collect();
    }

    BOOL IsMemoryKnown(LPCVOID Address) {
        if (!FilterData.Enabled) return TRUE;
        return FilterData.Storage.IsMemoryPresent(Address);
    }

    VOID FindUnknownMemoryRegions(__out std::vector<MEMORY_REGION_INFO>& UnknownRegions) {
        FilterData.Storage.FindUnknownMemoryRegions(UnknownRegions);
    }

    VOID BeginMemoryUpdate()
    {
        FilterData.Storage.BeginUpdate();
    }

    VOID EndMemoryUpdate()
    {
        FilterData.Storage.EndUpdate();
    }

    VOID AddKnownMemoryBase(LPCVOID AllocationBase)
    {
        FilterData.Storage.AddBase(AllocationBase);
    }

    VOID AddKnownMemory(LPCVOID Address)
    {
        FilterData.Storage.AddBaseByAddress(Address);
    }
}
#endif