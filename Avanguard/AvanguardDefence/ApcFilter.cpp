#include "AvnDefinitions.h"
#ifdef FEATURE_APC_FILTER

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>

#include "NativeAPI.h"
#include "AvnGlobals.h"

#include <HookLib.h>

#include "Locks.h"
#include <unordered_set>

#ifdef FEATURE_DLL_FILTER
#include "DllFilter.h"
#endif

#ifdef FEATURE_MEMORY_FILTER
#include "MemoryFilter.h"
#endif

#include "ApcFilter.h"

namespace ApcFilter {

    class ApcRoutinesStorage final {
    private:
        mutable RWLock Lock;
        std::unordered_set<LPCVOID> Allowed;
        std::unordered_set<LPCVOID> Denied;
    public:
        ApcRoutinesStorage(const ApcRoutinesStorage&) = delete;
        ApcRoutinesStorage(ApcRoutinesStorage&&) = delete;
        ApcRoutinesStorage& operator = (const ApcRoutinesStorage&) = delete;
        ApcRoutinesStorage& operator = (ApcRoutinesStorage&&) = delete;

        ApcRoutinesStorage() : Lock(), Allowed(), Denied() {}
        ~ApcRoutinesStorage() = default;

        VOID AddAllowed(LPCVOID EntryPoint) {
            if (EntryPoint) {
                Lock.LockExclusive();
                Allowed.emplace(EntryPoint);
                Lock.UnlockExclusive();
            }
        }

        VOID AddDenied(LPCVOID EntryPoint) {
            if (EntryPoint) {
                Lock.LockExclusive();
                Denied.emplace(EntryPoint);
                Lock.UnlockExclusive();
            }
        }

        VOID Clear() {
            Lock.LockExclusive();
            Allowed.clear();
            Denied.clear();
            Lock.UnlockExclusive();
        }

        BOOL IsAllowed(LPCVOID EntryPoint) const {
            Lock.LockShared();
            BOOL Exists = Allowed.find(EntryPoint) != Allowed.end();
            Lock.UnlockShared();
            return Exists;
        }

        BOOL IsDenied(LPCVOID EntryPoint) const {
            Lock.LockShared();
            BOOL Exists = Denied.find(EntryPoint) != Denied.end();
            Lock.UnlockShared();
            return Exists;
        }
    };

    static struct {
        ApcRoutinesStorage ApcRoutines;
    } FilterData = {};

    static BOOL IsApcAllowed(PVOID ApcRoutine)
    {
        if (FilterData.ApcRoutines.IsAllowed(ApcRoutine))
            return TRUE;
        
        if (FilterData.ApcRoutines.IsDenied(ApcRoutine))
            return FALSE;

#ifdef FEATURE_DLL_FILTER
        if (DllFilter::IsAddressInKnownModule(ApcRoutine))
            return TRUE;
#endif

#ifdef FEATURE_MEMORY_FILTER
        if (MemoryFilter::IsMemoryKnown(ApcRoutine))
            return TRUE;
#endif

        return FALSE;
    }

    [[noreturn]]
    static inline VOID DiscardApc(PCONTEXT Context)
    {
        NtContinue(Context, FALSE);
    }

    extern "C" {
        VOID NTAPI KiApcStub(); // KiUserApcDispatcher hook (defined in ApcStub.asm)

#ifdef _AMD64_
        // Context passes through a stack! Don't call it directly from a C/C++ code!
        VOID (NTAPI *OriginalApcDispatcher)(CONTEXT Context) = NULL;
        
        VOID NTAPI ApcHandler(PCONTEXT Context) // Calls from KiApcStub() in ApcStub.asm
        {
            // ApcRoutine = Context->P4Home, Arg = Context->P1Home:
            if (!IsApcAllowed(reinterpret_cast<PVOID>(Context->P4Home)))
                DiscardApc(Context);
        }
#else
        // All arguments passes through a stack! Don't call it directly from a C/C++ code!
        VOID(NTAPI* OriginalApcDispatcher)(
            PVOID NormalRoutine,   // ApcProc
            PVOID SystemArgument1, // Argument
            PVOID SystemArgument2,
            CONTEXT Context
        ) = NULL;

        VOID NTAPI ApcHandler(PVOID ApcRoutine, PVOID Arg, PCONTEXT Context) // Calls from KiApcStub() in ApcStub.asm
        {
            if (!IsApcAllowed(ApcRoutine))
                DiscardApc(Context);
        }
#endif
    }

    DeclareHook(
        NTSTATUS, NTAPI, NtQueueApcThread,
        IN HANDLE ThreadHandle,
        IN PIO_APC_ROUTINE ApcRoutine,
        IN OPTIONAL PVOID ApcRoutineContext,
        IN OPTIONAL PIO_STATUS_BLOCK ApcStatusBlock,
        IN ULONG ApcReserved
    ) {
        FilterData.ApcRoutines.AddAllowed(ApcRoutine);
        return CallOriginal(NtQueueApcThread)(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
    }

    BOOL EnableApcFilter()
    {
        FilterData.ApcRoutines.Clear();
        FilterData.ApcRoutines.AddDenied(_GetProcAddress(AvnGlobals.hModules.hNtdll, "LdrLoadDll"));
        FilterData.ApcRoutines.AddDenied(_GetProcAddress(AvnGlobals.hModules.hKernel32, "LoadLibraryA"));
        FilterData.ApcRoutines.AddDenied(_GetProcAddress(AvnGlobals.hModules.hKernel32, "LoadLibraryW"));
        FilterData.ApcRoutines.AddDenied(_GetProcAddress(AvnGlobals.hModules.hKernel32, "LoadLibraryExA"));
        FilterData.ApcRoutines.AddDenied(_GetProcAddress(AvnGlobals.hModules.hKernel32, "LoadLibraryExW"));
        FilterData.ApcRoutines.AddDenied(_GetProcAddress(AvnGlobals.hModules.hKernelBase, "LoadLibraryA"));
        FilterData.ApcRoutines.AddDenied(_GetProcAddress(AvnGlobals.hModules.hKernelBase, "LoadLibraryW"));
        FilterData.ApcRoutines.AddDenied(_GetProcAddress(AvnGlobals.hModules.hKernelBase, "LoadLibraryExA"));
        FilterData.ApcRoutines.AddDenied(_GetProcAddress(AvnGlobals.hModules.hKernelBase, "LoadLibraryExW"));

        SetHookTarget(NtQueueApcThread, _GetProcAddress(AvnGlobals.hModules.hNtdll, "NtQueueApcThread"));

        BOOL Status = SetHook(
            _GetProcAddress(AvnGlobals.hModules.hNtdll, "KiUserApcDispatcher"),
            KiApcStub,
            reinterpret_cast<LPVOID*>(&OriginalApcDispatcher)
        ) && EnableHook(NtQueueApcThread);

        if (!Status) DisableApcFilter();
        return Status;
    }

    VOID DisableApcFilter()
    {
        RemoveHook(OriginalApcDispatcher);
        DisableHook(NtQueueApcThread);
        FilterData.ApcRoutines.Clear();
    }
}

#endif