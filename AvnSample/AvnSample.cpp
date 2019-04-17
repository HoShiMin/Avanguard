#include <cstdio>
#include <vector>

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

#include <AvnApi.h>
#pragma comment(lib, "Avanguard.lib")

#include <intrin.h>

#define NtCurrentProcess() ((HANDLE)-1)
#define NtCurrentThread() ((HANDLE)-2)

extern "C" {
    NTSYSAPI NTSTATUS NtOpenThread(
        OUT PHANDLE ThreadHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        IN CLIENT_ID* ClientId
    );

    NTSYSAPI NTSTATUS NTAPI NtContinue(
        IN PCONTEXT ThreadContext,
        IN BOOLEAN RaiseAlert
    );

    NTSYSAPI NTSTATUS NTAPI NtSuspendThread(
        IN HANDLE ThreadHandle,
        OUT OPTIONAL PULONG PreviousSuspendCount
    );

    NTSYSAPI NTSTATUS NTAPI NtResumeThread(
        IN HANDLE ThreadHandle,
        OUT OPTIONAL PULONG SuspendCount
    );

    NTSYSAPI NTSTATUS NTAPI NtGetContextThread(
        IN HANDLE ThreadHandle,
        OUT PCONTEXT Context
    );

    NTSYSAPI NTSTATUS NTAPI NtSetContextThread(
        IN HANDLE ThreadHandle,
        IN PCONTEXT Context
    );

    NTSYSAPI NTSTATUS NTAPI NtFlushInstructionCache(
        IN HANDLE ProcessHandle,
        IN PVOID BaseAddress,
        IN SIZE_T NumberOfBytesToFlush
    );

    NTSYSAPI NTSTATUS NTAPI NtWriteVirtualMemory(
        IN HANDLE ProcessHandle,
        IN PVOID BaseAddress,
        IN PVOID Buffer,
        IN ULONG NumberOfBytesToWrite,
        OUT OPTIONAL PULONG NumberOfBytesWritten
    );
}

#ifdef _AMD64_
class Shell {
#pragma pack(push, 1)
    typedef struct _SHELL_MAPPING {
        const unsigned char Reserved0[145];
        const void* Arg;
        const unsigned char Reserved1[2];
        const void* Func;
        const unsigned char Reserved[147];
    } SHELL_MAPPING, *PSHELL_MAPPING;
#pragma pack(pop)
    unsigned char Code[310] = {
        /* +000 */ 0x9C, // pushfq
        /* +001 */ 0x50, // push rax
        /* +002 */ 0x51, // push rcx
        /* +003 */ 0x52, // push rdx
        /* +004 */ 0x53, // push rbx
        /* +005 */ 0x54, // push rsp
        /* +006 */ 0x55, // push rbp
        /* +007 */ 0x56, // push rsi
        /* +008 */ 0x57, // push rdi
        /* +009 */ 0x41, 0x50, // push r8
        /* +011 */ 0x41, 0x51, // push r9
        /* +013 */ 0x41, 0x52, // push r10
        /* +015 */ 0x41, 0x53, // push r11
        /* +017 */ 0x41, 0x54, // push r12
        /* +019 */ 0x41, 0x55, // push r13
        /* +021 */ 0x41, 0x56, // push r14
        /* +023 */ 0x41, 0x57, // push r15

        /* +025 */ 0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00, // sub rsp, 16 * sizeof(OWORD)
        /* +032 */ 0x0F, 0x29, 0x04, 0x24,                               // movaps [rsp + 0  * sizeof(OWORD)], xmm0
        /* +036 */ 0x0F, 0x29, 0x4C, 0x24, 0x10,                         // movaps [rsp + 1  * sizeof(OWORD)], xmm1
        /* +041 */ 0x0F, 0x29, 0x54, 0x24, 0x20,                         // movaps [rsp + 2  * sizeof(OWORD)], xmm2
        /* +046 */ 0x0F, 0x29, 0x5C, 0x24, 0x30,                         // movaps [rsp + 3  * sizeof(OWORD)], xmm3
        /* +051 */ 0x0F, 0x29, 0x64, 0x24, 0x40,                         // movaps [rsp + 4  * sizeof(OWORD)], xmm4
        /* +056 */ 0x0F, 0x29, 0x6C, 0x24, 0x50,                         // movaps [rsp + 5  * sizeof(OWORD)], xmm5
        /* +061 */ 0x0F, 0x29, 0x74, 0x24, 0x60,                         // movaps [rsp + 6  * sizeof(OWORD)], xmm6
        /* +066 */ 0x0F, 0x29, 0x7C, 0x24, 0x70,                         // movaps [rsp + 7  * sizeof(OWORD)], xmm7
        /* +071 */ 0x44, 0x0F, 0x29, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, // movaps [rsp + 8  * sizeof(OWORD)], xmm8
        /* +080 */ 0x44, 0x0F, 0x29, 0x8C, 0x24, 0x90, 0x00, 0x00, 0x00, // movaps [rsp + 9  * sizeof(OWORD)], xmm9
        /* +089 */ 0x44, 0x0F, 0x29, 0x94, 0x24, 0xA0, 0x00, 0x00, 0x00, // movaps [rsp + 10 * sizeof(OWORD)], xmm10
        /* +098 */ 0x44, 0x0F, 0x29, 0x9C, 0x24, 0xB0, 0x00, 0x00, 0x00, // movaps [rsp + 11 * sizeof(OWORD)], xmm11
        /* +107 */ 0x44, 0x0F, 0x29, 0xA4, 0x24, 0xC0, 0x00, 0x00, 0x00, // movaps [rsp + 12 * sizeof(OWORD)], xmm12
        /* +116 */ 0x44, 0x0F, 0x29, 0xAC, 0x24, 0xD0, 0x00, 0x00, 0x00, // movaps [rsp + 13 * sizeof(OWORD)], xmm13
        /* +125 */ 0x44, 0x0F, 0x29, 0xB4, 0x24, 0xE0, 0x00, 0x00, 0x00, // movaps [rsp + 14 * sizeof(OWORD)], xmm14
        /* +134 */ 0x44, 0x0F, 0x29, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00, // movaps [rsp + 15 * sizeof(OWORD)], xmm15

        /* +143 */ 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, Arg
        /* +153 */ 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, Func
        /* +163 */ 0xFF, 0xD0, // call rax

        /* +165 */ 0x44, 0x0F, 0x29, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00, // movaps xmm15, [rsp + 15 * sizeof(OWORD)]
        /* +174 */ 0x44, 0x0F, 0x29, 0xB4, 0x24, 0xE0, 0x00, 0x00, 0x00, // movaps xmm14, [rsp + 14 * sizeof(OWORD)]
        /* +183 */ 0x44, 0x0F, 0x29, 0xAC, 0x24, 0xD0, 0x00, 0x00, 0x00, // movaps xmm13, [rsp + 13 * sizeof(OWORD)]
        /* +192 */ 0x44, 0x0F, 0x29, 0xA4, 0x24, 0xC0, 0x00, 0x00, 0x00, // movaps xmm12, [rsp + 12 * sizeof(OWORD)]
        /* +201 */ 0x44, 0x0F, 0x29, 0x9C, 0x24, 0xB0, 0x00, 0x00, 0x00, // movaps xmm11, [rsp + 11 * sizeof(OWORD)]
        /* +210 */ 0x44, 0x0F, 0x29, 0x94, 0x24, 0xA0, 0x00, 0x00, 0x00, // movaps xmm10, [rsp + 10 * sizeof(OWORD)]
        /* +219 */ 0x44, 0x0F, 0x29, 0x8C, 0x24, 0x90, 0x00, 0x00, 0x00, // movaps xmm9,  [rsp + 9 * sizeof(OWORD)]
        /* +228 */ 0x44, 0x0F, 0x29, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, // movaps xmm8,  [rsp + 8 * sizeof(OWORD)]
        /* +237 */ 0x0F, 0x29, 0x7C, 0x24, 0x70,                         // movaps xmm7,  [rsp + 7 * sizeof(OWORD)]
        /* +242 */ 0x0F, 0x29, 0x74, 0x24, 0x60,                         // movaps xmm6,  [rsp + 6 * sizeof(OWORD)]
        /* +247 */ 0x0F, 0x29, 0x6C, 0x24, 0x50,                         // movaps xmm5,  [rsp + 5 * sizeof(OWORD)]
        /* +252 */ 0x0F, 0x29, 0x64, 0x24, 0x40,                         // movaps xmm4,  [rsp + 4 * sizeof(OWORD)]
        /* +257 */ 0x0F, 0x29, 0x5C, 0x24, 0x30,                         // movaps xmm3,  [rsp + 3 * sizeof(OWORD)]
        /* +262 */ 0x0F, 0x29, 0x54, 0x24, 0x20,                         // movaps xmm2,  [rsp + 2 * sizeof(OWORD)]
        /* +267 */ 0x0F, 0x29, 0x4C, 0x24, 0x10,                         // movaps xmm1,  [rsp + 1 * sizeof(OWORD)]
        /* +272 */ 0x0F, 0x29, 0x04, 0x24,                               // movaps xmm0,  [rsp + 0 * sizeof(OWORD)]
        /* +276 */ 0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00, // add rsp, 16 * sizeof(OWORD)

        /* +283 */ 0x41, 0x5F, // pop r15
        /* +285 */ 0x41, 0x5E, // pop r14
        /* +287 */ 0x41, 0x5D, // pop r13
        /* +289 */ 0x41, 0x5C, // pop r12
        /* +291 */ 0x41, 0x5B, // pop r11
        /* +293 */ 0x41, 0x5A, // pop r10
        /* +295 */ 0x41, 0x59, // pop r9
        /* +297 */ 0x41, 0x58, // pop r8
        /* +299 */ 0x5F, // pop rdi
        /* +300 */ 0x5E, // pop rsi
        /* +301 */ 0x5D, // pop rbp
        /* +302 */ 0x5C, // pop rsp
        /* +303 */ 0x5B, // pop rbx
        /* +304 */ 0x5A, // pop rdx
        /* +305 */ 0x59, // pop rcx
        /* +306 */ 0x58, // pop rax
        /* +307 */ 0x9D, // popfq
        /* +308 */ 0xC3, // ret
        /* +309 */ 0xCC, // int 3h (breakpoint)
    };
    static_assert(sizeof(SHELL_MAPPING) == sizeof(Code), "sizeof(SHELL_MAPPING) != sizeof(Code)");

    typedef enum _WRK_KTHREAD_STATE : ULONG {
        Initialized,
        Ready,
        Running,
        Standby,
        Terminated,
        Waiting,
        Transition,
        DeferredReady,
        GateWaitObsolete,
        WaitingForProcessInSwap,
        MaximumThreadState
    } WRK_KTHREAD_STATE, * PWRK_KTHREAD_STATE;

    typedef enum _WRK_KWAIT_REASON : ULONG {
        Executive,
        FreePage,
        PageIn,
        PoolAllocation,
        DelayExecution,
        Suspended,
        UserRequest,
        WrExecutive,
        WrFreePage,
        WrPageIn,
        WrPoolAllocation,
        WrDelayExecution,
        WrSuspended,
        WrUserRequest,
        WrEventPair,
        WrQueue,
        WrLpcReceive,
        WrLpcReply,
        WrVirtualMemory,
        WrPageOut,
        WrRendezvous,
        WrKeyedEvent,
        WrTerminated,
        WrProcessInSwap,
        WrCpuRateControl,
        WrCalloutStack,
        WrKernel,
        WrResource,
        WrPushLock,
        WrMutex,
        WrQuantumEnd,
        WrDispatchInt,
        WrPreempted,
        WrYieldExecution,
        WrFastMutex,
        WrGuardedMutex,
        WrRundown,
        WrAlertByThreadId,
        WrDeferredPreempt,
        MaximumWaitReason
    } WRK_KWAIT_REASON, * PWRK_KWAIT_REASON;

    typedef struct _WRK_SYSTEM_THREAD_INFORMATION {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
        PVOID StartAddress;
        CLIENT_ID ClientId;
        KPRIORITY Priority;
        LONG BasePriority;
        ULONG ContextSwitches;
        WRK_KTHREAD_STATE ThreadState; // ULONG
        WRK_KWAIT_REASON WaitReason; // ULONG
    } WRK_SYSTEM_THREAD_INFORMATION, * PWRK_SYSTEM_THREAD_INFORMATION;

    typedef struct _WRK_SYSTEM_PROCESS_INFORMATION {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER SpareLi1;
        LARGE_INTEGER SpareLi2;
        LARGE_INTEGER SpareLi3;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR PageDirectoryBase;
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
        SYSTEM_THREAD_INFORMATION Threads[1];
    } WRK_SYSTEM_PROCESS_INFORMATION, * PWRK_SYSTEM_PROCESS_INFORMATION;

    static BOOLEAN NTAPI EnumProcesses(
        BOOLEAN(*Callback)(
            PWRK_SYSTEM_PROCESS_INFORMATION Process,
            OPTIONAL PVOID Argument
        ),
        OPTIONAL PVOID Argument
    ) {
        ULONG Length = 0;
        NTSTATUS Status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &Length);
        if (Status != STATUS_INFO_LENGTH_MISMATCH) return FALSE;

        std::vector<BYTE> Buffer(Length);
        
        Status = NtQuerySystemInformation(SystemProcessInformation, &Buffer[0], Length, &Length);
        if (!NT_SUCCESS(Status)) return FALSE;
    
        auto Info = reinterpret_cast<PWRK_SYSTEM_PROCESS_INFORMATION>(&Buffer[0]);
        do {
            if (!Callback(Info, Argument)) break;
            Info = (PWRK_SYSTEM_PROCESS_INFORMATION)((PBYTE)Info + Info->NextEntryOffset);
        } while (Info->NextEntryOffset);

        return TRUE;
    }

    static DWORD FindReadyThread(DWORD ProcessId)
    {
        struct ARGS {
            DWORD ProcessId;
            DWORD ThreadId;
            DWORD FoundThreadId;
        } Args = {};
        Args.ProcessId = GetCurrentProcessId();
        Args.ThreadId = GetCurrentThreadId();

        EnumProcesses([](PWRK_SYSTEM_PROCESS_INFORMATION Process, PVOID Arg) -> BOOLEAN {
            auto Args = reinterpret_cast<ARGS*>(Arg);
            if (Process->UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<SIZE_T>(Args->ProcessId))) 
                return TRUE;

            for (unsigned i = 0; i < Process->NumberOfThreads; ++i) {
                if (Process->Threads[i].ThreadState == WRK_KTHREAD_STATE::Ready
                    || Process->Threads[i].ThreadState == WRK_KTHREAD_STATE::Running)
                {
                    if (Args->ProcessId != Args->ProcessId
                        || Process->Threads[i].ClientId.UniqueThread != reinterpret_cast<HANDLE>(static_cast<SIZE_T>(Args->ThreadId)))
                    {
                        Args->FoundThreadId = static_cast<DWORD>(reinterpret_cast<SIZE_T>(Process->Threads[i].ClientId.UniqueThread));
                        break;
                    }
                }
            }

            return FALSE;
        }, &Args);

        return Args.FoundThreadId;
    }
public:
    Shell(LPCVOID FuncAddr, LPCVOID Arg)
    {
        auto Mapping = reinterpret_cast<PSHELL_MAPPING>(Code);
        Mapping->Func = FuncAddr;
        Mapping->Arg = Arg;
    }

    BOOL Execute(DWORD ProcessId, DWORD ThreadId)
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);
        if (!hProcess || !hThread) {
            if (hProcess) CloseHandle(hProcess);
            if (hThread) CloseHandle(hThread);
            return FALSE;
        }

        SuspendThread(hThread);
        
        CONTEXT Context = {};
        Context.ContextFlags = CONTEXT_ALL;
        GetThreadContext(hThread, &Context);
        
        PVOID CodeBuf = VirtualAllocEx(hProcess, NULL, sizeof(Code), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(hProcess, CodeBuf, Code, sizeof(Code), NULL);
        
        Context.Rsp -= sizeof(PVOID);
        WriteProcessMemory(hProcess, reinterpret_cast<PVOID>(Context.Rsp), &Context.Rip, sizeof(Context.Rip), NULL);

        Context.Rip = reinterpret_cast<DWORD64>(CodeBuf);
        SetThreadContext(hThread, &Context);
        
        ResumeThread(hThread);

        CloseHandle(hThread);
        CloseHandle(hProcess);

        return TRUE;
    }

    BOOL Execute(DWORD ProcessId)
    {
        DWORD ThreadId = FindReadyThread(ProcessId);
        if (!ThreadId) return FALSE;
        return Execute(ProcessId, ThreadId);
    }
};

VOID WINAPI Func(SIZE_T Arg)
{
    printf("Func 0x%I64X\r\n", Arg);
}

DWORD WINAPI Thread(PVOID Arg)
{
    printf("Thread %p\r\n", Arg);
    while (true) {
        Sleep(1500);
        for (unsigned i = 0; i < 999999999; ++i);
    }
}
#endif

int main()
{
#ifdef _AMD64_
    DWORD ThreadId = 0;
    HANDLE hThread = CreateThread(NULL, 0, Thread, NULL, 0, &ThreadId);

    Sleep(200);

    Shell sh(Func, reinterpret_cast<PVOID>(0x1122334455667788));

    while (true) {
        if (!sh.Execute(GetCurrentProcessId()))
            printf("Unable to shell!\r\n");
        Sleep(300);
    }
#endif

    PAVN_API Api = Stub;
    while (true);
}