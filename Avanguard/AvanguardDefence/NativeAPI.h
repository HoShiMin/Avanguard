#pragma once

#define NtCurrentProcess() ((HANDLE)-1)
#define NtCurrentThread()  ((HANDLE)-2)

inline void* __teb()
{
#ifdef _AMD64_
    return (void*)__readgsqword(0x30);
#else
    return (void*)__readfsdword(0x18);
#endif
}

inline void* __peb()
{
#ifdef _AMD64_
    return (void*)__readgsqword(0x60);
#else
    return (void*)__readfsdword(0x30);
#endif
}

inline unsigned int __pid()
{
    // TEB::ClientId.UniqueProcessId:
#ifdef _AMD64_
    return *(unsigned int*)((unsigned char*)__teb() + 0x40);
#else
    return *(unsigned int*)((unsigned char*)__teb() + 0x20);
#endif
}

inline unsigned int __tid()
{
    // TEB::ClientId.UniqueThreadId:
#ifdef _AMD64_
    return *(unsigned int*)((unsigned char*)__teb() + 0x48);
#else
    return *(unsigned int*)((unsigned char*)__teb() + 0x24);
#endif
}

extern "C" NTSYSAPI NTSTATUS NTAPI NtQueueApcThread(
    IN HANDLE ThreadHandle,
    IN PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcRoutineContext,
    IN OPTIONAL PIO_STATUS_BLOCK ApcStatusBlock,
    IN ULONG ApcReserved
);

extern "C" NTSYSAPI NTSTATUS NTAPI NtTerminateThread(
    IN HANDLE ThreadHandle,
    IN NTSTATUS ExitStatus
);

typedef enum _WRK_MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} WRK_MEMORY_INFORMATION_CLASS, *PWRK_MEMORY_INFORMATION_CLASS;

extern "C" NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN WRK_MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID Buffer,
    IN SIZE_T Length,
    OUT OPTIONAL PSIZE_T ResultLength
);

#define LDR_DLL_NOTIFICATION_REASON_LOADED   1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED 2

typedef struct _LDR_DLL_NOTIFICATION_DATA {
    ULONG Flags;                  // Reserved
    PCUNICODE_STRING FullDllName; // The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName; // The base file name of the DLL module.
    PVOID DllBase;                // A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;            // The size of the DLL image, in bytes.
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION) (
    IN ULONG NotificationReason, // LDR_DLL_NOTIFICATION_REASON_***
    IN PLDR_DLL_NOTIFICATION_DATA NotificationData,
    IN OPTIONAL PVOID Context
);

typedef NTSTATUS(NTAPI *_LdrRegisterDllNotification) (
    IN ULONG Flags,
    IN PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    IN OPTIONAL PVOID Context,
    OUT PVOID* Cookie
);

typedef NTSTATUS(NTAPI *_LdrUnregisterDllNotification) (
    IN PVOID Cookie
);

namespace PebTeb {
    typedef struct _PEB_LDR_DATA {
        ULONG                   Length;
        BOOLEAN                 Initialized;
        PVOID                   SsHandle;
        LIST_ENTRY              InLoadOrderModuleList;
        LIST_ENTRY              InMemoryOrderModuleList;
        LIST_ENTRY              InInitializationOrderModuleList;
    } PEB_LDR_DATA, *PPEB_LDR_DATA;

    typedef struct _LDR_MODULE {
        LIST_ENTRY              InLoadOrderModuleList;
        LIST_ENTRY              InMemoryOrderModuleList;
        LIST_ENTRY              InInitializationOrderModuleList;
        PVOID                   BaseAddress;
        PVOID                   EntryPoint;
        ULONG                   SizeOfImage;
        UNICODE_STRING          FullDllName;
        UNICODE_STRING          BaseDllName;
        ULONG                   Flags;
        SHORT                   LoadCount;
        SHORT                   TlsIndex;
        LIST_ENTRY              HashTableEntry;
        ULONG                   TimeDateStamp;
    } LDR_MODULE, *PLDR_MODULE;

    typedef struct _RTL_USER_PROCESS_PARAMETERS *PRTL_USER_PROCESS_PARAMETERS;
    typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifdef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#endif

    typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];
    typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
    typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];

    // symbols
    typedef struct _PEB {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        union {
            BOOLEAN BitField;
            struct {
                BOOLEAN ImageUsesLargePages : 1;
                BOOLEAN IsProtectedProcess : 1;
                BOOLEAN IsImageDynamicallyRelocated : 1;
                BOOLEAN SkipPatchingUser32Forwarders : 1;
                BOOLEAN IsPackagedProcess : 1;
                BOOLEAN IsAppContainer : 1;
                BOOLEAN IsProtectedProcessLight : 1;
                BOOLEAN SpareBits : 1;
            };
        };
        HANDLE Mutant;
        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        PRTL_CRITICAL_SECTION FastPebLock;
        PVOID AtlThunkSListPtr;
        PVOID IFEOKey;
        union {
            ULONG CrossProcessFlags;
            struct {
                ULONG ProcessInJob : 1;
                ULONG ProcessInitializing : 1;
                ULONG ProcessUsingVEH : 1;
                ULONG ProcessUsingVCH : 1;
                ULONG ProcessUsingFTH : 1;
                ULONG ReservedBits0 : 27;
            };
            ULONG EnvironmentUpdateCount;
        };
        union {
            PVOID* KernelCallbackTable;
            PVOID UserSharedInfoPtr;
        };
        ULONG SystemReserved[1];
        ULONG AtlThunkSListPtr32;
        PVOID ApiSetMap;
        ULONG TlsExpansionCounter;
        PVOID TlsBitmap;
        ULONG TlsBitmapBits[2];
        PVOID ReadOnlySharedMemoryBase;
        PVOID HotpatchInformation;
        PVOID *ReadOnlyStaticServerData;
        PVOID AnsiCodePageData;
        PVOID OemCodePageData;
        PVOID UnicodeCaseTableData;

        ULONG NumberOfProcessors;
        ULONG NtGlobalFlag;

        LARGE_INTEGER CriticalSectionTimeout;
        SIZE_T HeapSegmentReserve;
        SIZE_T HeapSegmentCommit;
        SIZE_T HeapDeCommitTotalFreeThreshold;
        SIZE_T HeapDeCommitFreeBlockThreshold;

        ULONG NumberOfHeaps;
        ULONG MaximumNumberOfHeaps;
        PVOID *ProcessHeaps;

        PVOID GdiSharedHandleTable;
        PVOID ProcessStarterHelper;
        ULONG GdiDCAttributeList;

        PRTL_CRITICAL_SECTION LoaderLock;

        ULONG OSMajorVersion;
        ULONG OSMinorVersion;
        USHORT OSBuildNumber;
        USHORT OSCSDVersion;
        ULONG OSPlatformId;
        ULONG ImageSubsystem;
        ULONG ImageSubsystemMajorVersion;
        ULONG ImageSubsystemMinorVersion;
        ULONG_PTR ImageProcessAffinityMask;
        GDI_HANDLE_BUFFER GdiHandleBuffer;
        PVOID PostProcessInitRoutine;

        PVOID TlsExpansionBitmap;
        ULONG TlsExpansionBitmapBits[32];

        ULONG SessionId;

        ULARGE_INTEGER AppCompatFlags;
        ULARGE_INTEGER AppCompatFlagsUser;
        PVOID pShimData;
        PVOID AppCompatInfo;

        UNICODE_STRING CSDVersion;

        PVOID ActivationContextData;
        PVOID ProcessAssemblyStorageMap;
        PVOID SystemDefaultActivationContextData;
        PVOID SystemAssemblyStorageMap;

        SIZE_T MinimumStackCommit;

        PVOID *FlsCallback;
        LIST_ENTRY FlsListHead;
        PVOID FlsBitmap;
        ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
        ULONG FlsHighIndex;

        PVOID WerRegistrationData;
        PVOID WerShipAssertPtr;
        PVOID pContextData;
        PVOID pImageHeaderHash;
        union {
            ULONG TracingFlags;
            struct {
                ULONG HeapTracingEnabled : 1;
                ULONG CritSecTracingEnabled : 1;
                ULONG LibLoaderTracingEnabled : 1;
                ULONG SpareTracingBits : 29;
            };
        };
        ULONGLONG CsrServerReadOnlySharedMemoryBase;
    } PEB, *PPEB;

#define GDI_BATCH_BUFFER_SIZE 310

    typedef struct _GDI_TEB_BATCH {
        ULONG Offset;
        ULONG_PTR HDC;
        ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
    } GDI_TEB_BATCH, *PGDI_TEB_BATCH;


    typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
        ULONG Flags;
        PSTR FrameName;
    } TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

    typedef struct _TEB_ACTIVE_FRAME {
        ULONG Flags;
        struct _TEB_ACTIVE_FRAME *Previous;
        PTEB_ACTIVE_FRAME_CONTEXT Context;
    } TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;


    typedef struct _TEB {
        NT_TIB NtTib;

        PVOID EnvironmentPointer;
        CLIENT_ID ClientId;
        PVOID ActiveRpcHandle;
        PVOID ThreadLocalStoragePointer;
        PPEB ProcessEnvironmentBlock;

        ULONG LastErrorValue;
        ULONG CountOfOwnedCriticalSections;
        PVOID CsrClientThread;
        PVOID Win32ThreadInfo;
        ULONG User32Reserved[26];
        ULONG UserReserved[5];
        PVOID WOW32Reserved;
        LCID CurrentLocale;
        ULONG FpSoftwareStatusRegister;
        PVOID SystemReserved1[54];
        NTSTATUS ExceptionCode;
        PVOID ActivationContextStackPointer;
#ifdef _WIN64
        UCHAR SpareBytes[24];
#else
        UCHAR SpareBytes[36];
#endif
        ULONG TxFsContext;

        GDI_TEB_BATCH GdiTebBatch;
        CLIENT_ID RealClientId;
        HANDLE GdiCachedProcessHandle;
        ULONG GdiClientPID;
        ULONG GdiClientTID;
        PVOID GdiThreadLocalInfo;
        ULONG_PTR Win32ClientInfo[62];
        PVOID glDispatchTable[233];
        ULONG_PTR glReserved1[29];
        PVOID glReserved2;
        PVOID glSectionInfo;
        PVOID glSection;
        PVOID glTable;
        PVOID glCurrentRC;
        PVOID glContext;

        NTSTATUS LastStatusValue;
        UNICODE_STRING StaticUnicodeString;
        WCHAR StaticUnicodeBuffer[261];

        PVOID DeallocationStack;
        PVOID TlsSlots[64];
        LIST_ENTRY TlsLinks;

        PVOID Vdm;
        PVOID ReservedForNtRpc;
        PVOID DbgSsReserved[2];

        ULONG HardErrorMode;
#ifdef _WIN64
        PVOID Instrumentation[11];
#else
        PVOID Instrumentation[9];
#endif
        GUID ActivityId;

        PVOID SubProcessTag;
        PVOID EtwLocalData;
        PVOID EtwTraceData;
        PVOID WinSockData;
        ULONG GdiBatchCount;

        union {
            PROCESSOR_NUMBER CurrentIdealProcessor;
            ULONG IdealProcessorValue;
            struct {
                UCHAR ReservedPad0;
                UCHAR ReservedPad1;
                UCHAR ReservedPad2;
                UCHAR IdealProcessor;
            };
        };

        ULONG GuaranteedStackBytes;
        PVOID ReservedForPerf;
        PVOID ReservedForOle;
        ULONG WaitingOnLoaderLock;
        PVOID SavedPriorityState;
        ULONG_PTR SoftPatchPtr1;
        PVOID ThreadPoolData;
        PVOID *TlsExpansionSlots;
#ifdef _WIN64
        PVOID DeallocationBStore;
        PVOID BStoreLimit;
#endif
        ULONG MuiGeneration;
        ULONG IsImpersonating;
        PVOID NlsCache;
        PVOID pShimData;
        ULONG HeapVirtualAffinity;
        HANDLE CurrentTransactionHandle;
        PTEB_ACTIVE_FRAME ActiveFrame;
        PVOID FlsData;

        PVOID PreferredLanguages;
        PVOID UserPrefLanguages;
        PVOID MergedPrefLanguages;
        ULONG MuiImpersonation;
        union {
            USHORT CrossTebFlags;
            USHORT SpareCrossTebBits : 16;
        };
        union {
            USHORT SameTebFlags;
            struct {
                USHORT SafeThunkCall : 1;
                USHORT InDebugPrint : 1;
                USHORT HasFiberData : 1;
                USHORT SkipThreadAttach : 1;
                USHORT WerInShipAssertCode : 1;
                USHORT RanProcessInit : 1;
                USHORT ClonedThread : 1;
                USHORT SuppressDebugMsg : 1;
                USHORT DisableUserStackWalk : 1;
                USHORT RtlExceptionAttached : 1;
                USHORT InitialThread : 1;
                USHORT SessionAware : 1;
                USHORT SpareSameTebBits : 4;
            };
        };

        PVOID TxnScopeEnterCallback;
        PVOID TxnScopeExitCallback;
        PVOID TxnScopeContext;
        ULONG LockCount;
        ULONG SpareUlong0;
        PVOID ResourceRetValue;
        PVOID ReservedForWdf;
    } TEB, *PTEB;
}