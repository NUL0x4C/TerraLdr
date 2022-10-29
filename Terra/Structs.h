/*
	windows structs
*/
#pragma once

#include	<Windows.h>



#ifndef STRUCTS
#define STRUCTS

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;

} UNICODE_STRING, * PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;



typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;

} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) {	\
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
}


typedef PVOID PACTIVATION_CONTEXT;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PACTIVATION_CONTEXT EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	union
	{
		UCHAR BitField;
		struct
		{
			UCHAR ImageUsesLargePages : 1;
			UCHAR IsProtectedProcess : 1;
			UCHAR IsImageDynamicallyRelocated : 1;
			UCHAR SkipPatchingUser32Forwarders : 1;
			UCHAR IsPackagedProcess : 1;
			UCHAR IsAppContainer : 1;
			UCHAR IsProtectedProcessLight : 1;
			UCHAR IsLongPathAwareProcess : 1;
		};
	};
	UCHAR Padding0[4];
	VOID* Mutant;
	VOID* ImageBaseAddress;
	struct _PEB_LDR_DATA* Ldr;
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	VOID* SubSystemData;
	VOID* ProcessHeap;
	struct _RTL_CRITICAL_SECTION* FastPebLock;
	union _SLIST_HEADER* volatile AtlThunkSListPtr;
	VOID* IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1;
			ULONG ReservedBits0 : 24;
		};
	};
	UCHAR Padding1[4];
	union
	{
		VOID* KernelCallbackTable;
		VOID* UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	VOID* ApiSetMap;
	ULONG TlsExpansionCounter;
	UCHAR Padding2[4];
	VOID* TlsBitmap;
	ULONG TlsBitmapBits[2];
	VOID* ReadOnlySharedMemoryBase;
	VOID* SharedData;
	VOID** ReadOnlyStaticServerData;
	VOID* AnsiCodePageData;
	VOID* OemCodePageData;
	VOID* UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	union _LARGE_INTEGER CriticalSectionTimeout;
	ULONGLONG HeapSegmentReserve;
	ULONGLONG HeapSegmentCommit;
	ULONGLONG HeapDeCommitTotalFreeThreshold;
	ULONGLONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	VOID** ProcessHeaps;
	VOID* GdiSharedHandleTable;
	VOID* ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	UCHAR Padding3[4];
	struct _RTL_CRITICAL_SECTION* LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	UCHAR Padding4[4];
	ULONGLONG ActiveProcessAffinityMask;
	ULONG GdiHandleBuffer[60];
	VOID(*PostProcessInitRoutine)();
	VOID* TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
	UCHAR Padding5[4];
	union _ULARGE_INTEGER AppCompatFlags;
	union _ULARGE_INTEGER AppCompatFlagsUser;
	VOID* pShimData;
	VOID* AppCompatInfo;
	struct _UNICODE_STRING CSDVersion;
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
	ULONGLONG MinimumStackCommit;
	struct _FLS_CALLBACK_INFO* FlsCallback;
	struct _LIST_ENTRY FlsListHead;
	VOID* FlsBitmap;
	ULONG FlsBitmapBits[4];
	ULONG FlsHighIndex;
	VOID* WerRegistrationData;
	VOID* WerShipAssertPtr;
	VOID* pUnused;
	VOID* pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	UCHAR Padding6[4];
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	ULONGLONG TppWorkerpListLock;
	struct _LIST_ENTRY TppWorkerpList;
	VOID* WaitOnAddressHashTable[128];
	VOID* TelemetryCoverageHeader;
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags;
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
	struct _LEAP_SECOND_DATA* LeapSecondData;
	union
	{
		ULONG LeapSecondFlags;
		struct
		{
			ULONG SixtySecondEnabled : 1;
			ULONG Reserved : 31;
		};
	};
	ULONG NtGlobalFlag2;
} PEB, * PPEB;


typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;


typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	PVOID				ApcContext,
	PIO_STATUS_BLOCK	IoStatusBlock,
	ULONG				Reserved
	);


#endif // !STRUCTS











#ifndef NT_PROCESS
#define NT_PROCESS


#define RTL_MAX_DRIVE_LETTERS 32



typedef struct _RTL_DRIVE_LETTER_CURDIR 
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR 
{
	UNICODE_STRING DosPath;
	HANDLE Handle;

} CURDIR, * PCURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS 
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PWCHAR Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;

} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;




typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName, 
	PsCreateSuccess,
	PsCreateMaximumStates

} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		struct
		{
			union
			{
				ULONG InitFlags;
				struct
				{
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				} s1;
			} u1;
			ACCESS_MASK AdditionalFileAccess;
		} InitState;

		struct
		{
			HANDLE FileHandle;
		} FailSection;

		struct
		{
			USHORT DllCharacteristics;
		} ExeFormat;

		struct
		{
			HANDLE IFEOKey;
		} ExeName;

		struct
		{
			union
			{
				ULONG OutputFlags;
				struct
				{
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1; 
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				} s2;
			} u2;
			HANDLE FileHandle;
			HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};

} PS_CREATE_INFO, * PPS_CREATE_INFO;



typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;               
	SIZE_T Size;                       
	union
	{
		ULONG_PTR Value;                
		PVOID ValuePtr;                 
	};
	PSIZE_T ReturnLength;             

} PS_ATTRIBUTE, * PPS_ATTRIBUTE;



typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;                
	PS_ATTRIBUTE Attributes[3];   

} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;

} CLIENT_ID, * PCLIENT_ID;



#define PS_ATTRIBUTE_NUMBER_MASK    0x0000ffff
#define PS_ATTRIBUTE_THREAD         0x00010000 // Attribute may be used with thread creation
#define PS_ATTRIBUTE_INPUT          0x00020000 // Attribute is input only
#define PS_ATTRIBUTE_ADDITIVE       0x00040000 // Attribute may be "accumulated", e.g. bitmasks, counters, etc.

typedef enum _PS_ATTRIBUTE_NUM
{
	PsAttributeParentProcess,                   // in HANDLE
	PsAttributeDebugPort,                       // in HANDLE
	PsAttributeToken,                           // in HANDLE
	PsAttributeClientId,                        // out PCLIENT_ID
	PsAttributeTebAddress,                      // out PTEB
	PsAttributeImageName,                       // in PWSTR
	PsAttributeImageInfo,                       // out PSECTION_IMAGE_INFORMATION
	PsAttributeMemoryReserve,                   // in PPS_MEMORY_RESERVE
	PsAttributePriorityClass,                   // in UCHAR
	PsAttributeErrorMode,                       // in ULONG
	PsAttributeStdHandleInfo,                   // in PPS_STD_HANDLE_INFO
	PsAttributeHandleList,                      // in PHANDLE
	PsAttributeGroupAffinity,                   // in PGROUP_AFFINITY
	PsAttributePreferredNode,                   // in PUSHORT
	PsAttributeIdealProcessor,                  // in PPROCESSOR_NUMBER
	PsAttributeUmsThread,                       // see MSDN UpdateProceThreadAttributeList (CreateProcessW) - in PUMS_CREATE_THREAD_ATTRIBUTES
	PsAttributeMitigationOptions,               // in UCHAR
	PsAttributeProtectionLevel,                 // in ULONG
	PsAttributeSecureProcess,                   // since THRESHOLD (Virtual Secure Mode, Device Guard)
	PsAttributeJobList,
	PsAttributeChildProcessPolicy,              // since THRESHOLD2
	PsAttributeAllApplicationPackagesPolicy,    // since REDSTONE
	PsAttributeWin32kFilter,
	PsAttributeSafeOpenPromptOriginClaim,
	PsAttributeBnoIsolation,
	PsAttributeDesktopAppPolicy,
	PsAttributeMax
} PS_ATTRIBUTE_NUM;


#define PsAttributeValue(Number, Thread, Input, Additive)		\
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK)	|					\
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0)	|					\
    ((Input) ? PS_ATTRIBUTE_INPUT : 0)		|					\
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS									\
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)		
#define PS_ATTRIBUTE_DEBUG_PORT										\
    PsAttributeValue(PsAttributeDebugPort, FALSE, TRUE, TRUE)			
#define PS_ATTRIBUTE_TOKEN											\
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)				
#define PS_ATTRIBUTE_CLIENT_ID										\
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)			
#define PS_ATTRIBUTE_TEB_ADDRESS									\
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)			
#define PS_ATTRIBUTE_IMAGE_NAME										\
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)			
#define PS_ATTRIBUTE_IMAGE_INFO										\
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)			
#define PS_ATTRIBUTE_MEMORY_RESERVE									\
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)		
#define PS_ATTRIBUTE_PRIORITY_CLASS									\
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)		
#define PS_ATTRIBUTE_ERROR_MODE										\
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)			
#define PS_ATTRIBUTE_STD_HANDLE_INFO								\
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)		
#define PS_ATTRIBUTE_HANDLE_LIST									\
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)			
#define PS_ATTRIBUTE_GROUP_AFFINITY									\
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)		
#define PS_ATTRIBUTE_PREFERRED_NODE									\
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)		
#define PS_ATTRIBUTE_IDEAL_PROCESSOR								\
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)		
#define PS_ATTRIBUTE_MITIGATION_OPTIONS								\
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PROTECTION_LEVEL								\
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, FALSE)	
#define PS_ATTRIBUTE_UMS_THREAD										\
    PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_SECURE_PROCESS									\
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_JOB_LIST										\
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY							\
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY				\
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_WIN32K_FILTER									\
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM					\
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_BNO_ISOLATION									\
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY								\
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)




#define RTL_USER_PROC_PARAMS_NORMALIZED			0x00000001
#define RTL_USER_PROC_PROFILE_USER				0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL			0x00000004
#define RTL_USER_PROC_PROFILE_SERVER			0x00000008
#define RTL_USER_PROC_RESERVE_1MB				0x00000020
#define RTL_USER_PROC_RESERVE_16MB				0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE			0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT		0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL		0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT		0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING			0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS				0x00020000



#endif // !NT_PROCESS





#ifndef ENUMERATE
#define ENUMERATE


typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,                 
	SystemProcessorInformation,            
	SystemPerformanceInformation,          
	SystemTimeOfDayInformation,             
	SystemPathInformation,                 
	SystemProcessInformation,               
	SystemCallCountInformation,             
	SystemDeviceInformation,               
	SystemProcessorPerformanceInformation,  
	SystemFlagsInformation,                 
	SystemCallTimeInformation,              
	SystemModuleInformation,                
	SystemLocksInformation,               
	SystemStackTraceInformation,            
	SystemPagedPoolInformation,             
	SystemNonPagedPoolInformation,          
	SystemHandleInformation,               
	SystemObjectInformation,                
	SystemPageFileInformation,              
	SystemVdmInstemulInformation,           
	SystemVdmBopInformation,                
	SystemFileCacheInformation,             
	SystemPoolTagInformation,               
	SystemInterruptInformation,             
	SystemDpcBehaviorInformation,          
	SystemFullMemoryInformation,            
	SystemLoadGdiDriverInformation,         
	SystemUnloadGdiDriverInformation,      
	SystemTimeAdjustmentInformation,      
	SystemSummaryMemoryInformation,         
	SystemNextEventIdInformation,          
	SystemEventIdsInformation,              
	SystemCrashDumpInformation,            
	SystemExceptionInformation,            
	SystemCrashDumpStateInformation,        
	SystemKernelDebuggerInformation,        
	SystemContextSwitchInformation,        
	SystemRegistryQuotaInformation,         
	SystemExtendServiceTableInformation,   
	SystemPrioritySeperation,               
	SystemPlugPlayBusInformation,           
	SystemDockInformation,                 

} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_PROCESS_INFORMATION {

	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
	ULONG HandleCount;

} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;



#endif // !ENUMERATE



