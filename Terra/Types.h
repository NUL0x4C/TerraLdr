/*
	file that include the needed typedefs
*/
#include <Windows.h>


#ifndef TYPES
#define TYPES


typedef NTSTATUS(NTAPI* fnLdrLoadDll)(

	PWCHAR							PathToFile,
	ULONG							Flags,
	PUNICODE_STRING					ModuleFileName,
	PHANDLE							ModuleHandle
	
	);


typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(

	SYSTEM_INFORMATION_CLASS		SystemInformationClass,
	PVOID							SystemInformation,
	ULONG							SystemInformationLength,
	PULONG							ReturnLength

	);

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(

	HANDLE							ProcessHandle,
	PVOID*							BaseAddress,
	ULONG_PTR						ZeroBits,
	PSIZE_T							RegionSize,
	ULONG							AllocationType,
	ULONG							Protect

	);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(

	HANDLE							ProcessHandle,
	PVOID*							BaseAddress,
	PSIZE_T							NumberOfBytesToProtect,
	ULONG							NewAccessProtection,
	PULONG							OldAccessProtection

	);

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	
	struct USTRING* Img,
	struct USTRING* Key
	
	);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(

	HANDLE							ProcessHandle,
	PVOID							BaseAddress,
	PVOID							Buffer,
	ULONG							NumberOfBytesToWrite,
	PULONG							NumberOfBytesWritten

	);


typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(

	PRTL_USER_PROCESS_PARAMETERS*	pProcessParameters,
	PUNICODE_STRING					ImagePathName,
	PUNICODE_STRING					DllPath,
	PUNICODE_STRING					CurrentDirectory,
	PUNICODE_STRING					CommandLine,
	PVOID							Environment,
	PUNICODE_STRING					WindowTitle,
	PUNICODE_STRING					DesktopInfo,
	PUNICODE_STRING					ShellInfo,
	PUNICODE_STRING					RuntimeData,
	ULONG							Flags

	);



typedef NTSTATUS(NTAPI* fnNtCreateUserProcess)(

	PHANDLE							ProcessHandle,
	PHANDLE							ThreadHandle,
	ACCESS_MASK						ProcessDesiredAccess,
	ACCESS_MASK						ThreadDesiredAccess,
	POBJECT_ATTRIBUTES				ProcessObjectAttributes,
	POBJECT_ATTRIBUTES				ThreadObjectAttributes,
	ULONG							ProcessFlags,
	ULONG							ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS	ProcessParameters,
	PPS_CREATE_INFO					CreateInfo,
	PPS_ATTRIBUTE_LIST				AttributeList

	);


typedef NTSTATUS(NTAPI* fnNtQueueApcThread)(

	HANDLE							ThreadHandle,
	PIO_APC_ROUTINE					ApcRoutine,
	PVOID							ApcRoutineContext,
	PIO_STATUS_BLOCK				ApcStatusBlock,
	ULONG							ApcReserved

	);


typedef HANDLE(WINAPI* fnOpenProcess)(

	DWORD							dwDesiredAccess,
	BOOL							bInheritHandle,
	DWORD							dwProcessId
	
	);

typedef DWORD(WINAPI* fnGetProcessId)(
	
	HANDLE							Process
	
	);


typedef BOOL(WINAPI* fnDebugActiveProcess)(
	
	DWORD							dwProcessId

	);

typedef BOOL(WINAPI* fnDebugActiveProcessStop)(
	
	DWORD							dwProcessId

	);


typedef BOOL(WINAPI* fnCloseHandle)(
	
	HANDLE							hObject

	);



#endif // !TYPES
