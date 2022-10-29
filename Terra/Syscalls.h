/*
	file that include extern functions from *SYSCALLLIB* library
	https://github.com/ORCx41/Syscallslib
*/

#pragma once

#ifdef __cplusplus
#define EXTERN extern "C"
#else
#define EXTERN extern
#endif

#ifndef _SYSCALLS_H
#define _SYSCALLS_H

#include <Windows.h>

// struct here : [IMPORTANT FOR INITIALIZATION]
typedef struct _HashStruct {

	DWORD NtAllocateVirtualMemory_Hash;
	DWORD NtProtectVirtualMemory_Hash;

	DWORD NtCreateSection_Hash;
	DWORD NtOpenSection_Hash;
	DWORD NtMapViewOfSection_Hash;
	DWORD NtUnmapViewOfSection_Hash;

	DWORD NtClose_Hash;

	DWORD NtQuerySystemInformation_Hash;
	DWORD NtCreateUserProcess_Hash;
	DWORD NtWriteVirtualMemory_Hash;


}HashStruct, * PHashStruct;



EXTERN BOOL
InitializeStruct(
	IN			INT			Seed,							// INPUT : Seed Of The Rotr32 Hashing algo
	IN			PHashStruct PStruct							// INPUT : pointer to a struct of type 'HashStruct' that will initialize the data 
);

EXTERN PVOID
NtAllocateVirtualMemory(
	IN  OPTIONAL  HANDLE	ProcessHandle,								// INPUT  : in case of null, the function will run localy
	IN  OPTIONAL  PVOID		BaseAddress,							// INPUT  : NULL by default  
	IN			  SIZE_T	RegionSize,						// INPUT  : can't be NULL
	IN  OPTIONAL  ULONG		AllocationType,							// INPUT  : MEM_COMMIT | MEM_RESERVE by default
	IN  OPTIONAL  ULONG		Protect,							// INPUT  : PAGE_READWRITE by default
	OUT OPTIONAL  PNTSTATUS	STATUS									// OUTPUT : the return from the syscall
);

// calling the default NtAllocateVirtualMemory | u can do such thing to the others ...
EXTERN PVOID
NtAllocateVirtualMemory2(
	IN			  SIZE_T	RegionSize,						// INPUT  : can't be NULL
	OUT OPTIONAL  PNTSTATUS	STATUS									// OUTPUT : the return from the syscall
);

EXTERN ULONG
NtProtectVirtualMemory(
	IN  OPTIONAL HANDLE		ProcessHandle,							// INPUT  : in case of null, the function will run localy
	IN			 PVOID		BaseAddress,						// INPUT  : can't be NULL
	IN			 SIZE_T		NumberOfBytesToProtect,					// INPUT  : can't be NULL
	IN			 ULONG		NewAccessProtection,					// INPUT  : can't be NULL
	OUT OPTIONAL PNTSTATUS	STATUS									// OUTPUT : the return from the syscall
);

EXTERN HANDLE
NtCreateSection(
	IN	OPTIONAL	ACCESS_MASK			DesiredAccess,				// INPUT  : SECTION_ALL_ACCESS by default
	IN	OPTIONAL	POBJECT_ATTRIBUTES	ObjectAttributes,				// INPUT  : NULL by default
	IN				SIZE_T				NumberOfBytes,			// INPUT  : can't be NULL
	IN	OPTIONAL	ULONG               SectionPageProtection,				// INPUT  : PAGE_READWRITE be default
	IN	OPTIONAL	ULONG               AllocationAttributes,				// INPUT  : SEC_COMMIT by default
	IN	OPTIONAL	HANDLE              FileHandle,						// INPUT  : NULL by default
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall

);



EXTERN HANDLE
NtOpenSection(
	IN	OPTIONAL	ACCESS_MASK			DesiredAccess,				// INPUT  : SECTION_ALL_ACCESS by default
	IN				POBJECT_ATTRIBUTES  ObjectAttributes,				// INPUT  : can't be NULL
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall
);

EXTERN PVOID
NtMapViewOfSection(
	IN				HANDLE              SectionHandle,				// INPUT  : can't be NULL
	IN  OPTIONAL	HANDLE              ProcessHandle,						// INPUT  : in case of null, the function will run localy
	IN  OPTIONAL	PVOID				BaseAddress,					// INPUT  : NULL by default
	IN  OPTIONAL	ULONG               AllocationType,						// INPUT  : NULL by default
	IN  OPTIONAL	ULONG               Protect,							// INPUT  : PAGE_READWRITE by default
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall

);


EXTERN VOID
NtUnmapViewOfSection(
	IN  OPTIONAL	HANDLE              ProcessHandle,						// INPUT  : in case of null, the function will run localy
	IN  			PVOID				BaseAddress,				// INPUT  : can't be NULL
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall
);



EXTERN VOID
NtClose(															
	IN				HANDLE              SectionHandle,				// INPUT  : can't be NULL
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall
);



EXTERN SIZE_T 
NtWriteVirtualMemory(
	IN OPTIONAL		HANDLE               ProcessHandle,
	IN				PVOID                BaseAddress,
	IN				PVOID                Buffer,
	IN				SIZE_T               NumberOfBytesToWrite,
	OUT OPTIONAL	PNTSTATUS			 STATUS						// OUTPUT : the return from the syscall
);

EXTERN BOOL
NtCreateUserProcess(
	OUT				PHANDLE							ProcessHandle,
	OUT				PHANDLE							ThreadHandle,
	IN	OPTIONAL	ACCESS_MASK						ProcessDesiredAccess,
	IN	OPTIONAL	ACCESS_MASK						ThreadDesiredAccess,
	IN	OPTIONAL	POBJECT_ATTRIBUTES				ProcessObjectAttributes,
	IN	OPTIONAL	POBJECT_ATTRIBUTES				ThreadObjectAttributes,
	IN	OPTIONAL	ULONG							ProcessFlags,
	IN	OPTIONAL	ULONG							ThreadFlags,
	IN				PRTL_USER_PROCESS_PARAMETERS	ProcessParameters,
	IN				PPS_CREATE_INFO					CreateInfo,
	IN				PPS_ATTRIBUTE_LIST				AttributeList,
	OUT OPTIONAL	PNTSTATUS						STATUS						// OUTPUT : the return from the syscall
);

EXTERN BOOL
NtCreateUserProcess2(
	OUT				PHANDLE							ProcessHandle,
	OUT				PHANDLE							ThreadHandle,
	IN				PRTL_USER_PROCESS_PARAMETERS	ProcessParameters,
	IN				PPS_CREATE_INFO					CreateInfo,
	IN				PPS_ATTRIBUTE_LIST				AttributeList,
	OUT OPTIONAL	PNTSTATUS						STATUS						// OUTPUT : the return from the syscall
);


EXTERN BOOL
NtQuerySystemInformation(
	IN					SYSTEM_INFORMATION_CLASS		SystemInformationClass,
	IN	OPTIONAL		PVOID							SystemInformation,
	IN	OPTIONAL		ULONG							SystemInformationLength,
	OUT OPTIONAL		PULONG							ReturnLength,
	OUT OPTIONAL		PNTSTATUS						STATUS						// OUTPUT : the return from the syscall
);








#endif // !_SYSCALLS_H
