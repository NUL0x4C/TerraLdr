/*
	file that include the needed code to run NtCreateUserProcess 
*/

#include <Windows.h>
#include "Structs.h"
#include "Types.h"
#include "Header.h"




BOOL NtCreateProcess(IN	PWSTR szTargetProcess, IN PWSTR	szTargetProcessParameters, IN PWSTR szTargetProcessPath, IN	HANDLE hParentProcess, OUT PHANDLE hProcess, OUT PHANDLE hThread) {



	fnRtlCreateProcessParametersEx	RtlCreateProcessParametersEx	=
		(fnRtlCreateProcessParametersEx)GetProcAddressH(GetModuleHandleH(NTDLLDLL), RtlCreateProcessParametersEx_StrHashed);

	fnNtCreateUserProcess			NtCreateUserProcess				= 
		(fnNtCreateUserProcess)GetProcAddressH(GetModuleHandleH(NTDLLDLL), NtCreateUserProcess_StrHashed);

	if (NtCreateUserProcess == NULL || RtlCreateProcessParametersEx == NULL) {
		return FALSE;
	}




	PPS_ATTRIBUTE_LIST				AttributeList			= (PPS_ATTRIBUTE_LIST)LocalAlloc(LPTR, sizeof(PS_ATTRIBUTE_LIST));
	PRTL_USER_PROCESS_PARAMETERS	ProcessParameters		= NULL;
	UNICODE_STRING					NtImagePath				= { 0 },
									CurrentDirectory		= { 0 },
									CommandLine				= { 0 };
	PS_CREATE_INFO					CreateInfo = {
															.Size = sizeof(CreateInfo),
															.State = PsCreateInitialState
	};
	DWORD64							BlockDllsPolicy			= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;


	_RtlInitUnicodeString(&NtImagePath, szTargetProcess);
	_RtlInitUnicodeString(&CommandLine, szTargetProcessParameters);
	_RtlInitUnicodeString(&CurrentDirectory, szTargetProcessPath);


	RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, &CurrentDirectory, &CommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);

	if (!AttributeList) {
		return FALSE;
	}

	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

	AttributeList->Attributes[0].Attribute	= PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[0].Size		= NtImagePath.Length;
	AttributeList->Attributes[0].Value		= (ULONG_PTR)NtImagePath.Buffer;

	AttributeList->Attributes[1].Attribute	= PS_ATTRIBUTE_PARENT_PROCESS;
	AttributeList->Attributes[1].Size		= sizeof(HANDLE);
	AttributeList->Attributes[1].Value		= hParentProcess;


	AttributeList->Attributes[2].Attribute	= PS_ATTRIBUTE_MITIGATION_OPTIONS;
	AttributeList->Attributes[2].Size		= sizeof(DWORD64);
	AttributeList->Attributes[2].Value		= &BlockDllsPolicy;



	NtCreateUserProcess(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcessParameters, &CreateInfo, AttributeList);

	_ZeroMemory((PVOID)AttributeList, sizeof(PS_ATTRIBUTE_LIST));
	LocalFree((HLOCAL)AttributeList);

	if (*hProcess == NULL || *hThread == NULL)
		return FALSE;


	return TRUE;
}
