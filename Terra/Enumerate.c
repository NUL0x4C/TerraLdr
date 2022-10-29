/*
    file that include the needed code to do process enumeration (to get the pid of the target process *ParentProcessName*) 
    
*/

#include <Windows.h>
#include "Structs.h"
#include "Types.h"
#include "Header.h"


BOOL GetParentProcessid(IN PCWSTR ParentProcessName, OUT PDWORD pdwProcessId) {

    fnNtQuerySystemInformation	NtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddressH(GetModuleHandleH(NTDLLDLL), NtQuerySystemInformation_StrHashed);
    if (ParentProcessName == NULL || NtQuerySystemInformation == NULL)
        return FALSE;

    ULONG                       ReturnLength1   =   NULL,
                                ReturnLength2   =   NULL;
    PSYSTEM_PROCESS_INFORMATION SystemProcInfo  =   NULL;

    NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ReturnLength1);
    if (!ReturnLength1)
        return FALSE;

    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)LocalAlloc(LPTR, ReturnLength1);
    if (!SystemProcInfo)
        return FALSE;

    NtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, ReturnLength1, &ReturnLength2);
    if (!ReturnLength2)
        return FALSE;

    while (TRUE){
        if (SystemProcInfo->ImageName.Length && HASHW(SystemProcInfo->ImageName.Buffer) == HASHW(ParentProcessName)){
            *pdwProcessId = (DWORD)SystemProcInfo->UniqueProcessId;
            break;
        }
        
        if (!SystemProcInfo->NextEntryOffset)
            break;

        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }

    LocalFree((HLOCAL)SystemProcInfo);

    if (*pdwProcessId == NULL)
        return FALSE;
    
    return TRUE;
}

