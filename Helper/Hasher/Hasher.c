#include <Windows.h>
#include <stdio.h>

#define SEED 0x15
#define NAME "_StrHashed"


SIZE_T _StrlenA(LPCSTR String) {

    LPCSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SIZE_T _StrlenW(LPCWSTR String) {

    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}


UINT32 _HashStringRotr32SubA(UINT32 Value, UINT Count) {

    DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
    Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
    return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

DWORD HashStringRotr32A(PCHAR String) {

    DWORD Value = 0;

    for (INT Index = 0; Index < _StrlenA(String); Index++)
        Value = String[Index] + _HashStringRotr32SubA(Value, SEED);

    return Value;
}


UINT32 _HashStringRotr32SubW(UINT32 Value, UINT Count)
{
    DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
    Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
    return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

DWORD HashStringRotr32W(PWCHAR String)
{
    DWORD Value = 0;

    for (INT Index = 0; Index < _StrlenW(String); Index++)
        Value = String[Index] + _HashStringRotr32SubW(Value, SEED);

    return Value;
}




int main() {


    printf("#define %s%s \t0x%0.8X \n", "NtQuerySystemInformation", NAME, HashStringRotr32A("NtQuerySystemInformation"));


    printf("#define %s%s \t0x%0.8X \n", "NtAllocateVirtualMemory", NAME, HashStringRotr32A("NtAllocateVirtualMemory"));
    printf("#define %s%s \t0x%0.8X \n", "NtProtectVirtualMemory", NAME, HashStringRotr32A("NtProtectVirtualMemory"));
    printf("#define %s%s \t0x%0.8X \n", "NtWriteVirtualMemory", NAME, HashStringRotr32A("NtWriteVirtualMemory"));


    printf("#define %s%s \t0x%0.8X \n", "RtlCreateProcessParametersEx", NAME, HashStringRotr32A("RtlCreateProcessParametersEx"));
    printf("#define %s%s \t0x%0.8X \n", "NtCreateUserProcess", NAME, HashStringRotr32A("NtCreateUserProcess"));



    printf("#define %s%s \t0x%0.8X \n", "NtCreateSection", NAME, HashStringRotr32A("NtCreateSection"));
    printf("#define %s%s \t0x%0.8X \n", "NtOpenSection", NAME, HashStringRotr32A("NtOpenSection"));
    printf("#define %s%s \t0x%0.8X \n", "NtMapViewOfSection", NAME, HashStringRotr32A("NtMapViewOfSection"));
    printf("#define %s%s \t0x%0.8X \n", "NtUnmapViewOfSection", NAME, HashStringRotr32A("NtUnmapViewOfSection"));
    printf("#define %s%s \t0x%0.8X \n", "NtClose", NAME, HashStringRotr32A("NtClose"));




    printf("#define %s%s \t0x%0.8X \n", "OpenProcess", NAME, HashStringRotr32A("OpenProcess"));
    printf("#define %s%s \t0x%0.8X \n", "GetProcessId", NAME, HashStringRotr32A("GetProcessId"));
    printf("#define %s%s \t0x%0.8X \n", "DebugActiveProcess", NAME, HashStringRotr32A("DebugActiveProcess"));
    printf("#define %s%s \t0x%0.8X \n", "DebugActiveProcessStop", NAME, HashStringRotr32A("DebugActiveProcessStop"));
    printf("#define %s%s \t0x%0.8X \n", "NtQueueApcThread", NAME, HashStringRotr32A("NtQueueApcThread"));
    printf("#define %s%s \t0x%0.8X \n", "CloseHandle", NAME, HashStringRotr32A("CloseHandle"));



    printf("#define %s%s \t0x%0.8X \n", "LdrLoadDll", NAME, HashStringRotr32A("LdrLoadDll"));

    printf("#define %s%s \t0x%0.8X \n", "SystemFunction032", NAME, HashStringRotr32A("SystemFunction032"));



    //printf("#define %s%s \t0x%0.8X \n", "", NAME, HashStringRotr32A(""));
    //printf("#define %s%s \t0x%0.8X \n", "", NAME, HashStringRotr32W(""));

    return 0;

}

