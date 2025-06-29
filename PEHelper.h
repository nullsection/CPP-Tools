#pragma once
#include <winternl.h>
#include <Windows.h>
#include <stdio.h>
#include <utility>

NTSTATUS NtProtectVirtualMemory(PVOID baseAddress, SIZE_T viewSize, DWORD Protection) {

    NtProtectVirtualMemory_t NtProtectVirtualMemory =
        (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");

    if (!NtProtectVirtualMemory) {
        printf("Failed to resolve NtProtectVirtualMemory\n");
        return -1;
    }

    // Set new protection to RWX
    ULONG oldProtect = 0;
    PVOID protectAddr = baseAddress;
    SIZE_T protectSize = viewSize;

    NTSTATUS protStatus = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &protectAddr,
        &protectSize,
        Protection,
        &oldProtect
    );

    if (protStatus == 0) {
        printf("Changed Memory Permisions ok\n");
    }
    else {
        printf("NtProtectVirtualMemory failed: 0x%X\n", protStatus);
    }

    return protStatus; 
} 

void PrintMemoryRegionType(PVOID address) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    SIZE_T bytesReturned = VirtualQuery(address, &mbi, sizeof(mbi));

    if (bytesReturned == 0) {
        printf("VirtualQuery failed: %lu\n", GetLastError());
        return;
    }

    switch (mbi.Protect & 0xFF) {
    case PAGE_NOACCESS:
        printf("Protection: PAGE_NOACCESS\n");
        break;
    case PAGE_READONLY:
        printf("Protection: PAGE_READONLY\n");
        break;
    case PAGE_READWRITE:
        printf("Protection: PAGE_READWRITE\n");
        break;
    case PAGE_WRITECOPY:
        printf("Protection: PAGE_WRITECOPY\n");
        break;
    case PAGE_EXECUTE:
        printf("Protection: PAGE_EXECUTE\n");
        break;
    case PAGE_EXECUTE_READ:
        printf("Protection: PAGE_EXECUTE_READ\n");
        break;
    case PAGE_EXECUTE_READWRITE:
        printf("Protection: PAGE_EXECUTE_READWRITE\n");
        break;
    case PAGE_EXECUTE_WRITECOPY:
        printf("Protection: PAGE_EXECUTE_WRITECOPY\n");
        break;
    default:
        printf("Protection: UNKNOWN (0x%lx)\n", mbi.Protect);
        break;
    }

   printf("Protect: 0x%lx\n", mbi.Protect);
    printf("Region Size: 0x%Ix bytes\n", mbi.RegionSize);
}



bool GetTextSectionInfo(PVOID baseAddress, PBYTE* textAddress, DWORD* textSize)
{
    if (baseAddress == NULL || textAddress == NULL || textSize == NULL)
        return false;

    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    // Get the NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)baseAddress + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return false;

    // Get the first section header
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    // Loop through all sections
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        printf("Found Section:%s @Address:%p\n", section[i].Name,(PBYTE)baseAddress + section[i].VirtualAddress);
        if (memcmp(section[i].Name, ".text", 5) == 0)
        {
            *textAddress = (PBYTE)baseAddress + section[i].VirtualAddress;
            *textSize = section[i].Misc.VirtualSize;
            
        }
    }
    
    if (*textAddress != 0) { return true; }


    return false; // .text section not found
}
