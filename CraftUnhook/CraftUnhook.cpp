#include "./src/unhook.h"
#include "./src/hash/hash.h"

#include <iostream>
#include<winternl.h>

int main()
{
    if (craftunhook::init())
        printf("[+] CraftUnhook Initialized Successfully.\n");
    else
        printf("[-] Failed To Initialize CraftUnhook.\n");

    printf("[*] Press any Key to Proceed.\n");
    
    getchar();

    if (craftunhook::isHookedByHash(hashes::ZwQueryInformationProcess))
        printf("[!] ZwQueryInformationProcess is Hooked!\n");

    // if you don't care about the NTSTATUS return, you can use the CLEAN_CALL macro.
    // this will unhook the function (if its hooked), proceed with the users call and then restore it (if it was hooked) to its original state.

    PROCESS_BASIC_INFORMATION pbi{ 0 };
    CLEAN_CALL(
        hashes::ZwQueryInformationProcess,
        NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            NULL
        )
    );

    if (!pbi.PebBaseAddress) {
        printf("[-] Failed to Get Process PEB.\n");
        return -1;
    }

    printf("[PEB] Address: 0x%p\n", pbi.PebBaseAddress);

    if (pbi.PebBaseAddress->BeingDebugged) {
        printf("[!] Process is Being Debugged!\n");
    }
    else {
        printf("[!] Process isn't Being Debugged!\n");
    }

    system("pause");
}
