#include <iostream>
#include "./src/unhook.h"

int main()
{
    if (craftunhook::init())
        printf("[+] CraftUnhook Initialized Successfully.\n");
    else
        printf("[-] Failed To Initialize CraftUnhook.\n");

    // assuming that ZwWriteVirtualMemory has been hooked/tampered with.
    // if you wanna check if the function you're unhooking is actually hooked, use craftunhook::isHooked function.

    printf("[*] Press to Unhook [ZwWriteVirtualMemory].\n");

    getchar();

    // restores the original ZwWriteVirtualMemory without using a fresh NTDLL copy.
    if (craftunhook::unhook("ZwWriteVirtualMemory"))
        printf("[+] Unhooked Successfully.\n");
    else
        printf("[-] Failed to Unhook.\n");

    printf("[*] Press any Key to Exit.\n");

    getchar();
}
