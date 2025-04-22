
# CraftUnhook
Unhooking NTDLL Without Reading It From Disk.

## Explanation
CraftUnhook works by crafting a clean syscall stub for the desired native function without reading a new copy of NTDLL, By [Resolving System Call Service Numbers Using The Exception Directory](https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/) and overwriting the hooked stub with our new clean stub, This makes reading an NTDLL copy obsolete and less preferrable.

## Why Reading NTDLL From Disk Is Useless Now
Reading NTDLL allowed developers to fetch a clean syscall stub of the desired function, But now since we can fetch the service call service number (SSN) with the Exception Directory of NTDLL, Craft a stub and overwrite the hooked stub with it, We really don't have any reason to read NTDLL from disk, It's also very suspicious behaviour for a process and is monitored by AVs/EDRs.

## Usage
```cpp
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
```

## Credits

[MDSec](https://www.mdsec.co.uk/) - [Resolving System Call Service Numbers Using The Exception Directory](https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/), Very great article to read that gives you a whole new array of ideas for syscall shenanigans.
