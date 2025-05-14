
# CraftUnhook
Unhooking NTDLL Without Reading It From Disk.

## Explanation
CraftUnhook works by crafting a clean syscall stub for the desired native function without reading a new copy of NTDLL, By [Resolving System Call Service Numbers Using The Exception Directory](https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/) and overwriting the hooked stub with our new clean stub, This makes reading an NTDLL copy obsolete and less preferrable.

## Why Reading NTDLL From Disk Is Useless Now
Reading NTDLL allowed developers to fetch a clean syscall stub of the desired function, but now since we can fetch the service call service number (SSN) with the Exception Directory of NTDLL, craft a stub and overwrite the hooked stub with it, We really don't have any reason to read NTDLL from disk, it's also very suspicious behaviour for a process and is monitored by AVs/EDRs.

## Usage
Checking if a function is hooked:
```cpp
if (craftunhook::isHookedByHash(hashes::ZwQueryInformationProcess))
    printf("[!] ZwQueryInformationProcess is Hooked!\n");
```

Calling the function after being unhooked then restoring it to the original hooked state:
```cpp
// if you don't care about the NTSTATUS return, you can use the CLEAN_CALL macro.
// this will unhook the function (if its hooked), proceed with the users call and then restore it (if it was hooked) to its original state.

PROCESS_BASIC_INFORMATION pbi{ 0 };
CLEAN_CALL(
    hashes::ZwQueryInformationProcess, // ror13 hash of 'ZwQueryInformationProcess'
    NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        NULL
    )
);
```


## Showcase
https://files.catbox.moe/tcoyky.mp4

## Credits

[MDSec](https://www.mdsec.co.uk/) - [Resolving System Call Service Numbers Using The Exception Directory](https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/), very great article to read that gives you a whole new array of ideas for syscall shenanigans.
