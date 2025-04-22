#include "unhook.h"

DWORD findWow64DsRva() {
	auto imgNtdll = craftunhook::imgNtdll;

	auto expDir = imgNtdll.ExportDirectory;
	auto baseNtdll = imgNtdll.OptionalHeader.ImageBase;

	PDWORD addrOfNameRvas = (PDWORD)(baseNtdll + expDir->AddressOfNames);
	PWORD addrOfOrds = (PWORD)(baseNtdll + expDir->AddressOfNameOrdinals);
	PDWORD addrOfFnRvas = (PDWORD)(baseNtdll + expDir->AddressOfFunctions);

	for (size_t i = 1; i < expDir->NumberOfFunctions; i++)
	{
		LPCSTR fnName = (LPCSTR)(baseNtdll + addrOfNameRvas[i]);

		if (strncmp(fnName, "Zw", 2) && strcmp(fnName, "ZwQuerySystemTime"))
			continue;

		WORD fnOrd = addrOfOrds[i];
		PVOID fnAddr = (PVOID)(baseNtdll + addrOfFnRvas[fnOrd]);

		for (size_t x = 0; x < craftunhook::stubSize; x++)
		{
			if (!memcmp((PBYTE)((uintptr_t)fnAddr + x), craftunhook::wow64TestStart, 3)) {
				DWORD rva = *(PDWORD)((uintptr_t)fnAddr + x + 3);
				return rva;
			}
		}
	}

	return 0;
}

DWORD getFnSsnFromName(LPCSTR targetFnName) {
	auto imgNtdll = craftunhook::imgNtdll;
	auto baseNtdll = imgNtdll.OptionalHeader.ImageBase;

	auto expDir = imgNtdll.ExportDirectory;
	auto rtf = imgNtdll.RunTimeEntryTable;
	
	PDWORD addrOfNameRvas = (PDWORD)(baseNtdll + expDir->AddressOfNames);
	PWORD addrOfOrds = (PWORD)(baseNtdll + expDir->AddressOfNameOrdinals);
	PDWORD addrOfFnRvas = (PDWORD)(baseNtdll + expDir->AddressOfFunctions);

	DWORD index = 0;
	DWORD ssn = 0;

	while (rtf[index].BeginAddress) {

		for (size_t i = 0; i < expDir->NumberOfFunctions; i++)
		{
			LPCSTR fnName = (LPCSTR)(baseNtdll + addrOfNameRvas[i]);

			if (strncmp(fnName, "Zw", 2))
				continue;

			WORD fnOrd = addrOfOrds[i];
			DWORD fnRva = addrOfFnRvas[fnOrd];
			
			
			if (fnRva == rtf[index].BeginAddress) {

				if (!strcmp(targetFnName, fnName)) {
					return ssn;
				}

				ssn++;
			}

		}

		index++;
	}

	return 0;
}

bool craftunhook::init() {
	craftunhook::wow64DsRva = findWow64DsRva();
	memcpy(&craftunhook::stubTemplate[11], &craftunhook::wow64DsRva, sizeof(craftunhook::wow64DsRva));
	return craftunhook::wow64DsRva != 0;
}

bool craftunhook::isHooked(PVOID fnAddress) {
	return memcmp(fnAddress, stubStart, 4);
}

bool craftunhook::unhook(LPCSTR fnName) {
	BOOL success = false;

	if (!craftunhook::wow64DsRva)
		return success;
	
	DWORD ssn = getFnSsnFromName(fnName);

	memcpy(&craftunhook::stubTemplate[4], &ssn, sizeof(ssn));

	PVOID fnAddr = GetProcAddress(
		GetModuleHandleA("NTDLL"),
		fnName
	);

	DWORD oldProtection = 0;
	success = VirtualProtect(fnAddr, craftunhook::stubSize, PAGE_EXECUTE_READWRITE, &oldProtection);

	memcpy(fnAddr, stubTemplate, craftunhook::stubSize);

	success = VirtualProtect(fnAddr, craftunhook::stubSize, oldProtection, &oldProtection);

	DWORD zeroSsn = 0;
	memcpy(&craftunhook::stubTemplate[4], &zeroSsn, sizeof(ssn));

	return success;
}