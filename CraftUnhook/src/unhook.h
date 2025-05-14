#pragma once
#include "./pe/Pe.h"

#define CLEAN_CALL(fnHash, fnCall) \
    Unhook unhookObj = Unhook { fnHash }; \
	unhookObj.unhook(); \
    fnCall; \
    unhookObj.restore();

class Unhook {
private:
	DWORD procHash;
	PVOID procAddress;
	PVOID orgProc; // bytes of orgProc

public:
	Unhook(DWORD procHash);
	~Unhook();
	bool unhook();
	bool restore();

};

namespace hashes {
	constexpr DWORD ZwQueryInformationProcess = 0xb16fe439;
}
namespace craftunhook {

	static DWORD wow64DsRva = 0;
	static DWORD stubSize = 23;

	static Pe ntdll = ParsePeImage("ntdll");

	static BYTE stubStart[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
	static BYTE wow64TestStart[] = { 0xF6, 0x04, 0x25 };
	static BYTE stubTemplate[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xF6, 0x04, 0x25, 0x08, 0x00, 0xFE, 0x7F, 0x01, 0x75, 0x03, 0x0F, 0x05, 0xC3, 0xCD, 0x2E };

	bool init();
	bool isHookedByHash(DWORD procHash);
}
