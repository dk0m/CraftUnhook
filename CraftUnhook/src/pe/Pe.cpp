#include "Pe.h"

Pe ParsePeImage(LPCSTR imageName) {

	PVOID imageBase = GetModuleHandleA(imageName);
	DWORD_PTR peBase = (DWORD_PTR)imageBase;

	PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(peBase + Dos->e_lfanew);

	IMAGE_OPTIONAL_HEADER OptionalHeader = NtHeaders->OptionalHeader;
	IMAGE_FILE_HEADER FileHeader = NtHeaders->FileHeader;

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(peBase + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(peBase + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PIMAGE_RUNTIME_FUNCTION_ENTRY RunTimeFnTable = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(peBase + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);


	return Pe {
		imageBase,
		Dos,
		NtHeaders,
		OptionalHeader,
		FileHeader,
		ImportDescriptor,
		ExportDirectory,
		RunTimeFnTable
	};
}
