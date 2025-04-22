#include<windows.h>

class Pe {
public:
	PVOID ImageBase;
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeaders;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
	IMAGE_FILE_HEADER FileHeader;

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
	PIMAGE_RUNTIME_FUNCTION_ENTRY RunTimeEntryTable;

};

Pe ParsePeImage(LPCSTR imageName);