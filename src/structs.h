#pragma once
#include <windows.h>

typedef struct _COR20_METADATA_SECTION
{
	DWORD Signature;
	WORD MajorVersion;
	WORD MinorVersion;
	DWORD Reserved;
	DWORD Length;
	char Version[12];
	WORD Flags;
	WORD Streams;
	struct STREAM_HEADERS
	{
		DWORD Offset;
		DWORD Size;
	} StreamHeaders;
} COR20_METADATA_SECTION;


typedef struct _COR20_METADATA_TABLE
{
	DWORD Reserved;
	WORD MajorVersion;
	WORD MinorVersion;
	BYTE HeapOffsetSize;
	BYTE Reserved2;
	ULONGLONG Valid;
	ULONGLONG Sorted;
} COR20_METADATA_TABLE;


typedef struct _IMPORT_ADDRESS_ENTRY
{
	WORD Hint;
 	char import_function_name[12];
 	char Import_module_name[12];
} IMPORT_ADDRESS_ENTRY;

typedef struct _ENTRY_POINT_STRUCT
{
	DWORD emtpy_stub;
	WORD entry_point_sig;
	//DWORD characteristics;
} ENTRY_POINT_STRUCT;



typedef struct _RELOC_SECTION
{
	DWORD iat_va;
	DWORD Size;
	DWORD offset_clr_stub;
} RELOC_SECTION;



typedef struct _INPUT_PARAMS
{
	bool create_new_debug_entry;
	bool use_existing_pdb;
	bool delete_debug_entry_dir;
	LPCSTR file_name_output;
	LPCSTR pdb_file_name;
	LPCSTR pe_file_name;
	bool is_dll;
} INPUT_PARAMS;


// Platform independent part of nt header to check a magic number
typedef struct _PLATFORM_INDEPENDENT_PART_OF_NT_HEADER
{
	DWORD StubSignature;
    IMAGE_FILE_HEADER FileHeader;
    WORD Magic;	
} PLATFORM_INDEPENDENT_PART_OF_NT_HEADER;


// RSDS debug info
typedef struct _RSDSI
{
    DWORD sig;                 
    GUID guidSig;
    DWORD age;
    char pdbName[_MAX_PATH];
} RSDSI;


typedef struct _pdb_authenticity_info
{
	DWORD PDBImpvVC70Val;
	DWORD TimeDateStamp;
	DWORD age;
	GUID guidSig;
} pdb_authenticity_info;