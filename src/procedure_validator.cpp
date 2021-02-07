#include <windows.h>
#include <errhandlingapi.h>
#include <stdio.h>
#include "concepts.h"
#include "procedure_validator.h"
#include <string.h>


bool procedure_validator::check(bool is_successful)
{
    if(!is_successful)
        printf("%d%s", GetLastError(), " - error code");
    return is_successful;        
}

void procedure_validator::validate_section_headers(std::vector<IMAGE_SECTION_HEADER*>& sections)
{
    int is_text_sect = memcmp(sections[0]->Name, ".text", IMAGE_SIZEOF_SHORT_NAME);
	int is_rsrc_sect = memcmp(sections[1]->Name, ".rsrc", IMAGE_SIZEOF_SHORT_NAME);
	int is_reloc_sect = 0;
	if(sections.size() > 2)
		is_reloc_sect = memcmp(sections[2]->Name, ".reloc", IMAGE_SIZEOF_SHORT_NAME);

	bool is_text_sect_contains_code = (sections[0]->Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE;
	if(is_text_sect != 0 || is_rsrc_sect != 0 || is_reloc_sect != 0 || is_text_sect_contains_code == false)
		throw std::runtime_error("Section headers was shifted incorrectly");
}


void procedure_validator::validate_entry_point(byte* dos_header_ptr, const IMAGE_SECTION_HEADER* text_section_header, IMAGE_IMPORT_DESCRIPTOR* import_descriptor, DWORD address_of_entry_point)
    {
        char* entry_func_name = reinterpret_cast<char*>(reinterpret_cast<byte*>(dos_header_ptr + address_interpreter::to_rva(text_section_header, import_descriptor->Name)));
        int cmp = strcmp(entry_func_name, "mscoree.dll");
		if(cmp != 0)
            throw std::runtime_error("Entry point function name is invalid");
            
		WORD* klkl2 = reinterpret_cast<WORD*>(dos_header_ptr + address_interpreter::to_rva(text_section_header, address_of_entry_point));
        if(*klkl2 != ENTRY_POINT_SIG || import_descriptor->Name + 0x10 != address_of_entry_point)
            throw std::runtime_error("Definition of entry point is invalid");
    }

