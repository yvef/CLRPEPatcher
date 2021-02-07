#pragma once
#include <windows.h>

class address_interpreter
{
public:
    static DWORD to_rva(const IMAGE_SECTION_HEADER* pSectionHeader, const DWORD& virt_addr);
    static DWORD to_va(const IMAGE_SECTION_HEADER* section_header, const DWORD& rva);
};