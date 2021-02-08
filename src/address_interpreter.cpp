
#include "address_interpreter.h"
#include <stdexcept>


// Get Relative virtual Address
DWORD address_interpreter::to_rva(const IMAGE_SECTION_HEADER* section_header, const DWORD& virt_addr)
{
	DWORD cbMaxOnDisk = min(section_header->Misc.VirtualSize, section_header->SizeOfRawData); 
	if ((virt_addr >= section_header->VirtualAddress) && (virt_addr < section_header->VirtualAddress + cbMaxOnDisk))
	{   
		return section_header->PointerToRawData + virt_addr - section_header->VirtualAddress;   
	}
	else
		throw std::runtime_error("Could not to find rva by provided virtual address: " + virt_addr);
}


// Get Virtual Address
DWORD address_interpreter::to_va(const IMAGE_SECTION_HEADER* section_header, const DWORD& rva)
{
	DWORD cbMaxOnDisk = min(section_header->Misc.VirtualSize, section_header->SizeOfRawData);
	DWORD virt_addr = rva - section_header->PointerToRawData + section_header->VirtualAddress;
	if(virt_addr < section_header->VirtualAddress || virt_addr > section_header->VirtualAddress + cbMaxOnDisk)
	    throw std::runtime_error("Could not to calculate VA with provided RVA: " + rva);
	
	return virt_addr;
}