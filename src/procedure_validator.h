#pragma once

#include <windows.h>
#include "structs.h"
#include "concepts.h"
#include <vector>
#include <stdexcept>
#include "constants.h"
#include "address_interpreter.h"



class procedure_validator
{
public:
    bool check(bool is_successful);
    void validate_section_headers(std::vector<IMAGE_SECTION_HEADER*>& sections);
    void validate_entry_point(byte* dos_header_ptr, const IMAGE_SECTION_HEADER* text_section_header, IMAGE_IMPORT_DESCRIPTOR* import_descriptor, DWORD address_of_entry_point);


    template<NtHeaderConcept TNT_HEADERS>
    bool rsds_check(const TNT_HEADERS* nt_header, const IMAGE_SECTION_HEADER* section_header_text, byte* dos_header_address)
    {
        IMAGE_DATA_DIRECTORY entry_debug_directory2 = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if(entry_debug_directory2.VirtualAddress == 0)
            return false;

        DWORD rsdsAddress233 = address_interpreter::to_rva(section_header_text, entry_debug_directory2.VirtualAddress);
        IMAGE_DEBUG_DIRECTORY* image_debug_directory = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(dos_header_address + rsdsAddress233);
        RSDSI* rsds_info = reinterpret_cast<RSDSI*>(dos_header_address + image_debug_directory->PointerToRawData);
        if(rsds_info->sig != RSDS_SIG)
            return false;
    }


    template<TOptionalHeaderConcept TOPTIONAL_HEADERS>
    void throw_if_reqired_data_directory_missing(byte* dos_header_ptr, IMAGE_SECTION_HEADER* text_section_header, TOPTIONAL_HEADERS* optional_headers)
    {
        IMAGE_DATA_DIRECTORY dir_entry_resource = optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        if(dir_entry_resource.VirtualAddress == 0)
            throw std::runtime_error("Could not to locate entry resource directory");

        IMAGE_DATA_DIRECTORY com_descriptor = optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        if(com_descriptor.VirtualAddress == 0)
            throw std::runtime_error("Provided file is not clr compatible");

        IMAGE_COR20_HEADER* clr_headers = reinterpret_cast<IMAGE_COR20_HEADER*>(dos_header_ptr + address_interpreter::to_rva(text_section_header, com_descriptor.VirtualAddress));
        if(clr_headers->cb < 0x48)
            throw std::runtime_error("Bad image");
    }

    // firstly refactor this stuff
    template<TOptionalHeaderConcept TOPTIONAL_HEADERS>
    void throw_if_invalid(TOPTIONAL_HEADERS* optional_headers, std::vector<IMAGE_SECTION_HEADER*>& sections, BYTE* dos_header_ptr)
    {
        
        DWORD rva_t = address_interpreter::to_rva(sections[1], optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
        size_t size_res = sizeof(IMAGE_RESOURCE_DIRECTORY);
        int cc1 = optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size / size_res;
        IMAGE_RESOURCE_DIRECTORY* ird = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(dos_header_ptr + rva_t);
        IMAGE_RESOURCE_DIRECTORY* ird2 = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(dos_header_ptr + sections[1]->PointerToRawData);

        if(ird->Characteristics != ird2->Characteristics || ird->NumberOfIdEntries != ird2->NumberOfIdEntries)
            throw std::bad_exception();

        auto number_of_entries = ird->NumberOfIdEntries + ird->NumberOfNamedEntries;

        for(int i = 1; i <= number_of_entries; i++ )
        {
            IMAGE_RESOURCE_DIRECTORY_ENTRY* img_res_dir_ent = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(ird + i);

            if(MAKEINTRESOURCE(img_res_dir_ent->Id) == RT_VERSION)
            {
                if( img_res_dir_ent->DataIsDirectory )
                {
                    IMAGE_RESOURCE_DIRECTORY_ENTRY* img_res_dir_ent2 = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(dos_header_ptr + sections[1]->PointerToRawData + img_res_dir_ent->OffsetToDirectory);
                    IMAGE_RESOURCE_DIRECTORY_ENTRY* img_res_dir_ent4 = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(dos_header_ptr + img_res_dir_ent->OffsetToDirectory + rva_t);
                    
                    auto aaa123 = img_res_dir_ent2;
                }
            }
        }

        if(optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
        {
            // IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
            auto ssl1 = address_interpreter::to_rva(sections[0], optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
            IMAGE_IMPORT_DESCRIPTOR* iid = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(dos_header_ptr + ssl1);

            IMAGE_COR20_HEADER* ic20h = reinterpret_cast<IMAGE_COR20_HEADER*>(dos_header_ptr + address_interpreter::to_rva(sections[0], optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress));
            auto ic20h_metadata_rva = address_interpreter::to_rva(sections[0], ic20h->MetaData.VirtualAddress);
            COR20_METADATA_SECTION* cor20_ms = reinterpret_cast<COR20_METADATA_SECTION*>(dos_header_ptr + ic20h_metadata_rva);
            if(cor20_ms->Length != 12)
                throw std::runtime_error("Version length in clr metadata section is not 12. Say me about the case");

            COR20_METADATA_TABLE* cor20_mt = reinterpret_cast<COR20_METADATA_TABLE*>(dos_header_ptr + ic20h_metadata_rva + cor20_ms->StreamHeaders.Offset);

            printf("clr version: %s", cor20_ms->Version);


            auto clr_stbrva = address_interpreter::to_rva(sections[0], iid->Name - sizeof(IMPORT_ADDRESS_ENTRY::import_function_name) - sizeof(IMPORT_ADDRESS_ENTRY::Hint));
            IMPORT_ADDRESS_ENTRY* clr1 = reinterpret_cast<IMPORT_ADDRESS_ENTRY*>(dos_header_ptr + clr_stbrva);
            ENTRY_POINT_STRUCT* clr2 = reinterpret_cast<ENTRY_POINT_STRUCT*>(dos_header_ptr + clr_stbrva + sizeof(IMPORT_ADDRESS_ENTRY));

            auto ms1 = address_interpreter::to_rva(sections[2], optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            auto ms7 = reinterpret_cast<byte*>(dos_header_ptr + address_interpreter::to_rva(sections[0], iid->Name));


            RELOC_SECTION* reloc_section = reinterpret_cast<RELOC_SECTION*>(dos_header_ptr + sections[2]->PointerToRawData);
            if(!(reloc_section->offset_clr_stub && CLR_STUB_DEFUALT_OFFSET_FLAG))
                throw std::bad_exception();


            auto s2 = reloc_section->iat_va + (reloc_section->offset_clr_stub ^ CLR_STUB_DEFUALT_OFFSET_FLAG);
            DWORD* s2_check = reinterpret_cast<DWORD*>(dos_header_ptr + address_interpreter::to_rva(sections[0], s2));
            auto s5 = address_interpreter::to_rva(sections[0], optional_headers->AddressOfEntryPoint); // address of _corexemain virtual address which is 0x25ff
            DWORD* sm1 = reinterpret_cast<DWORD*>(dos_header_ptr + s5);

            auto s6 = address_interpreter::to_rva(sections[0], optional_headers->BaseOfCode); // start of code section

            // !!!
            auto br1 = address_interpreter::to_rva(sections[2], optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            auto br2 = reinterpret_cast<RELOC_SECTION*>(dos_header_ptr + br1);



            auto iat_rva = address_interpreter::to_rva(sections[0], optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
            IMAGE_THUNK_DATA32* iat1 = reinterpret_cast<IMAGE_THUNK_DATA32*>(dos_header_ptr + iat_rva);
            IMAGE_THUNK_DATA32* iat2 = reinterpret_cast<IMAGE_THUNK_DATA32*>(dos_header_ptr + address_interpreter::to_rva(sections[0], iid->FirstThunk));
            IMAGE_THUNK_DATA32* iat3 = reinterpret_cast<IMAGE_THUNK_DATA32*>(dos_header_ptr + address_interpreter::to_rva(sections[0], iid->OriginalFirstThunk));

            if(iat1->u1.Function != iat2->u1.Function || iat1->u1.Function != iat3->u1.Function)
                std::bad_exception();


            auto u1_rva = address_interpreter::to_rva(sections[0], iat1->u1.Function);

            IMPORT_ADDRESS_ENTRY* iaentr = reinterpret_cast<IMPORT_ADDRESS_ENTRY*>(dos_header_ptr + u1_rva);
            if(iaentr->Hint != clr1->Hint || strcmp(iaentr->import_function_name, clr1->import_function_name) != 0)
                throw std::bad_exception();
        }
    }

};