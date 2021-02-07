#include "pe_patcher.h"
#include <stdexcept>
#include "address_interpreter.h"
#include "io_processor.h"
#include "procedure_validator.h"


template<NtHeaderConcept TNT_HEADERS>
std::vector<IMAGE_SECTION_HEADER*>& pe_patcher::extract_sections(TNT_HEADERS* nt_headers)
{
	std::vector<IMAGE_SECTION_HEADER*>* result = new std::vector<IMAGE_SECTION_HEADER*>();
	for(int i=0; i < nt_headers->FileHeader.NumberOfSections; i++)
		result->push_back(reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<BYTE*>(nt_headers) + sizeof(TNT_HEADERS) + i * sizeof(IMAGE_SECTION_HEADER)));

	_validator.validate_section_headers(*result);

	return *result;
}

bool pe_patcher::delete_debug_info(IMAGE_DEBUG_DIRECTORY* img_debug_dir, BYTE* dos_header_ptr)
{
	if(img_debug_dir->SizeOfData == 0 || img_debug_dir->PointerToRawData == 0)
	{
		printf("%s", "Could not to delete debug information because it doesn't exists in the file");
		return false;
	}

	RSDSI* rsds_info2 = reinterpret_cast<RSDSI*>(dos_header_ptr + img_debug_dir->PointerToRawData);
	rsds_info2->age = 0;
	rsds_info2->guidSig = GUID();
	memset(rsds_info2->pdbName, 0, strlen(rsds_info2->pdbName));
	rsds_info2->sig = 0;

	*img_debug_dir = *get_empty_image_debug_directory();

	return true;
}

IMAGE_DEBUG_DIRECTORY* pe_patcher::get_empty_image_debug_directory()
{
	auto result = new IMAGE_DEBUG_DIRECTORY();
	result->AddressOfRawData = NULL;
	result->Characteristics = NULL;
	result->MajorVersion = NULL;
	result->MinorVersion = NULL;
	result->PointerToRawData = NULL;
	result->SizeOfData = NULL;
	result->TimeDateStamp = NULL;
	result->Type = 0x10;

	return result;
}


file_info* pe_patcher::run(INPUT_PARAMS& input_params)
{
    IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(_file_info->buffer);
    
    if(!_validator.check(dos_header->e_magic == IMAGE_DOS_SIGNATURE))
		throw std::runtime_error("Could not read dos header");

	PLATFORM_INDEPENDENT_PART_OF_NT_HEADER* independent_nt_header = reinterpret_cast<PLATFORM_INDEPENDENT_PART_OF_NT_HEADER*>(reinterpret_cast<BYTE*>(dos_header) + dos_header->e_lfanew);
    input_params.is_dll = (independent_nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL;

    if(independent_nt_header->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC || independent_nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		return run_dependent_part_operation<IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64>(_file_info, dos_header, input_params);
	else
		return run_dependent_part_operation<IMAGE_NT_HEADERS32, IMAGE_OPTIONAL_HEADER32>(_file_info, dos_header, input_params);

}

template<NtHeaderConcept TNT_HEADERS, TOptionalHeaderConcept TOPTIONAL_HEADERS>
file_info* pe_patcher::run_dependent_part_operation(file_info* fileInfo, IMAGE_DOS_HEADER* dos_header, const INPUT_PARAMS& input_params)
{
    BYTE* dos_header_ptr = reinterpret_cast<BYTE*>(dos_header);
	TNT_HEADERS* nt_header = reinterpret_cast<TNT_HEADERS*>(dos_header_ptr + dos_header->e_lfanew);
	const IMAGE_FILE_HEADER* file_header = &nt_header->FileHeader;
	TOPTIONAL_HEADERS* optional_headers = &nt_header->OptionalHeader;
	
	if(!_validator.check(nt_header->Signature == IMAGE_NT_SIGNATURE))
		throw std::runtime_error("Could not read image nt headers");
	if(file_header->NumberOfSections > 3)
		throw std::runtime_error("Oh, csc.exe generated more then 3 sections?! Okey. Notify me about that");

	DWORD file_alignment = optional_headers->FileAlignment;

	std::vector<IMAGE_SECTION_HEADER*> sections = extract_sections(nt_header);
	IMAGE_SECTION_HEADER* section_header_text = sections[0];
	IMAGE_SECTION_HEADER* section_header_rsrc = sections[1];

    if(input_params.create_new_debug_entry)
	{
		file_info* old_file_info = fileInfo;
        fileInfo = relocate_buffer_with_displacement(old_file_info, file_alignment, section_header_text);
        fileInfo->file_name = input_params.file_name_output;

        // Update pointers and VA
        dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(fileInfo->buffer);
        dos_header_ptr = reinterpret_cast<BYTE*>(dos_header);
        nt_header = reinterpret_cast<TNT_HEADERS*>(dos_header_ptr + dos_header->e_lfanew);
        if(!_validator.check(nt_header->Signature == IMAGE_NT_SIGNATURE))
            throw std::runtime_error("Could not read image nt headers");

        file_header = &nt_header->FileHeader;

        sections.clear();
        sections = extract_sections<TNT_HEADERS>(nt_header);
        
        section_header_text = sections[0];
        section_header_rsrc = sections[1];

        section_header_text->SizeOfRawData += file_alignment;
        section_header_text->Misc.VirtualSize = section_header_text->SizeOfRawData;

        for(int i=1; i<sections.size(); i++)
            sections[i]->PointerToRawData += file_alignment;

        optional_headers = &nt_header->OptionalHeader;
        optional_headers->SizeOfCode += file_alignment;
        optional_headers->SizeOfInitializedData += file_alignment;
        //optional_headers->SizeOfImage + file_alignment; // work with it later

        delete old_file_info;
	}

    // FOR TESTING
	//_validator.throw_if_invalid(optional_headers, sections, dos_header_ptr);

    _validator.throw_if_reqired_data_directory_missing(dos_header_ptr, section_header_text, optional_headers);

	if(optional_headers->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC || file_header->Machine == IMAGE_FILE_MACHINE_AMD64)
		printf("x64 PE file structure\n");	
	else 
        printf("x32 PE file structure\n");


	IMAGE_DATA_DIRECTORY entry_debug_directory = optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	if(entry_debug_directory.VirtualAddress == 0)
	{
		optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] = IMAGE_DATA_DIRECTORY 
		{ 
			address_interpreter::to_va(section_header_text, section_header_text->PointerToRawData + section_header_text->SizeOfRawData - (file_alignment/2)), 
			sizeof(IMAGE_DEBUG_DIRECTORY) 
		};

		entry_debug_directory = optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	auto image_dbg_dir_rva = address_interpreter::to_rva(section_header_text, entry_debug_directory.VirtualAddress);
	IMAGE_DEBUG_DIRECTORY* image_debug_directory = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(dos_header_ptr + image_dbg_dir_rva);

	if(input_params.delete_debug_entry_dir)
	{
		bool is_successful = delete_debug_info(image_debug_directory, dos_header_ptr);
		if(!is_successful)
			throw std::runtime_error("Could not to delete debug info");
	}
	else
	{
		bool is_successful = update_or_create_debug_info(optional_headers, entry_debug_directory, image_debug_directory, sections, dos_header_ptr, input_params);
		
		if(!is_successful)
			throw std::runtime_error("Invalid debug dir update operation");

		_validator.throw_if_invalid<TOPTIONAL_HEADERS>(optional_headers, sections, dos_header_ptr);

		if(!_validator.rsds_check<TNT_HEADERS>(nt_header, section_header_text, dos_header_ptr))
			throw std::runtime_error("Some error occured during this operation");
	}

    return fileInfo;
}


// relocate .rsrc(and .reloc) section and extend .text on file aligment size
file_info* pe_patcher::relocate_buffer_with_displacement(file_info* fileInfo, DWORD file_alignment, IMAGE_SECTION_HEADER* text_section_header)
{
	// COPY BUFFERS
	DWORD new_file_size = fileInfo->file_size + file_alignment;
	byte* new_buffer = new byte[new_file_size];

	DWORD first_part_of_file_size = text_section_header->PointerToRawData + text_section_header->SizeOfRawData;
	byte* end_first_part_old = fileInfo->buffer + first_part_of_file_size;
	byte* start_free_zone_of_file_ptr_new = new_buffer + first_part_of_file_size;
	byte* second_part_of_file_ptr_new = start_free_zone_of_file_ptr_new + file_alignment;

	std::copy(fileInfo->buffer, end_first_part_old, new_buffer);
	std::fill(start_free_zone_of_file_ptr_new, second_part_of_file_ptr_new, 0);
	std::copy(end_first_part_old, fileInfo->buffer + fileInfo->file_size, second_part_of_file_ptr_new);

	return new file_info(new_file_size, new_buffer, fileInfo->file_name);
}

pdb_authenticity_info* pe_patcher::get_pdb_authenticity_info(file_info* pdb_file_info)
{
	DWORD sig = PDBImpvVC70;
	constexpr size_t impv_size = sizeof(DWORD);
	byte pdb_impv[impv_size];
	memcpy(pdb_impv, &sig, impv_size);

	auto iter_buf_end = std::reverse_iterator<byte*>(pdb_file_info->buffer + 1);
	auto iter_buf_start = std::reverse_iterator<byte*>(pdb_file_info->buffer + pdb_file_info->file_size);
	auto iter_pdb_impv_sig_end = std::reverse_iterator<byte*>(pdb_impv);
	auto iter_pdb_impv_sig_start = std::reverse_iterator<byte*>(pdb_impv + impv_size);
	
	auto iter_result = std::search(iter_buf_start, iter_buf_end, iter_pdb_impv_sig_start, iter_pdb_impv_sig_end);
	byte* result_ptr = iter_result.base();
	result_ptr = result_ptr - impv_size;

	pdb_authenticity_info* pdb_info = reinterpret_cast<pdb_authenticity_info*>(result_ptr);
	if(pdb_info->PDBImpvVC70Val != PDBImpvVC70)
		throw std::runtime_error("Could not to find PDBImpvVC70 in the pdb file");

	return pdb_info;
}



template<TOptionalHeaderConcept TOPTIONAL_HEADERS>
bool pe_patcher::update_or_create_debug_info(
	TOPTIONAL_HEADERS* optional_headers, 
	const IMAGE_DATA_DIRECTORY& entry_debug_directory,
	IMAGE_DEBUG_DIRECTORY* image_debug_directory,
	std::vector<IMAGE_SECTION_HEADER*>& sections,
	byte* dos_header_ptr,
	const INPUT_PARAMS& input_params)
{
	GUID rsds_guid;
	DWORD timedate_stamp;
	DWORD age;

	if(input_params.use_existing_pdb)
	{
        io_processor io = io_processor(_validator);
		file_info* pdb_file_info = io.read_file(input_params.pdb_file_name);

		pdb_authenticity_info* pdb_authenticity_info = get_pdb_authenticity_info(pdb_file_info);
		rsds_guid = pdb_authenticity_info->guidSig;
		timedate_stamp = pdb_authenticity_info->TimeDateStamp;
		age = pdb_authenticity_info->age;

		delete pdb_file_info;
	}
	else
	{
		timedate_stamp = GetTickCount();
		age = RSDS_AGE_DEFAULT;
		CoCreateGuid(&rsds_guid);
	}

	RSDSI* rsds_info;
	constexpr size_t entry_debug_dir_size = sizeof(IMAGE_DEBUG_DIRECTORY) * 2;
	size_t image_debug_dir_size = sizeof(RSDSI) - sizeof(RSDSI::pdbName) + strlen(input_params.pdb_file_name) + 1;

	if(input_params.create_new_debug_entry)
	{
		if(image_debug_directory->SizeOfData != 0 || entry_debug_directory.Size == entry_debug_dir_size)
		{
			printf("%s", "Seem your pe file already contains rsds section");
			return false;
		}
		IMAGE_DATA_DIRECTORY new_entry_debug_directory2 = IMAGE_DATA_DIRECTORY { entry_debug_directory.VirtualAddress, entry_debug_dir_size };
		optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] = new_entry_debug_directory2;

		image_debug_directory->SizeOfData = image_debug_dir_size;
		image_debug_directory->Type = IMAGE_DEBUG_TYPE_CODEVIEW;
		image_debug_directory->PointerToRawData = address_interpreter::to_rva(sections[0], new_entry_debug_directory2.VirtualAddress) + new_entry_debug_directory2.Size;
		image_debug_directory->AddressOfRawData = address_interpreter::to_va(sections[0], image_debug_directory->PointerToRawData);
		image_debug_directory->TimeDateStamp = timedate_stamp;

		IMAGE_DEBUG_DIRECTORY* image_debug_directory3 = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(reinterpret_cast<byte*>(image_debug_directory) + sizeof(IMAGE_DEBUG_DIRECTORY));
		*image_debug_directory3 = *get_empty_image_debug_directory();

		rsds_info = reinterpret_cast<RSDSI*>(dos_header_ptr + image_debug_directory->PointerToRawData);
		memset(rsds_info->pdbName, 0, _MAX_PATH);
	}
	else
	{
		if(image_debug_directory->SizeOfData == 0)
		{
			printf("%s", "You wants to change debug info but it doesn't exists");
			return false;
		}

		rsds_info = reinterpret_cast<RSDSI*>(dos_header_ptr + image_debug_directory->PointerToRawData);
		size_t pdb_name_size = strlen(rsds_info->pdbName);
		if(pdb_name_size == NULL)
			pdb_name_size = _MAX_PATH;
		memset(rsds_info->pdbName, 0, pdb_name_size);
	}

	rsds_info->sig = RSDS_SIG;
	rsds_info->guidSig = rsds_guid;
	rsds_info->age = age;	
	strcpy(rsds_info->pdbName, input_params.pdb_file_name);

	IMAGE_DATA_DIRECTORY entry_import_data_dir = optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if(input_params.create_new_debug_entry && entry_import_data_dir.VirtualAddress != NULL)
	{
		// calculate import descr virt address
		DWORD target_imp_descr_rva = image_debug_directory->PointerToRawData + image_debug_directory->SizeOfData;
		DWORD target_imp_descr_va = address_interpreter::to_va(sections[0], target_imp_descr_rva);

		entry_import_data_dir = IMAGE_DATA_DIRECTORY { target_imp_descr_va, entry_import_data_dir.Size };
		optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = entry_import_data_dir;
		DWORD import_descr_rva = address_interpreter::to_rva(sections[0], entry_import_data_dir.VirtualAddress);
		if(import_descr_rva != target_imp_descr_rva)
			throw std::bad_exception();

		IMAGE_IMPORT_DESCRIPTOR* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(dos_header_ptr + import_descr_rva);
		if(import_descriptor->FirstThunk != 0)
			throw std::bad_exception();

		import_descriptor->FirstThunk = optional_headers->BaseOfCode;
		import_descriptor->OriginalFirstThunk = entry_import_data_dir.VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;
		import_descriptor->Name = import_descriptor->OriginalFirstThunk + ORIGINAL_FIRST_THUNK_DISPLACEMENT;

		RELOC_SECTION* reloc_section2 = reinterpret_cast<RELOC_SECTION*>(dos_header_ptr + sections[2]->PointerToRawData);
		if(!(reloc_section2->offset_clr_stub && CLR_STUB_DEFUALT_OFFSET_FLAG) || reloc_section2->Size != 12)
			throw std::bad_exception();

		// !!!!!

		DWORD import_addr_entry_va = import_descriptor->Name - sizeof(IMPORT_ADDRESS_ENTRY::import_function_name) - sizeof(IMPORT_ADDRESS_ENTRY::Hint);
		DWORD import_addr_entry_rva = address_interpreter::to_rva(sections[0], import_addr_entry_va);


		DWORD entry_point_struct_size = sizeof(ENTRY_POINT_STRUCT::emtpy_stub) + sizeof(ENTRY_POINT_STRUCT::entry_point_sig);


		DWORD entry_point_characteristics_va = import_addr_entry_va + sizeof(IMPORT_ADDRESS_ENTRY) + entry_point_struct_size;
		reloc_section2->offset_clr_stub = (entry_point_characteristics_va - reloc_section2->iat_va) | CLR_STUB_DEFUALT_OFFSET_FLAG;
		DWORD entry_point_characteristics_rva = address_interpreter::to_rva(sections[0], entry_point_characteristics_va);

		IMAGE_THUNK_DATA32* new_thunk = reinterpret_cast<IMAGE_THUNK_DATA32*>(dos_header_ptr + address_interpreter::to_rva(sections[0], import_descriptor->OriginalFirstThunk));
		auto new_u1 = &new_thunk->u1;
		new_u1->Function = import_addr_entry_va;
		IMAGE_THUNK_DATA32* thunk = reinterpret_cast<IMAGE_THUNK_DATA32*>(dos_header_ptr + address_interpreter::to_rva(sections[0], import_descriptor->FirstThunk));
		auto u1 = &thunk->u1;
		u1->Function = new_u1->Function;
		IMAGE_THUNK_DATA32* thunk_from_data_dir = reinterpret_cast<IMAGE_THUNK_DATA32*>(dos_header_ptr + address_interpreter::to_rva(sections[0], optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress));
		if(thunk_from_data_dir->u1.Function != thunk->u1.Function)
			throw std::bad_exception();


		IMPORT_ADDRESS_ENTRY* import_address_entry = reinterpret_cast<IMPORT_ADDRESS_ENTRY*>(dos_header_ptr + import_addr_entry_rva);
		if(import_address_entry->Hint != NULL)
			throw std::runtime_error("Bad address of clr stub");


		strcpy(import_address_entry->import_function_name, input_params.is_dll ? "_CorDllMain" : "_CorExeMain");
		strcpy(import_address_entry->Import_module_name, "mscoree.dll");
		ENTRY_POINT_STRUCT* entry_point_struct = reinterpret_cast<ENTRY_POINT_STRUCT*>(dos_header_ptr + import_addr_entry_rva + sizeof(IMPORT_ADDRESS_ENTRY));
		if(entry_point_struct->emtpy_stub != NULL || entry_point_struct->entry_point_sig != NULL)
			throw std::bad_exception();

		entry_point_struct->emtpy_stub = NULL;
		entry_point_struct->entry_point_sig = ENTRY_POINT_SIG;

		DWORD* entry_point_characteristics = reinterpret_cast<DWORD*>(dos_header_ptr + entry_point_characteristics_rva);
		*entry_point_characteristics = input_params.is_dll ? DLL_ENTRY_POINT_CHARACTERISTICS : EXE_ENTRY_POINT_CHARACTERISTICS;

		optional_headers->AddressOfEntryPoint = entry_point_characteristics_va - sizeof(ENTRY_POINT_STRUCT::entry_point_sig);


        _validator.validate_entry_point(dos_header_ptr, sections[0], import_descriptor, optional_headers->AddressOfEntryPoint);

	}

	printf("%s%d", "The RSDS section successfuly added to address: ", image_debug_directory->PointerToRawData);

	return true;
}