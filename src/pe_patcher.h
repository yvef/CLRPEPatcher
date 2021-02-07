#include <windows.h>
#include "file_info.h"
#include "structs.h"
#include "constants.h"
#include "concepts.h"
#include "procedure_validator.h"
#include <vector>


class pe_patcher
{
private:
    procedure_validator& _validator;
    file_info* _file_info;

    template<NtHeaderConcept TNT_HEADERS, TOptionalHeaderConcept TOPTIONAL_HEADERS>
    file_info* run_dependent_part_operation(file_info*, IMAGE_DOS_HEADER*, const INPUT_PARAMS&);
    file_info* relocate_buffer_with_displacement(file_info* file_info2, DWORD file_alignment, IMAGE_SECTION_HEADER* text_section_header);

    template<TOptionalHeaderConcept TOPTIONAL_HEADERS>
    bool update_or_create_debug_info(
	    TOPTIONAL_HEADERS* optional_headers2, 
	    const IMAGE_DATA_DIRECTORY& entry_debug_directory2,
	    IMAGE_DEBUG_DIRECTORY* image_debug_directory,
	    std::vector<IMAGE_SECTION_HEADER*>& sections,
	    byte* dos_header_ptr,
	    const INPUT_PARAMS& input_params);

    template<NtHeaderConcept TNT_HEADERS>
    std::vector<IMAGE_SECTION_HEADER*>& extract_sections(TNT_HEADERS* nt_headers);

    bool delete_debug_info(IMAGE_DEBUG_DIRECTORY* img_debug_dir, BYTE* dos_header_ptr);
    IMAGE_DEBUG_DIRECTORY* get_empty_image_debug_directory();
    pdb_authenticity_info* get_pdb_authenticity_info(file_info* pdb_file_info);

public:
    pe_patcher(file_info* fileInfo, procedure_validator& validator) : _file_info(fileInfo), _validator(validator) { }

    file_info* run(INPUT_PARAMS& input_params);    

    template<NtHeaderConcept TNT_HEADERS>
    void test(TNT_HEADERS header);
};