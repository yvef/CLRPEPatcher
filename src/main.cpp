#include <iostream>
#include <Windows.h>
#include "structs.h"
#include "file_info.h"
#include "io_processor.h"
#include "procedure_validator.h"
#include <vector>
#include "pe_patcher.h"




int main(int argc, char** argv) 
{
    LPCSTR pe_file_name = "c:\\Temp\\appblocksnopdb\\netstandard2.0\\Selerant.ApplicationBlocks.Core.dll";
	LPCSTR file_name_output = "c:\\Temp\\appblocksnopdb\\netstandard2.0\\Selerant.ApplicationBlocks.Core_output.dll";
	LPCSTR pdb_file_name = "c:\\Temp\\appblocksnopdb1\\netstandard2.0\\Selerant.ApplicationBlocks.Core.pdb";

    bool use_existing_pdb = true;
	bool delete_debug_entry_dir = false;
	bool create_new_debug_entry = !delete_debug_entry_dir;
	bool change_pdb_info = !create_new_debug_entry && !delete_debug_entry_dir;

    INPUT_PARAMS input_params;
	input_params.create_new_debug_entry = create_new_debug_entry;
	input_params.delete_debug_entry_dir = delete_debug_entry_dir;
	input_params.file_name_output = file_name_output;
	input_params.pdb_file_name = pdb_file_name;
	input_params.use_existing_pdb = use_existing_pdb;
	input_params.pe_file_name = pe_file_name;

    procedure_validator validator;
    io_processor ioProcessor(validator);
	try
	{
		file_info* fileInfo = ioProcessor.read_file(pe_file_name);
    	pe_patcher patcher(fileInfo, validator);
    	file_info* result = patcher.run(input_params);

    	bool flush_to_file_succeeded = ioProcessor.flush_to_file(result);
		delete result;

		if(!validator.check(flush_to_file_succeeded))
		{
			printf("%s", "Save to file operation is invalid");
			return INVALID_RETURN_CODE;
		}
	}
	catch(std::exception ex)
	{
		printf("%s", ex.what());
		return INVALID_RETURN_CODE;
	}
    
	return SUCCESS_RETURN_CODE;


}
