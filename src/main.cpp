#include <iostream>
#include <Windows.h>
#include "structs.h"
#include "file_info.h"
#include "io_processor.h"
#include "procedure_validator.h"
#include <vector>
#include "pe_patcher.h"
#include "arg_reader.h"




int main(int argc, char** argv) 
{
	if(argc < 4)
		return INVALID_RETURN_CODE;	

	INPUT_PARAMS input_params;
	arg_reader argument_reader;
	bool arg_parsing_is_successful =  argument_reader.read_input_params(argc, argv, &input_params);	
	if(!arg_parsing_is_successful)
	{
		printf("Something wrong with argument");
		return INVALID_RETURN_CODE;
	}
	
	procedure_validator validator;
	io_processor ioProcessor(validator);
	try
	{
		file_info* fileInfo = ioProcessor.read_file(input_params.file_name_input);
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
