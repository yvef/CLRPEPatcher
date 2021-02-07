#pragma once
#include <windows.h>
#include "file_info.h"
#include "procedure_validator.h"

class io_processor
{
private:
    procedure_validator& _validator;

public:
    io_processor(procedure_validator& validator) : _validator(validator)
    {
    }

    file_info* read_file(LPCSTR);
    bool flush_to_file(const file_info* file_info);
};