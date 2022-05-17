#pragma once 

#include "structs.h"
#include <string.h>
#include <iostream>

class arg_reader
{
public:
    bool read_input_params(int argc, char** argv, INPUT_PARAMS* input_params)
    {
        input_params->create_new_debug_entry = false;
        input_params->delete_debug_entry_dir = false;
        input_params->use_existing_pdb = false;
        input_params->pdb_file_name = LPCSTR('\0');

        input_params->file_name_input = argv[1];

        for(int i=2; i<argc; i++)
        {
            auto cmd = argv[i];
            if(strcmp(cmd, "-o") == 0)
            {
                input_params->file_name_output = argv[++i];
            }
            else if(strcmp(cmd, "-pdb") == 0)
            {
                input_params->pdb_file_name = argv[++i];
            }
            else if(strcmp(cmd, "-add") == 0)
            {
                if(input_params->delete_debug_entry_dir)
                {
                    return false;
                }
                input_params->create_new_debug_entry = true;
            }
            else if(strcmp(cmd, "-add-exists") == 0)
            {
                if(input_params->delete_debug_entry_dir)
                    return false;

                input_params->use_existing_pdb = true;
                input_params->create_new_debug_entry = true;
            }
            else if(strcmp(cmd, "-del") == 0)
            {
                if(input_params->create_new_debug_entry)
                {
                    return false;
                }
                input_params->delete_debug_entry_dir = true;
            }
            
        }


        if(input_params->pdb_file_name == LPCSTR('\0'))
        {
            size_t file_name_size = strlen(input_params->file_name_input);

            LPSTR pdb_name = (LPSTR)malloc(file_name_size);
            strcpy(pdb_name, input_params->file_name_input);

            pdb_name[file_name_size - 1] = 'b';
            pdb_name[file_name_size - 2] = 'd';
            pdb_name[file_name_size - 3] = 'p';

            input_params->pdb_file_name = const_cast<LPCSTR>(pdb_name);
        }

        return true;
    }
};