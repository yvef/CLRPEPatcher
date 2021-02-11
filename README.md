# CLRPEPatcher
The patcher for CLR compatible PE/COFF files, that can do the next things:
- Add debug directory with pdb info into file, if it doesn't exists.
- Update pdb info using an existing .pdb file
- Delete pdb info

##### Commands:
- -o: define output file
- -pdb: add existing pdb. (Optional. Default: output file name with .pdb extension).
- -add: add pdb info. Store the pdb file name info rsds info, but not use pdb authenticity. Another word, it will not be linked with provided pdb.
- -add-exists: add pdb info and grab authenticity from the provided pdb file.
- -del: delete pdb info.

Example:
```bash
$ CLRPEPatcher "file_path_input" -o "file_path_output" -add
```

##### Limitations:
- The tool works correctly if file alignment is 512, 1024 (and in rare cases 2048) bytes.
- "Add-exists" command can be used if the .pdb file has Microsoft legacy format. ("Full" option for msbuild).
  
