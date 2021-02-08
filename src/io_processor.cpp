#include "io_processor.h"
#include <stdexcept>

file_info* io_processor::read_file(LPCSTR file_name)
{
	HANDLE hFile = CreateFileA(file_name, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(!_validator.check(hFile != INVALID_HANDLE_VALUE))
		throw std::runtime_error("Could not to read file: " + std::string(file_name) + "Seems the file descriptor is busy or file is not exists");
	
	DWORD file_size = GetFileSize(hFile, NULL);
	byte* buffer = new byte[file_size];
	DWORD bytes_read = NULL;
	bool successReadFile = ReadFile(hFile, buffer, file_size, &bytes_read, NULL);
	if(!_validator.check(successReadFile))
		throw std::runtime_error("Could not to read file: " + std::string(file_name));
	
	if(!CloseHandle(hFile))
		throw std::runtime_error("Could not close file descriptor");
	return new file_info(file_size, buffer, file_name);
}

bool io_processor::flush_to_file(const file_info* file_info)
{
	HANDLE outputFile = CreateFileA(file_info->file_name, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(outputFile == INVALID_HANDLE_VALUE)
		return false;
	
	DWORD byteWritten = NULL;
	return WriteFile(outputFile, static_cast<LPCVOID>(file_info->buffer), file_info->file_size, &byteWritten, NULL);
}