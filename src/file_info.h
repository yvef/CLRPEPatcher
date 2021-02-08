#pragma once
#include <windows.h>

class file_info
{
public:
	DWORD file_size;
	byte* buffer;
	LPCSTR file_name;
	
	file_info(DWORD fileSize, byte* buf, LPCSTR fileName) 
	: file_size(fileSize), buffer(buf), file_name(fileName)
	{ }
	~file_info() { delete[] buffer; }
};

