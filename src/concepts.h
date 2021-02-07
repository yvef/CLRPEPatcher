#pragma once

#include <windows.h>
#include <algorithm>

template<typename TNT_HEADERS> concept NtHeaderConcept = std::is_same<TNT_HEADERS, IMAGE_NT_HEADERS64>::value || std::is_same<TNT_HEADERS, IMAGE_NT_HEADERS32>::value;
template<typename TOPTIONAL_HEADERS> concept TOptionalHeaderConcept = std::is_same<TOPTIONAL_HEADERS, IMAGE_OPTIONAL_HEADER64>::value || std::is_same<TOPTIONAL_HEADERS, IMAGE_OPTIONAL_HEADER32>::value;