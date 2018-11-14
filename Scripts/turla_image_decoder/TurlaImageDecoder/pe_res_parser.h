/**
The functions in the source file are used to access the resources of PE files.

The PE Resource Directory has the following format:

.rsrc section
IMAGE_RESOURCE_DIRECTORY
IMAGE_RESOURCE_DIRECTORY_ENTRY[] -> IMAGE_RESOURCE_DIRECTORY
IMAGE_RESOURCE_DIRECTORY_ENTRY[]
or
-> IMAGE_RESOURCE_DATA_ENTRY

The resource directory entry in the PE header will point to the .rsrc section. The .rsrc section starts with a
IMAGE_RESOURCE_DIRECTORY structure, directly followed by an array of IMAGE_RESOURCE_DIRECTORY_ENTRY structure.
The IMAGE_RESOURCE_DIRECTORY_ENTRY can point to either another IMAGE_RESOURCE_DIRECTORY structure, or a
IMAGE_RESOURCE_DATA_ENTRY structure (which points to the actual data).

Offsets in the IMAGE_RESOURCE_DIRECTORY_ENTRY structure are relative to the start of the .rsrc section.

Refs:
- https://msdn.microsoft.com/en-us/library/ms809762.aspx
- https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#resource-directory-table
- https://www.curlybrace.com/archive/PE%20File%20Structure.pdf

Ben Humphrey
2018-10-09
**/
#pragma once
#include <stdio.h>
#include "windows.h"

// callback prototype - used in enum_res_data_entries function
typedef int(*res_data_callback)(void *, int);

unsigned int rva_to_off_ex(unsigned int rva, int sec_file_off, int sec_virt_off);
void* rva_to_file_off(int rva, void *mapped_file);
BOOL is_pe_file(char *buffer);
IMAGE_RESOURCE_DIRECTORY *get_res_dir(void *buffer);
IMAGE_RESOURCE_DIRECTORY_ENTRY *find_res_by_name(IMAGE_RESOURCE_DIRECTORY *res_dir, const char *name);
int enum_res_data_entries(void *mapped_file, IMAGE_RESOURCE_DIRECTORY *res_dir, IMAGE_RESOURCE_DIRECTORY_ENTRY *rde, res_data_callback cb);
