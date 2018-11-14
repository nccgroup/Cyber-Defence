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
#include "pe_res_parser.h"

/*********************/
/** LOCAL FUNCTIONS **/
/*********************/

// basically memmem
BOOL _find_in_buffer(char* buffer, char* value, int value_len, int size)
{
	int i = 0;
	for (i = 0; i < size; i++)
	{
		if (memcmp(buffer + i, value, value_len) == 0) return TRUE;
	}

	return FALSE;
}

// given a buffer containing a pe file, return a pointer to the pe header
void *_find_pe_header(void *buffer)
{
	if (!is_pe_file((char *)buffer)) return NULL;
	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)buffer;
	return (void *)((LONG)buffer + dos_header->e_lfanew);
}

// given an rva and a pe_file in memory (buffer), find out which section it is in, and return 
// a pointer to its section table
void* _rva_to_sec(int rva, void* buffer)
{
	IMAGE_NT_HEADERS *pe_header = (IMAGE_NT_HEADERS *)_find_pe_header(buffer);
	IMAGE_SECTION_HEADER *sec_hdr = 0;
	int num_secs;

	if (!pe_header) return NULL;

	if (pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		// 32 bit pe
		sec_hdr = (IMAGE_SECTION_HEADER *)(pe_header + 1);
		num_secs = pe_header->FileHeader.NumberOfSections;
	}
	else
	{
		// 64 bit PE
		IMAGE_NT_HEADERS64 *pe64_header = (IMAGE_NT_HEADERS64 *)pe_header;
		sec_hdr = (IMAGE_SECTION_HEADER *)(pe64_header + 1);
		num_secs = pe64_header->FileHeader.NumberOfSections;
	}

	for (int i = 0; i < num_secs; i++)
	{
		if ((sec_hdr[i].VirtualAddress <= rva &&
			rva < (sec_hdr[i].VirtualAddress + sec_hdr[i].Misc.VirtualSize))) return sec_hdr + i;
	}

	return NULL;
}

// pass a buffer to a resource unicode string.
// returns pointer to ascii string (0 on error)
char *_get_resource_string(IMAGE_RESOURCE_DIR_STRING_U *str)
{
	char *ret = (char *)malloc(str->Length + 1);
	memset(ret, 0, str->Length + 1);

	if (WideCharToMultiByte(CP_ACP, NULL, (LPCWCH)&str->NameString, str->Length, ret, str->Length, NULL, NULL) == 0)
	{
		printf("Error in WideCharToMultiByteChar: 0x%x\n", GetLastError());
		return 0;
	}

	return ret;
}

/************************/
/** DECLARED FUNCTIONS **/
/************************/

// performs calculation to convert rva to file offset
unsigned int rva_to_off_ex(unsigned int rva, int sec_file_off, int sec_virt_off)
{
	return sec_file_off + (rva - sec_virt_off);
}

// converts rva to file offset. requires pe file passed as buffer
//void *rva_to_file_off(int rva, void *buffer)
void *rva_to_file_off(int rva, void *mapped_file)
{
	IMAGE_SECTION_HEADER *sec_hdr = (IMAGE_SECTION_HEADER*)_rva_to_sec(rva, mapped_file);
	if (!sec_hdr) return NULL;
	return (char*)mapped_file + rva_to_off_ex(rva, sec_hdr->PointerToRawData, sec_hdr->VirtualAddress);
}

// check if a pe file is contained at the beginning of a buffer
// if it is, the size is returned
BOOL is_pe_file(char *buffer)
{

	if (*((WORD *)buffer) == 0x5a4d) // is there an MZ header?
	{
		int i = 0;
		WORD e_lfanew = 0;
		WORD num_sections = 0;
		DWORD last_sec_offset = 0;
		char *last_sec = 0;
		char* pe_header = 0;
		char str_dos[] = { 'T','h','i','s',' ','p','r','o','g','r','a','m',' ','c','a','n','n','o','t',' ','b','e',' ','r','u','n',' ','i','n',' ','D','O','S',' ','m','o','d','e' };

		// i'm going to be really lazy and hardcode all the offsets to the info in the PE header
		e_lfanew = *((WORD *)(buffer + 0x3c));
		pe_header = buffer + e_lfanew;

		if (*((WORD *)(pe_header)) != 0x4550) return FALSE; // search for PE marker
		if (!_find_in_buffer(buffer + 0x40, str_dos, sizeof(str_dos), 0x40)) return FALSE; // find DOS stub string

		return TRUE;
	}

	return FALSE;
}

// given a buffer containing a pe file
// returns the start of the resource directory
IMAGE_RESOURCE_DIRECTORY *get_res_dir(void *buffer)
{
	IMAGE_DATA_DIRECTORY res_dir_data_dir;
	IMAGE_NT_HEADERS *tmp_hdr = (IMAGE_NT_HEADERS *)_find_pe_header(buffer);

	if (tmp_hdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		IMAGE_NT_HEADERS *pe_header = tmp_hdr;
		res_dir_data_dir = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	}
	else
	{
		IMAGE_NT_HEADERS64 *pe_header64 = (IMAGE_NT_HEADERS64 *)tmp_hdr;
		res_dir_data_dir = pe_header64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	}

	return (IMAGE_RESOURCE_DIRECTORY *)rva_to_file_off(res_dir_data_dir.VirtualAddress, buffer);
}

// search a IMAGE_RESOURCE_DIRECTORY for a specific named entry
IMAGE_RESOURCE_DIRECTORY_ENTRY *find_res_by_name(IMAGE_RESOURCE_DIRECTORY *res_dir, const char *name)
{
	IMAGE_RESOURCE_DIRECTORY_ENTRY *res_dir_entries = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(res_dir + 1);
	for (int i = 0; i < res_dir->NumberOfNamedEntries; i++) { // only enumerated named entries
		if (res_dir_entries[i].NameIsString)
		{
			if (strcmp(name, _get_resource_string((IMAGE_RESOURCE_DIR_STRING_U *)((char*)res_dir + res_dir_entries[i].NameOffset))) == 0)
				return &res_dir_entries[i];
		}
	}
}

//TODO: Implement find_res_by_id() function

// recursively traverse resource directory entry tree and run cb on each data entry
int enum_res_data_entries(void *mapped_file, IMAGE_RESOURCE_DIRECTORY *res_dir, IMAGE_RESOURCE_DIRECTORY_ENTRY *rde, res_data_callback cb)
{
	IMAGE_RESOURCE_DIRECTORY *new_res_dir = 0;
	IMAGE_RESOURCE_DIRECTORY_ENTRY *res_dir_entry = 0;
	IMAGE_RESOURCE_DATA_ENTRY *res_data = 0;
	int n_res_dir_entries = 0;

	void *resource_sec = get_res_dir(mapped_file);

	if (!resource_sec) return ERROR_INTERNAL_ERROR;

	if (rde->DataIsDirectory)
	{
		new_res_dir = (IMAGE_RESOURCE_DIRECTORY *)((char *)resource_sec + rde->OffsetToDirectory);
		n_res_dir_entries = new_res_dir->NumberOfNamedEntries + new_res_dir->NumberOfIdEntries;
		res_dir_entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(new_res_dir + 1);
		for (int i = 0; i < n_res_dir_entries; i++)
		{
			enum_res_data_entries(mapped_file, new_res_dir, &res_dir_entry[i], cb);
		}
	}
	else
	{
		res_data = (IMAGE_RESOURCE_DATA_ENTRY *)((char*)resource_sec + rde->OffsetToData);
		int ret = cb(rva_to_file_off(res_data->OffsetToData, mapped_file), res_data->Size);

	}
	return ERROR_SUCCESS;
}