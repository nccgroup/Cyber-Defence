#pragma once
#include "windows.h"

typedef struct
{
	char *res_name;
	void *res_data;
	int res_data_size;
} PE_RESOURCE_ENTRY;

typedef struct
{
	PE_RESOURCE_ENTRY *res_entry;
	PE_RESOURCE_ENTRY *res_next;
} PE_RESOURCES;

int rva_to_off(int rva, void *mem_file);

int is_pe(void *mem_file);

int get_resource_table_off(void *mem_file);
