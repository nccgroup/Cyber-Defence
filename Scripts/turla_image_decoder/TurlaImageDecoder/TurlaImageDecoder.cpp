/*
TurlaImageDecoder

This tool is used extract the payload from the Turla PNG Dropper. 

The dropper contains a number of PNG files, where the colour value for each pixel 
is the value for a corresponding byte in the payload. This tool extracts the pixel 
values contained in each file, rebuilds the payload, and then writes it to a file.
*/

#include <stdio.h>
#include "windows.h"

#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")

#include <gdiplusinit.h>
#include <gdiplusmem.h>
#include "pe_res_parser.h"

// I'm going to be lazy and put these as globals ;)
void *g_decoded_buffer = NULL; // pointer to the decoded pe file from the dropper
int g_decoded_buffer_size = 0; // the size of the decoded pe file

// does what is says on the tin
void *load_file_into_mem(char *file_name)
{
	DWORD file_size = 0;
	DWORD out_size = 0;
	HANDLE file_handle = NULL;
	LPVOID file_buffer = NULL;

	file_handle = CreateFile(file_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (file_handle == INVALID_HANDLE_VALUE)
	{
		printf("Error 0x%0.8d when attempting to open \"%s\"\n", GetLastError(), file_name);
		return NULL;
	}

	file_size = GetFileSize(file_handle, NULL);
	file_buffer = VirtualAlloc(NULL, file_size, MEM_COMMIT, PAGE_READWRITE);

	if (ReadFile(file_handle, file_buffer, file_size, &out_size, NULL) == 0)
	{
		printf("Error reading file: %x\n", GetLastError());
		return NULL;
	}

	CloseHandle(file_handle);

	return file_buffer;
}

// writes a block of memory to a file
int write_mem_to_file(char *filename, void *buffer, int size)
{
	HANDLE file_handle = NULL;
	DWORD bytes_written = 0;

	file_handle = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	printf("Writing file: %s\n", filename);
	WriteFile(file_handle, buffer, size, &bytes_written, NULL);

	CloseHandle(file_handle);
	return ERROR_SUCCESS;
}

// this is called on each enumerated resource.
// it will "decode" each PNG file and tack it on to the g_decoded_buffer global
int resource_callback(void *data, int size)
{
	IStream *stream = NULL;

	HGLOBAL h_buf = GlobalAlloc(GMEM_MOVEABLE, size);
	void *p_buf = GlobalLock(h_buf);
	CopyMemory(p_buf, data, size);

	if (CreateStreamOnHGlobal(h_buf, FALSE, &stream) != S_OK)
	{
		return (GetLastError());
	}

	Gdiplus::Bitmap bm(stream, false);
	stream->Release();

	Gdiplus::BitmapData *bdata = new Gdiplus::BitmapData();
	Gdiplus::Status lb_status = bm.LockBits(new Gdiplus::Rect(0, 0, bm.GetWidth(), bm.GetHeight()), Gdiplus::ImageLockModeRead, PixelFormat16bppARGB1555, bdata);

	if (lb_status != Gdiplus::Ok)
	{
		printf("LockBits failed. Error: %d\n", lb_status);
		return ERROR_SUCCESS;
	}

	// pixel hex values
	UINT* pixels = (UINT*)bdata->Scan0;

	if (g_decoded_buffer == NULL)
	{
		// VirtualAlloc size, write locked bits
		g_decoded_buffer = VirtualAlloc(NULL, bdata->Height * bdata->Width * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		CopyMemory(g_decoded_buffer, pixels, bdata->Height * bdata->Width * 2);
		g_decoded_buffer_size = bdata->Height * bdata->Width * 2;
	}
	else
	{
		// create new allocation (size of old alloc + new size)
		void *new_mem = VirtualAlloc(NULL, 
			g_decoded_buffer_size + (bdata->Height * bdata->Width * 2), 
			MEM_COMMIT | MEM_RESERVE, 
			PAGE_READWRITE);

		// copy old allocation
		CopyMemory(new_mem, g_decoded_buffer, g_decoded_buffer_size);

		// free old allocation
		VirtualFree(g_decoded_buffer, g_decoded_buffer_size, MEM_RELEASE);
		g_decoded_buffer = new_mem;

		// write new bits
		CopyMemory((char*)g_decoded_buffer + g_decoded_buffer_size, pixels, bdata->Height * bdata->Width * 2);
		g_decoded_buffer_size += bdata->Height * bdata->Width * 2;
	}

	GlobalFree(h_buf);

	return ERROR_SUCCESS;
}

// MAIN
int main(int argc, char *argv[])
{
	ULONG_PTR gdi_token = NULL;
	Gdiplus::GdiplusStartupInput gsi = { 0 };
	void *file_buffer = 0;
	IMAGE_RESOURCE_DIRECTORY *res_dir = 0;

	if (argc != 3)
	{
		printf("Usage: TurlaImageDecoder.exe <input file> <output_file>\n");
		return NULL;
	}

	Gdiplus::Status ret = Gdiplus::GdiplusStartup(&gdi_token, &gsi, NULL);

	file_buffer = load_file_into_mem(argv[1]);

	if (!file_buffer)
		return NULL;

	if (!is_pe_file((char *)file_buffer))
	{
		printf("File is not pe file\n");
		return NULL;
	}

	// get a pointer to the resource direcrory
	res_dir = get_res_dir(file_buffer);
	// enum each PNG resource
	enum_res_data_entries(file_buffer, res_dir, find_res_by_name(res_dir, "PNG"), resource_callback);

	// Write out the new file
	write_mem_to_file(argv[2], g_decoded_buffer, g_decoded_buffer_size);

	Gdiplus::GdiplusShutdown(gdi_token);
	VirtualFree(g_decoded_buffer);

	return ERROR_SUCCESS;
}