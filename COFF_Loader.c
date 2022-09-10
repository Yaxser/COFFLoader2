#include <stdlib.h>
#include <stdio.h>
#include "coff_definitions.h"
#include "beacon_compatibility.h"
#include "COFF_Loader.h"

#if defined(_WIN64)
#define PREPENDSYMBOLVALUE "__imp_"
#else
#define PREPENDSYMBOLVALUE "__imp__"
#endif

#pragma region general functions
PBYTE mem_alloc(SIZE_T size, UINT32 flags, UINT32 protection) {
	PBYTE ret;
	ret = (PBYTE)VirtualAlloc(NULL, size, flags, protection);
	return ret;
}
PBYTE coff_read_file(PCHAR filepath) {
	HANDLE hFile = NULL;
	UINT32 FileSize;
	PBYTE buffer = NULL;

	hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (!hFile)
		return NULL;

	FileSize = GetFileSize(hFile, NULL);
	if (FileSize == INVALID_FILE_SIZE)
		goto cleanup;

	buffer = mem_alloc(FileSize, MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
	if (!buffer)
		goto cleanup;

	if (!ReadFile(hFile, buffer, FileSize, NULL, NULL))
		DEBUG_PRINT("Couldn't read input file! %d\n", GetLastError());

	if (VirtualProtect(buffer, FileSize, PAGE_READONLY, NULL))
		DEBUG_PRINT("Couldn't change protection to PAGE_READONLY: %d\n", GetLastError);

cleanup:
	CloseHandle(hFile);
	return buffer;
}
PUCHAR unpack_arguments(PCHAR arguments, size_t* outlen) {
	PUCHAR retval = NULL;
	CHAR byteval[2] = { 0 };

	if (!arguments)
		RETURN_NULL_ERROR("No arguments to parse");

	size_t value_len = strlen((LPCSTR)arguments);

	if (value_len % 2 != 0)
		RETURN_NULL_ERROR("The hexlified string isn't valid\n");


	retval = mem_alloc(value_len + 1, MEM_COMMIT, PAGE_READWRITE);
	if (!retval)
		RETURN_NULL_ERROR("couldn't allocate memory for args");

	/* args are in hex, unpackign */
	for (size_t i = 0; i < value_len; i += 2) {
		memcpy(byteval, arguments + i, 2);
		CHAR character = strtol(byteval, NULL, 16);
		retval[i / 2] = character;
	}

	*outlen = value_len / 2;
	return retval;
}
LPVOID process_external_symbol(PCHAR symbolstring) {
	LPVOID functionaddress = NULL;
	CHAR localcopy[1024] = { 0 };
	PCHAR locallib = NULL;
	PCHAR localfunc = NULL;
	HMODULE llHandle = NULL;
	PCHAR therest = NULL;


	CHAR prefix[] = PREPENDSYMBOLVALUE;
	CHAR prefix_beacon[] = PREPENDSYMBOLVALUE"Beacon";
	CHAR prefix_towidechar[] = PREPENDSYMBOLVALUE"toWideChar";
	size_t prefix_len = strlen(prefix);

	/* the symbol name doesn't conform to our naming convention */
	if (strncmp(symbolstring, prefix, strlen(prefix)))
		RETURN_NULL_ERROR("not conforming to our naming convention\n");


	/* check if it's an internal beacon function */
	if (strncmp(symbolstring, prefix_beacon, strlen(prefix_beacon)) == 0
		|| strncmp(symbolstring, prefix_towidechar, strlen(prefix_towidechar)) == 0) {

		localfunc = symbolstring + prefix_len;

		for (int i = 0; i < 25; i++) {
			if (InternalFunctions[i][0] != NULL) {
				if (strcmp(localfunc, (PCHAR)(InternalFunctions[i][0])) == 0) {
					functionaddress = (PCHAR)InternalFunctions[i][1];
					return functionaddress;
				}
			}
		}
	}

	/* if we are here, it is an external function */
	strcpy_s(localcopy, _countof(localcopy), symbolstring);
	locallib = strtok_s(localcopy + prefix_len, "$@", &therest);
	localfunc = strtok_s(therest, "$@", &therest);
	if (!localfunc || !locallib)
		RETURN_NULL_ERROR("couldn't extract external function name, %s\n", symbolstring)

		llHandle = LoadLibraryA(locallib);
	if (llHandle) {
		functionaddress = GetProcAddress(llHandle, localfunc);
		if (!functionaddress)
			RETURN_NULL_ERROR("No func %s in %s\n", localfunc, locallib);
		//	FreeLibrary(llHandle); // we can't free the library until execution is done. TODO: keep a list of loaded dll per bof to unload after execution
	}
	else {
		RETURN_NULL_ERROR("couldn't load library %s\n", locallib)
	}
	return functionaddress;
}
#pragma endregion

#pragma region relocation functions
UINT32 read32le(const PUINT8 p)
{
    /* The one true way, see
     * https://commandcenter.blogspot.com/2012/04/byte-order-fallacy.html */
    return ((UINT32)p[0] << 0) |
        ((UINT32)p[1] << 8) |
        ((UINT32)p[2] << 16) |
        ((UINT32)p[3] << 24);
}
VOID write32le(PUINT8 dst, UINT32 x)
{
    dst[0] = (UINT8)(x >> 0);
    dst[1] = (UINT8)(x >> 8);
    dst[2] = (UINT8)(x >> 16);
    dst[3] = (UINT8)(x >> 24);
}
VOID add32(PUINT8 P, UINT32 V) { write32le(P, read32le(P) + V); }
VOID coff_apply_relocations(PUINT32 P, PBYTE S, UINT16 Type, UINT32 SymOffset) {

	switch (Type)
	{
	case IMAGE_REL_AMD64_REL32: add32(P, S + SymOffset - (PBYTE)P - 4); break;
	case IMAGE_REL_AMD64_ADDR32NB: add32(P, S - (PBYTE)P - 4); break;
	case IMAGE_REL_AMD64_ADDR64:*P = (*P + S);  break;
//	working alternatives
//	case IMAGE_REL_AMD64_REL32: *P += (S + SymOffset - P - 4); break;
//	case IMAGE_REL_AMD64_ADDR32NB: *P = (S - P - 4); break;
//	case IMAGE_REL_AMD64_ADDR64: *P = (*P + S);  break;
	case IMAGE_REL_I386_DIR32:*P = (*P + S); break;
	default:
		DEBUG_PRINT("NO CODE TO RELOCATE TYPE: %d\n", Type);
		break;
	}

}
#pragma endregion

#pragma region coff helper functions
SymbolTableEntry* coff_get_symbol_table(PBYTE pImageBase) {
	if (!pImageBase)
		return NULL;

	return (SymbolTableEntry*)(pImageBase + ((FileHeader*)pImageBase)->PointerToSymbolTable);
}
UINT32 coff_get_ext_function_space(PBYTE pImageBase) {
	UINT32 ret = 0;
	SymbolTableEntry* pSymbolTable;
	RelocationTableEntry* reloc;
	SectionHeader* pTextSectionHeader;
	if (!pImageBase)
		return 0; //TODO: This is not optimal because it may lead to crashes if external functions exist but NULL is passed

	pTextSectionHeader = coff_get_text_section_header(pImageBase);
	pSymbolTable = coff_get_symbol_table(pImageBase);
	reloc = (RelocationTableEntry*)(pImageBase + pTextSectionHeader->PointerToRelocations);
	if (!pTextSectionHeader || !pSymbolTable)
		RETURN_ERROR("couldn't get symbol table or text section");

	for (int i = 0; i < pTextSectionHeader->NumberOfRelocations; i++)
	{
		SymbolTableEntry* sym = pSymbolTable + reloc->SymbolTableIndex;
		/* The External storage class may include functions in the .text section as well (internal functions).
		   To ensure that only external functions are included, a check for the section number is added.
		   A section number of 0 == UNDEF section, which is the case for external functions.
		*/
		if (sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && sym->SectionNumber == 0)
		{
			ret++;
		}
		reloc++;
	}
	return ret * sizeof(PBYTE);
}
BOOL coff_execute_entry(coff_object coff, PCHAR func, PUCHAR args, UINT32 argSize) {
	VOID(*foo)(PCHAR in, UINT32 datalen) = NULL;

	if (!func || !coff.pImageBase)
		RETURN_ERROR("no entry provided");

	for (UINT32 counter = 0; counter < ((FileHeader*)coff.pImageBase)->NumberOfSymbols; counter++)
	{
		if (strcmp(coff.symbol_table[counter].first.Name, func) == 0) {
			//	foo = (PCHAR)coff.pTextSectionRawData; to my surprise, this won't work! It appears that go isn't always at the beginning of the .text section!
			foo = (PCHAR)(coff.pTextSectionRawData + coff.symbol_table[counter].Value);
			DEBUG_PRINT("Trying to run: %p\n", foo);
		}
	}

	if (!foo)
		RETURN_ERROR("couldn't find entry point");

	foo(args, argSize);
	return TRUE;
}
SectionHeader* coff_get_text_section_header(PBYTE pImageBase) {

	FileHeader* pFileHeader;

	if (!pImageBase)
		return NULL;

	pFileHeader = (FileHeader*)pImageBase;

	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		SectionHeader* pSectionHeader = (SectionHeader*)(pImageBase + sizeof(FileHeader) + (sizeof(SectionHeader) * i));
		if (strstr(pSectionHeader->Name, ".text"))
			return pSectionHeader;
	}

	return NULL;
}
BOOL coff_extract_text_section(PBYTE pImageBase, coff_object* coff) {

	UINT32 sizeOfData;
	SectionHeader* pTextSectionHeader;

	if (!coff || !pImageBase)
		RETURN_ERROR("invalid args");

	coff->pImageBase = pImageBase;
	coff->symbol_table = coff_get_symbol_table(pImageBase);

	pTextSectionHeader = coff_get_text_section_header(pImageBase);
	if (!pTextSectionHeader)
		RETURN_ERROR("pTextHeader is null");

	coff->pTextSectionHeader = pTextSectionHeader;
	sizeOfData = pTextSectionHeader->SizeOfRawData + coff_get_ext_function_space(pImageBase);
	coff->pTextSectionRawData = mem_alloc(sizeOfData, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
	if (!coff->pTextSectionRawData)
		RETURN_ERROR("couldn't allocate new .text section");

	memcpy(coff->pTextSectionRawData,
		pImageBase + pTextSectionHeader->PointerToRawData,
		pTextSectionHeader->SizeOfRawData);

	return TRUE;
}
PBYTE coff_get_section_raw_data_by_index(PBYTE pImageBase, UINT32 index) {
	SectionHeader* pSectionHeader;

	if (!pImageBase)
		return NULL;

	pSectionHeader = (SectionHeader*)(pImageBase + sizeof(FileHeader) + (sizeof(SectionHeader) * index));

	return pImageBase + pSectionHeader->PointerToRawData;
}
BOOL coff_relocate_text_section(coff_object coff) {

	UINT32 functionMappingCount = 0;
	PBYTE current_section_ptr;
	RelocationTableEntry* Reloc;


	current_section_ptr = coff.pTextSectionRawData;
	if (!current_section_ptr)
		RETURN_ERROR(".text is null");

	Reloc = (RelocationTableEntry*)(coff.pImageBase + coff.pTextSectionHeader->PointerToRelocations);

	for (int ireloc = 0; ireloc < coff.pTextSectionHeader->NumberOfRelocations; ireloc++)
	{
		UINT16 TargetSectionIndex;
		SymbolTableEntry* sym;
		BOOL isExternal, isInternal;
		PUINT32 P; /* Location to patch */

		TargetSectionIndex = coff.symbol_table[Reloc->SymbolTableIndex].SectionNumber - 1;
		sym = coff.symbol_table + Reloc->SymbolTableIndex;
		isExternal = (sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && sym->SectionNumber == 0);
		isInternal = (sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && sym->SectionNumber != 0);


		P = (PUINT32)(
			current_section_ptr
			+ Reloc->VirtualAddress
			- coff.pTextSectionHeader->VirtualAddress);

		if (isExternal)
		{
#if defined(_WIN64)
			PUINT64 pFunction;
#else
			PUINT32 pFunction;
#endif
			UINT32 StringTableOffset = sym->first.value[1];
			PCHAR function_full_name = ((PCHAR)(coff.symbol_table + ((FileHeader*)coff.pImageBase)->NumberOfSymbols) + StringTableOffset);
#if defined(_WIN64)
			PUINT64 func_addr2 = (PUINT64)(current_section_ptr + coff.pTextSectionHeader->SizeOfRawData);
#else
			PUINT32 func_addr2 = (PUINT32)(current_section_ptr + coff.pTextSectionHeader->SizeOfRawData);
#endif

			pFunction = process_external_symbol(function_full_name);

			if (pFunction)
			{
				/* copy the address of the ext. function into the region right after the .text section */
#if defined(_WIN64)
				*(func_addr2 + (functionMappingCount)) = (UINT64)pFunction;
#else
				*(func_addr2 + (functionMappingCount)) = (UINT32)pFunction;
#endif

#if defined(_WIN64)
				/* calculate the difference between P and the copied ext. func addr */
				UINT32 v = (UINT32)((UINT32)(func_addr2 + (functionMappingCount)) - (UINT32)(P)-4);

				/* copy the difference to P */
				*(PINT32)P = v;
#else
				*(PINT32)P = func_addr2;
#endif
				functionMappingCount += 1;
			}
			else {
				RETURN_ERROR("couldn't resolve function");
			}
		}
		else {
			/* not an external function, could be either internal or data
			if it's an internal function, then the target section should be the text
			section. Otherwise, the target section should be whatever section the data
			is in.

			The reason that .text section is having a special treatment here is because
			we re-allocated it to another region in memory to make it executable. If we
			use coff_get_section_by_index for the text section, we will get a pointer to
			the original text_section, which is not in an executable memory region.

			This can be simplified by allocating executable memory for the entire coff.  I wasn't sure about the
			detection complications in an executable memory for the entire coff so decided to stick to only the
			.text section. Maybe in future versions I'll simplifythis by having the entire coff in an
			executable region.

		*/
			PBYTE S = coff_get_section_raw_data_by_index(coff.pImageBase, TargetSectionIndex);
			if (!S)
				RETURN_ERROR("target section is null");

			/* VS compiler won't patch relative addresses of internal functions for us so we have to do it ourselves */
			if (isInternal)
				S = coff.pTextSectionRawData;

			coff_apply_relocations(P, S, Reloc->Type, sym->Value);
		}
		Reloc++;
	}
	return TRUE;
}
#pragma endregion

void main(int argc, char* argv[]) {

	PBYTE coff_data = NULL;
	coff_object coff;
	PCHAR arguments = NULL;
	size_t arg_size = 0;
#if  defined(_WIN64)
	char* entryfuncname = "go";
#else
	char* entryfuncname = "_go";
#endif

	if (argc < 2) {
		printf("not enough args...\nUsage: %s [path_to_obj_file] <opt: arguments>", argv[0]);
		return;
	}

	coff_data = coff_read_file(argv[1]);
	if (!coff_data)
		return;
	
	if(argv[2])
		arguments = unpack_arguments(argv[2], &arg_size);

	if (!coff_extract_text_section(coff_data, &coff))
		goto cleanup;


	if (!coff_relocate_text_section(coff))
		goto cleanup;


	if (!coff_execute_entry(coff, entryfuncname, arguments, (UINT32)arg_size))
		goto cleanup;

	PCHAR outdata = BeaconGetOutputData(NULL);
	if (outdata != NULL) {
		printf("\nOutdata Below:\n\n%s\n", outdata);
	}

cleanup:
	if(coff_data)
	VirtualFree(coff_data, 0, MEM_RELEASE);
	if (coff.pTextSectionRawData)
		VirtualFree(coff.pTextSectionRawData, 0, MEM_RELEASE);
	if (arguments)
		VirtualFree(arguments, 0, MEM_RELEASE);
}



