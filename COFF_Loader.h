#pragma once
#include "coff_definitions.h"

typedef struct {
	PBYTE pImageBase;
	SectionHeader* pTextSectionHeader;
	PBYTE pTextSectionRawData;
	SymbolTableEntry* symbol_table;
} coff_object;

#pragma region error_handling
#define RETURN_ERROR(x, ...) { printf(x, ##__VA_ARGS__); return FALSE; }
#define RETURN_NULL_ERROR(x, ...) { printf(x, ##__VA_ARGS__); return NULL;}
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#pragma endregion

/// <summary>
/// Reads a coff from a specified path, no parsing is done in this function
/// </summary>
/// <param name="filepath">path to coff object location</param>
/// <returns>a read/write pointer to in-memory coff object</returns>
PBYTE coff_read_file(PCHAR filepath);

/// <summary>
/// Unpack packed arguments for CS compatibility 
/// </summary>
/// <param name="arguments">hex string representing args</param>
/// <param name="outlen">on success, returns the total size of the args</param>
/// <returns>unpacked arguments</returns>
PUCHAR unpack_arguments(PCHAR arguments, size_t* outlen);

/// <summary>
/// Finds the address of an external symbol that was created using lib$func naming convention
/// </summary>
/// <param name="symbolstring">a string containing a lib$func to be resolved</param>
/// <returns>address to resolved external function</returns>
LPVOID process_external_symbol(PCHAR symbolstring);

/// <summary>
/// generic function to apply coff relocations, some reloc types aren't implemented yet
/// </summary>
/// <param name="P">The location to be patched</param>
/// <param name="S">The target section (section containing the actual data)</param>
/// <param name="Type">The type of the relocation</param>
/// <param name="SymOffset">The symbol offset in the symbol table</param>
VOID coff_apply_relocations(PUINT32 P, PBYTE S, UINT16 Type, UINT32 SymOffset);

/// <summary>
/// Calculates the size needed to store pointers for external functions right after the text section
/// </summary>
/// <param name="pImageBase">pointer to coff image base</param>
/// <returns>number of external symbols * sizeof(pointer) </returns>
UINT32 coff_get_ext_function_space(PBYTE pImageBase);

/// <summary>
/// 
/// </summary>
/// <param name="pImageBase">pointer to coff image base</param>
/// <returns>pointer to the symbol table</returns>
SymbolTableEntry* coff_get_symbol_table(PBYTE pImageBase);

/// <summary>
/// allocates memory using VirtualAlloc, can be easily modified to allocate using whatever method
/// </summary>
/// <param name="size"> nr of bytes to be allocated </param>
/// <param name="flags">dwFlags from VirtualAlloc </param>
/// <param name="protection">dwProtection from VirtualAlloc</param>
/// <returns>pointer to allocated memory</returns>
PBYTE mem_alloc(SIZE_T size, UINT32 flags, UINT32 protection);

/// <summary>
/// Returns a pointer to the text section header. The text section header is a special case because we have
/// to use strstr() instead of strcmp() since MSVC will generate ".text$mn" while gcc will generate ".text".
/// We cannot use strstr() with every section header because MSVC will generate .rdata while gcc will generate
/// ".rdata$zzz", so I decided to have a separate function for .text section header
/// </summary>
/// <param name="pImageBase">pointer to coff image base</param>
/// <returns>pointer to .text section header or null on failure</returns>
SectionHeader* coff_get_text_section_header(PBYTE pImageBase);

/// <summary>
/// Extracts the .text section into a PAGE_EXECUTE_READWRITE memory region 
/// </summary>
/// <param name="pImageBase">pointer to coff image base</param>
/// <param name="coff">a pointer to a coff_object struct to make my life easier</param>
/// <returns>true if creation of new memory region succeeded, the new .text section will be stored in the coff_object</returns>
BOOL coff_extract_text_section(PBYTE pImageBase, coff_object* coff);

/// <summary>
/// executes the coff entry function
/// </summary>
/// <param name="coff">pointer to coff_object struct</param>
/// <param name="entry_name">pointer to the name of entry function, usually "go" </param>
/// <param name="args">unpacked arguments</param>
/// <param name="argSize">the size of the arguments</param>
/// <returns>true if execution took place</returns>
BOOL coff_execute_entry(coff_object coff, PCHAR entry_name, PUCHAR args, UINT32 argSize);

/// <summary>
/// Returns the raw data of the target section, which is identified by its index. Useful in relocations
/// where we know the index of the target section and have to access its data.
/// </summary>
/// <param name="pImageBase">pointer to coff image base</param>
/// <param name="index">the index of the target section</param>
/// <returns>a pointer to the beginning of the target section</returns>
PBYTE coff_get_section_raw_data_by_index(PBYTE pImageBase, UINT32 index);

/// <summary>
/// Relocates the .text section of the coff file. The reason I chose to only relocate the .text sections
/// is because coff object execution only needs .text relocation.
/// </summary>
/// <param name="coff">coff_object struct that is pre-filled by calling coff_extract_text_section first</param>
/// <returns>true if relocations are performed without errors</returns>
BOOL coff_relocate_text_section(coff_object coff);