#pragma once
#include <windows.h>

//
//Microsoft COFF Header
//Section Headers
//Raw Data :
//code
//data
//debug info
//relocations
#pragma pack (push, 1)
typedef struct {
	UINT16 Machine;
	UINT16 NumberOfSections;
	UINT32 TimeDateStamp;
	UINT32 PointerToSymbolTable;
	UINT32 NumberOfSymbols;
	UINT16 SizeOfOptionalHeader;
	UINT16 Characteristics;
} FileHeader;


/// <summary>
/// <Name> Just a test! </Name>
/// </summary>
typedef struct {
	char Name[8];					//8 bytes long null-terminated string
	UINT32 VirtualSize;				//total size of section when loaded into memory, 0 for COFF, might be different because of padding
	UINT32 VirtualAddress;			//address of the first byte of the section before relocations are applied, should be set to 0
	UINT32 SizeOfRawData;			//The size of the section for COFF files
	UINT32 PointerToRawData;		//Pointer to the beginning of the section for COFF
	UINT32 PointerToRelocations;	//File pointer to the beginning of relocation entries
	UINT32 PointerToLinenumbers;	//The file pointer to the beginning of line-number entries for the section. T
	UINT16 NumberOfRelocations;		//The number of relocation entries for the section. This is set to zero for executable images. 
	UINT16 NumberOfLinenumbers;		//The number of line-number entries for the section. This value should be zero for an image because COFF debugging information is deprecated. 
	UINT32 Characteristics;			//The flags that describe the characteristics of the section
} SectionHeader;


typedef struct {
	union {
		char Name[8];					//8 bytes, name of the symbol, represented as a union of 3 structs
		UINT32	value[2];				//TODO: what does this represent?!
	} first;
	UINT32 Value;					//meaning depends on the section number and storage class
	UINT16 SectionNumber;			//signed int, some values have predefined meaning
	UINT16 Type;					//
	UINT8 StorageClass;				//
	UINT8 NumberOfAuxSymbols;
} SymbolTableEntry;


typedef struct {
	UINT32 VirtualAddress;
	UINT32 SymbolTableIndex;
	UINT16 Type;
} RelocationTableEntry;

#pragma pack(pop)


#define IMAGE_REL_AMD64_ABSOLUTE    0x0000
#define IMAGE_REL_AMD64_ADDR64      0x0001
#define IMAGE_REL_AMD64_ADDR32      0x0002
#define IMAGE_REL_AMD64_ADDR32NB    0x0003
/* Most common from the looks of it, just 32-bit relative address from the byte following the relocation */
#define IMAGE_REL_AMD64_REL32       0x0004
/* Second most common, 32-bit address without an image base. Not sure what that means... */
#define IMAGE_REL_AMD64_REL32_1     0x0005
#define IMAGE_REL_AMD64_REL32_2     0x0006
#define IMAGE_REL_AMD64_REL32_3     0x0007
#define IMAGE_REL_AMD64_REL32_4     0x0008
#define IMAGE_REL_AMD64_REL32_5     0x0009
#define IMAGE_REL_AMD64_SECTION     0x000A
#define IMAGE_REL_AMD64_SECREL      0x000B
#define IMAGE_REL_AMD64_SECREL7     0x000C
#define IMAGE_REL_AMD64_TOKEN       0x000D
#define IMAGE_REL_AMD64_SREL32      0x000E
#define IMAGE_REL_AMD64_PAIR        0x000F
#define IMAGE_REL_AMD64_SSPAN32     0x0010


//
// Storage classes.
//
#define IMAGE_SYM_CLASS_END_OF_FUNCTION     (BYTE )-1
#define IMAGE_SYM_CLASS_NULL                0x0000
#define IMAGE_SYM_CLASS_AUTOMATIC           0x0001
#define IMAGE_SYM_CLASS_EXTERNAL            0x0002
#define IMAGE_SYM_CLASS_STATIC              0x0003
#define IMAGE_SYM_CLASS_REGISTER            0x0004
#define IMAGE_SYM_CLASS_EXTERNAL_DEF        0x0005
#define IMAGE_SYM_CLASS_LABEL               0x0006
#define IMAGE_SYM_CLASS_UNDEFINED_LABEL     0x0007
#define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    0x0008
#define IMAGE_SYM_CLASS_ARGUMENT            0x0009
#define IMAGE_SYM_CLASS_STRUCT_TAG          0x000A
#define IMAGE_SYM_CLASS_MEMBER_OF_UNION     0x000B
#define IMAGE_SYM_CLASS_UNION_TAG           0x000C
#define IMAGE_SYM_CLASS_TYPE_DEFINITION     0x000D
#define IMAGE_SYM_CLASS_UNDEFINED_STATIC    0x000E
#define IMAGE_SYM_CLASS_ENUM_TAG            0x000F
#define IMAGE_SYM_CLASS_MEMBER_OF_ENUM      0x0010
#define IMAGE_SYM_CLASS_REGISTER_PARAM      0x0011
#define IMAGE_SYM_CLASS_BIT_FIELD           0x0012
#define IMAGE_SYM_CLASS_FAR_EXTERNAL        0x0044 
#define IMAGE_SYM_CLASS_BLOCK               0x0064
#define IMAGE_SYM_CLASS_FUNCTION            0x0065
#define IMAGE_SYM_CLASS_END_OF_STRUCT       0x0066
#define IMAGE_SYM_CLASS_FILE                0x0067
#define IMAGE_SYM_CLASS_SECTION             0x0068
#define IMAGE_SYM_CLASS_WEAK_EXTERNAL       0x0069
#define IMAGE_SYM_CLASS_CLR_TOKEN           0x006B


//the $ is used to group sections in object files. It doesn't exist in image files
//the linker will remove $ and its suffix. sect1$c comes before sect1$c and after sect1$a