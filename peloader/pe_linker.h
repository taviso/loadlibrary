#ifndef __PE_LINKER_H
#define __PE_LINKER_H

/*
 * This file is an excerpt of winnt.h from WINE, which bears the
 * following copyright:
 *
 * Win32 definitions for Windows NT
 *
 * Copyright 1996 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

/*
 * File formats definitions
 */
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;      /* 00: MZ Header signature */
    WORD  e_cblp;       /* 02: Bytes on last page of file */
    WORD  e_cp;         /* 04: Pages in file */
    WORD  e_crlc;       /* 06: Relocations */
    WORD  e_cparhdr;    /* 08: Size of header in paragraphs */
    WORD  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
    WORD  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
    WORD  e_ss;         /* 0e: Initial (relative) SS value */
    WORD  e_sp;         /* 10: Initial SP value */
    WORD  e_csum;       /* 12: Checksum */
    WORD  e_ip;         /* 14: Initial IP value */
    WORD  e_cs;         /* 16: Initial (relative) CS value */
    WORD  e_lfarlc;     /* 18: File address of relocation table */
    WORD  e_ovno;       /* 1a: Overlay number */
    WORD  e_res[4];     /* 1c: Reserved words */
    WORD  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
    WORD  e_oeminfo;    /* 26: OEM information; e_oemid specific */
    WORD  e_res2[10];   /* 28: Reserved words */
    DWORD e_lfanew;     /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct pe_image;

#define IMAGE_DOS_SIGNATURE    0x5A4D     /* MZ   */
#define IMAGE_OS2_SIGNATURE    0x454E     /* NE   */
#define IMAGE_OS2_SIGNATURE_LE 0x454C     /* LE   */
#define IMAGE_OS2_SIGNATURE_LX 0x584C     /* LX */
#define IMAGE_VXD_SIGNATURE    0x454C     /* LE   */
#define IMAGE_NT_SIGNATURE     0x00004550 /* PE00 */

/*
 * This is the Windows executable (NE) header.
 * the name IMAGE_OS2_HEADER is misleading, but in the SDK this way.
 */
typedef struct
{
    WORD  ne_magic;             /* 00 NE signature 'NE' */
    BYTE  ne_ver;               /* 02 Linker version number */
    BYTE  ne_rev;               /* 03 Linker revision number */
    WORD  ne_enttab;            /* 04 Offset to entry table relative to NE */
    WORD  ne_cbenttab;          /* 06 Length of entry table in bytes */
    LONG  ne_crc;               /* 08 Checksum */
    WORD  ne_flags;             /* 0c Flags about segments in this file */
    WORD  ne_autodata;          /* 0e Automatic data segment number */
    WORD  ne_heap;              /* 10 Initial size of local heap */
    WORD  ne_stack;             /* 12 Initial size of stack */
    DWORD ne_csip;              /* 14 Initial CS:IP */
    DWORD ne_sssp;              /* 18 Initial SS:SP */
    WORD  ne_cseg;              /* 1c # of entries in segment table */
    WORD  ne_cmod;              /* 1e # of entries in module reference tab. */
    WORD  ne_cbnrestab;         /* 20 Length of nonresident-name table */
    WORD  ne_segtab;            /* 22 Offset to segment table */
    WORD  ne_rsrctab;           /* 24 Offset to resource table */
    WORD  ne_restab;            /* 26 Offset to resident-name table */
    WORD  ne_modtab;            /* 28 Offset to module reference table */
    WORD  ne_imptab;            /* 2a Offset to imported name table */
    DWORD ne_nrestab;           /* 2c Offset to nonresident-name table */
    WORD  ne_cmovent;           /* 30 # of movable entry points */
    WORD  ne_align;             /* 32 Logical sector alignment shift count */
    WORD  ne_cres;              /* 34 # of resource segments */
    BYTE  ne_exetyp;            /* 36 Flags indicating target OS */
    BYTE  ne_flagsothers;       /* 37 Additional information flags */
    WORD  ne_pretthunks;        /* 38 Offset to return thunks */
    WORD  ne_psegrefbytes;      /* 3a Offset to segment ref. bytes */
    WORD  ne_swaparea;          /* 3c Reserved by Microsoft */
    WORD  ne_expver;            /* 3e Expected Windows version number */
} IMAGE_OS2_HEADER, *PIMAGE_OS2_HEADER;

typedef struct _IMAGE_VXD_HEADER {
  WORD  e32_magic;
  BYTE  e32_border;
  BYTE  e32_worder;
  DWORD e32_level;
  WORD  e32_cpu;
  WORD  e32_os;
  DWORD e32_ver;
  DWORD e32_mflags;
  DWORD e32_mpages;
  DWORD e32_startobj;
  DWORD e32_eip;
  DWORD e32_stackobj;
  DWORD e32_esp;
  DWORD e32_pagesize;
  DWORD e32_lastpagesize;
  DWORD e32_fixupsize;
  DWORD e32_fixupsum;
  DWORD e32_ldrsize;
  DWORD e32_ldrsum;
  DWORD e32_objtab;
  DWORD e32_objcnt;
  DWORD e32_objmap;
  DWORD e32_itermap;
  DWORD e32_rsrctab;
  DWORD e32_rsrccnt;
  DWORD e32_restab;
  DWORD e32_enttab;
  DWORD e32_dirtab;
  DWORD e32_dircnt;
  DWORD e32_fpagetab;
  DWORD e32_frectab;
  DWORD e32_impmod;
  DWORD e32_impmodcnt;
  DWORD e32_impproc;
  DWORD e32_pagesum;
  DWORD e32_datapage;
  DWORD e32_preload;
  DWORD e32_nrestab;
  DWORD e32_cbnrestab;
  DWORD e32_nressum;
  DWORD e32_autodata;
  DWORD e32_debuginfo;
  DWORD e32_debuglen;
  DWORD e32_instpreload;
  DWORD e32_instdemand;
  DWORD e32_heapsize;
  BYTE  e32_res3[12];
  DWORD e32_winresoff;
  DWORD e32_winreslen;
  WORD  e32_devid;
  WORD  e32_ddkver;
} IMAGE_VXD_HEADER, *PIMAGE_VXD_HEADER;

/* These defines describe the meanings of the bits in the
   Characteristics field */

#define IMAGE_FILE_RELOCS_STRIPPED      0x0001 /* No relocation info */
#define IMAGE_FILE_EXECUTABLE_IMAGE     0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED   0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED  0x0008
#define IMAGE_FILE_AGGRESIVE_WS_TRIM    0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE  0x0020
#define IMAGE_FILE_16BIT_MACHINE        0x0040
#define IMAGE_FILE_BYTES_REVERSED_LO    0x0080
#define IMAGE_FILE_32BIT_MACHINE        0x0100
#define IMAGE_FILE_DEBUG_STRIPPED       0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP      0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP    0x0800
#define IMAGE_FILE_SYSTEM               0x1000
#define IMAGE_FILE_DLL                  0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY       0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI    0x8000

/* These are the settings of the Machine field. */
#define IMAGE_FILE_MACHINE_UNKNOWN      0
#define IMAGE_FILE_MACHINE_I860         0x014d
#define IMAGE_FILE_MACHINE_I386         0x014c
#define IMAGE_FILE_MACHINE_R3000        0x0162
#define IMAGE_FILE_MACHINE_R4000        0x0166
#define IMAGE_FILE_MACHINE_R10000       0x0168
#define IMAGE_FILE_MACHINE_WCEMIPSV2    0x0169
#define IMAGE_FILE_MACHINE_ALPHA        0x0184
#define IMAGE_FILE_MACHINE_SH3          0x01a2
#define IMAGE_FILE_MACHINE_SH3DSP       0x01a3
#define IMAGE_FILE_MACHINE_SH3E         0x01a4
#define IMAGE_FILE_MACHINE_SH4          0x01a6
#define IMAGE_FILE_MACHINE_SH5          0x01a8
#define IMAGE_FILE_MACHINE_ARM          0x01c0
#define IMAGE_FILE_MACHINE_THUMB        0x01c2
#define IMAGE_FILE_MACHINE_AM33         0x01d3
#define IMAGE_FILE_MACHINE_POWERPC      0x01f0
#define IMAGE_FILE_MACHINE_POWERPCFP    0x01f1
#define IMAGE_FILE_MACHINE_IA64         0x0200
#define IMAGE_FILE_MACHINE_MIPS16       0x0266
#define IMAGE_FILE_MACHINE_ALPHA64      0x0284
#define IMAGE_FILE_MACHINE_MIPSFPU      0x0366
#define IMAGE_FILE_MACHINE_MIPSFPU16    0x0466
#define IMAGE_FILE_MACHINE_AXP64        IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE      0x0520
#define IMAGE_FILE_MACHINE_CEF          0x0cef
#define IMAGE_FILE_MACHINE_EBC          0x0ebc
#define IMAGE_FILE_MACHINE_AMD64        0x8664
#define IMAGE_FILE_MACHINE_M32R         0x9041
#define IMAGE_FILE_MACHINE_CEE          0xc0ee

#define IMAGE_SIZEOF_FILE_HEADER                20
#define IMAGE_SIZEOF_ROM_OPTIONAL_HEADER        56
#define IMAGE_SIZEOF_STD_OPTIONAL_HEADER        28
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER32       224
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER64       240
#define IMAGE_SIZEOF_SHORT_NAME                 8
#define IMAGE_SIZEOF_SECTION_HEADER             40
#define IMAGE_SIZEOF_SYMBOL                     18
#define IMAGE_SIZEOF_AUX_SYMBOL                 18
#define IMAGE_SIZEOF_RELOCATION                 10
#define IMAGE_SIZEOF_BASE_RELOCATION            8
#define IMAGE_SIZEOF_LINENUMBER                 6
#define IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR         60

/* Possible Magic values */
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC        0x010b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC        0x020b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x0107

#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER IMAGE_SIZEOF_NT_OPTIONAL_HEADER32
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR32_MAGIC

/* These are indexes into the DataDirectory array */
#define IMAGE_FILE_EXPORT_DIRECTORY             0
#define IMAGE_FILE_IMPORT_DIRECTORY             1
#define IMAGE_FILE_RESOURCE_DIRECTORY           2
#define IMAGE_FILE_EXCEPTION_DIRECTORY          3
#define IMAGE_FILE_SECURITY_DIRECTORY           4
#define IMAGE_FILE_BASE_RELOCATION_TABLE        5
#define IMAGE_FILE_DEBUG_DIRECTORY              6
#define IMAGE_FILE_DESCRIPTION_STRING           7
#define IMAGE_FILE_MACHINE_VALUE                8  /* Mips */
#define IMAGE_FILE_THREAD_LOCAL_STORAGE         9
#define IMAGE_FILE_CALLBACK_DIRECTORY           10

/* Directory Entries, indices into the DataDirectory array */

#define IMAGE_DIRECTORY_ENTRY_EXPORT            0
#define IMAGE_DIRECTORY_ENTRY_IMPORT            1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE          2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION         3
#define IMAGE_DIRECTORY_ENTRY_SECURITY          4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC         5
#define IMAGE_DIRECTORY_ENTRY_DEBUG             6
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT         7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR         8  /* (MIPS GP) */
#define IMAGE_DIRECTORY_ENTRY_TLS               9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      11
#define IMAGE_DIRECTORY_ENTRY_IAT               12  /* Import Address Table */
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    14

/* Subsystem Values */

#define IMAGE_SUBSYSTEM_UNKNOWN                 0
#define IMAGE_SUBSYSTEM_NATIVE                  1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI             2  /* Windows GUI subsystem */
#define IMAGE_SUBSYSTEM_WINDOWS_CUI             3  /* Windows character subsystem */
#define IMAGE_SUBSYSTEM_OS2_CUI                 5
#define IMAGE_SUBSYSTEM_POSIX_CUI               7
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS          8  /* native Win9x driver */
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI          9  /* Windows CE subsystem */
#define IMAGE_SUBSYSTEM_EFI_APPLICATION         10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER      12
#define IMAGE_SUBSYSTEM_EFI_ROM                 13
#define IMAGE_SUBSYSTEM_XBOX                    14

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER32 {

  /* Standard fields */

  WORD  Magic;
  BYTE  MajorLinkerVersion;
  BYTE  MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  DWORD BaseOfData;

  /* NT additional fields */
  DWORD ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD  MajorOperatingSystemVersion;
  WORD  MinorOperatingSystemVersion;
  WORD  MajorImageVersion;
  WORD  MinorImageVersion;
  WORD  MajorSubsystemVersion;
  WORD  MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD  Subsystem;
  WORD  DllCharacteristics;
  DWORD SizeOfStackReserve;
  DWORD SizeOfStackCommit;
  DWORD SizeOfHeapReserve;
  DWORD SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {

  /* Standard fields */

  WORD  Magic;
  BYTE  MajorLinkerVersion;
  BYTE  MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;

  /* NT additional fields */
  ULONGLONG ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD  MajorOperatingSystemVersion;
  WORD  MinorOperatingSystemVersion;
  WORD  MajorImageVersion;
  WORD  MinorImageVersion;
  WORD  MajorSubsystemVersion;
  WORD  MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD  Subsystem;
  WORD  DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS32 {
  DWORD Signature; /* "PE"\0\0 */       /* 0x00 */
  IMAGE_FILE_HEADER FileHeader;         /* 0x04 */
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;       /* 0x18 */
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
  DWORD Signature; /* "PE"\0\0 */       /* 0x00 */
  IMAGE_FILE_HEADER FileHeader;         /* 0x04 */
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;       /* 0x18 */
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER 40

#define IMAGE_FIRST_SECTION(ntheader) \
((PIMAGE_SECTION_HEADER)((LPBYTE)&((PIMAGE_NT_HEADERS)(ntheader))->OptionalHeader + \
((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))

/* These defines are for the Characteristics bitfield. */
/* #define IMAGE_SCN_TYPE_REG                   0x00000000 - Reserved */
/* #define IMAGE_SCN_TYPE_DSECT                 0x00000001 - Reserved */
/* #define IMAGE_SCN_TYPE_NOLOAD                0x00000002 - Reserved */
/* #define IMAGE_SCN_TYPE_GROUP                 0x00000004 - Reserved */
#define IMAGE_SCN_TYPE_NO_PAD                   0x00000008 /* Reserved */
/* #define IMAGE_SCN_TYPE_COPY                  0x00000010 - Reserved */

#define IMAGE_SCN_CNT_CODE                      0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA          0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA        0x00000080

#define IMAGE_SCN_LNK_OTHER                     0x00000100
#define IMAGE_SCN_LNK_INFO                      0x00000200
/* #define IMAGE_SCN_TYPE_OVER          0x00000400 - Reserved */
#define IMAGE_SCN_LNK_REMOVE                    0x00000800
#define IMAGE_SCN_LNK_COMDAT                    0x00001000

/*                                              0x00002000 - Reserved */
/* #define IMAGE_SCN_MEM_PROTECTED              0x00004000 - Obsolete */
#define IMAGE_SCN_MEM_FARDATA                   0x00008000

/* #define IMAGE_SCN_MEM_SYSHEAP                0x00010000 - Obsolete */
#define IMAGE_SCN_MEM_PURGEABLE                 0x00020000
#define IMAGE_SCN_MEM_16BIT                     0x00020000
#define IMAGE_SCN_MEM_LOCKED                    0x00040000
#define IMAGE_SCN_MEM_PRELOAD                   0x00080000

#define IMAGE_SCN_ALIGN_1BYTES                  0x00100000
#define IMAGE_SCN_ALIGN_2BYTES                  0x00200000
#define IMAGE_SCN_ALIGN_4BYTES                  0x00300000
#define IMAGE_SCN_ALIGN_8BYTES                  0x00400000
#define IMAGE_SCN_ALIGN_16BYTES                 0x00500000  /* Default */
#define IMAGE_SCN_ALIGN_32BYTES                 0x00600000
#define IMAGE_SCN_ALIGN_64BYTES                 0x00700000
#define IMAGE_SCN_ALIGN_128BYTES                0x00800000
#define IMAGE_SCN_ALIGN_256BYTES                0x00900000
#define IMAGE_SCN_ALIGN_512BYTES                0x00A00000
#define IMAGE_SCN_ALIGN_1024BYTES               0x00B00000
#define IMAGE_SCN_ALIGN_2048BYTES               0x00C00000
#define IMAGE_SCN_ALIGN_4096BYTES               0x00D00000
#define IMAGE_SCN_ALIGN_8192BYTES               0x00E00000
/*                                              0x00F00000 - Unused */
#define IMAGE_SCN_ALIGN_MASK                    0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL               0x01000000


#define IMAGE_SCN_MEM_DISCARDABLE               0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED                0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED                 0x08000000
#define IMAGE_SCN_MEM_SHARED                    0x10000000
#define IMAGE_SCN_MEM_EXECUTE                   0x20000000
#define IMAGE_SCN_MEM_READ                      0x40000000
#define IMAGE_SCN_MEM_WRITE                     0x80000000

typedef struct _IMAGE_SYMBOL {
    union {
        BYTE    ShortName[8];
        struct {
            DWORD   Short;
            DWORD   Long;
        } Name;
        DWORD   LongName[2];
    } N;
    DWORD   Value;
    SHORT   SectionNumber;
    WORD    Type;
    BYTE    StorageClass;
    BYTE    NumberOfAuxSymbols;
} IMAGE_SYMBOL;
typedef IMAGE_SYMBOL *PIMAGE_SYMBOL;

#define IMAGE_SIZEOF_SYMBOL 18

typedef struct _IMAGE_LINENUMBER {
    union {
        DWORD   SymbolTableIndex;
        DWORD   VirtualAddress;
    } Type;
    WORD    Linenumber;
} IMAGE_LINENUMBER;
typedef IMAGE_LINENUMBER *PIMAGE_LINENUMBER;

#define IMAGE_SIZEOF_LINENUMBER  6

typedef union _IMAGE_AUX_SYMBOL {
    struct {
        DWORD    TagIndex;
        union {
            struct {
                WORD    Linenumber;
                WORD    Size;
            } LnSz;
           DWORD    TotalSize;
        } Misc;
        union {
            struct {
                DWORD    PointerToLinenumber;
                DWORD    PointerToNextFunction;
            } Function;
            struct {
                WORD     Dimension[4];
            } Array;
        } FcnAry;
        WORD    TvIndex;
    } Sym;
    struct {
        BYTE    Name[IMAGE_SIZEOF_SYMBOL];
    } File;
    struct {
        DWORD   Length;
        WORD    NumberOfRelocations;
        WORD    NumberOfLinenumbers;
        DWORD   CheckSum;
        SHORT   Number;
        BYTE    Selection;
    } Section;
} IMAGE_AUX_SYMBOL;
typedef IMAGE_AUX_SYMBOL *PIMAGE_AUX_SYMBOL;

#define IMAGE_SIZEOF_AUX_SYMBOL 18

#define IMAGE_SYM_UNDEFINED           (SHORT)0
#define IMAGE_SYM_ABSOLUTE            (SHORT)-1
#define IMAGE_SYM_DEBUG               (SHORT)-2

#define IMAGE_SYM_TYPE_NULL                 0x0000
#define IMAGE_SYM_TYPE_VOID                 0x0001
#define IMAGE_SYM_TYPE_CHAR                 0x0002
#define IMAGE_SYM_TYPE_SHORT                0x0003
#define IMAGE_SYM_TYPE_INT                  0x0004
#define IMAGE_SYM_TYPE_LONG                 0x0005
#define IMAGE_SYM_TYPE_FLOAT                0x0006
#define IMAGE_SYM_TYPE_DOUBLE               0x0007
#define IMAGE_SYM_TYPE_STRUCT               0x0008
#define IMAGE_SYM_TYPE_UNION                0x0009
#define IMAGE_SYM_TYPE_ENUM                 0x000A
#define IMAGE_SYM_TYPE_MOE                  0x000B
#define IMAGE_SYM_TYPE_BYTE                 0x000C
#define IMAGE_SYM_TYPE_WORD                 0x000D
#define IMAGE_SYM_TYPE_UINT                 0x000E
#define IMAGE_SYM_TYPE_DWORD                0x000F
#define IMAGE_SYM_TYPE_PCODE                0x8000

#define IMAGE_SYM_DTYPE_NULL                0
#define IMAGE_SYM_DTYPE_POINTER             1
#define IMAGE_SYM_DTYPE_FUNCTION            2
#define IMAGE_SYM_DTYPE_ARRAY               3

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

#define N_BTMASK                            0x000F
#define N_TMASK                             0x0030
#define N_TMASK1                            0x00C0
#define N_TMASK2                            0x00F0
#define N_BTSHFT                            4
#define N_TSHIFT                            2

#define BTYPE(x) ((x) & N_BTMASK)

#ifndef ISPTR
#define ISPTR(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT))
#endif

#ifndef ISFCN
#define ISFCN(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT))
#endif

#ifndef ISARY
#define ISARY(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_ARRAY << N_BTSHFT))
#endif

#ifndef ISTAG
#define ISTAG(x) ((x)==IMAGE_SYM_CLASS_STRUCT_TAG || (x)==IMAGE_SYM_CLASS_UNION_TAG || (x)==IMAGE_SYM_CLASS_ENUM_TAG)
#endif

#ifndef INCREF
#define INCREF(x) ((((x)&~N_BTMASK)<<N_TSHIFT)|(IMAGE_SYM_DTYPE_POINTER<<N_BTSHFT)|((x)&N_BTMASK))
#endif
#ifndef DECREF
#define DECREF(x) ((((x)>>N_TSHIFT)&~N_BTMASK)|((x)&N_BTMASK))
#endif

#define IMAGE_COMDAT_SELECT_NODUPLICATES    1
#define IMAGE_COMDAT_SELECT_ANY             2
#define IMAGE_COMDAT_SELECT_SAME_SIZE       3
#define IMAGE_COMDAT_SELECT_EXACT_MATCH     4
#define IMAGE_COMDAT_SELECT_ASSOCIATIVE     5
#define IMAGE_COMDAT_SELECT_LARGEST         6
#define IMAGE_COMDAT_SELECT_NEWEST          7

#define IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY  1
#define IMAGE_WEAK_EXTERN_SEARCH_LIBRARY    2
#define IMAGE_WEAK_EXTERN_SEARCH_ALIAS      3

/* Export module directory */

typedef struct _IMAGE_EXPORT_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   Name;
        DWORD   Base;
        DWORD   NumberOfFunctions;
        DWORD   NumberOfNames;
        DWORD   AddressOfFunctions;
        DWORD   AddressOfNames;
        DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

/* Import name entry */
typedef struct _IMAGE_IMPORT_BY_NAME {
        WORD    Hint;
        BYTE    Name[1];
} IMAGE_IMPORT_BY_NAME,*PIMAGE_IMPORT_BY_NAME;

/* Import thunk */
typedef struct _IMAGE_THUNK_DATA32 {
        union {
                DWORD    ForwarderString;
                DWORD    Function;
                DWORD    Ordinal;
                DWORD   AddressOfData;
        } u1;
} IMAGE_THUNK_DATA32,*PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_THUNK_DATA64 {
        union {
                ULONGLONG    ForwarderString;
                ULONGLONG    Function;
                ULONGLONG    Ordinal;
                ULONGLONG    AddressOfData;
        } u1;
} IMAGE_THUNK_DATA64,*PIMAGE_THUNK_DATA64;

typedef IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA32 PIMAGE_THUNK_DATA;

/* Import module directory */

typedef struct __packed _IMAGE_IMPORT_DESCRIPTOR {
        union {
                DWORD   Characteristics; /* 0 for terminating null
                                          * import descriptor */
                DWORD   OriginalFirstThunk; /* RVA to original unbound
                                             * IAT */
        } u;
        DWORD   TimeDateStamp;  /* 0 if not bound,
                                 * -1 if bound, and real date\time stamp
                                 *    in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
                                 * (new BIND)
                                 * otherwise date/time stamp of DLL bound to
                                 * (Old BIND)
                                 */
        DWORD   ForwarderChain; /* -1 if no forwarders */
        DWORD   Name;
        /* RVA to IAT (if bound this IAT has actual addresses) */
        DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR;

#define IMAGE_ORDINAL_FLAG32            0x80000000
#define IMAGE_ORDINAL_FLAG64            0x8000000000000000UL
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_ORDINAL(Ordinal) (Ordinal & 0xffff)

#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG32
#define IMAGE_SNAP_BY_ORDINAL IMAGE_SNAP_BY_ORDINAL32

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR
{
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    NumberOfModuleForwarderRefs;
/* Array of zero or more IMAGE_BOUND_FORWARDER_REF follows */
} IMAGE_BOUND_IMPORT_DESCRIPTOR, *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF
{
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    Reserved;
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;

typedef struct _IMAGE_BASE_RELOCATION
{
        DWORD   VirtualAddress;
        DWORD   SizeOfBlock;
        WORD    TypeOffset[0];
} IMAGE_BASE_RELOCATION,*PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_RELOCATION
{
    union {
        DWORD   VirtualAddress;
        DWORD   RelocCount;
    } DUMMYUNIONNAME;
    DWORD   SymbolTableIndex;
    WORD    Type;
} IMAGE_RELOCATION, *PIMAGE_RELOCATION;

#define IMAGE_SIZEOF_RELOCATION 10

/* generic relocation types */
#define IMAGE_REL_BASED_ABSOLUTE                0
#define IMAGE_REL_BASED_HIGH                    1
#define IMAGE_REL_BASED_LOW                     2
#define IMAGE_REL_BASED_HIGHLOW                 3
#define IMAGE_REL_BASED_HIGHADJ                 4
#define IMAGE_REL_BASED_MIPS_JMPADDR            5
#define IMAGE_REL_BASED_SECTION                 6
#define IMAGE_REL_BASED_REL                     7
#define IMAGE_REL_BASED_MIPS_JMPADDR16          9
#define IMAGE_REL_BASED_IA64_IMM64              9 /* yes, 9 too */
#define IMAGE_REL_BASED_DIR64                   10
#define IMAGE_REL_BASED_HIGH3ADJ                11

/* I386 relocation types */
#define IMAGE_REL_I386_ABSOLUTE                 0
#define IMAGE_REL_I386_DIR16                    1
#define IMAGE_REL_I386_REL16                    2
#define IMAGE_REL_I386_DIR32                    6
#define IMAGE_REL_I386_DIR32NB                  7
#define IMAGE_REL_I386_SEG12                    9
#define IMAGE_REL_I386_SECTION                  10
#define IMAGE_REL_I386_SECREL                   11
#define IMAGE_REL_I386_REL32                    20

/* MIPS relocation types */
#define IMAGE_REL_MIPS_ABSOLUTE         0x0000
#define IMAGE_REL_MIPS_REFHALF          0x0001
#define IMAGE_REL_MIPS_REFWORD          0x0002
#define IMAGE_REL_MIPS_JMPADDR          0x0003
#define IMAGE_REL_MIPS_REFHI            0x0004
#define IMAGE_REL_MIPS_REFLO            0x0005
#define IMAGE_REL_MIPS_GPREL            0x0006
#define IMAGE_REL_MIPS_LITERAL          0x0007
#define IMAGE_REL_MIPS_SECTION          0x000A
#define IMAGE_REL_MIPS_SECREL           0x000B
#define IMAGE_REL_MIPS_SECRELLO         0x000C
#define IMAGE_REL_MIPS_SECRELHI         0x000D
#define IMAGE_REL_MIPS_JMPADDR16        0x0010
#define IMAGE_REL_MIPS_REFWORDNB        0x0022
#define IMAGE_REL_MIPS_PAIR             0x0025

/* ALPHA relocation types */
#define IMAGE_REL_ALPHA_ABSOLUTE        0x0000
#define IMAGE_REL_ALPHA_REFLONG         0x0001
#define IMAGE_REL_ALPHA_REFQUAD         0x0002
#define IMAGE_REL_ALPHA_GPREL           0x0003
#define IMAGE_REL_ALPHA_LITERAL         0x0004
#define IMAGE_REL_ALPHA_LITUSE          0x0005
#define IMAGE_REL_ALPHA_GPDISP          0x0006
#define IMAGE_REL_ALPHA_BRADDR          0x0007
#define IMAGE_REL_ALPHA_HINT            0x0008
#define IMAGE_REL_ALPHA_INLINE_REFLONG  0x0009
#define IMAGE_REL_ALPHA_REFHI           0x000A
#define IMAGE_REL_ALPHA_REFLO           0x000B
#define IMAGE_REL_ALPHA_PAIR            0x000C
#define IMAGE_REL_ALPHA_MATCH           0x000D
#define IMAGE_REL_ALPHA_SECTION         0x000E
#define IMAGE_REL_ALPHA_SECREL          0x000F
#define IMAGE_REL_ALPHA_REFLONGNB       0x0010
#define IMAGE_REL_ALPHA_SECRELLO        0x0011
#define IMAGE_REL_ALPHA_SECRELHI        0x0012
#define IMAGE_REL_ALPHA_REFQ3           0x0013
#define IMAGE_REL_ALPHA_REFQ2           0x0014
#define IMAGE_REL_ALPHA_REFQ1           0x0015
#define IMAGE_REL_ALPHA_GPRELLO         0x0016
#define IMAGE_REL_ALPHA_GPRELHI         0x0017

/* PowerPC relocation types */
#define IMAGE_REL_PPC_ABSOLUTE          0x0000
#define IMAGE_REL_PPC_ADDR64            0x0001
#define IMAGE_REL_PPC_ADDR            0x0002
#define IMAGE_REL_PPC_ADDR24            0x0003
#define IMAGE_REL_PPC_ADDR16            0x0004
#define IMAGE_REL_PPC_ADDR14            0x0005
#define IMAGE_REL_PPC_REL24             0x0006
#define IMAGE_REL_PPC_REL14             0x0007
#define IMAGE_REL_PPC_TOCREL16          0x0008
#define IMAGE_REL_PPC_TOCREL14          0x0009
#define IMAGE_REL_PPC_ADDR32NB          0x000A
#define IMAGE_REL_PPC_SECREL            0x000B
#define IMAGE_REL_PPC_SECTION           0x000C
#define IMAGE_REL_PPC_IFGLUE            0x000D
#define IMAGE_REL_PPC_IMGLUE            0x000E
#define IMAGE_REL_PPC_SECREL16          0x000F
#define IMAGE_REL_PPC_REFHI             0x0010
#define IMAGE_REL_PPC_REFLO             0x0011
#define IMAGE_REL_PPC_PAIR              0x0012
#define IMAGE_REL_PPC_SECRELLO          0x0013
#define IMAGE_REL_PPC_SECRELHI          0x0014
#define IMAGE_REL_PPC_GPREL             0x0015
#define IMAGE_REL_PPC_TYPEMASK          0x00FF
/* modifier bits */
#define IMAGE_REL_PPC_NEG               0x0100
#define IMAGE_REL_PPC_BRTAKEN           0x0200
#define IMAGE_REL_PPC_BRNTAKEN          0x0400
#define IMAGE_REL_PPC_TOCDEFN           0x0800

/* SH3 ? relocation type */
#define IMAGE_REL_SH3_ABSOLUTE          0x0000
#define IMAGE_REL_SH3_DIRECT16          0x0001
#define IMAGE_REL_SH3_DIRECT          0x0002
#define IMAGE_REL_SH3_DIRECT8           0x0003
#define IMAGE_REL_SH3_DIRECT8_WORD      0x0004
#define IMAGE_REL_SH3_DIRECT8_LONG      0x0005
#define IMAGE_REL_SH3_DIRECT4           0x0006
#define IMAGE_REL_SH3_DIRECT4_WORD      0x0007
#define IMAGE_REL_SH3_DIRECT4_LONG      0x0008
#define IMAGE_REL_SH3_PCREL8_WORD       0x0009
#define IMAGE_REL_SH3_PCREL8_LONG       0x000A
#define IMAGE_REL_SH3_PCREL12_WORD      0x000B
#define IMAGE_REL_SH3_STARTOF_SECTION   0x000C
#define IMAGE_REL_SH3_SIZEOF_SECTION    0x000D
#define IMAGE_REL_SH3_SECTION           0x000E
#define IMAGE_REL_SH3_SECREL            0x000F
#define IMAGE_REL_SH3_DIRECT32_NB       0x0010

/* ARM (Archimedes?) relocation types */
#define IMAGE_REL_ARM_ABSOLUTE          0x0000
#define IMAGE_REL_ARM_ADDR              0x0001
#define IMAGE_REL_ARM_ADDR32NB          0x0002
#define IMAGE_REL_ARM_BRANCH24          0x0003
#define IMAGE_REL_ARM_BRANCH11          0x0004
#define IMAGE_REL_ARM_SECTION           0x000E
#define IMAGE_REL_ARM_SECREL            0x000F

/* IA64 relocation types */
#define IMAGE_REL_IA64_ABSOLUTE         0x0000
#define IMAGE_REL_IA64_IMM14            0x0001
#define IMAGE_REL_IA64_IMM22            0x0002
#define IMAGE_REL_IA64_IMM64            0x0003
#define IMAGE_REL_IA64_DIR              0x0004
#define IMAGE_REL_IA64_DIR64            0x0005
#define IMAGE_REL_IA64_PCREL21B         0x0006
#define IMAGE_REL_IA64_PCREL21M         0x0007
#define IMAGE_REL_IA64_PCREL21F         0x0008
#define IMAGE_REL_IA64_GPREL22          0x0009
#define IMAGE_REL_IA64_LTOFF22          0x000A
#define IMAGE_REL_IA64_SECTION          0x000B
#define IMAGE_REL_IA64_SECREL22         0x000C
#define IMAGE_REL_IA64_SECREL64I        0x000D
#define IMAGE_REL_IA64_SECREL           0x000E
#define IMAGE_REL_IA64_LTOFF64          0x000F
#define IMAGE_REL_IA64_DIR32NB          0x0010
#define IMAGE_REL_IA64_RESERVED_11      0x0011
#define IMAGE_REL_IA64_RESERVED_12      0x0012
#define IMAGE_REL_IA64_RESERVED_13      0x0013
#define IMAGE_REL_IA64_RESERVED_14      0x0014
#define IMAGE_REL_IA64_RESERVED_15      0x0015
#define IMAGE_REL_IA64_RESERVED_16      0x0016
#define IMAGE_REL_IA64_ADDEND           0x001F

/* archive format */

#define IMAGE_ARCHIVE_START_SIZE             8
#define IMAGE_ARCHIVE_START                  "!<arch>\n"
#define IMAGE_ARCHIVE_END                    "`\n"
#define IMAGE_ARCHIVE_PAD                    "\n"
#define IMAGE_ARCHIVE_LINKER_MEMBER          "/               "
#define IMAGE_ARCHIVE_LONGNAMES_MEMBER       "//              "

typedef struct _IMAGE_ARCHIVE_MEMBER_HEADER
{
    BYTE     Name[16];
    BYTE     Date[12];
    BYTE     UserID[6];
    BYTE     GroupID[6];
    BYTE     Mode[8];
    BYTE     Size[10];
    BYTE     EndHeader[2];
} IMAGE_ARCHIVE_MEMBER_HEADER, *PIMAGE_ARCHIVE_MEMBER_HEADER;

#define IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR 60

/*
 * Resource directory stuff
 */
typedef struct _IMAGE_RESOURCE_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        WORD    NumberOfNamedEntries;
        WORD    NumberOfIdEntries;
        /*  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[]; */
} IMAGE_RESOURCE_DIRECTORY,*PIMAGE_RESOURCE_DIRECTORY;

#define IMAGE_RESOURCE_NAME_IS_STRING           0x80000000
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY        0x80000000

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
        union {
                struct {
#ifdef BITFIELDS_BIGENDIAN
                        unsigned NameIsString:1;
                        unsigned NameOffset:31;
#else
                        unsigned NameOffset:31;
                        unsigned NameIsString:1;
#endif
                } DUMMYSTRUCTNAME1;
                DWORD   Name;
                struct {
#ifdef WORDS_BIGENDIAN
                        WORD    __pad;
                        WORD    Id;
#else
                        WORD    Id;
                        WORD    __pad;
#endif
                } DUMMYSTRUCTNAME2;
        } DUMMYUNIONNAME1;
        union {
                DWORD   OffsetToData;
                struct {
#ifdef BITFIELDS_BIGENDIAN
                        unsigned DataIsDirectory:1;
                        unsigned OffsetToDirectory:31;
#else
                        unsigned OffsetToDirectory:31;
                        unsigned DataIsDirectory:1;
#endif
                } DUMMYSTRUCTNAME3;
        } DUMMYUNIONNAME2;
} IMAGE_RESOURCE_DIRECTORY_ENTRY,*PIMAGE_RESOURCE_DIRECTORY_ENTRY;


typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
        WORD    Length;
        CHAR    NameString[ 1 ];
} IMAGE_RESOURCE_DIRECTORY_STRING,*PIMAGE_RESOURCE_DIRECTORY_STRING;

typedef struct _NT_TIB {
    PVOID ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    ULONG Version;
    PVOID UserPointer;
    PVOID Self;
} NT_TIB, *PNT_TIB;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, PRLIST_ENTRY;

typedef struct _PEB_LDR_DATA
{
    ULONG               Length;
    BOOLEAN             Initialized;
    PVOID               SsHandle;
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
    BOOLEAN                      InheritedAddressSpace;           /* 0x00 */
    BOOLEAN                      ReadImageFileExecOptions;        /* 0x01 */
    BOOLEAN                      BeingDebugged;                   /* 0x02 */
    BOOLEAN                      SpareBool;                       /* 0x03 */
    HANDLE                       Mutant;                          /* 0x04 */
    HMODULE                      ImageBaseAddress;                /* 0x08 */
    PPEB_LDR_DATA                LdrData;                         /* 0x0c */
    PVOID                        ProcessParameters;               /* 0x10 */
    PVOID                        SubSystemData;                   /* 0x14 */
    HANDLE                       ProcessHeap;                     /* 0x18 */
    PVOID                        FastPebLock;                     /* 0x1c */
    PVOID                        FastPebLockRoutine;              /* 0x20 */
    PVOID                        FastPebUnlockRoutine;            /* 0x24 */
    ULONG                        EnvironmentUpdateCount;          /* 0x28 */
    PVOID                        KernelCallbackTable;             /* 0x2c */
    PVOID                        EventLogSection;                 /* 0x30 */
    PVOID                        EventLog;                        /* 0x34 */
    PVOID                        FreeList;                        /* 0x38 */
    ULONG                        TlsExpansionCounter;             /* 0x3c */
    PRTL_BITMAP                  TlsBitmap;                       /* 0x40 */
    ULONG                        TlsBitmapBits[2];                /* 0x44 */
    PVOID                        ReadOnlySharedMemoryBase;        /* 0x4c */
    PVOID                        ReadOnlySharedMemoryHeap;        /* 0x50 */
    PVOID                       *ReadOnlyStaticServerData;        /* 0x54 */
    PVOID                        AnsiCodePageData;                /* 0x58 */
    PVOID                        OemCodePageData;                 /* 0x5c */
    PVOID                        UnicodeCaseTableData;            /* 0x60 */
    ULONG                        NumberOfProcessors;              /* 0x64 */
    ULONG                        NtGlobalFlag;                    /* 0x68 */
    BYTE                         Spare2[4];                       /* 0x6c */
    LARGE_INTEGER                CriticalSectionTimeout;          /* 0x70 */
    ULONG                        HeapSegmentReserve;              /* 0x78 */
    ULONG                        HeapSegmentCommit;               /* 0x7c */
    ULONG                        HeapDeCommitTotalFreeThreshold;  /* 0x80 */
    ULONG                        HeapDeCommitFreeBlockThreshold;  /* 0x84 */
    ULONG                        NumberOfHeaps;                   /* 0x88 */
    ULONG                        MaximumNumberOfHeaps;            /* 0x8c */
    PVOID                       *ProcessHeaps;                    /* 0x90 */
    PVOID                        GdiSharedHandleTable;            /* 0x94 */
    PVOID                        ProcessStarterHelper;            /* 0x98 */
    PVOID                        GdiDCAttributeList;              /* 0x9c */
    PVOID                        LoaderLock;                      /* 0xa0 */
    ULONG                        OSMajorVersion;                  /* 0xa4 */
    ULONG                        OSMinorVersion;                  /* 0xa8 */
    ULONG                        OSBuildNumber;                   /* 0xac */
    ULONG                        OSPlatformId;                    /* 0xb0 */
    ULONG                        ImageSubSystem;                  /* 0xb4 */
    ULONG                        ImageSubSystemMajorVersion;      /* 0xb8 */
    ULONG                        ImageSubSystemMinorVersion;      /* 0xbc */
    ULONG                        ImageProcessAffinityMask;        /* 0xc0 */
    ULONG                        GdiHandleBuffer[34];             /* 0xc4 */
    ULONG                        PostProcessInitRoutine;          /* 0x14c */
    PRTL_BITMAP                  TlsExpansionBitmap;              /* 0x150 */
    ULONG                        TlsExpansionBitmapBits[32];      /* 0x154 */
    ULONG                        SessionId;                       /* 0x1d4 */
} PEB, *PPEB;

typedef struct _TEB {
    NT_TIB      Tib;
    PVOID       EnvironmentPointer;
    CLIENT_ID   Cid;
    PVOID       ActiveRpcInfo;
    PVOID       ThreadLocalStoragePointer;
    PPEB        ProcessEnvironmentBlock;
    // The fields below this are deliberately omitted so that access causes a
    // crash (because of the segment limit). This lets me know I have to fix
    // it, otherwise the error is very difficult to track down.
} TEB, *PTEB;

typedef struct _IMAGE_TLS_DIRECTORY {
    PVOID RawDataStart;
    PVOID RawDataEnd;
    PDWORD AddressOfIndex;
    PVOID AddressOfCallbacks;
    DWORD SizeOfZeroFill;
    DWORD Characteristics;
} IMAGE_TLS_DIRECTORY, *PIMAGE_TLS_DIRECTORY;

struct user_desc {
    unsigned int  entry_number;
    unsigned long base_addr;
    unsigned int  limit;
    unsigned int  seg_32bit : 1;
    unsigned int  contents : 2;
    unsigned int  read_exec_only : 1;
    unsigned int  limit_in_pages : 1;
    unsigned int  seg_not_present : 1;
    unsigned int  useable : 1;
};

#define LDT_READ 0
#define LDT_WRITE 1

bool pe_load_library(const char *filename, void **image, size_t *size);
void * get_export_address(const char *name);
int link_pe_images(struct pe_image *pe_image, unsigned short n);
int get_export(const char *name, void *func);
int get_data_export(char *name, uint32_t base, void *result);
bool setup_nt_threadinfo(PEXCEPTION_HANDLER handler);
bool setup_kuser_shared_data(void);
bool process_extra_exports(void *imagebase, size_t base, const char *filename);

extern PKUSER_SHARED_DATA SharedUserData;

#endif
