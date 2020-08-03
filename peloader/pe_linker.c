//
// Copyright (C) 2017 Tavis Ormandy
//
// Portions of this code are based on ndiswrapper, which included this
// notice:
//
// Copyright (C) 2003-2005 Pontus Fuchs, Giridhar Pemmasani
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>
#include <err.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "log.h"

struct pe_exports {
        char *dll;
        char *name;
        generic_func addr;
};

static struct pe_exports *pe_exports;
static int num_pe_exports;
PKUSER_SHARED_DATA SharedUserData;

#define DRIVER_NAME "pelinker"
#define RVA2VA(image, rva, type) (type)(ULONG_PTR)((void *)image + rva)

//#define DBGLINKER(fmt, ...) printf("%s (%s:%d): " fmt "\n",     \
//                                   DRIVER_NAME, __func__,               \
//                                   __LINE__ , ## __VA_ARGS__);

#define DBGLINKER(fmt, ...)

#ifndef NDEBUG
#define ERROR(fmt, ...) printf("%s (%s:%d): " fmt "\n", \
                                   DRIVER_NAME, __func__,               \
                                   __LINE__ , ## __VA_ARGS__);
#else
# define ERROR(fmt, ...)
#endif
#define TRACE1(fmt, ...) printf("%s (%s:%d): " fmt "\n",        \
                                   DRIVER_NAME, __func__,               \
                                   __LINE__ , ## __VA_ARGS__);

static const char *image_directory_name[] = {
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "SECURITY",
    "BASERELOC",
    "DEBUG",
    "COPYRIGHT",
    "GLOBALPTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "COM_DESCRIPTOR"
};

extern struct wrap_export crt_exports[];

uintptr_t LocalStorage[1024] = {0};
PFLS_CALLBACK_FUNCTION FlsCallbacks[1024] = {0};

static ULONG TlsBitmapData[32];
static RTL_BITMAP TlsBitmap = {
    .SizeOfBitMap = sizeof(TlsBitmapData) * CHAR_BIT,
    .Buffer = (PVOID) &TlsBitmapData[0],
};

struct hsearch_data extraexports;
struct hsearch_data crtexports;

void __destructor clearexports(void)
{
    hdestroy_r(&crtexports);
}

int get_data_export(char *name, uint32_t base, void *result)
{
    uint32_t *hack = result;

    get_export(name, result);

    *hack += base - 0x3000;

    ERROR("THIS WAS A TEMPORARY HACK DO NOT CALL WITHOUT FIXING");
}

void * get_export_address(const char *name)
{
    void *address;
    if (get_export(name, &address) != -1)
        return address;
    return NULL;
}

int get_export(const char *name, void *result)
{
        ENTRY key = { (char *)(name) }, *item;
        int i, j;
        void **func = result;

        if (crtexports.size) {
            if (hsearch_r(key, FIND, &item, &crtexports)) {
                *func = item->data;
                return 0;
            }
        }

        if (extraexports.size) {
            if (hsearch_r(key, FIND, &item, &extraexports)) {
                *func = item->data;
                return 0;
            }
        }

        // Search the ndiswrapper crt
        for (i = 0; crt_exports[i].name != NULL; i++) {
                if (strcmp(crt_exports[i].name, name) == 0) {
                        *func = crt_exports[i].func;
                        return 0;
                }
        }

        // Search PE exports
        for (i = 0; i < num_pe_exports; i++)
                if (strcmp(pe_exports[i].name, name) == 0) {
                        *func = pe_exports[i].addr;
                        return 0;
                }

        return -1;
}

static void *get_dll_init(char *name)
{
        int i;
        for (i = 0; i < num_pe_exports; i++)
                if ((strcmp(pe_exports[i].dll, name) == 0) &&
                    (strcmp(pe_exports[i].name, "DllInitialize") == 0))
                        return (void *)pe_exports[i].addr;
        return NULL;
}

/*
 * Find and validate the coff header
 *
 */
static int check_nt_hdr(IMAGE_NT_HEADERS *nt_hdr)
{
        int i;
        WORD attr;
        PIMAGE_OPTIONAL_HEADER opt_hdr;

        /* Validate the "PE\0\0" signature */
        if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
                ERROR("is this driver file? bad signature %08x",
                      nt_hdr->Signature);
                return -EINVAL;
        }

        opt_hdr = &nt_hdr->OptionalHeader;

        if (opt_hdr->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                ERROR("kernel is 32-bit, but Windows driver is not 32-bit;"
                      "bad magic: %04X", opt_hdr->Magic);
                return -EINVAL;
        }

        /* Validate the image for the current architecture. */
        if (nt_hdr->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
                ERROR("kernel is 32-bit, but Windows driver is not 32-bit;"
                      " (PE signature is %04X)", nt_hdr->FileHeader.Machine);
                return -EINVAL;
        }

        /* Must have attributes */
        attr = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;

        if ((nt_hdr->FileHeader.Characteristics & attr) != attr)
                return -EINVAL;

        /* Must be relocatable */
        attr = IMAGE_FILE_RELOCS_STRIPPED;
        if ((nt_hdr->FileHeader.Characteristics & attr))
                return -EINVAL;

        /* Make sure we have at least one section */
        if (nt_hdr->FileHeader.NumberOfSections == 0)
                return -EINVAL;

        if (opt_hdr->SectionAlignment < opt_hdr->FileAlignment) {
                ERROR("alignment mismatch: section: 0x%x, file: 0x%x",
                      opt_hdr->SectionAlignment, opt_hdr->FileAlignment);
                return -EINVAL;
        }

#if 0
        DBGLINKER("number of datadictionary entries %d",
                  opt_hdr->NumberOfRvaAndSizes);
        for (i = 0; i < opt_hdr->NumberOfRvaAndSizes; i++) {
                DBGLINKER("datadirectory %s RVA:%X Size:%d",
                          (i <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) ?
                          image_directory_name[i] : "unknown",
                          opt_hdr->DataDirectory[i].VirtualAddress,
                          opt_hdr->DataDirectory[i].Size);
        }
#endif

        if ((nt_hdr->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
                return IMAGE_FILE_EXECUTABLE_IMAGE;
        if ((nt_hdr->FileHeader.Characteristics & IMAGE_FILE_DLL))
                return IMAGE_FILE_DLL;
        return -EINVAL;
}

static int import(void *image, IMAGE_IMPORT_DESCRIPTOR *dirent, char *dll)
{
        ULONG_PTR *lookup_tbl, *address_tbl;
        char *symname = NULL;
        int i;
        int ret = 0;
        generic_func adr;

        void ordinal_import_stub(void)
        {
            warnx("function at %p attempted to call a symbol imported by ordinal", __builtin_return_address(0));
            __debugbreak();
        }

        void unknown_symbol_stub(void)
        {
            warnx("function at %p attempted to call an unknown symbol", __builtin_return_address(0));
            __debugbreak();
        }

        lookup_tbl = RVA2VA(image, dirent->u.OriginalFirstThunk, ULONG_PTR *);
        address_tbl = RVA2VA(image, dirent->FirstThunk, ULONG_PTR *);

        for (i = 0; lookup_tbl[i]; i++) {
                if (IMAGE_SNAP_BY_ORDINAL(lookup_tbl[i])) {
                        ERROR("ordinal import not supported: %llu", (uint64_t)lookup_tbl[i]);
                        address_tbl[i] = (ULONG) ordinal_import_stub;
                        continue;
                }
                else {
                        symname = RVA2VA(image, ((lookup_tbl[i] & ~IMAGE_ORDINAL_FLAG) + 2), char *);
                }

                if (get_export(symname, &adr) < 0) {
                        ERROR("unknown symbol: %s:%s", dll, symname);
                        address_tbl[i] = (ULONG) unknown_symbol_stub;
                        continue;
                } else {
                        //DBGLINKER("found symbol: %s:%s: addr: %p, rva = %llu",
                        //          dll, symname, adr, (uint64_t)address_tbl[i]);
                        address_tbl[i] = (ULONG_PTR)adr;
                }
        }

        return 0;
}

static int read_exports(struct pe_image *pe)
{
        IMAGE_EXPORT_DIRECTORY *export_dir_table;
        int i;
        uint32_t *name_table;
        uint16_t *ordinal_table;
        PIMAGE_OPTIONAL_HEADER opt_hdr;
        IMAGE_DATA_DIRECTORY *export_data_dir;

        opt_hdr = &pe->nt_hdr->OptionalHeader;
        export_data_dir =
                &opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (export_data_dir->Size == 0) {
                DBGLINKER("no exports");
                return 0;
        }

        export_dir_table =
                RVA2VA(pe->image, export_data_dir->VirtualAddress,
                       IMAGE_EXPORT_DIRECTORY *);

        name_table = (unsigned int *)(pe->image +
                                      export_dir_table->AddressOfNames);
        ordinal_table = (uint16_t *)(pe->image +
                                      export_dir_table->AddressOfNameOrdinals);

        pe_exports = calloc(export_dir_table->NumberOfNames, sizeof(struct pe_exports));

        for (i = 0; i < export_dir_table->NumberOfNames; i++) {
                uint32_t address = ((uint32_t *) (pe->image + export_dir_table->AddressOfFunctions))[*ordinal_table];

                if (export_data_dir->VirtualAddress <= address ||
                    address >= (export_data_dir->VirtualAddress +
                                           export_data_dir->Size)) {
                        //DBGLINKER("forwarder rva");
                }

                //DBGLINKER("export symbol: %s, at %p",
                //          (char *)(pe->image + *name_table),
                //          pe->image + address);

                pe_exports[num_pe_exports].dll = pe->name;
                pe_exports[num_pe_exports].name = pe->image + *name_table;
                pe_exports[num_pe_exports].addr = pe->image + address;

                num_pe_exports++;
                name_table++;
                ordinal_table++;
        }
        return 0;
}

static int fixup_imports(void *image, IMAGE_NT_HEADERS *nt_hdr)
{
        int i;
        char *name;
        int ret = 0;
        IMAGE_IMPORT_DESCRIPTOR *dirent;
        IMAGE_DATA_DIRECTORY *import_data_dir;
        PIMAGE_OPTIONAL_HEADER opt_hdr;

        opt_hdr = &nt_hdr->OptionalHeader;
        import_data_dir =
                &opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        dirent = RVA2VA(image, import_data_dir->VirtualAddress,
                        IMAGE_IMPORT_DESCRIPTOR *);

        for (i = 0; dirent[i].Name; i++) {
                name = RVA2VA(image, dirent[i].Name, char*);

                DBGLINKER("imports from dll: %s", name);
                ret += import(image, &dirent[i], name);
        }
        return ret;
}

static int fixup_reloc(void *image, IMAGE_NT_HEADERS *nt_hdr)
{
        ULONG_PTR base;
        ULONG_PTR size;
        IMAGE_BASE_RELOCATION *fixup_block;
        IMAGE_DATA_DIRECTORY *base_reloc_data_dir;
        PIMAGE_OPTIONAL_HEADER opt_hdr;

        opt_hdr = &nt_hdr->OptionalHeader;
        base = opt_hdr->ImageBase;
        base_reloc_data_dir =
                &opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (base_reloc_data_dir->Size == 0)
                return 0;

        fixup_block = RVA2VA(image, base_reloc_data_dir->VirtualAddress,
                             IMAGE_BASE_RELOCATION *);
        DBGLINKER("fixup_block=%p, image=%p", fixup_block, image);
        DBGLINKER("fixup_block info: %x %d",
                  fixup_block->VirtualAddress, fixup_block->SizeOfBlock);

        while (fixup_block->SizeOfBlock) {
                int i;
                WORD fixup, offset;

                size = (fixup_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

                for (i = 0; i < size; i++) {
                        fixup = fixup_block->TypeOffset[i];
                        offset = fixup & 0xfff;
                        switch ((fixup >> 12) & 0x0f) {
                        case IMAGE_REL_BASED_ABSOLUTE:
                                break;

                        case IMAGE_REL_BASED_HIGHLOW: {
                                uint32_t addr;
                                uint32_t *loc =
                                        RVA2VA(image,
                                               fixup_block->VirtualAddress +
                                               offset, uint32_t *);
                                addr = RVA2VA(image, (*loc - base), uint32_t);
                                *loc = addr;
                        }
                                break;

                        case IMAGE_REL_BASED_DIR64: {
                                uint64_t addr;
                                uint64_t *loc =
                                        RVA2VA(image,
                                               fixup_block->VirtualAddress +
                                               offset, uint64_t *);
                                addr = RVA2VA(image, (*loc - base), uint64_t);
                                DBGLINKER("relocation: *%p (Val:%llX)= %llx",
                                          loc, *loc, addr);
                                *loc = addr;
                        }
                                break;

                        default:
                                ERROR("unknown fixup: %08X",
                                      (fixup >> 12) & 0x0f);
                                return -EOPNOTSUPP;
                                break;
                        }
                }

                fixup_block = (IMAGE_BASE_RELOCATION *)
                        ((void *)fixup_block + fixup_block->SizeOfBlock);
        };

        return 0;
}

/* Expand the image in memory if necessary. The image on disk does not
 * necessarily maps the image of the driver in memory, so we have to
 * re-write it in order to fulfill the sections alignments. The
 * advantage to do that is that rva_to_va becomes a simple
 * addition. */
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

static int fix_pe_image(struct pe_image *pe)
{
        void *image;
        IMAGE_SECTION_HEADER *sect_hdr;
        int i, sections;
        int image_size;

        if (pe->size == pe->opt_hdr->SizeOfImage) {
                /* Nothing to do */
                return 0;
        }

        image_size = pe->opt_hdr->SizeOfImage;

        // TODO: If image does not have DYNAMIC_BASE, add MAP_FIXED.

        image      = mmap((PVOID)(pe->opt_hdr->ImageBase),
                          image_size + getpagesize(),
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_ANONYMOUS | MAP_PRIVATE,
                          -1,
                          0);

        if (image == MAP_FAILED) {
                ERROR("failed to mmap desired space for image: %d bytes, image base %p, %m", image_size, pe->opt_hdr->ImageBase);
                return -ENOMEM;
        }

        memset(image, 0, image_size);

        /* Copy all the headers, ie everything before the first section. */

        sections = pe->nt_hdr->FileHeader.NumberOfSections;
        sect_hdr = IMAGE_FIRST_SECTION(pe->nt_hdr);

        DBGLINKER("copying headers: %u bytes", sect_hdr->PointerToRawData);

        memcpy(image, pe->image, sect_hdr->PointerToRawData);

        /* Copy all the sections */
        for (i = 0; i < sections; i++) {
                DBGLINKER("Copy section %s from %x to %x",
                          sect_hdr->Name, sect_hdr->PointerToRawData,
                          sect_hdr->VirtualAddress);
                if (sect_hdr->VirtualAddress+sect_hdr->SizeOfRawData >
                    image_size) {
                        ERROR("Invalid section %s in driver", sect_hdr->Name);
                        munmap(image, image_size + getpagesize());
                        return -EINVAL;
                }

                memcpy(image+sect_hdr->VirtualAddress,
                       pe->image + sect_hdr->PointerToRawData,
                       sect_hdr->SizeOfRawData);
                sect_hdr++;
        }

        // If the original is still there, clean it up.
        munmap(pe->image, pe->size);

        pe->image = image;
        pe->size = image_size;

        /* Update our internal pointers */
        pe->nt_hdr = (IMAGE_NT_HEADERS *)
                (pe->image + ((IMAGE_DOS_HEADER *)pe->image)->e_lfanew);
        pe->opt_hdr = &pe->nt_hdr->OptionalHeader;

        DBGLINKER("set nt headers: nt_hdr=%p, opt_hdr=%p, image=%p",
                  pe->nt_hdr, pe->opt_hdr, pe->image);

        return 0;
}

int link_pe_images(struct pe_image *pe_image, unsigned short n)
{
        int i;
        struct pe_image *pe;

        for (i = 0; i < n; i++) {
                IMAGE_DOS_HEADER *dos_hdr;
                pe = &pe_image[i];
                dos_hdr = pe->image;

                if (pe->size < sizeof(IMAGE_DOS_HEADER)) {
                        TRACE1("image too small: %d", pe->size);
                        return -EINVAL;
                }

                pe->nt_hdr =
                        (IMAGE_NT_HEADERS *)(pe->image + dos_hdr->e_lfanew);
                pe->opt_hdr = &pe->nt_hdr->OptionalHeader;

                pe->type = check_nt_hdr(pe->nt_hdr);
                if (pe->type <= 0) {
                        TRACE1("type <= 0");
                        return -EINVAL;
                }

                if (fix_pe_image(pe)) {
                        TRACE1("bad PE image");
                        return -EINVAL;
                }

                if (read_exports(pe)) {
                        TRACE1("read exports failed");
                        return -EINVAL;
                }
        }

        for (i = 0; i < n; i++) {
                pe = &pe_image[i];

                if (fixup_reloc(pe->image, pe->nt_hdr)) {
                        TRACE1("fixup reloc failed");
                        return -EINVAL;
                }
                if (fixup_imports(pe->image, pe->nt_hdr)) {
                        TRACE1("fixup imports failed");
                        return -EINVAL;
                }
                pe->entry =
                        RVA2VA(pe->image,
                               pe->opt_hdr->AddressOfEntryPoint, void *);
                //TRACE1("entry is at %p, rva at %08X", pe->entry,
                //       pe->opt_hdr->AddressOfEntryPoint);

                // Check if there were enough data directories for a TLS section.
                if (pe->opt_hdr->NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_TLS) {
                    // Normally, we would be expected to allocate a TLS slot,
                    // place the number into *TlsData->AddressOfIndex, and make
                    // it a pointer to RawData, and then process the callbacks.
                    //
                    // We don't support threads, so it seems safe to just
                    // pre-allocate a slot and point it straight to the
                    // template data.
                    //
                    // FIXME: Verify callbacks list is empty and SizeOfZeroFill is zero.
                    //
                    PIMAGE_TLS_DIRECTORY TlsData = RVA2VA(pe->image,
                                                          pe->opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
                                                          IMAGE_TLS_DIRECTORY *);

                    // This means that slot 0 is reserved.
                    LocalStorage[0] = (uintptr_t) TlsData->RawDataStart;
                }
        }

        return 0;
}


// Map (but do not link) the DLL specified in filename, return an image pointer
// and size in the appropriate parameters.
bool pe_load_library(const char *filename, void **image, size_t *size)
{
    struct stat buf;
    int fd;

    assert(image);
    assert(size);

    *image  = MAP_FAILED;
    *size   = 0;
    fd      = -1;

    if ((fd = open(filename, O_RDONLY)) < 0) {
        l_error("failed to open pe library %s, %m", filename);
        goto error;
    }

    // Stat the file descriptor to determine filesize.
    if (fstat(fd, &buf) < 0) {
        l_error("failed to stat the specified pe library %s, %m", filename);
        goto error;
    }

    // Attempt to map the file PROT_READ | PROT_WRITE, it doesn't need to be
    // executable yet because I haven't applied the relocations.
    *size  = buf.st_size;
    *image = mmap(NULL, *size, PROT_READ, MAP_SHARED, fd, 0);

    if (*image == MAP_FAILED) {
        l_error("failed to map library %s, %m", filename);
        goto error;
    }

    // If that succeeded, we can proceed.
    l_debug("successfully mapped %s@%p", filename, *image);

    // File descriptor no longer required.
    close(fd);

    // Install a minimal thread information block (TIB), this is required for
    // code that uses SEH as it accesses it via fs selector.
    setup_nt_threadinfo(NULL);

    // Install a minimal KUSER_SHARED_DATA structure.
    setup_kuser_shared_data();

    return true;

error:
    if (fd >= 0)
        close(fd);

    if (image != MAP_FAILED)
        munmap(image, buf.st_size);

    return false;
}

bool setup_nt_threadinfo(PEXCEPTION_HANDLER ExceptionHandler)
{
    static EXCEPTION_FRAME ExceptionFrame;
    static PEB ProcessEnvironmentBlock = {
        .TlsBitmap          = &TlsBitmap,
    };
    static TEB ThreadEnvironment = {
        .Tib.Self                   = &ThreadEnvironment.Tib,
        .ThreadLocalStoragePointer  = LocalStorage, // https://github.com/taviso/loadlibrary/issues/65
        .ProcessEnvironmentBlock    = &ProcessEnvironmentBlock,
    };
    struct user_desc pebdescriptor = {
        .entry_number       = -1,
        .base_addr          = (uintptr_t) &ThreadEnvironment,
        .limit              = sizeof ThreadEnvironment,
        .seg_32bit          = 1,
        .contents           = 0,
        .read_exec_only     = 0,
        .limit_in_pages     = 0,
        .seg_not_present    = 0,
        .useable            = 1,
    };

    if (ExceptionHandler) {
        if (ThreadEnvironment.Tib.ExceptionList) {
            DebugLog("Resetting ThreadInfo.ExceptionList");
        }
        ExceptionFrame.handler              = ExceptionHandler;
        ExceptionFrame.prev                 = NULL;
        ThreadEnvironment.Tib.ExceptionList = &ExceptionFrame;
    }

    if (syscall(__NR_set_thread_area, &pebdescriptor) != 0) {
        return false;
    }

    // Install descriptor
    asm("mov %[segment], %%fs" :: [segment] "r"(pebdescriptor.entry_number*8+3));

    return true;
}

// Minimal KUSER_SHARED_DATA structure, for those applications that require it.
bool setup_kuser_shared_data(void)
{
    SharedUserData = mmap((PVOID)(MM_SHARED_USER_DATA_VA),
                          sizeof(KUSER_SHARED_DATA),
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                          -1,
                          0);

    if (SharedUserData == MAP_FAILED) {
        DebugLog("failed to map KUSER_SHARED_DATA, %m");
        return false;
    }

    return true;
}
