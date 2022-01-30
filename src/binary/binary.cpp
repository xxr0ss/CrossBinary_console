#include "binary.h"

/*
 *    PE_Binary implementation
 */

PE_Binary::PE_Binary(std::string filename, uint8_t *bytes)
    : Binary(Binary::BinaryType::BIN_TYPE_PE, filename, bytes)
{
}

PE_Binary::~PE_Binary()
{
}

int PE_Binary::parse_bytes()
{
    PIMAGE_DOS_HEADER pdos_header = (PIMAGE_DOS_HEADER)bytes;
    PBYTE pnt_header = (PBYTE)(bytes + pdos_header->e_lfanew);
    PIMAGE_FILE_HEADER pfile_header = (PIMAGE_FILE_HEADER)(pnt_header + sizeof(DWORD));

    /* get bits and arch */
    switch (pfile_header->Machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        bits = 32;
        arch = Binary::ARCH_X86;
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        bits = 64;
        arch = Binary::ARCH_X86;
        break;
        // TODO: add other machin types
    }

    WORD sections_count = pfile_header->NumberOfSections;
    PIMAGE_SECTION_HEADER psection_header = nullptr;

    /* get entry and base_addr */
    if (32 == bits)
    {
        PIMAGE_NT_HEADERS32 pnt_header32 = (PIMAGE_NT_HEADERS32)pnt_header;
        entry = pnt_header32->OptionalHeader.AddressOfEntryPoint;
        psection_header = (PIMAGE_SECTION_HEADER)((PBYTE)pnt_header32 + sizeof(IMAGE_NT_HEADERS32));
        base_addr = pnt_header32->OptionalHeader.ImageBase;
    }
    else if (64 == bits)
    {
        PIMAGE_NT_HEADERS64 pnt_header64 = (PIMAGE_NT_HEADERS64)pnt_header;
        entry = pnt_header64->OptionalHeader.AddressOfEntryPoint;
        psection_header = (PIMAGE_SECTION_HEADER)((PBYTE)pnt_header64 + sizeof(IMAGE_NT_HEADERS64));
        base_addr = pnt_header64->OptionalHeader.ImageBase;
    }


    /* get sections */
    for (size_t i = 0; i < sections_count; i++)
    {
        Section s;
        s.binary = this;
        auto sh = psection_header[i];
        s.name = (char *)sh.Name;
        s.size = sh.Misc.VirtualSize;
        s.bytes = bytes + sh.PointerToRawData;
        s.vma = sh.VirtualAddress;

        auto ch_code = sh.Characteristics;
        if (ch_code | IMAGE_SCN_CNT_CODE)
        {
            s.type = Section::SEC_TYPE_CODE;
        }
        else if (ch_code | IMAGE_SCN_CNT_INITIALIZED_DATA || ch_code | IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        {
            s.type = Section::SEC_TYPE_DATA;
        }
        else
        {
            s.type = Section::SEC_TYPE_NONE;
        }

        sections.push_back(s);
    }

    return 0;
}

/*
 *    ELF_Binary implementation
 */

ELF_Binary::ELF_Binary(std::string filename, uint8_t *bytes)
    : Binary(Binary::BinaryType::BIN_TYPE_ELF, filename, bytes)
{
}

ELF_Binary::~ELF_Binary()
{
}

int ELF_Binary::parse_bytes()
{
    Elf32_Ehdr *dummy_ehdr = (Elf32_Ehdr *)bytes;
    // e_machine is at the same offset in Elf32 and Elf64
    switch (dummy_ehdr->e_machine)
    {
    case EM_386:
        arch = BinaryArch::ARCH_X86;
        bits = 32;
        break;
    case EM_X86_64:
        arch = BinaryArch::ARCH_X86;
        bits = 64;
        break;
        // TODO: add other machin types
    }

    if (bits == 32)
    {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)bytes;
        entry = ehdr->e_entry;
    }
    else if (bits == 64)
    {
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)bytes;
        entry = ehdr->e_entry;
    }

    return 0;
}