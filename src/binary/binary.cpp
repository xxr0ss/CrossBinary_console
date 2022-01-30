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

    if (bits = 32)
    {
        PIMAGE_NT_HEADERS32 pnt_header32 = (PIMAGE_NT_HEADERS32)pnt_header;
        entry = pnt_header32->OptionalHeader.AddressOfEntryPoint;
    }
    else if (bits = 64)
    {
        PIMAGE_NT_HEADERS64 pnt_header64 = (PIMAGE_NT_HEADERS64)pnt_header;
        entry = pnt_header64->OptionalHeader.AddressOfEntryPoint;
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