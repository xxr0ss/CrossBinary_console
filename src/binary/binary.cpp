#include "binary.h"

Binary::BinaryType detect_file_binary_type(std::filesystem::path filename)
{
    std::ifstream binary_file(filename, std::ios::in | std::ios::binary);
    char a_few_bytes[16];
    binary_file.read(a_few_bytes, sizeof(a_few_bytes));
    binary_file.close();

    char ELF_signature[] = {0x7F, 'E', 'L', 'F'};
    char PE_signature[] = {'M', 'Z'};

    if (!memcmp(a_few_bytes, ELF_signature, sizeof(ELF_signature)))
    {
        return Binary::BIN_TYPE_ELF;
    }
    else if (!memcmp(a_few_bytes, PE_signature, sizeof(PE_signature)))
    {
        return Binary::BIN_TYPE_PE;
    }

    return Binary::BIN_TYPE_RAW;
}

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
        if (ch_code & IMAGE_SCN_CNT_CODE)
        {
            s.type = Section::SEC_TYPE_CODE;
        }
        else if (ch_code & IMAGE_SCN_CNT_INITIALIZED_DATA || ch_code & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
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
    base_addr = 0;

    /* get arch and bits */
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

    /* get entry, sections, symbols */
    char *shstrtab = nullptr;
    char *strtab = nullptr;
    size_t sh_num;
    if (32 == bits)
    {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)bytes;
        entry = ehdr->e_entry;
        sh_num = ehdr->e_shnum;
        Elf32_Shdr *shdr = (Elf32_Shdr *)(bytes + ehdr->e_shoff);

        // get string table for the names for section headers
        for (size_t i = sh_num - 1; i >= 0; i--)
        {
            if (shdr[i].sh_type == SHT_STRTAB)
            {
                // assume the current one is the .shstrtab
                shstrtab = (char *)(bytes + shdr[i].sh_offset);
                if (std::string(&shstrtab[shdr[i].sh_name]) == ".shstrtab")
                {
                    break;
                }
            }
            // keep the shstrtab a nullptr when not found
            shstrtab = nullptr;
        }

        for (size_t i = 0; i < sh_num; i++)
        {
            Section s;
            s.binary = this;
            s.bytes = (uint8_t *)(bytes + shdr[i].sh_offset);
            if (shstrtab && shstrtab[shdr[i].sh_name])
            {
                s.name = &shstrtab[shdr[i].sh_name];
                if (!strtab && s.name == ".strtab")
                {
                    // get strtab
                    strtab = (char *)(bytes + shdr[i].sh_offset);
                }
            }
            else
            {
                s.name = "";
            }
            s.size = shdr[i].sh_size;
            s.vma = shdr[i].sh_addr;
            if (shdr[i].sh_type == SHT_PROGBITS)
            {
                s.type = Section::SEC_TYPE_CODE;
            }
            else if (shdr[i].sh_type == SHT_NULL)
            {
                s.type = Section::SEC_TYPE_NONE;
            }
            else
            {
                s.type = Section::SEC_TYPE_DATA;
            }
            sections.push_back(s);
        }

        if (strtab)
        {
            // there's no point looking for symbols if we do not have strtab
            Elf32_Sym *symtab = nullptr;
            size_t sym_count = 0;
            for (size_t i = sh_num - 1; i >= 0; i--)
            {
                if (shdr[i].sh_type != SHT_SYMTAB)
                    continue;

                symtab = (Elf32_Sym *)(bytes + shdr[i].sh_offset);
                sym_count = shdr[i].sh_size / sizeof(Elf32_Sym);

                for (int j = 0; j < sym_count; j++)
                {
                    Symbol sym;
                    if (symtab[j].st_name != 0)
                        sym.name = &strtab[symtab[j].st_name];
                    else
                        sym.name = "";

                    if (symtab[j].st_info & STT_FUNC)
                        sym.type = Symbol::SYM_TYPE_FUNC;
                    else
                        sym.type = Symbol::SYM_TYPE_UKN;

                    sym.addr = symtab[j].st_value;
                    symbols.push_back(sym);
                }

                break;
            }
        }
    }
    else if (64 == bits)
    {
        // refer to 32 bits for code comments
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)bytes;
        entry = ehdr->e_entry;
        sh_num = ehdr->e_shnum;
        Elf64_Shdr *shdr = (Elf64_Shdr *)(bytes + ehdr->e_shoff);

        for (size_t i = sh_num - 1; i >= 0; i--)
        {
            if (shdr[i].sh_type == SHT_STRTAB)
            {
                shstrtab = (char *)(bytes + shdr[i].sh_offset);
                if (std::string(&shstrtab[shdr[i].sh_name]) == ".shstrtab")
                {
                    break;
                }
            }
            shstrtab = nullptr;
        }

        for (size_t i = 0; i < sh_num; i++)
        {
            Section s;
            s.binary = this;
            s.bytes = (uint8_t *)(bytes + shdr[i].sh_offset);
            if (shstrtab && shstrtab[shdr[i].sh_name])
            {
                s.name = &shstrtab[shdr[i].sh_name];
                if (!strtab && s.name == ".strtab")
                {
                    strtab = (char *)(bytes + shdr[i].sh_offset);
                }
            }
            else
            {
                s.name = "";
            }
            s.size = shdr[i].sh_size;
            s.vma = shdr[i].sh_addr;
            if (shdr[i].sh_type == SHT_PROGBITS)
            {
                s.type = Section::SEC_TYPE_CODE;
            }
            else if (shdr[i].sh_type == SHT_NULL)
            {
                s.type = Section::SEC_TYPE_NONE;
            }
            else
            {
                s.type = Section::SEC_TYPE_DATA;
            }
            sections.push_back(s);
        }

        if (strtab)
        {
            Elf64_Sym *symtab = nullptr;
            size_t sym_count = 0;
            for (size_t i = sh_num - 1; i >= 0; i--)
            {
                if (shdr[i].sh_type != SHT_SYMTAB)
                    continue;

                symtab = (Elf64_Sym *)(bytes + shdr[i].sh_offset);
                sym_count = shdr[i].sh_size / sizeof(Elf64_Sym);

                for (int j = 0; j < sym_count; j++)
                {
                    Symbol sym;
                    if (symtab[j].st_name != 0)
                        sym.name = &strtab[symtab[j].st_name];
                    else
                        sym.name = "";

                    if (symtab[j].st_info & STT_FUNC)
                        sym.type = Symbol::SYM_TYPE_FUNC;
                    else
                        sym.type = Symbol::SYM_TYPE_UKN;

                    sym.addr = symtab[j].st_value;
                    symbols.push_back(sym);
                }

                break;
            }
        }
    }

    return 0;
}