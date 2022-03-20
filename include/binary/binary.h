#ifndef BINARY_H
#define BINARY_H

#include <stdint.h>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include "m_elf.h"
#include "m_pe.h"

typedef uint64_t address, offset;
typedef uint8_t BYTE, *PBYTE;

class Binary;
class Section;
class Symbol;
class PE_Binary;
class ELF_Binary;


class Symbol
{
public:
    enum SymbolType
    {
        SYM_TYPE_UKN = 0,
        SYM_TYPE_FUNC = 1,
        SYM_TYPE_IMPORTED = 2,
        SYM_TYPE_EXPORTED = 4
    };

    Symbol() : type(SYM_TYPE_UKN), name(), addr(0) {}

    int type;
    std::string name;
    address addr;
};

typedef Symbol::SymbolType SymType;

class Section
{
public:
    enum SectionType
    {
        SEC_TYPE_NONE = 0,
        SEC_TYPE_CODE = 1,
        SEC_TYPE_DATA = 2
    };

    Section() : binary(NULL), type(SEC_TYPE_NONE), vma(0), size(0), bytes(NULL) {}

    bool contains(address addr) { return (addr >= vma) && (addr - vma < size); }

    Binary *binary;
    std::string name;
    SectionType type;
    address vma;
    uint64_t size;
    BYTE *bytes;
};

class Binary
{
public:
    enum BinaryType
    {
        BIN_TYPE_AUTO = 0,
        BIN_TYPE_RAW = 1,
        BIN_TYPE_ELF = 2,
        BIN_TYPE_PE = 3,
    };
    enum BinaryArch
    {
        ARCH_NONE = 0,
        ARCH_X86 = 1
    };

    Binary() : type(BIN_TYPE_AUTO), arch(ARCH_NONE), bits(0), entry(0), bytes(nullptr), base_addr(0) {}
    Binary(BinaryType type, std::string filename, BYTE *bytes) : type(type), filename(filename), bytes(bytes) {}
    virtual ~Binary()
    {
        if (bytes)
        {
            free(bytes);
            bytes = nullptr;
        }
    }

    /*
        read information from bytes, fill the rest uninitialized fields.
        and initialize other stuff in derived object according to the type
        return int to indicate the parsing result
    */
    virtual int parse_bytes() { return 0; };

    Section *get_text_section() {
        for(auto &s: sections) if(s.name == ".text") return &s; return NULL;
    }

    std::string filename;
    BinaryType type;
    BinaryArch arch;
    unsigned bits;
    address base_addr;
    address entry;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    BYTE *bytes;
};

class PE_Binary : public Binary
{
public:
    PE_Binary(std::string filename, BYTE *bytes);
    ~PE_Binary();

    int parse_bytes() override;
};

class ELF_Binary : public Binary
{
public:
    ELF_Binary(std::string filename, BYTE *bytes);
    ~ELF_Binary();

    int parse_bytes() override;

private:
    void elf32_init_sections();
    void elf64_init_sections();
};



Binary::BinaryType detect_file_binary_type(std::filesystem::path filename);


#endif /* BINARY_H */