#include <cstdio>
#include <cstring>
#include <inttypes.h>
#include <capstone/capstone.h>
#include "binary.h"
#include <iostream>
#include <filesystem>
#include <fstream>

int disasm(PBYTE code, size_t code_addr, uint64_t code_size)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
	{
		printf("CS_ERR: %d", cs_errno(handle));
		return -1;
	}

	count = cs_disasm(handle, code, code_size, code_addr, 0, &insn);
	if (count > 0)
	{
		size_t i;
		for (i = 0; i < count; i++)
		{
			auto ins = &insn[i];
			printf("0x%016I64X:\t", ins->address);
			for (int k = 0; k < 16; k++)
			{
				if (k < ins->size)
					printf("%02X ", ins->bytes[k]);
				else
					printf("   ");
			}
			printf("\t%s %s\n", ins->mnemonic, ins->op_str);
		}

		cs_free(insn, count);
	}
	else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

	return 0;
}

using namespace std;

int main(int argc, char *argv[])
{
	if (argc == 1)
	{
		printf("Usage: %s <file>", argv[0]);
		return 0;
	}

	auto filename = filesystem::path(argv[1]);
	auto abs_fname = filesystem::absolute(filename);

	Binary::BinaryType file_binary_type = detect_file_binary_type(abs_fname.generic_string());

	ifstream binary_file(abs_fname, ios::in | ios::binary);

	if (!binary_file)
	{
		cout << "No such file" << filename << endl;
		return 0;
	}

	binary_file.seekg(0, ios::end);
	auto filesize = binary_file.tellg();
	cout << "Filesize: " << filesize << "B" << endl;

	binary_file.seekg(0, ios::beg);
	auto buffer = (PBYTE)malloc(sizeof(BYTE) * filesize);
	binary_file.read((char *)buffer, filesize);

	Binary *binary;
	if (file_binary_type == Binary::BIN_TYPE_PE)
	{
		binary = new PE_Binary(abs_fname.generic_string(), buffer);
		cout << "Binary type: PE" << endl;
	}
	else if (file_binary_type == Binary::BIN_TYPE_ELF)
	{
		binary = new ELF_Binary(abs_fname.generic_string(), buffer);
		cout << "Binary type: ELF" << endl;
	}
	else
	{
		cout << "Unsupported binary type" << endl;
		return 0;
	}
	binary->parse_bytes();

	cout << "Parsing result: " << endl;
	cout << "Filename: " << binary->filename << endl;

	string arch_str;
	if (binary->arch == Binary::BinaryArch::ARCH_X86)
	{
		arch_str = "X86";
	}
	else
	{
		arch_str = "UKN";
	}
	cout << "Arch: " << arch_str << endl;

	printf("Entry: 0x%016I64X\n", binary->entry);

	int count = binary->symbols.size();
	printf("%d symbol%s found, symbols with name:\n", count, count > 1 ? "s" : "");
	for(auto &sym: binary->symbols) {
		if (!sym.name.empty()) {
			printf("0x%016I64X: %s\n", sym.addr, sym.name.c_str());
		}
	}

	for(auto section: binary->sections) {
		if (section.name == ".text") {
			cout << section.name << endl;

			disasm(section.bytes, binary->base_addr + section.vma, section.size);
		}
	}

	return 0;
}
