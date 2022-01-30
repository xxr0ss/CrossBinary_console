#include <cstdio>
#include <cstring>
#include <inttypes.h>
#include <capstone/capstone.h>
#include "binary.h"
#include <iostream>
#include <filesystem>
#include <fstream>


PE_Binary *pe;

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
			printf("0x%I64X:\t", ins->address);
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
	if (argc == 1) {
		printf("Usage: %s <file>", argv[0]);
		return 0;
	}

	
	auto filename = filesystem::path(argv[1]);
	auto abs_fname = filesystem::absolute(filename);

	ifstream binary_file(abs_fname, ios::in | ios::binary);

	if(!binary_file) {
		cout << "No such file" << filename << endl;
		return 0;
	}

	binary_file.seekg(0, ios::end);
	auto filesize = binary_file.tellg();
	cout << "filesize: " << filesize << "B" << endl;

	binary_file.seekg(0, ios::beg);
	auto buffer = (PBYTE)malloc(sizeof(BYTE) * filesize);
	binary_file.read((char*)buffer, filesize);

	pe = new PE_Binary(abs_fname.generic_string(), buffer);
	pe->parse_bytes();

	cout << "Parsing result: " << endl;
	cout << "filename: " << pe->filename << endl;
	
	string arch_str;
	if(pe->arch == Binary::BinaryArch::ARCH_X86) {
		arch_str = "X86";
	}else{
		arch_str = "UKN";
	}
	cout << "arch: " << arch_str << endl;

	printf("entry: 0x%016I64X\n", pe->entry);

	for(auto section: pe->sections) {
		if (section.type != Section::SEC_TYPE_CODE)
			continue;
		uint64_t delta = pe->entry - section.vma;
		printf("Disassembling range 0x%016I64X @+ 0x%016I64X\n", pe->base_addr + pe->entry, section.size - delta);
		disasm(section.bytes + delta, pe->base_addr + pe->entry, section.size - delta);
	}

	

	return 0;
}
