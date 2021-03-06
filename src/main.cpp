#include <cstdio>
#include <cstring>
#include <inttypes.h>
#include <capstone/capstone.h>
#include "binary.h"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <queue>
#include <map>

using namespace std;

void print_ins(cs_insn *ins)
{
	printf("0x%016I64x: ", ins->address);
	for (size_t i = 0; i < 16; i++)
	{
		if (i < ins->size)
			printf("%02x ", ins->bytes[i]);
		else
			printf("   ");
	}
	printf("%-12s %s\n", ins->mnemonic, ins->op_str);
}

bool is_cs_cflow_group(uint8_t g)
{
	return g == CS_GRP_JUMP || g == CS_GRP_CALL || g == CS_GRP_RET || g == CS_GRP_IRET;
}

bool is_cs_cflow_ins(cs_insn *ins)
{
	for (size_t i = 0; i < ins->detail->groups_count; i++)
	{
		if (is_cs_cflow_group(ins->detail->groups[i]))
			return true;
	}
	return false;
}

bool is_cs_unconditional_cflow_ins(cs_insn *ins)
{
	switch (ins->id)
	{
	case X86_INS_JMP:
	case X86_INS_LJMP:
	case X86_INS_RET:
	case X86_INS_RETF:
	case X86_INS_RETFQ:
		return true;
	default:
		return false;
	}
}

bool is_cs_ret_ins(cs_insn *ins)
{
	switch (ins->id)
	{
	case X86_INS_RET:
		return true;
	default:
		return false;
	}
}

address get_cs_ins_immediate_target(cs_insn *ins)
{
	cs_x86_op *cs_op;
	for (size_t i = 0; i < ins->detail->groups_count; i++)
	{
		if (is_cs_cflow_group(ins->detail->groups[i]))
		{
			for (size_t j = 0; j < ins->detail->x86.op_count; j++)
			{
				cs_op = &ins->detail->x86.operands[j];
				if (cs_op->type == X86_OP_IMM)
					return cs_op->imm;
			}
		}
	}
	return 0;
}

int disasm(Binary *bin)
{
	csh dis;

	Section *text = bin->get_text_section();
	if (!text)
	{
		fprintf(stderr, "Nothing to disassemble\n");
		return 0;
	}

	cs_mode mode = (cs_mode)(bin->bits >> 4);
	if (cs_open(CS_ARCH_X86, mode, &dis) != CS_ERR_OK)
	{
		fprintf(stderr, "Failed to open Capstone\n");
		return -1;
	}

	cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *cs_ins = cs_malloc(dis);
	if (!cs_ins)
	{
		fprintf(stderr, "Out of memory");
		cs_close(&dis);
		return -1;
	}

	queue<address> Q;

	// add all function symbol to Q
	address addr = bin->entry;
	if (text->contains(addr))
		Q.push(addr);
	for (auto &sym : bin->symbols)
	{
		if (sym.type == Symbol::SYM_TYPE_FUNC)
		{
			Q.push(sym.addr);
			printf("Function symbol: 0x%016I64x  %s\n", sym.addr, sym.name.c_str());
		}
	}

	map<address, bool> seen;
	while (!Q.empty())
	{
		addr = Q.front();
		Q.pop();
		if (seen[addr])
		{
			printf("Already seen addr 0x%016I64x, ignored", addr);
			continue;
		}

		offset off = addr - text->vma;
		const BYTE *pc = text->bytes + off;
		size_t n = text->size - off;

		while (cs_disasm_iter(dis, &pc, &n, &addr, cs_ins))
		{
			if (cs_ins->id == X86_INS_INVALID || cs_ins->size == 0)
			{
				break;
			}

			seen[cs_ins->address] = true;
			print_ins(cs_ins);

			if (is_cs_cflow_ins(cs_ins))
			{
				address target = get_cs_ins_immediate_target(cs_ins);
				if (target && !seen[target] && text->contains(target))
				{
					Q.push(target);
					printf(" -> new target: 0x%016llu\n", target);
				}
				if (is_cs_unconditional_cflow_ins(cs_ins))
				{
					break;
				}
			}
			else if (cs_ins->id == X86_INS_HLT)
				break;
		}
		printf("-------------\n");
	}

	cs_free(cs_ins, 1);
	cs_close(&dis);

	return 0;
}

int find_gadgets_at_root(Section *text, address root, map<string, vector<address>> *gadgets, csh dis)
{
	if (!text->contains(root))
		return -1;

	// we want to keep the gadget instructions simple,
	// so max inscount in a gadget is limited to max_gadgets_ins_count
	const size_t max_gadgets_ins_count = 5;
	const size_t x86_max_ins_bytes = 15;
	offset root_off = min(root - text->vma, max_gadgets_ins_count * x86_max_ins_bytes);

	cs_insn *ins = cs_malloc(dis);
	if (!ins)
	{
		fprintf(stderr, "Out of memory!");
		return -1;
	}

	size_t ins_count = 0;
	address start_addr = root - 1;
	while (ins_count < max_gadgets_ins_count)
	{
		address addr = start_addr;
		offset addr_off = addr - text->vma;
		const uint8_t *pc = text->bytes + addr_off;
		size_t rest_size = text->size - addr_off;
		string gadget_str = "";
		while (cs_disasm_iter(dis, &pc, &rest_size, &addr, ins))
		{
			if (ins->id == X86_INS_INVALID || ins->size == 0)
				break;
			if (ins->address > root)
				break;
			if (is_cs_cflow_ins(ins) && !is_cs_ret_ins(ins))
				break;
			
			gadget_str += string(ins->mnemonic) + " " + string(ins->op_str);
			if(ins->address == root) {
				(*gadgets)[gadget_str].push_back(addr_off);
				break;
			}

			gadget_str += "; ";
			ins_count ++;
		}
		start_addr --;
		if (start_addr < root - root_off)
			break;
	}
	cs_free(ins, 1);

	return 0;
}

int find_gadgets(Binary *bin)
{
	csh dis;
	map<string, vector<address>> gadgets;

	const uint8_t x86_opc_ret = 0xc3;

	Section *text = bin->get_text_section();
	if (!text)
	{
		fprintf(stderr, "Nothing to disassemble\n");
		return 0;
	}

	cs_mode mode = (cs_mode)(bin->bits >> 4);
	if (cs_open(CS_ARCH_X86, mode, &dis) != CS_ERR_OK)
	{
		fprintf(stderr, "Failed to open Capstone\n");
		return -1;
	}

	cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);

	for (size_t i = 0; i < text->size; i++)
	{
		if (text->bytes[i] == x86_opc_ret)
		{
			if (find_gadgets_at_root(text, text->vma + i, &gadgets, dis) < 0)
				break;
		}
	}

	for (auto &kv : gadgets)
	{
		printf("%s\t[ ", kv.first.c_str());
		for (auto addr : kv.second)
		{
			printf("0x%016I64x ", addr);
		}
		printf("]\n");
	}

	return 0;
}

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

	printf("Entry: 0x%016I64x\n", binary->entry);

	// disasm(binary);

	find_gadgets(binary);

	return 0;
}
