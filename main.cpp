#include <cstdio>
#include <cstring>
#include <inttypes.h>

#include <capstone/capstone.h>

#define CODE "\x48\x8B\x05\x4E\x83\x6E\x00"

int main(void)
{
	printf("Hello My capstone tool\n");
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
		printf("%d", cs_errno(handle));
		return -1;
	}

	printf("code_size: %llu\n", sizeof(CODE) - 1);
	count = cs_disasm(handle, (uint8_t*)CODE, sizeof(CODE) - 1, 0x1000, 0, &insn);
	if (count > 0) {
		size_t i;
		for (i = 0; i < count; i++) {
			auto ins = &insn[i];
			printf("0x%I64X:\t", ins->address);
			for(int k = 0; k < 16; k++){
				if(k < ins->size) printf("%02X ", ins->bytes[k]);
				else printf("   ");
			}
			printf("\t%s %s\n", ins->mnemonic, ins->op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

    return 0;
}
