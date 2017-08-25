/*
 * Author: Nigel Edwards, 2017
 */

#include<linux/memory.h>
#include<linux/mm.h>
#include<linux/syscalls.h>
#include<asm-generic/sections.h>
#include<asm/text-patching.h>
#include<asm/set_memory.h>

extern int set_memory_rw(unsigned long addr, int numpages);
extern void flush_tlb_all(void);
extern void *text_poke(void *addr, const void *opcode, size_t len);
extern void flush_tlb_kernel_range(unsigned long start, unsigned long end);
extern pte_t *lookup_address(unsigned long, unsigned int *);
void oktargets(unsigned long (*address)[])
{
	(*address)[0] = (unsigned long)_text;
	(*address)[1] = (unsigned long)_etext;
	(*address)[2] = (unsigned long)&__start_rodata;
	(*address)[3] = (unsigned long)&__end_rodata;
	(*address)[4] = (unsigned long)set_memory_rw;
	(*address)[5] = (unsigned long)flush_tlb_all;
	(*address)[6] = (unsigned long)linux_proc_banner;
	(*address)[7] = (unsigned long)text_poke;
	(*address)[8] = (unsigned long)&text_mutex;
	(*address)[9] = (unsigned long)flush_tlb_kernel_range;
	(*address)[10] = (unsigned long)sys_unlinkat;
}
EXPORT_SYMBOL_GPL(oktargets);


