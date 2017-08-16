/*
 * Author: Nigel Edwards, 2017
 */

#include<linux/memory.h>
#include<linux/mm.h>
#include<asm-generic/sections.h>
#include<asm/text-patching.h>

extern int set_memory_rw(unsigned long addr, int numpages);
extern void *text_poke(void *addr, const void *opcode, size_t len);
void oktargets(unsigned long (*address)[])
{
	struct page *p;
	(*address)[0] = (unsigned long)_text;
	(*address)[1] = (unsigned long)_etext;
	(*address)[2] = (unsigned long)&__start_rodata;
	(*address)[3] = (unsigned long)&__end_rodata;
	(*address)[4] = (unsigned long)set_memory_rw;
	(*address)[5] = (unsigned long)linux_banner;
	(*address)[6] = (unsigned long)text_poke;
	(*address)[7] = (unsigned long)&text_mutex;
}

EXPORT_SYMBOL_GPL(oktargets);
