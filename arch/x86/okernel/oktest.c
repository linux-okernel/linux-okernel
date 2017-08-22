/*
 * Author: Nigel Edwards, 2017
 */

#include<linux/memory.h>
#include<linux/mm.h>
#include<asm-generic/sections.h>
#include<asm/text-patching.h>

extern void *text_poke(void *addr, const void *opcode, size_t len);
void oktargets(unsigned long (*address)[])
{
	struct page *p;
	(*address)[0] = (unsigned long)_text;
	(*address)[1] = (unsigned long)_etext;
	(*address)[2] = (unsigned long)&__start_rodata;
	(*address)[3] = (unsigned long)&__end_rodata;
	(*address)[4] = (unsigned long)text_poke;
	(*address)[5] = (unsigned long)&text_mutex;
	(*address)[6] = (unsigned long)linux_banner;
	p = vmalloc_to_page((void *) linux_banner);
	printk("okernel linux_banner page is %#lx\n", (unsigned long) p);
	p = vmalloc_to_page((void *) &linux_banner);
	printk("okernel &linux_banner page is %#lx\n", (unsigned long) p);
	p = vmalloc_to_page((void *)text_poke);
	printk("okernel text_poke page is %#lx\n", (unsigned long) p);
	p = vmalloc_to_page((void *)_etext);
	printk("okernel _etext page is %#lx\n", (unsigned long) p);
	
}

EXPORT_SYMBOL_GPL(oktargets);
