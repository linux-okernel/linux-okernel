/*
 * Author: Nigel Edwards, 2017
 */

#include<linux/memory.h>
#include<linux/mm.h>
#include<asm-generic/sections.h>
#include<asm/text-patching.h>
#include<asm/set_memory.h>

extern int set_memory_rw(unsigned long addr, int numpages);
extern void flush_tlb_all(void);
extern void *text_poke(void *addr, const void *opcode, size_t len);
extern void flush_tlb_kernel_range(unsigned long start, unsigned long end);
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
}
EXPORT_SYMBOL_GPL(oktargets);

void okcheck_va(unsigned long va)
{
	pte_t *kpte;
	unsigned int level;
	pgprot_t prot;

	printk(KERN_INFO "oktest checking guest physical pg perms for va %#lx",
	       va);
	kpte = lookup_address(va, &level);
	if (!kpte){
		printk(KERN_CONT "address not found in guest page tables\n");
		return;
	}
	prot = pte_pgprot(*kpte);
	if (pgprot_val(prot) & pgprot_val(__pgprot(_PAGE_NX)))
		printk(KERN_CONT " NX is set");
	if (pgprot_val(prot) & pgprot_val(__pgprot(_PAGE_RW)))
		printk(KERN_CONT " RW is set");
}
EXPORT_SYMBOL_GPL(okcheck_va);

void okset_mem_rw(unsigned long va)
{	pte_t *kpte, old_pte, new_pte;
	unsigned int level;
	pgprot_t new_prot, old_prot;
	unsigned long pfn;

	/*
	unsigned long rodata_start = PFN_ALIGN(__start_rodata);
	unsigned long rodata_end = PFN_ALIGN(&__end_rodata);
	kernel_set_to_readonly = 0;
	set_memory_rw(rodata_start, (rodata_end - rodata_start) >> PAGE_SHIFT);
	*/
//	set_memory_rw(PFN_ALIGN(va), 1);
	kpte = lookup_address(va, &level);
	if (level != PG_LEVEL_4K) {
		printk(KERN_INFO "okset_mem_rw kpte va %#lx not 4k page\n", va);
	}
	if (!kpte){
		printk(KERN_INFO "okset_mem_rw kpte not found va %#lx\n", va);
		return;
	}
	old_pte = *kpte;
	if (pte_none(old_pte)) {
		printk(KERN_INFO "okset_mem_rw va %#lx not mapped?\n", va);
		return;
	}
	pfn = pte_pfn(old_pte);
	new_prot = pte_pgprot(old_pte);
	pgprot_val(new_prot) |= pgprot_val(__pgprot(_PAGE_RW));
	new_pte = pfn_pte(pfn, new_prot);
	set_pte_atomic(kpte, new_pte);
	return;
}
EXPORT_SYMBOL_GPL(okset_mem_rw);

