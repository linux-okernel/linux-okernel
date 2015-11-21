/* 
 * Simpler version of vmx enabling based on bitvisor / existing labs code, with
 * some structuring / code based on KVM / dune.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/okernel.h>

#include <asm/tlbflush.h>
#include <asm/e820.h>

#include "constants.h"
#include "vt_asm.h"
#include "vt.h"
#include "vt_init.h"

DEFINE_PER_CPU(struct vt_pcpu_data *, vt);
static struct vt_data vt_info;
static u64 ept_phys = 0;

/* Need to fix this...adjust dynamically based on real physical regions */
#define END_PHYSICAL 0x3FFEFFFFF /* with 1GB physical memory */

static int
no_cache_region(u64 addr, u64 size)
{
	if (((addr >= 0) && (addr < 0x9F00))||((addr >= BIOS_END) && (addr < END_PHYSICAL))){
		return 0;
	}                                                                                                                                        return 1;
}

#if 0
static int
no_cache_region(u64 addr, u64 size)
{
        /*
         * Basic test to note whether an area of memory is normal,
         * usuable RAM or not. Used to setup the caching attributes
         * under EPT.
         */
        u32 n, nn;
        u64 base, len;
        u32 type;
        int ret = 1;

        n = 0;

        if(((BIOS_BEGIN >= addr) && (BIOS_BEGIN < addr+size)) || ((BIOS_BEGIN < addr) && (BIOS_END > addr))){
            /* Outside of what the BIOS e820 map tells us, avoid
             * caching 0xa0000 > 0x100000 - memmap will probably
             * report this as normal memory even though it usually
             * isn't (mapped adaptor ROMS, etc. Play safe and don't
             * cache.)
             */
            HDEBUG2(("found nocaching match for addr (%llX).\n", addr));
            return ret;
        }
        for (nn = 1; nn; n = nn) {
            nn = getfakesysmemmap (n, &base, &len, &type);

            if(((base >= addr) && (base < addr+size)) || ((base < addr) && ((base + len) > addr))){
                  if(type == SYSMEMMAP_TYPE_AVAILABLE){
                    ret = 0;
                    continue;
                  }
                  HDEBUG2(("found nocaching match for addr (%llX).\n", addr));
                  ret = 1;
                  return ret;
            }
        }
        return ret;
}
#endif

int vt_alloc_page(void **virt, u64 *phys)
{
	struct page *pg;
	void* v;
	
	pg = alloc_page(GFP_KERNEL);
	
	v = page_address(pg);

	if(!v){
		printk(KERN_ERR "okernel: failed to alloc page.\n");
		return 0;
	}

	if(virt)
		*virt = v;
	if(phys)
		*phys = page_to_phys(pg);
	return 1;
}

/* Check whether VMX is usable
   Return value:
   0:usable
   -1:unusable (disabled by BIOS Setup, or not supported) */
static int
check_vmx (void)
{
	u32 a, b, c, d;
	u64 tmp;

	/* 19.6 DISCOVERING SUPPORT FOR VMX */
	asm_cpuid (CPUID_1, 0, &a, &b, &c, &d);
	if (c & CPUID_1_ECX_VMX_BIT) {
		/* VMX operation is supported. */
	} else {
		printk(KERN_ERR "okernel: VMX operation is not supported.\n");
		return -1;
	}
	
	/* 19.7 ENABLING AND ENTERING VMX OPERATION */
msr_enable_loop:
	asm_rdmsr64 (MSR_IA32_FEATURE_CONTROL, &tmp);
	if (tmp & MSR_IA32_FEATURE_CONTROL_LOCK_BIT) {
		if (tmp & MSR_IA32_FEATURE_CONTROL_VMXON_BIT) {
			/* VMXON is enabled. */
			HDEBUG(("VMXON is enabled.\n"));
		} else {
			printk (KERN_ERR "okernel: VMXON is disabled.\n");
			return -1;
		}
	} else {
		HDEBUG(("Trying to enable VMXON.\n"));
		tmp |= MSR_IA32_FEATURE_CONTROL_VMXON_BIT;
		tmp |= MSR_IA32_FEATURE_CONTROL_LOCK_BIT;
		asm_wrmsr64 (MSR_IA32_FEATURE_CONTROL, tmp);
		goto msr_enable_loop;
	}

	return 0;
}

int
vt__vmx_init (int cpu)
{
	struct page *pg;
	struct vt_pcpu_data* vt_p;
	u64 *vaddr_p;
	u32 dummy, size;
	
	HDEBUG(("Allocating percpu page...\n"));

	/*
	  Check size of page required for vmxon + vmcs region: bits 44:32 (mask 0x1FFF).
	  Should be no greater than 4096. We want to assume it can fit in a single page.
	*/
	asm_rdmsr32 (MSR_IA32_VMX_BASIC, &dummy, &size);

	size = (size & 0x1fff);

	HDEBUG(("vmxon / vmcs region size (%u)\n", size));

	if(size > PAGE_SIZE){
		printk("okernel: vmxon/vmcs region size > PAGE_SIZE.\n");
		return -ENOMEM;
	}
	
	pg = alloc_pages_exact_node(cpu_to_node(cpu), GFP_KERNEL, 0);
	
	vt_p = page_address(pg);
	
	if(!vt_p){
		printk(KERN_ERR "okernel: failed to allocate per-cpu page for VT info.\n");
		return -ENOMEM;
	}
	
	HDEBUG(("allocated kernel vaddr (%#lx)\n", (unsigned long)vt_p));

	memset(vt_p, 0, PAGE_SIZE);
	per_cpu(vt, cpu) = vt_p;
	HDEBUG(("Allocating per-cpu page...done. (%#lx)\n",
		(unsigned long)per_cpu(vt, cpu)));
	
	HDEBUG(("Allocating VMXON page...\n"));
	if(!(pg = alloc_pages_exact_node(cpu_to_node(cpu), GFP_KERNEL, 0))){
		printk(KERN_ERR "okernel: failed to allocate page for VMXON.\n");
		return 0;
	}

	HDEBUG(("Allocating VMXON page...done.\n"));
	vaddr_p = page_address(pg);
	
	if(!vaddr_p){
		printk(KERN_ERR "okernel: failed to alloc vregion page.\n");
		return -ENOMEM;
	}
	
	HDEBUG(("Clearing vregion page...\n"));
	memset(vaddr_p, 0, PAGE_SIZE);
	HDEBUG(("Clearing vregion page...done.\n"));

	HDEBUG(("Setting page in percpu data vt...\n"));
	vt_p = per_cpu(vt, cpu);
	vt_p->vmxon_region_virt = (void*)vaddr_p;
	vt_p->vmxon_region_phys = __pa(vaddr_p);
	HDEBUG(("Set region(vp) percpu (virt:%#lx phys:%#lx)\n",
		(unsigned long)vt_p->vmxon_region_virt,
		(unsigned long)vt_p->vmxon_region_phys));
	return 1;
}

/* Enable VMX and do VMXON
   INPUT:
   vmxon_region_phys: physical address of VMXON region
   vmxon_region_virt: virtual address of VMXON region
   OUTPUT:
   vmcs_revision_identifier: VMCS revision identifier
*/
int
vt__vmxon (int cpu)
{
	ulong cr0_0, cr0_1, cr4_0, cr4_1;
	ulong cr0, cr4;
	u32 *p = NULL;
	u32 dummy;
	u32 revision_id;
	struct vt_pcpu_data *vt_p = NULL;
	
	
	/* apply FIXED bits */
	HDEBUG(("Applying fixed CR0,CR4 bits...\n"));
	asm_rdmsr (MSR_IA32_VMX_CR0_FIXED0, &cr0_0);

	HDEBUG(("CR0_0 FIXED: %#lx\n", cr0_0));
	asm_rdmsr (MSR_IA32_VMX_CR0_FIXED1, &cr0_1);
	HDEBUG(("CR0_1 FIXED: %#lx\n", cr0_1));
	asm_rdmsr (MSR_IA32_VMX_CR4_FIXED0, &cr4_0);
	HDEBUG(("CR4_0 FIXED: %#lx\n", cr4_0));
	asm_rdmsr (MSR_IA32_VMX_CR4_FIXED1, &cr4_1);
	HDEBUG(("CR4_1 FIXED: %#lx\n", cr4_1));
	asm_rdcr0 (&cr0);
	cr0 &= cr0_1;
	cr0 |= cr0_0;
	asm_wrcr0 (cr0);
	asm_rdcr4 (&cr4);
	cr4 &= cr4_1;
	cr4 |= cr4_0;
	asm_wrcr4 (cr4);
	HDEBUG(("Applying fixed CR0,CR4 bits...done.\n"));

	/* set VMXE bit to enable VMX */
        /* Make sure kernel shadow copy of cr4 updated too */	
	HDEBUG(("Setting VMXE in CR4...\n"));
	cr4_set_bits(X86_CR4_VMXE);
	HDEBUG(("Setting VMXE in CR4...done.\n"));

	/* write a VMCS revision identifier */
	HDEBUG(("Setting VMCS revision id...\n"));
	asm_rdmsr32 (MSR_IA32_VMX_BASIC, &revision_id, &dummy);
	HDEBUG(("Revision_id as read: %u\n", revision_id));
	       
	vt_p = per_cpu(vt, cpu);

	if(!vt_p){
		printk(KERN_ERR "Null VT data struct in percpu data.\n");
		return 0;
	}

	HDEBUG(("Writing VMCS revision id...\n"));
	vt_p->vmcs_revision_identifier = revision_id;
	HDEBUG(("Writing VMCS revision id...done\n"));
	HDEBUG(("Writing VMCS revision id to region_virt...\n"));

	p = (u32*)vt_p->vmxon_region_virt;

	if(!p){
		printk(KERN_ERR "Null region_virt in percpu data.\n");
		return 0;
	}

	HDEBUG(("percpu p value: %#lx\n", (unsigned long)p));
	*p = revision_id;
	HDEBUG(("set percpu revision id in region virt: %u\n", *p));

	/* VMXON */
	HDEBUG(("Turning on VMXON (phys_addr: %#lx) cpu(%d)\n",
		(unsigned long)vt_p->vmxon_region_phys, cpu));
	asm_vmxon (&vt_p->vmxon_region_phys);
	HDEBUG(("Turning on VMXON...done.\n"));
	return 1;
}

int 
vt_features_available(void)
{
	/* 
         * cid - find EPT/UG/VPID, etc. capabilities. Check bit 55 to see if
	 * allowed settings from proc ctrls are valid. May break down
	 * this into individual capabilities at some point.
	 */

	ulong basic = 0;
	u32   proc_ctrls_0  = 0;
	u32   proc_ctrls_1  = 0;
	ulong proc_ctrls2 = 0;
	ulong ept_msr  = 0;
	u32   exit_ctrls_0 = 0;
	u32   exit_ctrls_1 = 0;
	u32   entry_ctrls_0 = 0;
	u32   entry_ctrls_1 = 0;

	memset(&vt_info, 0, sizeof(vt_info));

	/* Check if IA32_VMX_TRUE_PROCBASED_CTLS supported */
	asm_rdmsr(MSR_IA32_VMX_BASIC, &basic);

	vt_info.vmx_basic = basic;
	
	if(basic & MSR_IA32_VMX_BASIC_TRUE_MSR_BIT){
		HDEBUG(("IA32_VMX_BASIC_TRUE_MSR supported.\n"));
		asm_rdmsr32(MSR_IA32_VMX_TRUE_PROCBASED_CTLS, &proc_ctrls_0, &proc_ctrls_1);
		asm_rdmsr32(MSR_IA32_VMX_TRUE_EXIT_CTLS, &exit_ctrls_0, &exit_ctrls_1);
		asm_rdmsr32 (MSR_IA32_VMX_TRUE_ENTRY_CTLS, &entry_ctrls_0, &entry_ctrls_1);
	} else {
		HDEBUG(("IA32_VMX_BASIC_TRUE_MSR not supported.\n"));
		asm_rdmsr32(MSR_IA32_VMX_PROCBASED_CTLS, &proc_ctrls_0, &proc_ctrls_1);
		asm_rdmsr32(MSR_IA32_VMX_EXIT_CTLS, &exit_ctrls_0, &exit_ctrls_1);
		asm_rdmsr32(MSR_IA32_VMX_ENTRY_CTLS, &entry_ctrls_0, &entry_ctrls_1);
	}

	vt_info.vmx_proc_ctrls_0 = proc_ctrls_0;
	vt_info.vmx_proc_ctrls_1 = proc_ctrls_1;
	
	if(!(proc_ctrls_1 & VMCS_PROC_BASED_VMEXEC_CTL_ENABLE_2NDRY_BIT)){
		printk(KERN_ERR "okernel: 2ndry controls not available, e.g. no EPT.\n");	    
		return 0;
	}
	
	HDEBUG(("2ndry proc based controls can be enabled.\n"));
	asm_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2, &proc_ctrls2);
	HDEBUG(("2ndry proc based ctrls: %lX\n", proc_ctrls2));

	vt_info.vmx_proc_ctrls2 = proc_ctrls2;
	
	// bottom 32 bits are allowed 0 settings - always 0. Top
	// 32 are allowed 1 settings so we check against these.
	proc_ctrls2 = proc_ctrls2 >> 32;
	HDEBUG(("2ndary ctrls allowed 1 settings: %lX\n", proc_ctrls2));

	if(!(proc_ctrls2 & VMCS_PROC_BASED_VMEXEC_CTL2_EPT_BIT)){
		printk(KERN_ERR "okernelL EPT ctrl not supported.\n");
		return 0;
	}
	HDEBUG(("EPT feature supported.\n"));
	
	/* We could use EPT without UG or VPID support but this
	 * complicates the code quite a bit so for now we rquire EPT,
	 * UG and VPID. 
	 */
	if(!(proc_ctrls2 &  VMCS_PROC_BASED_VMEXEC_CTL2_UG_BIT)){
		printk(KERN_ERR "okernel: UG ctrl not supported.\n");
		return 0;
	}
	HDEBUG(("UG ctrl  supported.\n"));

	if(!(proc_ctrls2 & VMCS_PROC_BASED_VMEXEC_CTL2_VPID_BIT)){
		printk(KERN_ERR "vpid ctrl not supported.\n");
		return 0; 
	}
	HDEBUG(("vpid ctrl supported.\n"));

	if(!(proc_ctrls2 & VMCS_PROC_BASED_VMEXEC_CTL2_INVPCID_BIT)){
		printk(KERN_ERR "okernel: invpcid ctrl not supported.\n");
		return 0; 
	}
	HDEBUG(("invpcid  ctrl supported.\n"));

	/* Optional */
	HDEBUG(("Check for optional features:\n"));
	if((proc_ctrls2 & VMCS_PROC_BASED_VMEXEC_CTL2_VMFUNC_BIT)){
		vt_info.vmfunc_support = true;
		HDEBUG(("vmfunc ctrl supported.\n"));
	}
	
	if((proc_ctrls2 & VMCS_PROC_BASED_VMEXEC_CTL2_EPTVIOL_BIT)){
		vt_info.eptviol_support = true;
		HDEBUG(("EPTVIOL ctrl supported.\n"));
	}

	/* Detailed EPT support */
	HDEBUG(("Check for detailed EPT support:\n"));
	asm_rdmsr(MSR_IA32_VMX_EPT_VPID_CAP, &ept_msr);
	vt_info.vmx_ept_msr = ept_msr;

	HDEBUG(("vmx EPT msr  : %lX\n", ept_msr));
	
	if(ept_msr & VMCS_EPT_XO){
		HDEBUG(("EPT XO supported.\n"));
	}
	if(ept_msr & VMCS_EPT_PW4){
		HDEBUG(("EPT PW4 supported.\n"));
	}
	if(ept_msr & VMCS_EPT_UC){
		HDEBUG(("EPT XC supported.\n"));
	}
	if(ept_msr & VMCS_EPT_WB){
		HDEBUG(("EPT WB supported.\n"));
	}
	
	if(ept_msr & VMCS_EPT_2MB){
		HDEBUG(("EPT 2MB supported.\n"));
	} else {
		printk(KERN_ERR "okernel: need at least 2MB EPT pages to be supported.\n");
		return 0;
	}
	
	if(ept_msr & VMCS_EPT_1GB){
		HDEBUG(("EPT 1GB supported.\n"));
	}
	if(ept_msr & VMCS_EPT_INVEPT){
		HDEBUG(("EPT INVEPT supported.\n"));
	}
	if(ept_msr & VMCS_EPT_ADEPT){
		HDEBUG(("EPT DEPT supported.\n"));
	}
	if(ept_msr & VMCS_EPT_IEPTS){
		HDEBUG(("EPT IEPTS supported.\n"));
	}
	if(ept_msr & VMCS_EPT_IEPTA){
		HDEBUG(("EPT IEPTA supported.\n"));
	}
	if(ept_msr & VMCS_EPT_INVPID){
		HDEBUG(("EPT INVPID supported.\n"));
	}
	if(ept_msr & VMCS_EPT_INVPIDI){
		HDEBUG(("EPT INVPIDI supported.\n"));
	}
	if(ept_msr & VMCS_EPT_INVPIDS){
		HDEBUG(("EPT INVPIDS supported.\n"));
	}
	if(ept_msr & VMCS_EPT_INVPIDA){
		HDEBUG(("EPT INVPIDA supported.\n"));
	}
	if(ept_msr & VMCS_EPT_INVPIDG){
		HDEBUG(("EPT INVPIDG supported.\n"));
	}

	/* Also check required vmexit / vmentry controls */
	HDEBUG(("exit ctrls allowed 0 (%X) allowed 1 (%X)\n", exit_ctrls_0, exit_ctrls_1));
	HDEBUG(("entry ctrls allowed 0 (%X) allowed 1 (%X)\n", entry_ctrls_0, entry_ctrls_1));
	
	if(!(exit_ctrls_1 & VMCS_EXIT_CTL_LOAD_IA32EFER)){
		printk(KERN_ERR "load_efer vm exit control not supported.\n");
		return 0;
	}
	HDEBUG(("load_efer vm exit control supported.\n"));

	if(!(exit_ctrls_1 & VMCS_EXIT_CTL_SAVE_IA32EFER)){
		printk(KERN_ERR "save_efer vm exit control not supported.\n");
		return 0;
	}
	HDEBUG(("save_efer vm exit control supported.\n"));

	if(!(entry_ctrls_1 & VMCS_ENTRY_CTL_LOAD_IA32EFER)){
		printk(KERN_ERR "load_efer vm entry control not supported.\n");
		return 0;
	}
	HDEBUG(("load_efer vm entry control supported.\n"));
	
	vt_info.vmexit_ctrls_0 = exit_ctrls_0;
	vt_info.vmexit_ctrls_1 = exit_ctrls_1;
	vt_info.vmentry_ctrls_0 = entry_ctrls_0;
	vt_info.vmentry_ctrls_1 = entry_ctrls_1;
	return 1;
}


/* Adapted from e820_end_pfn */
static unsigned long e820_end_paddr(unsigned long limit_pfn)
{
	int i;
	unsigned long last_pfn = 0;
	unsigned long max_arch_pfn = (MAXMEM >> PAGE_SHIFT);

	for (i = 0; i < e820.nr_map; i++) {
		struct e820entry *ei = &e820.map[i];
		unsigned long start_pfn;
		unsigned long end_pfn;

		start_pfn = ei->addr >> PAGE_SHIFT;
		end_pfn = (ei->addr + ei->size) >> PAGE_SHIFT;

		if (start_pfn >= limit_pfn)
			continue;
		if (end_pfn > limit_pfn) {
			last_pfn = limit_pfn;
			break;
		}
		if (end_pfn > last_pfn)
			last_pfn = end_pfn;
	}

	if (last_pfn > max_arch_pfn)
		last_pfn = max_arch_pfn;

	HDEBUG(("last_pfn = %#lx max_arch_pfn = %#lx\n", last_pfn, max_arch_pfn));
	return last_pfn << PAGE_SHIFT;
}

u64 vt_ept_init(void)
{
	/*
	 * For now share a direct 1:1 EPT mapping of host physical to
	 * guest physical across all vmx 'containers'. 
	 *
	 * Setup the per-vcpu pagetables here. For now we just map up to
	 * 512G of physical RAM, and we use a 2MB page size. So we need
	 * one PML4 physical page, one PDPT physical page and 1 PD
	 * physical page per GB.  We need correspondingly, 1 PML4 entry
	 * (PML4E), 1 PDPT entrie per GB (PDPTE), and 512 PD entries
	 * (PDE) per PD.
	 *
	 * The first 2Mb region we break down into 4K page table entries
	 * so we can be more selectively over caching controls, etc. for
	 * that region.
	 */
	unsigned long mappingsize = 0;      
	unsigned long rounded_mappingsize = 0;
	unsigned int n_entries = PAGESIZE / 8; 
	unsigned int n_pt   = 0;
	unsigned int n_pd   = 0;
	unsigned int n_pdpt = 0;
	pt_page* pt = NULL;
	pt_page* pd = NULL;
	pt_page* pdpt = NULL;
	int i = 0, k = 0;
	u64* q = NULL;
	u64 addr = 0;
	u64* pml4_virt = NULL;
	u64  pml4_phys = 0;
	
	/* What range do the EPT tables need to cover (including areas like the APIC mapping)? */
	mappingsize = e820_end_paddr(MAXMEM);

	HDEBUG(("max physical address to map under EPT: %#lx\n", (unsigned long)mappingsize));
	
	/* Round upp to closest Gigabyte of memory */
	rounded_mappingsize = ((mappingsize + (GIGABYTE-1)) & (~(GIGABYTE-1)));      

	HDEBUG(("Need EPT tables covering (%lu) Mb (%lu) bytes for Phys Mapping sz: %lu MB\n", 
		rounded_mappingsize >> 20, rounded_mappingsize, mappingsize >> 20));

	if((rounded_mappingsize >> GIGABYTE_SHIFT) >  PML4E_MAP_LIMIT){
		/* Only setup one PDPTE entry for now so can map up to 512Gb */
		printk(KERN_ERR "Physical memory greater than (%d) Gb not supported.\n",
		       PML4E_MAP_LIMIT);
		return 0;
	}

	/* Only need 1 pdpt to map upto 512G */
	n_pdpt = 1;
	/* Need 1 PD per gigabyte of physical mem */
	n_pd = rounded_mappingsize >> GIGABYTE_SHIFT;
	/* We just split the 1st 2Mb region into 4K pages so need only 1 PT table. */
	n_pt = 1;
	
	/* pt - PML1, pd - PML2, pdpt - PML3 */
	pdpt = (pt_page*)kmalloc(sizeof(pt_page)* n_pdpt, GFP_KERNEL);
	pd   = (pt_page*)kmalloc(sizeof(pt_page)* n_pd, GFP_KERNEL);
	pt   = (pt_page*)kmalloc(sizeof(pt_page)* n_pt, GFP_KERNEL);
	
	HDEBUG(("Allocated (%u) pdpt (%u) pd (%u) pt tables.\n", n_pdpt, n_pd, n_pt));

        /* Allocate the paging structures from bottom to top so we start
	 * at the PT level (PML1) and finish with the PML4 table.
	 */
	
	/* 1st 2Meg mapping (PML1 / PT):
	 * At the moment we only use a PT for the 1st 2MB region, for
	 * the rest of memory we map in via 2MB PD entries. We break
	 * first 2M region into 4k pages so that we can use the CPU
	 * cache in real-mode otherwise we end up with UC memory for the
	 * whole 2M.
	 */

	BUG_ON(n_pt != 1);
	
	/* XXXX todo cid: recheck on the caching bits / ipat bit and when they should be set. */
	/* This is the 0-2MB first set of mappings which we break into 4K PTEs*/
	for(i = 0; i < n_pt; i++){
		if(!(vt_alloc_page((void**)&pt[i].virt, &pt[i].phys))){
			printk(KERN_ERR "okernel: failed to allocate PML1 table.\n");
			return 0;
		}
		memset(pt[i].virt, 0, PAGESIZE);
		HDEBUG(("n=(%d) PML1 pt virt (%llX) pt phys (%llX)\n", i, (unsigned long long)pt[i].virt, pt[i].phys));
	}

	q = pt[0].virt;

	for(i = 0; i < n_entries; i++){
		addr = i << 12;
		if(no_cache_region(addr, PAGESIZE)){
			q[i] = (i << 12) | EPT_R | EPT_W | EPT_X;
		} else {
			q[i] = (i << 12) | EPT_R | EPT_W | EPT_X | EPT_CACHE_2 | EPT_CACHE_3;
		}
	}
	
        /* Now the PD (PML2) tables (plug the pt[0] entry back in later) */
	for(i = 0; i < n_pd; i++){
		if(!(vt_alloc_page((void**)&pd[i].virt, &pd[i].phys))){
			printk(KERN_ERR "okernel: failed to allocate PML2 tables.\n");
			return 0;
		}
		memset(pd[i].virt, 0, PAGESIZE);
		HDEBUG(("n=(%d) PML2 pd virt (%llX) pd phys (%llX)\n", i, (unsigned long long)pd[i].virt, pd[i].phys));
	}
	/* XXXX todo cid: recheck correct CACHE / IPAT attribute setting. */
	for(k = 0; k < n_pd; k++){
		q = pd[k].virt;
		for(i = 0; i < n_entries; i++){
			addr = ((i + k*n_entries) << 21);
			if(no_cache_region(addr,  PAGESIZE2M)){
				q[i] = ((i + k*n_entries) << 21) | EPT_R | EPT_W | EPT_X | EPT_2M_PAGE;
			} else {
				q[i] = ((i + k*n_entries) << 21) | EPT_R | EPT_W | EPT_X | EPT_2M_PAGE | EPT_CACHE_2 | EPT_CACHE_3;
			}
		}
	}

	/* Point just the PD entry covering the 1st 2Mb region to the PT we set
	 * up earlier. The rest of the PD entries directly map a 2Mb
	 * page entry, not a PT table. 
	 */
	q = pd[0].virt;
	q[0] = pt[0].phys + EPT_R + EPT_W + EPT_X;


	/* Now the PDPT (PML3) tables */
	for(i = 0; i < n_pdpt; i++){
		if(!(vt_alloc_page((void**)&pdpt[i].virt, &pdpt[i].phys))){
			printk(KERN_ERR "okernel: failed to allocate PML3 tables.\n");
			return 0;
		}
		memset(pdpt[i].virt, 0, PAGESIZE);
		HDEBUG(("n=(%d) PML3 pdpt virt (%llX) pdpt phys (%llX)\n",
			i, (u64)pdpt[i].virt, pdpt[i].phys));
	}
	/* And link to the PD (PML2) tables created earlier...*/
       for(k = 0; k < n_pdpt; k++){
	    q = pdpt[k].virt;
	    for(i = 0; i < n_pd; i++){
		// These are the PDPTE entries - just 4 at present to map 4GB
		q[i] = pd[i].phys + EPT_R + EPT_W + EPT_X;
	    }
       }

       /* Finally create the PML4 table that is the root of the EPT tables (VMCS EPTRTR field) */
       if(!(vt_alloc_page((void**)&pml4_virt, &pml4_phys))){
	       printk(KERN_ERR "okernel: failed to allocate PML4 table.\n");
	       return 0;
       }
       
       memset(pml4_virt, 0, PAGESIZE);
       q = pml4_virt;
       
       /* Link to the PDPT table above.These are the PML4E entries - just one at present */
       for(i = 0; i < n_pdpt; i++){
	    q[i] = pdpt[i].phys + EPT_R + EPT_W + EPT_X;
       }
       
       HDEBUG(("PML4 plm4_virt (%#lx) *plm4_virt (%#lx) pml4_phys (%#lx)\n", 
	       (unsigned long)pml4_virt, (unsigned long)*pml4_virt,
	       (unsigned long)pml4_phys));
	
       return pml4_phys;
}



int vt_init(void)
{
	int cpu;
	
	HDEBUG(("Checking for vmx availability...\n"));
	if(check_vmx()){
		printk(KERN_ERR "okernel: VMX not available.\n");
		return -1;
	}
	
	HDEBUG(("VMX is available.\n"));

	if(!vt_features_available()){
		printk(KERN_ERR "okernel: required VT EPT, etc. support not available.\n");
		return -1;
	}

	HDEBUG(("EPT and supporting features are available.\n"));

	/* Setup direct 1:1 EPT host to 'guest' physical memory which
	   we share across all 'containerized' processes for now.
	 */
	if(!(ept_phys= vt_ept_init())){
		printk(KERN_ERR "Initial EPT direct map setup failed.\n");
		return -1;
	}

	HDEBUG(("Allocate EPT root phys: %#lx\n", (unsigned long)ept_phys)); 
	
	/* We need to do this per-cpu */
	HDEBUG(("Entering root-mode vmx...\n"));
	for_each_possible_cpu(cpu) { 
		HDEBUG(("calling vt__vmx_init on cpu: %d\n", cpu));
		(void)vt__vmx_init(cpu);
		HDEBUG(("calling vt__vmxon on cpu: %d\n", cpu));
		vt__vmxon(cpu);
	}
	HDEBUG(("Now running in root-mode vmx.\n"));
	return 0;
}
