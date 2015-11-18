/* 
 * Simpler version of vmx enabling based on bitvisor / existing labs code. 
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/okernel.h>


#include "constants.h"
#include "vt_asm.h"
#include "vt.h"



DEFINE_PER_CPU(unsigned long *, fred);
DEFINE_PER_CPU(struct vt_pcpu_data *, vt);





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
	return 0;
#if 0
	
	struct page* pg;
	struct vt_pcpu_data* vt;
		
	HDEBUG(("Allocating percpu page...\n"));

	if(!(pg = alloc_pages_exact_node(cpu_to_node(cpu), GFP_KERNEL, 0))){
		printk(KERN_ERR "okernel: failed to allocate per-cpu page for VT info.\n");
		return 0;
	}

	vt = page_address(pg);

	HDEBUG(("allocated kernel vaddr (%#lx) page (%lu)\n", (unsigned long)vt, (unsigned long)pg));

	memset(vt, 0, PAGE_SIZE);

	per_cpu(vt, cpu) = vt;

	HDEBUG(("Allocating per-cpu page...done. (%#lx)\n",
		(unsigned long)per_cpu(vt, cpu)));

	HDEBUG(("Allocating VMXON page...\n"));
	if(!(pg = alloc_pages_exact_node(cpu_to_node(cpu), GFP_KERNEL, 1))){
		printk(KERN_ERR "okernel: failed to allocate page for VMXON.\n");
		return 0;
	}
	HDEBUG(("Allocating VMXON page...done.\n"));


	HDEBUG(("Setting page in percpu data...\n"));	
	per_cpu(vt->vmxon_region_virt, cpu) = page_address(pg);
	per_cpu(vt->vmxon_region_phys, cpu) = __pa(page_address(pg));
	HDEBUG(("Setting page in percpu data (virt:%#lx phys:%#lx) ...done.\n",
		(unsigned long)per_cpu(vt->vmxon_region_virt, cpu),
		(unsigned long)per_cpu(vt->vmxon_region_phys, cpu)));
#endif
	return 1;
}

/* Enable VMX and do VMXON
   INPUT:
   vmxon_region_phys: physical address of VMXON region
   vmxon_region_virt: virtual address of VMXON region
   OUTPUT:
   vmcs_revision_identifier: VMCS revision identifier
*/
void
vt__vmxon (int cpu)
{
	return;
#if 0
	ulong cr0_0, cr0_1, cr4_0, cr4_1;
	ulong cr0, cr4;
	u32 *p;
	u32 dummy;
	u32 revision_id;

	
	/* apply FIXED bits */
	HDEBUG(("Applying fixed CR0,CR4 bits...\n"));
	asm_rdmsr (MSR_IA32_VMX_CR0_FIXED0, &cr0_0);
	asm_rdmsr (MSR_IA32_VMX_CR0_FIXED1, &cr0_1);
	asm_rdmsr (MSR_IA32_VMX_CR4_FIXED0, &cr4_0);
	asm_rdmsr (MSR_IA32_VMX_CR4_FIXED1, &cr4_1);
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
	HDEBUG(("Setting VMCE in CR4...\n"));
	asm_rdcr4 (&cr4);
	cr4 |= CR4_VMXE_BIT;
	asm_wrcr4 (cr4);
	HDEBUG(("Setting VMCE in CR4...done.\n"));

	/* write a VMCS revision identifier */
	HDEBUG(("Writing VMCS revision id...\n"));
	asm_rdmsr32 (MSR_IA32_VMX_BASIC, &revision_id, &dummy);

	
	per_cpu(vt->vmcs_revision_identifier, cpu) = revision_id;
	
	p = per_cpu(vt->vmxon_region_virt, cpu);
	*p = per_cpu(vt->vmcs_revision_identifier, cpu);
	HDEBUG(("Writing VMCS revision id...done.\n"));
	
	/* VMXON */
	HDEBUG(("Not Turning on VMXON (phys_addr: %#lx)\n",
		(unsigned long)per_cpu(vt->vmcs_region_phys, cpu)));
	//asm_vmxon (&currentcpu->vt.vmxon_region_phys);
	HDEBUG(("Not Turning on VMXON...done.\n"));
	return;
#endif
}

static struct vt_pcpu_data* vt_alloc_data(int cpu)
{

	int node = cpu_to_node(cpu);
	struct page *page;
	struct vt_pcpu_data *vt;

	HDEBUG(("Allocatin data and initializing...\n"));

	page = alloc_pages_exact_node(node, GFP_KERNEL, 0);

	if(!page)
		return NULL;

	vt = page_address(page);

	memset(vt, 0, PAGE_SIZE);

	HDEBUG(("Allocatin data and initializing...done.\n"));
	return vt;
}

int __init vt_init(void)
{
	int cpu;
	//unsigned long test_val = 0;
	
	HDEBUG(("Checking for vmx availability...\n"));
	if(check_vmx()){
		printk(KERN_ERR "okernel: VMX not available.\n");
		return -1;
	}
	HDEBUG(("VMX is available.\n"));

	/* We need to do this per-cpu */
#if 0
        for_each_possible_cpu(cpu) {
		struct vt_pcpu_data *vt;

		vt = vt_alloc_data(cpu);

		if(!vt){
			printk(KERN_ERR "okernel: Failed to alloc vt data.\n");
			return -ENOMEM;
		}
		HDEBUG(("Allocated vt data.\n"));
		per_cpu(vt, cpu) = vt;
		HDEBUG(("Set vt data per cpu.\n"));
	}
		       
#endif
#if 1
	for_each_possible_cpu(cpu) {
		unsigned long *p;
		unsigned long *q;
		struct page *pg;
		struct vt_pcpu_data* vt_p;

		HDEBUG(("Allocatin data and initializing...\n"));

		pg = alloc_pages_exact_node(cpu_to_node(cpu), GFP_KERNEL, 0);
		
		p = page_address(pg);

		if(!p){
			printk(KERN_ERR "okernel: Failed to alloc data.\n");
			return -ENOMEM;
		}
		HDEBUG(("Allocated p data.\n"));
		per_cpu(fred, cpu) = p;
		q = per_cpu(fred, cpu);

		*q = 2;

		HDEBUG(("Set data per cpu: %lu\n", *(per_cpu(fred, cpu))));

		
		HDEBUG(("Allocating percpu page...\n"));

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
		
	}
#endif
#if 1
	for_each_possible_cpu(cpu) {
		struct page *pg;
		struct vt_pcpu_data* vt_p;
		u64 *vaddr_p;
	
		HDEBUG(("Allocating percpu page...\n"));

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
		
		
		HDEBUG(("Setting page in percpu data (virt:%#lx phys:%#lx) ...done.\n",
			(unsigned long)vt_p->vmxon_region_virt,
			(unsigned long)vt_p->vmxon_region_phys));
		
	}
#endif
#if 0
	HDEBUG(("Entering root-mode vmx...\n"));
	for_each_possible_cpu(cpu) { 
		HDEBUG(("calling vt__vmx_init on cpu: %d\n", cpu));
		(void)vt__vmx_init(cpu);
		HDEBUG(("calling vt__vmxon on cpu: %d\n", cpu));
		vt__vmxon(cpu);
	}
	HDEBUG(("Now running in root-mode vmx.\n"));
#endif
	return 0;
}
