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

#include <asm/tlbflush.h>

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
	
	HDEBUG(("Setting VMXE in CR4...\n"));

        /* Make sure kernel shadow copy of cr4 updated too */
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


int vt_init(void)
{
	int cpu;
	
	HDEBUG(("Checking for vmx availability...\n"));
	if(check_vmx()){
		printk(KERN_ERR "okernel: VMX not available.\n");
		return -1;
	}
	HDEBUG(("VMX is available.\n"));

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
