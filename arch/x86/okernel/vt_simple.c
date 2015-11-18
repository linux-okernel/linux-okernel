/* 
 * Simpler version of vmx enabling based on bitvisor / existing labs code. 
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/okernel.h>

#include "constants.h"

#include "vt_simple.h"


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

void
vt__vmx_init (void)
{
	/* Original - replace with linux alternative:
	void *v;
	u64 p;

	

	if (alloc_page (&v, &p) < 0)
		panic ("Fatal error: vt__vmx_init: alloc_page failed.");
	currentcpu->vt.vmxon_region_virt = v;
	currentcpu->vt.vmxon_region_phys = p;
	*/
	return;
}

/* Enable VMX and do VMXON
   INPUT:
   vmxon_region_phys: physical address of VMXON region
   vmxon_region_virt: virtual address of VMXON region
   OUTPUT:
   vmcs_revision_identifier: VMCS revision identifier
*/
void
vt__vmxon (void)
{
	return;

#if 0
	// Original
	ulong cr0_0, cr0_1, cr4_0, cr4_1;
	ulong cr0, cr4;
	u32 *p;
	u32 dummy;

	/* apply FIXED bits */
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

	/* set VMXE bit to enable VMX */
	asm_rdcr4 (&cr4);
	cr4 |= CR4_VMXE_BIT;
	asm_wrcr4 (cr4);

	/* write a VMCS revision identifier */
	asm_rdmsr32 (MSR_IA32_VMX_BASIC,
		     &currentcpu->vt.vmcs_revision_identifier, &dummy);
	p = currentcpu->vt.vmxon_region_virt;
	*p = currentcpu->vt.vmcs_revision_identifier;

	/* VMXON */
	asm_vmxon (&currentcpu->vt.vmxon_region_phys);
#endif
}

int __init vt_init(void)
{
	
	HDEBUG(("Checking for vmx availability...\n"));
	if(check_vmx()){
		printk(KERN_ERR "okernel: VMX not available.\n");
		return -1;
	}
	HDEBUG(("VMX is available.\n"));
	vt__vmx_init();
	vt__vmxon();
	return 0;
}
