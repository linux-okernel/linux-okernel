/* 
 * Simpler version of vmx enabling based on bitvisor / existing labs code. 
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/okernel.h>

#include "constants.h"

#include "vmx-simple.h"


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

int __init vmx_init(void)
{
	
	HDEBUG(("Checking for vmx availability...\n"));
	if(check_vmx()){
		printk(KERN_ERR "okernel: VMX not available.\n");
		return -1;
	}
	HDEBUG(("VMX is available.\n"));
	return 0;
}
