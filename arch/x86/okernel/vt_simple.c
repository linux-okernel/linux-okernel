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

DEFINE_PER_CPU(struct vt_pcpu_data *, vt);
static struct vt_data vt_info;

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
  	    HDEBUG(("2ndry controls not available, e.g. no EPT.\n"));	    
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
	    HDEBUG(("EPT ctrl not supported.\n"));
	    return 0;
	}
	HDEBUG(("EPT feature supported.\n"));
	
	/* We could use EPT without UG or VPID support but this
	 * complicates the code quite a bit so for now we rquire EPT,
	 * UG and VPID. 
	 */
	if(!(proc_ctrls2 &  VMCS_PROC_BASED_VMEXEC_CTL2_UG_BIT)){
	    HDEBUG(("UG ctrl not supported.\n"));
	    return 0;
	}
	HDEBUG(("UG ctrl  supported.\n"));

	if(!(proc_ctrls2 & VMCS_PROC_BASED_VMEXEC_CTL2_VPID_BIT)){
	    HDEBUG(("vpid ctrl not supported.\n"));
	    return 0; 
	}
	HDEBUG(("vpid ctrl supported.\n"));

	if(!(proc_ctrls2 & VMCS_PROC_BASED_VMEXEC_CTL2_INVPCID_BIT)){
	    HDEBUG(("invpcid ctrl not supported.\n"));
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
