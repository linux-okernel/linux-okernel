/* 
 * linux/include/linux/okernel.h
 * 
 * Copyright (C) 2015 - Chris Dalton (cid@hpe.com), HPE Corp.
 * Suport for splitting the kernel into inner and outer regions,
 * we the aim of achieving some degree of intra-kernel protection.
 * Processes marked as 'OKERNEL' run under vmx non-root mode (x86).
 * They enter the kernel in that mode too (outer-kernel mode) 
 * thus giving a (inner kernel - running in root-mode vmx on x86)
 * a control point where restrictions can be put in place, e.g. enforce
 * something like a vMMU interface, as in 'Nested Kernel', Dautenhahn,
 *  et al. 
 */

#ifndef _LINUX_OKERNEL_H
#define _LINUX_OKERNEL_H
#include <asm/special_insns.h>

/* 
 * Flags to control initial vmx non-root mode setup from user-space 
 * and subsequent scheduling / fork, etc. behaviour.  
 * Applies to task struct okernel entry for a process. By default, this
 * is set to OKERNEL_OFF. A userspace process can set the state to 
 * OKERNEL_ON_EXEC before exec'ing a program executable. Within the exec
 * handling in the kernel, this flag is checked to see whether to launch
 * the executable within a VMX container. Processes runnning within a 
 * VMX container have task->okernel set to OKERNEL_ACTIVE.
 *
 *
 * Set during okernel_init() at boot and used to gate access to /proc/<pid>/okernel
 * state setting,i.e. don't allow a process to be put in OKERNEL_ON_EXEC state if
 * the okernel functionality is not enabled.
 */
#define OKERNEL_OFF     0
#define OKERNEL_ON_EXEC 1
#define OKERNEL_ON      2


#ifdef CONFIG_OKERNEL
#define VMCALL_NOP 0
int vmcall(unsigned int cmd);

static inline bool vmx_nr_mode(void)
{
	unsigned long cr4;

	cr4 = native_read_cr4();
	
	if(cr4 & X86_CR4_VMXE)
		return false;
	return true;
}

int is_in_vmx_nr_mode(void);
extern int okernel_enabled;
int okernel_setup(int* vcpu);
void okernel_enter(int64_t *ret);

void okernel_schedule_helper(void);
void okernel_dump_stack_info(void);
#endif 
#endif /* _LINUX_OKERNEL_H */
