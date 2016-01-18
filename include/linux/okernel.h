/* 
 * linux/include/linux/okernel.h
 * 
 * Copyright (C) 2015 - Chris Dalton (cid@hpe.com), HPE Corp.
 * Suport for splitting the kernel into inner and outer regions,
 * with the aim of achieving some degree of intra-kernel protection.
 * Processes marked as 'OKERNEL' run under vmx non-root mode (x86).
 * They enter the kernel in that mode too (outer-kernel mode) 
 * thus giving a (inner kernel - running in root-mode vmx on x86)
 * a control point where restrictions can be put in place, e.g. enforce
 * something like a vMMU interface, as in 'Nested Kernel', Dautenhahn,
 *  et al. 
 */

#ifndef _LINUX_OKERNEL_H
#define _LINUX_OKERNEL_H
#include <linux/compat.h>
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

#define OKERNEL_IOCTL_LAUNCH 1
#define OKERNEL_FORK_LAUNCH  2


#ifdef CONFIG_OKERNEL
#define VMCALL_NOP 0
#define VMCALL_SCHED 1
#define VMCALL_PREEMPT_SCHED 2
#define VMCALL_DOEXIT 3
#define VMCALL_DO_FORK_FIXUP 4
#define VMCALL_DO_EXEC_1 5 /* execve */
#define VMCALL_DO_EXEC_2 6 /* execveat */
#ifdef CONFIG_COMPAT
#define VMCALL_DO_EXEC_3 5 /* compat_execve */
#define VMCALL_DO_EXEC_4 6 /* compat_execveat */
#endif

int vmcall(unsigned int cmd);
int vmcall2(unsigned int cmd, unsigned long arg1);
int vmcall3(unsigned int cmd, unsigned long arg1, unsigned long arg2);
int vmcall4(unsigned int cmd, unsigned long arg1, unsigned long arg2, unsigned long arg3);
int vmcall5(unsigned int cmd, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4);
int vmcall6(unsigned int cmd, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

/* Keep these in here for now so that our dependencies are tracked until we find a better place */
void do_page_fault_r(struct pt_regs *regs, unsigned long error_code, unsigned long address);

int do_execve(struct filename *filename,
	      const char __user *const __user *__argv,
	      const char __user *const __user *__envp);

int do_execveat(int fd, struct filename *filename,
		const char __user *const __user *__argv,
		const char __user *const __user *__envp,
		int flags);

#ifdef CONFIG_COMPAT
int compat_do_execve(struct filename *filename,
		     const compat_uptr_t __user *__argv,
		     const compat_uptr_t __user *__envp);

int compat_do_execveat(int fd, struct filename *filename,
		       const compat_uptr_t __user *__argv,
		       const compat_uptr_t __user *__envp,
		       int flags);
#endif



#define HPE_DEBUG
#ifdef HPE_DEBUG
#define HDEBUG(args)  (printk(KERN_ERR "%s: cpu(%d) pid(%d) %s: ", vmx_nr_mode()?"NR":"R ", raw_smp_processor_id(), current->pid,__func__), printk args)
#else
#define HDEBUG(args) {}
#endif
//#define HPL_DEBUG2
#ifdef HPE_DEBUG2
#define HDEBUG2(args) (printk(KERN_ERR "%s: cpu(%d) pid(%d) %s: ", vmx_nr_mode()?"NR":"R ", raw_smp_processor_id(), current->pid,__func__), printk args)
#else
#define HDEBUG2(args) {}
#endif


#define HPE_BREAKPOINTS_ENABLED
#ifdef HPE_BREAKPOINTS_ENABLED
#define BXMAGICBREAK asm volatile("xchg %bx,%bx")
#define BXMAGICBREAK_ASM xchg %bx,%bx
#else
#define BXMAGICBREAK
#define BXMAGICBREAK_ASM
#endif






static inline bool vmx_nr_mode(void)
{
	unsigned long cr4;

	cr4 = native_read_cr4();
	
	if(cr4 & X86_CR4_VMXE)
		return false;
	return true;
}

int is_in_vmx_nr_mode(void);

static inline void break_in_nr_mode(void)
{
	if(is_in_vmx_nr_mode()){
		asm volatile("xchg %bx, %bx");
	}
}
extern int okernel_enabled;
int okernel_setup(int* vcpu);
//int okernel_enter(unsigned long flags, unsigned long rbp, unsigned long rsp);
int okernel_enter(unsigned long flags);
asmlinkage void __noclone okernel_enter_fork(void);
void okernel_enter_test(unsigned long flags);

void okernel_schedule_helper(void);
void okernel_dump_stack_info(void);
#endif 
#endif /* _LINUX_OKERNEL_H */
