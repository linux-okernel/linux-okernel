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
#include <asm/percpu.h>

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
#define OKERNEL_ON      1
#define OKERNEL_ON_EXEC 2

#define OKERNEL_IOCTL_LAUNCH 1
#define OKERNEL_FORK_LAUNCH  2


#ifdef CONFIG_OKERNEL
#define VMCALL_NOP 0
#define VMCALL_SCHED 1
#define VMCALL_PREEMPT_SCHED 2
#define VMCALL_DOEXIT 3
#define VMCALL_DO_FORK_FIXUP 4
#define VMCALL_DO_GET_CPU_HELPER 5
#define VMCALL_DO_EXEC_FIXUP_HOST 10
#define VMCALL_DO_TLS_FIXUP 11

#define OK_SCHED         1
#define OK_SCHED_PREEMPT 2


int vmcall(unsigned int cmd);
int vmcall2(unsigned int cmd, unsigned long arg1);
int vmcall3(unsigned int cmd, unsigned long arg1, unsigned long arg2);
int vmcall4(unsigned int cmd, unsigned long arg1, unsigned long arg2, unsigned long arg3);
int vmcall5(unsigned int cmd, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4);
int vmcall6(unsigned int cmd, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

/* Keep these in here for now so that our dependencies are tracked until we find a better place */
void do_page_fault_r(struct pt_regs *regs, unsigned long error_code, unsigned long address);


/* Enforce rudimentary protected interface */
#define OKERNEL_PROTECTED_MEMORY
extern struct page_ext_operations page_okernel_ops;

struct protected_data {
        /* This is a physical address we will ask the kernel vuln module to
           access.
        */
        unsigned long p_addr;
        /*
           This should be a pointer to a PAGESIZE buffer. The kernel vuln module
           will try and copy the data from the given physical address into this
           buffer.
        */
        char *p_data;
};
extern unsigned long ok_protected_pfn_start;
extern unsigned long ok_protected_pfn_end;
struct page *ok_alloc_protected_page(void);
int ok_free_protected_page(struct page *pg);


/* Use trace_printk instead of printk */
#define HPE_LOOP_DETECT
#//define HPE_LOG
#ifdef HPE_LOG
#define HLOG(fmt, args...)  trace_printk( KERN_ERR "%s: cpu(%d) pid(%d) %s: "\
					  fmt , vmx_nr_mode()?"NR":"R ", \
					  raw_smp_processor_id(), \
					  current->pid,__func__, ## args)
#else
#define HLOG(fmt, args...)
#endif
//#define HPE_DEBUG
#ifdef HPE_DEBUG
#define HDEBUG(fmt, args...)  trace_printk( KERN_ERR "%s: cpu(%d) pid(%d) %s: " fmt , vmx_nr_mode()?"NR":"R ", raw_smp_processor_id(), current->pid,__func__, ## args)
//#define HDEBUG(fmt, args...)  printk( KERN_ERR "%s: cpu(%d) pid(%d) %s: " fmt , vmx_nr_mode()?"NR":"R ", raw_smp_processor_id(), current->pid,__func__, ## args)
#else
#define HDEBUG(fmt, args...)
#endif
//#define HPE_DEBUG2
#ifdef HPE_DEBUG2
#define HDEBUG2(fmt, args...) trace_printk( KERN_ERR "%s: cpu(%d) pid(%d) %s: " fmt, vmx_nr_mode()?"NR":"R ", raw_smp_processor_id(), current->pid,__func__, ## args)
#else
#define HDEBUG2(fmt, args...)
#endif
//#define HPE_DEBUG3
#ifdef HPE_DEBUG3
#define HDEBUG3(fmt, args...) trace_printk( KERN_ERR "%s: cpu(%d) pid(%d) %s: " fmt, vmx_nr_mode()?"NR":"R ", raw_smp_processor_id(), current->pid,__func__, ## args)
#else
#define HDEBUG3(fmt, args...)
#endif



//#define HPE_BREAKPOINTS_ENABLED
#ifdef HPE_BREAKPOINTS_ENABLED
#define BXMAGICBREAK asm volatile("xchg %bx,%bx")
#define BXMAGICBREAK_ASM xchg %bx,%bx
#else
#define BXMAGICBREAK
#define BXMAGICBREAK_ASM
#endif


DECLARE_PER_CPU(int, __nr_mode);
DECLARE_PER_CPU(int, __r_mode);



static inline bool vmx_nr_mode(void)
{
	unsigned long cr4;

	cr4 = native_read_cr4();

	if(cr4 & X86_CR4_VMXE)
		return false;
	return true;
}

static inline void set_vmx_r_mode(void)
{
	raw_cpu_write_4(__r_mode, 1);
}

static inline void unset_vmx_r_mode(void)
{
	raw_cpu_write_4(__r_mode, 0);
}

static inline bool vmx_r_mode(void)
{
	return raw_cpu_read_4(__r_mode);
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
asmlinkage void okernel_ret_from_fork(void);
void okernel_enter_test(unsigned long flags);

void okernel_schedule_helper(void);
void okernel_dump_stack_info(void);
bool __ok_protected_phys_addr(unsigned long paddr);
void ok_free_protected_page_by_id(pid_t pid);
#endif
#endif /* _LINUX_OKERNEL_H */
