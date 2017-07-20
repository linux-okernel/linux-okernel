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
#include <linux/kern_levels.h>
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
//extern int __ok_trace(const char *fmt, ...);
extern const char *ok_trace_get_level(const char *buffer);

/* OKERNEL_DEBUG */
#define OKERNEL_DEBUG

#ifdef OKERNEL_DEBUG

/* #define __ok_trace(fmt, ...)					\
 do {									\
 	const char *label = ok_trace_get_level(fmt);			\
 									\
 	if (strcmp(label, "OK_ERROR") == 0)					\
 		printk(KERN_ERR "[%s - cpu(%d) pid(%d)] %s: " fmt, vmx_nr_mode()?"NR":"R", raw_smp_processor_id(), current->pid,__func__, ## __VA_ARGS__);	\
 	else								\
 		trace_printk("(%s) [%s - cpu(%d) pid(%d)] %s: " fmt, label, vmx_nr_mode()?"NR":"R", raw_smp_processor_id(), current->pid,__func__, ## __VA_ARGS__);	\
} while (0) */

#define __ok_trace(fmt, ...) trace_printk("[%s - cpu(%d) pid(%d)] : " fmt, vmx_nr_mode()?"NR":"R", raw_smp_processor_id(), current->pid, ## __VA_ARGS__);


#define ok_pr_fmt(fmt) fmt
/* maintain correspondence to levels defined in 'linux/kern_levels.h' */
#define OK_ERR		KERN_ERR		/* "3" - error conditions */
#define OK_WARNING	KERN_WARNING	/* "4" - warning conditions */
#define OK_LOG		KERN_NOTICE		/* "5" - notice messages */
#define OK_DEBUG	KERN_DEBUG		/* "7" - debug-level messages */
#define OK_SEC		KERN_SOH "s"	/* security exception messages (custom level)*/

#define ok_trace(fmt, ...) __ok_trace(fmt, ## __VA_ARGS__)
//#define ok_trace(fmt, ...) trace_printk("[%s - cpu(%d) pid(%d)] %s: " ok_pr_fmt(fmt), vmx_nr_mode()?"NR":"R", raw_smp_processor_id(), current->pid,__func__, ## __VA_ARGS__)

#define HLOG(fmt, ...) ok_trace(OK_LOG ok_pr_fmt(fmt), ## __VA_ARGS__)
#define TDEBUG(p, fmt, args...)  if (p) snprintf(p, VCPUBUFLEN, \
						 "pid(%d) %s: " fmt , \
						 current->pid,__func__, ## args)
//#define HPE_LOOP_DETECT
#define OKERR(fmt, ...) ok_trace(OK_ERR ok_pr_fmt(fmt), ## __VA_ARGS__)
#define OKWARN(fmt, ...) ok_trace(OK_WARNING ok_pr_fmt(fmt), ## __VA_ARGS__)
#define OKDEBUG(fmt, ...) ok_trace(OK_DEBUG ok_pr_fmt(fmt), ## __VA_ARGS__)
#define OKSEC(fmt, ...) ok_trace(OK_SEC ok_pr_fmt(fmt), ## __VA_ARGS__)

#else /* !OKERNEL_DEBUG */
#define HLOG(fmt, ...)
#define TDEBUG(p, fmt, args...)
#define OKERR(fmt, ...)
#define OKWARN(fmt, ...)
#define OKDEBUG(fmt, ...)
#define OKSEC(fmt, ...)
#define ok_trace(fmt, ...)
#endif /* OKERNEL_DEBUG */



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
