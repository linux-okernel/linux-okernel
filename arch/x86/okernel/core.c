/* 
 * linux/arch/x86/okernel/core.c
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
 *  
 * For basic vmx setup we re-use some of the existing kvm / dune code (in vmx.c). 
 *
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/okernel.h>
#include <linux/kdev_t.h>


#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/ftrace.h>
#include <linux/slab.h>
#include <linux/tboot.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/syscalls.h>
#include <linux/version.h>

#include <asm/desc.h>
#include <asm/vmx.h>
#include <asm/unistd_64.h>
#include <asm/virtext.h>
#include <asm/percpu.h>
#include <asm/preempt.h>
#include <asm/tlbflush.h>

#include "vmx.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Okernel intra-kernel protection");

#ifdef CONFIG_OKERNEL_SCHED
extern void __ok_schedule(void);
#endif

/* For the okernel ioctl device */
#define DEVICE_NAME "okernel"
#define DEVICE_PATH "/dev/okernel"
#define MAGIC_NO '4'
#define OKERNEL_ON_CMD _IOW(MAGIC_NO, 0, unsigned int)
static struct class *okernel_dev_class;
static int major_no;

int okernel_enabled;



#ifdef CONFIG_OKERNEL_SCHED
void okernel_schedule_helper(void)
{
	int a = 0;
	
	a++;
	HDEBUG("called a: (%d)\n", a);
	__ok_schedule();
}

int okernel_setup(int *vcpu)
{
	*vcpu = 3;
	HDEBUG("called.\n");
	return 1;
}
#endif



unsigned long okernel_stack_use(void)
{
	return  (current_top_of_stack() - current_stack_pointer());
}

void okernel_dump_stack_info(void)
{
	unsigned long sp, sp0, end_stack;

	sp0 = current_top_of_stack();
	sp  = current_stack_pointer();
	end_stack = sp0 - THREAD_SIZE;

	HDEBUG("thread/stack size (%lu) thread_info* (%#lx) stack in-use (%#lx) (%lu)\n",
		THREAD_SIZE, (unsigned long)current_thread_info(), okernel_stack_use(), okernel_stack_use());
	HDEBUG("stack sp0 (%#lx) current sp (%#lx) end stack (%#lx)\n",
		sp0, sp, sp0-THREAD_SIZE);
}

void __noclone okernel_enter_test(unsigned long flags)
{
	int i;
	
	HDEBUG("called - flags (%lx) pid(%d)\n", flags, current->pid);
	for(i = 0; i < 10; i++){
		
		HDEBUG("pid (%d) Calling schedule_timeout (%d)...\n", current->pid, i);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(2*HZ);
		HDEBUG("pid (%d) Done calling schedule_timeout (%d).\n", current->pid, i);
	}
	//HDEBUG("Calling do_exit() for pid (%d)...\n", current->pid);
	//do_exit(0);
}

asmlinkage void __noclone okernel_enter_fork_debug(void)
{
	unsigned long fs;
	
	HDEBUG("Returning from okernel_enter_fork (pid=%d)\n",
		current->pid);
	rdmsrl(MSR_FS_BASE, fs);
	HDEBUG("MSR_FS_BASE (%#lx) curr (%#lx)\n",
		fs ,current->okernel_fork_fs_base); 
	BXMAGICBREAK;
		
	HDEBUG("initial state in return from okernel_enter_fork :\n");
	HDEBUG("current->h_irqs_en (%d)\n",
		current->hardirqs_enabled);
	HDEBUG("in_atomic(): %d, irqs_disabled(): %d, pid: %d, name: %s\n",
		in_atomic(), irqs_disabled(), current->pid, current->comm);
	HDEBUG("preempt_count (%#x) rcu_preempt_depth (%#x)\n",
		preempt_count(), rcu_preempt_depth());
	HDEBUG("going back to okernel_ret_from_fork.\n");
}

asmlinkage void __noclone okernel_enter_fork(void)
{
	unsigned long tmpl;

	/* Malloc this since the stack will get over written later
	 * when the cloned thread is running. And passing a pointer
	 * allows us to save stack space. */

	struct nr_cloned_state *cloned_thread = kmalloc(sizeof(struct nr_cloned_state), GFP_KERNEL);
	
	unsigned long rbp,rsp,cr2,rflags,rax,rcx,rdx,rbx,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15;
	int ret;

	HDEBUG("called for pid=%d\n", current->pid);

	cloned_thread->msr_fs_base = 0;

	asm volatile ("mov %%cr2,%0" : "=rm" (cr2));
	
	asm volatile ("mov %%rbp,%0" : "=rm" (rbp));
	
	HDEBUG("cloned thread rbp will be set to  (%#lx)\n", rbp);
	cloned_thread->rbp = rbp;
		
	HDEBUG("cloned thread cr2 will be set to  (%#lx)\n", cr2);
	cloned_thread->cr2 = cr2;
	
	asm volatile ("mov %%rax,%0" : "=rm" (rax));
	HDEBUG("cloned thread rax will be set to  (%#lx)\n", rax);
	cloned_thread->rax = rax;
	
	asm volatile ("mov %%rcx,%0" : "=rm" (rcx));
	HDEBUG("cloned thread rcx will be set to  (%#lx)\n", rcx);
	cloned_thread->rcx = rcx;
	
	asm volatile ("mov %%rdx,%0" : "=rm" (rdx));
	HDEBUG("cloned thread rdx will be set to  (%#lx)\n", rdx);
	cloned_thread->rdx = rdx;
	
	asm volatile ("mov %%rdx,%0" : "=rm" (rbx));
	HDEBUG("cloned thread rbx will be set to  (%#lx)\n", rbx);
	cloned_thread->rbx = rbx;
	
	asm volatile ("mov %%rsi,%0" : "=rm" (rsi));
	HDEBUG("cloned thread rsi will be set to  (%#lx)\n", rsi);
	cloned_thread->rsi = rsi;
	
	asm volatile ("mov %%rdi,%0" : "=rm" (rdi));
	HDEBUG("cloned thread rdi will be set to  (%#lx)\n", rdi);
	cloned_thread->rdi = rdi;
	
	asm volatile ("mov %%r8,%0" : "=rm" (r8));
	HDEBUG("cloned thread r8 will be set to  (%#lx)\n", r8);
	cloned_thread->r8 = r8;
	
	asm volatile ("mov %%r9,%0" : "=rm" (r9));
	HDEBUG("cloned thread r9 will be set to  (%#lx)\n", r9);
	cloned_thread->r9 = r9;
	
	asm volatile ("mov %%r10,%0" : "=rm" (r10));
	HDEBUG("cloned thread r10 will be set to  (%#lx)\n", r10);
	cloned_thread->r10 = r10;
	
	asm volatile ("mov %%r11,%0" : "=rm" (r11));
	HDEBUG("cloned thread r11 will be set to  (%#lx)\n", r11);
	cloned_thread->r11 = r11;
	
	asm volatile ("mov %%r12,%0" : "=rm" (r12));
	HDEBUG("cloned thread r12 will be set to  (%#lx)\n", r12);
	cloned_thread->r12 = r12;
	
	asm volatile ("mov %%r13,%0" : "=rm" (r13));
	HDEBUG("cloned thread r13 will be set to  (%#lx)\n", r13);
	cloned_thread->r13 = r13;
	
	asm volatile ("mov %%r14,%0" : "=rm" (r14));
	HDEBUG("cloned thread r14 will be set to  (%#lx)\n", r14);
	cloned_thread->r14 = r14;
	
	asm volatile ("mov %%r15,%0" : "=rm" (r15));
	HDEBUG("cloned thread r15 will be set to  (%#lx)\n", r15);
	cloned_thread->r15 = r15;

	
	rflags = 0x002;
	cloned_thread->rflags = rflags;
	HDEBUG("cloned thread rflags will be set to  (%#lx)\n", rflags);
	
	
	asm("mov $.Lc_ret_from_fork_label, %0" : "=r"(tmpl));
	HDEBUG("cloned thread RIP will be set to: (%#lx)\n", tmpl);
	cloned_thread->rip = tmpl;

	cloned_thread->msr_fs_base = current->okernel_fork_fs_base;
	cloned_thread->msr_gs_base = current->okernel_fork_gs_base;

	asm volatile ("mov %%rsp,%0" : "=rm" (rsp));

	HDEBUG("cloned thread rsp will be set to  (%#lx)\n", rsp);
	cloned_thread->rsp = rsp;
	
	BXMAGICBREAK;

	barrier();
	
	ret = vmx_launch(2, cloned_thread);
	
	asm volatile(".Lc_ret_from_fork_label: ");

	BXMAGICBREAK;
	
	/* Be careful what we do here as the C register state may not
	   be the same as the compiler is expecting (since we are
	   jumping straight to this point with state restored from a
	   VMCS record which the compiler won't be aware of). We are
	   ok once we return to our calling function, or if we call a
	   function.*/
	
	okernel_enter_fork_debug();
	return;
}

int __noclone okernel_enter(unsigned long flags)
{
	unsigned long tmpl;

	/* Malloc this since the stack will get over written later
	 * when the cloned thread is running. And passing a pointer
	 * allows us to save stack space. */

	struct nr_cloned_state *cloned_thread = kmalloc(sizeof(struct nr_cloned_state), GFP_KERNEL);
	
	unsigned long rbp,rsp,rflags,cr2,rax,rcx,rdx,rbx,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15;
	int ret;

		
	HDEBUG("called - flags (%lx)\n", flags);

	cloned_thread->msr_fs_base = 0;
	
	if(flags == OKERNEL_IOCTL_LAUNCH){
		HDEBUG("OKERNEL_IOCTL_LAUNCH...\n");
	} else {
		printk(KERN_ERR "okernel_enter: invalid flags arg.\n");
		BUG();
	}

	asm volatile ("mov %%cr2,%0" : "=rm" (cr2));
	
	asm volatile ("mov %%rbp,%0" : "=rm" (rbp));
	
	HDEBUG("cloned thread rbp will be set to  (%#lx)\n", rbp);
	
	cloned_thread->rbp = rbp;



	HDEBUG("cloned thread cr2 will be set to  (%#lx)\n", cr2);
	cloned_thread->cr2 = cr2;
	
	asm volatile ("mov %%rax,%0" : "=rm" (rax));
	HDEBUG("cloned thread rax will be set to  (%#lx)\n", rax);
	cloned_thread->rax = rax;
	
	asm volatile ("mov %%rcx,%0" : "=rm" (rcx));
	HDEBUG("cloned thread rcx will be set to  (%#lx)\n", rcx);
	cloned_thread->rcx = rcx;
	
	asm volatile ("mov %%rdx,%0" : "=rm" (rdx));
	HDEBUG("cloned thread rdx will be set to  (%#lx)\n", rdx);
	cloned_thread->rdx = rdx;
	
	asm volatile ("mov %%rdx,%0" : "=rm" (rbx));
	HDEBUG("cloned thread rbx will be set to  (%#lx)\n", rbx);
	cloned_thread->rbx = rbx;
	
	asm volatile ("mov %%rsi,%0" : "=rm" (rsi));
	HDEBUG("cloned thread rsi will be set to  (%#lx)\n", rsi);
	cloned_thread->rsi = rsi;
	
	asm volatile ("mov %%rdi,%0" : "=rm" (rdi));
	HDEBUG("cloned thread rdi will be set to  (%#lx)\n", rdi);
	cloned_thread->rdi = rdi;
	
	asm volatile ("mov %%r8,%0" : "=rm" (r8));
	HDEBUG("cloned thread r8 will be set to  (%#lx)\n", r8);
	cloned_thread->r8 = r8;
	
	asm volatile ("mov %%r9,%0" : "=rm" (r9));
	HDEBUG("cloned thread r9 will be set to  (%#lx)\n", r9);
	cloned_thread->r9 = r9;
	
	asm volatile ("mov %%r10,%0" : "=rm" (r10));
	HDEBUG("cloned thread r10 will be set to  (%#lx)\n", r10);
	cloned_thread->r10 = r10;
	
	asm volatile ("mov %%r11,%0" : "=rm" (r11));
	HDEBUG("cloned thread r11 will be set to  (%#lx)\n", r11);
	cloned_thread->r11 = r11;
	
	asm volatile ("mov %%r12,%0" : "=rm" (r12));
	HDEBUG("cloned thread r12 will be set to  (%#lx)\n", r12);
	cloned_thread->r12 = r12;
	
	asm volatile ("mov %%r13,%0" : "=rm" (r13));
	HDEBUG("cloned thread r13 will be set to  (%#lx)\n", r13);
	cloned_thread->r13 = r13;
	
	asm volatile ("mov %%r14,%0" : "=rm" (r14));
	HDEBUG("cloned thread r14 will be set to  (%#lx)\n", r14);
	cloned_thread->r14 = r14;
	
	asm volatile ("mov %%r15,%0" : "=rm" (r15));
	HDEBUG("cloned thread r15 will be set to  (%#lx)\n", r15);
	cloned_thread->r15 = r15;

	rflags = 0x002;
	cloned_thread->rflags = rflags;
	HDEBUG("cloned thread rflags will be set to  (%#lx)\n", rflags);


	cloned_thread->idt_base = (unsigned long)idt_table;
	cloned_thread->idt_limit = 0x0FFF;
	       
	asm("mov $.Lc_rip_label, %0" : "=r"(tmpl));
	HDEBUG("cloned thread RIP will be set to: (%#lx)\n", tmpl);
	cloned_thread->rip = tmpl;

	asm volatile ("mov %%rsp,%0" : "=rm" (rsp));
	HDEBUG("cloned thread rsp will be set to  (%#lx)\n", rsp);
	cloned_thread->rsp = rsp;	
	
	barrier();
	
	ret = vmx_launch(flags, cloned_thread);
	
	asm volatile(".Lc_rip_label: ");
	
	/* Be careful what we do here as the C register state may not
	   be the same as the compiler is expecting (since we are
	   jumping straight to this point with state restored from a
	   VMCS record which the compiler won't be aware of). We are
	   ok once we return to our calling function.*/
	
	return ret;
}

/* IOCTL to allow okernel ON to be toggled as an alternative to /proc/<pid> toggling */
static int ok_device_open(struct inode *inode, struct file *file)
{
	HDEBUG("Opening device <%s>\n", DEVICE_NAME);
	return 0;
}

long ok_device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned long val;
	int ret;
	struct thread_info *ti;
	

	HDEBUG("called.\n");
	switch(cmd)
	{
	case OKERNEL_ON_CMD:
		val = arg;
		HDEBUG("cmd is OKERNEL_ON_CMD with arg (%lu) for pid (%d)\n",
			val, current->pid);
		if(val != 1){
			HDEBUG("OKERNEL_ON_CMD arg not 1.\n");
			return -EINVAL;
		}
		/* do okernel_enter() here... */
		HDEBUG("About to go into okernel on mode via okernel_enter() for pid (%d)\n",
		       current->pid);

		current->okernel_status = OKERNEL_ON;

		if(is_in_vmx_nr_mode()){
			printk(KERN_CRIT "NR: Calling okernel_enter in  NR mode kernel...shouldn't get here!!\n");
		}
		
		ret = okernel_enter(OKERNEL_IOCTL_LAUNCH);

		if(is_in_vmx_nr_mode()){
			BXMAGICBREAK;
			HDEBUG("Returning from okernel_enter (IOCTL_LAUNCH).\n");
			BXMAGICBREAK;

			ti = current_thread_info();
			
			HDEBUG("initial state in return from okernel_enter (IOCTL_LAUNCH):\n");
			HDEBUG("current->h_irqs_en (%d)\n",
				current->hardirqs_enabled);
			HDEBUG("in_atomic(): %d, irqs_disabled(): %d, pid: %d, name: %s\n",
				in_atomic(), irqs_disabled(), current->pid, current->comm);
			HDEBUG("preempt_count (%#x) rcu_preempt_depth (%#x)\n",
				preempt_count(), rcu_preempt_depth());
			HDEBUG("ti->saved_preempt_count (%#x) current->lockdep_depth (%d)\n",
				ti->saved_preempt_count, current->lockdep_depth);
			current->lockdep_depth = 0;
			local_irq_enable();
			HDEBUG("------------------------------------------------------------------\n");
			HDEBUG("set state for return through kernel to upace from okernel_enter:\n");
			HDEBUG("current->h_irqs_en (%d)\n",
				current->hardirqs_enabled);
			HDEBUG("in_atomic(): %d, irqs_disabled(): %d, pid: %d, name: %s\n",
				in_atomic(), irqs_disabled(), current->pid, current->comm);
			HDEBUG("preempt_count (%#x) rcu_preempt_depth (%#x) saved preempt (%#x)\n",
				preempt_count(), rcu_preempt_depth(), ti->saved_preempt_count);
			HDEBUG("ti->saved_preempt_count (%#x) current->lockdep_depth (%d)\n",
				ti->saved_preempt_count, current->lockdep_depth);
			HDEBUG("starting back towards user space (IOCTL_LAUNCH)...\n");
			goto nr_exit;
		}
		current->okernel_status = OKERNEL_OFF;

		if(ret){
			printk(KERN_ERR "okernel_enter failed for pid <%d> ret (%lu)\n",
			       current->pid, (unsigned long)ret);
		}
		HDEBUG("outer kernel off for <%d>\n", current->pid);
		break;
	default:
	
		printk(KERN_ERR "okernel invalid IOCTL cmd.\n");
		return -ENODEV;
		
	}
nr_exit:
	return 0;
}


static int ok_device_release(struct inode *inode, struct file *file)
{
	HDEBUG("Releasing device <%s>\n", DEVICE_NAME);
	return 0;
}



static struct file_operations fops={
    .open = ok_device_open,
    .release = ok_device_release,
    .unlocked_ioctl = ok_device_ioctl
};


static int __init okernel_init(void)
{
	
	HDEBUG("Start initialization...\n");
	
	major_no = register_chrdev(0, DEVICE_NAME, &fops);
	HDEBUG("Creating Device Major_no : %d\n", major_no);
	okernel_dev_class = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(okernel_dev_class, NULL, MKDEV(major_no,0), NULL, DEVICE_NAME);
	HDEBUG("Device <%s> Initialized in kernel.\n", DEVICE_NAME);

	if(vmx_init()){
		printk(KERN_ERR "okernel: failed to initialize x86 vmx extensions.\n");
		okernel_enabled = 0;
		return -1;
	}
	
	okernel_enabled = 1;
	okernel_dump_stack_info();
	HDEBUG("Enabled, initialization done.\n");
	return 0;
}

static void  __exit okernel_exit(void)
{
	HDEBUG("exit called.\n");
	okernel_enabled = 0;
	HDEBUG("Removing device (%s)\n", DEVICE_NAME);
	device_destroy(okernel_dev_class,MKDEV(major_no,0));
	class_unregister(okernel_dev_class);
	class_destroy(okernel_dev_class);
	unregister_chrdev(major_no, DEVICE_NAME);
	HDEBUG("done.\n");
	return;
}

#ifdef CONFIG_OKERNEL_SCHED
EXPORT_SYMBOL(okernel_setup);
EXPORT_SYMBOL(okernel_schedule_helper);
#endif
EXPORT_SYMBOL(okernel_enabled);
EXPORT_SYMBOL(okernel_enter);
module_init(okernel_init)
module_exit(okernel_exit)

