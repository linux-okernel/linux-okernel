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
 * For basic vmx setup we re-use some of the existing kvm / dune
 * code (in vmx.c / vmx.h).
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

/* For the okernel ioctl device */
#define DEVICE_NAME "okernel"
#define DEVICE_PATH "/dev/okernel"
#define MAGIC_NO '4'

#define OKERNEL_ON_CMD _IOW(MAGIC_NO, 0, unsigned int)

/* Rudimentary protected memory user space ioctl interface */
#define OKERNEL_ALLOCATE_PROTECTED_PAGE _IOR(MAGIC_NO, 1, unsigned long)
#define OKERNEL_FREE_PROTECTED_PAGE     _IOW(MAGIC_NO, 2, unsigned long)
#define OKERNEL_PROTECTED_PAGE_READ     _IOW(MAGIC_NO, 3, char *)
#define OKERNEL_PROTECTED_PAGE_WRITE    _IOW(MAGIC_NO, 4, char *)

static struct class *okernel_dev_class;
static int major_no;

int okernel_enabled;




/* Start a new tree of NR-processes */
#define OKERNEL_ENTER_IOCTL 1
/* Fork from an exisiting NR-process */
#define OKERNEL_ENTER_FORK  2


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

	OKDEBUG("thread/stack size (%lu) thread_info* (%#lx) stack in-use (%#lx) (%lu)\n",
		THREAD_SIZE, (unsigned long)current_thread_info(), okernel_stack_use(), okernel_stack_use());
	OKDEBUG("stack sp0 (%#lx) current sp (%#lx) end stack (%#lx)\n",
		sp0, sp, sp0-THREAD_SIZE);
}

void __noclone okernel_enter_test(unsigned long flags)
{
	int i;

	OKDEBUG("called - flags (%lx) pid(%d)\n", flags, current->pid);
	for(i = 0; i < 10; i++){

		OKDEBUG("pid (%d) Calling schedule_timeout (%d)...\n", current->pid, i);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(2*HZ);
		OKDEBUG("pid (%d) Done calling schedule_timeout (%d).\n", current->pid, i);
	}
	//OKDEBUG("Calling do_exit() for pid (%d)...\n", current->pid);
	//do_exit(0);
}

asmlinkage void __noclone okernel_enter_fork_debug(void)
{
	unsigned long fs;

	OKDEBUG("Returning from okernel_enter_fork (pid=%d)\n",
		current->pid);
	rdmsrl(MSR_FS_BASE, fs);
	OKDEBUG("MSR_FS_BASE (%#lx) curr (%#lx)\n",
		fs ,current->okernel_fork_fs_base);
	BXMAGICBREAK;

	OKDEBUG("initial state in return from okernel_enter_fork :\n");
#if defined(CONFIG_TRACE_IRQFLAGS) && defined(CONFIG_PROVE_LOCKING)
	OKDEBUG("current->h_irqs_en (%d)\n",
		current->hardirqs_enabled);
#endif
	OKDEBUG("in_atomic(): %d, irqs_disabled(): %d, pid: %d, name: %s\n",
		in_atomic(), irqs_disabled(), current->pid, current->comm);
	OKDEBUG("preempt_count (%#x) rcu_preempt_depth (%#x)\n",
		preempt_count(), rcu_preempt_depth());
	OKDEBUG("going back to okernel_ret_from_fork.\n");
}

asmlinkage int okernel_enter_core(unsigned int mode, unsigned long flags)
{
	/* Flags unused at the moment - reserve for different EPT settings, etc. */
	unsigned long tmpl;

	/* Malloc this since the stack will get over written later
	 * when the cloned thread is running. And passing a pointer
	 * allows us to save stack space. */

	struct nr_cloned_state *cloned_thread = kmalloc(sizeof(struct nr_cloned_state), GFP_KERNEL);

	unsigned long rbp,rsp,rflags,cr2,rax,rcx,rdx,rbx,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15;
	int ret;

	if(!cloned_thread){
		OKDEBUG("Failed to allocate cloned thread structure.\n");
		BUG();
	}

	OKDEBUG("called - mode (%u)\n", mode);

	cloned_thread->msr_fs_base = 0;

	if(mode == OKERNEL_ENTER_FORK){
		OKDEBUG("OKERNEL_ENTER_FORK...\n");
	} else	if(mode == OKERNEL_ENTER_IOCTL){
		OKDEBUG("OKERNEL_ENTER_IOCTL...\n");
	} else {
		printk(KERN_ERR "okernel_enter_core: invalid mode arg (%u)\n", mode);
		BUG();
	}

	cr2 = read_cr2();

	asm volatile ("mov %%rbp,%0" : "=rm" (rbp));

	OKDEBUG("cloned thread rbp will be set to  (%#lx)\n", rbp);

	cloned_thread->rbp = rbp;

	OKDEBUG("cloned thread cr2 will be set to  (%#lx)\n", cr2);
	cloned_thread->cr2 = cr2;

	asm volatile ("mov %%rax,%0" : "=rm" (rax));
	OKDEBUG("cloned thread rax will be set to  (%#lx)\n", rax);
	cloned_thread->rax = rax;

	asm volatile ("mov %%rcx,%0" : "=rm" (rcx));
	OKDEBUG("cloned thread rcx will be set to  (%#lx)\n", rcx);
	cloned_thread->rcx = rcx;

	asm volatile ("mov %%rdx,%0" : "=rm" (rdx));
	OKDEBUG("cloned thread rdx will be set to  (%#lx)\n", rdx);
	cloned_thread->rdx = rdx;

	asm volatile ("mov %%rdx,%0" : "=rm" (rbx));
	OKDEBUG("cloned thread rbx will be set to  (%#lx)\n", rbx);
	cloned_thread->rbx = rbx;

	asm volatile ("mov %%rsi,%0" : "=rm" (rsi));
	OKDEBUG("cloned thread rsi will be set to  (%#lx)\n", rsi);
	cloned_thread->rsi = rsi;

	asm volatile ("mov %%rdi,%0" : "=rm" (rdi));
	OKDEBUG("cloned thread rdi will be set to  (%#lx)\n", rdi);
	cloned_thread->rdi = rdi;

	asm volatile ("mov %%r8,%0" : "=rm" (r8));
	OKDEBUG("cloned thread r8 will be set to  (%#lx)\n", r8);
	cloned_thread->r8 = r8;

	asm volatile ("mov %%r9,%0" : "=rm" (r9));
	OKDEBUG("cloned thread r9 will be set to  (%#lx)\n", r9);
	cloned_thread->r9 = r9;

	asm volatile ("mov %%r10,%0" : "=rm" (r10));
	OKDEBUG("cloned thread r10 will be set to  (%#lx)\n", r10);
	cloned_thread->r10 = r10;

	asm volatile ("mov %%r11,%0" : "=rm" (r11));
	OKDEBUG("cloned thread r11 will be set to  (%#lx)\n", r11);
	cloned_thread->r11 = r11;

	asm volatile ("mov %%r12,%0" : "=rm" (r12));
	OKDEBUG("cloned thread r12 will be set to  (%#lx)\n", r12);
	cloned_thread->r12 = r12;

	asm volatile ("mov %%r13,%0" : "=rm" (r13));
	OKDEBUG("cloned thread r13 will be set to  (%#lx)\n", r13);
	cloned_thread->r13 = r13;

	asm volatile ("mov %%r14,%0" : "=rm" (r14));
	OKDEBUG("cloned thread r14 will be set to  (%#lx)\n", r14);
	cloned_thread->r14 = r14;

	asm volatile ("mov %%r15,%0" : "=rm" (r15));
	OKDEBUG("cloned thread r15 will be set to  (%#lx)\n", r15);
	cloned_thread->r15 = r15;

	asm volatile ( "pushf\n\t"
		       "pop %0"
		       : "=g"(rflags) );

	cloned_thread->rflags = rflags;
	OKDEBUG("cloned thread rflags will be set to  (%#lx)\n", rflags);

	asm("mov $.Lc_ret_from_vmlaunch_label, %0" : "=r"(tmpl));
	OKDEBUG("cloned thread RIP will be set to: (%#lx)\n", tmpl);
	cloned_thread->rip = tmpl;

	cloned_thread->msr_fs_base = current->okernel_fork_fs_base;
	cloned_thread->msr_gs_base = current->okernel_fork_gs_base;

	asm volatile ("mov %%rsp,%0" : "=rm" (rsp));

	OKDEBUG("cloned thread rsp will be set to  (%#lx)\n", rsp);

	cloned_thread->rsp = rsp;

	BXMAGICBREAK;

	//barrier();

	ret =  vmx_launch(mode, flags, cloned_thread);

	if(ret){
		printk(KERN_ERR "vmx_launch failed for pid <%d> ret (%d) mode (%u) flags (%lu)\n",
		       current->pid, ret, mode, flags);
		BUG();
	}

	asm volatile(".Lc_ret_from_vmlaunch_label: ");

	/* Be careful what we do here as the C register state may not
	   be the same as the compiler is expecting (since we are
	   jumping straight to this point with state restored from a
	   VMCS record which the compiler won't be aware of). We are
	   ok once we return to our calling function, or if we call a
	   function.*/

	return ret;
}

asmlinkage void __noclone okernel_enter_fork(void)
{
	/* Flags unused at present: reserved for EPT setting, etc. */
	(void)okernel_enter_core(OKERNEL_ENTER_FORK, 0);
	BXMAGICBREAK;
	okernel_enter_fork_debug();
	return;
}

int __noclone okernel_enter(unsigned long flags)
{
	/* Flags unused at present: reserved for EPT setting, etc. */
	int ret;

	ret = okernel_enter_core(OKERNEL_ENTER_IOCTL, 0);
	BXMAGICBREAK;
	return ret;
}



/* IOCTL to allow okernel ON to be toggled as an alternative to /proc/<pid> toggling */
static int ok_device_open(struct inode *inode, struct file *file)
{
	OKDEBUG("Opening device <%s>\n", DEVICE_NAME);
	return 0;
}

long ok_device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned long val;
	int ret;
	struct thread_info *ti;
	struct page *pg;
	unsigned long phys_addr = 0;
	struct protected_data pd;
	unsigned long pfn;
	unsigned long p_addr;
	char *p;
	unsigned long *v_addr;

	OKDEBUG("called.\n");
	switch(cmd)
	{
		/* Really we should do an mmap interface above protected pages - this will suffice for now */
	case OKERNEL_ALLOCATE_PROTECTED_PAGE:
		if(!(pg = ok_alloc_protected_page())){
			printk("ok: failed to alloc protected page.\n");
			return -EINVAL;
		}

		phys_addr = page_to_phys(pg);

		printk("ok: allocated protected page at phys addr (%#lx)\n", phys_addr);

		if(copy_to_user((void*)arg, &phys_addr, sizeof(unsigned long))){
			return -EFAULT;
		}
		return 0;
		break;
	case OKERNEL_FREE_PROTECTED_PAGE:
		phys_addr = arg;
		printk("ok: Passed physical Address for permission removal:=(%#lx)\n", phys_addr);
		(void)ok_free_protected_page(pfn_to_page(__phys_to_pfn(phys_addr)));
		return 0;
		break;
	case OKERNEL_PROTECTED_PAGE_READ:
		copy_from_user(&pd, (void*)arg, sizeof(struct protected_data));
		p_addr = pd.p_addr;

		printk("OK page reaad: Passed physical Address <%#lx>\n", p_addr);

		/* In range? */
		pfn = __phys_to_pfn(p_addr);

		if((pfn < ok_protected_pfn_start) || (pfn > ok_protected_pfn_end)){
			return -EINVAL;
		}


		v_addr = phys_to_virt(p_addr);
		printk("OK: Kernel virtual address <%p>\n", v_addr);
		p = (char*)v_addr;

		printk("OK: Read from p_addr/vaddr (%#lx/%#lx) in kernel: %s\n",
		       p_addr, (unsigned long)v_addr, p);
		copy_to_user(pd.p_data, p, PAGE_SIZE);
		break;
	case OKERNEL_PROTECTED_PAGE_WRITE:
		copy_from_user(&pd, (void*)arg, sizeof(struct protected_data));
		p_addr = pd.p_addr;

		printk("OK page write: Passed physical Address <%#lx>\n", p_addr);

		/* In range? */
		pfn = __phys_to_pfn(p_addr);

		if((pfn < ok_protected_pfn_start) || (pfn > ok_protected_pfn_end)){
			return -EINVAL;
		}

		v_addr = phys_to_virt(p_addr);

		printk("OK: Kernel virtual address <%p>\n", v_addr);

		p = (char*)v_addr;
		memset(p, 0, PAGE_SIZE);
		copy_from_user(p, pd.p_data, PAGE_SIZE-1);
		printk("OK: write to p_addr/vaddr (%#lx/%#lx) in kernel: %s\n",
		       p_addr, (unsigned long)v_addr, p);
		break;
	case OKERNEL_ON_CMD:
		set_vmx_r_mode();
		val = arg;

		OKDEBUG("cmd is OKERNEL_ON_CMD with arg (%lu) for pid (%d)\n",
			val, current->pid);


		if(val != 1){
			OKDEBUG("OKERNEL_ON_CMD arg not 1.\n");
			return -EINVAL;
		}
		/* do okernel_enter() here... */
		OKDEBUG("About to go into okernel on mode via okernel_enter() for pid (%d)\n",
		       current->pid);

		current->okernel_status = OKERNEL_ON;

		if(is_in_vmx_nr_mode()){
			printk(KERN_CRIT "NR: Calling okernel_enter in  NR mode kernel...shouldn't get here!!\n");
		}

		ret = okernel_enter(OKERNEL_ENTER_IOCTL);

		if(is_in_vmx_nr_mode()){
			BXMAGICBREAK;

			OKDEBUG("Returning from okernel_enter (IOCTL_LAUNCH).\n");

			//dump_stack();
			BXMAGICBREAK;
			ti = current_thread_info();

			OKDEBUG("initial state in return from okernel_enter (IOCTL_LAUNCH):\n");
#if defined(CONFIG_TRACE_IRQFLAGS) && defined(CONFIG_PROVE_LOCKING)
			OKDEBUG("current->h_irqs_en (%d)\n",
				current->hardirqs_enabled);
#endif
			OKDEBUG("in_atomic(): %d, irqs_disabled(): %d, pid: %d, name: %s\n",
				in_atomic(), irqs_disabled(), current->pid, current->comm);
			OKDEBUG("preempt_count (%#x) rcu_preempt_depth (%#x)\n",
				preempt_count(), rcu_preempt_depth());

			OKDEBUG("------------------------------------------------------------------\n");
			OKDEBUG("set state for return through kernel to upace from okernel_enter:\n");
#if defined(CONFIG_TRACE_IRQFLAGS) && defined(CONFIG_PROVE_LOCKING)
			OKDEBUG("current->h_irqs_en (%d)\n",
				current->hardirqs_enabled);
#endif
			OKDEBUG("in_atomic(): %d, irqs_disabled(): %d, pid: %d, name: %s\n",
				in_atomic(), irqs_disabled(), current->pid, current->comm);
			OKDEBUG("preempt_count (%#x) rcu_preempt_depth (%#x)\n",
			       preempt_count(), rcu_preempt_depth());
			OKDEBUG("starting back towards user space (IOCTL_LAUNCH)...\n");
			goto nr_exit;
		}
		current->okernel_status = OKERNEL_OFF;

		if(ret){
			printk(KERN_ERR "okernel_enter failed for pid <%d> ret (%d)\n",
			       current->pid, ret);
		}
		OKDEBUG("outer kernel off for <%d>\n", current->pid);
		unset_vmx_r_mode();
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
	OKDEBUG("Releasing device <%s>\n", DEVICE_NAME);
	return 0;
}



static struct file_operations fops={
    .open = ok_device_open,
    .release = ok_device_release,
    .unlocked_ioctl = ok_device_ioctl
};


static int __init okernel_init(void)
{

	OKDEBUG("Start initialization...\n");

	major_no = register_chrdev(0, DEVICE_NAME, &fops);
	OKDEBUG("Creating Device Major_no : %d\n", major_no);
	okernel_dev_class = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(okernel_dev_class, NULL, MKDEV(major_no,0), NULL, DEVICE_NAME);
	OKDEBUG("Device <%s> Initialized in kernel.\n", DEVICE_NAME);

	if(vmx_init()){
		printk(KERN_ERR "okernel: failed to initialize x86 vmx extensions.\n");
		okernel_enabled = 0;
		return -1;
	}

	okernel_enabled = 1;
	okernel_dump_stack_info();
	OKDEBUG("Enabled, initialization done.\n");
	return 0;
}

static void  __exit okernel_exit(void)
{
	OKDEBUG("exit called.\n");
	okernel_enabled = 0;
	OKDEBUG("Removing device (%s)\n", DEVICE_NAME);
	device_destroy(okernel_dev_class,MKDEV(major_no,0));
	class_unregister(okernel_dev_class);
	class_destroy(okernel_dev_class);
	unregister_chrdev(major_no, DEVICE_NAME);
	OKDEBUG("done.\n");
	return;
}

EXPORT_SYMBOL(okernel_enabled);
EXPORT_SYMBOL(okernel_enter);
module_init(okernel_init)
module_exit(okernel_exit)

