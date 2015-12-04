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
//#include <asm/paravirt.h>

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
struct nr_cloned_state cloned_thread;

#ifdef CONFIG_OKERNEL_SCHED
void okernel_schedule_helper(void)
{
	int a = 0;
	
	a++;
	HDEBUG(("called a: (%d)\n", a));
	__ok_schedule();
}

int okernel_setup(int *vcpu)
{
	*vcpu = 3;
	HDEBUG(("called.\n"));
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

	printk(KERN_ERR  "okernel: thread/stack size (%lu) thread_info* (%#lx) stack in-use (%#lx) (%lu)\n",
	       THREAD_SIZE, (unsigned long)current_thread_info(), okernel_stack_use(), okernel_stack_use());
	printk(KERN_ERR "okernel: stack sp0 (%#lx) current sp (%#lx) end stack (%#lx)\n",
	       sp0, sp, sp0-THREAD_SIZE);
}

int __noclone okernel_enter(void)
{
	//struct pt_regs *regs;	
	unsigned long rbp,rsp,rflags,rax,rcx,rdx,rbx,rsi,rdi,r8,r9,r10,r11,r12,r13,r15;
	int ret;
	
	HDEBUG(("called.\n"));

	asm volatile ("mov %%rbp,%0" : "=rm" (rbp));
	HDEBUG(("cloned thread rbp will be set to  (%#lx)\n", rbp));
	cloned_thread.rbp = rbp;

	asm volatile ("mov %%rsp,%0" : "=rm" (rsp));
	HDEBUG(("cloned thread rsp will be set to  (%#lx)\n", rsp));
	cloned_thread.rsp = rsp;

	asm volatile ( "pushf\n\t"
                   "pop %0"
                   : "=g"(rflags) );
	
	HDEBUG(("cloned thread rflags will be set to  (%#lx)\n", rflags));
	cloned_thread.rflags = rflags;

	asm volatile ("mov %%rax,%0" : "=rm" (rax));
	HDEBUG(("cloned thread rax will be set to  (%#lx)\n", rax));
	cloned_thread.rax = rax;

	asm volatile ("mov %%rcx,%0" : "=rm" (rcx));
	HDEBUG(("cloned thread rcx will be set to  (%#lx)\n", rcx));
	cloned_thread.rcx = rcx;
	
	asm volatile ("mov %%rdx,%0" : "=rm" (rdx));
	HDEBUG(("cloned thread rdx will be set to  (%#lx)\n", rdx));
	cloned_thread.rdx = rdx;

	asm volatile ("mov %%rdx,%0" : "=rm" (rbx));
	HDEBUG(("cloned thread rbx will be set to  (%#lx)\n", rbx));
	cloned_thread.rbx = rbx;

	asm volatile ("mov %%rsi,%0" : "=rm" (rsi));
	HDEBUG(("cloned thread rsi will be set to  (%#lx)\n", rsi));
	cloned_thread.rsi = rsi;

	asm volatile ("mov %%rdi,%0" : "=rm" (rdi));
	HDEBUG(("cloned thread rdi will be set to  (%#lx)\n", rdi));
	cloned_thread.rdi = rdi;

	asm volatile ("mov %%r8,%0" : "=rm" (r8));
	HDEBUG(("cloned thread r8 will be set to  (%#lx)\n", r8));
	cloned_thread.r8 = r8;

	asm volatile ("mov %%r9,%0" : "=rm" (r9));
	HDEBUG(("cloned thread r9 will be set to  (%#lx)\n", r9));
	cloned_thread.r9 = r9;

	asm volatile ("mov %%r10,%0" : "=rm" (r10));
	HDEBUG(("cloned thread r10 will be set to  (%#lx)\n", r10));
	cloned_thread.r10 = r10;

	asm volatile ("mov %%r11,%0" : "=rm" (r11));
	HDEBUG(("cloned thread r11 will be set to  (%#lx)\n", r11));
	cloned_thread.r11 = r11;
	
	asm volatile ("mov %%r12,%0" : "=rm" (r12));
	HDEBUG(("cloned thread r12 will be set to  (%#lx)\n", r12));
	cloned_thread.r12 = r12;

	asm volatile ("mov %%r13,%0" : "=rm" (r13));
	HDEBUG(("cloned thread r13 will be set to  (%#lx)\n", r13));
	cloned_thread.r13 = r13;

	asm volatile ("mov %%r15,%0" : "=rm" (r15));
	HDEBUG(("cloned thread r15 will be set to  (%#lx)\n", r15));
	cloned_thread.r15 = r15;

	
#if 0
	regs = task_pt_regs(current);
	HDEBUG(("----start of 'current' regs from __show_regs:\n"));
	__show_regs(regs, 1);
	HDEBUG(("----end of 'current' regs from __show_regs:\n"));
#endif	

	asm volatile("xchg %bx, %bx");

	ret = vmx_launch();
	
	asm volatile(".Lc_rip_label: ");
	asm volatile("xchg %bx, %bx");
#if 1
	if(vmx_nr_mode()){
		asm volatile("xchg %bx, %bx");
		//printk(KERN_CRIT "Resuming cloned process In NR mode kernel.\n");
		//asm volatile("xchg %bx, %bx");
		//vmcall(VMCALL_NOP);
                //printk(KERN_CRIT "About to leave okernel_enter() function...\n");
		//asm volatile("xchg %bx, %bx");
	}
#endif
	return ret;
}

/* IOCTL to allow okernel ON to be toggled as an alternative to /proc/<pid> toggling */
static int ok_device_open(struct inode *inode, struct file *file)
{
	HDEBUG(("Opening device <%s>\n", DEVICE_NAME));
	return 0;
}


long ok_device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned long val;
	int ret;

	HDEBUG(("called.\n"));
	switch(cmd)
	{
	case OKERNEL_ON_CMD:
		val = arg;
		HDEBUG(("cmd is OKERNEL_ON_CMD with arg (%lu) for pid (%d)\n",
			val, current->pid));
		if(val != 1){
			printk(KERN_ERR "OKERNEL_ON_CMD arg not 1.\n");
			return -EINVAL;
		}
		/* do okernel_enter() here... */
		HDEBUG(("About to go into okernel on mode via okernel_enter() for pid (%d)\n",
			current->pid));

		current->okernel_status = OKERNEL_ON;

		if(vmx_nr_mode()){
			printk(KERN_CRIT "Calling okernel_enter in  NR mode kernel...shouldn't get here!!\n");
		}
		
		ret = okernel_enter();
		
#if 1
		if(vmx_nr_mode()){
			asm volatile("xchg %bx, %bx");
			printk(KERN_CRIT "Returning in ok_device_ioctl in cloned process NR mode kernel.\n");
			asm volatile("xchg %bx, %bx");
			do_exit(1);
			vmcall(VMCALL_NOP);
			return 0;
		}
#endif
		current->okernel_status = OKERNEL_OFF;

		if(ret){
			printk(KERN_ERR "okernel_enter failed for pid <%d> ret (%lu)\n",
			       current->pid, (unsigned long)ret);
		}
		HDEBUG(("NR kernel off for <%d>\n", current->pid));
		break;
	default:
		printk(KERN_ERR "okernel invalid IOCTL cmd.\n");
		return -ENODEV;
		
	}
	return 0;
}


static int ok_device_release(struct inode *inode, struct file *file)
{
	HDEBUG(("Releasing device <%s>\n", DEVICE_NAME));
	return 0;
}



static struct file_operations fops={
    .open = ok_device_open,
    .release = ok_device_release,
    .unlocked_ioctl = ok_device_ioctl
};


static int __init okernel_init(void)
{
	unsigned long tmpl;
	
	HDEBUG(("Start initialization...\n"));
	
	major_no = register_chrdev(0, DEVICE_NAME, &fops);
	HDEBUG(("Creating Device Major_no : %d\n", major_no));
	okernel_dev_class = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(okernel_dev_class, NULL, MKDEV(major_no,0), NULL, DEVICE_NAME);
	HDEBUG(("Device <%s> Initialized in kernel.\n", DEVICE_NAME));

	if((vmx_init())){
		printk(KERN_ERR "okernel: failed to initialize x86 vmx extensions.\n");
		okernel_enabled = 0;
		return -1;
	}

	okernel_enabled = 1;
	okernel_dump_stack_info();
	asm("mov $.Lc_rip_label, %0" : "=r"(tmpl));

	HDEBUG(("cloned thread RIP will be set to: (%#lx)\n", tmpl));
	cloned_thread.rip = tmpl;
	HDEBUG(("Enabled, initialization done.\n"));
	return 0;
}

static void  __exit okernel_exit(void)
{
	HDEBUG(("exit called.\n"));
	okernel_enabled = 0;
	HDEBUG(("Removing device (%s)\n", DEVICE_NAME));
	device_destroy(okernel_dev_class,MKDEV(major_no,0));
	class_unregister(okernel_dev_class);
	class_destroy(okernel_dev_class);
	unregister_chrdev(major_no, DEVICE_NAME);
	HDEBUG(("done.\n"));
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

