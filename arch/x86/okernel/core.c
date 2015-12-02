#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/okernel.h>
#include <linux/kdev_t.h>

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
unsigned long cloned_thread_rip;

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

int __noclone okernel_enter(int64_t *ret)
{
	int r = 0;
	int64_t dummy;
	
	HDEBUG(("called.\n"));

#if 0
	HDEBUG(("1 (before clean and jmp)\n"));

	// Do the clean and jmp as though this function has returned.
	asm("jmp .Lc_rip_label");

	HDEBUG(("2 (after clean and jmp - shouldn't get here!)\n"));
#endif
	dummy = 0;
	r = vmx_launch(&dummy);

	asm(".Lc_rip_label: ");

	return r;
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
		HDEBUG(("would do okernel_enter()\n"));
		current->okernel_status = OKERNEL_ON;
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
	
	cloned_thread_rip = tmpl;
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

