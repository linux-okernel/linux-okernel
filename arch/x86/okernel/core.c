#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/perf_event.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/okernel.h>

#include <asm/virtext.h>

int okernel_enabled;

static int vmx_init(void)
{
	if (!cpu_has_vmx()) {
		printk(KERN_ERR "vmx: CPU does not support VT-x\n");
		return -EIO;
	}
	return 0;
}

static int __init okernel_init(void)
{
	/* Should only be called on boot-cpu during init/main.c */
	
	printk(KERN_DEBUG "okernel_init: 1\n");

	if((vmx_init())){
		printk(KERN_ERR "okernel: failed to initialize x86 vmx extensions.\n");
		okernel_enabled = 0;
		return -1;
	}

	printk(KERN_DEBUG "okernel_init: 2\n");
	okernel_enabled = 1;
	return 0;
}

static void __exit okernel_exit(void)
{
	printk(KERN_DEBUG "okernel: exit called.\n");
}

module_init(okernel_init);
module_exit(okernel_exit);
