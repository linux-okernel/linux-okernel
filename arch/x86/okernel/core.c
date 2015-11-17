#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/okernel.h>

#include "vmx-simple.h"


int okernel_enabled;

static int __init okernel_init(void)
{
	printk(KERN_ERR "okernel_init: 1\n");

	if((vmx_init())){
		printk(KERN_ERR "okernel: failed to initialize x86 vmx extensions.\n");
		okernel_enabled = 0;
		return -1;
	}

	printk(KERN_ERR "okernel_init: 2\n");
	okernel_enabled = 1;
	return 0;
}

static void __exit okernel_exit(void)
{
	printk(KERN_DEBUG "okernel: exit called.\n");
}

module_init(okernel_init);
module_exit(okernel_exit);
