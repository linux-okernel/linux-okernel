#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/okernel.h>

#include "constants.h"
#include "vt.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Okernel intra-kernel protection");


int okernel_enabled;


int okernel_setup(void)
{
	HDEBUG(("called.\n"));
	return 1;
}

int okernel_activate(void)
{
	HDEBUG(("called.\n"));
	return 1;
}


static int __init okernel_init(void)
{
	HDEBUG(("Start initialization...\n"));
	
	if((vt_init())){
		printk(KERN_ERR "okernel: failed to initialize x86 vmx extensions.\n");
		okernel_enabled = 0;
		return -1;
	}
	okernel_enabled = 1;
	HDEBUG(("Enabled, initialization done.\n"));
	return 0;
}

static void  __exit okernel_exit(void)
{
	okernel_enabled = 0;
	HDEBUG(("exit called.\n"));
}

EXPORT_SYMBOL(okernel_enabled);
EXPORT_SYMBOL(okernel_setup);
EXPORT_SYMBOL(okernel_activate);
module_init(okernel_init)
module_exit(okernel_exit)

