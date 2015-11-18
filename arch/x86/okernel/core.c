#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/okernel.h>

#include "constants.h"
#include "vmx-simple.h"


int okernel_enabled;

static int __init okernel_init(void)
{
	HDEBUG(("Start initialization...\n"));

	if((vmx_init())){
		printk(KERN_ERR "okernel: failed to initialize x86 vmx extensions.\n");
		okernel_enabled = 0;
		return -1;
	}

	okernel_enabled = 1;
	HDEBUG(("Enabled, initialization done.\n"));
	return 0;
}

static void __exit okernel_exit(void)
{
	HDEBUG(("exit called.\n"));
}

module_init(okernel_init);
module_exit(okernel_exit);
