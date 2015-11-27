#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/okernel.h>

#include "vmx.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Okernel intra-kernel protection");

extern void __ok_schedule(void);

int okernel_enabled;
unsigned long cloned_thread_rip;

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

static int __init okernel_init(void)
{
	unsigned long tmpl;
	
	HDEBUG(("Start initialization...\n"));
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
	okernel_enabled = 0;
	HDEBUG(("exit called.\n"));
}
EXPORT_SYMBOL(okernel_schedule_helper);
EXPORT_SYMBOL(okernel_enabled);
EXPORT_SYMBOL(okernel_setup);
EXPORT_SYMBOL(okernel_enter);
module_init(okernel_init)
module_exit(okernel_exit)

