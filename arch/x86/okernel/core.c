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

extern void __ok_schedule(void);

int okernel_enabled;

void okernel_schedule_helper(void)
{
	int a = 0;
	
	a++;
	//HDEBUG(("called a: (%d)\n", a));
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

static void __noclone  okernel_test_stack_clean_and_jmp(int a, int b, int c, int d, int e, int f)
{
	unsigned long tmpl;

	a = 1; b = 2;
	
	asm("mov $.Lokernel_clone_rip, %0" : "=r"(tmpl));

        //asm("push %r12 ");
	HDEBUG(("cloned thread RIP will be set to: (%#lx)\n", tmpl));
	
	
	HDEBUG(("1 (before clean and jmp: a(%d), b(%d))\n", a, b));

	// Do the clean and jmp as though this function has returned.
	asm("jmp .Lokernel_clone_rip ");
	
	a++; b++;
	HDEBUG(("2 (after clean and jmp: a(%d) b(%d) - shouldn't get here!)\n", a, b));
	
	asm(".Lokernel_clone_rip: ");
	return;
}

int okernel_enter(void)
{
	HDEBUG(("called.\n"));
	okernel_test_stack_clean_and_jmp(1,2,3,4,5,6);
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
	okernel_dump_stack_info();
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

