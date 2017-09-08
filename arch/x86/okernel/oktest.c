/*
 * Author: Nigel Edwards, 2017
 */

#include<linux/memory.h>
#include<linux/mm.h>
#include<linux/syscalls.h>
#include<linux/kmod.h>
#include<asm-generic/sections.h>
#include<asm/text-patching.h>
#include<asm/set_memory.h>



/* For the oktest ioctl device */
#define DEVICE_NAME "oktest"
#define DEVICE_PATH "/dev/oktest"
#define MAGIC_NO '4'

#define OKTEST_EXEC _IOW(MAGIC_NO, 0, unsigned long)

static struct class *oktest_dev_class;
static int major_no;

extern int set_memory_rw(unsigned long addr, int numpages);
extern void flush_tlb_all(void);
extern void *text_poke(void *addr, const void *opcode, size_t len);
extern void flush_tlb_kernel_range(unsigned long start, unsigned long end);
extern pte_t *lookup_address(unsigned long, unsigned int *);
extern char __vsyscall_page;
void oktargets(unsigned long (*address)[])
{
	(*address)[0] = (unsigned long)_text;
	(*address)[1] = (unsigned long)_etext;
	(*address)[2] = (unsigned long)&__start_rodata;
	(*address)[3] = (unsigned long)&__end_rodata;
	(*address)[4] = (unsigned long)set_memory_rw;
	(*address)[5] = (unsigned long)flush_tlb_all;
	(*address)[6] = (unsigned long)linux_proc_banner;
	(*address)[7] = (unsigned long)text_poke;
	(*address)[8] = (unsigned long)&text_mutex;
	(*address)[9] = (unsigned long)sys_unlinkat;
	(*address)[10] = (unsigned long)register_sysctl_table;
}

static int oktest_device_open(struct inode *inode, struct file *file)
{
	printk("Opening device <%s>\n", DEVICE_NAME);
	return 0;
}

long oktest_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void (*func)(void);
	unsigned long cr4;
	printk("oktest_ioctl called.\n");
	switch(cmd)
	{
	case OKTEST_EXEC:
		printk(KERN_INFO " oktest updating CR4 to bypass SMAP/SMEP\n");
		cr4 = native_read_cr4();
		printk("oktest CR4 is currently set to %#lx\n", cr4);
		cr4 = cr4 & ~(X86_CR4_SMEP|X86_CR4_SMAP);
		native_write_cr4(cr4);
		printk("SMAP/SMEP disabled CR4 now %#lx\n", cr4);
		func = (void (*)(void))arg;
		printk("Invoking supplied function\n");
		func();
		printk("Done invocation\n");
		return 0;
		break;

	default:

		printk(KERN_ERR "oktest invalid IOCTL cmd.\n");
		return -ENODEV;

	}
	return 0;
}


static int oktest_device_release(struct inode *inode, struct file *file)
{
	printk("Releasing device <%s>\n", DEVICE_NAME);
	return 0;
}

static struct file_operations fops={
    .open = oktest_device_open,
    .release = oktest_device_release,
    .unlocked_ioctl = oktest_ioctl
};


static int ok_test_dev_init(void)
{

	printk("Start initialization...\n");

	major_no = register_chrdev(0, DEVICE_NAME, &fops);
	printk("Creating Device Major_no : %d\n", major_no);
	oktest_dev_class = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(oktest_dev_class, NULL, MKDEV(major_no,0), NULL, DEVICE_NAME);
	printk("Device <%s> Initialized in kernel.\n", DEVICE_NAME);
	return 0;
}

static void ok_test_dev_remove(void)
{

	printk("Removing device (%s)\n", DEVICE_NAME);
	device_destroy(oktest_dev_class, MKDEV(major_no,0));
	class_unregister(oktest_dev_class);
	class_destroy(oktest_dev_class);
	unregister_chrdev(major_no, DEVICE_NAME);
	printk("Removed\n");
	return;
}

EXPORT_SYMBOL_GPL(ok_test_dev_init);
EXPORT_SYMBOL_GPL(ok_test_dev_remove);
EXPORT_SYMBOL_GPL(oktargets);


