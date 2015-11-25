/*
 * Derived from original dune header:
 * vmx.h - header file for USM VMX driver.
 */

#include <linux/mmu_notifier.h>
#include <linux/types.h>
//#include <asm/tlbflush.h>
#include <asm/vmx.h>
#include <linux/kvm_types.h>

#if !defined(VMX_EPT_AD_BIT)
#define VMX_EPT_AD_BIT          (1ull << 21)
#define VMX_EPT_AD_ENABLE_BIT   (1ull << 6)
#endif

#ifndef VMX_EPT_EXTENT_INDIVIDUAL_BIT
#define VMX_EPT_EXTENT_INDIVIDUAL_BIT           (1ull << 24)
#endif

#ifndef X86_CR4_PCIDE
#define X86_CR4_PCIDE		0x00020000 /* enable PCID support */
#endif

#ifndef SECONDARY_EXEC_ENABLE_INVPCID
#define SECONDARY_EXEC_ENABLE_INVPCID	0x00001000
#endif

#ifndef X86_CR4_FSGSBASE
#define X86_CR4_FSGSBASE	X86_CR4_RDWRGSFS
#endif


#define HPL_DEBUG
#ifdef HPL_DEBUG
#define HDEBUG(args) (printk(KERN_ERR "ok: cpu(%d) %s: ", raw_smp_processor_id(), __func__), printk args)
#else
#define HDEBUG(args)
#endif
//#define HPL_DEBUG2
#ifdef HPL_DEBUG2
#define HDEBUG2(args) (printk(KERN_ERR "ok: cpu(%d) %s: ", raw_smp_processor_id(), __func__), printk args)
#else
#define HDEBUG2(args)
#endif


#if 0
#define read_cr4 native_read_cr4

void write_cr4(unsigned long cr4_val)
{
	this_cpu_write(cpu_tlbstate.cr4, cr4);
	__write_cr4(cr4_val);
}
#endif

DECLARE_PER_CPU(struct vmx_vcpu *, local_vcpu);

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

struct vmx_capability {
	u32 ept;
	u32 vpid;
	int has_load_efer:1;
};

extern struct vmx_capability vmx_capability;

#define NR_AUTOLOAD_MSRS 8

enum vmx_reg {
	VCPU_REGS_RAX = 0,
	VCPU_REGS_RCX = 1,
	VCPU_REGS_RDX = 2,
	VCPU_REGS_RBX = 3,
	VCPU_REGS_RSP = 4,
	VCPU_REGS_RBP = 5,
	VCPU_REGS_RSI = 6,
	VCPU_REGS_RDI = 7,
#ifdef CONFIG_X86_64
	VCPU_REGS_R8 = 8,
	VCPU_REGS_R9 = 9,
	VCPU_REGS_R10 = 10,
	VCPU_REGS_R11 = 11,
	VCPU_REGS_R12 = 12,
	VCPU_REGS_R13 = 13,
	VCPU_REGS_R14 = 14,
	VCPU_REGS_R15 = 15,
#endif
	VCPU_REGS_RIP,
	NR_VCPU_REGS
};


extern __init int vmx_init(void);
extern void vmx_exit(void);

static __always_inline unsigned long vmcs_readl(unsigned long field)
{
        unsigned long value;

        asm volatile (ASM_VMX_VMREAD_RDX_RAX
                      : "=a"(value) : "d"(field) : "cc");
        return value;
}


static __always_inline u16 vmcs_read16(unsigned long field)
{
	return vmcs_readl(field);
}

static __always_inline u32 vmcs_read32(unsigned long field)
{
	return vmcs_readl(field);
}

static __always_inline u64 vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return vmcs_readl(field);
#else
	return vmcs_readl(field) | ((u64)vmcs_readl(field+1) << 32);
#endif
}

#if 0
static noinline void vmwrite_error(unsigned long field, unsigned long value)
{
	printk(KERN_ERR "vmwrite error: reg %lx value %lx (err %d)\n",
	       field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
	dump_stack();
}

static void vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile (ASM_VMX_VMWRITE_RAX_RDX "; setna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
	if (unlikely(error))
		vmwrite_error(field, value);
}

static void vmcs_write16(unsigned long field, u16 value)
{
	vmcs_writel(field, value);
}

static void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_writel(field, value);
}

static void vmcs_write64(unsigned long field, u64 value)
{
	vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	vmcs_writel(field+1, value >> 32);
#endif
}
#endif
