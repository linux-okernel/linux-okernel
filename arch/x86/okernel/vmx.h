/*
 * Derived from original dune header:
 * vmx.h - header file for USM VMX driver.
 */

#include <linux/mmu_notifier.h>
#include <linux/types.h>
//#include <asm/tlbflush.h>
#include <asm/vmx.h>
#include <linux/kvm_types.h>


#define GPA_STACK_SIZE  ((unsigned long) 1 << 28) /* 256 megabytes */
#define GPA_MAP_SIZE    (((unsigned long) 1 << 31) - GPA_STACK_SIZE) /* 1.75 gigabytes */
#define LG_ALIGN(addr)  ((addr + (1 << 21) - 1) & ~((1 << 21) - 1))

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


struct vmx_vcpu {
	int cpu;
	int vpid;
	int launched;

	struct mmu_notifier mmu_notifier;
	spinlock_t ept_lock;
	unsigned long ept_root;
	unsigned long eptp;
	bool ept_ad_enabled;

	u8  fail;
	u64 exit_reason;
	u64 host_rsp;
	u64 regs[NR_VCPU_REGS];
	u64 cr2;

	int shutdown;
	int ret_code;

	struct msr_autoload {
		unsigned nr;
		struct vmx_msr_entry guest[NR_AUTOLOAD_MSRS];
		struct vmx_msr_entry host[NR_AUTOLOAD_MSRS];
	} msr_autoload;

	struct vmcs *vmcs;
	void *syscall_tbl;
};

extern __init int vmx_init(void);
extern void vmx_exit(void);

//extern int vmx_launch(struct dune_config *conf, int64_t *ret_code);

extern int vmx_init_ept(struct vmx_vcpu *vcpu);
extern int vmx_create_ept(struct vmx_vcpu *vcpu);
extern void vmx_destroy_ept(struct vmx_vcpu *vcpu);

extern int
vmx_do_ept_fault(struct vmx_vcpu *vcpu, unsigned long gpa,
                 unsigned long gva, int fault_flags);

extern void vmx_ept_sync_vcpu(struct vmx_vcpu *vcpu);
extern void vmx_ept_sync_individual_addr(struct vmx_vcpu *vcpu, gpa_t gpa);


static __always_inline unsigned long vmcs_readl(unsigned long field)
{
        unsigned long value;

        asm volatile (ASM_VMX_VMREAD_RDX_RAX
                      : "=a"(value) : "d"(field) : "cc");
        return value;
}
