/*
 * Derived from original dune header:
 * vmx.h - header file for USM VMX driver.
 */

#include <linux/mmu_notifier.h>
#include <linux/types.h>
//#include <asm/tlbflush.h>
#include <asm/vmx.h>
#include <linux/kvm_types.h>
#include <linux/okernel.h>
#include "constants2.h"


struct nr_cloned_state {
	unsigned long rflags;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rbx;
	unsigned long rsp;
	unsigned long rbp;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	unsigned long r11;
	unsigned long r12;
	unsigned long r13;
	unsigned long r14;
	unsigned long r15;
	unsigned long rip;
	unsigned long cr2;
	unsigned long msr_fs_base;
	unsigned long msr_gs_base;
	unsigned int  idt_limit;
	unsigned long idt_base;
};

/* Need to make these non-global */
/* Initial cloned thread state */

//extern struct nr_cloned_state cloned_thread;



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

#define SECONDARY_EXEC_MODE_BASE_CTL	0x00400000

#ifndef X86_CR4_FSGSBASE
#define X86_CR4_FSGSBASE	X86_CR4_RDWRGSFS
#endif

#define RFLAGS_IF_BIT 0x200

#if 0
#define HPL_DEBUG
#ifdef HPL_DEBUG
#define HDEBUG(args) (printk(KERN_ERR "%s: cpu(%d) %s: ", vmx_nr_mode()?"NR":"R", raw_smp_processor_id(), __func__), printk args)
#else
#define HDEBUG(args)
#endif
//#define HPL_DEBUG2
#ifdef HPL_DEBUG2
#define HDEBUG2(args) (printk(KERN_ERR "NR(%u):  cpu(%d) %s: ", vmx_nr_mode(), raw_smp_processor_id(), __func__), printk args)
#else
#define HDEBUG2(args)
#endif
#endif

#if 0
#define read_cr4 native_read_cr4

void write_cr4(unsigned long cr4_val)
{
	this_cpu_write(cpu_tlbstate.cr4, cr4);
	__write_cr4(cr4_val);
}
#endif

static inline void
asm_rdrsp (ulong *rsp)
{
#ifdef __x86_64__
        asm volatile ("mov %%rsp,%0" : "=rm" (*rsp));
#else
        asm volatile ("mov %%esp,%0" : "=rm" (*rsp));
#endif
}

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

struct ept_pt_list {
	struct list_head list;
	pt_page* page;
	int n_pages;
};

#define VCPUBUFLEN 300
#define NVCPUBUF 1000

struct vmx_vcpu {
	int cpu;
	int vpid;
	int launched;

	//struct mmu_notifier mmu_notifier;
	struct ept_pt_list ept_table_pages;
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
	struct thread_info *cloned_thread_info;
	struct task_struct *cloned_tsk;
	struct nr_cloned_state *cloned_thread;
	unsigned int *nr_stack_canary;
	void *syscall_tbl;

	/* Circular log pending NR-mode lock-safe logging*/
	char log[NVCPUBUF][VCPUBUFLEN];
	/* Pointer to next entry in circular log*/
	int lp;
};
#define VCPU_DEBUG_INIT "\n"

extern __init int vmx_init(void);
extern void vmx_exit(void);
extern int vmx_launch(unsigned int mode, unsigned int flags, struct nr_cloned_state *cloned_thread);
extern int vmx_init_ept(struct vmx_vcpu *vcpu);
extern int vmx_create_ept(struct vmx_vcpu *vcpu);
extern void vmx_destroy_ept(struct vmx_vcpu *vcpu);

extern int
vmx_do_ept_fault(struct vmx_vcpu *vcpu, unsigned long gpa,
                 unsigned long gva, int fault_flags);

extern void vmx_ept_sync_vcpu(struct vmx_vcpu *vcpu);
extern void vmx_ept_sync_individual_addr(struct vmx_vcpu *vcpu, gpa_t gpa);
extern int vt_alloc_page(void **virt, u64 *phys);


static __always_inline unsigned long vmcs_readl(unsigned long field)
{
        unsigned long value;

        asm volatile (ASM_VMX_VMREAD_RDX_RAX
                      : "=a"(value) : "d"(field) : "cc");
        return value;
}


#define VMX_EPT_FAULT_READ	0x01
#define VMX_EPT_FAULT_WRITE	0x02
#define VMX_EPT_FAULT_INS	0x04

typedef unsigned long epte_t;

#define __EPTE_READ	0x01
#define __EPTE_WRITE	0x02
#define __EPTE_EXEC	0x04
#define __EPTE_IPAT	0x40
#define __EPTE_SZ	0x80
#define __EPTE_A	0x100
#define __EPTE_D	0x200
#define __EPTE_PFNMAP	0x400 /* ignored by HW */
#define __EPTE_TYPE(n)	(((n) & 0x7) << 3)

enum {
	EPTE_TYPE_UC = 0, /* uncachable */
	EPTE_TYPE_WC = 1, /* write combining */
	EPTE_TYPE_WT = 4, /* write through */
	EPTE_TYPE_WP = 5, /* write protected */
	EPTE_TYPE_WB = 6, /* write back */
};

#define __EPTE_NONE	0
#define __EPTE_FULL	(__EPTE_READ | __EPTE_WRITE | __EPTE_EXEC)

#define EPTE_ADDR	(~(PAGE_SIZE - 1))
#define EPTE_FLAGS	(PAGE_SIZE - 1)

static inline uintptr_t epte_addr(epte_t epte)
{
	return (epte & EPTE_ADDR);
}

static inline uintptr_t epte_page_vaddr(epte_t epte)
{
	return (uintptr_t) __va(epte_addr(epte));
}

static inline epte_t epte_flags(epte_t epte)
{
	return (epte & EPTE_FLAGS);
}

static inline int epte_present(epte_t epte)
{
	return (epte & __EPTE_FULL) > 0;
}

static inline int epte_big(epte_t epte)
{
	return (epte & __EPTE_SZ) > 0;
}

#define ADDR_INVAL ((unsigned long) -1)
