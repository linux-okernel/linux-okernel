/*
 * vmx.c - The Intel VT-x driver for intra-kernel protection using
 * vt-x features. The vmx setup code of this file is derived from the
 * dune code base which itself is derived from the kvm code base (with
 * the hope that we can possibly at some point share code).  The EPT
 * code is not dune/kvm based and was developed originally for
 * microvisor use.
 *
 * This is still very much a (limited) research prototype.
 *
 * Author: C I Dalton <cid@hpe.com> 2015
 *
 * This is the original dune header:

 * This file is derived from Linux KVM VT-x support.
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Original Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This modified version is simpler because it avoids the following
 * features that are not requirements for Dune:
 *  * Real-mode emulation
 *  * Nested VT-x support
 *  * I/O hardware emulation
 *  * Any of the more esoteric X86 features and registers
 *  * KVM-specific functionality
 *
 * In essence we provide only the minimum functionality needed to run
 * a process in vmx non-root mode rather than the full hardware emulation
 * needed to support an entire OS.
 *
 * This driver is a research prototype and as such has the following
 * limitations:
 *
 * FIXME: Backward compatability is currently a non-goal, and only recent
 * full-featured (EPT, PCID, VPID, etc.) Intel hardware is supported by this
 * driver.
 *
 * FIXME: Eventually we should handle concurrent user's of VT-x more
 * gracefully instead of requiring exclusive access. This would allow
 * Dune to interoperate with KVM and other HV solutions.
 *
 * FIXME: We need to support hotplugged physical CPUs.
 *
 * Authors:
 *   Adam Belay   <abelay@stanford.edu>
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/ftrace.h>
#include <linux/slab.h>
#include <linux/tboot.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/syscalls.h>
#include <linux/console.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/gfp.h>
#include <linux/jump_label.h>
#include <linux/rbtree.h>

/* The following #includes are for tracking of static_key patching*/
#include <linux/cpuset.h>
#include <linux/memcontrol.h>
#include <linux/perf_event.h>
#include <linux/page_owner.h>
#include <linux/bpf-cgroup.h>
#include <linux/frontswap.h>
#include <linux/context_tracking_state.h>
#include <linux/cgroup-defs.h>
/* End of #includes for static_key patching*/

#include <asm/mtrr.h>
#include <asm/desc.h>
#include <asm/vmx.h>
#include <asm/unistd_64.h>
#include <asm/virtext.h>
#include <asm/percpu.h>
//#include <asm/paravirt.h>
#include <asm/pgtable_types.h>
#include <asm/preempt.h>
#include <asm/tlbflush.h>
#include <asm/e820/api.h>
#include <asm/fixmap.h>			/* VSYSCALL_ADDR */

#include "constants2.h"
#include "vmx.h"
#include "okmm.h"

static atomic_t vmx_enable_failed;

static DECLARE_BITMAP(vmx_vpid_bitmap, VMX_NR_VPIDS);
static DEFINE_SPINLOCK(vmx_vpid_lock);


/* Rudimentary 'protected' memory allocator */
#define OK_NR_PROTECTED_PAGES 8
static DECLARE_BITMAP(ok_protected_pg_bitmap, OK_NR_PROTECTED_PAGES);
static DEFINE_SPINLOCK(ok_protected_pg_lock);
static struct page *ok_protected_page;
static struct page *ok_protected_dummy_page;

unsigned long ok_protected_pfn_start;
unsigned long ok_protected_pfn_end;

void ok_free_protected_page_by_id(pid_t pid);
bool ok_allow_protected_access(unsigned long phys_addr);
unsigned long ok_get_protected_dummy_paddr(void);

/* For Demo Hack Only */
//#define OK_DEMO_HACK_MESSAGE
#ifdef OK_DEMO_HACK_MESSAGE
#define OK_DUMMY_TEXT "No secrets here, move along please."
#endif

static unsigned long *msr_bitmap;

static unsigned long max_phys_mem;
static unsigned long ept_limit;
static unsigned long ept_no_cache_start;



static DEFINE_PER_CPU(struct vmcs *, vmxarea);
static DEFINE_PER_CPU(struct desc_ptr, host_gdt);
static DEFINE_PER_CPU(int, vmx_enabled);
DEFINE_PER_CPU(struct vmx_vcpu *, local_vcpu);

static struct vmcs_config {
	int size;
	int order;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
} vmcs_config;

struct vmx_capability vmx_capability;

/* EPT violation context*/
struct eptvc {
	struct vmx_vcpu *vcpu;
	unsigned long gpa; /* guest or non root physical address */
	unsigned long gva; /* guest or non root virtual address */
	unsigned long qual; /* The qualification from VMEXIT */
};

#define NR_FIXUP_PAGES 3
static struct fixup_pages {
	struct {
		unsigned long pa;
		unsigned long prot;
	} pages[NR_FIXUP_PAGES];
	int index;
} fixup_pages = {.index = 0};

struct key_tag {
	struct static_key *key;
	char *tag;
};

extern struct static_key_false sched_smt_present;
extern struct static_key_false sched_numa_balancing;
extern struct static_key_false sched_schedstats;
extern struct static_key_true **ok_cgrp_subsys_enabled_key;
extern struct static_key_true **ok_cgrp_subsys_on_dfl_key;
#ifdef CONFIG_NF_TABLES
extern struct static_key_false nft_trace_enabled;
#endif
static struct key_tag static_key_tags[] = {
	{&cpusets_pre_enable_key.key, "cpusets_pre_enable_key"},
	{&cpusets_enabled_key.key, "cpusets_enabled_key"},
	{&sched_smt_present.key, "sched_smt_present"},
	{&sched_numa_balancing.key, "sched_numa_balancing"},
	{&sched_schedstats.key, "sched_schedstats"},
#ifdef CONFIG_NF_TABLES
	{&nft_trace_enabled.key, "nft_trace_enabled"},
#endif
	{&memcg_sockets_enabled_key.key, "memcg_sockets_enabled_key"},
	{&memcg_kmem_enabled_key.key, "memcg_kmem_enabled_key"},
	{&perf_sched_events.key, "perf_sched_events"},
#ifdef CONFIG_PAGE_OWNER
	{&page_owner_inited.key, "page_owner_inited"},
#endif
#ifdef CONFIG_CGROUP_BPF
	{&cgroup_bpf_enabled_key.key, "cgroup_bpf_enabled_key"},
#endif
	{&frontswap_enabled_key.key, "frontswap_enabled_key"},
#ifdef CONFIG_CONTEXT_TRACKING
	{&context_tracking_enabled.key, "context_tracking_enabled"},
#endif
	{NULL, NULL}
};

/* Container for addresses which might be patched. Currently we only
 * handle patches which use the static_key mechanism, see:
 * ./Documentation/static-keys.txt */
struct patch_addr {
	struct rb_node node;
	unsigned long pa;
	char *tag;
};

static struct rb_root patch_addresses = RB_ROOT;

static struct patch_addr *mk_patch_addr(unsigned long pa, char *tag)
{
	struct patch_addr *p;
	p = (struct patch_addr *)kmalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return NULL;
	p->pa = pa;
	p->tag = tag;
	return p;
}

static struct patch_addr *find_patch_addr(struct rb_root *root, unsigned long pa)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct patch_addr *data = container_of(node, struct patch_addr,
						       node);
		if (pa < data->pa)
			node = node->rb_left;
		else if (pa > data->pa)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}


static int insert_patch_addr(struct rb_root *root, struct patch_addr *new)
{
	struct rb_node **data = &(root->rb_node), *parent = NULL;
	/* Figure out where to put new node */
	while (*data) {
		struct patch_addr *this = container_of(*data, struct patch_addr,
						       node);
		parent = *data;
		if (new->pa < this->pa)
			data = &((*data)->rb_left);
		else if (new->pa > this->pa)
			data = &((*data)->rb_right);
		else
			return FALSE;
	}
	/* Add new node and rebalance tree. */
	rb_link_node(&new->node, parent, data);
	rb_insert_color(&new->node, root);

	return TRUE;
}


static inline int dummy_in_vmx_nr_mode(void)
{
	return 0;
}

static inline int real_in_vmx_nr_mode(void)
{
	unsigned long cr4;

	cr4 = native_read_cr4();

	if(cr4 & X86_CR4_VMXE)
		return 0;
	return 1;
}


static int (*in_vmx_nr_mode)(void) = dummy_in_vmx_nr_mode;

inline int is_in_vmx_nr_mode(void)
{
	return in_vmx_nr_mode();
}

/* Copy vcpu regs into a pt_regs structure */
void copy_vcpu_to_ptregs(struct vmx_vcpu *vcpu, struct pt_regs *regs)
{


	regs->bp = vcpu->regs[VCPU_REGS_RBP];
	regs->ip = vcpu->regs[VCPU_REGS_RIP];


	regs->ax = vcpu->regs[VCPU_REGS_RAX];
	regs->cx = vcpu->regs[VCPU_REGS_RCX];
	regs->dx = vcpu->regs[VCPU_REGS_RDX];
	regs->bx = vcpu->regs[VCPU_REGS_RBX];

	regs->si = vcpu->regs[VCPU_REGS_RSI];
	regs->di = vcpu->regs[VCPU_REGS_RDI];

	regs->r8 = vcpu->regs[VCPU_REGS_R8];
	regs->r9 = vcpu->regs[VCPU_REGS_R9];
	regs->r10 = vcpu->regs[VCPU_REGS_R10];
	regs->r11 = vcpu->regs[VCPU_REGS_R11];
	regs->r12 = vcpu->regs[VCPU_REGS_R12];
	regs->r13 = vcpu->regs[VCPU_REGS_R13];
	regs->r14 = vcpu->regs[VCPU_REGS_R14];
	regs->r15 = vcpu->regs[VCPU_REGS_R15];
}


/* Started from https://github.com/rustyrussell/virtbench/blob/master/micro/vmcall.c */
/* Added multiple register arg passing and return val. Need to guard the use of this call */
int vmcall(unsigned int cmd)
{
	unsigned long rax;

	asm volatile(".byte 0x0F,0x01,0xC1\n" ::"a"(cmd));
	asm volatile ("mov %%rax,%0" : "=rm" (rax));
	return (int)rax;
}

int vmcall2(unsigned int cmd, unsigned long arg1)
{
	unsigned long rax;

	asm volatile(".byte 0x0F,0x01,0xC1\n" ::"a"(cmd),"b"(arg1));
	asm volatile ("mov %%rax,%0" : "=rm" (rax));
	return (int)rax;
}

int vmcall3(unsigned int cmd, unsigned long arg1, unsigned long arg2)
{
	unsigned long rax;

	asm volatile(".byte 0x0F,0x01,0xC1\n" ::"a"(cmd),"b"(arg1),"c"(arg2));
	asm volatile ("mov %%rax,%0" : "=rm" (rax));
	return (int)rax;
}

int vmcall4(unsigned int cmd, unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
	unsigned long rax;
	register long r10 asm("r10") = arg3;

	asm volatile(".byte 0x0F,0x01,0xC1\n" ::"a"(cmd),"b"(arg1),"c"(arg2), "r"(r10));
	asm volatile ("mov %%rax,%0" : "=rm" (rax));
	return (int)rax;
}

int vmcall5(unsigned int cmd, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4)
{
	unsigned long rax;
	register long r10 asm("r10") = arg3;
	register long r11 asm("r11") = arg4;

	asm volatile(".byte 0x0F,0x01,0xC1\n" ::"a"(cmd),"b"(arg1),"c"(arg2), "r"(r10), "r"(r11));
	asm volatile ("mov %%rax,%0" : "=rm" (rax));
	return (int)rax;
}

int vmcall6(unsigned int cmd, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	unsigned long rax;
	register long r10 asm("r10") = arg3;
	register long r11 asm("r11") = arg4;
	register long r12 asm("r12") = arg5;

	asm volatile(".byte 0x0F,0x01,0xC1\n" ::"a"(cmd),"b"(arg1),"c"(arg2), "r"(r10), "r"(r11), "r"(r12));
	asm volatile ("mov %%rax,%0" : "=rm" (rax));
	return (int)rax;
}

#if 1
static int
no_cache_region(u64 addr, u64 size)
{

	if (((addr > ((1UL << 32) -1))) ||
	    ((addr >= 0x1000) && (addr < 0x8F000)) ||
	    ((addr >= 0x90000) && (addr < 0xa0000)) ||
	    ((addr >= 0x100000) && (addr < ept_no_cache_start))){
	     return 0;
	}
	return 1;
}
#endif

#if 0
/* This is currently 8560p specific obviously Need to fix this...adjust dynamically based on real physical regions */
#define END_PHYSICAL 0x3FFFFFFFF /* with 1GB physical memory */
static int
no_cache_region(u64 addr, u64 size)
{
	if (((addr >= 0x1000) && (addr < 0x8F000)) ||
	    ((addr >= 0x90000) && (addr < 0xa0000)) ||
		((addr >= 0x100000) && (addr < END_PHYSICAL))){
		return 0;
	}
	return 1;
}
#endif

#if 0 // Bochs
#define END_PHYSICAL 0x3FFEFFFFF /* with 1GB physical memory */

static int
no_cache_region(u64 addr, u64 size)
{
	if (((addr >= 0x0) && (addr < 0x9F00))||((addr >= BIOS_END) && (addr < END_PHYSICAL))){
		return 0;
	}
	return 1;
}
#endif


/* Adapted from e820_end_pfn */
static unsigned long e820_end_paddr(unsigned long limit_pfn)
{
	int i;
	unsigned long last_pfn = 0;
	unsigned long max_arch_pfn = (MAXMEM >> PAGE_SHIFT);

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *ei = &e820_table->entries[i];
		unsigned long start_pfn;
		unsigned long end_pfn;

		start_pfn = ei->addr >> PAGE_SHIFT;
		end_pfn = (ei->addr + ei->size) >> PAGE_SHIFT;

		if (start_pfn >= limit_pfn)
			continue;
		if (end_pfn > limit_pfn) {
			last_pfn = limit_pfn;
			break;
		}
		if (end_pfn > last_pfn)
			last_pfn = end_pfn;
	}

	if (last_pfn > max_arch_pfn)
		last_pfn = max_arch_pfn;

	OKDEBUG("last_pfn = %#lx max_arch_pfn = %#lx\n", last_pfn, max_arch_pfn);
	return last_pfn << PAGE_SHIFT;
}

int vt_alloc_page(void **virt, u64 *phys)
{
        struct page *pg;
        void* v;

        pg = alloc_page(GFP_KERNEL);

        v = page_address(pg);

        if(!v){
                printk(KERN_ERR "okernel: failed to alloc page.\n");
                return 0;
        }

        if(virt)
                *virt = v;
        if(phys)
                *phys = page_to_phys(pg);
        return 1;
}

int vt_alloc_pages(struct pt_page *pt, int order)
{
        struct page *pg;
        void* v;
	int i;

	if(!pt){
		printk(KERN_ERR "okernel: Null pt passed.\n");
		return 0;
	}

	pg = alloc_pages(GFP_KERNEL, order);

	if(!pg){
		printk(KERN_ERR "okernel: failed to alloc pages.\n");
		return 0;
	}

        v = page_address(pg);

        if(!v){
                printk(KERN_ERR "okernel: failed to get page vaddr.\n");
                return 0;
        }


	for(i = 0; i <  (1 << order); i++){
		pt[i].virt = v+i*PAGESIZE;
		pt[i].phys = page_to_phys(pg+i);
	}
	return 1;
}

int vt_ept_unmap_pages(u64 vaddr, unsigned long num_pages)
{
	return 0;
}

int vt_ept_replace_pages(u64 vaddr, unsigned long num_pages)
{
	return 0;
}



/* Essentially create 1:1 map of 'host' physical mem to 'guest' physical */
u64 vt_ept_4K_init(void)
{
	return 0;
}

unsigned long* find_pd_entry(struct vmx_vcpu *vcpu, u64 paddr)
{
	/* Find index in a PD that maps a particular 2MB range containing a given address. */

	/* First need the PDP enty from a given PML4 root */
	epte_t *pml3 = NULL;
	epte_t *pml2 = NULL;
	epte_t *pde  = NULL;
	unsigned long* pml2_p;

	int pml3_index, pml2_index;

	epte_t *pml4 =  (epte_t*) __va(vcpu->ept_root);



	pml3 = (epte_t *)epte_page_vaddr(*pml4);

	pml3_index = (paddr & (~(GIGABYTE -1))) >> GIGABYTE_SHIFT;

	OKDEBUG("addr (%#lx) pml3 (%#lx) pml3_index (%i)\n",
		(unsigned long)paddr, (unsigned long)pml3, pml3_index);

	pml2 = (epte_t *)epte_page_vaddr(pml3[pml3_index]);

	pml2_index = ((paddr & (GIGABYTE -1)) >> PAGESIZE2M_SHIFT);

	OKDEBUG("addr (%#lx) pml2 index (%i)\n", (unsigned long)paddr, pml2_index);

	pde = (epte_t *)epte_page_vaddr(pml2[pml2_index]);

	pml2_p = &pml2[pml2_index];
	OKDEBUG("addr (%#lx) pde (%#lx) pml2 entry (%#lx)\n",
	       (unsigned long)paddr, (unsigned long)pde, (unsigned long)(*pml2_p));
	return pml2_p;
}

unsigned long* find_pt_entry(struct vmx_vcpu *vcpu, u64 paddr)
{
	/* Find index in a PT that maps a particular 4K range containing a given address. */

	/* First need the PDP enty from a given PML4 root */
	epte_t *pml3 = NULL;
	epte_t *pml2 = NULL;
	epte_t *pml1 = NULL;

	unsigned long* pml1_p;

	int pml3_index, pml2_index, pml1_index;

	epte_t *pml4 =  (epte_t*) __va(vcpu->ept_root);

	pml3 = (epte_t *)epte_page_vaddr(*pml4);

	pml3_index = (paddr & (~(GIGABYTE -1))) >> GIGABYTE_SHIFT;

	OKDEBUG("addr (%#lx) pml3 index (%i)\n", (unsigned long)paddr, pml3_index);

	pml2 = (epte_t *)epte_page_vaddr(pml3[pml3_index]);


	pml2_index = ((paddr & (GIGABYTE -1)) >> PAGESIZE2M_SHIFT);

	OKDEBUG("addr (%#lx) pml2 index (%i)\n", (unsigned long)paddr, pml2_index);

	pml1 = (epte_t *)epte_page_vaddr(pml2[pml2_index]);

	OKDEBUG("check for 4k page mapping.\n");
	BUG_ON(*pml1 & EPT_2M_PAGE);

	pml1_index = ((paddr & (PAGESIZE2M-1)) >> PAGESIZE_SHIFT);

	pml1_p = &pml1[pml1_index];

	OKDEBUG("addr (%#lx) pte (%#lx)\n", (unsigned long)paddr, (unsigned long)pml1);
	return pml1_p;
}



int do_split_2M_mapping(struct vmx_vcpu* vcpu, u64 paddr, int cache)
{
	unsigned long *pml2_e;
	pt_page *pt = NULL;
	struct ept_pt_list *e_pt = NULL;
	unsigned int n_entries = PAGESIZE / 8;
	u64* q = NULL;
	int i = 0;
	u64 p_base_addr;
	u64 addr;
	unsigned long pml1_attrs;

	if((paddr & (PAGESIZE2M -1)) != 0){
		printk(KERN_ERR "okernel: 2MB unaligned addr passed to is_2M_mapping.\n");
		return 0;
	}

	if(!(pml2_e =  find_pd_entry(vcpu, paddr))){
		printk(KERN_ERR "okernel: NULL pml2 entry for paddr (%#lx)\n",
		       (unsigned long)paddr);
		return 0;
	}

	/* check if 2M mapping or slpit already */
	if(!(*pml2_e & EPT_2M_PAGE)){
		OKDEBUG("paddr ept entry for 2MB region starting at phys addr (%#lx) already split.\n",
			(unsigned long)paddr);
		return 1;
	}

	/* 2M region base address */

	p_base_addr = (*pml2_e & ~(PAGESIZE2M-1));
	pml1_attrs = (*pml2_e & PDE_ATTR_MASK & ~EPT_2M_PAGE);

	/*
	 * Intel SDM says EPT_2M_PAGE is ignored in PL1 4k entries
	 * But we are using it for sanity checking
	 */

	OKDEBUG("base EPT physical addr for table 2M split (%#lx) paddr (%#lx)\n",
		(unsigned long)p_base_addr, (unsigned long)paddr);

	/* split the plm2_e into 4k ptes,i.e. have it point to a PML1 table */

        /* First allocate a physical page for the PML1 table (512*4K entries) */
	if (cache) {
		okmm_get_ce(&e_pt, &pt);
		if (!e_pt || !pt){
			printk(KERN_ERR "okernel: E_PT entries exhausted\n");
			return 0;
		}
	} else {
		e_pt = (struct ept_pt_list*) kmalloc(sizeof(struct ept_pt_list),
						     GFP_KERNEL);
		if (!e_pt) {
			printk(KERN_ERR "okernel: failed to allocate E_PT list");
			return 0;
		}

		if (!(pt = (pt_page*)kmalloc(sizeof(pt_page), GFP_KERNEL))) {
			printk(KERN_ERR
			       "okernel: failed to allocate PT table.\n");
			return 0;
		}
	}
	e_pt->page = pt;
	e_pt->n_pages = 1;
	INIT_LIST_HEAD(&e_pt->list);
	list_add(&e_pt->list, &vcpu->ept_table_pages.list);
	if (!cache) {
		if (!(vt_alloc_page((void**)&pt[0].virt, &pt[0].phys))) {
			printk(KERN_ERR
			       "okernel: failed to allocate PML1 table.\n");
			return 0;
		}
	}
	memset(pt[0].virt, 0, PAGESIZE);
	OKDEBUG("PML1 pt virt (%llX) pt phys (%llX)\n", (unsigned long long)pt[0].virt, pt[0].phys);

	/* Fill in eack of the 4k ptes for the PML1 */
	q = pt[0].virt;

	for(i = 0; i < n_entries; i++){
		addr = p_base_addr + i*PAGESIZE;
		q[i] = addr | pml1_attrs;
	}

	*pml2_e = pt[0].phys + EPT_R + EPT_W + EPT_X;
	return 1;
}

int split_2M_mapping(struct vmx_vcpu* vcpu, u64 paddr)
{
	return do_split_2M_mapping(vcpu, paddr, 0);
}

int split_2M_mapping_okmm(struct vmx_vcpu* vcpu, u64 paddr)
{
	return do_split_2M_mapping(vcpu, paddr, 1);
}

/* Returns virtual mapping of the new page */
void* replace_ept_page(struct vmx_vcpu *vcpu, u64 paddr, unsigned long perms)
{
	unsigned long *pml1_p;
	struct ept_pt_list *e_pt;
	pt_page *pt;
	u64 orig_paddr;
	u64 split_addr;

	split_addr = (paddr & ~(PAGESIZE2M-1));

	OKDEBUG("Check or split 2M mapping at (%#lx)\n", (unsigned long)split_addr);

	if(!(split_2M_mapping(vcpu, split_addr))){
		printk(KERN_ERR "okernel: %s couldn't split 2MB mapping for (%#lx)\n",
		       __func__, (unsigned long)paddr);
		return NULL;
	}

	OKDEBUG("Split or check ok: looking for pte for paddr (%#lx)\n",
		(unsigned long)paddr);

	if(!(pml1_p = find_pt_entry(vcpu, paddr))){
		printk(KERN_ERR "okernel: failed to find pte for (%#lx)\n",
		       (unsigned long)paddr);
		return NULL;
	}

	OKDEBUG("pte val for paddr (%#lx) is (%#lx)\n",
		(unsigned long)paddr, (unsigned long)*pml1_p);

	e_pt =(struct ept_pt_list*) kmalloc(sizeof(struct ept_pt_list), GFP_KERNEL);

	pt   = (pt_page*)kmalloc(sizeof(pt_page), GFP_KERNEL);

	if(!pt || ! e_pt){
		printk(KERN_ERR "okernel: failed to allocate PT table in replace ept page.\n");
		return NULL;
	}

	e_pt->page = pt;
	e_pt->n_pages = 1;
	INIT_LIST_HEAD(&e_pt->list);
	list_add(&e_pt->list, &vcpu->ept_table_pages.list);

	if(!(vt_alloc_page((void**)&pt[0].virt, &pt[0].phys))){
		printk(KERN_ERR "okernel: failed to allocate PML1 table.\n");
		return NULL;
	}

	memset(pt[0].virt, 0, PAGESIZE);

	OKDEBUG("Replacement page pt virt (%llX) pt phys (%llX)\n",
	       (unsigned long long)pt[0].virt, pt[0].phys);

	orig_paddr = (*pml1_p & ~(OK_FLAGS + PAGESIZE-1));

	OKDEBUG("orig paddr (%#lx)\n", (unsigned long)orig_paddr);

	if(orig_paddr != paddr){
		printk(KERN_ERR "okernel: address mis-match in EPT tables.\n");
		return NULL;
	}

	OKDEBUG("Replacing (%#lx) as pte entry with (%#lx)\n",
	       (unsigned long)(*pml1_p), (unsigned long)(pt[0].phys | perms));

	*pml1_p = pt[0].phys | perms;

	OKDEBUG("copying data from va (%#lx) to va of replacement physical (%#lx)\n",
		(unsigned long)__va(orig_paddr), (unsigned long)pt[0].virt);

	memcpy(pt[0].virt, __va(orig_paddr), PAGESIZE);
	OKDEBUG("Done for pa (%#lx)\n", (unsigned long)paddr);
	return pt[0].virt;
}

/* Modify access permissions on an EPT mapping (W,R,X)  */
/* To do: should also pay attemtion to eth EPT MT / PAT bits */
int modify_ept_physaddr_perms(struct vmx_vcpu *vcpu, u64 paddr, unsigned long perms)
{
	unsigned long *pml1_p;
	u64 orig_paddr;
	u64 split_addr;

	split_addr = (paddr & ~(PAGESIZE2M-1));

	OKDEBUG("Check or split 2M mapping at (%#lx)\n", (unsigned long)split_addr);

	if(!(split_2M_mapping(vcpu, split_addr))){
		printk(KERN_ERR "okernel: %s: couldn't split 2MB mapping for (%#lx)\n",
		       __func__, (unsigned long)paddr);
		return 0;
	}

	OKDEBUG("Split or check ok: looking for pte for paddr (%#lx)\n",
		(unsigned long)paddr);

	if(!(pml1_p = find_pt_entry(vcpu, paddr))){
		printk(KERN_ERR "okernel: failed to find pte for (%#lx)\n",
		       (unsigned long)paddr);
		return 0;
	}

	OKDEBUG("pte val for paddr (%#lx) is (%#lx)\n",
		(unsigned long)paddr, (unsigned long)*pml1_p);

	orig_paddr = (*pml1_p & ~(OK_FLAGS + PAGESIZE-1));

	OKDEBUG("orig paddr (%#lx)\n", (unsigned long)orig_paddr);

	if(orig_paddr != paddr){
		printk(KERN_ERR "okernel: address mis-match in EPT tables.\n");
		return 0;
	}

	OKDEBUG("Replacing  pte (%#lx) as pte entry with (%#lx)\n",
	       (unsigned long)(*pml1_p), (unsigned long)(paddr | perms));

	*pml1_p = paddr | perms;

	OKDEBUG("Done for pa (%#lx)\n", (unsigned long)paddr);
	return 1;
}

/* Could do this much more efficiently - hack for now... */
int modify_ept_page_range_perms(struct vmx_vcpu *vcpu, struct page *pg, int pages, unsigned long perms)
{
	int i;
	unsigned long p_addr;

	for(i = 0; i < pages; i++){
		p_addr = page_to_phys(pg + i);
		if(!(modify_ept_physaddr_perms(vcpu, p_addr, perms))){
			printk("okernel: couldn't modify perms on:=%#lx\n", p_addr);
			return 0;
		}
		OKDEBUG("modified perms on:=%#lx\n", p_addr);
	}
	return 1;
}


int add_ept_page_perms(struct vmx_vcpu *vcpu, u64 paddr)
{
	/* Need to sort out return handling */
	unsigned long perms;

	perms = EPT_R | EPT_W | EPT_CACHE_2 | EPT_CACHE_3;

	if(!(modify_ept_physaddr_perms(vcpu, paddr, perms))){
		printk("okernel: Failed to modify EPT page permissions.\n");
		BUG();
	}
	return 0;
}

static unsigned long *ept_page_entry(struct vmx_vcpu *vcpu, u64 paddr)
{
	unsigned long *pml2_e;
	unsigned long *pml1_e;
	unsigned long *ept_page_entry;

	if(!(pml2_e =  find_pd_entry(vcpu, paddr))){
		OKDEBUG("NULL pml2 entry for paddr (%#lx)\n",
		       (unsigned long)paddr);
		return 0;
	}

	/* check if 2M or 4K mapping entry */
	if((*pml2_e & EPT_2M_PAGE)){
		OKDEBUG("2MB mapping ept entry for paddr (%#lx).\n",
			(unsigned long)paddr);
		ept_page_entry = pml2_e;
	} else {
		/* Need to find the 4k page entry */

		if(!(pml1_e = find_pt_entry(vcpu, paddr))){
			OKDEBUG("failed to find pte for (%#lx)\n",
			       (unsigned long)paddr);
			return 0;
		}
		/*
		OKDEBUG("4KB mapping ept entry for paddr (%#lx).\n",
		       (unsigned long)paddr);
		*/
		ept_page_entry = pml1_e;
	}
	return ept_page_entry;
}

static unsigned long is_set_ept_page_flag(struct vmx_vcpu *vcpu, u64 paddr,
				   unsigned long flag)
{
	unsigned long *epte = ept_page_entry(vcpu, paddr);
	if (!epte) {
		return -1;
	}
	return *epte & flag;
}

static int set_clr_ept_page_flags(struct vmx_vcpu *vcpu, u64 paddr,
			   unsigned long s_flags, unsigned long c_flags,
			   int level)
{
	unsigned long *epte = ept_page_entry(vcpu, paddr);
	//unsigned long page2m = *epte & EPT_2M_PAGE;

	if (!epte) 
		return 0;
	if (level > PG_LEVEL_2M) {
		printk(KERN_ERR "okernel unsupported page level");
		BUG();
		return 0;
	}
	/* split if the kernel is using 4k pages and the EPT is 2M */
	if (level == PG_LEVEL_4K && (*epte & EPT_2M_PAGE)) {
		if (!split_2M_mapping_okmm(vcpu, (paddr & ~(PAGESIZE2M - 1))))
				return 0;
		else /* get new epte after split*/
			epte = ept_page_entry(vcpu, paddr);
	}
	*epte |= s_flags;
	*epte &= ~(c_flags);
	return 1;
}

/* Need to sort out code duplication amongst replace/modify/rmap ept pages */
static int remap_ept_page(struct vmx_vcpu *vcpu, u64 paddr, u64 new_paddr)
{

	unsigned long *pml1_p;
	u64 orig_paddr;
	u64 split_addr;
	unsigned long perms;

	split_addr = (paddr & ~(PAGESIZE2M-1));

	OKDEBUG("Check or split 2M mapping at (%#lx)\n", (unsigned long)split_addr);

	if(!(split_2M_mapping(vcpu, split_addr))){
		printk(KERN_ERR "okernel: %s: couldn't split 2MB mapping for (%#lx)\n",
		       __func__, (unsigned long)paddr);
		return 0;
	}

	OKDEBUG("Split or check ok: looking for pte for paddr (%#lx)\n",
		(unsigned long)paddr);

	if(!(pml1_p = find_pt_entry(vcpu, paddr))){
		printk(KERN_ERR "okernel: failed to find pte for (%#lx)\n",
		       (unsigned long)paddr);
		return 0;
	}

	OKDEBUG("pte val for paddr (%#lx) is (%#lx)\n",
		(unsigned long)paddr, (unsigned long)*pml1_p);

	orig_paddr = (*pml1_p & ~(OK_FLAGS + PAGESIZE-1));

	OKDEBUG("orig paddr (%#lx)\n", (unsigned long)orig_paddr);

	if(orig_paddr != paddr){
		printk(KERN_ERR "okernel: address mis-match in EPT tables.\n");
		return 0;
	}

	/* Hack perms for now to make RO */
	perms =  EPT_R | EPT_CACHE_2 | EPT_CACHE_3;

	OKDEBUG("Replacing  pte (%#lx) as pte entry with (%#lx)\n",
	       (unsigned long)(*pml1_p), (unsigned long)(new_paddr | perms));

	*pml1_p = new_paddr | perms;

	OKDEBUG("Done for pa (%#lx)\n", (unsigned long)paddr);
	return 1;
}

static unsigned long  guest_physical_page_address(unsigned long addr,
					   unsigned int *level,
					   pgprot_t *prot)
{
	/*
	 * Find the guest physical page address , or 0 if not mapped
	 * We can't use virt_to_phys((void *)vaddr) because it won't
	 * work for module mapping space (MODULES_VADDR)
	 * use current->mm, so we can lookup user space vaddr
	 */

	unsigned long pa;
	pte_t *pte;
	pgd_t *pgd = pgd_offset(current->active_mm, addr);
	pte = lookup_address_in_pgd(pgd,addr, level);
	if (!pte || !pte_present(*pte)){
		return 0;
	}
	*prot = pte_pgprot(*pte);
	switch(*level) {
	case PG_LEVEL_4K:
		pa = pte_val(*pte) & ~(PAGE_SIZE-1) & __PHYSICAL_MASK;
		break;
	case PG_LEVEL_2M:
		pa = pte_val(*pte) & ~(PAGESIZE2M-1) & __PHYSICAL_MASK;
		break;
	default:
		OKERR("Unsupported page level %d\n", *level);
		BUG();
		pa = 0;
	}
	return pa;
}

static unsigned long guest_physical_address(unsigned long va, int *level,
					    pgprot_t *prot)
{
	unsigned long pa;
	pa = guest_physical_page_address(va, level, prot);
	if (!pa)
		return 0;
	switch(*level) {
	case PG_LEVEL_4K:
		pa += (va & (PAGE_SIZE - 1));
		break;
	case PG_LEVEL_2M:
		pa += (va & (PAGESIZE2M - 1));
		break;
	default:
		OKWARN("Unsupported page level %d\n", *level);
		pa = 0;
		break;
	}
	return pa;
}

static unsigned long find_pg_va(struct vmx_vcpu *vcpu, unsigned long paddr,
			 unsigned long start, unsigned long end)
{
	/*
	 * Searches a range of virtual addresses to see if the physical
	 * address is mapped there. If it is mapped returns the
	 * virtual address of the start of the page, otherwise 0
	 */
	unsigned long vaddr, pa, ps, match;
	unsigned int level;
	pgprot_t prot;

	ps = PAGESIZE2M;
	vaddr = start & ~(PAGESIZE2M - 1);
	if (start != vaddr) {
		ps = PAGE_SIZE;
		OKWARN("Start address %#lx is not 2M aligned\n", start);
	}
	for (; vaddr < end; vaddr += ps){
		pa = guest_physical_page_address(vaddr, &level, &prot);
		if (!pa) {
			/* vaddr NOT MAPPED */
			continue;
		}
		if (level == 1) {
			ps = PAGE_SIZE;
			match = paddr & PAGE_MASK;
		} else if (level == 2) {
			ps = PAGESIZE2M;
			match = paddr & ~(PAGESIZE2M - 1);
		} else {
			OKWARN("Unsupported page size, level %u\n", level);
			return 0;
		}
		if (pa == match) { 
			return vaddr;
		}
	}
	/* No match found so not mapped in the range*/
	return 0;
}

static unsigned long kmod_page(struct vmx_vcpu *vcpu, unsigned long paddr){
	unsigned long start = PFN_ALIGN(MODULES_VADDR);
	unsigned long end = PFN_ALIGN(MODULES_END);

	return find_pg_va(vcpu, paddr, start, end);
}

static unsigned long ktext_page(struct vmx_vcpu *vcpu, unsigned long paddr)
{
	unsigned long start = PFN_ALIGN(_text);
	unsigned long end = PFN_ALIGN(&__stop___ex_table);

	return find_pg_va(vcpu, paddr, start, end);
}

static unsigned long kdata_page(struct vmx_vcpu *vcpu, unsigned long paddr)
{
	unsigned long data_start = PFN_ALIGN(&__start_rodata);
	unsigned long data_end = PFN_ALIGN(&__end_rodata);

	return find_pg_va(vcpu, paddr, data_start, data_end);
}

static unsigned long vsys_page(struct vmx_vcpu *vcpu, unsigned long paddr)
{
	unsigned long vsys_end = VSYSCALL_ADDR + PAGE_SIZE;
	return find_pg_va(vcpu, paddr, VSYSCALL_ADDR, vsys_end);
}

static unsigned long kmapped_page(struct vmx_vcpu *vcpu, unsigned long pa)
{
	unsigned long addr;
	if ((addr = ktext_page(vcpu, pa)))
	    return addr;
	if ((addr = kmod_page(vcpu, pa)))
		return addr;
	if ((addr = kdata_page(vcpu, pa)))
		return addr;
	if ((addr = vsys_page(vcpu, pa)))
		return addr;
	return 0;
}

static void ept_flags_from_prot(pgprot_t prot, unsigned long *s_flags,
			unsigned long *c_flags)
{
	*s_flags = 0;
	*c_flags = 0;
	if (pgprot_val(prot) & pgprot_val(__pgprot(_PAGE_NX))) {
		*c_flags |= EPT_X;
	} else {
		*s_flags |= EPT_X;
	}
	if (pgprot_val(prot) & pgprot_val(__pgprot(_PAGE_RW))) {
		*s_flags |= EPT_R | EPT_W;
	} else {
		*s_flags |= EPT_R;
		*c_flags |= EPT_W;
	}
}

static void ept_flags_from_qual(unsigned long qual, unsigned long *s_flags,
			unsigned long *c_flags)
{
	*c_flags = 0;
	*s_flags = qual & (EPT_X | EPT_R | EPT_W);
}


static int x_or_ro(unsigned long flags)
{
	if ((flags & EPT_X) && (flags & EPT_W)){
		OKSEC("WARNING WX memory\n");
	}
	return (((flags & EPT_X) || (flags & EPT_R)) && !(flags & EPT_W));
}

/*
 * Fix up any anomalies in kernel integrity coverage. This
 * will go when we have a shared base EPT, as we will fix up
 * the anomalies in the master EPT when we chose to allow them
 */
static void do_fixups(struct vmx_vcpu *vcpu)
{
	int i;
	for (i = 0; i < fixup_pages.index; i++) {
		if (!set_clr_ept_page_flags(vcpu, fixup_pages.pages[i].pa,
					    fixup_pages.pages[i].prot, 0,
					    PG_LEVEL_4K)) {
			OKERR("set_clr_ept_page_flags failed.\n");
			BUG();
		}
	}
}

static void add_fixup(unsigned long pa, unsigned long prot)
{
	if (fixup_pages.index < (NR_FIXUP_PAGES - 1)) {
		fixup_pages.pages[fixup_pages.index].pa = pa;
		fixup_pages.pages[fixup_pages.index].prot = prot;
		fixup_pages.index++;
	}
 }

static void set_kmem_ept(struct vmx_vcpu *vcpu, unsigned long start,
			 unsigned long end, unsigned long set, unsigned long clr)
{
	unsigned long gvs, va, pa;
	int l;
	pgprot_t p;

	gvs = start & ~(PAGESIZE - 1);
	if (start != gvs)
		OKWARN("Start address not 4k aligned");
	for (va = gvs; va < end; va += PAGE_SIZE){
		pa = guest_physical_address(va, &l, &p);
		if (!pa) {
			OKWARN("Guest physical address not found\n");
			continue;
		}
		if ((pa != (pa &  ~(PAGESIZE - 1)))) {
			OKERR("PA not 4k aligned kernel protection failed\n");
			return;
		}
		/* 
		 * Split explicitly to avoid using and exhausting
		 * okmm. okmm is only needed when we've started
		 * running in NR mode
		 */
		if (!split_2M_mapping(vcpu, pa & ~(PAGESIZE2M - 1))) {
			OKERR("Failed to split page");
			BUG();
		}
		if (!set_clr_ept_page_flags(vcpu, pa, set, clr, PG_LEVEL_4K)){
			OKERR("EPT set_clr_ept_page_flags failed.\n");
			BUG();
		}
	}
}

static void set_clr_module_ept_flags(struct vmx_vcpu *vcpu)
{
	unsigned long va, pa, set, clr;
	int level;
	pgprot_t prot;
	unsigned long start = PFN_ALIGN(MODULES_VADDR);
	unsigned long end = PFN_ALIGN(MODULES_END);

	for(va = start; va < end; va += PAGE_SIZE) {
		pa = guest_physical_address(va, &level, &prot);
		if (!pa)
			continue;
		if ((pa != (pa &  ~(PAGESIZE - 1)))) {
			OKERR("PA not 4k aligned module protection failed\n");
			return;
		}
		ept_flags_from_prot(prot, &set, &clr);
		if (x_or_ro(set)) 
			set |= OK_MOD;
		if ((set & EPT_W) && (set & EPT_X))
				OKSEC("WX on pa %lx\n", pa);
		/* 
		 * Split explicitly to avoid using and exhausting
		 * okmm. okmm is only needed when we've started
		 * running in NR mode
		 */
		if (!split_2M_mapping(vcpu, pa & ~(PAGESIZE2M - 1))) {
			OKERR("Failed to split page");
			BUG();
		}
		if (!set_clr_ept_page_flags(vcpu, pa, set, clr, PG_LEVEL_4K)) {
			OKERR("set_clr_ept_page_flags failed.\n");
			BUG();
		}
	}
}

static void protect_kernel_integrity(struct vmx_vcpu *vcpu)
{
	/*
	 *
	 * Assume default EPT protections remove EPT_X
	 *
	 * We try to align this protection with init_64:mark_rodata_ro
	 * Here we use EPT to ensure it cannot be tampered with by the
	 * okernel. We assume EPT_X is already removed, so we don't
	 * have to unset it explicitly, rather it is set where needed.
	 */
	unsigned long text_start = PFN_ALIGN(_text);
	unsigned long text_end = PFN_ALIGN(&__stop___ex_table);
	unsigned long data_start = PFN_ALIGN(&__start_rodata);
	unsigned long data_end = PFN_ALIGN(&__end_rodata);
	unsigned long vsys_end = VSYSCALL_ADDR + PAGE_SIZE;

	/* Set execute remove write for kernel text*/
	set_kmem_ept(vcpu, text_start, text_end, EPT_X | OK_TEXT, EPT_W);
	set_kmem_ept(vcpu, data_start, data_end, OK_DATA, EPT_W);
	set_kmem_ept(vcpu, VSYSCALL_ADDR, vsys_end, EPT_X | OK_TEXT, EPT_W);
	do_fixups(vcpu);

	/* Set protection for modules*/
	set_clr_module_ept_flags(vcpu);
}

/* We just clone the bottom page of the stack for now */
int clone_kstack2(struct vmx_vcpu *vcpu, unsigned long perms)
{
	int n_pages;
	unsigned long k_stack;
	u64 paddr;
	void  *vaddr;
	unsigned int* nr_stack_canary;

	n_pages = THREAD_SIZE / PAGESIZE;

	BUG_ON(n_pages != 4);

	k_stack  = (unsigned long)current->stack;

	/* Write a canary value before we replace the EPT page: use this later to detect NR stack overflow */
	nr_stack_canary = (unsigned int*)(k_stack + PAGE_SIZE - 4);
	*nr_stack_canary = NR_STACK_END_MAGIC;

        OKDEBUG("kstack addr:=%#lx nr_stack_canary:=%#lx *nr_stack_canary:=%#x\n",
	       k_stack, (unsigned long)nr_stack_canary, *nr_stack_canary);

#if !defined(CONFIG_VMAP_STACK)
	paddr = __pa(k_stack);
#else
	paddr = page_to_phys(vmalloc_to_page(((void *)k_stack)));
#endif
	
	OKDEBUG("tsk->stack vaddr (%#lx) paddr (%#lx) top of stack (%#lx)\n",
	       k_stack, (unsigned long)paddr, current_top_of_stack());


       OKDEBUG("ept page clone on (%#lx)\n", (unsigned long)paddr);
       /* also need replace_ept_contiguous_region */
       if(!(vaddr = replace_ept_page(vcpu, paddr, perms))){
	       printk(KERN_ERR "okernel: failed to clone page at (%#lx)\n",
		      (unsigned long)paddr);
	       return 0;
       }

       /* We assume for now that the thread_info structure is at the bottom of the first page */
       /* Bad assumption it seems! */
	//vcpu->cloned_thread_info = (struct thread_info*)vaddr;
       vcpu->cloned_thread_info = current_thread_info();
       vcpu->nr_stack_canary = (unsigned int*)(vaddr + PAGE_SIZE -4);


       OKDEBUG("vaddr:=%#lx vaddr->nr_stack_canary:=%#lx *vaddr->nr_stack_canary:=%#x\n",
	      (unsigned long)vaddr, (unsigned long)vcpu->nr_stack_canary, *vcpu->nr_stack_canary);

       /* Check the canary value */
       if(*(vcpu->nr_stack_canary) != NR_STACK_END_MAGIC){
	       printk("okernel: failed to setup NR stack correctly.\n");
	       return 0;
       }

       return 1;
}

int vt_ept_2M_init(struct vmx_vcpu *vcpu)
{
	/*
	 * For now share a direct 1:1 EPT mapping of host physical to
	 * guest physical across all vmx 'containers'.
	 *
	 * Setup the per-vcpu pagetables here. For now we just map up to
	 * 512G of physical RAM, and we use a 2MB page size. So we need
	 * one PML4 physical page, one PDPT physical page and 1 PD
	 * physical page per GB.  We need correspondingly, 1 PML4 entry
	 * (PML4E), 1 PDPT entry per GB (PDPTE), and 512 PD entries
	 * (PDE) per PD.
	 *
	 * The first 2Mb region we break down into 4K page table entries
	 * so we can be more selectively over caching controls, etc. for
	 * that region.
	 */
	unsigned long mappingsize = 0;
	unsigned long rounded_mappingsize = 0;
	unsigned int n_entries = PAGESIZE / 8;
	unsigned int n_pt   = 0;
	unsigned int n_pd   = 0;
	unsigned int n_pdpt = 0;
	struct ept_pt_list* e_pt;
	struct ept_pt_list* e_pd;
	struct ept_pt_list* e_pdpt;
	pt_page* pt = NULL;
	pt_page* pd = NULL;
	pt_page* pdpt = NULL;
	int i = 0, k = 0;
	u64* q = NULL;
	u64 addr = 0;
	u64* pml4_virt = NULL;
	u64  pml4_phys = 0;

	/* Keep track of pages we allocate for holding the ept tables so we can de-allocate */
	INIT_LIST_HEAD(&vcpu->ept_table_pages.list);

	/* What range do the EPT tables need to cover (including areas like the APIC mapping)? */
	//mappingsize = e820_end_paddr(MAXMEM);
	mappingsize = ept_limit;

	OKDEBUG("max address range to map under EPT: %#lx\n", (unsigned long)mappingsize);

	/* Round upp to closest Gigabyte of memory */
	rounded_mappingsize = ((mappingsize + (GIGABYTE-1)) & (~(GIGABYTE-1)));

	OKDEBUG("Need EPT tables covering (%lu) Mb (%lu) bytes for Phys Mapping sz: %lu MB\n",
		rounded_mappingsize >> 20, rounded_mappingsize, mappingsize >> 20);

	if((rounded_mappingsize >> GIGABYTE_SHIFT) >  PML4E_MAP_LIMIT){
		/* Only setup one PDPTE entry for now so can map up to 512Gb */
		printk(KERN_ERR "okernel: Physical memory greater than (%d) Gb not supported.\n",
		       PML4E_MAP_LIMIT);
		return 0;
	}

	/* Only need 1 pdpt to map upto 512G */
	n_pdpt = 1;
	/* Need 1 PD per gigabyte of physical mem */
	n_pd = rounded_mappingsize >> GIGABYTE_SHIFT;
	/* We just split the 1st 2Mb region into 4K pages so need only 1 PT table. */
	n_pt = 1;

	/* pt - PML1, pd - PML2, pdpt - PML3 */
	e_pdpt = kmalloc(sizeof(struct ept_pt_list), GFP_KERNEL);
	pdpt = (pt_page*)kmalloc(sizeof(pt_page)* n_pdpt, GFP_KERNEL);


	if(!e_pdpt || !pdpt){
		printk(KERN_ERR "okernel: failed to allocate (e)pdpt table in replace ept page.\n");
		return 0;
	}

	e_pdpt->page = pdpt;
	e_pdpt->n_pages = n_pdpt;
	INIT_LIST_HEAD(&e_pdpt->list);
	list_add(&e_pdpt->list, &vcpu->ept_table_pages.list);

	e_pd = kmalloc(sizeof(struct ept_pt_list), GFP_KERNEL);
	pd   = (pt_page*)kmalloc(sizeof(pt_page)* n_pd, GFP_KERNEL);

	if(!e_pd || !pd){
		printk(KERN_ERR "okernel: failed to allocate (e)pd table in replace ept page.\n");
		return 0;
	}

	e_pd->page = pd;
	e_pd->n_pages = n_pd;
	INIT_LIST_HEAD(&e_pd->list);
	list_add(&e_pd->list, &vcpu->ept_table_pages.list);

	e_pt = kmalloc(sizeof(struct ept_pt_list), GFP_KERNEL);
	pt   = (pt_page*)kmalloc(sizeof(pt_page)* n_pt, GFP_KERNEL);


	if(!e_pt || !pt){
		printk(KERN_ERR "okernel: failed to allocate (e)pt table in replace ept page.\n");
		return 0;
	}

	e_pt->page = pt;
	e_pt->n_pages = n_pt;
	INIT_LIST_HEAD(&e_pt->list);
	list_add(&e_pt->list, &vcpu->ept_table_pages.list);

	OKDEBUG("Allocated (%u) pdpt (%u) pd (%u) pt tables.\n", n_pdpt, n_pd, n_pt);

        /* Allocate the paging structures from bottom to top so we start
	 * at the PT level (PML1) and finish with the PML4 table.
	 */

	/* 1st 2Meg mapping (PML1 / PT):
	 * At the moment we only use a PT for the 1st 2MB region, for
	 * the rest of memory we map in via 2MB PD entries. We break
	 * first 2M region into 4k pages so that we can use the CPU
	 * cache in real-mode otherwise we end up with UC memory for the
	 * whole 2M.
	 */

	BUG_ON(n_pt != 1);

	/* XXXX todo cid: recheck on the caching bits / ipat bit and when they should be set. */
	/* This is the 0-2MB first set of mappings which we break into 4K PTEs*/
	for(i = 0; i < n_pt; i++){
		if(!(vt_alloc_page((void**)&pt[i].virt, &pt[i].phys))){
			printk(KERN_ERR "okernel: failed to allocate PML1 table.\n");
			return 0;
		}
		memset(pt[i].virt, 0, PAGESIZE);
		OKDEBUG("n=(%d) PML1 pt virt (%llX) pt phys (%llX)\n", i, (unsigned long long)pt[i].virt, pt[i].phys);
	}

	q = pt[0].virt;

	for(i = 0; i < n_entries; i++){
		addr = i << 12;
		if(no_cache_region(addr, PAGESIZE)){
			q[i] = (u64)((i << 12) | EPT_R | EPT_W);
		} else {
			q[i] = (u64)((i << 12) | EPT_R | EPT_W | EPT_CACHE_2 | EPT_CACHE_3);
		}
	}

        /* Now the PD (PML2) tables (plug the pt[0] entry back in later) */
	for(i = 0; i < n_pd; i++){
		if(!(vt_alloc_page((void**)&pd[i].virt, &pd[i].phys))){
			printk(KERN_ERR "okernel: failed to allocate PML2 tables.\n");
			return 0;
		}
		memset(pd[i].virt, 0, PAGESIZE);
		OKDEBUG("n=(%d) PML2 pd virt (%llX) pd phys (%llX)\n", i, (unsigned long long)pd[i].virt, pd[i].phys);
	}
	/* XXXX todo cid: recheck correct CACHE / IPAT attribute setting. */
	for(k = 0; k < n_pd; k++){
		q = pd[k].virt;
		for(i = 0; i < n_entries; i++){
			addr = (((u64)(i + k*n_entries)) << 21);
#if 0
			OKDEBUG("calculated addr (i=%d) (k=%d) (n_entries=%d) (%#llx)\n", i, k, n_entries, addr);
#endif
			if(no_cache_region(addr,  PAGESIZE2M)){
				q[i] = (((u64)(i + k*n_entries)) << 21) | EPT_R | EPT_W | EPT_2M_PAGE;
			} else {
				q[i] = (((u64)(i + k*n_entries)) << 21) | EPT_R | EPT_W | EPT_2M_PAGE | EPT_CACHE_2 | EPT_CACHE_3;
			}
#if 0
			OKDEBUG("pml2[%d] entry %d=%#llx\n", k, i, q[i]);
#endif
		}
	}

	/* Point just the PD entry covering the 1st 2Mb region to the PT we set
	 * up earlier. The rest of the PD entries directly map a 2Mb
	 * page entry, not a PT table.
	 */
	q = pd[0].virt;
	q[0] = (u64)(pt[0].phys + EPT_R + EPT_W + EPT_X);


	/* Now the PDPT (PML3) tables */
	for(i = 0; i < n_pdpt; i++){
		if(!(vt_alloc_page((void**)&pdpt[i].virt, &pdpt[i].phys))){
			printk(KERN_ERR "okernel: failed to allocate PML3 tables.\n");
			return 0;
		}
		memset(pdpt[i].virt, 0, PAGESIZE);
		OKDEBUG("n=(%d) PML3 pdpt virt (%llX) pdpt phys (%llX)\n",
			i, (u64)pdpt[i].virt, pdpt[i].phys);
	}
	/* And link to the PD (PML2) tables created earlier...*/
       for(k = 0; k < n_pdpt; k++){
	    q = pdpt[k].virt;
	    for(i = 0; i < n_pd; i++){
		    /* These are the PDPTE entries - just 4 at present to map 4GB */
		    q[i] = (u64)(pd[i].phys + EPT_R + EPT_W + EPT_X);
	    }
       }

       /* Finally create the PML4 table that is the root of the EPT tables (VMCS EPTRTR field) */
       if(!(vt_alloc_page((void**)&pml4_virt, &pml4_phys))){
	       printk(KERN_ERR "okernel: failed to allocate PML4 table.\n");
	       return 0;
       }

       memset(pml4_virt, 0, PAGESIZE);
       q = pml4_virt;

       /* Link to the PDPT table above.These are the PML4E entries - just one at present */
       for(i = 0; i < n_pdpt; i++){
	       q[i] = (u64)(pdpt[i].phys + EPT_R + EPT_W + EPT_X);
       }

       OKDEBUG("PML4 plm4_virt (%#lx) *plm4_virt (%#lx) pml4_phys (%#lx)\n",
	       (unsigned long)pml4_virt, (unsigned long)*pml4_virt,
	       (unsigned long)pml4_phys);

       vcpu->ept_root = pml4_phys;
       protect_kernel_integrity(vcpu);
       return 1;
}
/* End: imported code from original BV prototype */

static inline bool cpu_has_secondary_exec_ctrls(void)
{
	return vmcs_config.cpu_based_exec_ctrl &
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
}

static inline bool cpu_has_vmx_xsaves(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_XSAVES;
}

static inline bool cpu_has_vmx_vpid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_VPID;
}

static inline bool cpu_has_vmx_invpcid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_INVPCID;
}

static inline bool cpu_has_vmx_invvpid_single(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_invvpid_global(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_ept(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_EPT;
}

static inline bool cpu_has_vmx_ept_mode_ctl(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_MODE_BASE_CTL;
}

static inline bool cpu_has_vmx_invept_individual_addr(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_INDIVIDUAL_BIT;
}

static inline bool cpu_has_vmx_invept_context(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_invept_global(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_GLOBAL_BIT;
}

static inline bool cpu_has_vmx_ept_ad_bits(void)
{
	return vmx_capability.ept & VMX_EPT_AD_BIT;
}

/*-------------------------------------------------------------------------------------*/
/* code moved                                                                          */
/*-------------------------------------------------------------------------------------*/
static inline void __invept(int ext, u64 eptp, gpa_t gpa)
{
	struct {
		u64 eptp, gpa;
	} operand = {eptp, gpa};

	asm volatile (ASM_VMX_INVEPT
			/* CF==1 or ZF==1 --> rc = -1 */
			"; ja 1f ; ud2 ; 1:\n"
			: : "a" (&operand), "c" (ext) : "cc", "memory");
}

static inline void ept_sync_global(void)
{
	if (cpu_has_vmx_invept_global())
		__invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
}

static inline void ept_sync_context(u64 eptp)
{
	if (cpu_has_vmx_invept_context())
		__invept(VMX_EPT_EXTENT_CONTEXT, eptp, 0);
	else
		ept_sync_global();
}

static inline void ept_sync_individual_addr(u64 eptp, gpa_t gpa)
{
	if (cpu_has_vmx_invept_individual_addr())
		__invept(VMX_VPID_EXTENT_INDIVIDUAL_ADDR,
				eptp, gpa);
	else
		ept_sync_context(eptp);
}

static inline void __vmxon(u64 addr)
{
	asm volatile (ASM_VMX_VMXON_RAX
			: : "a"(&addr), "m"(addr)
			: "memory", "cc");
}

static inline void __vmxoff(void)
{
	asm volatile (ASM_VMX_VMXOFF : : : "cc");
}

static inline void __invvpid(int ext, u16 vpid, gva_t gva)
{
    struct {
	u64 vpid : 16;
	u64 rsvd : 48;
	u64 gva;
    } operand = { vpid, 0, gva };

    asm volatile (ASM_VMX_INVVPID
		  /* CF==1 or ZF==1 --> rc = -1 */
		  "; ja 1f ; ud2 ; 1:"
		  : : "a"(&operand), "c"(ext) : "cc", "memory");
}

static inline void vpid_sync_vcpu_single(u16 vpid)
{
	if (vpid == 0)
		return;

	if (cpu_has_vmx_invvpid_single())
		__invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, vpid, 0);
}

static inline void vpid_sync_vcpu_global(void)
{
	if (cpu_has_vmx_invvpid_global())
		__invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, 0, 0);
}

static inline void vpid_sync_context(u16 vpid)
{
	if (cpu_has_vmx_invvpid_single())
		vpid_sync_vcpu_single(vpid);
	else
		vpid_sync_vcpu_global();
}

/*--------------------------------------------------------------------------------------------*/


static void vmcs_clear(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (ASM_VMX_VMCLEAR_RAX "; setna %0"
		      : "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
		      : "cc", "memory");
	if (error)
		printk(KERN_ERR "okernel: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
}

static void vmcs_load(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (ASM_VMX_VMPTRLD_RAX "; setna %0"
			: "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
			: "cc", "memory");
	if (error)
		printk(KERN_ERR "okernel: vmx: vmptrld %p/%llx failed\n",
		       vmcs, phys_addr);
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

static noinline void vmwrite_error(unsigned long field, unsigned long value)
{
	printk(KERN_ERR "okernel: vmwrite error: reg %lx value %lx (err %d)\n",
	       field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
	//dump_stack();
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



static __init int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, u32 *result)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return -EIO;

	*result = ctl;
	return 0;
}

static __init bool allow_1_setting(u32 msr, u32 ctl)
{
	u32 vmx_msr_low, vmx_msr_high;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);
	return vmx_msr_high & ctl;
}

static __init int setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 min, opt, min2, opt2;
	u32 _pin_based_exec_control = 0;
	u32 _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;

	//min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	//min = PIN_BASED_NMI_EXITING;
	//min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	//min = PIN_BASED_EXT_INTR_MASK;
	min = 0;
	opt = 0;
	//opt = PIN_BASED_VIRTUAL_NMIS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
				&_pin_based_exec_control) < 0)
		return -EIO;

	min = CPU_BASED_USE_TSC_OFFSETING;

	opt = CPU_BASED_TPR_SHADOW |
	      CPU_BASED_USE_MSR_BITMAPS |
	      CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;

	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
				&_cpu_based_exec_control) < 0)
		return -EIO;

	if ((_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_exec_control &= ~CPU_BASED_CR8_LOAD_EXITING &
					   ~CPU_BASED_CR8_STORE_EXITING;

	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = 0;

		/* INVPCID will operate normally without exit as long as INVLPG exiting is 0 */
		/* cid: we should mark some of these as non-optional. */
		opt2 =  SECONDARY_EXEC_WBINVD_EXITING |
			SECONDARY_EXEC_ENABLE_VPID |
			SECONDARY_EXEC_ENABLE_EPT |
			SECONDARY_EXEC_RDTSCP |
			SECONDARY_EXEC_ENABLE_INVPCID |
			SECONDARY_EXEC_MODE_BASE_CTL |
			SECONDARY_EXEC_XSAVES;

		if (adjust_vmx_controls(min2, opt2,
					MSR_IA32_VMX_PROCBASED_CTLS2,
					&_cpu_based_2nd_exec_control) < 0){
			return -EIO;
		}
	}

	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		/* CR3 accesses and invlpg don't need to cause VM Exits when EPT
		   enabled */
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
					     CPU_BASED_CR3_STORE_EXITING |
					     CPU_BASED_INVLPG_EXITING);
		rdmsr(MSR_IA32_VMX_EPT_VPID_CAP,
		      vmx_capability.ept, vmx_capability.vpid);
	}

	min = 0;

	min |= VM_EXIT_HOST_ADDR_SPACE_SIZE;

//	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT;
	opt = 0;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
				&_vmexit_control) < 0)
		return -EIO;

	min = 0;
//	opt = VM_ENTRY_LOAD_IA32_PAT;
	opt = 0;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&_vmentry_control) < 0)
		return -EIO;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;


	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return -EIO;

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return -EIO;

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->order = get_order(vmcs_config.size);
	vmcs_conf->revision_id = vmx_msr_low;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl         = _vmexit_control;
	vmcs_conf->vmentry_ctrl        = _vmentry_control;

	vmx_capability.has_load_efer =
		allow_1_setting(MSR_IA32_VMX_ENTRY_CTLS,
				VM_ENTRY_LOAD_IA32_EFER)
		&& allow_1_setting(MSR_IA32_VMX_EXIT_CTLS,
				   VM_EXIT_LOAD_IA32_EFER);

	return 0;
}







static struct vmcs *__vmx_alloc_vmcs(int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcs *vmcs;

	pages = alloc_pages_node(node, GFP_KERNEL, vmcs_config.order);
	if (!pages)
		return NULL;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_config.size);
	vmcs->revision_id = vmcs_config.revision_id; /* vmcs revision id */
	return vmcs;
}


/**
 * vmx_free_vmcs - frees a VMCS region
 */
static void vmx_free_vmcs(struct vmcs *vmcs)
{
	free_pages((unsigned long)vmcs, vmcs_config.order);
}




/*-------------------------------------------------------------------------------------*/
/*  start: vmx__launch releated code                                                   */
/*-------------------------------------------------------------------------------------*/

/*
 * Set up the vmcs's constant host-state fields, i.e., host-state fields that
 * will not change in the lifetime of the guest.
 * Note that host-state that does change is set elsewhere. E.g., host-state
 * that is set differently for each CPU is set in vmx_vcpu_load(), not here.
 */
static void vmx_setup_constant_host_state(void)
{
	u32 low32, high32;
	unsigned long tmpl;
	struct desc_ptr dt;

	vmcs_writel(HOST_CR0, read_cr0() & ~X86_CR0_TS);  /* 22.2.3 */
	vmcs_writel(HOST_CR4, native_read_cr4());  /* 22.2.3, 22.2.5 */
	vmcs_writel(HOST_CR3, __read_cr3());  /* 22.2.3 */

	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);  /* 22.2.4 */
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);  /* 22.2.4 */

	store_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.address);   /* 22.2.4 */

	asm("mov $.Lokernel_vmx_return, %0" : "=r"(tmpl));
	vmcs_writel(HOST_RIP, tmpl); /* 22.2.5 */

	rdmsr(MSR_IA32_SYSENTER_CS, low32, high32);
	vmcs_write32(HOST_IA32_SYSENTER_CS, low32);
	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, tmpl);   /* 22.2.3 */

	rdmsr(MSR_EFER, low32, high32);
	vmcs_write32(HOST_IA32_EFER, low32);

	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, low32, high32);
		vmcs_write64(HOST_IA32_PAT, low32 | ((u64) high32 << 32));
	}

	vmcs_write16(HOST_FS_SELECTOR, 0);            /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, 0);            /* 22.2.4 */

	rdmsrl(MSR_FS_BASE, tmpl);
	OKDEBUG("setting host MSR_FS_BASE=%#lx\n", tmpl);
	vmcs_writel(HOST_FS_BASE, tmpl); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, tmpl);
	OKDEBUG("setting host MSR_GS_BASE=%#lx\n", tmpl);
	vmcs_writel(HOST_GS_BASE, tmpl); /* 22.2.4 */
}


static inline u16 vmx_read_ldt(void)
{
	u16 ldt;
	asm("sldt %0" : "=g"(ldt));
	return ldt;
}

static unsigned long segment_base(u16 selector)
{
	struct desc_ptr *gdt = this_cpu_ptr(&host_gdt);
	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (!(selector & ~3))
		return 0;

	table_base = gdt->address;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector = vmx_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;

		table_base = segment_base(ldt_selector);
	}
	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = get_desc_base(d);
#ifdef CONFIG_X86_64
       if (d->s == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
               v |= ((unsigned long)((struct ldttss_desc *)d)->base3) << 32;
#endif
	return v;
}

static inline unsigned long vmx_read_tr_base(void)
{
	u16 tr;
	asm("str %0" : "=g"(tr));
	return segment_base(tr);
}

static void __vmx_setup_cpu(void)
{
	struct desc_ptr *gdt = this_cpu_ptr(&host_gdt);
	unsigned long sysenter_esp;
	unsigned long tmpl;

	/*
	 * Linux uses per-cpu TSS and GDT, so set these when switching
	 * processors.
	 */
	vmcs_writel(HOST_TR_BASE, vmx_read_tr_base()); /* 22.2.4 */
	vmcs_writel(HOST_GDTR_BASE, gdt->address);   /* 22.2.4 */

	rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, sysenter_esp); /* 22.2.3 */

	rdmsrl(MSR_FS_BASE, tmpl);
	OKDEBUG("setting host MSR_FS_BASE=%#lx\n", tmpl);
	vmcs_writel(HOST_FS_BASE, tmpl); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, tmpl);
	OKDEBUG("setting host MSR_GS_BASE=%#lx\n", tmpl);
	vmcs_writel(HOST_GS_BASE, tmpl); /* 22.2.4 */
}

void vmx_update_nr_cpu_state(void)
{

	struct desc_ptr *gdt = this_cpu_ptr(&host_gdt);
	unsigned long sysenter_esp;
	unsigned long gs;
	unsigned long tmpl;
	struct desc_ptr idt;
	/*
	 * Linux uses per-cpu TSS and GDT, so set these when switching
	 * processors.
	 */

	rdmsrl(MSR_GS_BASE, gs);
	vmcs_writel(GUEST_GS_BASE, gs);

	vmcs_writel(GUEST_TR_BASE, vmx_read_tr_base()); /* 22.2.4 */
	vmcs_writel(GUEST_GDTR_BASE, gdt->address);   /* 22.2.4 */

	rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
	vmcs_writel(GUEST_SYSENTER_ESP, sysenter_esp); /* 22.2.3 */

	rdmsrl(MSR_IA32_SYSENTER_CS, tmpl);
	vmcs_write32(GUEST_SYSENTER_CS, tmpl);

	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl);
	vmcs_writel(GUEST_SYSENTER_EIP, tmpl);

	store_idt(&idt);
	vmcs_writel(GUEST_IDTR_BASE, idt.address);
	vmcs_writel(GUEST_IDTR_LIMIT, idt.size);

	return;
}


/* This needs to be run in R-mode and need to make it more robust / secure  */
static void __vmx_get_cpu_helper(void *ptr)
{
	unsigned int cmd = VMCALL_DO_GET_CPU_HELPER;

        struct vmx_vcpu *vcpu = ptr;

	if(is_in_vmx_nr_mode()){
		/* do a vmcall */
		asm volatile(".byte 0x0F,0x01,0xC1\n" ::"a"(cmd),"b"(ptr));
	} else {
		BUG_ON(raw_smp_processor_id() != vcpu->cpu);
		vmcs_clear(vcpu->vmcs);
		//if (__this_cpu_read(local_vcpu) == vcpu)
		//	__this_cpu_write(local_vcpu, NULL);
	}
}

/**
 * vmx_get_cpu - called before using a cpu
 * @vcpu: VCPU that will be loaded.
 *
 * Disables preemption. Call vmx_put_cpu() when finished.
 */
static void vmx_get_cpu(struct vmx_vcpu *vcpu)
{
	int cur_cpu = get_cpu();

	//if (__this_cpu_read(local_vcpu) != vcpu) {
	//	__this_cpu_write(local_vcpu, vcpu);
	//}

	if (vcpu->cpu != cur_cpu) {
		if (vcpu->cpu >= 0){
			smp_call_function_single(vcpu->cpu,
						 __vmx_get_cpu_helper, (void *) vcpu, 1);
		} else {
			vmcs_clear(vcpu->vmcs);
		}
		vpid_sync_context(vcpu->vpid);
		vcpu->launched = 0;
		vmcs_load(vcpu->vmcs);
		__vmx_setup_cpu();
		if(vcpu->cpu >= 0){
			/* Need to update nr-mode view of GS (per-cpu data) */
			vmx_update_nr_cpu_state();
		}
		vcpu->cpu = cur_cpu;
	} else {
		vmcs_load(vcpu->vmcs);
	}
}





/**
 * vmx_put_cpu - called after using a cpu
 * @vcpu: VCPU that was loaded.
 */
static void vmx_put_cpu(struct vmx_vcpu *vcpu)
{
	put_cpu();
}

static void __vmx_sync_helper(void *ptr)
{
	struct vmx_vcpu *vcpu = ptr;

	ept_sync_context(vcpu->eptp);
}

struct sync_addr_args {
	struct vmx_vcpu *vcpu;
	gpa_t gpa;
};


static void __vmx_sync_individual_addr_helper(void *ptr)
{
	struct sync_addr_args *args = ptr;

	ept_sync_individual_addr(args->vcpu->eptp,
				 (args->gpa & ~(PAGE_SIZE - 1)));
}

/**
 * vmx_ept_sync_global - used to evict everything in the EPT
 * @vcpu: the vcpu
 */
void vmx_ept_sync_vcpu(struct vmx_vcpu *vcpu)
{
	smp_call_function_single(vcpu->cpu,
		__vmx_sync_helper, (void *) vcpu, 1);
}

/**
 * vmx_ept_sync_individual_addr - used to evict an individual address
 * @vcpu: the vcpu
 * @gpa: the guest-physical address
 */
void vmx_ept_sync_individual_addr(struct vmx_vcpu *vcpu, gpa_t gpa)
{
	struct sync_addr_args args;
	args.vcpu = vcpu;
	args.gpa = gpa;

	smp_call_function_single(vcpu->cpu,
		__vmx_sync_individual_addr_helper, (void *) &args, 1);
}


static u64 construct_eptp(unsigned long root_hpa)
{
	u64 eptp = VMX_EPTP_MT_WB | VMX_EPTP_PWL_4;

	/* TODO write the value reading from MSR */
	if (cpu_has_vmx_ept_ad_bits())
		eptp |= VMX_EPTP_AD_ENABLE_BIT;
	eptp |= (root_hpa & PAGE_MASK);

	return eptp;
}

/**
 * vmx_alloc_vmcs - allocates a VMCS region
 *
 * NOTE: Assumes the new region will be used by the current CPU.
 *
 * Returns a valid VMCS region.
 */
static struct vmcs *vmx_alloc_vmcs(void)
{
	return __vmx_alloc_vmcs(raw_smp_processor_id());
}




struct vmcs_cpu_state {
	unsigned long rsp;
	unsigned long rbp;
	unsigned long cr0;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long rflags;
	unsigned long efer;

	u16 cs_selector;
	u16 ds_selector;
	u16 es_selector;
	u16 ss_selector;
	u16 tr_selector;
	u16 fs_selector;
	u16 gs_selector;

	unsigned long  idt_base;
	unsigned long  gdt_base;
	unsigned long  ldt_base;
	unsigned short idt_limit;
	unsigned short gdt_limit;
	unsigned short ldt_limit;

	unsigned long  tr_base;
	unsigned short tr_limit;

	unsigned long cs_base;
	unsigned long ds_base;
	unsigned long es_base;
	unsigned long ss_base;
	unsigned long fs_base;
	unsigned long gs_base;

	unsigned long sysenter_cs;
	unsigned long sysenter_eip;
	unsigned long sysenter_esp;
};

void show_cpu_state(struct vmcs_cpu_state state)
{
	OKDEBUG("Control regs / flags: \n");
	OKDEBUG("rsp     (%#lx)\n", state.rsp);
	OKDEBUG("rbp     (%#lx)\n", state.rbp);
	OKDEBUG("cr0     (%#lx)\n", state.cr0);
	OKDEBUG("cr3     (%#lx)\n", state.cr3);
	OKDEBUG("cr4     (%#lx)\n", state.cr4);
	OKDEBUG("rflags  (%#lx)\n", state.rflags);
	OKDEBUG("efer    (%#lx)\n", state.efer);

	OKDEBUG("idt base (%#lx) limit (%#x)\n", state.idt_base, state.idt_limit);
	OKDEBUG("gdt base (%#lx) limit (%#x)\n", state.gdt_base, state.gdt_limit);
	OKDEBUG("ldt base (%#lx) limit (%#x)\n", state.ldt_base, state.ldt_limit);

	OKDEBUG("Selectors: \n");
	OKDEBUG("cs_s (%#x) ds_s (%#x) es_s (%#x) ss_s (%#x) tr_s (%#x)\n",
		state.cs_selector, state.ds_selector, state.es_selector,
		state.ss_selector, state.tr_selector);
	OKDEBUG("fs_s (%#x) gs_s (%#x)\n",
		state.fs_selector, state.gs_selector);

	OKDEBUG("fs_base (%#lx) gs_base (%#lx)\n",
		state.fs_base,state.gs_base);

	OKDEBUG("sysenter_cs (%lx), systenter_esp (%lx) systenter_eip (%lx)\n",
		state.sysenter_cs, state.sysenter_esp, state.sysenter_eip);
	return;
}

void get_cpu_state(struct vmx_vcpu *vcpu, struct vmcs_cpu_state* cpu_state)
{
	u32 low32, high32;
	struct desc_ptr idt;
	struct desc_ptr gdt;
	//struct desc_ptr ldt;
	unsigned long tr;
	unsigned long tmpl;
	struct nr_cloned_state *cloned_thread;


	cloned_thread = vcpu->cloned_thread;
	/* Start with control regs / flags */
	cpu_state->rsp = cloned_thread->rsp;
	cpu_state->rflags = cloned_thread->rflags;
	cpu_state->rbp = cloned_thread->rbp;

	cpu_state->cr0 = read_cr0();
	cpu_state->cr3 = __read_cr3();
	cpu_state->cr4 = native_read_cr4();

	rdmsr(MSR_EFER, low32, high32);
	cpu_state->efer = low32;


	/* Segment Selectors */
	cpu_state->cs_selector = __KERNEL_CS;
	cpu_state->ds_selector = __KERNEL_DS;
	cpu_state->es_selector = __KERNEL_DS;
	cpu_state->ss_selector = __KERNEL_DS;
	cpu_state->tr_selector = GDT_ENTRY_TSS*8;
	cpu_state->fs_selector = 0;
	cpu_state->gs_selector = 0;

	/* Segment Base + Limits */
#if 1
	if(cloned_thread->msr_fs_base){
		cpu_state->fs_base = cloned_thread->msr_fs_base;
	} else {
		rdmsrl(MSR_FS_BASE, tmpl);
		cpu_state->fs_base = tmpl;
	}
#else
	rdmsrl(MSR_FS_BASE, tmpl);
	cpu_state->fs_base = tmpl;
#endif
#if 0
	if(cloned_thread->msr_gs_base){
		cpu_state->gs_base = cloned_thread->msr_gs_base;
	} else {
		rdmsrl(MSR_GS_BASE, tmpl);
		cpu_state->gs_base = tmpl;
	}
#else
	rdmsrl(MSR_GS_BASE, tmpl);
	cpu_state->gs_base = tmpl;
#endif
	/*Segment AR Bytes */

	/* IDT, GDT, LDT */

#if 0
	cpu_state->idt_base = cloned_thread->idt_base;
	cpu_state->idt_limit = cloned_thread->idt_limit;
#else
	store_idt(&idt);
	cpu_state->idt_base = idt.address;
	cpu_state->idt_limit = idt.size;
#endif
	OKDEBUG("setting IDT values from store_idt: vaddr=%#lx, paddr=%#lx, size=%#x\n",
		cpu_state->idt_base, __pa(cpu_state->idt_base), cpu_state->idt_limit);
        //cpu_state->idt_limit = 0xFFFF;


	native_store_gdt(&gdt);
	cpu_state->gdt_base = gdt.address;
	cpu_state->gdt_limit = gdt.size;

	//native_store_ldt(&ldt);
	cpu_state->ldt_base = 0;
	cpu_state->ldt_limit = 0;


	tr = native_store_tr();
	cpu_state->tr_base = tr;
	cpu_state->tr_limit = 0xff;


	/* sysenter */
	rdmsrl(MSR_IA32_SYSENTER_CS, tmpl);
	cpu_state->sysenter_cs =  tmpl;
	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl);
	cpu_state->sysenter_eip = tmpl;
	rdmsrl(MSR_IA32_SYSENTER_ESP, tmpl);
	cpu_state->sysenter_esp =  tmpl;
	return;
}


/**
 * vmx_setup_initial_guest_state - configures the initial state of guest registers
 */
static void vmx_setup_initial_guest_state(struct vmx_vcpu *vcpu)
{

	/* Need to mask out X64_CR4_VMXE in guest read shadow: we use
	 * this to detect if we are in nr-mode or not. Also mask out
	 * SMEP bit so we can detect when it is turned off. */
	unsigned long cr4_mask = X86_CR4_VMXE | X86_CR4_SMEP;
	unsigned long cr4_shadow = X86_CR4_SMEP;
	unsigned long cr4;
	struct nr_cloned_state *cloned_thread;

	struct vmcs_cpu_state current_cpu_state;
	struct pt_regs *regs;

	regs = task_pt_regs(current);

	get_cpu_state(vcpu, &current_cpu_state);
#ifdef OKERNEL_DEBUG
	show_cpu_state(current_cpu_state);
#endif

	cloned_thread = vcpu->cloned_thread;

	//vcpu->regs[VCPU_REGS_RSP] = cloned_thread.rsp;
	vcpu->regs[VCPU_REGS_RBP] = cloned_thread->rbp;
	vcpu->regs[VCPU_REGS_RAX] = cloned_thread->rax;
	vcpu->regs[VCPU_REGS_RCX] = cloned_thread->rcx;
	vcpu->regs[VCPU_REGS_RDX] = cloned_thread->rdx;
	vcpu->regs[VCPU_REGS_RBX] = cloned_thread->rbx;
	vcpu->regs[VCPU_REGS_RSI] = cloned_thread->rsi;
	vcpu->regs[VCPU_REGS_RDI] = cloned_thread->rdi;
	vcpu->regs[VCPU_REGS_R8] = cloned_thread->r8;
	vcpu->regs[VCPU_REGS_R9] = cloned_thread->r9;
	vcpu->regs[VCPU_REGS_R10] = cloned_thread->r10;
	vcpu->regs[VCPU_REGS_R11] = cloned_thread->r11;
	vcpu->regs[VCPU_REGS_R12] = cloned_thread->r12;
	vcpu->regs[VCPU_REGS_R13] = cloned_thread->r13;
	vcpu->regs[VCPU_REGS_R14] = cloned_thread->r14;
	vcpu->regs[VCPU_REGS_R15] = cloned_thread->r15;
	vcpu->cr2 = cloned_thread->cr2;


#if 0
	OKDEBUG("----start of 'current' regs from __show_regs:\n");
	__show_regs(regs, 1);
	OKDEBUG("----end of 'current' regs from __show_regs.\n");
#endif
	/* Most likely will need to adjust */
	cr4 = current_cpu_state.cr4;
	vmcs_writel(GUEST_CR0, current_cpu_state.cr0);
	vmcs_writel(CR0_READ_SHADOW, current_cpu_state.cr0);
	vmcs_writel(GUEST_CR3, current_cpu_state.cr3);
	vmcs_writel(GUEST_CR4, cr4);
	vmcs_writel(CR4_GUEST_HOST_MASK, cr4_mask);
	vmcs_writel(CR4_READ_SHADOW, cr4_shadow);

	/* Most of this we can set from the host state apart. Need to make
	   sure we clone the kernel stack pages in the EPT mapping.
	*/

	vmcs_writel(GUEST_RIP, cloned_thread->rip);
	//vmcs_writel(GUEST_RSP, current_cpu_state.rsp);
	vmcs_writel(GUEST_RSP, cloned_thread->rsp);
	vmcs_writel(GUEST_RFLAGS, cloned_thread->rflags);
	//vmcs_writel(GUEST_RFLAGS, 0x2);
	vmcs_writel(GUEST_IA32_EFER, current_cpu_state.efer);

	/* configure segment selectors */
	vmcs_write16(GUEST_CS_SELECTOR, current_cpu_state.cs_selector);
	vmcs_write16(GUEST_DS_SELECTOR, current_cpu_state.ds_selector);
	vmcs_write16(GUEST_ES_SELECTOR, current_cpu_state.es_selector);
	vmcs_write16(GUEST_FS_SELECTOR, current_cpu_state.fs_selector);
	vmcs_write16(GUEST_GS_SELECTOR, current_cpu_state.gs_selector);
	vmcs_write16(GUEST_SS_SELECTOR, current_cpu_state.ss_selector);
	vmcs_write16(GUEST_TR_SELECTOR, current_cpu_state.tr_selector);

        /* initialize sysenter */
	vmcs_write32(GUEST_SYSENTER_CS, current_cpu_state.sysenter_cs);
	vmcs_writel(GUEST_SYSENTER_ESP, current_cpu_state.sysenter_esp);
	vmcs_writel(GUEST_SYSENTER_EIP, current_cpu_state.sysenter_eip);

	vmcs_writel(GUEST_GDTR_BASE, current_cpu_state.gdt_base);

	vmcs_writel(GUEST_GDTR_LIMIT, current_cpu_state.gdt_limit);
	//vmcs_writel(GUEST_GDTR_LIMIT, 0x7f);
	vmcs_writel(GUEST_IDTR_BASE, current_cpu_state.idt_base);
	vmcs_writel(GUEST_IDTR_LIMIT, current_cpu_state.idt_limit);


        /* guest LDTR */
	vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	vmcs_writel(GUEST_LDTR_AR_BYTES, 0x0082);
	vmcs_writel(GUEST_LDTR_BASE, 0);
	vmcs_writel(GUEST_LDTR_LIMIT, 0);

#if 0
	vmcs_writel(GUEST_TR_BASE, current_cpu_state.tr_base);
	vmcs_writel(GUEST_TR_LIMIT, current_cpu_state.tr_limit);
	vmcs_writel(GUEST_TR_AR_BYTES, 0x0080 | VMX_AR_TYPE_BUSY_64_TSS);
#else
	vmcs_writel(GUEST_TR_BASE, vmx_read_tr_base());
	vmcs_writel(GUEST_TR_AR_BYTES, 0x0080 | VMX_AR_TYPE_BUSY_64_TSS);
	vmcs_writel(GUEST_TR_LIMIT, current_cpu_state.tr_limit);
#endif

	// DO WE NEED CHANGE ANY OF THESE???
	vmcs_writel(GUEST_DR7, 0);

	/* guest segment bases */
	vmcs_writel(GUEST_CS_BASE, 0);
	vmcs_writel(GUEST_DS_BASE, 0);
	vmcs_writel(GUEST_ES_BASE, 0);
	OKDEBUG("setting GUEST_GS_BASE=%#lx\n", current_cpu_state.gs_base);
	vmcs_writel(GUEST_GS_BASE, current_cpu_state.gs_base);
	vmcs_writel(GUEST_SS_BASE, 0);
	OKDEBUG("setting GUEST_FS_BASE=%#lx\n", current_cpu_state.fs_base);
	vmcs_writel(GUEST_FS_BASE, current_cpu_state.fs_base);

        /* guest segment access rights */
	vmcs_writel(GUEST_CS_AR_BYTES, 0xA09B);
	vmcs_writel(GUEST_DS_AR_BYTES, 0xA093);
	vmcs_writel(GUEST_ES_AR_BYTES, 0xA093);
	vmcs_writel(GUEST_FS_AR_BYTES, 0xA093);
	vmcs_writel(GUEST_GS_AR_BYTES, 0xA093);
	vmcs_writel(GUEST_SS_AR_BYTES, 0xA093);

	/* guest segment limits */
	vmcs_write32(GUEST_CS_LIMIT, 0xFFFFFFFF);
	vmcs_write32(GUEST_DS_LIMIT, 0xFFFFFFFF);
	vmcs_write32(GUEST_ES_LIMIT, 0xFFFFFFFF);
	vmcs_write32(GUEST_FS_LIMIT, 0xFFFFFFFF);
	vmcs_write32(GUEST_GS_LIMIT, 0xFFFFFFFF);
	vmcs_write32(GUEST_SS_LIMIT, 0xFFFFFFFF);

	/* other random initialization */
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */
	return;
}



/**
 *  vmx_setup_vmcs - configures the vmcs with starting parameters
 */
static void vmx_setup_vmcs(struct vmx_vcpu *vcpu)
{
	unsigned int exception_bitmap;

	vmcs_write16(VIRTUAL_PROCESSOR_ID, vcpu->vpid);
	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Control */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
		vmcs_config.pin_based_exec_ctrl);

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
		vmcs_config.cpu_based_exec_ctrl);

	if (cpu_has_secondary_exec_ctrls()) {
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
			     vmcs_config.cpu_based_2nd_exec_ctrl);
	}

	vmcs_write64(EPT_POINTER, vcpu->eptp);

	vmcs_write32(CR3_TARGET_COUNT, 0);           /* 22.2.1 */

	vmcs_write64(MSR_BITMAP, __pa(msr_bitmap));

	vmcs_config.vmentry_ctrl |= VM_ENTRY_IA32E_MODE;

	vmcs_write32(VM_EXIT_CONTROLS, vmcs_config.vmexit_ctrl);
	vmcs_write32(VM_ENTRY_CONTROLS, vmcs_config.vmentry_ctrl);

	vmcs_writel(CR0_GUEST_HOST_MASK, ~0ul);
	vmcs_writel(CR4_GUEST_HOST_MASK, ~0ul);

	//kvm_write_tsc(&vmx->vcpu, 0);
	vmcs_writel(TSC_OFFSET, 0);


#if 0
	/* Handle (page-faults) exceptions in R-mode */

	vmcs_write32(VMCS_EXCEPTION_BMP, 0xFFFFFFFF);
        vmcs_writel(VMCS_PAGEFAULT_ERRCODE_MASK, 0);
        vmcs_writel(VMCS_PAGEFAULT_ERRCODE_MATCH, 0);
#else
	/* Handle (page-faults) exceptions in NR-mode */
	//exception_bitmap = 0xFFFFFFFF;
	//exection_bitmap = (exception_bitmap & ~(EXCEPTION_PF));
	exception_bitmap = 0;
	vmcs_write32(VMCS_EXCEPTION_BMP, exception_bitmap);
	vmcs_writel(VMCS_PAGEFAULT_ERRCODE_MASK, 0);
        vmcs_writel(VMCS_PAGEFAULT_ERRCODE_MATCH, 0);
#endif

	/* cid: We most likely will need to protect parts of the xsaves region.
	   and add an exit handler condition. At the moment we don't care. */
	if(cpu_has_vmx_xsaves()){
		vmcs_write64(XSS_EXIT_BITMAP, 0);
	}
	vmx_setup_constant_host_state();
}



/**
 * vmx_allocate_vpid - reserves a vpid and sets it in the VCPU
 * @vmx: the VCPU
 */
static int vmx_allocate_vpid(struct vmx_vcpu *vmx)
{
	int vpid;

	vmx->vpid = 0;

	spin_lock(&vmx_vpid_lock);
	vpid = find_first_zero_bit(vmx_vpid_bitmap, VMX_NR_VPIDS);
	if (vpid < VMX_NR_VPIDS) {
		vmx->vpid = vpid;
		__set_bit(vpid, vmx_vpid_bitmap);
	}
	spin_unlock(&vmx_vpid_lock);

	return vpid >= VMX_NR_VPIDS;
}

/**
 * vmx_free_vpid - frees a vpid
 * @vmx: the VCPU
 */
static void vmx_free_vpid(struct vmx_vcpu *vmx)
{
	spin_lock(&vmx_vpid_lock);
	if (vmx->vpid != 0)
		__clear_bit(vmx->vpid, vmx_vpid_bitmap);
	spin_unlock(&vmx_vpid_lock);
}



/**
 * vmx_create_vcpu - allocates and initializes a new virtual cpu
 *
 * Returns: A new VCPU structure
 */
static struct vmx_vcpu * vmx_create_vcpu(struct nr_cloned_state* cloned_thread)
{
	struct vmx_vcpu *vcpu = kmalloc(sizeof(struct vmx_vcpu), GFP_KERNEL);

	if (!vcpu){
		printk(KERN_ERR "okernel: vmx_create_vcpu: failed to kmalloc vcpu.\n");
		return NULL;
	}

	if(!cloned_thread){
		printk(KERN_ERR "okernel: vmx_create_vcpu: passed NULL cloned_thread_state.\n");
		return NULL;
	}

	memset(vcpu, 0, sizeof(*vcpu));

	vcpu->vmcs = vmx_alloc_vmcs();

	if (!vcpu->vmcs)
		goto fail_vmcs;

	if (vmx_allocate_vpid(vcpu))
		goto fail_vpid;

	vcpu->cpu = -1;

	spin_lock_init(&vcpu->ept_lock);

	if(!vt_ept_2M_init(vcpu)){
		goto fail_ept;
	}

	vcpu->eptp = construct_eptp(vcpu->ept_root);

	vmx_get_cpu(vcpu);

	vmx_setup_vmcs(vcpu);

	vcpu->cloned_thread = cloned_thread;

	vmx_setup_initial_guest_state(vcpu);

	vmx_put_cpu(vcpu);

#if 1
	if (cpu_has_vmx_ept_ad_bits()) {
		vcpu->ept_ad_enabled = true;
		OKDEBUG("enabled EPT A/D bits");
	}
#endif
#if defined (OKERNEL_PROTECTED_MEMORY)
	/* Example of the kind of memory protection we can provide: unmap 'protected pages' from any EPT tables */
	if(!(modify_ept_page_range_perms(vcpu, ok_protected_page, OK_NR_PROTECTED_PAGES, 0))){
		printk("okernel: failed to remove protected pages from EPT...\n");
		BUG();
	}
#endif

	return vcpu;

fail_ept:
	vmx_free_vpid(vcpu);

fail_vpid:
	vmx_free_vmcs(vcpu->vmcs);
fail_vmcs:
	kfree(vcpu);
	return NULL;
}

void vmx_destroy_ept(struct vmx_vcpu *vcpu)
{
	int i;
	struct ept_pt_list *entry;
	struct ept_pt_list *q;
	unsigned long *vaddr;
	unsigned long vaddr_p;

	list_for_each_entry_safe(entry, q, &vcpu->ept_table_pages.list, list){
		for(i = 0; i < entry->n_pages; i++){
			vaddr = __va(entry->page[i].phys);
			vaddr_p = (unsigned long)*vaddr;
			OKDEBUG("Freeing page phys=%#lx __va(phys)=%#lx *virtp=%#lx *virt=%#lx\n",
			       (unsigned long)entry->page[i].phys,
			       (unsigned long)vaddr,
			       (unsigned long)vaddr_p,
			       (unsigned long)*entry->page[i].virt);
			__free_page(virt_to_page(__va(entry->page[i].phys)));
		}
		kfree(entry->page);
		list_del(&entry->list);
		kfree(entry);
	}
	return;
}

/**
 * vmx_destroy_vcpu - destroys and frees an existing virtual cpu
 * @vcpu: the VCPU to destroy
 */
static void vmx_destroy_vcpu(struct vmx_vcpu *vcpu)
{
	OKDEBUG("called.\n");
	vmx_get_cpu(vcpu);
	ept_sync_context(vcpu->eptp);
	vmx_destroy_ept(vcpu);
	__free_page(virt_to_page(__va(vcpu->eptp)));
	vmcs_clear(vcpu->vmcs);
	__this_cpu_write(local_vcpu, NULL);
	vmx_put_cpu(vcpu);
	vmx_free_vpid(vcpu);
	vmx_free_vmcs(vcpu->vmcs);
	kfree(vcpu);
}


#ifdef CONFIG_X86_64
#define R "r"
#define Q "q"
#else
#define R "e"
#define Q "l"
#endif

/**
 * vmx_run_vcpu - launches the CPU into non-root mode
 * @vcpu: the vmx instance to launch
 */
static unsigned int __noclone vmx_run_vcpu(struct vmx_vcpu *vcpu)
{
	nr_preempt_count_set_offset(1);
	unset_vmx_r_mode();

	asm(
		/* Store host registers */
		"push %%"R"dx; push %%"R"bp;"
		"push %%"R"cx \n\t" /* placeholder for guest rcx */
		"push %%"R"cx \n\t"
		"cmp %%"R"sp, %c[host_rsp](%0) \n\t"
		"je 1f \n\t"
		"mov %%"R"sp, %c[host_rsp](%0) \n\t"
		ASM_VMX_VMWRITE_RSP_RDX "\n\t"
		"1: \n\t"
		/* Reload cr2 if changed */
		"mov %c[cr2](%0), %%"R"ax \n\t"
		"mov %%cr2, %%"R"dx \n\t"
		"cmp %%"R"ax, %%"R"dx \n\t"
		"je 2f \n\t"
		"mov %%"R"ax, %%cr2 \n\t"
		"2: \n\t"
		/* Check if vmlaunch or vmresume is needed */
		"cmpl $0, %c[launched](%0) \n\t"
		/* Load guest registers.  Don't clobber flags. */
		"mov %c[rax](%0), %%"R"ax \n\t"
		"mov %c[rbx](%0), %%"R"bx \n\t"
		"mov %c[rdx](%0), %%"R"dx \n\t"
		"mov %c[rsi](%0), %%"R"si \n\t"
		"mov %c[rdi](%0), %%"R"di \n\t"
		"mov %c[rbp](%0), %%"R"bp \n\t"
#ifdef CONFIG_X86_64
		"mov %c[r8](%0),  %%r8  \n\t"
		"mov %c[r9](%0),  %%r9  \n\t"
		"mov %c[r10](%0), %%r10 \n\t"
		"mov %c[r11](%0), %%r11 \n\t"
		"mov %c[r12](%0), %%r12 \n\t"
		"mov %c[r13](%0), %%r13 \n\t"
		"mov %c[r14](%0), %%r14 \n\t"
		"mov %c[r15](%0), %%r15 \n\t"
#endif
		"mov %c[rcx](%0), %%"R"cx \n\t" /* kills %0 (ecx) */
		// "xchg %%bx, %%bx \n\t"
		/* Enter guest mode */
		"jne .Llaunched \n\t"
		ASM_VMX_VMLAUNCH "\n\t"
		"jmp .Lokernel_vmx_return \n\t"
		".Llaunched: " ASM_VMX_VMRESUME "\n\t"
		".Lokernel_vmx_return: "
		/* Save guest registers, load host registers, keep flags */
		"mov %0, %c[wordsize](%%"R"sp) \n\t"
		"pop %0 \n\t"
		"mov %%"R"ax, %c[rax](%0) \n\t"
		"mov %%"R"bx, %c[rbx](%0) \n\t"
		"pop"Q" %c[rcx](%0) \n\t"
		"mov %%"R"dx, %c[rdx](%0) \n\t"
		"mov %%"R"si, %c[rsi](%0) \n\t"
		"mov %%"R"di, %c[rdi](%0) \n\t"
		"mov %%"R"bp, %c[rbp](%0) \n\t"
#ifdef CONFIG_X86_64
		"mov %%r8,  %c[r8](%0) \n\t"
		"mov %%r9,  %c[r9](%0) \n\t"
		"mov %%r10, %c[r10](%0) \n\t"
		"mov %%r11, %c[r11](%0) \n\t"
		"mov %%r12, %c[r12](%0) \n\t"
		"mov %%r13, %c[r13](%0) \n\t"
		"mov %%r14, %c[r14](%0) \n\t"
		"mov %%r15, %c[r15](%0) \n\t"
#endif
		"mov %%rax, %%r10 \n\t"
		"mov %%rdx, %%r11 \n\t"

		"mov %%cr2, %%"R"ax   \n\t"
		"mov %%"R"ax, %c[cr2](%0) \n\t"

		"pop  %%"R"bp; pop  %%"R"dx \n\t"
		"setbe %c[fail](%0) \n\t"

		"mov $" __stringify(__USER_DS) ", %%rax \n\t"
		"mov %%rax, %%ds \n\t"
		"mov %%rax, %%es \n\t"
	      : : "c"(vcpu), "d"((unsigned long)HOST_RSP),
		[launched]"i"(offsetof(struct vmx_vcpu, launched)),
		[fail]"i"(offsetof(struct vmx_vcpu, fail)),
		[host_rsp]"i"(offsetof(struct vmx_vcpu, host_rsp)),
		[rax]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RBP])),
#ifdef CONFIG_X86_64
		[r8]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R15])),
#endif
		[cr2]"i"(offsetof(struct vmx_vcpu, cr2)),
		[wordsize]"i"(sizeof(ulong))
	      : "cc", "memory"
		, R"ax", R"bx", R"di", R"si"
#ifdef CONFIG_X86_64
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
#endif
	);

	set_vmx_r_mode();
	nr_preempt_count_set_offset(0);

	vcpu->launched = 1;

	if (unlikely(vcpu->fail)) {
		printk(KERN_ERR "vmx: failure detected (err %x)\n",
		       vmcs_read32(VM_INSTRUCTION_ERROR));
		return VMX_EXIT_REASONS_FAILED_VMENTRY;
	}

	return vmcs_read32(VM_EXIT_REASON);
}


static void vmx_step_instruction(void)
{
        vmcs_writel(GUEST_RIP, vmcs_readl(GUEST_RIP) +
                               vmcs_read32(VM_EXIT_INSTRUCTION_LEN));
}

static void vmx_handle_cpuid(struct vmx_vcpu *vcpu)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned int orig_eax;

	eax = vcpu->regs[VCPU_REGS_RAX];
	orig_eax = eax;
	ecx = vcpu->regs[VCPU_REGS_RCX];

	native_cpuid(&eax, &ebx, &ecx, &edx);
	vcpu->regs[VCPU_REGS_RAX] = eax;
	vcpu->regs[VCPU_REGS_RBX] = ebx;

	if(orig_eax == 1){
		/* Requesting processor features, need to mask VMX (bit 5, ecx) */
		OKDEBUG("Masking cpuid ecx vmx bit");
		ecx &= ~(ECX_VMX_BIT);
	}

	vcpu->regs[VCPU_REGS_RCX] = ecx;
	vcpu->regs[VCPU_REGS_RDX] = edx;
}

static void  get_upc(uid_t *uid, pid_t *pid, char** comm)
{
	*uid = from_kuid(&init_user_ns, current_uid());
	*pid = current->pid;
	*comm = current->comm;
}

static int vmx_handle_CR_access(struct vmx_vcpu *vcpu)
{
	static const char cr4_warning[] = KERN_CRIT
		"okernel blocking write to CR4: SMEP exploit attempt?"
		" (uid %d, pid %d, command %s, access type %d, "
		"register %d, reg value %#lx)\n";

	static const char cr_error[] = KERN_CRIT
		"okernel detected unhandled write to CR: bug or exploit attempt?"
		" (uid %d, pid %d, command %s, exit qualification %#lx)\n";

	unsigned long qual, gpv;
	unsigned int cr, at, gp;
	uid_t uid;
	pid_t pid;
	char *comm;

	vmx_get_cpu(vcpu);
	qual = vmcs_readl(EXIT_QUALIFICATION);
	vmx_put_cpu(vcpu);
	cr = CR_FROM_QUAL(qual);
	at = CR_ACCESS_TYPE_FROM_QUAL(qual);
	gp = CR_ACCESS_GP_FROM_QUAL(qual);
	gpv = (unsigned long)vcpu->regs[gp];
	get_upc(&uid, &pid, &comm);

	if (cr == 4){
		printk(cr4_warning, uid, pid, comm, at, gp, gpv);
		OKSEC("okernel blocking write to CR4: SMEP exploit attempt?"
		      " (uid %d, pid %d, command %s, access type %d, "
		      "register %d, ""reg value %#lx)\n",
		      uid, pid, comm, at, gp, gpv);
		vmx_step_instruction();
		vmx_destroy_vcpu(vcpu);
		do_exit(-1);
		return 1;
	}
	printk(cr_error, uid, pid, comm, qual);
	OKSEC("okernel detected unhandled write to CR: bug or exploit attempt?"
	      " (uid %d, pid %d, command %s, exit qualification %#lx)\n",
	      uid, pid, comm, qual);
	return 0;
}

static int vmx_handle_EPT_misconfig(struct vmx_vcpu *vcpu)
{
	static const char warning[] = KERN_CRIT
		"okernel ept misconfig for NR physical address %#lx "
		"found plm2 entry %#lx pte/pml1 %#lx\n";

	unsigned long gp_addr, *pml2_e, *epte;
	vmx_get_cpu(vcpu);
	gp_addr = vmcs_readl(GUEST_PHYSICAL_ADDRESS);
	vmx_put_cpu(vcpu);

	if((pml2_e =  find_pd_entry(vcpu, gp_addr))){
		epte = ept_page_entry(vcpu, gp_addr);
	} else {
		epte = 0;
	}
	printk(warning, gp_addr, (pml2_e) ? *pml2_e : 0, (epte) ? *epte : 0);
	return 0;
}

static int vmx_handle_exception_NMI(struct vmx_vcpu *vcpu)
{
	static const char gp_excp[] = KERN_CRIT
		"okernel unhandled GP exception exit qualification "
		"%#lx err %#lx non root RIP %#lx\n";

	static const char other_excp[] = KERN_CRIT
		"okernel unhandled exception or NMI  vector %d "
		"exit qualification %#lx\n";

	union {
		struct intr_info s;
		ulong v;
	} vii;
	unsigned long qual, err, rip;

	vmx_get_cpu(vcpu);
	vii.v = vmcs_readl(VM_EXIT_INTR_INFO);
	if(vii.s.valid == INTR_INFO_VALID_VALID){
		qual = (u64)vmcs_readl(EXIT_QUALIFICATION);
		if(vii.s.vector == EXCEPTION_GP){
			err = (u64)vmcs_readl(VMCS_VMEXIT_INTR_ERRCODE);
			rip = vmcs_readl(GUEST_RIP);
			printk(gp_excp, qual, err, rip);
		} else {
			printk(other_excp, vii.s.vector, qual);
		}
	} else {
		printk("okernel exception or NMI, no valid diagnosis info\n");
	}
	vmx_put_cpu(vcpu);
	return 0;
}

#if 0
static void check_int(struct vmx_vcpu *vcpu, char *s)
{
	vmx_get_cpu(vcpu);
	if((vmcs_readl(GUEST_RFLAGS) & RFLAGS_IF_BIT)){
		OKLOG("INFO: %s with interrupts enabled\n", s);
	}else{
		OKWARN("WARNING: %s with interrupts disabled\n",s);
	}
	vmx_put_cpu(vcpu);
}

static void check_int_enabled(struct vmx_vcpu *vcpu, char *s)
{
	vmx_get_cpu(vcpu);
	if(!(vmcs_readl(GUEST_RFLAGS) & RFLAGS_IF_BIT)){
		OKWARN("WARNING: %s with interrupts disabled\n",s);
	}
	vmx_put_cpu(vcpu);
}
#endif

void vmx_handle_vmcall(struct vmx_vcpu *vcpu, int nr_irqs_enabled)
{
	int ret = 0;
	unsigned long cmd;
	unsigned long arg1;
#if !defined(CONFIG_THREAD_INFO_IN_TASK)
	struct thread_info *nr_ti;
	struct thread_info *r_ti;
#endif
	unsigned int cloned_tsk_state;
#if defined(OKERNEL_DEBUG)
	unsigned long rbp;
	unsigned long rsp;
#endif

	int cpu;
	struct tss_struct *tss;
	volatile unsigned long fs;
	volatile unsigned long gs;
	volatile unsigned long nr_fs;
	volatile unsigned long nr_gs;
	unsigned long h_cr3 = 0;
#if !defined(CONFIG_THREAD_INFO_IN_TASK)
	int need_set_signal;
#endif

	long code;
	unsigned long tls;

	struct vmx_vcpu *cpu_ptr;
        /* do_fork_fixup args */
	struct task_struct *p;

	unsigned long r_irqs_disabled;
	unsigned long nr_rflags;

	cmd = vcpu->regs[VCPU_REGS_RAX];

#if defined(OKERNEL_DEBUG)
	OKDEBUG("cmd (%lu)\n", cmd);
	OKDEBUG("in_atomic(): %d, irqs_disabled(): %d, pid: %d, name: %s\n",
		 in_atomic(), irqs_disabled(), current->pid, current->comm);
	OKDEBUG("preempt_count (%d) rcu_preempt_depth (%d)\n",
		preempt_count(), rcu_preempt_depth());

	asm volatile ("mov %%rbp,%0" : "=rm" (rbp));
	OKDEBUG("rbp currently  (%#lx)\n", rbp);
	asm volatile ("mov %%rsp,%0" : "=rm" (rsp));
	OKDEBUG("rsp currently  (%#lx)\n", rsp);
#endif

	if(cmd == VMCALL_DO_FORK_FIXUP){
		struct fork_frame *fork_frame;
		struct inactive_task_frame *frame;
		p = (struct task_struct*)vcpu->regs[VCPU_REGS_RBX];
		tls = (unsigned long)vcpu->regs[VCPU_REGS_RCX];

		OKDEBUG("VMCALL_DO_FORK_FIXUP called for p (%#lx) (%s) tls (%#lx)\n",
			(unsigned long)p, p->comm, tls);
		fork_frame = (struct fork_frame*) p->thread.sp;
		frame = &fork_frame->frame;
		frame->ret_addr = (unsigned long) okernel_ret_from_fork; //instead of ret_from_fork

		vmx_get_cpu(vcpu);
		gs = vmcs_readl(GUEST_GS_BASE);
		vmx_put_cpu(vcpu);

		OKDEBUG("current pid (%d) (%x)\n", current->pid, current->pid);

		p->okernel_fork_gs_base = gs;

		OKDEBUG("VMCALL_DO_FORK_FIXUP setting gs to (%#lx) for p (%#lx)\n",
			p->okernel_fork_gs_base, (unsigned long)p);

		BXMAGICBREAK;
		ret = 0;
	} else if (cmd == VMCALL_DO_TLS_FIXUP){
		p = (struct task_struct*)vcpu->regs[VCPU_REGS_RBX];
		tls = (unsigned long)vcpu->regs[VCPU_REGS_RCX];

		vmx_get_cpu(vcpu);
		fs = vmcs_readl(GUEST_FS_BASE);
		vmx_put_cpu(vcpu);

		OKDEBUG("current pid (%d) (%x)\n", current->pid, current->pid);

		/* Need to look into TLS setting some more. */
		if(tls){
			OKDEBUG("setting new process FS based on TLS=%#lx\n", tls);
			p->okernel_fork_fs_base = tls;
		} else {
			p->okernel_fork_fs_base = fs;

		}

		OKDEBUG("VMCALL_TLS_FIXUP setting fs to (%#lx) for p (%#lx)\n",
			p->okernel_fork_fs_base, (unsigned long)p);

		OKDEBUG("\nCurrent (pid=%d) Code  Segment start = 0x%lx, end = 0x%lx \n"
		       "Data  Segment start = 0x%lx, end = 0x%lx\n"
		       "Stack Segment start = 0x%lx\n",
		       current->pid,
		       current->mm->start_code, current->mm->end_code,
		       current->mm->start_data, current->mm->end_data,
		       current->mm->start_stack);
		OKDEBUG("Current (pid=%d) mm vma mappings done.\n", current->pid);
		BXMAGICBREAK;
		ret = 0;
	} else if(cmd == VMCALL_DO_EXEC_FIXUP_HOST){
		/* Next time we take a vmexit we will return using these page tables - should validate the address */
		h_cr3 = vcpu->regs[VCPU_REGS_RBX];
		OKDEBUG("excec_fixup: Setting saved HOST CR3 to (%#lx) __pa (%#lx)\n",
		       (unsigned long)h_cr3, __pa(h_cr3));
		vmx_get_cpu(vcpu);
		vmcs_writel(HOST_CR3, __pa(h_cr3));
		vmx_put_cpu(vcpu);
		BXMAGICBREAK;
		ret = 0;
	} else if (cmd == VMCALL_DO_GET_CPU_HELPER){
		cpu_ptr = (void*)vcpu->regs[VCPU_REGS_RBX];
		OKDEBUG("calling __vmx_get_cpu_helper.\n");
		__vmx_get_cpu_helper(cpu_ptr);
		ret = 0;
	} else if (cmd == VMCALL_SCHED){

		arg1 = (unsigned long)vcpu->regs[VCPU_REGS_RBX];

#if !defined(CONFIG_THREAD_INFO_IN_TASK)
		nr_ti = vcpu->cloned_thread_info;
		r_ti = current_thread_info();
#endif
		cloned_tsk_state = vcpu->cloned_tsk->state;

		OKDEBUG("in VMCALL schedule - current state (%lu) cloned state (%u)\n",
			current->state, cloned_tsk_state);
		OKDEBUG("VMCALL sched arg:=(%#lx)\n", arg1);

		switch(cloned_tsk_state){
		case TASK_RUNNING:
			OKDEBUG("cloned_task (TASK_RUNNING)\n");
			break;
		case TASK_INTERRUPTIBLE:
			OKDEBUG("cloned_task (TASK_INTERRUPTIBLE)\n");
			break;
		case TASK_UNINTERRUPTIBLE:
			OKDEBUG("cloned_task (TASK_UNINTERRUPTIBLE)\n");
			break;
		default:
			OKDEBUG("cloned_task (OTHER STATE)\n");
		}

		switch(current->state){
		case TASK_RUNNING:
			OKDEBUG("current (TASK_RUNNING)\n");
			break;
		case TASK_INTERRUPTIBLE:
			OKDEBUG("current (TASK_INTERRUPTIBLE)\n");
			break;
		case TASK_UNINTERRUPTIBLE:
			OKDEBUG("current (TASK_UNINTERRUPTIBLE)\n");
			break;
		default:
			OKDEBUG("current (OTHER STATE)\n");
		}

#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
		OKDEBUG("state=%lx set at [<%p>] %pS\n",
			current->state,
			(void *)current->task_state_change,
			(void *)current->task_state_change);
#endif
#if !defined(CONFIG_THREAD_INFO_IN_TASK)
                /* Re-sync cloned-thread thread_info */
		OKDEBUG("syncing cloned thread_info state (NR->R) (original r_ti->flags=%#lx)\n",
			r_ti->flags);
		BXMAGICBREAK;

		if((need_set_signal = signal_pending(current))){
			OKDEBUG("sig pending before copy thread_info from NR to R.\n");
		}


		memcpy(r_ti, nr_ti, sizeof(struct thread_info));
		//smp_mb();

		OKDEBUG("synced cloned thread_info state (NR->R) (new r_ti->flags=%#lx)\n",
		       r_ti->flags);

		if(need_set_signal){
			set_tsk_thread_flag(current, TIF_SIGPENDING);
		}


#if defined(OKERNEL_DEBUG)
		if(signal_pending(current)){
			OKDEBUG("sig pending after copy thread_info from NR to R.\n");
		}
#endif
#endif // CONFIG_THREAD_INFO_IN_TASK
		vmx_get_cpu(vcpu);
		nr_fs = vmcs_readl(GUEST_FS_BASE);
		nr_gs = vmcs_readl(GUEST_GS_BASE);
		vmx_put_cpu(vcpu);
		wrmsrl(MSR_FS_BASE, nr_fs);
		wrmsrl(MSR_GS_BASE, nr_gs);
#if defined(OKERNEL_DEBUG)
		/* Don't need this rdmsrl, just for debug output */
		rdmsrl(MSR_FS_BASE, fs);
		rdmsrl(MSR_GS_BASE, gs);

		cpu = smp_processor_id();
		tss = &per_cpu(cpu_tss, cpu);

		OKDEBUG("calling schedule_r (pid %d) cpu_cur_tos (%#lx) tss.sp0 (%#lx) flgs (%#lx)\n",
		       current->pid, current_top_of_stack(), (unsigned long)tss->x86_tss.sp0,
		       current_thread_info()->flags);

		OKDEBUG("calling schedule_r MSR_FS_BASE=%#lx nr_fs=%#lx MSR_GS_BASE=%#lx nr_gs=%#lx\n",
		       fs, nr_fs, gs, nr_gs);

		OKDEBUG("calling schedule_r in_atomic(): %d, irqs_disabled(): %d, pid: %d, name: %s\n",
		       in_atomic(), irqs_disabled(), current->pid, current->comm);
		OKDEBUG("calling schedule_r preempt_count (%d) rcu_preempt_depth (%d)\n",
		       preempt_count(), rcu_preempt_depth());
#endif
		r_irqs_disabled = irqs_disabled();

		BXMAGICBREAK;

		unset_vmx_r_mode();

                /* This is the only place we should be swapping CPUs */


		/* There is redunancy here: don't need to do all this flushing */
		vpid_sync_vcpu_global();
		ept_sync_global();
		barrier();

		if(arg1 == OK_SCHED){
			schedule_r_mode();
		} else if (arg1 == OK_SCHED_PREEMPT){
			preempt_schedule_r_mode();
		} else {
			OKERR("Invalid vmcall schedule argument.\n");
			BUG();
		}
		vpid_sync_vcpu_global();
		ept_sync_global();

		/* We may come back here on a different CPU...*/

		set_vmx_r_mode();

                /* Re-sync cloned-thread thread_info */
		cpu = smp_processor_id();
		tss = &per_cpu(cpu_tss, cpu);

		OKDEBUG("ret schedule_r (pid %d) cpu_cur_tos (%#lx) tss.sp0 (%#lx) flgs (%#lx)\n",
		       current->pid, current_top_of_stack(), (unsigned long)tss->x86_tss.sp0,
		       current_thread_info()->flags);

		OKDEBUG("syncing cloned thread_info state (R->NR)...\n");
		BXMAGICBREAK;

#if !defined(CONFIG_THREAD_INFO_IN_TASK)
		memcpy(nr_ti, r_ti, sizeof(struct thread_info));
		OKDEBUG("synced cloned thread_info state (R->NR) (nr_ti->flags=%#lx)\n",
		       nr_ti->flags);
#endif

		OKDEBUG("ret from sched in_atomic(): %d, irqs_disabled(): %d, pid: %d, name: %s\n",
		       in_atomic(), irqs_disabled(), current->pid, current->comm);
		OKDEBUG("ret from preempt_count (%d) rcu_preempt_depth (%d)\n",
		       preempt_count(), rcu_preempt_depth());

		/* IRQs should be enabled on return from schedule()...check this */
		BUG_ON(irqs_disabled());

		if(r_irqs_disabled){
			/* irqs were disabled when we entered from NR mode but now they are enabled */
			/* so update NR mode state (can happen through calls to sched_yield() */
			vmx_get_cpu(vcpu);
			nr_rflags = vmcs_readl(GUEST_RFLAGS);
			vmcs_writel(GUEST_RFLAGS, nr_rflags | RFLAGS_IF_BIT);
			vmx_put_cpu(vcpu);
		}
		BXMAGICBREAK;
	} else if(cmd == VMCALL_DOEXIT){
		code = (long)vcpu->regs[VCPU_REGS_RBX];
		OKDEBUG("calling do_exit(%ld)...\n", code);
		vmx_destroy_vcpu(vcpu);
		do_exit(code);
	} else {
		OKERR("unexpected VMCALL argument.\n");
		BUG();
		ret = -1;
	}
#if defined(OKERNEL_DEBUG)
	if(signal_pending(current)){
		OKDEBUG("sig pending on exit from vmcall.\n");
	}
#endif
	/* This is what vmcall() sees as the retun value */
	vcpu->regs[VCPU_REGS_RAX] = ret;
	return;
}


void check_gva(unsigned long addr)
{
	pte_t *kpte;
	unsigned int level;
	pgprot_t prot;

	OKDEBUG("Checking guest physical pg perms for guest virtual %#lx\n",
	       addr);
	kpte = lookup_address(addr, &level);
	if (!kpte){
		OKDEBUG("Address %#lx not found in guest page tables", addr);
		return;
	}
	prot = pte_pgprot(*kpte);
	if (pgprot_val(prot) & pgprot_val(__pgprot(_PAGE_NX))){
		OKDEBUG("NX is set\n");
	}
	if (pgprot_val(prot) & pgprot_val(__pgprot(_PAGE_RW))){
		OKDEBUG("RW is set\n");
	}
}

void check_gpa(struct vmx_vcpu *vcpu, unsigned long addr)
{
	OKDEBUG("Checking EPT perms for %#lx\n", addr);
	if (is_set_ept_page_flag(vcpu, addr, EPT_R)){
		OKDEBUG("EPT_R set\n");
	}
	if (is_set_ept_page_flag(vcpu, addr, EPT_W)){
		OKDEBUG("EPT_W set\n");
	}
	if (is_set_ept_page_flag(vcpu, addr, EPT_X)){
		OKDEBUG("EPT_X set\n");
	}
}

static inline int is_user_space(unsigned long vaddr)
{
	return (vaddr <= USER_HI_MEM);
}

static inline int is_module_space (unsigned long vaddr)
{
	return (vaddr >= MODULES_VADDR && vaddr <= MODULES_END);
}

static inline int is_text_space (unsigned long vaddr)
{
	unsigned long text_start = PFN_ALIGN(_text);
	unsigned long text_end = PFN_ALIGN(&__stop___ex_table);
	return (vaddr >= text_start && vaddr <= text_end);
}

static inline int need_integrity_flag(unsigned long va, unsigned long s_flags)
{
	if ((is_module_space(va) | is_text_space(va)) &&
	    x_or_ro(s_flags)) {
		return 1;
	} else {
		return 0;
	}
}

static inline void set_clr_ok_tags(unsigned long gva, unsigned long *s_flags,
				 unsigned long *c_flags)
{
	/*
	 * Tags a physical memory region Text or Module RO
	 * if the current virtual address is in kernel text or module
	 * space and marked RO.
	 * ASSUMPTION: OK_DATA region is protected at initialization
         * and never changes: no pages removed or added.
         * So this will never tage anything as OK_DATA
	 */
	if ((is_text_space(gva)) && x_or_ro(*s_flags)) {
		*s_flags |= OK_TEXT;
		*c_flags |= OK_MOD | OK_DATA;
	} else if ((is_module_space(gva)) && x_or_ro(*s_flags)){
		*s_flags |= OK_MOD;
		*c_flags |= OK_TEXT | OK_DATA;
	} else {
		*c_flags |= (OK_FLAGS);
	}

}

static void flags_from_qual(unsigned long qual, unsigned long *s,
			    unsigned long *c)
{
	/*
	 * Note if EPT_W or EPT_X is set, then EPT_R must be set
	 * Otherwise we will get an EPT_Misconfiguration induced VMExit
	 */
	*s = 0;
	if (qual & EPT_R){
		*s |= EPT_R;
	}
	if (qual & EPT_W){
		*s |= EPT_W | EPT_R;
	}
	if (qual & EPT_X){
		*s |= EPT_X | EPT_R;
	}
	*c = ((~*s) & EPT_PERM_MASK);
}

static int grant_all(struct eptvc *e, int level)
{
	unsigned long s_flags, c_flags;
	c_flags = OK_FLAGS;
	s_flags = EPT_W | EPT_R | EPT_X;
	if(set_clr_ept_page_flags(e->vcpu, e->gpa, s_flags, c_flags, level)){
		return 1;
	} else {
		OKERR("set_clr_ept_page_flags failed.\n");
		BUG();
	}
	return 0;
}

/*
 * Handler for ept violations that are a result of access to protected pages
 */
int vmexit_protected_page(struct vmx_vcpu *vcpu)
{
	uid_t uid;
	pid_t pid;
	char *comm;
	unsigned long gp_addr = vmcs_readl(GUEST_PHYSICAL_ADDRESS);
	get_upc(&uid, &pid, &comm);

	if(ok_allow_protected_access(gp_addr)){
		(void)add_ept_page_perms(vcpu, gp_addr);
		OKDEBUG("Allow protected access for uid %d pid %d command %s\n",
			uid, pid, comm);
	} else {
		OKSEC("Deny protected access for uid %d pid %d command %s\n",
		      uid, pid, comm);
		/*
		 * Map in 'dummy' page for now  - need to be careful
		 * not to create another vulnerability.
		 */
		(void)remap_ept_page(vcpu, gp_addr,
				     ok_get_protected_dummy_paddr());
	}
	return 1;
}

/* 
 * Handler for ept violation that are a result of page walks or the
 * dirty bit being  set
 */
static int page_walk_ept_violation(struct eptvc *e)
{
	unsigned long s_flags, c_flags;
	if (is_set_ept_page_flag(e->vcpu, e->gpa, OK_FLAGS)) {
		OKSEC("Clearing OK_FLAGS, allocated to page tables\n");
	}
	flags_from_qual(e->qual, &s_flags, &c_flags);
	c_flags |= OK_FLAGS;
	if(set_clr_ept_page_flags(e->vcpu, e->gpa, s_flags, c_flags,
				  PG_LEVEL_NONE)){
		return 1;
	} else {
		OKERR("set_clr_ept_page_flags failed.\n");
		BUG();
	}
	return 0;
}

static int kro_userspace_eptv(struct eptvc *e, int level)
{
	unsigned long ktp, kmp, kdp, kva, set, clr, eprot, n_eprot, *epte;
	int l;
	pgprot_t p;
	ktp = ktext_page(e->vcpu, e->gpa);
	kmp = kmod_page(e->vcpu, e->gpa);
	kdp = kdata_page(e->vcpu, e->gpa);
	epte = ept_page_entry(e->vcpu, e->gpa);

	if (ktp || kmp) {
		OKERR("User space alias for kernel RO memory\n");
		BUG();
		return 0;
	} else if (kdp) {
		kva = kdp + (e->gpa - guest_physical_address(kdp, &l, &p));
		eprot = *epte & (EPT_W | EPT_R | EPT_X);
		ept_flags_from_qual(e->qual, &set, &clr);
		n_eprot = set | eprot;
		OKDEBUG("VDSO fix up for protected 4k page %#lx"
			" OK_DATA %d kernel va %#lx, user space va "
			"%#lx EPT exit qual %#lx, new EPT prot %#lx\n",
			e->gpa & ~(PAGESIZE - 1), (*epte & OK_DATA)?1:0,
			kva, e->gva, e->qual, n_eprot);
		if(!set_clr_ept_page_flags(e->vcpu, e->gpa, n_eprot, 0, level)) {
			OKERR("set_clr_ept_page_flags failed.\n");
			BUG();
			return 0;
		}
		add_fixup(e->gpa, n_eprot);
		return 1;
	} else {
		OKDEBUG("Protected 4k block %#lx released to user space"
			" OK_TEXT %d OK_MOD %d OK_DATA %d no longer mapped by "
			"kernel exit qual %#lx guest virtual %#lx\n",
			e->gpa & ~(PAGESIZE - 1), (*epte & OK_TEXT)?1:0,
			(*epte & OK_MOD)?1:0, (*epte & OK_DATA)?1:0, e->qual,
			e->gva);
		return grant_all(e, level);
	}
}

static int kro_mapped_eptv(struct eptvc *e, unsigned long ma, int level)
{
	/* if already mapped, it may be a legitimate patch, otherwise
	 * it's a security issue */

	unsigned long *epte, set, clr, eprot, n_eprot;
	uid_t uid;
	char *comm;
	struct patch_addr *p;

	epte = ept_page_entry(e->vcpu, e->gpa);
	eprot = *epte & (EPT_W | EPT_R | EPT_X);
	ept_flags_from_qual(e->qual, &set, &clr);
	p = find_patch_addr(&patch_addresses, e->gpa);
	uid = from_kuid(&init_user_ns, current_uid());
	comm = current->comm;
	/* New prots = guest prot + old prot */
	n_eprot = set | eprot;
	if (p)
		OKDEBUG("Patch of pa %#lx with EPT prot %#lx for %s. Alias"
			" for kernel protected code mapped at page %#lx being "
			"created at page %#lx for virtual address %#lx, "
			"new EPT prot %#lx, uid %d, command %s\n", e->gpa, eprot,
			p->tag, ma, e->gva & ~(PAGESIZE2M - 1), e->gva, n_eprot,
			uid, comm);
	else
		OKSEC("Physical address %#lx with EPT prot %#lx alias or change"
		      " for kernel protected code mapped at page %#lx being "
		      "created at page %#lx for virtual address %#lx, "
		      "new EPT prot %#lx, uid %d, command %s\n", e->gpa, eprot,
		      ma, e->gva & ~(PAGESIZE2M - 1), e->gva, n_eprot,
		      uid, comm);
	if(!set_clr_ept_page_flags(e->vcpu, e->gpa, n_eprot, 0, level)) {
		OKERR("set_clr_ept_page_flags failed.\n");
		BUG();
		return 0;
	}
	return 1;
}

/*
 * Handler for EPT violations on kernel RO memory we've previously marked
 * for protection with OK_FLAGS.
 * 
 * If the gva is kernel integrity memory, in an ideal world we
 * wouldn't need to change it. Unfortunately, sometimes aliases are
 * created. So we have to allow changes and log them.
 *
 */
static int kernel_ro_ept_violation(struct eptvc *e)
{
	unsigned long *epte, set, clr, eprot, ma;
	int level;
	pgprot_t prot;

	BUG_ON(!guest_physical_page_address(e->gva, &level, &prot));
	if (is_user_space(e->gva))
		return kro_userspace_eptv(e, level);

	if ((ma = kmapped_page(e->vcpu, e->gpa))) {
		return kro_mapped_eptv(e, ma, level);
	} else {
		epte = ept_page_entry(e->vcpu, e->gpa);
		eprot = *epte & (EPT_W | EPT_R | EPT_X);
		ept_flags_from_qual(e->qual, &set, &clr);

		set_clr_ok_tags(e->gva, &set, &clr);
		/* We need to fix by tracking release */
		if (set & EPT_X)
			OKSEC("New executable code added to kernel "
			      "Physical address %#lx with EPT prot %#lx no "
			      "longer at original mapping. New mapping created "
			      "at guest virtual %#lx, new EPT prot %#lx\n",
			      e->gpa, eprot, e->gva, set);
		else
			OKDEBUG("Physical address %#lx with EPT prot %#lx no "
				"longer at original mapping. New mapping created"
				" at guest virtual %#lx, new EPT prot %#lx"
				" OK_TEXT %d OK_MOD %d OK_DATA %d"
				" new mapping level %d""\n", e->gpa, eprot,
				e->gva, set, (*epte & OK_TEXT)?1:0,
				(*epte & OK_MOD)?1:0, (*epte & OK_DATA)?1:0,
				level);
		if(!set_clr_ept_page_flags(e->vcpu, e->gpa, set, clr, level)) {
			OKERR("set_clr_ept_page_flags failed.\n");
			BUG();
			return 0;
		}
	}
	return 1;
}

/*
 * This handles ept violations for module code which is not
 * already tagged and protected by OK_MOD tags Typically this
 * will happen if the process does an insmod Anything that was
 * already installed before the process is started will be
 * protected by OK_MOD tags
 */
int module_ept_violation(struct eptvc *e)
{
	int level;
	unsigned long s_flags, c_flags;
	pgprot_t prot;

	BUG_ON(!guest_physical_page_address(e->gva, &level, &prot));

	/* Get the protection flags to set on the EPT from
	 * the upper level page tables */
	ept_flags_from_qual(e->qual, &s_flags, &c_flags);
	set_clr_ok_tags(e->gva, &s_flags, &c_flags);
	if (set_clr_ept_page_flags(e->vcpu, e->gpa, s_flags, c_flags, level)) {
		if (s_flags & EPT_X) 
			OKSEC("New module code at pa %#lx va %#lx\n",
			      e->gpa, e->gva);
		return 1;
	} else {
		OKERR("set_clr_ept_page_flags failed.\n");
		BUG();
		return 0;
	}
}

/*
 * Handler for kernel memory ept violations for which physical
 * memory is not tagged for protection by OK_FLAGS
 * and is not in module memory range
 */
int kernel_ept_violation(struct eptvc *e)
{
	int level;
	unsigned long s_flags, c_flags;
	pgprot_t prot;
	
	BUG_ON(!guest_physical_page_address(e->gva, &level, &prot));
	ept_flags_from_qual(e->qual, &s_flags, &c_flags);
	set_clr_ok_tags(e->gva, &s_flags, &c_flags);
	if (set_clr_ept_page_flags(e->vcpu, e->gpa, s_flags, c_flags, level)) {
		if (s_flags & EPT_X) 
			OKSEC("New kernel code at pa %#lx va %#lx\n", e->gpa,
			      e->gva);
		return 1;
	} else {
		OKERR("set_clr_ept_page_flags failed.\n");
		BUG();
		return 0;
	}
}

static int vmx_handle_EPT_violation(struct vmx_vcpu *vcpu)
{
	/* Returns 1 if handled, 0 if not */
	struct eptvc e;
	int level;
	pgprot_t prot;

	vmx_get_cpu(vcpu);
	e.vcpu = vcpu;
	e.qual = vmcs_readl(EXIT_QUALIFICATION);
	e.gpa = vmcs_readl(GUEST_PHYSICAL_ADDRESS);
	e.gva = (u64)vmcs_readl(GUEST_LINEAR_ADDRESS);
	vmx_put_cpu(vcpu);

	/* Grant access to protected pages lazily */
	if(__ok_protected_phys_addr(e.gpa)){
		return vmexit_protected_page(vcpu);
	}

	/* Guest linear (virtual address) is valid */
	if(e.qual & EPT_GLV){
		/* 
		 * If EPT_LT is set, the violation was a result of a
		 * result of a translation of a linear address,
		 * otherwise it was a result of a page walk or update
		 * of access or dirty bit
		 */
		if (!(e.qual & EPT_LT)){
			return page_walk_ept_violation(&e);
		}
		if (is_set_ept_page_flag(e.vcpu, e.gpa, OK_FLAGS)){
			return kernel_ro_ept_violation(&e);
		} else if (is_module_space(e.gva)){
			return module_ept_violation(&e);
		} else if (is_user_space(e.gva)){
			BUG_ON(!guest_physical_page_address(e.gva, &level,
							    &prot));
			return grant_all(&e, level);

		} else {
			return kernel_ept_violation(&e);
		}
	}
	return 0;
}


/*
 * vmx_launch - the main loop for a cloned VMX okernel process (thread)
 */
int vmx_launch(unsigned int mode, unsigned int flags, struct nr_cloned_state *cloned_thread)
{
	/* Do we need to do anything about FPU state? */
	unsigned long rsp;
	unsigned long rbp;
	unsigned long new_rsp;
	unsigned long new_rbp;
	unsigned long current_frame_len;
	unsigned long r_stack_top;
	unsigned long in_use;
	unsigned int ret = 0;
	unsigned long c_rip;
	struct vmx_vcpu *vcpu;
//	struct vmx_vcpu *remote_vcpu;
	unsigned long saved_irqs_on;
	unsigned long k_stack;
	unsigned long qual;
#ifdef OKERNEL_DEBUG
	int orig_cpu;
#ifdef OKERNEL_DEBUG_FULL
	unsigned long nr_gs;
	unsigned long nr_fs;
	unsigned long event_type;
    u32 event_info;
	unsigned long fred = 7;
#endif
#endif
	unsigned long perms = 0;
#if !defined(CONFIG_THREAD_INFO_IN_TASK)
	struct thread_info *nr_ti;
#endif
#if defined(HPE_LOOP_DETECT)
	unsigned long last_time;
	unsigned long current_time;
	unsigned long vmexit_counter;
#endif

	if (in_atomic()) {
		OKWARN("!!!!!!in_atomic() true - preemption disabled!!!!!\n");
	}

	if(!cloned_thread)
		return -EINVAL;

	c_rip = cloned_thread->rip;

	OKDEBUG("c_rip: (#%#lx)\n", c_rip);

	vcpu = vmx_create_vcpu(cloned_thread);

	if (!vcpu)
		return -ENOMEM;

	OKDEBUG("created new VMX process context (VPID %d)\n", vcpu->vpid);

	//perms =  EPT_R | EPT_W | EPT_X | EPT_CACHE_2 | EPT_CACHE_3;
	/* Could make this non-X too */
	perms =  EPT_R | EPT_W | EPT_CACHE_2 | EPT_CACHE_3;

	if(!clone_kstack2(vcpu, perms)){
		printk(KERN_ERR "okernel: clone kstack failed.\n");
		return -ENOMEM;
	}

	/* To do: Need to take a copy of the orignal stack contents, restore when/if we leave */
	in_use = current_top_of_stack() - current_stack_pointer();

	k_stack = (unsigned long)current->stack;

	r_stack_top = k_stack + PAGE_SIZE;

        /* Check currently not using last page of stack otherwise we break */
	if((current_stack_pointer() & PAGE_MASK) == (r_stack_top & PAGE_SIZE)){
		OKERR("Process already using last page of kernel stack - can't continue.\n");
		printk(KERN_ERR "okernel: stack slide failed.\n");
		return -ENOMEM;
	}


	OKDEBUG("reset stack to top of bottom page for orig thread: in use (%lu) new top (%#lx)\n",
		in_use, r_stack_top);

	OKDEBUG("kernel thread_info (tsk->stack) vaddr (%#lx) paddr (%#lx) top of stack (%#lx)\n",
		k_stack, __pa(k_stack), current_top_of_stack());

	OKDEBUG("sizeof(struct thread_info) (%lu)\n", sizeof(struct thread_info));

	asm volatile ("mov %%rbp,%0" : "=rm" (rbp));
	OKDEBUG("original thread rbp currently  (%#lx)\n", rbp);
	asm volatile ("mov %%rsp,%0" : "=rm" (rsp));
	OKDEBUG("orginal thread rsp currently  (%#lx)\n", rsp);

	/*
	 * Ok we want to clone the stack contents from
	 * old rsp->old rbp so the local variables are still available
	 * to us
	 */
	current_frame_len = rbp - rsp;
	OKDEBUG("current stack from in use (%lu)\n", current_frame_len);

	new_rbp = r_stack_top;
	new_rsp = new_rbp - current_frame_len;
	memcpy((u64 *)new_rsp, (u64 *)rsp, current_frame_len);

	OKDEBUG("setting rsp to (%#lx) rbp to (%#lx)\n", new_rsp, new_rbp);
	asm volatile ("mov %0, %%rbp": : "r" (new_rbp));
	asm volatile ("mov %0, %%rsp": : "r" (new_rsp));

	BXMAGICBREAK;

	/* Check our stack manipulation & sliding - can we still access fred? */
#if defined(OKERNEL_DEBUG) && defined(OKERNEL_DEBUG_FULL)
	OKDEBUG("fred (%lu) address of fred (%#lx)\n", fred, (unsigned long)&fred);
	BXMAGICBREAK;
#endif
	vcpu->cloned_tsk = current;



	OKDEBUG("Before vmexit handling loop: in_atomic(): %d, irqs_disabled(): %d, pid: %d, name: %s\n",
		in_atomic(), irqs_disabled(), current->pid, current->comm);
	OKDEBUG("preempt_count (%d) rcu_preempt_depth (%d) cloned rflags (%lu)\n",
	       preempt_count(), rcu_preempt_depth(), cloned_thread->rflags);

	saved_irqs_on = (cloned_thread->rflags & RFLAGS_IF_BIT);

	OKDEBUG("saved_irqs_on (%#lx)\n", saved_irqs_on);

	kfree(cloned_thread);

	OKDEBUG("About to enter vmx handler while loop...\n");

#ifdef OKERNEL_DEBUG
	orig_cpu = smp_processor_id();
#endif

//#define COUNTER_MAX 10 //doesn't work with Docker at all
//#define COUNTER_MAX 25  // Unreliable with Docker
//#define COUNTER_MAX 50	  //works with Docker
#define COUNTER_MAX 100 //works with Docker
#define COUNTER_THRESHOLD 1000000 //approx 0.001s

#if defined(HPE_LOOP_DETECT)
	vmexit_counter = 0;
	last_time = rdtsc();
#endif


	while(1){
#if defined(HPE_LOOP_DETECT)

		if(vmexit_counter > COUNTER_MAX){
			/* Check rate we are generating vmexits - if more than threshold then exit. */
			current_time = rdtsc();
			/* Did we see more exits than we were expecting over a given time period? */
			if((current_time - last_time) < COUNTER_THRESHOLD){
				printk(KERN_ERR "vmexit threshold count exceeded - calling BUG()\n");
				BUG();
			}
			vmexit_counter = 0;
			last_time = current_time;
		}
#endif
		OKDEBUG("Entering vmexit handler loop...\n");

		vmx_get_cpu(vcpu);

		/* We may be on a different CPU now compared to when we exited the vmx_run_vcpu() call below.
		 * As a consequence we need to be careful with percpu data.
		 */

#if defined(OKERNEL_DEBUG) && defined(OKERNEL_DEBUG_FULL)
		nr_fs = vmcs_readl(GUEST_FS_BASE);
		nr_gs = vmcs_readl(GUEST_GS_BASE);
		OKDEBUG("Before run,  nr_fs=%#lx nr_gs=%#lx\n", nr_fs, nr_gs);
#endif

		OKDEBUG("About to call vmx_run_vcpu...\n");

#if defined(OKERNEL_DEBUG) && defined(OKERNEL_DEBUG_FULL)
		if(signal_pending(current)){
			OKDEBUG("sig pending before vmx_run_vcpu...\n");
		}
#endif

#if !defined(CONFIG_THREAD_INFO_IN_TASK)
		// cid: Need to think through some more...
		/* Push signals to be handled in NR mode */
		nr_ti = vcpu->cloned_thread_info;
		if(test_tsk_thread_flag(current, TIF_SIGPENDING)){
			OKDEBUG("Setting sig pending flag before vmx_run_vcpu()\n");
			set_ti_thread_flag(nr_ti, TIF_SIGPENDING);
			clear_tsk_thread_flag(current, TIF_SIGPENDING);
		}
#endif // CONFIG_THREAD_INFO_IN_TASK

#if defined(OKERNEL_DEBUG) && defined(OKERNEL_DEBUG_FULL)
                /* Are we about to inject an event to NR-mode? */
                event_info = vmcs_read32(VMCS_VMENTRY_INTR_INFO_FIELD);
                //event_err_code = vmcs_read32(VMCS_VMENTRY_EXCEPTION_ERR_CODE);
                //event_ilen = vmcs_read32(VMCS_VMENTRY_INSTRUCTION_LEN);

                event_type = (event_info >> 8) & 7;

                if(event_info & 0x80000000){
                        OKDEBUG("About to inject event on vmentry - event type (%#lx)\n", event_type);
                } else {
			OKDEBUG("Not about to inject event on vmentry.\n");
		}
#endif
                /* Use this instead of local_irq_disable() to save getting tangled in irq on/off tracing stuff. */
		native_irq_disable();

		//fast_path:
		
                /**************************** GO FOR IT ***************************/
		ret = vmx_run_vcpu(vcpu);
                /*************************** GONE FOR IT! *************************/

#if defined(HPE_LOOP_DETECT)
		vmexit_counter++;
#endif

		//if((ret == EXIT_REASON_VMCALL) && (vcpu->regs[VCPU_REGS_RAX] == VMCALL_DO_GET_CPU_HELPER)){
		//	/* Should always be called with interrupts disabled. */
		//	OKDEBUG("vmcall do_get_cpu_helper called.\n");
		//	remote_vcpu = (struct vmx_vcpu*)vcpu->regs[VCPU_REGS_RBX];
		//	vmcs_clear(remote_vcpu->vmcs);
		//	vmx_step_instruction();
		//	goto fast_path;
		//}

		if((vmcs_readl(GUEST_RFLAGS) & RFLAGS_IF_BIT)){
			native_irq_enable();
		}

		OKDEBUG("Returned from vmx_run_vcpu...handling exit condition...\n");

		if (ret == EXIT_REASON_VMCALL || ret == EXIT_REASON_CPUID){
			vmx_step_instruction();
		}

		if(*(vcpu->nr_stack_canary) != NR_STACK_END_MAGIC){
			printk(KERN_ERR "okernel: NR stack overflow detected.\n");
			BUG();
		}

		vmx_put_cpu(vcpu);

		if(ret==VMX_EXIT_REASONS_FAILED_VMENTRY){
			OKERR("vmentry failed (%#x)\n", ret);
			BUG();
		} else if((ret == EXIT_REASON_EXTERNAL_INTERRUPT)){
			/* We should be handling interrupts in NR-mode at the moment...*/
			printk(KERN_CRIT "vmexit on external interrupt.\n");
			BUG();
		} else if (ret == EXIT_REASON_CPUID){
			OKDEBUG("cpuid called.\n");
			vmx_handle_cpuid(vcpu);
		} else if (ret == EXIT_REASON_VMCALL){
			vmx_handle_vmcall(vcpu, saved_irqs_on);
		} else if (ret == EXIT_REASON_CR_ACCESS){
			if (!vmx_handle_CR_access(vcpu)){
				printk(KERN_CRIT "okernel: Unhandled CR access \n");
				BUG();
			}
		} else if (ret == EXIT_REASON_EPT_VIOLATION){
			if (!vmx_handle_EPT_violation(vcpu)){
				vmx_put_cpu(vcpu);
				printk(KERN_CRIT "okernel: Unhandled EPT Violation\n");
				BUG();
			}
		} else if (ret == EXIT_REASON_EPT_MISCONFIG){
			if (!vmx_handle_EPT_misconfig(vcpu)){
				printk(KERN_CRIT "okernel: Unhandle EPT Misconfig\n");
				BUG();
			}
		} else if (ret == EXIT_REASON_EXCEPTION_NMI) {
			if (!vmx_handle_exception_NMI(vcpu)){
				printk(KERN_CRIT "okernel: Unhandled NMI exception\n");
				BUG();
			}
		} else {
			vmx_get_cpu(vcpu);
			printk(KERN_CRIT "okernel: unhandled exit: reason %#x, "
			       "exit qualification %#lx\n",
			       ret, vmcs_readl(EXIT_QUALIFICATION));
			vmx_put_cpu(vcpu);
			BUG();
		}
		OKDEBUG("Done handling exit condition, looping...\n");
	}

	/* something went wrong - legitimate exit would have been through the
	 * do_exit() kernel path.  (Likely) this may (will) cause a problem if irqs were
	 * disabled / locks held, etc. in cloned thread on vmexit
	 * fault - we will have inconsistent kernel state we will need
	 * to sort out.
	 */
	qual = vmcs_readl(EXIT_QUALIFICATION);
	OKERR("leaving vmexit() loop (VPID %d) ret(%x) qual(%lx) "
	       "- trigger BUG() for now...\n", vcpu->vpid, ret, qual);
	vmx_destroy_vcpu(vcpu);
	BUG();
	return 0;
}



/*-------------------------------------------------------------------------------------*/
/*  end: vmx__launch releated code                                                     */
/*-------------------------------------------------------------------------------------*/

#if 0
KEEP
		if (!__thread_has_fpu(current))
			math_state_restore();
#endif




/**
 * __vmx_enable - low-level enable of VMX mode on the current CPU
 * @vmxon_buf: an opaque buffer for use as the VMXON region
 */
static __init int __vmx_enable(struct vmcs *vmxon_buf)
{
	u64 phys_addr = __pa(vmxon_buf);
	u64 old;
#if 0
	u64 test_bits;
#endif

	if (native_read_cr4() & X86_CR4_VMXE)
		return -EBUSY;


	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);
#if 1
	if(old & FEATURE_CONTROL_LOCKED){
		if(!(old & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)){
			printk(KERN_ERR "okernel: __vmx_enable vxmon disabled by FW.\n");
			return -1;
		}
	} else { /* try enable since feature not locked */
		OKDEBUG("__vmx_enable trying to enable VMXON.\n");
		old |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
		old |= FEATURE_CONTROL_LOCKED;
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old);
		rdmsrl(MSR_IA32_FEATURE_CONTROL, old);

		if(!(old & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)){
			printk(KERN_ERR "okernel: __vmx_enable failed to enable VXMON.\n");
			return -1;
		}
		OKDEBUG("__vmx_enable VMXON enabled.\n");
	}
#endif
#if 0
	test_bits = FEATURE_CONTROL_LOCKED;
	test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

	/*
	if (tboot_enabled())
		test_bits |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX;
	*/
	if ((old & test_bits) != test_bits) {
		/* enable and lock */
	        OKDEBUG("VMX_FEATURE_CONTROL NOT ENABLED - fixing...\n");
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | test_bits);
	}
#endif

	cr4_set_bits(X86_CR4_VMXE);
	__vmxon(phys_addr);
	vpid_sync_vcpu_global();
	ept_sync_global();
	return 0;
}



/**
 * vmx_enable - enables VMX mode on the current CPU
 * @unused: not used (required for on_each_cpu())
 *
 * Sets up necessary state for enable (e.g. a scratchpad for VMXON.)
 */
static __init void vmx_enable(void *unused)
{
	int ret;
	struct vmcs *vmxon_buf = __this_cpu_read(vmxarea);

	if ((ret = __vmx_enable(vmxon_buf)))
		goto failed;

	__this_cpu_write(vmx_enabled, 1);
	native_store_gdt(this_cpu_ptr(&host_gdt));

	printk(KERN_INFO "okernel vmx: VMX enabled on CPU %d\n",
	       raw_smp_processor_id());
	return;

failed:
	atomic_inc(&vmx_enable_failed);
	printk(KERN_ERR "okernel vmx: failed to enable VMX, err = %d\n", ret);
}

/**
 * vmx_disable - disables VMX mode on the current CPU
 */
static void vmx_disable(void *unused)
{
	if (__this_cpu_read(vmx_enabled)) {
		__vmxoff();
		cr4_clear_bits(X86_CR4_VMXE);
		__this_cpu_write(vmx_enabled, 0);
	}
}

/**
 * vmx_free_vmxon_areas - cleanup helper function to free all VMXON buffers
 */
static void vmx_free_vmxon_areas(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (per_cpu(vmxarea, cpu)) {
			vmx_free_vmcs(per_cpu(vmxarea, cpu));
			per_cpu(vmxarea, cpu) = NULL;
		}
	}
}


DEFINE_STATIC_KEY_FALSE(okernel_inited);

static bool need_okernel(void)
{
	return true;
}

static void init_okernel(void)
{
	/* safe to use page extensions after this */
	static_branch_enable(&okernel_inited);
}


struct page_ext_operations page_okernel_ops = {
	.need = need_okernel,
	.init = init_okernel,
};

/* Rudimentry 'protected' memory allocator  - use PG_protected flag for consistency checks */
void ok_init_protected_pages(void)
{
	int i;
	struct page *pg;
	struct page_ext *pg_ext;

	if(!static_branch_unlikely(&okernel_inited)){
		printk(KERN_ERR "okernel: ext page info not available - can't init protected pages.\n");
		return;
	}

	spin_lock(&ok_protected_pg_lock);
	pg = alloc_pages(GFP_KERNEL, order_base_2(OK_NR_PROTECTED_PAGES));
	if(!pg){
		printk(KERN_ERR "okernel: failed to allocate protected memory page array.\n");
		BUG();
	}
	/* Set PG_protected attribute on the pages */
	for(i = 0; i < OK_NR_PROTECTED_PAGES; i++){
		printk(KERN_INFO "okernel: protected page (%#lx) pfn (%#lx) vaddr (%#lx)\n",
		       (unsigned long)(pg + i), page_to_pfn(pg + i), (unsigned long)page_address(pg+i));
		pg_ext = lookup_page_ext(pg + i);
		if(!pg_ext){
			printk("okernel: pg_ext NULL\n");
			continue;
		}
		set_bit(PAGE_EXT_OK_PROTECTED, &pg_ext->flags);
		pg_ext->pid = 0;
	}
	ok_protected_pfn_start = page_to_pfn(pg);
	ok_protected_pfn_end = page_to_pfn(pg+OK_NR_PROTECTED_PAGES);
	ok_protected_page = pg;
	/* And the dummy page to redirect invalid access requests to */
	if(!(pg = alloc_page(GFP_KERNEL))){
		printk(KERN_ERR "okernel: failed to alloc dummy protected page.\n");
		BUG();
	}
	ok_protected_dummy_page = pg;
	memset(page_address(ok_protected_dummy_page), 0, PAGESIZE);
#ifdef OK_DEMO_HACK_MESSAGE
	memcpy(page_address(ok_protected_dummy_page), OK_DUMMY_TEXT, strlen(OK_DUMMY_TEXT)+1);
#endif
	spin_unlock(&ok_protected_pg_lock);
}

unsigned long ok_get_protected_dummy_paddr(void)
{

	return (page_to_phys(ok_protected_dummy_page));
}

void ok_release_protected_pages(void)
{
	struct page *pg;
	struct page_ext *pg_ext;
	int i;

	spin_lock(&ok_protected_pg_lock);
	pg = ok_protected_page;

	for(i = 0; i < OK_NR_PROTECTED_PAGES; i++){
		pg_ext = lookup_page_ext(pg + i);
		clear_bit(PAGE_EXT_OK_PROTECTED, &pg_ext->flags);
		pg_ext->pid = 0;
		__free_page(pg + i);
	}
	free_pages((unsigned long)page_address(ok_protected_page), order_base_2(OK_NR_PROTECTED_PAGES));
	ok_protected_page = NULL;
	ok_protected_pfn_start = 0;
	ok_protected_pfn_end   = 0;
	free_pages((unsigned long)page_address(ok_protected_dummy_page), 0);
	ok_protected_dummy_page = NULL;
	spin_unlock(&ok_protected_pg_lock);
	return;
}

struct page *ok_alloc_protected_page(void)
{
	int i;
	struct page *pg;
	struct page_ext *pg_ext;

	spin_lock(&ok_protected_pg_lock);
	i = find_first_zero_bit(ok_protected_pg_bitmap, OK_NR_PROTECTED_PAGES);
	if(i < OK_NR_PROTECTED_PAGES){
		pg = ok_protected_page+i;
		__set_bit(i, ok_protected_pg_bitmap);
		pg_ext = lookup_page_ext(pg);
		pg_ext->pid = current->pid;
	} else {
		printk(KERN_ERR "okernel: out of protected memory pages.\n");
		pg = NULL;
	}
	spin_unlock(&ok_protected_pg_lock);
	return pg;
}

bool __ok_protected_phys_addr(unsigned long paddr)
{
	unsigned long pfn;

	pfn = (paddr >> PAGE_SHIFT);

	if((pfn < ok_protected_pfn_start) || (pfn > ok_protected_pfn_end)){
		return false;
	}
	return true;
}

int __ok_free_protected_page(struct page *pg)
{
	int i;
	unsigned long pfn;
	int ret = 0;
	struct page_ext *pg_ext;


	pfn = page_to_pfn(pg);

	if((pfn < ok_protected_pfn_start) || (pfn > ok_protected_pfn_end)){
		printk(KERN_ERR "okernel: tried to free invalid protected page (%#lx) pfn (%#lx) vaddr (%#lx)\n",
		       (unsigned long)(pg), page_to_pfn(pg), (unsigned long)page_address(pg));
		ret = 1;
		goto fail;
	}

	i = (pfn - ok_protected_pfn_start);
	memset(page_address(pg), 0, PAGE_SIZE);
	__clear_bit(i, ok_protected_pg_bitmap);
	printk(KERN_ERR "okernel: free protected page (%#lx) pfn (%#lx) vaddr (%#lx) index:=(%d)\n",
	       (unsigned long)(pg), page_to_pfn(pg),
	       (unsigned long)page_address(pg), i);
	pg_ext = lookup_page_ext(pg);
	pg_ext->pid = 0;
fail:
	return ret;
}

int ok_free_protected_page(struct page *pg)
{
	int ret;

	spin_lock(&ok_protected_pg_lock);

	ret = __ok_free_protected_page(pg);

	spin_unlock(&ok_protected_pg_lock);
	return ret;
}

void ok_free_protected_page_by_id(pid_t pid)
{
	/*
	   (in-efficiently) scan protected pages and free ones allocated to the given (p)id
	   Will likely use container id + refcnt in future for container wide
	   allocations. Probably better to maintain a per-id hash-map / list of allocations.
	*/

	int i;
	struct page_ext *pg_ext;
	struct page *pg;

	if(!okernel_enabled){
		return;
	}

	spin_lock(&ok_protected_pg_lock);
	pg = ok_protected_page;

	for(i = 0; i < OK_NR_PROTECTED_PAGES; i++){
		if((pg_ext = lookup_page_ext(pg + i))){
			if(pg_ext->pid == pid){
				__ok_free_protected_page(pg+i);
			}
		} else {
			continue;
		}
	}
	spin_unlock(&ok_protected_pg_lock);
}

bool ok_allow_protected_access(unsigned long phys_addr)
{
	/* Just do pid check for now - expand into container id check, etc. later */
	struct page *pg;
	struct page_ext *pg_ext;

	pg = pfn_to_page(phys_addr >> PAGE_SHIFT);
	pg_ext = lookup_page_ext(pg);
	if(pg_ext->pid == current->pid){
		return true;
	}
	return false;
}

static void __init printk_constants(void)
{
	int l;
	pgprot_t p;
	unsigned long mod_start = (unsigned long)PFN_ALIGN(MODULES_VADDR);
	unsigned long mod_end = (unsigned long)PFN_ALIGN(MODULES_END);

	printk(KERN_INFO "okernel _text %#lx\n", (unsigned long)_text);
	printk(KERN_INFO "okernel &__stop___ex_table %#lx\n",
	       (unsigned long)&__stop___ex_table);
	printk(KERN_INFO "okernel &__end_rodata_hpage_align %#lx\n",
	       (unsigned long) &__end_rodata_hpage_align);
	printk(KERN_INFO "okernel &__start_rodata va %#lx pa %#lx\n",
	       (unsigned long)&__start_rodata,
	       guest_physical_address((unsigned long)&__start_rodata, &l, &p));
	printk(KERN_INFO "okernel &__end_rodata va %#lx pa %#lx\n",
	       (unsigned long) &__end_rodata,
	       guest_physical_address((unsigned long)&__end_rodata, &l, &p));
	printk(KERN_INFO "okernel __PHYSICAL_MASK is %#lx\n",
	       (unsigned long) __PHYSICAL_MASK);
	printk(KERN_INFO "okernel ~(PAGE_SIZE-1) %#lx\n",
	       (unsigned long) ~(PAGE_SIZE-1));
	printk(KERN_INFO "okernel ~(PAGESIZE2M-1) %#lx\n",
	       (unsigned long) ~(PAGESIZE2M-1));
	printk(KERN_INFO "okernel module space start va %#lx pa %#lx\n",
	       mod_start, guest_physical_address(mod_start, &l, &p));
	printk(KERN_INFO "okernel module space end va %#lx pa %#lx\n",
	       mod_end, guest_physical_address(mod_end, &l, &p));
	printk(KERN_INFO "okernel FIXADDR_TOP %#lx\n", FIXADDR_TOP);
	printk(KERN_INFO "okernel VSYSCALL_PAGE %#x\n", VSYSCALL_PAGE);
	printk(KERN_INFO "okernel FIX_TEXT_POKE0 %#lx\n",
	       fix_to_virt(FIX_TEXT_POKE0));
}

static __init struct static_key *entry_key(struct jump_entry *entry)
{
	return (struct static_key *)((unsigned long)entry->key & ~1UL);
}

static void __init add_patch_addr(struct static_key *key, char *tag)
{
	int level;
	unsigned long pa;
	pgprot_t prot;
	struct patch_addr *p_addr;
	struct jump_entry *stop = __stop___jump_table;
	struct jump_entry *entry = (struct jump_entry *)
		(key->type & ~JUMP_TYPE_MASK);
	if (!entry)
		return;
	for (; (entry < stop) && (entry_key(entry) == key); entry++) {
		pa = guest_physical_address(entry->code, &level, &prot);
		if (!(p_addr = mk_patch_addr(pa, tag))) {
			printk(KERN_CRIT "okernel add_patch_addr no memory?\n");
			return;
		}
		if (!insert_patch_addr(&patch_addresses, p_addr))
			printk(KERN_INFO "okernel duplicate patch addr %#lx\n",
			       pa);
	}
}

static void __init dump_patch_addr(void)
{
	struct rb_node *node;
	struct patch_addr *p;
	printk(KERN_INFO "Dumping okernel RB patch address tree\n");
	for (node = rb_first(&patch_addresses); node; node = rb_next(node)) {
		p = rb_entry(node, struct patch_addr, node);
		if (p)
			printk("pa %#lx tag %s\n", p->pa, p->tag);
	}
}

static void patch_addr_from_keys(void)
{
	int ssid;
	struct key_tag *p = static_key_tags;
	for(; p->key != NULL; p++)
		add_patch_addr(p->key, p->tag);
	for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT; (ssid)++) {
		add_patch_addr(&(ok_cgrp_subsys_enabled_key[ssid]->key),
			       "cgroups");
		add_patch_addr(&(ok_cgrp_subsys_on_dfl_key[ssid]->key),
			       "cgroups_dfl");
	}
}

int __init vmx_init(void)
{
	int r, cpu;

        if (!cpu_has_vmx()) {
		printk(KERN_ERR "vmx: CPU does not support VT-x\n");
		return -EIO;
	}

	if (setup_vmcs_config(&vmcs_config) < 0)
		return -EIO;

	if (!cpu_has_vmx_vpid()) {
		printk(KERN_ERR "vmx: CPU is missing required feature 'VPID'\n");
		return -EIO;
	}

	if (!cpu_has_vmx_ept()) {
		printk(KERN_ERR "vmx: CPU is missing required feature 'EPT'\n");
		return -EIO;
	}

	if (!vmx_capability.has_load_efer) {
		printk(KERN_ERR "vmx: ability to load EFER register is required\n");
		return -EIO;
	}

	if (cpu_has_vmx_ept_mode_ctl()){
		printk(KERN_INFO "okernel: Mode-based execute control for EPT available\n");
	} else {
		printk(KERN_INFO "okernel: Mode-based execute control for EPT unavailable\n");
	}


	/* Don't exit on any MSR accesses */
	msr_bitmap = (unsigned long *)__get_free_page(GFP_KERNEL);

	if (!msr_bitmap) {
                return -ENOMEM;
        }

	memset(msr_bitmap, 0x0, PAGE_SIZE);

        set_bit(0, vmx_vpid_bitmap); /* 0 is reserved for host */


	/* Establish physical memory / EPT mapping limits */
	max_phys_mem = e820_end_paddr(MAXMEM);

	if(max_phys_mem > (1UL << 32)){
		ept_limit = max_phys_mem;
		ept_no_cache_start = (e820__end_of_low_ram_pfn() * PAGE_SIZE);
	} else {
		ept_limit = (1UL << 32);
		ept_no_cache_start = max_phys_mem;
	}


	for_each_possible_cpu(cpu) {
		struct vmcs *vmxon_buf;

		vmxon_buf = __vmx_alloc_vmcs(cpu);
		if (!vmxon_buf) {
			vmx_free_vmxon_areas();
			return -ENOMEM;
		}

		per_cpu(vmxarea, cpu) = vmxon_buf;
	}

	atomic_set(&vmx_enable_failed, 0);
	if (on_each_cpu(vmx_enable, NULL, 1)) {
		printk(KERN_ERR "vmx: timeout waiting for VMX mode enable.\n");
		r = -EIO;
		goto failed1; /* sadly we can't totally recover */
	}

	if (atomic_read(&vmx_enable_failed)) {
		r = -EBUSY;
		goto failed2;
	}

	in_vmx_nr_mode = real_in_vmx_nr_mode;

	(void)ok_init_protected_pages();

	if ((r = okmm_init())) {
		goto failed2;
	}
	printk_constants();
	patch_addr_from_keys();
	dump_patch_addr();
	return 0;


failed2:
	on_each_cpu(vmx_disable, NULL, 1);
failed1:
	vmx_free_vmxon_areas();
	return r;
}

EXPORT_SYMBOL(vmcall);
