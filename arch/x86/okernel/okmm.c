/*
 * Author: Nigel Edwards, 2017
 */

#include <linux/init.h>
#include <linux/okernel.h>
#include <linux/percpu.h>
#include <linux/slab.h>

#include "constants2.h"
#include "vmx.h"
#include "okmm.h"

/*
 * A cache of page table entries.
 *
 * Sometimes when we get EPT violations from a process in NR
 * (Non-Root) mode we need to create new page table entries during
 * handling of the VMEXIT while running in R (Root) mode. However,
 * calling kmalloc() in R mode during handling of a VMEXIT is
 * dangerous: we may be holding a lock via kmalloc() in NR mode,
 * trying to claim the same lock again in R mode will cause deadlock.
 * This is reasonably likely during EPT violations, caused by NR
 * allocation of memory. So we need cache of entries.
 *
 * We have a small percpu cache and a global cache. Only accesses to the
 * global cache require locks.
 *
 * Only call okmm_refill, which may call kmalloc indirectly, before
 * entering NR mode for the first time. So do it during creation of
 * the vcpu structure, before starting in NR mode. It should never be
 * called during a VMEXIT.
 *
 * A futher complication is that we can never be sure whether or not
 * okmm_refill will be called with interrupts disabled or not.  So to
 * be safe we need to use spin_lock_irqsave and
 * spin_lock_irqrestore. Otherwise the following deadlock scenario is
 * possible
 *
 *  CPU(0)                        CPU(1)
 *  okmm_lock                     lockA
 *    <interrupt>                 okmm_lock
 *       lockA
 *
 * Also will need percpu list pairs and to embrach the SMP locking strategy
 * used by the slab: see comments on "SMP synchronization" in ./mm/slab.c
 * Disable local interrupts and therefore no locking needed for per-cpu
 * lists.
 */

static DEFINE_PER_CPU(struct ok_mm_cache, ok_cache);
static struct ok_mm_cache gc; /* global backing cache*/
static DEFINE_SPINLOCK(okmm_lock);
static int refill_in_progress = 0;

static atomic64_t refill_needed = ATOMIC64_INIT(0);
/* 1 : gc_refill needed */

#ifdef OKMM_DEBUG
static atomic64_t percpu_cache_fills = ATOMIC64_INIT(0);
static atomic64_t gc_cache_fills = ATOMIC64_INIT(0);
static atomic64_t gc_refill_calls = ATOMIC64_INIT(0);


static inline void kern_mess(int n, int lw, int id)
{
	long p = atomic64_read(&percpu_cache_fills);
	long g = atomic64_read(&gc_cache_fills);
	long c = atomic64_read(&gc_refill_calls);
	
	printk(KERN_INFO "cpu(%d) pid(%d): okmm %d entries:%d low water:%d, %ld"
	       " gc cache refills %ld percpu cache refills %ld gc refill calls",
	       raw_smp_processor_id(), current->pid, id, n, lw, g, p, c);
}

static void do_metrics(struct ok_mm_cache *c)
{
	/* Output a message every max_count calls regardless of low_water val*/
	static const int max_count = 10000;
	c->ticks++;
	if (c->ticks > max_count || c->navailable < c->low_water) {
		if (c->ticks > max_count)
			c->ticks = 0;
		if (c->navailable < c->low_water)
			c->low_water = c->navailable;
		kern_mess(c->nentries, c->low_water, c->cpu);
	}
}

#define printk_metrics(c) do_metrics(c)
#define inc_metric(x) atomic64_inc(&(x))

#else

#define printk_metrics(c) do {} while(0)
#define inc_metric(x) do {} while(0)

#endif /* OKMM_DEBUG */

static struct okmm_ce *make_entry(void)
{
	struct okmm_ce *e;
	struct ept_pt_list *ept;
	pt_page *pt;

	e = (struct okmm_ce *) kmalloc(sizeof(*e), GFP_KERNEL);
	ept = (struct ept_pt_list*) kmalloc(sizeof(*ept), GFP_KERNEL);
	pt   = (pt_page*)kmalloc(sizeof(*pt), GFP_KERNEL);
	if (!e | !ept | !pt ){
		return 0;
	}
	if(!(vt_alloc_page((void**)&pt[0].virt, &pt[0].phys))){
		return 0;
	}
	e->epte = ept;
	e->pt = pt;
	INIT_LIST_HEAD(&e->list);
	return e;

}

static void make_entries(struct okmm_ce *extra, int m)
{
	int i;
	struct okmm_ce *e;

	for(i = 0; i < m; i++) {
		if (!(e = make_entry())){
			printk(KERN_ERR "okmm add_entries out of memory?\n");
			break;
		}
		list_add(&e->list, &extra->list);
	}
}

static struct okmm_ce * make_refills(int n) {
	struct okmm_ce *refills;
	struct ept_pt_list *ept;
	pt_page *pt;
	int i;
	
	refills = (struct okmm_ce *)kmalloc((sizeof(*refills) * n), GFP_KERNEL);
	if (!refills){
		return 0;
	}

	for (i = 0; i < n; i++){
		ept = (struct ept_pt_list*) kmalloc(sizeof(*ept), GFP_KERNEL);
		pt   = (pt_page*)kmalloc(sizeof(*pt), GFP_KERNEL);
		if (!ept | !pt ){
			return 0;
		}
		if(!(vt_alloc_page((void**)&pt[0].virt, &pt[0].phys))){
			return 0;
		}
		refills[i].epte = ept;
		refills[i].pt = pt;
	}
	return refills;
}

static void do_refill(struct okmm_ce *refills, int n)
{
	int i;
	struct okmm_ce *e;
	
	for (i = 0; i < n; i++){
		BUG_ON(list_empty(&gc.used.list));
		e = list_first_entry(&gc.used.list, struct okmm_ce, list);
		e->epte = refills[i].epte;
		e->pt = refills[i].pt;
		list_move(&e->list, &gc.available.list);
	}
	return;
}

static int do_new(struct okmm_ce *new_entries)
{
	struct okmm_ce *e, *t;
	int i = 0;
	
	list_for_each_entry_safe(e, t, &new_entries->list, list){
		list_move(&e->list, &gc.available.list);
		i++;
	}
	return i;
}

/*
 * This gets called each time a process is started before it ever goes
 * into NR mode. It only fills the cache if it is needed. A refill is
 * needed of a percpu cache has previouly been refilled from the
 * global cache gc.
 */
static int gc_refill(void)
{
	int n, m;
	unsigned long flags;
	struct okmm_ce new_entries;
	struct okmm_ce *refills;

	inc_metric(gc_refill_calls);
	if (!atomic64_dec_and_test(&refill_needed)) {
		return 0;
	}

	spin_lock_irqsave(&okmm_lock, flags);
	if (refill_in_progress) {
		spin_unlock_irqrestore(&okmm_lock, flags);
		HLOG("Lock release refresh in progress\n");
		return 0;
	}
	refill_in_progress = 1;
	inc_metric(gc_cache_fills);
	printk_metrics(&gc);
	n = gc.nentries - gc.navailable;
	m = (gc.navailable < GC_N_MIN) ? GC_STEP : 0;
	spin_unlock_irqrestore(&okmm_lock, flags);

	INIT_LIST_HEAD(&new_entries.list);
	make_entries(&new_entries, m);
	if (!(refills = make_refills(n))) {
		return -ENOMEM;
	}

	spin_lock_irqsave(&okmm_lock, flags);
	do_refill(refills, n);
	m = do_new(&new_entries);

	gc.navailable += n + m;
	gc.nentries += m;
	gc.low_water += m;
	refill_in_progress = 0;
	spin_unlock_irqrestore(&okmm_lock, flags);

	kfree(refills);
	return 0;
}

int static percpu_refill(struct ok_mm_cache *c)
{
	unsigned long flags;
	struct okmm_ce *e, *f;

	inc_metric(percpu_cache_fills);
	spin_lock_irqsave(&okmm_lock, flags);
	for(; (c->navailable < c->nentries) && (gc.navailable > 0);
	    c->navailable++, gc.navailable--){
		BUG_ON(list_empty(&c->used.list)
		       || list_empty(&gc.available.list));
		e = list_first_entry(&c->used.list,
				     struct okmm_ce, list);
		f = list_first_entry(&gc.available.list,
				     struct okmm_ce, list);
		e->epte = f->epte;
		e->pt = f->pt;
		list_move(&e->list, &c->available.list);
		list_move(&f->list, &gc.used.list);
	}
	HLOG("Setting refill needed\n");
	atomic64_set(&refill_needed, (long) 1);
	spin_unlock_irqrestore(&okmm_lock, flags);
	if (c->navailable <= 0) {
		return -ENOMEM;
	}
	return 0;
}

int okmm_refill(void)
{
	return gc_refill();
}

void okmm_get_ce(struct ept_pt_list **epte, pt_page **pt)
{
	struct ok_mm_cache *c;
	struct okmm_ce *e;

	c = get_cpu_ptr(&ok_cache);
	/* If it's empty try to refill it from the global cache*/
	if (!(list_empty(&c->available.list)) || (percpu_refill(c) >= 0)){
		c->navailable--;
		BUG_ON(list_empty(&c->available.list));
		e = list_first_entry(&c->available.list,
				     struct okmm_ce, list);
		*epte = e->epte;
		*pt = e->pt;
		list_move(&e->list, &c->used.list);
	} else {
		*epte = 0;
		*pt = 0;
	}
	put_cpu_ptr(c);
}

int __init init_cache (struct ok_mm_cache *c, int cpu)
{
	INIT_LIST_HEAD(&c->available.list);
	INIT_LIST_HEAD(&c->used.list);
	c->nentries = 0;
	c->navailable = 0;
	c->low_water = 0;
	c->ticks = 0;
	c->cpu = cpu;
	return 0;
}

int __init fill_cache (struct ok_mm_cache *c, int n)
{
	int i;
	struct okmm_ce *e;

	for(i = 0; i < n; i++){
		if (!(e = make_entry())){
			return -ENOMEM;
		}
		list_add(&e->list, &c->available.list);
	}
	c->nentries = n;
	c->navailable = n;
	c->low_water = n;
	return 0;
}

int __init okmm_init(void)
{
	/* Returns Null if successful*/
	int i;
	int cpu;
	int n;
	int ret;
	struct ok_mm_cache *c;

	printk(KERN_ERR "Initializing okmm_cache.\n");

	for_each_possible_cpu(cpu){
		c = per_cpu_ptr(&ok_cache, cpu);
		if ((ret = init_cache(c, cpu)) < 0){
			return ret;
		}
	}
	if ((ret = init_cache(&gc, OKMM_GC_CPU_ID)) < 0){
		return ret;
	}
	
	i = 0;
	for_each_online_cpu(cpu){
		c = per_cpu_ptr(&ok_cache, cpu);
		if ((ret = fill_cache(c, OKMM_N_PERCPU)) < 0){
			return ret;
		}
		i++;
	}

	n = OKMM_N_PERCPU * (i + 1);
	printk(KERN_INFO "okmm_init %d CPUs, percpu cache size %d, global %d\n",
	       i, OKMM_N_PERCPU, n);

	return fill_cache(&gc, n);
}
