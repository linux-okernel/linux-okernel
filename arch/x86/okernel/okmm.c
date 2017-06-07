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
 * Only call okmm_refresh_pt_cache, which may call kmalloc, before
 * entering NR mode for the first time. So do it during creation of
 * the vcpu structure, before starting in NR mode. It should never be
 * called during a VMEXIT.
 *
 * A futher complication is that we can never be sure whether or not
 * okmm_refresh_pt_cache will be called with interrupts disabled or
 * not.  So to be safe we need to use spin_lock_irqsave and
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
static int refresh_in_progress = 0;

static atomic64_t refresh_needed = ATOMIC64_INIT(0);
/* 1 : gc_refresh needed */

static atomic64_t percpu_cache_fill = ATOMIC64_INIT(0);
static atomic64_t gc_cache_fill = ATOMIC64_INIT(0);
static atomic64_t gc_refresh_calls = ATOMIC64_INIT(0);

static inline void kern_mess(int n, int lw, char *l, int id)
{
	long p = atomic64_read(&percpu_cache_fill);
	long g = atomic64_read(&gc_cache_fill);
	long c = atomic64_read(&gc_refresh_calls);
	
	printk(KERN_ERR "cpu(%d) pid(%d): okmm %s:%d entries:%d low water:%d"
	       " percpu cache fill %ld  gc cache fill %ld refresh calls %ld",
	       raw_smp_processor_id(), current->pid, l, id, n, lw, p, g, c);
}

static void okmm_metrics(struct ok_mm_cache *c, char *level)
{
	/* Output a message every max_count calls regardless of low_water val*/
	static const int max_count = 10000;
	c->ticks++;
	if (c->ticks > max_count || c->navailable < c->low_water) {
		if (c->ticks > max_count)
			c->ticks = 0;
		if (c->navailable < c->low_water)
			c->low_water = c->navailable;
		kern_mess(c->nentries, c->low_water, level, c->id);
	}
}

static struct ok_pt_cache_entry *make_entry(void)
{
	struct ok_pt_cache_entry *e;
	struct ept_pt_list *ept;
	pt_page *pt;

	e = (struct ok_pt_cache_entry *) kmalloc(sizeof(*e), GFP_KERNEL);
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

void add_entries(struct ok_pt_cache_entry *extra, int m)
{
	int i;
	struct ok_pt_cache_entry *e;

	for(i = 0; i < m; i++) {
		if (!(e = make_entry())){
			printk(KERN_ERR "okmm add_entries out of memory?\n");
			break;
		}
		list_add(&e->list, &extra->list);
	}
}

int alloc_entries(struct ept_pt_list **epta, pt_page **pta, int n) {
	struct ept_pt_list *ept;
	pt_page *pt;
	int i;

	for (i = 0; i < n; i++){
		ept = (struct ept_pt_list*) kmalloc(sizeof(*ept), GFP_KERNEL);
		pt   = (pt_page*)kmalloc(sizeof(*pt), GFP_KERNEL);
		if (!ept | !pt ){
			return -ENOMEM;
		}
		if(!(vt_alloc_page((void**)&pt[0].virt, &pt[0].phys))){
			return -ENOMEM;
		}
		epta[i] = ept;
		pta[i] = pt;
	}
	return 0;
}

static int gc_refresh(void)
{
	struct ept_pt_list **epta;
	pt_page **pta;
	int i, n, m;
	unsigned long flags;
	struct ok_pt_cache_entry grow;
	struct ok_pt_cache_entry *e, *t;

	atomic64_inc(&gc_refresh_calls);
	INIT_LIST_HEAD(&grow.list);
	if (!atomic64_dec_and_test(&refresh_needed)) {
		return 0;
	}
	HLOG("Trying to get lock for refresh\n");
	spin_lock_irqsave(&okmm_lock, flags);
	if (refresh_in_progress) {
		spin_unlock_irqrestore(&okmm_lock, flags);
		HLOG("Lock release refresh in progress\n");
		return 0;
	}
	refresh_in_progress = 1;
	HLOG("Doing refresh\n");
	okmm_metrics(&gc, "global");
	n = gc.nentries - gc.navailable;
	if (gc.navailable < GC_MIN) {
		m = GC_STEP;
	} else {
		m = 0;
	}
	spin_unlock_irqrestore(&okmm_lock, flags);
	add_entries(&grow, m);

	epta = (struct ept_pt_list **) kmalloc((sizeof(*epta) * n), GFP_KERNEL);
	pta = (pt_page **) kmalloc((sizeof(*pta) * n), GFP_KERNEL);
	if (!epta || !pta) {
		return -ENOMEM;
	}
	if (alloc_entries(epta, pta, n) < 0) {
		return -ENOMEM;
	}

	spin_lock_irqsave(&okmm_lock, flags);
	for (i = 0; i < n; i++){
		BUG_ON(list_empty(&gc.used.list));
		e = list_first_entry(&gc.used.list, struct ok_pt_cache_entry, list);
		e->epte = epta[i];
		e->pt = pta[i];
		list_move(&e->list, &gc.available.list);
	}
	m = 0;
	list_for_each_entry_safe(e, t, &grow.list, list){
		list_move(&e->list, &gc.available.list);
		m++;
	}
	gc.navailable += n + m;
	gc.nentries += m;
	gc.low_water += m;
	atomic64_inc(&gc_cache_fill);
	refresh_in_progress = 0;
	spin_unlock_irqrestore(&okmm_lock, flags);

	kfree(epta);
	kfree(pta);
	return 0;
}

int static do_refresh(struct ok_mm_cache *c)
{
	unsigned long flags;
	struct ok_pt_cache_entry *e, *f;
	spin_lock_irqsave(&okmm_lock, flags);
	for(; (c->navailable < c->nentries) && (gc.navailable > 0);
	    c->navailable++, gc.navailable--){
		BUG_ON(list_empty(&c->used.list)
		       || list_empty(&gc.available.list));
		e = list_first_entry(&c->used.list,
				     struct ok_pt_cache_entry, list);
		f = list_first_entry(&gc.available.list,
				     struct ok_pt_cache_entry, list);
		e->epte = f->epte;
		e->pt = f->pt;
		list_move(&e->list, &c->available.list);
		list_move(&f->list, &gc.used.list);
	}
	HLOG("Setting refresh needed\n");
	atomic64_set(&refresh_needed, (long) 1);
	spin_unlock_irqrestore(&okmm_lock, flags);
	if (c->navailable <= 0) {
		return -ENOMEM;
	}
	return 0;
}

int static do_inc_refresh(struct ok_mm_cache *c)
{
	atomic64_inc(&percpu_cache_fill);
	return do_refresh(c);
}

int okmm_refresh_pt_cache(void)
{
	/*
	int ret;
	struct ok_mm_cache *c;

	c = get_cpu_ptr(&ok_cache);
	okmm_metrics(c, "percpu");
	ret = do_refresh(c);
	put_cpu_ptr(c);
	if (ret < 0) {
		printk(KERN_ERR "okmm_refresh_pt_cache memory exhaustion?\n");
	}
	*/
	return gc_refresh();
}

void okmm_get_ptce(struct ept_pt_list **epte, pt_page **pt)
{
	struct ok_mm_cache *c;
	struct ok_pt_cache_entry *e;

	c = get_cpu_ptr(&ok_cache);
	/* If it's empty try to refresh it from the global cache*/
	if (!(list_empty(&c->available.list)) || (do_inc_refresh(c) >= 0)){
		c->navailable--;
		BUG_ON(list_empty(&c->available.list));
		e = list_first_entry(&c->available.list,
				     struct ok_pt_cache_entry, list);
		*epte = e->epte;
		*pt = e->pt;
		list_move(&e->list, &c->used.list);
	} else {
		*epte = 0;
		*pt = 0;
	}
	put_cpu_ptr(c);
}

int init_cache (struct ok_mm_cache *c, int n, int id)
{
	int i;
	struct ok_pt_cache_entry *e;

	INIT_LIST_HEAD(&c->available.list);
	INIT_LIST_HEAD(&c->used.list);
	for(i = 0; i < n; i++){
		if (!(e = make_entry())){
			return -ENOMEM;
		}
		list_add(&e->list, &c->available.list);
	}
	c->nentries = n;
	c->navailable = n;
	c->low_water = n;
	c->ticks = 0;
	c->id = id;
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
	/*
	n = OKMM_INIT_NR / nr_cpu_ids;
	if (n < OKMM_MIN_PERCPU) {
		n = OKMM_MIN_PERCPU;
	}
	*/
	i = 0;
	for_each_possible_cpu(cpu){
		c = per_cpu_ptr(&ok_cache, cpu);
		if ((ret = init_cache(c, OKMM_PERCPU, cpu)) < 0){
			return ret;
		}
		i++;
	}
	printk(KERN_ERR "okmm_init nr_cpu_ids: %d; number cpus found: %d\n\n",
	       nr_cpu_ids, i);

	n = (OKMM_PERCPU * nr_cpu_ids) * 2;
	printk(KERN_ERR "okmm_init percpu cache size: %d, global:%d\n",
	       OKMM_PERCPU, n);


	/* Avoid exhaustion  by adding an extra OKMM_PERCPU*/
	return init_cache(&gc, n /*OKMM_INIT_NR*/, 0);
}
