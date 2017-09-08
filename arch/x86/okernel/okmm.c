/*
 * Author: Nigel Edwards, 2017
 */

#include <linux/freezer.h>
#include <linux/init.h>
#include <linux/kthread.h>
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
 * global cache require locks. The percup caches are filled on demand
 * from the global cache. Each percpu fill wakes an allocator thread
 * which tops up the global cache
 *
 * A futher complication is that we can never be sure whether or not
 * okmm_get_ce will be called with interrupts disabled or not.  So to
 * be safe okmm_lock must be locked with spin_lock_irqrestore. Otherwise
 * the following deadlock scenario is possible when okmm_get_ce
 * triggers a percpu cache fill and needs to get okmm_lock
 *
 *  CPU(0)                        CPU(1)
 *  okmm_lock                     lockA
 *    <interrupt>                 okmm_lock
 *       lockA
 *
 * Locks are only needed when the global backing cache gc is being
 * accessed. Also note since kmalloc() can call functions which sleep,
 * we release the lock before calling kmalloc.
 *
 * TODO: Make the global cache a percpu backing cache and create a
 * percpu allocator thread. May improve performance somewhat on
 * large multi-processor machines.
 *
 */

static struct task_struct *okmm_allocator_th;
static DECLARE_WAIT_QUEUE_HEAD(okmm_refill_needed);

static DEFINE_PER_CPU(struct ok_mm_cache, ok_cache);
static struct ok_mm_cache gc; /* global backing cache*/
static DEFINE_SPINLOCK(okmm_lock);

static atomic64_t nrefills_needed = ATOMIC64_INIT(0);
/* number of : gc_refills needed */

#ifdef OKMM_DEBUG
static atomic64_t percpu_cache_fills = ATOMIC64_INIT(0);
static atomic64_t gc_cache_fills = ATOMIC64_INIT(0);

static inline void kern_mess(int n, int a, int lw, int id)
{
	long p = atomic64_read(&percpu_cache_fills);
	long g = atomic64_read(&gc_cache_fills);
	
	printk(KERN_INFO "cpu(%d) pid(%d): okmm %d, entries:%d available:%d "
	       "low water:%d, gc refills:%ld, percpu cache refills:%ld",
	       raw_smp_processor_id(), current->pid, id, n, a, lw, g, p);
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
		kern_mess(c->nentries, c->navailable, c->low_water, c->cpu);
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
	if (!e) {
		return NULL;
	}

	ept = (struct ept_pt_list*) kmalloc(sizeof(*ept), GFP_KERNEL);
	if (!ept) {
		goto err_e;
	}

	pt = (pt_page*)kmalloc(sizeof(*pt), GFP_KERNEL);
	if (!pt) {
		goto err_ept;
	}
	if(!(vt_alloc_page((void**)&pt[0].virt, &pt[0].phys))){
		goto err_pt;
	}
	e->epte = ept;
	e->pt = pt;
	INIT_LIST_HEAD(&e->list);
	return e;

err_pt:
	kfree(pt);
err_ept:
	kfree(ept);
err_e:
	kfree(e);
	return NULL;

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
		if (!ept || !pt ){
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

static int gc_refill(void)
{
	int n, m;
	struct okmm_ce new_entries;
	struct okmm_ce *refills;
	unsigned long flags;

	inc_metric(gc_cache_fills);
	spin_lock_irqsave(&okmm_lock, flags);
	printk_metrics(&gc);
	n = gc.nentries - gc.navailable;
	n = (n > OKMM_N_PERCPU) ? OKMM_N_PERCPU : n; //max fill is OKMM_N_PERCPU
	m = (gc.navailable <= gc.min) ? GC_STEP : 0;
	spin_unlock_irqrestore(&okmm_lock, flags);

	INIT_LIST_HEAD(&new_entries.list);
	make_entries(&new_entries, m);
	if (!(refills = make_refills(n))) {
		printk(KERN_CRIT "Asking for %d refills\n", n);
			return -ENOMEM;
	}

	spin_lock_irqsave(&okmm_lock, flags);
	do_refill(refills, n);
	m = do_new(&new_entries);

	gc.navailable += OKMM_N_PERCPU + m;
	gc.nentries += m;
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
	atomic64_inc(&nrefills_needed);
	spin_unlock_irqrestore(&okmm_lock, flags);
	wake_up(&okmm_refill_needed);
	if (c->navailable <= 0) {
		return -ENOMEM;
	}
	return 0;
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

static int __init init_cache (struct ok_mm_cache *c, int cpu)
{
	INIT_LIST_HEAD(&c->available.list);
	INIT_LIST_HEAD(&c->used.list);
	c->nentries = 0;
	c->navailable = 0;
	c->low_water = 0;
	c->ticks = 0;
	c->cpu = cpu;
	c->min = 0;
	return 0;
}

static int __init fill_cache (struct ok_mm_cache *c, int n)
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

static int okmm_allocator(void *unused)
{
	unsigned long i;
	while(!kthread_should_stop()) {
		wait_event_freezable(okmm_refill_needed,
				     atomic64_read(&nrefills_needed) > 0);
		for (i = atomic64_read(&nrefills_needed); i > 0;
		     i = atomic64_dec_if_positive(&nrefills_needed)){
			if (gc_refill() < 0) {
				printk(KERN_ERR
				       "okmm_allocator out of memory\n?");
			}
		}
	}
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

	printk(KERN_INFO "Initializing okmm_cache.\n");

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

	gc.min = OKMM_N_PERCPU * i * 2;
	n = gc.min * 3;
	printk(KERN_INFO "okmm_init %d CPUs, percpu cache size %d, global %d\n",
	       i, OKMM_N_PERCPU, n);
	okmm_allocator_th = kthread_run(okmm_allocator, NULL, "okmm_allocator");
	if (IS_ERR(okmm_allocator_th)) {
		printk(KERN_ERR "Unable to start okmm_allocator thread\n");
		return -1;
	}
	return fill_cache(&gc, n);
}

