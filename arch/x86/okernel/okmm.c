/*
 * Author: Nigel Edwards, 2017
 */

#include <linux/init.h>
#include <linux/okernel.h>
#include <linux/slab.h>

#include "constants2.h"
#include "vmx.h"
#include "okmm.h"

/*
 * Note on locking: we can't make assumptions about what is going on in
 * non-root (NR) mode. So we can only call anything which sets a lock in
 * another part of the kernel if we know we have not yet run in NR mode.
 * In particulary kmalloc() may try to obtain a lock. Hence only call
 * okmm_refresh_pt_cache, which may call kmalloc, before we enter NR mode,
 * during creation of the vcpu structure, before starting in NR mode.
 *
 * A futher complication is that we can never be sure whether or not
 * okmm_refresh_pt_cache will be called with interrupts disabled or not.
 * So to be safe we need to be safe we need to use spin_lock_irqsave
 * and spin_lock_irqrestore. Otherwise the following deadlock scenario
 * is possible
 *
 *  CPU(0)                        CPU(1)
 *  okmm_lock                     lockA
 *    <interrupt>                 okmm_lock
 *       lockA
 *
 * Also will need percpu list pairs
 */
static struct ok_pt_cache_entry available;
static struct ok_pt_cache_entry used;
static int nentries;
static int navailable;
static int in_refresh;
static int low_water;

static DEFINE_SPINLOCK(okmm_lock);

static inline void kern_mess(int lw)
{
	printk(KERN_ERR "cpu(%d) pid(%d): okmm cache low water mark: %d",
	       raw_smp_processor_id(), current->pid, lw);
}

static void okmm_metrics(void)
{
	/* Output a message every max_count calls regardless of low_water val*/
	static const int max_count = 10000;
	static int count = 0;
	count++;
	if (count > max_count || navailable < low_water) {
		if (count > max_count)
			count = 0;
		if (navailable < low_water)
			low_water = navailable;
		kern_mess(low_water);
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
static int okmm_grow_if_low(int na)
{
	struct ok_pt_cache_entry **ea;
	unsigned long flags;
	int i;
	int n = 0;
	if (na < (nentries >> 1)) {
		n = nentries;
		ea = (struct ok_pt_cache_entry**) kmalloc((sizeof(*ea) * n),
							  GFP_KERNEL);
		if (!ea){
			printk(KERN_ERR "okmm cache out of memory?\n");
			return 0;
		}
		for(i = 0; i < n; i++){
			if (!(ea[i] = make_entry())){
				printk(KERN_ERR "okmm cache out of memory?\n");
				return 0;
			}
		}
		spin_lock_irqsave(&okmm_lock, flags);
		for(i = 0; i < n; i++){
			list_add(&ea[i]->list, &available.list);
		}
		nentries += n;
		navailable += n;
		low_water = navailable;
		spin_unlock_irqrestore(&okmm_lock, flags);
		kfree(ea);
	}
	if (n > 0) {
		printk(KERN_ERR "okmm added %d new entries\n", n);
	}
	return n;
}

static int do_refresh(int na)
{
	/* na is a local copy of navailable to avoid holding okmm_lock */
	struct ept_pt_list **epta, *ept;
	pt_page **pta, *pt;
	int i, n;
	unsigned long flags;
	struct ok_pt_cache_entry *e;

	n = nentries - na;
	okmm_grow_if_low(na);
	epta = (struct ept_pt_list **) kmalloc((sizeof(*epta) * n), GFP_KERNEL);
	pta = (pt_page **) kmalloc((sizeof(*pta) * n), GFP_KERNEL);
	if (!epta || !pta) {
		return -ENOMEM;
	}

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

	spin_lock_irqsave(&okmm_lock, flags);
	for (i = 0; i < n; i++){
		e = list_first_entry(&used.list, struct ok_pt_cache_entry, list);
		e->epte = epta[i];
		e->pt = pta[i];
		list_move(&e->list, &available.list);
	}
	navailable += n;
	in_refresh = 0;
	spin_unlock_irqrestore(&okmm_lock, flags);
	kfree(epta);
	kfree(pta);
	return 0;
}

int okmm_refresh_pt_cache(void)
{
	unsigned long flags;
	int na;
	spin_lock_irqsave(&okmm_lock, flags);
	okmm_metrics();
	if (!in_refresh){
		na = navailable;
		in_refresh = 1;
		spin_unlock_irqrestore(&okmm_lock, flags);
		return do_refresh(na);
	}
	spin_unlock_irqrestore(&okmm_lock, flags);
	return 0;
}

void okmm_get_ptce(struct ept_pt_list **epte, pt_page **pt)
{
	unsigned long flags;
	struct ok_pt_cache_entry *e;

	spin_lock_irqsave(&okmm_lock, flags);
	if (!(list_empty(&available.list))){
		navailable--;
		e = list_first_entry(&available.list, struct ok_pt_cache_entry,
				     list);
		*epte = e->epte;
		*pt = e->pt;
		list_move(&e->list, &used.list);
	} else {
		*epte = 0;
		*pt = 0;
	}
	spin_unlock_irqrestore(&okmm_lock, flags);
}

int __init okmm_init(void)
{
	/* Returns Null if successful*/
	int i;
	struct ok_pt_cache_entry *e;

	navailable = 0;
	in_refresh = 0;
	printk(KERN_ERR "Initializing okmm_cache.\n");
	INIT_LIST_HEAD(&available.list);
	INIT_LIST_HEAD(&used.list);
	for(i = 0; i < OKMM_INIT_NR; i++){
		if (!(e = make_entry())){
			return -ENOMEM;
		}
	list_add(&e->list, &available.list);
	}
	nentries = OKMM_INIT_NR;
	navailable = OKMM_INIT_NR;
	low_water = OKMM_INIT_NR;
	return 0;
}
