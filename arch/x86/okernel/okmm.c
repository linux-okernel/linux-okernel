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
 * This needs to be changed to a list available and used
 * Available contains entries which can be used
 * Used have their ept_pt_list and pt_page structures being used
 * these structures  will be freed when the okernel mode process exits
 * so used can be placed back on the available list once we have
 * allocated new ept_pt_list and pt_page structures for them
 *
 * Also will need percpu list pairs
 */
static struct ok_pt_cache_entry pt_cache[OKMM_MAX];
static unsigned long nentries;
static int in_refresh;
static unsigned long low_water;

static DEFINE_SPINLOCK(okmm_lock);

static inline void kern_mess(unsigned long lw)
{
	printk(KERN_ERR "cpu(%d) pid(%d): okmm cache low water mark: %lu",
	       raw_smp_processor_id(), current->pid, lw);
}

static void okmm_metrics(void)
{
	/* Output a message every max_count calls regardless of low_water val*/
	static const int max_count = 10000;
	static int count = 0;
	count++;
	if (count > max_count || nentries < low_water) {
		if (count > max_count)
			count = 0;
		if (nentries < low_water)
			low_water = nentries;
		kern_mess(low_water);
	}
}

static int do_refresh(unsigned long n)
{
	struct ok_pt_cache_entry *nc;
	struct ept_pt_list *ept;
	pt_page *pt;
	unsigned long i, j;
	unsigned long flags;

	nc = (struct ok_pt_cache_entry*) kmalloc((sizeof(*nc) * n), GFP_KERNEL);
	if (!nc) {
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
		nc[i].epte = ept;
		nc[i].pt = pt;
	}
	spin_lock_irqsave(&okmm_lock, flags);
	for (i = 0, j = nentries; i < n; i++, j++){
		pt_cache[j].epte = nc[i].epte;
		pt_cache[j].pt = nc[i].pt;
	}
	nentries += n;
	in_refresh = 0;
	spin_unlock_irqrestore(&okmm_lock, flags);
	kfree(nc);
	return 0;
}

int okmm_refresh_pt_cache(void)
{
	unsigned long flags;
	unsigned long n;
	spin_lock_irqsave(&okmm_lock, flags);
	okmm_metrics();
	if (nentries <= OKMM_MIN && !(in_refresh)){
		n = OKMM_MAX - nentries;
		in_refresh = 1;
		spin_unlock_irqrestore(&okmm_lock, flags);
		return do_refresh(n);
	}
	spin_unlock_irqrestore(&okmm_lock, flags);
	return 0;
}

void okmm_get_ptce(struct ept_pt_list **epte, pt_page **pt)
{
	unsigned long flags;

	spin_lock_irqsave(&okmm_lock, flags);
	if (nentries > 0){
		nentries--;
		*epte = pt_cache[nentries].epte;
		*pt = pt_cache[nentries].pt;
	} else {
		*epte = 0;
		*pt = 0;
	}
	spin_unlock_irqrestore(&okmm_lock, flags);
}

static int alloc_ok_ptce(int index)
{
	struct ept_pt_list *ept;
	pt_page *pt;

	ept =(struct ept_pt_list*) kmalloc(sizeof(*ept), GFP_KERNEL);
	pt   = (pt_page*)kmalloc(sizeof(*pt), GFP_KERNEL);
	if (!ept | !pt ){
		return 0;
	}
	if(!(vt_alloc_page((void**)&pt[0].virt, &pt[0].phys))){
		return 0;
	}
	pt_cache[index].epte = ept;
	pt_cache[index].pt = pt;
	return 1;
}

int __init okmm_init(void)
{
	/* Returns Null if successful*/
	unsigned long i;
	nentries = 0;
	in_refresh = 0;
	printk(KERN_ERR "Initializing okmm_cache.\n");
	for(i = nentries; i < OKMM_MAX; i++){
		if (!alloc_ok_ptce(i)){
			return -ENOMEM;
		}
		nentries++;
	}
	low_water = OKMM_MIN;
	return 0;
}
