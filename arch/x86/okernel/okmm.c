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
static unsigned long low_water;

static DEFINE_SPINLOCK(okmm_lock);

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

int okmm_refresh_pt_cache(void)
{
	int ret = 0;
	unsigned long i;
	spin_lock(&okmm_lock);
	okmm_metrics();
	if (nentries > OKMM_MIN){
		goto end_unlock;
	}
	for(i = nentries; i < OKMM_MAX; i++){
		if (!alloc_ok_ptce(i)){
			ret = -ENOMEM;
			goto end_unlock;
		}
		nentries++;
	}
end_unlock:
	spin_unlock(&okmm_lock);
	return ret;

}

void okmm_get_ptce(struct ept_pt_list **epte, pt_page **pt)
{
	spin_lock(&okmm_lock);
	if (nentries > 0){
		nentries--;
		*epte = pt_cache[nentries].epte;
		*pt = pt_cache[nentries].pt;
	} else {
		*epte = 0;
		*pt = 0;
	}
	spin_unlock(&okmm_lock);
}

int __init okmm_init(void)
{
	/* Returns Null if successful*/
	int ret;
	printk(KERN_ERR "Initializing okmm_cache.\n");
	nentries = 0;
	ret = okmm_refresh_pt_cache();
	low_water = OKMM_MIN;
	return ret;
}
