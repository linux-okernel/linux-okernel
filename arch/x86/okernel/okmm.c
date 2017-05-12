/*
 * Author: Nigel Edwards, 2017
 */

#include <linux/init.h>
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
static unsigned long pt_cache_size;
static struct mutex okmm_mutex;

static inline int alloc_ok_ptce(int index)
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

int okmm_refresh_pt_cache(void)
{
	int ret = 0;
	unsigned long i;
	mutex_lock(&okmm_mutex);
	HDEBUG("Cache size is %lu\n", pt_cache_size);
	if (pt_cache_size > OKMM_MIN){
		goto end_unlock;
	}
	for(i = pt_cache_size; i < OKMM_MAX; i++){
		if (!alloc_ok_ptce(i)){
			ret = -ENOMEM;
			goto end_unlock;
		}
		pt_cache_size++;
	}
end_unlock:
	printk(KERN_ERR "Exiting okmm_refresh_pt_cache.\n");
	mutex_unlock(&okmm_mutex);
	return ret;

}

void okmm_get_ptce(struct ept_pt_list **epte, pt_page **pt)
{
	mutex_lock(&okmm_mutex);
	/*
	 * Bug : need to the index needs to be one less than the 
	 * cache size
	 */
	
	if (pt_cache_size > 0){
		*epte = pt_cache[pt_cache_size].epte;
		*pt = pt_cache[pt_cache_size].pt;
		pt_cache_size--;
	} else {
		*epte = 0;
		*pt = 0;
	}
	mutex_unlock(&okmm_mutex);
}

int __init okmm_init(void)
{
	/* Returns Null if successful*/
	printk(KERN_ERR "Initializing okmm_cache.\n");
	mutex_init(&okmm_mutex);
	pt_cache_size = 0;
	return okmm_refresh_pt_cache();
}
