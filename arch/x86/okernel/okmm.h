#ifndef OKMM_H
#define OKMM_H

#define OKMM_INIT_NR 128 /* Initial number of entries */
#define OKMM_MIN_PERCPU 64 /* Mininum initial number in per CPU cache */

 /* Miniumum number of entries in Global backing cache */
#define GC_MIN (OKMM_MIN_PERCPU * 2)
/* Step by which to grow the cache if we go below GC_MIN*/
#define GC_STEP OKMM_MIN_PERCPU

struct ok_pt_cache_entry {
	struct list_head list;

	/* For use by okernel to track the allocated page*/
	struct ept_pt_list *epte;

	pt_page *pt;
};

struct ok_mm_cache {
	struct ok_pt_cache_entry available;
	struct ok_pt_cache_entry used;
	int id;
	int nentries;
	int navailable;
	int low_water;
	int ticks; /* Count since last low_water message*/
};

extern int __init okmm_init(void);
extern void okmm_get_ptce(struct ept_pt_list **epte, pt_page **pt);
extern int okmm_refresh_pt_cache(void);

#endif /* OKMM_H */
