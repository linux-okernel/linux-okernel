#ifndef OKMM_H
#define OKMM_H

/* Mininum initial number in per CPU cache */
#define OKMM_PERCPU (1 << 8)

/* Mininumum number in the global cache, it grows if we go lower*/
#define GC_MIN (OKMM_PERCPU << 1)

/* Step by which to grow the cache if we go below GC_MIN*/
#define GC_STEP OKMM_PERCPU


struct okmm_ce {
	struct list_head list;

	/* For use by okernel to track the allocated page*/
	struct ept_pt_list *epte;

	pt_page *pt;
};

struct ok_mm_cache {
	struct okmm_ce available;
	struct okmm_ce used;
	int id;
	int nentries;
	int navailable;
	int low_water;
	int ticks; /* Count since last low_water message*/
};

extern int __init okmm_init(void);
extern void okmm_get_ptce(struct ept_pt_list **epte, pt_page **pt);
extern int okmm_refill_pt_cache(void);

#endif /* OKMM_H */
