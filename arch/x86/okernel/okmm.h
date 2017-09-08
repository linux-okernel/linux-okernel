#ifndef OKMM_H
#define OKMM_H

/* Mininum initial number in per CPU cache */
#define OKMM_N_PERCPU (1 << 5)

/* Step by which to grow the cache if we go below minimum */
#define GC_STEP OKMM_N_PERCPU

/* CPU ids are positive, so use -1 to denote the global cache*/
#define OKMM_GC_CPU_ID -1

#define OKMM_DEBUG


struct okmm_ce {
	struct list_head list;

	/* For use by okernel to track the allocated page*/
	struct ept_pt_list *epte;

	pt_page *pt;
};

struct ok_mm_cache {
	struct okmm_ce available;
	struct okmm_ce used;
	int cpu;
	int nentries;
	int navailable;
	int min; /* min or fewer entries triggers growth */
	int low_water;
	int ticks; /* Count since last low_water message*/
};

extern int __init okmm_init(void);
extern void okmm_get_ce(struct ept_pt_list **epte, pt_page **pt);

#endif /* OKMM_H */
