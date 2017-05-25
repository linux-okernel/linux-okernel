#ifndef OKMM_H
#define OKMM_H

#define OKMM_INIT_NR 512 /* Initial number of entries */

struct ok_pt_cache_entry {
	struct list_head list;

	/* For use by okernel to track the allocated page*/
	struct ept_pt_list *epte;

	pt_page *pt;
};

extern int __init okmm_init(void);
extern void okmm_get_ptce(struct ept_pt_list **epte, pt_page **pt);
extern int okmm_refresh_pt_cache(void);

#endif /* OKMM_H */
