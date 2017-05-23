#ifndef OKMM_H
#define OKMM_H

#define OKMM_MIN 1024 /* Minimum number below which we allocate new entries */
#define OKMM_MAX (OKMM_MIN + 256) /* Maximum number of entries */

struct ok_pt_cache_entry {
	struct ept_pt_list *epte;
	pt_page *pt;
};

extern int __init okmm_init(void);
extern void okmm_get_ptce(struct ept_pt_list **epte, pt_page **pt);
extern int okmm_refresh_pt_cache(void);

#endif /* OKMM_H */
