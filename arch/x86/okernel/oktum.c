/*
 * Tracks code being released from user space memory (Track User
 * Memory - TUM). We need to clear the EPT_X bit in the EPTs on this
 * memory, so it isn't executable when it gets reused. This machinery
 * is only necessary on processors without mode-based execute control
 * for EPT. With mode-based execute control for EPT, provided we can
 * control execution rights in supervisor and user mode separately.
 *
 * Author: Nigel Edwards, 2017
 */

#include <linux/okernel.h>
#include <linux/page_ext.h>
#include <linux/types.h>

#include <asm/pgtable_64.h>

#include "oktum.h"

/* Page state flags */
enum ok_user_flags {
	OK_USER_X,         /* Page is executable in user space*/
};

/* Per-page house-keeping data */
struct ok_tum {
	unsigned long flags;	/* Page state */
};

DEFINE_STATIC_KEY_FALSE(ok_tum_inited);

static bool need_ok_tum(void)
{
	return true;
}

static void init_ok_tum(void)
{
	/* safe to use page extensions after this */
	static_branch_enable(&ok_tum_inited);
}

struct page_ext_operations page_okernel_tum_ops = {
	.size = sizeof(struct ok_tum),
	.need = need_ok_tum,
	.init = init_ok_tum,
};

static inline struct ok_tum *lookup_ok_tum(struct page *page)
{
	struct page_ext *page_ext = lookup_page_ext(page);

	if (unlikely(!page_ext)) {
		WARN(1, "oktum: failed to get page ext");
		return NULL;
	}

	return (void *)page_ext + page_okernel_tum_ops.offset;
}

static inline void __clr_eptx(struct page *page)
{
	if(is_in_vmx_nr_mode())
		(void)vmcall2(VMCALL_CLR_EPTX, (unsigned long) page);
	else
		ok_clr_eptx(page);
}

void okernel_free_pages(struct page *page, unsigned int order)
{
	int i;
	struct ok_tum *ok_tum;

	if(!static_branch_unlikely(&ok_tum_inited))
		return;
	for (i = 0; i < (1 << order); i++) {
		ok_tum = lookup_ok_tum(page + i);
		if (!ok_tum)
			continue;
		/*
		 * Clear the EPT_X bit if previously set
		 */

		if (test_and_clear_bit(OK_USER_X, &ok_tum->flags))
			__clr_eptx(page);
	}
}

void okernel_kmap(struct page *page)
{
	struct ok_tum *ok_tum;

	if(!static_branch_unlikely(&ok_tum_inited))
		return;

	/*
	 * Clear the EPT_X bit if previously set
	 */
	ok_tum = lookup_ok_tum(page);
	if (!ok_tum)
		return;
	if (test_and_clear_bit(OK_USER_X, &ok_tum->flags))
		__clr_eptx(page);
}
EXPORT_SYMBOL(okernel_kmap);

bool okernel_page_user_x(struct page *page)
{
	struct ok_tum *ok_tum;

	if(!static_branch_unlikely(&ok_tum_inited))
		return false;

	ok_tum = lookup_ok_tum(page);
	if (!ok_tum)
		return false;
	else
		return test_bit(OK_USER_X, &ok_tum->flags);
}



void okernel_tum_x(u64 pa)
{
	struct ok_tum *ok_tum;
	struct page *page;

	if(!static_branch_unlikely(&ok_tum_inited))
		return;

	/*
	 * Set OK_USER_X
	 */
	page = pfn_to_page(PHYS_PFN(pa));
	if ((pa & ~(PAGESIZE - 1)) != page_to_phys(page)) {
		BUG();
		OKLOG("PFN consistency problem");
		OKLOG("guest physical page is %#lx", pa & ~(PAGESIZE - 1));
		OKLOG("page_to_phys(pfn_to_page(PHYS_PFN(pa))) %#lx",
		      page_to_phys(pfn_to_page(PHYS_PFN(pa))));
	}
	ok_tum = lookup_ok_tum(page);
	if(!ok_tum)
		return;
	set_bit(OK_USER_X, &ok_tum->flags);
}
