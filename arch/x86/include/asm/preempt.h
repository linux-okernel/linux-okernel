#ifndef __ASM_PREEMPT_H
#define __ASM_PREEMPT_H

#include <asm/rmwcc.h>
#include <asm/percpu.h>
#include <linux/thread_info.h>

DECLARE_PER_CPU(int, __preempt_count);
#if defined(CONFIG_OKERNEL)
DECLARE_PER_CPU(int, __nr_preempt_count_offset);
#endif

/*
 * We use the PREEMPT_NEED_RESCHED bit as an inverted NEED_RESCHED such
 * that a decrement hitting 0 means we can and should reschedule.
 */
#define PREEMPT_ENABLED	(0 + PREEMPT_NEED_RESCHED)

#if defined(CONFIG_OKERNEL)
static __always_inline int nr_preempt_count_offset(void)
{
       return raw_cpu_read_4(__nr_preempt_count_offset);
}
#if defined(CONFIG_PREEMPT_COUNT)
static __always_inline void nr_preempt_count_set_offset(int pc)
{
       raw_cpu_write_4(__nr_preempt_count_offset, pc);
}
#else
static __always_inline void nr_preempt_count_set_offset(int pc)
{
}
#endif
#endif

/*
 * We mask the PREEMPT_NEED_RESCHED bit so as not to confuse all current users
 * that think a non-zero value indicates we cannot preempt.
 */
#if defined(CONFIG_OKERNEL)
static __always_inline int preempt_count(void)
{
	int count = raw_cpu_read_4(__preempt_count) & ~PREEMPT_NEED_RESCHED;
	return (count -  nr_preempt_count_offset());
}
#else
static __always_inline int preempt_count(void)
{
	return raw_cpu_read_4(__preempt_count) & ~PREEMPT_NEED_RESCHED;
}
#endif

static __always_inline void preempt_count_set(int pc)
{
	int old, new;

	do {
		old = raw_cpu_read_4(__preempt_count);
		new = (old & PREEMPT_NEED_RESCHED) |
			(pc & ~PREEMPT_NEED_RESCHED);
	} while (raw_cpu_cmpxchg_4(__preempt_count, old, new) != old);
}



/*
 * must be macros to avoid header recursion hell
 */
#define init_task_preempt_count(p) do { } while (0)

#define init_idle_preempt_count(p, cpu) do { \
	per_cpu(__preempt_count, (cpu)) = PREEMPT_ENABLED; \
} while (0)

/*
 * We fold the NEED_RESCHED bit into the preempt count such that
 * preempt_enable() can decrement and test for needing to reschedule with a
 * single instruction.
 *
 * We invert the actual bit, so that when the decrement hits 0 we know we both
 * need to resched (the bit is cleared) and can resched (no preempt count).
 */

static __always_inline void set_preempt_need_resched(void)
{
	raw_cpu_and_4(__preempt_count, ~PREEMPT_NEED_RESCHED);
}

static __always_inline void clear_preempt_need_resched(void)
{
	raw_cpu_or_4(__preempt_count, PREEMPT_NEED_RESCHED);
}

static __always_inline bool test_preempt_need_resched(void)
{
	return !(raw_cpu_read_4(__preempt_count) & PREEMPT_NEED_RESCHED);
}

/*
 * The various preempt_count add/sub methods
 */

static __always_inline void __preempt_count_add(int val)
{
	raw_cpu_add_4(__preempt_count, val);
}

static __always_inline void __preempt_count_sub(int val)
{
	raw_cpu_add_4(__preempt_count, -val);
}

/*
 * Because we keep PREEMPT_NEED_RESCHED set when we do _not_ need to reschedule
 * a decrement which hits zero means we have no preempt_count and should
 * reschedule.
 */
#if defined(CONFIG_OKERNEL)
static __always_inline bool __ok_preempt_count_dec_and_test(void)
{
	/* XXXX cid: Fix this up to take nr mode offset into account */
	/* Returns 1 if count is 0 (e.g. PREEMPT_NEED_RESCHED flag not set)  */
	GEN_UNARY_RMWcc("decl", __preempt_count, __percpu_arg(0), e);
}

static __always_inline bool __preempt_count_dec_and_test(void)
{
	/* __ok_preempt_count_dec_and_test Returns 1 if count is 0 */
	/* (e.g. PREEMPT_NEED_RESCHED flag not set) so we need to check for nr offset too */
	if((__ok_preempt_count_dec_and_test() && !nr_preempt_count_offset())){
		return 1;
	}
	return 0;
}
#else
static __always_inline bool __preempt_count_dec_and_test(void)
{
	/* XXXX cid: need to fix this up to take nr mode offset into account */
	GEN_UNARY_RMWcc("decl", __preempt_count, __percpu_arg(0), e);
}
#endif
/*
 * Returns true when we need to resched and can (barring IRQ state).
 */
static __always_inline bool should_resched(int preempt_offset)
{
#if defined(CONFIG_OKERNEL)
	return unlikely((raw_cpu_read_4(__preempt_count) - nr_preempt_count_offset()) == preempt_offset);
#else
	return unlikely(raw_cpu_read_4(__preempt_count) == preempt_offset);
#endif
}

#ifdef CONFIG_PREEMPT
  extern asmlinkage void ___preempt_schedule(void);
# define __preempt_schedule() \
	asm volatile ("call ___preempt_schedule" : ASM_CALL_CONSTRAINT)

  extern asmlinkage void preempt_schedule(void);
  extern asmlinkage void ___preempt_schedule_notrace(void);
# define __preempt_schedule_notrace() \
	asm volatile ("call ___preempt_schedule_notrace" : ASM_CALL_CONSTRAINT)

  extern asmlinkage void preempt_schedule_notrace(void);
#endif

#endif /* __ASM_PREEMPT_H */
