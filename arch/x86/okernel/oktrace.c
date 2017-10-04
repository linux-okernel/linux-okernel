/*
 * oktrace.c
 *      Author: Theo Koulouris
 */

#include <linux/slab.h>
#include <linux/okernel.h>
#include "vmx.h"


#define OKERNEL_LOG_BUFFER_MAX 512
#define OK_BUFFER_SIZE (OKERNEL_LOG_BUFFER_MAX * sizeof(char))
DEFINE_SPINLOCK(oktrace_lock);
char *msgbuffer = NULL;

int ok_trace_init(void) {
	msgbuffer = kmalloc(OK_BUFFER_SIZE, GFP_KERNEL);
	if (msgbuffer == NULL) {
		return 0;
	} else {
		printk(KERN_INFO "okernel: Allocated tracing buffer, size: %lu", OK_BUFFER_SIZE);
		return (OK_BUFFER_SIZE);
	}
}

int do_ok_trace(unsigned long ip, const char *label, const char *fmt, ...)
{
	va_list args;
	int r = 0;
	char *msg = msgbuffer;
	size_t msg_len = 0;

	if (spin_trylock(&oktrace_lock)) {
		/* Generate header */
		if (label != NULL) {
			msg_len = scnprintf(msg, OK_BUFFER_SIZE,
					    "[%s] [%s,cpu(%d),pid(%d)]: ",
					    label, vmx_nr_mode()? "NR" : "R",
					    raw_smp_processor_id(),
					    current->pid);
		} else {
			msg_len = scnprintf(msg, OK_BUFFER_SIZE,
					    "[%s,cpu(%d),pid(%d)]: ",
					    vmx_nr_mode()? "NR" : "R",
					    raw_smp_processor_id(),
					    current->pid);
		}

		/* Append original message contents */
		if (msg_len < OK_BUFFER_SIZE) {
			va_start(args, fmt);
			msg_len +=
			    vscnprintf(msg + msg_len,
				       (OK_BUFFER_SIZE - msg_len), fmt,
				       args);
			va_end(args);

			r = __trace_puts(ip, msg, msg_len);
		}
		spin_unlock(&oktrace_lock);
	}

	return r;
}
