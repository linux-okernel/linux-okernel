/*
 * oktrace.c
 *      Author: Theo Koulouris
 */

#include <linux/okernel.h>
#include "vmx.h"



int do_ok_trace(unsigned long ip, const char *label, const char *fmt, ...)
{
	va_list args;
	int r;
	static char msgbuffer[OKERNEL_LOG_BUFFER_MAX];
	char *msg = msgbuffer;
	size_t msg_len = 0;


	/* Generate header */
	if (label != NULL) {
		msg_len = scnprintf(msg, sizeof(msgbuffer),
				    "[%s] [%s, cpu(%d),pid(%d)] : ",
				    label, vmx_nr_mode()? "NR" : "R",
				    raw_smp_processor_id(), current->pid);
	} else {
		msg_len = scnprintf(msg, sizeof(msgbuffer),
				    "[%s, cpu(%d),pid(%d)] : ",
				    vmx_nr_mode()? "NR" : "R",
				    raw_smp_processor_id(), current->pid);
	}

	/* Append original message contents */
	va_start(args, fmt);
	msg_len += vscnprintf(msg + msg_len, sizeof(msgbuffer), fmt, args);
	va_end(args);

	//r = __trace_printk(ip, msg);
	r = __trace_puts(ip, msg, msg_len);

	return r;
}
