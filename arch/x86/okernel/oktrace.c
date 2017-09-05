/*
 * oktrace.c
 *      Author: Theo Koulouris
 */

//#include <linux/string.h>
#include <linux/okernel.h>
#include "vmx.h"



// NJE BEGIN NEEDS TO GO
/*
 * We can use trace_printk or printk safely when we have a process running
 * in NR mode. So this is a quick and dirty circular buffer until we
 * build something better (it is in hand).
 */
//static
char *log_ptr(struct vmx_vcpu *vcpu)
{
	char *p;
	if (vcpu->lp < NVCPUBUF) {
		p = &(vcpu->log[vcpu->lp][0]);
		vcpu->lp++;
		return p;
	} else {
		p = &(vcpu->log[0][0]);
		vcpu->lp = 1;
		return p;
	}
}

//static
void dump_log(struct vmx_vcpu *vcpu)
{
	int i;
	for (i = 0; i < vcpu->lp; i++) {
		trace_printk(&(vcpu->log[i][0]));
	}
}

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
