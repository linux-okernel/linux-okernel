/*
 * oktrace.c
 *      Author: Theo Koulouris
 */

#include <linux/kern_levels.h>
#include <linux/string.h>
#include <linux/okernel.h>
#include "vmx.h"

#define OK_DEFAULT_LOGLEVEL OK_DEBUG	/* the default okernel loglevel */

char *ok_loglevel_labels[] = { "OK_EMERG", "OK_ALERT", "OK_CRITICAL",
	"OK_ERROR", "OK_WARNING", "OK_NOTICE", "OK_INFO", "OK_DEBUG",
	"OK_SECURITY"
};

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

static inline int ok_trace_get_level(const char *buffer)
{
	if (buffer[0] == KERN_SOH_ASCII && buffer[1]) {
		switch (buffer[1]) {
		case '3' ... '7':
		case 's':
			return buffer[1];
		}
	}
	return 0;
}

int do_ok_trace(unsigned long ip, const char *fmt, ...)
{
	va_list args;
	int r;
	int level;
	char *text_level = NULL;
	static char textbuf[OKERNEL_LOG_BUFFER_MAX];
	char *text = textbuf;
	char buffer[OKERNEL_LOG_BUFFER_MAX + 48];
	size_t text_len = 0, buffer_len = 0;

	/* get original message contents */
	va_start(args, fmt);
	text_len = vscnprintf(text, sizeof(textbuf), fmt, args);
	va_end(args);

	/* mark and strip a trailing newline */
	if (text_len && text[text_len - 1] == '\n') {
		text_len--;
	}

	/* Read and strip message-level header if present */
	while ((level = ok_trace_get_level(text)) != 0) {
		switch (level) {
		case '0' ... '7':
			text_level = ok_loglevel_labels[(level - '0')];
			break;
		case 's':
			text_level = ok_loglevel_labels[8];
			break;
		}

		text_len -= 2;
		text += 2;
	}

	/* Prepend final header */
	if (text_level != NULL) {
		buffer_len = scnprintf(buffer, sizeof(buffer),
				       "(%s) [%s cpu(%d) pid(%d)] : %s",
				       text_level, vmx_nr_mode()? "NR" : "R",
				       raw_smp_processor_id(), current->pid,
				       text);
	} else {
		buffer_len = scnprintf(buffer, sizeof(buffer),
				       "[%s cpu(%d) pid(%d)] : %s",
				       vmx_nr_mode()? "NR" : "R",
				       raw_smp_processor_id(), current->pid,
				       text);
	}

	r = __trace_printk(ip, buffer);

	return r;
}
