/*
 * oktrace.c
 *      Author: Theo Koulouris
 */

#include <linux/kern_levels.h>
#include <linux/string.h>
#include <linux/okernel.h>
#include "vmx.h"



#define OK_DEFAULT_LOGLEVEL OK_DEBUG /* the default okernel loglevel */

const char *ok_loglevel_labels[] = {
		"",
		"",
		"",
		"OK_ERROR",
		"OK_WARNING",
		"OK_INFO",
		"",
		"OK_DEBUG",
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
	if (vcpu->lp < NVCPUBUF){
		p = &(vcpu->log[vcpu->lp][0]);
		vcpu->lp++;
		return p;
	}
	else{
		p = &(vcpu->log[0][0]);
		vcpu->lp = 1;
		return p;
	}
}

//static
void dump_log(struct vmx_vcpu *vcpu)
{
	int i;
	for (i=0; i< vcpu->lp; i++){
		trace_printk(&(vcpu->log[i][0]));
	}
}

const char *ok_trace_get_level(const char *buffer)
{
	if (buffer[0] == KERN_SOH_ASCII && buffer[1]) {
		switch (buffer[1]) {
		case '3' ... '7':
			if( ((int)buffer[1]>=3) && ((int)buffer[1]<=7) ) {
				return ok_loglevel_labels[(int)buffer[1]];
			}
			break;
		case 's':
			return ok_loglevel_labels[8];
		}
	}
	return "";
}


/*void __ok_trace(const char *fmt, ...)
{
	const char *label = ok_trace_get_level(fmt);
	trace_printk("(%s) [%s - cpu(%d) pid(%d)] %s: ", label, vmx_nr_mode()?"NR":"R", raw_smp_processor_id(), current->pid,__func__, fmt, ...);
}*/
