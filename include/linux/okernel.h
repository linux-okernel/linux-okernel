/* 
 * linux/include/linux/okernel.h
 * 
 * Copyright (C) 2015 - Chris Dalton (cid@hpe.com), HPE Corp.
 * Suport for splitting the kernel into inner and outer regions,
 * we the aim of achieving some degree of intra-kernel protection.
 * Processes marked as 'PKERNEL' run under vmx non-root mode (x86).
 * They enter the kernel in that mode too (outer-kernel mode) 
 * thus giving a (inner kernel - running in root-mode vmx on x86)
 * a control point where restrictions can be put in place, e.g. enforce
 * something like a vMMU interface, as in 'Nested Kernel', Dautenhahn,
 *  et al. 
 */

#ifndef _LINUX_OKERNEL_H
#define _LINUX_OKERNEL_H


/* 
 * Flags to control initial vmx non-root mode setup from user-space 
 * and subsequent scheduling / fork, etc. behaviour.
 *
 */
#define PKERNEL_ON_EXEC 1
#define PKERNEL 2

#endif /* _LINUX_OKERNEL_H */
