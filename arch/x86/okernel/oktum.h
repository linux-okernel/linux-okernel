/*
 * Author: Nigel Edwards, 2017
 */
#ifndef OKTUM_H
#define OKTUM_H
#include "vmx.h"

void ok_clr_eptx(struct vmx_vcpu *vcpu, struct page *page);
void okernel_tum_x(u64 pa);
bool okernel_page_user_x(struct page *page);

#endif /* OKTUM_H */
