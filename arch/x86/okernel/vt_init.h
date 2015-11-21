/*
 * Copyright (c) 2007, 2008 University of Tsukuba
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the University of Tsukuba nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * EPT additions: C I Dalton 
*/

#ifndef _CORE_VT_INIT_H
#define _CORE_VT_INIT_H


/* Mapping limits of each type of page table in Gbytes. */
#define PML4E_MAP_LIMIT 512
#define PML3E_MAP_LIMIT 1


#define EPT_R_BIT       (0)
#define EPT_W_BIT       (1)
#define EPT_X_BIT       (2)
#define EPT_2M_PAGE_BIT (7)

#define EPT_CACHE_BIT1  (3)
#define EPT_CACHE_BIT2  (4)
#define EPT_CACHE_BIT3  (5)
 
#define EPT_R       (1UL << EPT_R_BIT)
#define EPT_W       (1UL << EPT_W_BIT)
#define EPT_X       (1UL << EPT_X_BIT)
#define EPT_2M_PAGE (1UL << EPT_2M_PAGE_BIT)
#define EPT_CACHE_1 (1UL << EPT_CACHE_BIT1)
#define EPT_CACHE_2 (1UL << EPT_CACHE_BIT2)
#define EPT_CACHE_3 (1UL << EPT_CACHE_BIT3)

#define EPT_IPAT_BIT (1UL << 6)

#define EPT_P_MTYPE    0x6
/* Actual value that goes into EPTP is EPT_PWL-1 */
#define EPT_PWL        0x4
#define EPT_PWL_SHIFT  0x3
#define EPT_PAGE_MASK  0xFFFFF000
#define EPT_MEM_WB     0x18

#define GIGABYTE       0x40000000
#define GIGABYTE_SHIFT 30


typedef struct pt_page {
     u64  phys;
     u64* virt;
 } pt_page;

#endif
