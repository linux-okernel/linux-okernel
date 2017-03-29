#ifndef _CORE_CONSTANTS2_H
#define _CORE_CONSTANTS2_H
#include <linux/smp.h>

/* Execption / NMI vmexit handling */

enum vmmerr {
	VMMERR_SUCCESS = 0,
	VMMERR_GUESTSEG_LOAD_FAILED,
	VMMERR_GUESTSEG_NOT_PRESENT,
	VMMERR_INVALID_GUESTSEG,
	VMMERR_PAGE_NOT_PRESENT,
	VMMERR_PAGE_NOT_ACCESSIBLE,
	VMMERR_PAGE_NOT_EXECUTABLE,
	VMMERR_PAGE_BAD_RESERVED_BIT,
	VMMERR_INSTRUCTION_TOO_LONG,
	VMMERR_UNIMPLEMENTED_OPCODE,
	VMMERR_UNSUPPORTED_OPCODE,
	VMMERR_EXCEPTION_UD,
	VMMERR_AVOID_COMPILER_WARNING,
	VMMERR_SW,
	VMMERR_NOMEM,
	VMMERR_MSR_FAULT,
};

#define EXCEPTION_DE			0x0
#define EXCEPTION_GP			0xD
#define EXCEPTION_PF			0xE


enum intr_info_err {
        INTR_INFO_ERR_INVALID = 0,
        INTR_INFO_ERR_VALID = 1,
};

enum intr_info_type {
        INTR_INFO_TYPE_EXTERNAL = 0,
        INTR_INFO_TYPE_NMI = 2,
        INTR_INFO_TYPE_HARD_EXCEPTION = 3,
        INTR_INFO_TYPE_SOFT_INTR = 4,
        INTR_INFO_TYPE_PRIV_SOFT_EXCEPTION = 5,
        INTR_INFO_TYPE_SOFT_EXCEPTION = 6,
};

enum intr_info_valid {
        INTR_INFO_VALID_INVALID = 0,
        INTR_INFO_VALID_VALID = 1,
};

struct intr_info {
        unsigned int vector : 8;
        enum intr_info_type type : 3;
        enum intr_info_err err : 1;
        unsigned int nmi : 1;
        unsigned int reserved : 18;
        enum intr_info_valid valid : 1;
} __attribute__ ((packed));





/* 32-Bit Control Fields */
#define VMCS_EXCEPTION_BMP              0x4004
#define VMCS_PAGEFAULT_ERRCODE_MASK     0x4006
#define VMCS_PAGEFAULT_ERRCODE_MATCH    0x4008
#define VMCS_VMENTRY_INTR_INFO_FIELD    0x4016
#define VMCS_VMENTRY_EXCEPTION_ERRCODE  0x4018
#define VMCS_VMENTRY_INSTRUCTION_LEN    0x401A
#define VMCS_VMEXIT_INTR_ERRCODE	0x4406


/* EPT / VPID capabilities*/
#define VMCS_EPT_XO     0x1
#define VMCS_EPT_PW4    0x40
#define VMCS_EPT_UC     0x100
#define VMCS_EPT_WB     0x4000
#define VMCS_EPT_2MB    0x10000
#define VMCS_EPT_1GB    0x20000
#define VMCS_EPT_INVEPT 0x100000
#define VMCS_EPT_ADEPT  0x200000
#define VMCS_EPT_IEPTS  0x2000000
#define VMCS_EPT_IEPTA  0x4000000



#define RFLAGS_CF_BIT			0x1
#define RFLAGS_PF_BIT			0x4
#define RFLAGS_AF_BIT			0x10
#define RFLAGS_ZF_BIT			0x40
#define RFLAGS_SF_BIT			0x80
#define RFLAGS_TF_BIT			0x100
#define RFLAGS_IF_BIT			0x200
#define RFLAGS_DF_BIT			0x400
#define RFLAGS_OF_BIT			0x800
#define RFLAGS_IOPL_MASK		0x3000
#define RFLAGS_IOPL_0			0x0000
#define RFLAGS_IOPL_1			0x1000
#define RFLAGS_IOPL_2			0x2000
#define RFLAGS_IOPL_3			0x3000
#define RFLAGS_NT_BIT			0x4000
#define RFLAGS_RF_BIT			0x10000
#define RFLAGS_VM_BIT			0x20000
#define RFLAGS_AC_BIT			0x40000
#define RFLAGS_VIF_BIT			0x80000
#define RFLAGS_VIP_BIT			0x100000
#define RFLAGS_ID_BIT			0x200000
#define RFLAGS_ALWAYS1_BIT		0x2
#define RFLAGS_SYS_MASK			RFLAGS_TF_BIT | \
					RFLAGS_IF_BIT | \
					RFLAGS_IOPL_MASK | \
					RFLAGS_NT_BIT | \
					RFLAGS_RF_BIT | \
					RFLAGS_VM_BIT | \
					RFLAGS_AC_BIT | \
					RFLAGS_VIF_BIT | \
					RFLAGS_VIP_BIT | \
					RFLAGS_ID_BIT
#define RFLAGS_NONSYS_MASK		RFLAGS_CF_BIT | \
					RFLAGS_PF_BIT | \
					RFLAGS_AF_BIT | \
					RFLAGS_ZF_BIT | \
					RFLAGS_SF_BIT | \
					RFLAGS_DF_BIT | \
					RFLAGS_OF_BIT


#define CR_REG_ACCESS_MASK              0xF
#define CR_REG_ACCESS_TYPE              0x48
#define CR_REG_ACCESS_GP                0xFF00   

#define PDE_P_BIT			0x1
#define PDE_RW_BIT			0x2
#define PDE_US_BIT			0x4
#define PDE_PWT_BIT			0x8
#define PDE_PCD_BIT			0x10
#define PDE_A_BIT			0x20
#define PDE_D_BIT			0x40
#define PDE_PS_BIT			0x80
#define PDE_G_BIT			0x100
#define PDE_AVAILABLE1_BIT		0x200
#define PDE_AVAILABLE2_BIT		0x400
#define PDE_AVAILABLE3_BIT		0x800
#define PDE_AVAILABLE_MASK		0xE00
#define PDE_NX_BIT			0x8000000000000000ULL
#define PDE_4K_ADDR_MASK		0xFFFFF000
#define PDE_ATTR_MASK			0xFFF
#define PDE_PS_PAT_BIT			0x1000
#define PDE_4M_PAT_BIT			PDE_PS_PAT_BIT
#define PDE_4M_OFFSET_MASK		0x003FFFFF
#define PDE_4M_ADDR_MASK		(~PDE_4M_OFFSET_MASK)
#define PDE_2M_PAT_BIT			PDE_PS_PAT_BIT
#define PDE_2M_OFFSET_MASK		0x001FFFFF
#define PDE_2M_ADDR_MASK		(~PDE_2M_OFFSET_MASK)
#define PDE_ADDR_MASK64			0x0000000FFFFFF000ULL

#define PTE_P_BIT			0x1
#define PTE_RW_BIT			0x2
#define PTE_US_BIT			0x4
#define PTE_PWT_BIT			0x8
#define PTE_PCD_BIT			0x10
#define PTE_A_BIT			0x20
#define PTE_D_BIT			0x40
#define PTE_PAT_BIT			0x80
#define PTE_G_BIT			0x100
#define PTE_AVAILABLE1_BIT		0x200
#define PTE_AVAILABLE2_BIT		0x400
#define PTE_AVAILABLE3_BIT		0x800
#define PTE_AVAILABLE_MASK		0xE00
#define PTE_NX_BIT			0x8000000000000000ULL
#define PTE_ADDR_MASK			0xFFFFF000
#define PTE_ATTR_MASK			0xFFF
#define PTE_ADDR_MASK64			0x0000000FFFFFF000ULL



#define PAGESIZE			0x1000
#define PAGESIZE2M			0x200000
#define PAGESIZE4M			0x400000
#define PAGESIZE_SHIFT			12
#define PAGESIZE2M_SHIFT		21
#define PAGESIZE4M_SHIFT		22
#define PAGESIZE_MASK			(PAGESIZE - 1)
#define PAGESIZE2M_MASK			(PAGESIZE2M - 1)
#define PAGESIZE4M_MASK			(PAGESIZE4M - 1)

/* 
 * Bits 63:52 are ignored by the processor so use 52 denoted
 * an integrity protected page
 */ 
#define OK_IP                           (1UL << 52)
/* Taken the memory map description in Documentation/x86/x86_64/mm.txt */
#define USER_HI_MEM                     0X00007FFFFFFFFFFFUL

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

#define EPT_PERM_MASK   (EPT_R | EPT_W | EPT_X)

#define EPT_P_MTYPE    0x6
/* Actual value that goes into EPTP is EPT_PWL-1 */
#define EPT_PWL        0x4
#define EPT_PWL_SHIFT  0x3
#define EPT_PAGE_MASK  0xFFFFF000
#define EPT_MEM_WB     0x18

#define GIGABYTE       0x40000000
#define GIGABYTE_SHIFT 30

#define TWO_MBYTE       0x200000
#define TWO_MBYTE_SHIFT 21

/* CPUID  bits of interest */
#define ECX_VMX_BIT 0x20

typedef struct pt_page {
     u64  phys;
     u64* virt;
 } pt_page;

#endif
