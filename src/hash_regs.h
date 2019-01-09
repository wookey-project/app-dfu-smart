#ifndef HASH_REGS_H_
#define HASH_REGS_H_

#define r_CORTEX_M_HASH_BASE 0x50060400

#define HASH_IRQ 0x60 /* interrupt identifier (starting from ESTACK, IRQ is 0x50 */

/**** Control register *****/
#define _r_CORTEX_M_HASH_CR  REG_ADDR(r_CORTEX_M_HASH_BASE)
#define HASH_CR_INIT_Pos      2
#define HASH_CR_INIT_Msk      ((uint32_t)1 << HASH_CR_INIT_Pos)
#define HASH_CR_DMAE_Pos      3
#define HASH_CR_DMAE_Msk      ((uint32_t)1 << HASH_CR_DMAE_Pos)
#define HASH_CR_DATATYPE_Pos  4
#define HASH_CR_DATATYPE_Msk  ((uint32_t)3 << HASH_CR_DATATYPE_Pos)
#define HASH_CR_MODE_Pos      6
#define HASH_CR_MODE_Msk      ((uint32_t)1 << HASH_CR_MODE_Pos)
#define HASH_CR_ALGO0_Pos     7
#define HASH_CR_ALGO0_Msk     ((uint32_t)1 << HASH_CR_ALGO0_Pos)
#define HASH_CR_NBW_Pos       8
#define HASH_CR_NBW_Msk       ((uint32_t)0xf << HASH_CR_NBW_Pos)
#define HASH_CR_DINNE_Pos     12
#define HASH_CR_DINNE_Msk     ((uint32_t)0x1 << HASH_CR_DINNE_Pos)
#define HASH_CR_MDMAT_Pos     13
#define HASH_CR_MDMAT_Msk     ((uint32_t)0x1 << HASH_CR_MDMAT_Pos)
#define HASH_CR_LKEY_Pos      16
#define HASH_CR_LKEY_Msk      ((uint32_t)0x1 << HASH_CR_LKEY_Pos)
#define HASH_CR_ALGO1_Pos     18
#define HASH_CR_ALGO1_Msk     ((uint32_t)1 << HASH_CR_ALGO1_Pos)

/**** Data-in register *****/
#define _r_CORTEX_M_HASH_DIN  REG_ADDR(r_CORTEX_M_HASH_BASE + 0x004)
#define HASH_DIN_DATAIN_Pos   0
#define HASH_DIN_DATAIN_Msk   0xffffffff

/**** STR register *****/
#define _r_CORTEX_M_HASH_STR  REG_ADDR(r_CORTEX_M_HASH_BASE + 0x008)
#define HASH_STR_NBLW_Pos      0
#define HASH_STR_NBLW_Msk      ((uint32_t)1f << HASH_STR_NBLW_Pos)
#define HASH_STR_DCAL_Pos      8
#define HASH_STR_DCAL_Msk      ((uint32_t)1 << HASH_STR_DCAL_Pos)

/**** Interrupt management register *****/
#define _r_CORTEX_M_HASH_IMR  REG_ADDR(r_CORTEX_M_HASH_BASE + 0x020)
#define HASH_IMR_DINIE_Pos      0
#define HASH_IMR_DINIE_Msk      ((uint32_t)1 << HASH_IMR_DINIE_Pos)
#define HASH_IMR_DCIE_Pos       1
#define HASH_IMR_DCIE_Msk       ((uint32_t)1 << HASH_IMR_DCIE_Pos)

/**** Status register *****/
#define _r_CORTEX_M_HASH_SR  REG_ADDR(r_CORTEX_M_HASH_BASE + 0x024)
#define HASH_SR_DINIS_Pos       0
#define HASH_SR_DINIS_Msk       ((uint32_t)1 << HASH_SR_DINIS_Pos)
#define HASH_SR_DCIS_Pos        1
#define HASH_SR_DCIS_Msk        ((uint32_t)1 << HASH_SR_DCIS_Pos)
#define HASH_SR_DMAS_Pos        2
#define HASH_SR_DMAS_Msk        ((uint32_t)1 << HASH_SR_DMAS_Pos)
#define HASH_SR_BUSY_Pos        3
#define HASH_SR_BUSY_Msk        ((uint32_t)1 << HASH_SR_BUSY_Pos)

/* data out registers banks base */
#define _r_CORTEX_M_HASH_CSR  REG_ADDR(r_CORTEX_M_HASH_BASE + 0x0F8)
#define HASH_HR               REG_ADDR(r_CORTEX_M_HASH_BASE + 0x00C)
#define HASH_HR_              REG_ADDR(r_CORTEX_M_HASH_BASE + 0x310)

#endif /*HASH_REGS_H_*/
