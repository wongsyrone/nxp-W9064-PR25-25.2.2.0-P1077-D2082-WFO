/** @file shal_sema.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2014-2020 NXP
  *
  * This software file (the "File") is distributed by NXP
  * under the terms of the GNU General Public License Version 2, June 1991
  * (the "License").  You may use, redistribute and/or modify the File in
  * accordance with the terms and conditions of the License, a copy of which
  * is available by writing to the Free Software Foundation, Inc.,
  * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
  * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
  *
  * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
  * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
  * this warranty disclaimer.
  *
  */

/**
 * @file
 * @brief SMAC Semaphore function APIs.
 */

#ifndef _SHAL_SEMA_H_
#define _SHAL_SEMA_H_

/**
   @addtogroup SMAC_Semaphores SMAC Semaphores
   1. TOTAL # of SEMAPHORE IDs :  : 4096(2^SEMA_PRI)
   2. MAX # of SEMAPHORES any single processor can own at a time : 4
   3. priority : highest (15) - lowest (0)
   4. 16-bit ID encoding: priority [15..12], semaphore ID [11..0]
   @{
*/
#define SEMA_PRI_ID                  (SCFG_SEMA_BASE_ADDR + 0x0)
#define SEMA_GET                     (SCFG_SEMA_BASE_ADDR + 0x4)
#define SEMA_REL                     (SCFG_SEMA_BASE_ADDR + 0x8)
#define SEMA_WAIT                    (SCFG_SEMA_BASE_ADDR + 0xC)
#define SEMA_PRI                     12
#define SEMA_ID                      0

// Assign semaphore IDs and priority for corresponding ID
// SFW:             0 -   63 (48- SFW,PFW shared)
#define SEMA_AVL0_PRI0        (U32)((0 << SEMA_PRI) | (2 << SEMA_ID))	///< pri=0, id=2
#define SEMA_AVL1_PRI0        (U32)((0 << SEMA_PRI) | (3 << SEMA_ID))	///< pri=0, id=3
#define SEMA_AVL2_PRI0        (U32)((0 << SEMA_PRI) | (4 << SEMA_ID))	///< pri=0, id=4
#define SEMA_AVL3_PRI0        (U32)((0 << SEMA_PRI) | (5 << SEMA_ID))	///< pri=0, id=5

// sema for LBM
#define SEMA_LBM_SFW          (U32)((0 << SEMA_PRI) | (6 << SEMA_ID))	///< pri=0, id=6
#define SEMA_LBM_PFW          (U32)((0 << SEMA_PRI) | (7 << SEMA_ID))	///< pri=0, id=7
// sema for msgQue
#define SEMA_MSG_QUE_SFW      (U32)((0 << SEMA_PRI) | (8 << SEMA_ID))	///< pri=0, id=8
#define SEMA_MSG_QUE_PFW      (U32)((0 << SEMA_PRI) | (9 << SEMA_ID))	///< pri=0, id=9
// sema for frmQue
#define SEMA_FRM_QUE_SFW      (U32)((0 << SEMA_PRI) | (10 << SEMA_ID))	///< pri=0, id=10
#define SEMA_FRM_QUE_PFW      (U32)((0 << SEMA_PRI) | (11 << SEMA_ID))	///< pri=0, id=11
// sema for dbm
#define SEMA_DBM_SFW          (U32)((0 << SEMA_PRI) | (12 << SEMA_ID))	///< pri=0, id=12
#define SEMA_DBM_SFW_LARGE    (U32)((0 << SEMA_PRI) | (13 << SEMA_ID))	///< pri=0, id=13
#define SEMA_DBM_PFW          (U32)((0 << SEMA_PRI) | (14 << SEMA_ID))	///< pri=0, id=14
// sema for TX Packet Buffer Return Count
#define SEMA_TX_BUF_RETURN    (U32)((0 << SEMA_PRI) | (16 << SEMA_ID))	///< pri=0, id=16
#define SEMA_RX_BUF_RETURN    (U32)((0 << SEMA_PRI) | (17 << SEMA_ID))	///< pri=0, id=17
// sema for gMBss and gMbss_head
#define SEMA_GMBSS_ENTRY      (U32)((0 << SEMA_PRI) | (18 << SEMA_ID))	///< pri=0, id=18
//sema for acnt record
#define SEMA_ACNT_RCD         (U32)((0 << SEMA_PRI) | (19 << SEMA_ID))	///< pri=0, id=19
//sema for cm3 remap window register access
#define SEMA_CM3_REMAP_WIN    (U32)((0 << SEMA_PRI) | (20 << SEMA_ID))	///< pri=0, id=20
//sema for bf register related excess
#define SEMA_BF_REG_ENTRY     (U32)((0 << SEMA_PRI) | (21 << SEMA_ID))	///< pri=0, id=21
//sema for critical sections in MU
#define SEMA_MU               (U32)((0 << SEMA_PRI) | (22 << SEMA_ID))	///< pri=0, id=22

// sema for AC Entry
#define SEMA_AC_ENTRY_BK      (U32)((0 << SEMA_PRI) | (48 << SEMA_ID))	///< pri=0, id=48
#define SEMA_AC_ENTRY_BE      (U32)((0 << SEMA_PRI) | (49 << SEMA_ID))	///< pri=0, id=49
#define SEMA_AC_ENTRY_VI      (U32)((0 << SEMA_PRI) | (50 << SEMA_ID))	///< pri=0, id=50
#define SEMA_AC_ENTRY_VO      (U32)((0 << SEMA_PRI) | (51 << SEMA_ID))	///< pri=0, id=51
#define SEMA_AC_ENTRY_BAP     (U32)((0 << SEMA_PRI) | (52 << SEMA_ID))	///< pri=0, id=52
#ifdef SCFG_MCQ_SUPPORT
#define SEMA_AC_ENTRY_MCBC    (U32)((0 << SEMA_PRI) | (53 << SEMA_ID))	///< pri=0, id=53
#endif
// sema for TXD5
#define SEMA_TXD5             (U32)((0 << SEMA_PRI) | (54 << SEMA_ID))	///< pri=0, id=54
// sema for DSP
#define SEMA_PFW2DFW_MSGQ_LP  (U32)((0 << SEMA_PRI) | (55 << SEMA_ID))	///< pri=0, id=55
#define SEMA_PFW2DFW_MSGQ_MP  (U32)((0 << SEMA_PRI) | (56 << SEMA_ID))	///< pri=0, id=56
#define SEMA_PFW2DFW_MSGQ_HP  (U32)((0 << SEMA_PRI) | (57 << SEMA_ID))	///< pri=0, id=57

#define SEMA_INFINITE_WAIT    (U32)((15 << SEMA_PRI)| (62 << SEMA_ID))	///< pri=15,id=63

// Assigned semaphore IDs
// PFW:            64 -  479
#define SEMA_PFW_CSU          (U32)((0 << SEMA_PRI)| (64 << SEMA_ID))	///< pri=0, id=64
// HW BSS Table:  480 -  511
#define SEMA_TXD_BSS_BASE     (U32)((0 << SEMA_PRI)| (480 << SEMA_ID))	///< pri=0,id=480 - 511

// HW STA Table:  512 - 1023
#define SEMA_TXD_STA_BASE     (U32)((0 << SEMA_PRI)| (512 << SEMA_ID))	///< pri=0,id=512 - 1023

// HW TXQ Table: 1024 - 4095
#define SEMA_TXD_TXQ_BASE     (U32)((0 << SEMA_PRI)| (1024 << SEMA_ID))	///< pri=0,id=1024 - 4095

static U32 const SEMA_acSemaphoreId[AC_NUM] = {
	SEMA_AC_ENTRY_BK,
	SEMA_AC_ENTRY_BE,
	SEMA_AC_ENTRY_VI,
	SEMA_AC_ENTRY_VO,
	SEMA_AC_ENTRY_BAP,
#ifdef SCFG_MCQ_SUPPORT
	SEMA_AC_ENTRY_MCBC,
#endif
};

static U32 const SEMA_msgQueSemaphoreId[2] = {
	SEMA_MSG_QUE_SFW,
	SEMA_MSG_QUE_PFW
};

#ifndef __KERNEL__

static SHAL_INLINE void SEMA_init(void)
{
	UTIL_write32(SEMA_WAIT, 0);
}

static SHAL_INLINE void SEMA_wait(U16 delay)
{
	UTIL_write32(SEMA_WAIT, delay);
}

extern U32 SEMA_get(U32 id);
extern U32 SEMA_rel(U32 id);

#endif				/* #ifndef __KERNEL__ */

	  /** @} */// group SMAC_Semaphores

#endif				// _SHAL_SEMA_H_
