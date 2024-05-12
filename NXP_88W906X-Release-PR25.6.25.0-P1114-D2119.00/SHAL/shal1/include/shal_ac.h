/** @file shal_ac.h
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
 * @brief SMAC HAL AC management calls.
 */

#ifndef _SHAL_AC_H_
#define _SHAL_AC_H_

#ifdef SCFG_MCQ_SUPPORT
#define AC_NUM                6	///< Number of AC entries
#else
#define AC_NUM                5	///< Number of AC entries
#endif

#define SHAL_AC_BK            0	///< Background access category
#define SHAL_AC_BE            1	///< Best-Effort access category
#define SHAL_AC_VI            2	///< Video access category
#define SHAL_AC_VO            3	///< Voice access category
#define SHAL_AC_BAP           4	///< Basic Access Procedure, for such as Probe-Response
#ifdef SCFG_MCQ_SUPPORT
#define SHAL_AC_MCBC          5	///< Bufferred multicast/broadcast packets
#endif

typedef struct AC_ENTRY_st {
	LIST_ELEM_st txqList;
// DW2
	U16 txopLimit;		///< [us]
	U8 boCountDown;
	U8 rsvd;
// DW3
	U16 cwMin;		///< 2^eCwMin - 1, eCwMin=15
	U16 cwMax;		///< 2^eCwMax - 1, cCwMax=15
// DW4
	U16 cw;
	U16 backOff;
// DW5
	U8 primTcTid1;		///< TC TID which belong to this AC
	U8 primTcTid2;		///< TC TID which belong to this AC
	U8 scndTcTid[6];	///< TC TID which NOT belong to this AC
// DW7
	U8 aifsn;		///< 2-15
	U8 ifs;			///< 2-15

	// TODO: tx MU
	U8 muFlag:1;
	U8 muPreSetup:7;
	U8 muBitmap;		///< for TxBBIF
// DW8
	U8 muNsts[4];		///< [txcpu]
	U8 muPos[4];		///< [txcpu]
	GRP_ENTRY_st *muGrp;
	SMAC_TXQ_ENTRY_st *muTxq[4];	///< [txcpu]
} AC_ENTRY_st;

#endif				//_SHAL_AC_H_
