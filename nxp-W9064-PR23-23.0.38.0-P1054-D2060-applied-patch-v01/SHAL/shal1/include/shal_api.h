/** @file shal_api.h
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
 * @brief SMAC API calls.
 */

/**
 * @addtogroup SMAC_API SMAC API
 *@{*/

#ifndef _SHAL_API_H_
#define _SHAL_API_H_

typedef int boolean;

// LBM size
#define SMAC_LBM_BUF_SIZE      1024

// Messaging macros
#define HALS_PFW_2_SFW          0
#define HALS_SFW_2_PFW          1
// When msg is moving from PFW to SFW
#define HALS_TO_SFW             HALS_PFW_2_SFW
#define HALS_FR_PFW             HALS_PFW_2_SFW
// When msg is moving from SFW to PFW
#define HALS_TO_PFW             HALS_SFW_2_PFW
#define HALS_FR_SFW             HALS_SFW_2_PFW

#define HALS_SMAC_0             0	///< for dual band
#define HALS_SMAC_1             1	///< for dual band

////////////////////////////////////
// Message Cmd Buf, Que
////////////////////////////////////
// LBM
typedef struct SMAC_LBM_st {
	U8 buf[SMAC_LBM_BUF_SIZE];
	U32 base;
	U16 head;
	U16 tail;
	U32 end;
} SMAC_LBM_st;
#define LBM_MARK_FREE    (1U<<31)
#define LBM_MARK_ALLOC   (0<<31)

// MsgQ
#define SMAC_MSQ_SIZE           16
typedef struct SMAC_MSQ_st {
	U32 que[SMAC_MSQ_SIZE];
	U16 head;
	U16 tail;
} SMAC_MSQ_st;

/// Cmd Interface struct (encapsulate buf and queue)
typedef struct CMD_INF_st {
	SMAC_LBM_st cmdBuf;
	SMAC_MSQ_st cmdQue;
} CMD_INF_st;

#ifndef MFG_FW
#define DBM_BUF_NUM_PFW     8
#define DBM_BUF_SIZE_PFW    1500
#else
#define DBM_BUF_NUM_PFW     2
#define DBM_BUF_SIZE_PFW    SMAC_BCN_BUFSIZE
#endif

#define DBM_BUF_SIZE_DATA   (DBM_BUF_SIZE_PFW - sizeof(SMAC_TXQ_ENTRY_st) - sizeof(U32) * 2)
#define MAX_MAC_HDR_LEN     64

typedef struct DMB_PFW_st {
	SMAC_TXQ_ENTRY_st txq;	//19 DW. 
	U32 config;
	U32 rsvd[2];		//PF:rateInfo, TF:rateInfo + param0
	U32 buf[4 + (DBM_BUF_SIZE_DATA / 4)];	//extra 4DW for 16-byte alignment
} DBM_PFW_st;

/**
 * @brief Allocate a command buffer
 *
 * @param  flag  undocumented
 * @param  size  Size of the command buffer to allocated.
 * @param  macId undocumented.
 * @return Pointer to the allocated buffer, 0 in case of failure.
 *
 * @todo Document flag and macId parameters.
 */
U8 *HALS_allocCmdBuf(U32 flag, U32 size, U32 macId);

/**
 * @brief Insert entry into queue
 * @return 1: failure, queue is full. 0; success, entry inserted correctly
 */
U8 HALS_enqCmdBuf(U32 flag, U8 * cmdBufPtr, U32 macId);

/**
 * @brief Retrieve a pointer from the SFW queue (called by SFW on retrieve side)
 * @return 0: empty. != 0 : valid cmdBufPtr returned
 */
U8 *HALS_deqCmdBuf(U32 flag, U32 macId);

/// Free buffer
void HALS_freeCmdBuf(U32 flag, U8 * cmdBufPtr, U32 macId);

boolean HALS_smacInitDone(void);

	/**@}*/// group SMAC_API

U8 HALS_allocDbmPfw(U32 baseAddr, U32 * txqAddr, U32 * bufAddr);

#endif //_SHAL_API_H_
