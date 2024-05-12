/** @file shal_sched.h
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
 * @brief SMAC HAL scheduler interface
 */

#ifndef SHAL_SCHED_H_
#define SHAL_SCHED_H_

#ifdef SCFG_MCQ_SUPPORT
#define TCQ_NUM               6	///< Number of TCQ
#else
#define TCQ_NUM               5	///< Number of TCQ
#endif
#define TCQ_NUM_SLOT          2	///< Number of TXQ that can be scheduled in a TCQ
#define TCQ_SLOT_MASK         (TCQ_NUM_SLOT - 1)

/// TCQ Ring status
typedef enum {
	RING_STATUS_EMPTY = 0,
	RING_STATUS_FULL,
	RING_STATUS_IN_TX,
} RING_STATUS_t;

typedef enum {
	AP_NORMAL_ACK = 0,
	AP_NO_ACK,
	AP_NO_EXP_ACK,
	AP_BLOCK_ACK
} SW_TXPARAM_ACK_POLICY_t;

typedef enum {
	MU_ACK_SEQ_IMPBAR,
	MU_ACK_SEQ_EXPBAR,
	MU_ACK_SEQ_MUBAR,
	MU_ACK_SEQ_TRIGBA,
	MU_ACK_SEQ_MAX
} MU_ACK_SEQ_DEFINED;

typedef struct {
	U32 rtsFormat:1;
	U32 RetryLimitType:1;
	U32 RTS:1;
	U32 EnableControlWrapper:1;
	U32 CTS_to_self:1;
	U32 ACKPolicy:2;
	U32 DisableDur:1;
	U32 EnableSwLegacyLength:1;
	U32 NoRateDrop:1;
	U32 AggrBit:1;		///< change to indicate this tx slot is for ampdu
	U32 MIDpktTx:1;
	U32 enableIndBW:1;
	U32 enableDynBW:1;
	U32 smoothing:1;
	U32 TxHTSIG2_2:1;
	U32 NDPA_MPDU:1;
	U32 NDPA_RTS:1;
	U32 lifetimeExpCheck:1;
	U32 EnableLegacyTcdd:1;
	U32 EnableTxHtTcdd:1;
	U32 align:1;
	U32 TRPCidSource:1;
	U32 EnableSWSeqNum:1;
	U32 ExpIFBResp:1;
	U32 mcs9Tx:1;		///< in sc4, this was in txparam2
	U32 EnableMCSFeedback:1;	///< in sc4, this was in txparam2
	U32 preamble:1;		///< in sc4, this was in rateinfo
	U32 beam_change:1;
	U32 MU_RTS:1;
	U32 reserved:2;
} SW_TXPARAM_st;

#ifdef __CC_ARM
#pragma anon_unions
#endif

/// This structure is used by PFW scheduler to transmit packets. One SW_TXINFO_st
/// entry represents one PSDU (A-MPDU). SMAC will consume SW_TXINFO_st entries
/// and start the transmission.
typedef struct SW_TXINFO_st {
	//0
	/// Head of the list of scheduled TXQ (1 element for SU, multiple elements for MU)
	LIST_ELEM_st txqList;

	//8
	U8 status;
	U8 TxAttemptCnt;
	U8 rsvd0;
	U8 antennaBitmap;

	//12
	SW_TXPARAM_st txparam;	///< 32bits

	//16
	U16 SwAggrDensity;
	U16 partialAid;

	//20
	U32 rtsRateInfo;

	//24
	U8 user_num;		///< Number of user (1 for SU)
	U8 tx_mode:6;		///< Transmission mode. See ::BB_MODE_t. set to U8 to reduce size
	U8 tf_type:2;
	U8 ofdmaoption:4;	//fix ru option ie.  fix 26 ru , firx 52 ru, fix  106, fix 242 
	U8 ofdma:4;		///< OFDMA enable (0: disabled, 1: OFDMA enabled)
	U8 muGID;

	//28
	U8 ru_comb[2][4];

	//36
	U32 txpwr_abcd:11;
	U32 txpwr_efgh:11;
	U32 bm_idx:2;
	U32 nullru:8;		//to indicate if nullru is use, actuall only 2 bit is require now

	/// Aggregation limits.
	/// SMAC will try to perform A-MPDU aggregation up to these limits.
	//40
	U32 maxBytes[MAX_USERS];	///< Maximum number of bytes to aggregate

	//104
	U16 maxMpdus[MAX_USERS];	///< Maximum number of MPDUs to aggregate
	//136
	SW_TXINFO_COMMON_st common;

	/// Union depending on the value of tx_mode, user_num and ofdma
	union {
		/// ((tx_mode == BB_MODE_OFDM) || (tx_mode == BB_MODE_DSSS))
		struct {
			//148
			U8 pad[sizeof(SW_TXINFO_VHT_COMMON_st)];
			//156
			USER_t users[1];
		}
		legacy;

		/// ((tx_mode == BB_MODE_HTMF) || (tx_mode == BB_MODE_HTGF))
		struct {
			//148
			U8 pad[sizeof(SW_TXINFO_VHT_COMMON_st)];
			//156
			USER_t users[1];
		}
		ht;

		/// ((tx_mode == BB_MODE_VHT) && (user_num == 1))
		struct {
			//148
			SW_TXINFO_VHT_COMMON_st vht_common;
			//156
			USER_t users[1];
		} vht_su;

		/// ((tx_mode == BB_MODE_VHT) && (user_num > 1))
		struct {
			//148
			SW_TXINFO_VHT_COMMON_st vht_common;
			//156
			USER_t users[MAX_MUMIMO_USERS];
		} vht_mu;

		/// ((tx_mode == BB_MODE_HE) && (user_num == 1) && !OFDMA_en)
		struct {
			//148
			SW_TXINFO_HE_COMMON_st he_common;
			//156
			USER_t users[1];
		} he_su;

		/// ((tx_mode == BB_MODE_HE) && (user_num > 1) && !OFDMA_en)
		struct {
			//148
			SW_TXINFO_HE_COMMON_st he_common;
			//156
			USER_OFDMA_t users[MAX_OFDMA_USERS];
		} he_mu;

		/// ((tx_mode == BB_MODE_HE) && OFDMA_en)
		struct {
			//148
			SW_TXINFO_HE_COMMON_st he_common;
			//156
			USER_OFDMA_t users[MAX_OFDMA_USERS];
			S16 OFDMA_80MHz_centerRU_sch[2];
		} he_ofdma;
	};
	SW_TXINFO_TF_COMMON_st tf_common;
	SW_TXINFO_TF_USER_st tf_user[MAX_OFDMA_USERS];

	U16 tf_txRateMcs:2;
	U16 tf_mu_rts_ul:1;
#ifdef SCFG_MCQ_SUPPORT
	U16 mcbcPending:1;
	U16 rsvd:12;
#else
	U16 rsvd:13;
#endif
	U16 tf_slotIdx:2;
	U16 tf_ac:2;
	U16 mu_ack_seq:2;
	U16 tf_frameLen:10;

	U32 txInfoTS;		// SwTxInfo created timestamp
} SW_TXINFO_st;

typedef struct TCQ_RING_st {
	U32 rsvdTcq[3];		// For 16B allignment
	U32 slotIndex;
	SW_TXINFO_st swTxInfo[TCQ_NUM_SLOT];
} TCQ_RING_st;

typedef struct SHAL_L2_SW_ENTRY_st {
//DW0
	U32 l0Pointer;		//It should be always the 1st entry (see TXD_l2SwStore)
//DW1
	U32 tsf;
//DW2                            //First 24bits are same with proposed l2like (see TXD2_start)
	U16 codeNlen;		//Copy of L2_HW_ENTRY_st
	U8 pktAmsdu;
	U8 retryCnt:4;
	U8 rtsRetryCnt:4;
//DW3
	U16 PN_low;
	U16 SN:12;
	U16 rsvd:4;
} SHAL_L2_SW_ENTRY_st;

//#define DBG_SCHEDULER_TRACE          TRUE        //only valid in SU for now
#if defined(DBG_SCHEDULER_TRACE)
typedef struct SCHEDTRACE_st {
//DW0
	U8 acNum:4;
	U8 slotIndex:4;
	U8 tx_mode:4;
	U8 gi:1;
	U8 rsvd1:1;
	U8 bw:2;
	U8 mcs;
	U8 nss;

//DW1
	SW_TXINFO_st *swTxInfo;

//DW2
	SMAC_TXQ_ENTRY_st *txq;

//DW3
	U32 maxBytes;

//DW4
	U16 numMSDU;
	U16 numMPDU;

//DW5
	U32 tsf;
} SCHEDTRACE_st;
#endif

#endif				// SHAL_SCHED_H_
