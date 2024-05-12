/** @file shal_txq.h
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
 * @brief SMAC TXQ definitions (shared between SFW and PFW).
 */

#ifndef _SHAL_TXQ_H_
#define _SHAL_TXQ_H_

#define SMAC_TXQ_UNUSED_L0_POINTER 0xFFFFFFFF

typedef struct SMAC_TXD_TXLIMIT_st {
	//DW0
	U32 l0MinUnit:12;	///< [512-byte]mantissa(8b)+exponent(4b)
	U32 l0MinPkt:12;	///< [packet]  mantissa(8b)+exponent(4b)
	U32 rsvd1:8;
	//DW1
	U32 l0MaxUnit:12;	///< [512-byte]mantissa(8b)+exponent(4b)
	U32 l0MaxPkt:12;	///< [packet]  mantissa(8b)+exponent(4b)
	U32 rsvd2:8;
} SMAC_TXD_TXLIMIT_st;

typedef struct SMAC_TXQ_TXD1_2_FIELD_st {
	U8 txd1WAR:1;
	U8 rsvd1:3;
	U8 discardData:1;	///< queue whose data is to be discarded
	U8 queueInTx:1;		///< 1 if queues is currently being transmitted (between Txd6 and Txd3)
	U8 rsvd2:2;
} SMAC_TXQ_TXD1_2_FIELD_st;

//====== SW ================
typedef struct SMAC_TXQ_ENTRY_st {
	//Common for all kinds of frames
	LIST_ELEM_st acLink;
//[2]
	U8 queType;
	//Common end

	//Info for scheduler
	U8 retryCntFirst:4;
	U8 ppdu_PER_range:4;
	U16 qid;
//[3]
	U32 tsfFirst;		///< @todo when update it, be careful HALs_procFrmPfw()
//[4]
	U32 tsfLast;		///< @todo when update it, be careful HALs_procFrmPfw()
//[5]
	U32 numBytes;
//[6]
	U16 numMSDU;
	U16 numMPDU;
//[7]
	U16 fbLenFirst;		///< 1st(oldest) Frame Body(MSDU or AMSDU) length only for PFW RTS decision
	///< Need to consider adding MAC[SEC] header length and FCS(4)
	//Info end
	U16 pfw_amsdu_adp:1;
	U16 fbCodeFirst:3;	/* [2:0] 0:MSDU, 1:AMSDU, 2:MMDU, 3:ACKed(not expected value), 7:invalid */
	U16 rsvd1:12;
//[8]
	U32 l1Pointer;
//[9]
	U16 l2Head;
	U16 l2Last;
//[10]
	U16 winSizeO;
	U16 winStartO;
//[11]
	U16 winStartOSn;
	U16 SN;
//[12]
	U16 l3Start;
	U16 l3End;
//[13]
	U8 l3Status:2;
	U8 l3TxBstFlag:2;	///< need to Tx after Tx
	U8 l3ImmRspFlag:2;	///< expect IR after Tx
	U8 l3BarFlag:1;		///< need to Tx BAR after Tx
	U8 l3IrBstFlag:1;	///< need to Tx after Tx- Rx IR
	U8 retxMode:3;		///< retransmission mode
	U8 allowSendToPFW:1;	///< 1: txq can be added to AC list for PFW scheduling. 0: Donot add to AC list
	U8 ap:2;		///< Ack Policy
	U8 blockAp:1;		///< ADDBA Block Ack Policy
	U8 pktlocation:1;	///< 0:DDR, 1:DMEM
	U8 l2inUse1;		///< spinlock for codeNlen
	U8 up:3;		///< user priority
	U8 rsvd2:1;
	U8 retryRateIndex:2;	///< rate to use for RTS when RTS is being retried 
	U8 txqMark:2;
//[14]
	U32 txd4ByteAmpdu;
//[15]
	U8 userId;
	U8 txd4NumMpdu;
	U16 codeNlen;		///< for handling partial amsdu in TXD2/TXD4
//[16]
	U32 l0PointerFirst;	///< first L0 entry still allocated
//[17]
	SMAC_TXQ_TXD1_2_FIELD_st txd1Info;
	U8 pktAmsdu;
	U16 maxAmsduLen;

	U32 lastTxD2Tsf;

// Do not increase more
} SMAC_TXQ_ENTRY_st;

#endif //_SHAL_TXQ_H_
