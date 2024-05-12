/** @file shal_msg.h
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
 * @brief SMAC HAL message body.
 */

#ifndef _SHAL_MSG_H_
#define _SHAL_MSG_H_

/** @addtogroup SMAC_Command_Types IDs of commands sent by PFW to SMAC
 *@{*/
/**
 * @brief @a start indicates end of initial config and lets SFW to start its normal operation
 */
#define  HAL_PFW_TYPE_START           1
#define  HAL_PFW_TYPE_DEV_CFG         2
#define  HAL_PFW_TYPE_ADD_BSS         3
#define  HAL_PFW_TYPE_DEL_BSS         4
#define  HAL_PFW_TYPE_ADD_STA         5
#define  HAL_PFW_TYPE_SET_RATE_STA    6
#define  HAL_PFW_TYPE_ADD_BA          9
#define  HAL_PFW_TYPE_DEL_STA         13
#define  HAL_PFW_TYPE_KEY_CFG         14
#define  HAL_PFW_TYPE_FIPS_TEST       15
#define  HAL_PFW_TYPE_REPORT_EVENT    16
#define  HAL_PFW_TYPE_MU_GROUP        17
#define  HAL_PFW_TYPE_ADD_SR          18
#define  HAL_PFW_TYPE_CHG_BF_MODE     19	// Change STA's BF Mode

#ifdef DSP_COMMAND
#define  HAL_PFW_TYPE_DSP_CMD         32
#endif
	/**@}*/// group SMAC_Command_Types

#define  HAL_SFW_TYPE_RSP              1
#define  HAL_SFW_TYPE_RX_MGT_FRAME     2
#define  HAL_SFW_TYPE_TIME_BEFORE_TBTT 3
#define  HAL_SFW_TYPE_BCNTX_COMPLETE   4
#ifdef DSP_COMMAND
#define  HAL_DFW_TYPE_RSP              5
#endif
#define  HAL_SFW_TYPE_SEND_BB_2_PFW    6
#define  HAL_SFW_TYPE_SEND_PRD_CSI_DMA_2_PFW 7
#define  HAL_SFW_TYPE_PS_TRIGGER       8

#define  HAL_SFW_MSG_RSP_NONE         0
#define  HAL_SFW_MSG_RSP_REQUIRED     1

#define  HAL_SFW_MSG_RET_SUCCESS      1

#ifdef DSP_COMMAND
#define  HAL_DFW_MSG_RSP_NONE         0
#define  HAL_DFW_MSG_RSP_REQUIRED     1
#endif

#define HAL_TXQ_TYPE_DATA        0	//Data frame
#define HAL_TXQ_TYPE_MMDU        1	//MMDU frame
#define HAL_TXQ_TYPE_MGT         2	//Management frame. Set in HALs_procFrmPfw() and go through same path with TXQ_TYPE_DATA.
#define HAL_TXQ_TYPE_RTS         3	//RTS control. Set in TXD6_evtSlotTick() and go through TXD6_startTxCtrl()
#define HAL_TXQ_TYPE_CTS         4	//CTS control. Set in FCS
#define HAL_TXQ_TYPE_ACK         5	//ACK control. Set in FCS
#define HAL_TXQ_TYPE_BA_COMP     6	//BA. Set in FCS
#define HAL_TXQ_TYPE_BAR         7	//BAR. Set in Eu
#define HAL_TXQ_TYPE_BCN         8	//Beacon. Set in TXD6_evtTimerBeacon() and go through TXD6_startTxCtrl()
#define HAL_TXQ_TYPE_NDPA        9	//NDPA. Set in TXD6_transmitNdpa
#define HAL_TXQ_TYPE_NDP         10	//NDP. Set in TXD6_transmitNdp
#define HAL_TXQ_TYPE_IMMDFB      11	//immediate feedback
#define HAL_TXQ_TYPE_CTS_TO_SELF 12	//CTS to self control
#define HAL_TXQ_TYPE_BFPOLL      13	//BF-POLL
#define HAL_TXQ_TYPE_TF          14	//Trigger Frame
#define HAL_TXQ_TYPE_PFW         15	//General from PFW
#define HAL_TXQ_TYPE_QOSNULL     16	//QoS NULL Data
#define HAL_TXQ_TYPE_BA_MSTA     17	//Multi Sta BA Frame
#define HAL_TXQ_TYPE_MU_RTS      18	//MU RTS
#define HAL_TXQ_TYPE_TF_MUBAR    19	//Trigger Frame MU BAR
#define HAL_TXQ_TYPE_TF_BASIC    20	//Trigger Frame Basic

#define HAL_TXQ_AP_ACK       0	//AP_NORMAL_ACK
#define HAL_TXQ_AP_NO_ACK    1	//AP_NO_ACK
//#define HAL_TXQ_AP_BA_IMMED  2    //Immediate BA
//#define HAL_TXQ_AP_BA_DELAY  3    //Delayed BA

/* HAL_PFW_ADD_BA_st baAp definiton */
#define HAL_BAP_BA_IMMED  1	//Immediate BA, 802.11-2016 9.4.1.14 Block Ack Policy
#define HAL_BAP_BA_DELAY  0	//Delayed BA, 802.11-2016 9.4.1.14 Block Ack Policy

#ifdef MFG_FW
// TODO: Remove when there is proper Hostless MFG Mode
#define  SMAC_BCN_BUFSIZE             65536	///< bytes. Allow larger size for sending larger MFG packets
#else
#define  SMAC_BCN_BUFSIZE             2048	///< bytes
#endif

#define  SMAC_TIME_BEFORE_TBTT        200	///< us

#define STAFLAG_STA_MODE(x)       (x & 0x1)

#define SHAL_ACT_GET            0
#define SHAL_ACT_SET            1
#define SHAL_ACT_DEL            2

#define SHAL_EU_MODE_CCMP       0
#define SHAL_EU_MODE_WAPI       1
#define SHAL_EU_MODE_CMAC       2
#define SHAL_EU_MODE_BYPASS     3
#define SHAL_EU_MODE_GCMP       4
#define SHAL_EU_MODE_GMAC       5
#define SHAL_EU_MODE_TKIP       6
#define SHAL_EU_MODE_WEP        7

#define SHAL_KEY_TYPE_PTK       0
#define SHAL_KEY_TYPE_GTK       1
#define SHAL_KEY_TYPE_IGTK      2

#define TF_CALLBACK_OFFSET      0	//8 bits
#define TF_USERINFO_OFFSET      8	//4 bits
#define TF_COMMON_OFFSET       12	//4 bits
#define TXINFO_TF_TYPE_OFFSET  16	//4 bits OFDMA(2)/MUMIMO(1)
#define TF_TYPE_OFFSET         20	//4 bits BASIC/BSRP/BFRP/...
#define TF_MBA_RATE_OFFSET     24	//2 bits. 0: 6Mbps, 1:12Mbps, 2:24Mbps
#define TF_CNT_ID_OFFSET       31	//1 bit index = 0/1

typedef enum {
	MSG_BUFFER_PFW_2_SFW = 0,
	MSG_BUFFER_SFW_2_PFW = 1,
	MSG_BUFFER_PFW_2_DFW_LP = 2,
	MSG_BUFFER_PFW_2_DFW_MP = 3,
	MSG_BUFFER_PFW_2_DFW_HP = 4,
	MSG_BUFFER_DFW_2_PFW = 5,
	MSG_BUFFER_NUMBER = 6
} HAL_MSG_BUFFER_TYPE_t;

/**
 * @brief Common header portion of message sent between SFW and PFW
 */
typedef struct HAL_PFW_MSG_HDR_st {
	U16 type;		///< HAL_PFW_MSG types
	U16 len;		///< length of the message body, excluding HAL_PFW_MSG_HDR_st
	U8 trid;		///< transaction ID
	U8 rspType;		///< 0: no response, 1:response required
	U16 rsvd;
} HAL_PFW_MSG_HDR_st;

typedef struct SR_INFO_t {
	U8 bssColorInfo;	// BSS color info field in HE operation
	U8 srSupport:1;		// 1: SR supported, 0: SR not supported
	U8 heSupport:1;		// 1: HE supported, 0: HE not supported
	U8 srIeCheck:1;		// 1: Check pass of SR IE with Non-SRG OBSS PD SR Disallowed or no SR IE, 0: check fail
	U8 radioMode:5;		// 0: normal mode, 1: 80+80
	U8 heTxNSSCnt:4;	// Highest Nss count in HE capability IE fpr Spatial Reuse usage. Doesn't handle separate MBSS value
	U8 totalTxAntCnt:4;	// Total tx ant
	U8 rsvd;

	//Spatial reuse IE stuff
	U8 srCtrl;		// SR control field SR parameter elem
	U8 srNonSrgPdMaxOffset;	// Non-SRG OBSS PD Max offset in SR parameter elem
	U8 srSrgPDMinOffset;	// SRG OBSS PD Min offset in SR parameter elem
	U8 srSrgPDMaxOffset;	// SRG OBSS PD Max offset in SR parameter elem

} SR_INFO_t;

typedef struct HAL_PFW_ADD_BSS_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2-3
	U8 macAddr[6];		///< STA MAC address
	U16 bssIndex;
// DW4
	U16 bssBasicRate;	///< b0: 1M, b1: 2M, b2: 5.5M, b3: 6M,
	///< b4: 9M, b5:11M, b6: 12M,  b7: 18M,
	///< b8:24M, b9:36M, b10:48M,  b11:54M
	U16 staFlag:1;		///< 0 : as AP role, 1: as STA role
	U16 dualCtsProt:1;	///< dual CTS in-use for this BSS
	U16 nonTxBssidProfile:1;	///< 0: beaconing, 1: NonTransmitted BSSID. no beacoing this BSSID
	U16 rsvd:13;
// DW5
	U16 rtsThreshold;
	U8 shortRetryLimit;
	U8 longRetryLimit;
// DW6
	U8 qosflag;
	U8 SPPflag;
	U8 nonQosMcBcFlag;
	U8 pad;

//DW 7 -8
	SR_INFO_t srInfo;	//Spatial reuse info
} HAL_PFW_ADD_BSS_st;

typedef struct HAL_PFW_ADD_STA_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2-3
	U8 macAddr[6];		///< STA MAC address
	U16 bssIndex;
// DW4
	U16 staIndex;
	U16 maxAmsduLen;	///< 0-no AMSDU aggregation, 3839 or 7935 or 11454 octets
// DW5
	U32 maxAmpduLen;
// DW6
	U16 aid;		///< b15:14  11,
	///< b13:0   valid (1-2007)
	U8 mmss;		///< for HT, VHT: 1us, 2us, 4us, 8us, 16us
	U8 mfpEnabled:1;	///< MFP(Mgmt Frame Protection) enabled
	U8 supp_he_htc:1;	///< HTC+HE support
	U8 insufficientNdp:1;
	U8 sys_bw:5;		//mostly use for 80+80         
// DW7
	U8 bss_color;
	U8 pbac;		///< dot11RSNAPBACRequired - For protected BA agreement

	U8 priority;		///< STA priority. From 0 for the lowest priority, to
	///< SCFG_STA_PRI_NUM - 1) for the highest priority

	U8 maxAmsduSubframes;	///< Maximum number of MSDU in a single AMSDU, only
	///< applied starting from VHT stations.
	///< 0 means unlimited.
// DW8
	U8 wdsflag;		///< 1: wds, 0: not wds
	U8 staflag;		///< 1: station mode, 0: AP mode
	U8 qosflag:4;		///< < 1: Qos enabled, 0: disable
	U8 SPPflag:4;		///< 1: SPP AMSDU enable, 0: disable
	U8 qosInfo;		///< for qos

// DW9 bf related field
	U8 bfType;		// = SMAC_BF_TYPE_HW_EXP;
	U8 csiType;		// = SBF_CSI_TYPE_BF_INFO | SBF_CSI_TYPE_LLTF | SBF_CSI_TYPE_CSI;
	U8 lowestBW;		// Lowest BW that triggers CSI generation
	U8 lowestSS;		//  Lowest SS  that triggers CSI generation

// DW10  sounding related etc
	U8 mu;
	    /** MU field, TRUE OR FALSE **/
	U8 bw;			// < BW for sounding (SU)
	U8 ss;			// < SS for sounding (SU)
	U8 is11acW1MBP:1;	// is a 11ac wave 1 3x3 Apple Macbook Pro that supports only 3ss sounding.
	U8 isModify:1;		// 0 = called from StaInfoDbActionAddEntry, 1 = StaInfoDbActionModifyEntry
	U8 pad2:6;

} HAL_PFW_ADD_STA_st;

typedef struct HAL_PFW_DEL_STA_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2
	U16 staIndex;
	U8 priority;
	U8 rsvd;
} HAL_PFW_DEL_STA_st;

typedef struct HAL_PFW_DEL_BSS_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2
	U16 bssIndex;
	U8 priority;
	U8 rsvd;
} HAL_PFW_DEL_BSS_st;

typedef struct HAL_PFW_CHG_STA_BF_MODE_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2
	U16 staIndex;
	U8 bfType;		// = SMAC_BF_TYPE_HW_EXP;
	U8 pad;
} HAL_PFW_CHG_STA_BF_MODE_st;

typedef struct HAL_PFW_SET_RATE_STA_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2
	U16 staIndex;
	U8 txMode;		///< 0:OFDM, 1:DSSS, 2:HT-MF, 3:HT-GF, 4:VHT
	U8 shortPreamble;	///< DSSS  1:short preamble, 0:long preamble
// DW3
	U8 rateMcs;		///< for HT-MF/HT-GF/VHT - MCS
	///< for OFDM - Rate :0-6Mb, 1-9Mb,  2-12Mb,   3-18Mb, 4-24Mb, 5-36Mb, 6-48Mb, 7-54Mb
	///< for DSSS - Rate :8-1Mb, 9-2Mb, 10-5.5Mb, 11-11Mb
	U8 stbc;		///< for HT - 0, 1, 2
	///< for VHT- 0, 1
	U8 nEss;		///< for HT:  0-3
	U8 nSts;		///< for HT   1-4
	///< for VHT  1-4(our support), note) 1-8(standard)
// DW4
	U8 shortGi;		///< for HT, VHT  note)OFDM-always long GI
	U8 bw;			///< for HT:  0-20MHz, 1-40MHz
	///< for VHT: 0-20MHz, 1-40MHz, 2-80MHz, 3-160MHz
	U8 fecCode;		///< for HT and VHT: 0-BCC, 1-LDPC
	U8 rsvd;
} HAL_PFW_SET_RATE_STA_st;

typedef struct HAL_PFW_START_st {
	HAL_PFW_MSG_HDR_st hdr;
} HAL_PFW_START_st;

typedef struct HAL_PFW_ADD_BA_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2
	U16 staIndex;
	U8 originatorInd;	///< 1: originator, 0:recipient
	U8 tid;
// DW3
	U8 amsduSupported;	///< Based on BA Parameter->amsduSupported
	U8 baAp:7;		///< 1:HAL_BAP_BA_IMMED, 0:HAL_BAP_BA_DELAY
	U8 baForRoamed:1;
	U16 bufSize;
// DW4
	U16 baTimeout;
	U16 ssn;
} HAL_PFW_ADD_BA_st;

typedef struct HAL_PFW_SET_KEY_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2
	U16 intfIndex;		///< Bits[0:11] Index: macId : 0 ~ 31, staid : 0 ~511, Bits[12:15] IndexType: 0: Index is macId, 1: Index is staid
	U16 keyInfo;		///< Bits[0:1]: 0: PTK, 1: GTK, 2: IGTK, Bit2: isDefaultKey  (For WEP Tx), Bit3: isRxGtkKey, Others: reserved
// DW3
	U8 action;		///< 0:get, 1: set, 2: delete
	U8 euMode;		///< 0:CCMP, 1:WAPI, 2:CMAC, 3:BYPASS, 4:GCMP, 5:GMAC, 6:TKIP, 7:WEP
	U8 keyIndex;		///< PTK:0,1. GTK:1,2,3. IGTK: 4,5. WEP: 0,1,2,3
	U8 keyLength;		///< TKIP=16, CCMP/GCMP/CMAC/GMAC=[16, 32], WAPI=32, WEP=[5, 13]
// DW4-11
	U8 key[32];		///< Note: TKIP (total 32 bytes) format is - Key 16 bytes - TxMicKey 8 bytes - RxMicKey8 bytes
// DW12-15
	U8 pn[16];		///< WAPI--16 bytes, WEP: Not used (set to zero), Others: 8 bytes
} HAL_PFW_SET_KEY_st;

typedef struct HAL_SFW_MSG_HDR_st {
	U16 type;		///< HAL_SFW_MSG types
	U16 len;		///< length of the message body, excluding HAL_PFW_MSG_HDR_st
	U8 trid;		///< transaction ID
	U8 rspType;		///< 0: no response, 1:response required
	U16 rsvd;
} HAL_SFW_MSG_HDR_st;

typedef struct HAL_SFW_PS_TRIGGER_st {
	HAL_SFW_MSG_HDR_st hdr;	//'trid' TBD: central maintenance
	U32 *staPtr;
	U16 type;		// 0 - ps poll trigger, 1 - uapsd trigger
	U16 tid;
} HAL_SFW_PS_TRIGGER_st;

typedef struct HAL_SFW_SMPS_st {
	HAL_SFW_MSG_HDR_st hdr;	//'trid' TBD: central maintenance
	U32 *staPtr;
	U8 type;
} HAL_SFW_SMPS_st;

typedef struct HAL_SFW_RSP_st {
// DW0-1
	HAL_SFW_MSG_HDR_st hdr;
// DW2
	U8 result;		///< 1:success, 0:failure
	U8 hdrType;		///< same as 'PFW_MSG_HDR_st->type'
	U16 rsvd;
// DW3
	U32 ret;		///< bssIndex for PFW_ADD_BSS, PFW_UPDATE_BSS
// DW4, 5
	U32 param0;
	U32 param1;
} HAL_SFW_RSP_st;

/**
 * @brief Structure of command response sent by SFW to PFW
 */
typedef struct HAL_PFW_RSP_SFW_st {
// DW0-1
	HAL_SFW_MSG_HDR_st hdr;	///< Header
// DW2
	U8 result;		///< 1:success, 0:failure
	U8 hdrType;		///< HAL_PFW_MSG types
	U16 ret;		///< Return value. Eg: bssIndex for PFW_ADD_BSS, PFW_UPDATE_BSS
	///< staIndex for PFW_ADD_STA
} HAL_PFW_RSP_SFW_st;

#ifdef MFG_FW
typedef struct HAL_MFG_CFG_PER_USER_st {
	U16 STAID;
	U8 mcs;
	U8 nss;
	U8 TF_mcs;
	U8 TF_nss;
	U8 FEC:1;
	U8 reserved1:7;
	U8 RU_Alloc_Size_OFDMA;
	U8 TF_RU_Alloc;
	U8 HESIGB_usercontent_chIdx_RU;
	U16 Power_Scaling;
	U8 TF_Start_SS;
	U8 TF_RSSI_Delta;
	U16 reserved2;
	U32 Payload_Length;
	U32 TF_Payload_Length;
} HAL_MFG_CFG_PER_USER_st;

typedef struct HAL_MFG_CFG_st {
	U8 act_sub;
	U8 Packet_Extension;
	U8 ExtRangeMode;
	U8 Num_RU;		///< OFDMA Number of RU's
	U32 payload;

	// For Rx ack / TF response
	U32 RxAckMode;

	// DL OFDMA - Common
	U8 RU_COMB_CH1[4];
	U8 RU_COMB_CH2[4];
	U16 HESIGBMCS;
	U16 reserved1;

	// OFDMA TF - Common
	U8 TF_Type;
	U8 TF_BANDWIDTH;
	U8 TF_GI_LTF;
	U8 TF_NO_HE_LTF_SYM;
	U8 TF_Max_PE;
	U8 TF_NUM_USERS;
	U8 TF_MU_RTS;
	U8 TF_En_MDRHPF;

	// DL OFDMA / TF Per User Data
	HAL_MFG_CFG_PER_USER_st OFDMA_User_Data[MAX_OFDMA_USERS];

	// Filtered RSSI Readings
	U32 rx_info4;
	U32 rx_info5;
	U32 rx_info6;
	U32 rx_info7;
	U32 rx_info8;
	U32 rx_info9;
	U32 rx_info10;
	U32 rx_info11;
	U32 rx_info12;
	U32 rx_info15;
	U32 rx_info16;
	U32 rx_info17;
	U32 rx_info18;
	U32 rx_info19;
	U32 rx_info20;
	U32 rx_info21;
} HAL_MFG_CFG_st;

typedef struct HAL_MFG_NDPA_NDP_CFG_st {
	U32 Enable:1;		///< 0 = Disable, 1 = Enable
	U32 Mode:4;		///< BB_MODE_t
	U32 BW:2;		///< BW_t
	U32 LDPC:1;		///< FEC_t
	U32 NSS:8;
	U32 MCS:8;
	U32 Reserved:8;
} HAL_MFG_NDPA_NDP_CFG_st;
#endif

#if defined(MFG_FW) || defined(PRD_CSI_DMA)
typedef struct HAL_MFG_CSI_CFG_st {
	U32 Enable_CSI:2;	///< Enable CSI Capture. 1 - Normal Packet. 2 - NDP. 3 - TDDE + CSI. Clears to 0 when complete.
	U32 CSI_Count:15;	///< Processed CSI Count
	U32 Reserved:15;
	U32 CSI_Buf_Loc_DMEM;	///< Location in DMEM to store the CSI Data
	U8 MAC_Address[6];	///< MAC Address for filtering. All 0's means promiscuous mode.
	U8 Packet_Type;		///< Packet Type filtering. 0xFF means all packet types.
	U8 Packet_Subtype;	///< Packet Subtype filtering. 0xFF means all packet subtypes.
} HAL_MFG_CSI_CFG_st;
#endif

typedef struct HAL_BEACON_st {
// DW0
	U16 bcnBodyLen;
	U8 testTxMode;		///< MFG only
	U8 reserved;
// DW1
	U32 startTsf[2];
// DW3
	U32 bcnTbtt[2];
// DW5
	U32 timestamp[2];
// DW7
	U16 bcnInterval;
	U16 capability;
//DW8
	U8 body[SMAC_BCN_BUFSIZE - (4 * 8)];
} HAL_BEACON_st;

typedef struct HAL_SFW_TIME_BEFORE_TBTT_st {
// DW0-1
	HAL_SFW_MSG_HDR_st hdr;
// DW2
	U32 bssBitmap;
} HAL_SFW_TIME_BEFORE_TBTT_st;

typedef struct HAL_SFW_SEND_BB_REG_TO_PFW_st {
// DW0-1
	HAL_SFW_MSG_HDR_st hdr;
// DW2-4
	U32 addr;		// BB Register Address
	U32 mask;		// Bit set implies that the bit will be modified
	U32 value;		// Value to write
} HAL_SFW_SEND_BB_REG_TO_PFW_st;

#ifdef PRD_CSI_DMA
typedef struct HAL_SFW_SEND_PRD_CSI_DMA_TO_PFW_st {
// DW0-1
	HAL_SFW_MSG_HDR_st hdr;
// DW2
	U32 done;		// Done flag
} HAL_SFW_SEND_PRD_CSI_DMA_TO_PFW_st;
#endif

typedef struct hal_pwr_cfg_st {
	U32 TX_ANT_CFG:8;	// TX Antenna Bitmap
	U32 TX_PWR_PRI:11;	// Tx Power for Primary Channel / Antenna ABCD / AB. In dBm s11.4 Format.
	U32 TX_PWR_SEC:11;	// Tx Power for Secondary Channel / Antenna EFGH / EF. In dBm s11.4 Format.
	U32 rsvd0:2;
} hal_pwr_cfg_st;

typedef struct HAL_PFW_MU_GROUP_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2
	U8 usernum;
	U8 type;		//ac, ax
	U8 bw;
	U8 GID;
	U32 bfdllen;
	U16 staIndex[8];
	U8 nss[8];
	U32 steerindex[8];
} HAL_PFW_MU_GROUP_st;

#define MU_GROUP_TYPE_VHT   1
#define MU_GROUP_TYPE_HE    2

typedef enum {
	HAL_SFW_PWR_TBL_CCK = 0,	// 0
	HAL_SFW_PWR_TBL_OFDM,	// 1
	HAL_SFW_PWR_TBL_11ax_MCS0_3,	// 2
	HAL_SFW_PWR_TBL_11ax_MCS4,	// 3
	HAL_SFW_PWR_TBL_11ax_MCS5_7,	// 4
	HAL_SFW_PWR_TBL_11ax_MCS5_8_9,	// 5
	HAL_SFW_PWR_TBL_11ax_MCS5_10_11,	// 6
	HAL_SFW_PWR_TBL_MAX,	// 7
} HAL_SFW_PWR_TBL_IDX_t;

typedef struct HAL_SFW_PWR_ANT_CFG_st {
// DW0-x
	hal_pwr_cfg_st sfw_pwr_ant_tbl[HAL_SFW_PWR_TBL_MAX];
} HAL_SFW_PWR_ANT_CFG_st;

typedef struct HAL_SFW_DRA_NF_STATS_st {
// DW0-x
	U8 index;		// Iteration Index
	U8 bin_count;		// Count of how many NF within boundary
	U8 NF_Offset;		// Computed NF offset from bin_count
	U8 NF_Offset_NoScale;	// Unscaled / Last NF_Offset
// DW1-x
	U8 NF_bin_upper_thresh;	// Upper threshold for NF bin counter, e.g. 62->-62
	U8 NF_bin_lower_thresh;	// Lower threshold for NF bin counter, e.g. 70->-70
	U8 NF_Offset_scaling_factor;	// NF_offset scaling factor. Default 1.5 -> 15. (Factor of 10)
	U8 last;
} HAL_SFW_DRA_NF_STATS_st;

typedef struct HAL_PFW_DEV_CFG_st {
// DW0-1
	HAL_SFW_MSG_HDR_st hdr;
// DW2
	U8 band;
} HAL_PFW_DEV_CFG_st;

/**
 * @brief Structure of message queue
 *
 * This structure contains a @a read @a pointer, @a write @a pointer, and a
 * pointer to start of message buffer array.
 * Producer will fill in the buffer and increment the @a write @a pointer.
 * Consumer will read the buffer and increment the @a read @a pointer.
 *
 */
typedef struct HAL_MSGQ_CTRL_st {
	U32 writeIndex;		///< producer increments this value
	U32 readIndex;		///< consumer increments this value
	 U8(*msgBase)[SMAC_MSGQ_BUFSIZE];	///< pointer to base of array of contiguous memory used to store command payload
	U32 reserved;
} HAL_MSGQ_CTRL_st;

typedef struct HAL_PFW_ADD_BSSCOLOR_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2
	U8 bssColor;		//6bit bss color for this bss_index
	U8 bssIndex;		//same bss index when creating bss. Index to gBss[ ]
	U8 srEnable;		//1: spatial reuse enabled, 0: disabled
	U8 rsvd;
} HAL_PFW_ADD_BSSCOLOR_st;

#define SR_RSSI_LOG_SIZE            4
typedef enum {
	HAL_SFW_SR_GET_RSSI = 0,	// 0
	HAL_SFW_SR_SET_TESTMODE,	// 1
	HAL_SFW_SR_SET_SRPARAM,	// 2
} HAL_PFW_CFG_SR_ACTION_st;

typedef struct HAL_PFW_CFG_SR_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2
	U8 srEnable;		//1: spatial reuse enabled, 0: disabled
	S8 thresNonSrg;		//Spatial reuse threshold in 2's complement. S8 data type range can't exceed -128
	S8 thresSrg;
	U8 action;

// DW3-4
	U8 macaddr[6];
	U8 rsvd2[2];
} HAL_PFW_CFG_SR_st;

/**
 * @brief Checks whether a message queue is empty
 * @param[in] q pointer to HAL_MSGQ_CTRL_st
 */
#define IS_MSGQ_EMPTY(q) ((q)->writeIndex == (q)->readIndex)

/**
 * @brief Checks whether a message queue is full
 * @param[in] q pointer to HAL_MSGQ_CTRL_st
 */
#define IS_MSGQ_FULL(q) ((((q)->writeIndex & (1U<<31)) != ((q)->readIndex & (1U<<31))) && (((q)->writeIndex & SMAC_MSGQ_ENTRY_MASK) == ((q)->readIndex & SMAC_MSGQ_ENTRY_MASK)))

/**
 * @brief Increments write pointer. Shall be invoked by Producer.
 * @param[in] q pointer to HAL_MSGQ_CTRL_st
 * @param[in] n write pointer is incremented by this value
 */
#define INCR_MSGQ_WR_INDEX(q, n) {\
    int wrapBit = (q)->writeIndex & (1U<<31);\
    int val = (q)->writeIndex & SMAC_MSGQ_ENTRY_MASK;\
    int newVal = (val + n) & SMAC_MSGQ_ENTRY_MASK;\
    if (n > 0) {\
        if (newVal <= val) {\
            (q)->writeIndex = newVal | (wrapBit ^ (1U<<31));\
        } else {\
            (q)->writeIndex = newVal | wrapBit;\
        }\
    }\
}

/**
 * @brief Increments read pointer. Shall be invoked by Consumer.
 * @param[in] q pointer to HAL_MSGQ_CTRL_st
 * @param[in] n read pointer is incremented by this value
 */
#define INCR_MSGQ_RD_INDEX(q, n) {\
    int wrapBit = (q)->readIndex & (1U<<31);\
    int val = (q)->readIndex & SMAC_MSGQ_ENTRY_MASK;\
    int newVal = (val + n) & SMAC_MSGQ_ENTRY_MASK;\
    if (n > 0) {\
        if (newVal <= val) {\
            (q)->readIndex = newVal | (wrapBit ^ (1U<<31));\
        } else {\
            (q)->readIndex = newVal | wrapBit;\
        }\
    }\
}

#ifdef DSP_COMMAND
/**
 * @brief Structure of message queue
 *
 * This structure contains a @a read @a pointer, @a write @a pointer, and a
 * pointer to start of message buffer array.
 * Producer will fill in the buffer and increment the @a write @a pointer.
 * Consumer will read the buffer and increment the @a read @a pointer.
 *
 */
typedef struct HAL_DFW_MSGQ_CTRL_st {
	U32 writeIndex;		///< producer increments this value
	U32 readIndex;		///< consumer increments this value
	 U8(*msgBase)[DFW_MSGQ_BUFSIZE];	///< pointer to base of array of contiguous memory used to store command payload
	U32 reserved;
} HAL_DFW_MSGQ_CTRL_st;

typedef struct HAL_PFW_DSP_CMD_st {
// DW0-1
	HAL_PFW_MSG_HDR_st hdr;
// DW2
	U8 cmdIndex;
	U8 cmdFlag;
	U8 cmdPriority;
	U8 cmdResult;
// DW3
	U32 cmdSeqNum;
// DW4
	U32 ptrSrcData;
// DW5
	U32 srcDataLen;
// DW6
	U32 ptrDstData;
// DW7
	U32 dstDataLen;
} HAL_PFW_DSP_CMD_st;

typedef struct HAL_DFW_MSG_HDR_st {
	U16 type;		///< HAL_PFW_MSG types
	U16 len;		///< length of the message body, excluding HAL_PFW_MSG_HDR_st
	U8 trid;		///< transaction ID
	U8 rspType;		///< 0: no response, 1:response required
	U16 rsvd;
} HAL_DFW_MSG_HDR_st;

typedef struct HAL_DFW_RSP_st {
// DW0-1
	HAL_DFW_MSG_HDR_st hdr;
// DW2
	U8 cmdIndex;
	U8 cmdFlag;
	U8 cmdPriority;
	U8 cmdResult;
// DW3
	U32 cmdSeqNum;
// DW4
	U32 ptrSrcData;
// DW5
	U32 srcDataLen;
// DW6
	U32 ptrDstData;
// DW7
	U32 dstDataLen;
} HAL_DFW_RSP_st;

/**
 * @brief Checks whether a message queue is empty
 * @param[in] q pointer to HAL_MSGQ_CTRL_st
 */
#define IS_DFW_MSGQ_EMPTY(q) ((q)->writeIndex == (q)->readIndex)

/**
 * @brief Checks whether a message queue is full
 * @param[in] q pointer to HAL_MSGQ_CTRL_st
 */
#define IS_PFW2DFW_MSGQ_FULL(q) ((((q)->writeIndex & (1U<<31)) != ((q)->readIndex & (1U<<31))) && (((q)->writeIndex & 0x7) == ((q)->readIndex & 0x7)))
#define IS_DFW2PFW_MSGQ_FULL(q) ((((q)->writeIndex & (1U<<31)) != ((q)->readIndex & (1U<<31))) && (((q)->writeIndex & 0xf) == ((q)->readIndex & 0xf)))

/**
 * @brief Increments write pointer. Shall be invoked by Producer.
 * @param[in] q pointer to HAL_MSGQ_CTRL_st
 * @param[in] n write pointer is incremented by this value
 */
#define INCR_PFW2DFW_MSGQ_WR_INDEX(q, n) {\
    int wrapBit = (q)->writeIndex & (1U<<31);\
    int val = (q)->writeIndex & 0x7;\
    int newVal = (val + n) & 0x7;\
    if (n > 0) {\
        if (newVal <= val) {\
            (q)->writeIndex = newVal | (wrapBit ^ (1U<<31));\
        } else {\
            (q)->writeIndex = newVal | wrapBit;\
        }\
    }\
}

/**
 * @brief Increments read pointer. Shall be invoked by Consumer.
 * @param[in] q pointer to HAL_MSGQ_CTRL_st
 * @param[in] n read pointer is incremented by this value
 */
#define INCR_PFW2DFW_MSGQ_RD_INDEX(q, n) {\
    int wrapBit = (q)->readIndex & (1U<<31);\
    int val = (q)->readIndex & 0x7;\
    int newVal = (val + n) & 0x7;\
    if (n > 0) {\
        if (newVal <= val) {\
            (q)->readIndex = newVal | (wrapBit ^ (1U<<31));\
        } else {\
            (q)->readIndex = newVal | wrapBit;\
        }\
    }\
}

/**
 * @brief Increments write pointer. Shall be invoked by Producer.
 * @param[in] q pointer to HAL_MSGQ_CTRL_st
 * @param[in] n write pointer is incremented by this value
 */
#define INCR_DFW2PFW_MSGQ_WR_INDEX(q, n) {\
    int wrapBit = (q)->writeIndex & (1U<<31);\
    int val = (q)->writeIndex & 0xf;\
    int newVal = (val + n) & 0xf;\
    if (n > 0) {\
        if (newVal <= val) {\
            (q)->writeIndex = newVal | (wrapBit ^ (1U<<31));\
        } else {\
            (q)->writeIndex = newVal | wrapBit;\
        }\
    }\
}

/**
 * @brief Increments read pointer. Shall be invoked by Consumer.
 * @param[in] q pointer to HAL_MSGQ_CTRL_st
 * @param[in] n read pointer is incremented by this value
 */
#define INCR_DFW2PFW_MSGQ_RD_INDEX(q, n) {\
    int wrapBit = (q)->readIndex & (1U<<31);\
    int val = (q)->readIndex & 0xf;\
    int newVal = (val + n) & 0xf;\
    if (n > 0) {\
        if (newVal <= val) {\
            (q)->readIndex = newVal | (wrapBit ^ (1U<<31));\
        } else {\
            (q)->readIndex = newVal | wrapBit;\
        }\
    }\
}

#endif				//DSP_COMMAND

#endif				//_SHAL_MSG_H_
