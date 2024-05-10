/** @file shal_sta.h
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
 * @brief SMAC STA database management structures and APIs (shared between SFW and PFW).
 */

#ifndef _SHAL_STA_H_
#define _SHAL_STA_H_

#ifndef __KERNEL__

#pragma anon_unions

#endif

#ifdef __CC_ARM
#pragma anon_unions
#endif

#define MODE_ACT_UL_OFDMA          BIT(0)

typedef enum {
	STA_PWR_AWAKE = 0,	///< Power Save State = Awake
	STA_PWR_ASLEEP = 0x1,	///< Power Save State = Asleep and resting
	STA_PWR_PSPOLL = 0x2,	///< Power Save State = PS-POLL Service Period in progress
	STA_PWR_UAPSD = 0x4,	///< Power Save State = U-APSD Service Period in progress
	STA_PWR_UAPSD_PSPOLL = (0x6),	///< Power Save State = U-APSD Service Period in progress and also PS_POLL is received
} STA_PW_t;

typedef enum {
	SMAC_BF_TYPE_HW_EXP = 0,
	SMAC_BF_TYPE_HW_IMP,
	SMAC_BF_TYPE_SSM,
	SMAC_BF_TYPE_CSI,
	SMAC_BF_TYPE_NONE
} SMAC_BF_TYPE_t;

typedef struct STA_RX_BA_st {
	U8 pbac;		///< Protected BA agreement is enabled after association procedure(dot11RSNAPBACRequired)
	U8 htCapa;		///< for HT(1)/VHT(2) from (Re)Assoc Req
	U8 tidNum;
	U8 idxLast;
	U8 tidMap[SMAC_QID_PER_STA];	///< stores tid + 1 value 
	U32 policyBM;		///< Bitmap for BA agreement(2bits/TID,1-Immediate,2-Delayed...) from ADDBA
} STA_RX_BA_st;

typedef struct SMAC_STA_ENTRY_st {
#ifndef DRV_SKIP_DEFINE
	LIST_ELEM_st link;
#else
	U32 reserved[2];
#endif
// DW2
	U8 txMode;		///< 0:OFDM, 1:DSSS, 2:HT-MF, 3:HT-GF, 4:VHT
	U8 shortPreamble;	///< DSSS  1:short preamble, 0:long preamble
	U16 maxAmsduLen;	///< 0-no AMSDU aggregation, 3839 or 7935 or 11454 octets
// DW3
	U16 mmssByte;		///< min. MPDU start space [bytes]
	U8 rateMcs;		///< for HT-MF/HT-GF/VHT - MCS
	///< for OFDM - Rate :0-6Mb, 1-9Mb,  2-12Mb,   3-18Mb, 4-24Mb, 5-36Mb, 6-48Mb, 7-54Mb
	///< for DSSS - Rate :8-1Mb, 9-2Mb, 10-5.5Mb, 11-11Mb
	U8 rtsRate;		///< Basic rate. Same as rateMcs
// DW4
	U8 stbc:2;		///< for HT - 0, 1, 2
	///< for VHT- 0, 1
	U8 nDltf:4;		///< for HT:  1-4, N_DLTF
	///< for VHT: 1-8, N_BHTLTF
	U8 nEss:2;		///< for HT:  0-3
	U8 nSts:4;		///< for HT   1-4
	///< for VHT  1-8
	///< for HE   1-8
	U8 fecCode:1;		///< for HT and VHT: 0-BCC, 1-LDPC
	U8 nEs:3;		///< for HT:  1,2 BBC encoders
	///< for VHT: 1,2,3,4,6 BCC encoders
	U8 shortGi:2;		///< for HT (0 - 1), VHT (0 - 1), HE (0 - 3)
	U8 bw:6;		///< for HT:  0-20MHz, 1-40MHz
	///< for VHT: 0-20MHz, 1-40MHz, 2-80MHz, 3-160MHz
	U8 minAmsduSubframe;
// DW5
	U16 nDbps;		///< for HT, VHT, OFDM
	U8 mmss;		///< for HT, VHT: 1us, 2us, 4us, 8us, 16us
	U8 tPreamble;		///< HT, VHT, OFDM, DSSS : from PPDU start before data symbol
	///<                      based on 'rateMcs'
// DW6
	U32 maxAmpduLen;	///< for HT : 2^16 - 1
	///< for VHT: 2^20 - 1
// DW7
	U16 aid;		///< b15:14  11,
	///< b13:0   valid (1-2007)
	U16 euModeCtrl;		///< pre-assigned for eu_desc_rx0 - Ksize[7:6],Mode[2:0]
// DW8
	U8 DSbit;		///< bit0-1: Distribution bit. 0x1- toDS:1, fromDS:0; 0x2- toDS:0, fromDS:1; 0x3: wds
	///< bit2: 0-AP mode, 1-station mode
	U8 euMode;		///< 0:CCMP, 1:WAPI, 2:CMAC, 3:BYPASS,
	///< 4:GCMP, 5:GMAC, 6:TKIP, 7:WEP
	U8 keyId[2];
// DW9
	U8 pn[16];		///< PN for PTKSA: WAPI: 16 bytes, WEP: Not used, Others: 6 bytes
// DW13
	U32 key[2][8];		///< [keyIdx]
// DW29
	U8 keyRecIdx:4;		///< 0 or 1
	U8 pn_inc:4;		///< 1: Mcast or 2:Ucast for WAPI
	U8 txd4Overload;	///< DLM(4)+FCS(4)+Security Header&MIC(n)
	U8 qosMask;		///< 0x8F - SPP AMSDU enabled
	///< 0x0F - SPP AMSDU disabled
	///< 0: no QoS in new RTL
	U8 muGrpId;		///< for MU, 0: it belongs to no MU group
// DW30
#ifndef DRV_SKIP_DEFINE
	void *bssidInfo;	///< AP: SMAC_BSS_ENTRY_st, STA: 0->Self SMAC_STA_ENTRY_st(AP) for associated BSSID
#else
	U32 bssidInfo;		//Pointer in DRV is 8 bytes
#endif
// DW31
	U8 state;		///< State 1: Initial start state, unauthenticated, unassociated. C1
	///< State 2: Authenticated, not associated. C1,2
	///< State 3: Authenticated and associated (Pending RSN Authentication). C1,2,3
	///< State 4: Authenticated and associated. C1,2,3
	///< 0xFF: Disconnected
	U8 mfpEnabled;		///< MFP enabled
	U16 lastSeqCtrl[16 + 3];	///< 0-15:QoS Data, 16-non-QoS, 17-mgmt, 18-mgmtTimePriority
// DW41
	STA_RX_BA_st rxBa;	///< RX BA maintenance 16B
// DW45
	U32 baInfoDdrAddr;	///< L2 buffer Address that contains RXD_STA_TID_st
// DW46
	U8 psmpState:1;		///< 0 = Not under PSMP Mode, 1 = Under PSMP Mode
	U8 dualCtsProtection:1;	///< 0 = disabled, 1=enabled
	U8 DCM:1;		///< Dual Carrier Modulation. 0: Disabled, 1: Enabled
	U8 pad0:1;		///<
	U8 cb_mode:4;		///< 0: non-cb, 1: cb active, 2 cb inactive
	U8 pad1;
	U8 macAddr[6];		///< workaround because gTxdSta[] is corrupted by HW
// DW48
	U8 maxAmsduSubframesConf;	///< Configured by host
	///< Maximum number of MSDU in a single AMSDU, only
	///< applied starting from VHT stations.
	///< 0 means unlimited.
	U8 maxAmsduSubframesUsing;	///< Currently used by FW. This is recalculated based on rate
	///< and limitation
	U8 pwrState;		//enum in DRV is 4 bytes
	U8 trigger;		//b[0-3]: ACs triggered, b[4-7]: USP is about to end. QoS NULL/ESOP=1 is added.
// DW49
	U8 qosInfo;
	U8 bssColor;
	U16 SeqCtrl;
// DW50
	U32 tkipMic[2];
	U32 tkipData0;
	U32 tkipData1;
	U32 tkipData2;
// DW55
	U16 rssiInit:1;		//0: not start, 1: rssi updated,
	U16 hdrmShown:1;
	U16 uphDeActivated:1;
	U16 minTxPwer:1;
	U16 supp_he_htc:1;
	U16 ul_queBufFrom:1;	//0: from Qos, 1: from A-Control
	U16 hdrmPwr:5;		//0~31 db
	U16 bsrBuffShown:1;
	U16 isQosNull:1;
	U16 tf_cnt_idx:1;
	U16 rxbw:2;

	U8 rxmcs:4;
	U8 rxnss:2;
	U8 rsvd2:2;
	S8 rssi;
// DW56 - DW57
	union {
		U8 qosBuff[8];	//unit: 256 bytes, 255 is unknown size
		U64 buffSizeInfo;
	};
//DW58 - DW59
	U16 tf_goodFcsCnt[2];
	U16 tf_badFcsCnt[2];

//DW60
	U32 bsrBuff;		//[0:3]: ACI Bitmap, [4:5]: Delta TID, [6:7]: ACI High, [10:17]: Queue Size High, [18:25]: Queue Size All
//DW61
	S8 he_rssi;
	U8 rsvd3[3];
} SMAC_STA_ENTRY_st;

#define DSBIT_STAMODE_SHIFT     2
#define DSBIT_DS_BIT(x)         (x & 0x3)
#define DSBIT_STA_BIT(x)        ((x >> DSBIT_STAMODE_SHIFT) & 0x1)
#define STA_INDEX(x)            (((U32)(x) - ((U32)&gSta[0])) / sizeof(SMAC_STA_ENTRY_st))

typedef struct GRP_ENTRY_st {
	U8 grpId;
	U8 muCacheId;
	U8 nDltf;
	U8 tPreamble;
// DW1
	U16 staIndex[4];	///< [muPos]
// DW3
	U8 nSts[4];		///< [muPos]
// DW4
	U16 nDbps[4];		///< [muPos]
// DW6
	U16 mmssByte[4];	///< [muPos]
// DW8
	U32 maxAmpduLen[4];	///< [muPos]
} GRP_ENTRY_st;

#endif // _SHAL_STA_H_
