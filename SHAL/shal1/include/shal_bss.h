/** @file shal_bss.h
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
 * @brief SMAC HAL BSS-related data structures and API.
 */

#ifndef _SHAL_BSS_H_
#define _SHAL_BSS_H_

#define BSS_INDEX(x)            (((U32)(x) - ((U32)&gBss[0])) / sizeof(SMAC_BSS_ENTRY_st))

typedef struct WIFI_st {
	U8 band;		///< 0: 2.4G  1: 5G
	U8 sifs;
} WIFI_st;

/**
 * @brief Structure contains BSS information
 *
 * This structure is used by PFW to configure SFW
 */
typedef struct SMAC_BSS_ENTRY_st {
	U8 macAddr[6];		///< BSSID = mac Address of AP
	U16 capaInfo;		///< b0:  ESS: Transmitter is AP
	///< b4:  privacy
	///< b10: short slot time in use
// DW2
	U16 bssBasicRate;	///< b0: 1M, b1: 2M, b2: 5.5M, b3: 6M,
	///< b4: 9M, b5:11M, b6: 12M,  b7: 18M,
	///< b8:24M, b9:36M, b10:48M,  b11:54M
	U16 lowestRateMcs;	///< lowest basic rate in [rateMcs]
// DW3
	U32 ackTxTime;		///< pre-calculated ackTxTime for EIFS support
// DW4
	U16 rtsThreshold;	///< dot11, CRC(4) + SecurityOverload
	U8 shortRetryLimit;	///< dot11
	U8 longRetryLimit;	///< dot11
// DW5
	U16 ePifs[2];		///< from TX_RDY_DN to 2nd slot boundary
	///< [0] - DSSS, [1] -OFDM
// DW6
	U8 sifs;		///< 16us or 10us
	U8 sigExtension;	///< 0us or 6us
	U16 SN;			///< for mgmt/group-addressed QoS Data/non-QoS data
// DW7
	U32 timeStampDly;	///< for timestamp in Beacon/Prob Response/
// DW8
	U32 bcnTsf;
// DW9
	U32 bcnTsfMsb;		///< MSB32 of tsf
// DW10
	U32 bcnInterval;	///< [us]
// DW11
	U8 bcnPifs;		///< [us]
	U8 DSbit;		///< bit0-1: Distribution bit. 0x1- toDS:1, fromDS:0; 0x2- toDS:0, fromDS:1; 0x3: wds
	///< bit2: 0-AP mode, 1-station mode
	U16 igtkEuModeCtrl;	///< pre-assigned for eu_desc_rx0 - modeCtrl[15:0] for MICsize[9:8],Ksize[7:6],Mode[2:0]
// DW12
	U8 igtkEuMode;		///< 0:CCMP, 1:WAPI, 2:CMAC, 3:BYPASS,
	///< 4:GCMP, 5:GMAC, 6:TKIP, 7:WEP
	U8 igtkIdx;
	U8 igtkId[2];
// DW13
	U32 igtkKey[2][8];	///< [keyIdx]
// DW29
	U8 igtkPn[8];		///< PN for IGTKSA
// DW31
	U16 staIndex;		///< Used in STA mode to link to gSta[] this bss is tied to
	U8 bssIndex;
	U8 qosMask;		///< 0x8F - SPP AMSDU enabled
	///< 0x0F - SPP AMSDU disabled
	///< 0: no QoS in new RTL
// DW32
	U16 NonQosPeerCnt;	///< Keep track non QoS peer for BSS bcast/mcast in QoS pkt decision making
	U8 bssColor:6;		///< BSS color for this bss entry
	U8 srEnable:2;		///< 1: Spatial reuse enabled, 0: disabled
	U8 ul_done_flag;
// DW33
	U32 ul_next_tsf;
} SMAC_BSS_ENTRY_st;

#endif //_SHAL_BSS_H_
