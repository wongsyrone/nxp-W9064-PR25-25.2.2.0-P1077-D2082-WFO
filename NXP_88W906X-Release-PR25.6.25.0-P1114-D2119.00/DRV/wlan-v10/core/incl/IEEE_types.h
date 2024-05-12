/** @file IEEE_types.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2020 NXP
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

/*****************************************************************************
*
* Purpose:
*    This file contains definitions relating to messages specified in the
*    IEEE 802.11 spec.
*
*****************************************************************************/

#ifndef _IEEE_TYPES_H_
#define _IEEE_TYPES_H_

/*============================================================================= */
/*                               INCLUDE FILES */
/*============================================================================= */
#include "wltypes.h"

/*============================================================================= */
/*                            PUBLIC DEFINITIONS */
/*============================================================================= */

/*--------------------------------------------------------------*/
/* Reason Codes - these codes are used in management message    */
/* frame bodies to indicate why an action is taking place (such */
/* as a disassociation or deauthentication).                    */
/*--------------------------------------------------------------*/
#define IEEEtypes_REASON_RSVD                     cpu_to_le16(0)
#define IEEEtypes_REASON_UNSPEC                   cpu_to_le16(1)
#define IEEEtypes_REASON_PRIOR_AUTH_INVALID       cpu_to_le16(2)
#define IEEEtypes_REASON_DEAUTH_LEAVING           cpu_to_le16(3)
#define IEEEtypes_REASON_DISASSOC_INACTIVE        cpu_to_le16(4)
#define IEEEtypes_REASON_DISASSOC_AP_BUSY         cpu_to_le16(5)
#define IEEEtypes_REASON_CLASS2_NONAUTH           cpu_to_le16(6)
#define IEEEtypes_REASON_CLASS3_NONASSOC          cpu_to_le16(7)
#define IEEEtypes_REASON_DISASSOC_STA_HASLEFT     cpu_to_le16(8)
#define IEEEtypes_REASON_CANT_ASSOC_NONAUTH       cpu_to_le16(9)
#ifdef IEEE80211H
/***************IEEE802dot11h*****************/
#define IEEEtypes_REASON_DISASSOC_PWR_CAP_UNACCEPT  cpu_to_le16(10)
#define IEEEtypes_REASON_DISASSOC_SUP_CHA_UNACCEPT  cpu_to_le16(11)
#endif				/* IEEE80211H */
/***************WPA Reasons*******************/
#define IEEEtypes_REASON_INVALID_IE               cpu_to_le16(13)
#define IEEEtypes_REASON_MIC_FAILURE              cpu_to_le16(14)
#define IEEEtypes_REASON_4WAY_HANDSHK_TIMEOUT     cpu_to_le16(15)
#define IEEEtypes_REASON_GRP_KEY_UPD_TIMEOUT      cpu_to_le16(16)
#define IEEEtypes_REASON_IE_4WAY_DIFF             cpu_to_le16(17)
#define IEEEtypes_REASON_INVALID_MCAST_CIPHER     cpu_to_le16(18)
#define IEEEtypes_REASON_INVALID_UNICAST_CIPHER   cpu_to_le16(19)
#define IEEEtypes_REASON_INVALID_AKMP             cpu_to_le16(20)
#define IEEEtypes_REASON_UNSUPT_RSNE_VER          cpu_to_le16(21)
#define IEEEtypes_REASON_INVALID_RSNE_CAP         cpu_to_le16(22)
#define IEEEtypes_REASON_8021X_AUTH_FAIL          cpu_to_le16(23)
/*********************************************/

/*------------------------------------------------------------*/
/* Status Codes - these codes are used in management message  */
/* frame bodies to indicate the results of an operation (such */
/* as association, reassociation, and authentication).        */
/*------------------------------------------------------------*/
#define IEEEtypes_STATUS_SUCCESS                 cpu_to_le16(0)
#define IEEEtypes_STATUS_UNSPEC_FAILURE          cpu_to_le16(1)
#define IEEEtypes_STATUS_CAPS_UNSUPPORTED        cpu_to_le16(10)
#define IEEEtypes_STATUS_REASSOC_NO_ASSOC        cpu_to_le16(11)
#define IEEEtypes_STATUS_ASSOC_DENIED_UNSPEC     cpu_to_le16(12)
#define IEEEtypes_STATUS_UNSUPPORTED_AUTHALG     cpu_to_le16(13)
#define IEEEtypes_STATUS_RX_AUTH_NOSEQ           cpu_to_le16(14)
#define IEEEtypes_STATUS_CHALLENGE_FAIL          cpu_to_le16(15)
#define IEEEtypes_STATUS_AUTH_TIMEOUT            cpu_to_le16(16)
#define IEEEtypes_STATUS_ASSOC_DENIED_BUSY       cpu_to_le16(17)
#define IEEEtypes_STATUS_ASSOC_DENIED_RATES      cpu_to_le16(18)
#define IEEEtypes_STATUS_ASSOC_REJECTED_TEMPORARILY cpu_to_le16(30)
#define IEEEtypes_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION cpu_to_le16(31)
#define IEEEtypes_STATUS_REQUEST_DECLINED        cpu_to_le16(37)
#define IEEEtypes_STATUS_INVALID_PARAMETERS      cpu_to_le16(38)

/* */
/* 802.11b additions */
/* */
#define IEEEtypes_STATUS_ASSOC_DENIED_NOSHORT     cpu_to_le16(19)
#define IEEEtypes_STATUS_ASSOC_DENIED_NOPBCC      cpu_to_le16(20)
#define IEEEtypes_STATUS_ASSOC_DENIED_NOAGILITY   cpu_to_le16(21)

#ifdef IEEE80211H
/* */
/* 802.11h additions */
/* */
#define IEEEtypes_STATUS_ASSOC_SPEC_MGMT_REQUIRED  cpu_to_le16(22)
#define IEEEtypes_STATUS_ASSOC_PWE_CAP_REQUIRED    cpu_to_le16(23)
#define IEEEtypes_STATUS_ASSOC_SUP_CHA_REQUIRED    cpu_to_le16(24)
#endif				/* IEEE80211H */

/* */
/* 802.11g additions */
/* */
#define IEEEtypes_STATUS_ASSOC_DENIED_NOSHORTSLOTTIME  cpu_to_le16(25)
#define IEEEtypes_STATUS_ASSOC_DENIED_NODSSSOFDM       cpu_to_le16(26)

/* */
/* 802.11i additions */
/* */
#define IEEEtypes_STATUS_ASSOC_DENIED_INVALID_IE                        cpu_to_le16(40)
#define IEEEtypes_STATUS_ASSOC_DENIED_INVALID_GRP_CIPHER                cpu_to_le16(41)
#define IEEEtypes_STATUS_ASSOC_DENIED_INVALID_PAIRWISE_CIPHER           cpu_to_le16(42)
#define IEEEtypes_STATUS_ASSOC_DENIED_INVALID_AKMP                      cpu_to_le16(43)
#define IEEEtypes_STATUS_ASSOC_DENIED_INVALID_RSN_IE                    cpu_to_le16(44)
#define IEEEtypes_STATUS_ASSOC_DENIED_INVALID_RSN_IE_CAP                cpu_to_le16(45)
#define IEEEtypes_STATUS_ASSOC_DENIED_CIPHER_SUITE_REJECTED             cpu_to_le16(46)

#ifdef QOS_FEATURE
#define IEEEtypes_STATUS_QOS_UNSPECIFIED_FAIL     cpu_to_le16(32)
#define IEEEtypes_STATUS_QOS_INSUFFICIENT_BW      cpu_to_le16(33)
#define IEEEtypes_STATUS_QOS_POOR_CONDITIONS      cpu_to_le16(34)
#define IEEEtypes_STATUS_QOS_NOT_QOSAP            cpu_to_le16(35)
#define IEEEtypes_STATUS_QOS_REFUSED              cpu_to_le16(37)
#define IEEEtypes_STATUS_QOS_INVALID_PARAMS       cpu_to_le16(38)
#define IEEEtypes_STATUS_QOS_TIMEOUT  			cpu_to_le16(39)
#define IEEEtypes_STATUS_QOS_DLP_NOT_ALLOW       cpu_to_le16( 41)
#define IEEEtypes_STATUS_QOS_DLP_NOT_PRESENT      cpu_to_le16(42)
#define IEEEtypes_STATUS_QOS_NOT_QSTA             cpu_to_le16(43)

#endif
#include "ieeetypescommon.h"
typedef struct IEEEtypes_StartCmd_t {
	IEEEtypes_SsId_t SsId;
	IEEEtypes_Bss_t BssType;
	IEEEtypes_BcnInterval_t BcnPeriod;
	IEEEtypes_DtimPeriod_t DtimPeriod;
	IEEEtypes_SsParamSet_t SsParamSet;
	IEEEtypes_PhyParamSet_t PhyParamSet;
	UINT16 ProbeDelay;
	IEEEtypes_CapInfo_t CapInfo;
	IEEEtypes_DataRate_t BssBasicRateSet[IEEEtypes_MAX_DATA_RATES_G];
	IEEEtypes_DataRate_t OpRateSet[IEEEtypes_MAX_DATA_RATES_G];
	IEEEtypes_DataRate_t BssBasicRateSet2[IEEEtypes_MAX_DATA_RATES_G];
	IEEEtypes_DataRate_t OpRateSet2[IEEEtypes_MAX_DATA_RATES_G];
	IEEEtypes_SsId_t SsId2;
#ifdef IEEE80211H
	IEEEtypes_COUNTRY_IE_t Country;
#endif				/* IEEE80211H */
	u8 sae_pwe;
} PACK_END IEEEtypes_StartCmd_t;
/* */
/* Start request message sent from the SME to start a new BSS; the BSS */
/* may be either an infrastructure BSS (with the MAC entity acting as the */
/* AP) or an independent BSS (with the MAC entity acting as the first */
/* station in the IBSS) */
/* */

#endif				/* _IEEE_TYPES_H_ */
