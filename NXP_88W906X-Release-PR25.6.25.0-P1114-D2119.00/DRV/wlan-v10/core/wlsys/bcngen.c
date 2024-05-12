/** @file bcngen.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2021 NXP
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

/*
 *
 * Purpose:
 *    This file contains the implementations of the beacon update functions.
 *
 */

#include "wltypes.h"
#include "IEEE_types.h"
#include "osif.h"
#include "mib.h"
#include "ds.h"
#include "tkip.h"
#include "StaDb.h"
#include "macmgmtap.h"
#include "qos.h"
#include "wlmac.h"

#include "bcngen.h"

#include "macMgmtMlme.h"

#include "wl_macros.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "ap8xLnxFwcmd.h"
#include "domain.h"

#ifdef SUPPORTED_EXT_NSS_BW
#include "mlmeApi.h"
#endif

#define bcngen_TBTT_EVENT   (1 >> 0 )
#define BCNGEN_EVENT_TRIGGERS bcngen_TBTT_EVENT

typedef enum {
	COPY_FULL,
	COPY_END,
	COPY_BYTE
} CopyMode_e;

macmgmtQ_MgmtMsg_t Bcn;		// __attribute__ ((section (".sdbuf")));
macmgmtQ_MgmtMsg_t *BcnBuffer_p = (macmgmtQ_MgmtMsg_t *) & Bcn;
macmgmtQ_MgmtMsg_t Bcn2;	// __attribute__ ((section (".sdbuf")));
macmgmtQ_MgmtMsg_t *BcnBuffer_p2 = (macmgmtQ_MgmtMsg_t *) & Bcn2;

extern IEEEtypes_DataRate_t OpRateSet[IEEEtypes_MAX_DATA_RATES_G];
extern IEEEtypes_DataRate_t BasicRateSet[IEEEtypes_MAX_DATA_RATES_G];
extern UINT32 BasicRateSetLen;
extern UINT32 OpRateSetLen;
UINT8 *BcnErpInfoLocation_p, *BcnErpInfoLocation_p2;
UINT8 *PrbrspErpInfoLocation_p, *PrbrspErpInfoLocation_p2;

#ifdef FLEX_TIME
UINT8 *BcnIntervalLocation_p, *BcnIntervalLocation_p2;
UINT8 *ProbeIntervalLocation_p, *ProbeIntervalLocation_p2;
#endif

UINT8 *Bcnchannel;
UINT8 *Bcnchannel2;
extern UINT8 freq54g;

#ifdef IEEE80211H
typedef struct _CHANNELSWITCH_CTRL {
	BOOLEAN isActivated;
	UINT8 targetChannel;
} CHANNELSWITCH_CTRL;

static CHANNELSWITCH_CTRL ChannelSwitchCtrl = { FALSE, 0 };

IEEEtypes_StartCmd_t StartCmd_update;
SINT8 BcnTxPwr = 0xd;
SINT8 ProbeRspTxPwr = 0xd;
UINT8 *BcnCSACount;
UINT8 *ProbeCSACount;
UINT8 bcn_reg_domain = DOMAIN_CODE_FCC;
#endif				/* IEEE80211H */

IEEEtypes_Tim_t Tim, Tim2;
IEEEtypes_Tim_t *TimPtr, *TimPtr2;
UINT8 TrafficMap[251], TrafficMap2[251];

IEEEtypes_MacAddr_t BcastAddr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

extern UINT32 CBP_QID;
extern UINT32 BRATE_QID;
extern UINT8 BarkerPreambleSet;
extern UINT8 RfSwitchChanA, RfSwitchChanG;
UINT32 EDCA_Beacon_Counter;
UINT8 *BcnWMEInfoElemLocation_p;
UINT8 *BcnWMEParamElemLocation_p;
UINT8 *PrbWMEParamElemLocation_p;
UINT8 *PrbWMEInfoElemLocation_p;
#ifdef QOS_FEATURE
extern mib_QAPEDCATable_t mib_QAPEDCATable[4];
#endif

#ifdef FLEX_TIME
UINT8 AGinterval = 20;
extern UINT32 flexmode_duration;
#else
UINT8 AGinterval = 34;		/*46 */
#endif

#ifdef SOC_W906X
void Init_Mbssid_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_Mbssid_Element_t * element);
u8 Add_NonTxProfile_IEs(vmacApInfo_t * vmacSta_p, u8 * pnext);
UINT8 isMbssidConfigured(struct net_device *netdev);
#endif
#ifdef COUNTRY_INFO_SUPPORT
#ifndef IEEE80211_DH

typedef struct _DomainChannelEntry {
	UINT8 FirstChannelNo;
	UINT8 NoofChannel;
	UINT8 MaxTransmitPw;
} PACK_END DomainChannelEntry;

typedef struct _DomainCountryInfo {
	UINT8 CountryString[3];
	UINT8 GChannelLen;
	DomainChannelEntry DomainEntryG[1]; /** Assume only 1 G zone **/
	UINT8 AChannelLen;
	DomainChannelEntry DomainEntryA[20]; /** Assume max of 5 A zone **/
} PACK_END DomainCountryInfo;
#endif				//IEEE80211_DH
#endif

#ifdef UR_WPA
IEEEtypes_RSN_IE_t thisStaRsnIEUr;
IEEEtypes_RSN_IE_WPA2_t thisStaRsnIEWPA2Ur;
extern UINT8 mib_urMode;
extern UINT8 mib_wbMode;
#endif

//UINT32 txbfcap = 0x1807ff1f;
UINT32 txbfcap = 0x18040410;	// temp disable 11n BFmee cap
extern BOOLEAN wlSet11aRFChan(UINT32 chan);
extern void wlQosChangeSlotTimeMode(void);
extern void wlChangeSlotTimeMode(void);

/**
 * Fill Beacon Buffer with ERP parameters
 *
 * @param pBcnBuf Pointer to start of ERP parameters in beacon buffer
 * @return The number of bytes written
 */

#ifdef ERP

inline UINT16 ErpBufUpdate(UINT8 * pBcnBuf, IEEEtypes_StartCmd_t * StartCmd, UINT16 MsgSubType, IEEEtypes_ExtSuppRatesElement_t * ExtSuppRateSet_p)
{
	UINT8 *pNextElement = pBcnBuf;
	IEEEtypes_ExtSuppRatesElement_t *pExtSuppRate;
	IEEEtypes_ERPInfoElement_t *pErpInfo;

	UINT16 byteCnt = 0;
	UINT16 totalLen = 0;

	/* ERP Info */
	pErpInfo = (IEEEtypes_ERPInfoElement_t *) pNextElement;
	pErpInfo->ElementId = ERP_INFO;
	pErpInfo->Len = 1;
	*(UINT8 *) & pErpInfo->ERPInfo = 0;
	if (MsgSubType == IEEE_MSG_PROBE_RSP) {
		PrbrspErpInfoLocation_p = (UINT8 *) & pErpInfo->ERPInfo;	/* Will be used later probe rsp update when
										 * b only stations associate */
	} else {
		BcnErpInfoLocation_p = (UINT8 *) & pErpInfo->ERPInfo;
	}
	byteCnt = sizeof(IEEEtypes_InfoElementHdr_t) + pErpInfo->Len;

	totalLen += byteCnt;
	pNextElement += byteCnt;
	pExtSuppRate = (IEEEtypes_ExtSuppRatesElement_t *) pNextElement;
	*pExtSuppRate = *ExtSuppRateSet_p;

	byteCnt = sizeof(IEEEtypes_InfoElementHdr_t) + ExtSuppRateSet_p->Len;

	totalLen += byteCnt;
	return totalLen;
}

/* ErpInfo is updated when the first NonErp station associates and when the last NonErp station
 * leaves the BSS */

extern UINT32 BStnAroundCnt;
extern UINT32 BAPCount;
void bcngen_UpdateBeaconErpInfo(vmacApInfo_t * vmacSta_p, BOOLEAN SetFlag)
{
	int val = 0;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

	if (SetFlag) {
#ifdef DISABLE_B_AP_CHECK
		if (vmacSta_p->bOnlyStnCnt)
#else
		if ((vmacSta_p->bOnlyStnCnt) || (BAPCount > 0))
#endif
		{
			val = 0x3;
		} else if (BStnAroundCnt && !vmacSta_p->bOnlyStnCnt) {
			val = 0x2;
		}

		if (vmacSta_p->BarkerPreambleStnCnt > 0)
			val = 0x7;

	} else {
		if (!vmacSta_p->BarkerPreambleStnCnt) {
#ifdef DISABLE_B_AP_CHECK
			if (vmacSta_p->bOnlyStnCnt || BStnAroundCnt)
#else
			if (vmacSta_p->bOnlyStnCnt || BAPCount || BStnAroundCnt)
#endif
			{
				val = wlpptr->wlpd_p->BcnErpVal & ~0x4;
			} else
				val = 0;
		} else
			return;
	}
	if (val != wlpptr->wlpd_p->BcnErpVal) {
		wlpptr->wlpd_p->BcnErpVal = val;
		wlFwSetGProt(vmacSta_p->dev, val);
	}
}
#endif

#ifdef QOS_FEATURE
/******************************************************************************
 *
 * Name: bcngen_UpdateQBSSLoad
 *
 * Description: Will append the QBSS Load Info Element to the Beacon.
 *
 *
 * Conditions For Use:
 *    When the QoSOptImpl and the QBSSLoadOptImpl are true.
 *
 * Arguments:
 *    None.
 *
 * Return Value:
 *    The offset to the beacon buffer after the new information element is added.
 *
 * Notes:
 *    None.
 *
 * PDL:
 *
 * END PDL
 *
 *****************************************************************************/
inline UINT16 bcngen_UpdateQBSSLoad(vmacApInfo_t * vmacSta_p, UINT8 * pBcnBuf)
{
	MIB_STA_CFG *mib_StaCfg_p = vmacSta_p->Mib802dot11->StationConfig;
	QBSS_load_t *pQBSSLoad = (QBSS_load_t *) pBcnBuf;

	if (!*(vmacSta_p->Mib802dot11->QoSOptImpl) || !mib_StaCfg_p->QBSSLoadOptImpl)
		return 0;
	pQBSSLoad->ElementId = QBSS_LOAD;
	pQBSSLoad->Len = 5;
	pQBSSLoad->sta_cnt = AssocStationsCnt;
	//Currently assign a default channel utilization of zero.
	pQBSSLoad->channel_util = 0;
	pQBSSLoad->avail_admit_cap = GetChannelCapacity();
	return sizeof(QBSS_load_t);
}

/******************************************************************************
 *
 * Name: bcngen_UpdateEDCAParamSet
 *
 * Description: Will append the QBSS Load Info Element to the Beacon.
 *
 *
 * Conditions For Use:
 *    When the QoSOptImpl and the QBSSLoadOptImpl are true and for 2 DTIM intervals after EDCA has been
 *    changed.
 *
 * Arguments:
 *    None.
 *
 * Return Value:
 *    The offset to the beacon buffer after the new information element is added.
 *
 * Notes:
 *    None.
 *
 * PDL:
 *
 * END PDL
 *
 *****************************************************************************/
inline UINT16 bcngen_AppendEDCAParamSet(vmacApInfo_t * vmacSta_p, UINT8 * pBcnBuf)
{
	MIB_STA_CFG *mib_StaCfg_p = vmacSta_p->Mib802dot11->StationConfig;
	EDCA_param_set_t *pEDCA_param_set = (EDCA_param_set_t *) pBcnBuf;

	if (!*(vmacSta_p->Mib802dot11->QoSOptImpl))
		return 0;
	pEDCA_param_set->ElementId = EDCA_PARAM_SET;
	pEDCA_param_set->Len = 18;
#ifdef WMM_PS_SUPPORT
	//pEDCA_param_set->QoS_info.EDCA_param_set_update_cnt = EDCA_param_set_update_cnt;
	pEDCA_param_set->QoS_info.EDCA_param_set_update_cnt = vmacSta_p->VMacEntry.edca_param_set_update_cnt;
	pEDCA_param_set->QoS_info.U_APSD = 1;
	pEDCA_param_set->QoS_info.Reserved = 0;
#else
	//pEDCA_param_set->QoS_info.EDCA_param_set_update_cnt = EDCA_param_set_update_cnt;
	pEDCA_param_set->QoS_info.EDCA_param_set_update_cnt = vmacSta_p->VMacEntry.edca_param_set_update_cnt;
	pEDCA_param_set->QoS_info.Q_ack = mib_StaCfg_p->QAckOptImpl;
	pEDCA_param_set->QoS_info.TXOP_req = PROCESS_TXOP_REQ;	//We can process TxOp Request.
	pEDCA_param_set->QoS_info.Q_req = PROCESS_QUEUE_REQ;	//We can process non-zero Queue Size.
#endif
	//Update EDCA for BE
	pEDCA_param_set->AC_BE.ACI_AIFSN.AIFSN = mib_QAPEDCATable[0].QAPEDCATblAIFSN;
	pEDCA_param_set->AC_BE.ACI_AIFSN.ACI = 0;
	pEDCA_param_set->AC_BE.ECW_min_max.ECW_min = GetLog(mib_QAPEDCATable[0].QAPEDCATblCWmin);
	pEDCA_param_set->AC_BE.ECW_min_max.ECW_max = GetLog(mib_QAPEDCATable[0].QAPEDCATblCWmax);
	pEDCA_param_set->AC_BE.TXOP_lim = ENDIAN_SWAP16(mib_QAPEDCATable[0].QAPEDCATblTXOPLimit);
	//Update EDCA for BK
	pEDCA_param_set->AC_BK.ACI_AIFSN.AIFSN = mib_QAPEDCATable[1].QAPEDCATblAIFSN;
	pEDCA_param_set->AC_BK.ACI_AIFSN.ACI = 1;
	pEDCA_param_set->AC_BK.ECW_min_max.ECW_min = GetLog(mib_QAPEDCATable[1].QAPEDCATblCWmin);
	pEDCA_param_set->AC_BK.ECW_min_max.ECW_max = GetLog(mib_QAPEDCATable[1].QAPEDCATblCWmax);
	pEDCA_param_set->AC_BK.TXOP_lim = ENDIAN_SWAP16(mib_QAPEDCATable[1].QAPEDCATblTXOPLimit);
	//Update EDCA for VI
	pEDCA_param_set->AC_VI.ACI_AIFSN.AIFSN = mib_QAPEDCATable[2].QAPEDCATblAIFSN;
	pEDCA_param_set->AC_VI.ACI_AIFSN.ACI = 2;
	pEDCA_param_set->AC_VI.ECW_min_max.ECW_min = GetLog(mib_QAPEDCATable[2].QAPEDCATblCWmin);
	pEDCA_param_set->AC_VI.ECW_min_max.ECW_max = GetLog(mib_QAPEDCATable[2].QAPEDCATblCWmax);
	pEDCA_param_set->AC_VI.TXOP_lim = ENDIAN_SWAP16(mib_QAPEDCATable[2].QAPEDCATblTXOPLimit);
	//Update EDCA for VO
	pEDCA_param_set->AC_VO.ACI_AIFSN.AIFSN = mib_QAPEDCATable[3].QAPEDCATblAIFSN;
	pEDCA_param_set->AC_VO.ACI_AIFSN.ACI = 3;
	pEDCA_param_set->AC_VO.ECW_min_max.ECW_min = GetLog(mib_QAPEDCATable[3].QAPEDCATblCWmin);
	pEDCA_param_set->AC_VO.ECW_min_max.ECW_max = GetLog(mib_QAPEDCATable[3].QAPEDCATblCWmax);
	pEDCA_param_set->AC_VO.TXOP_lim = ENDIAN_SWAP16(mib_QAPEDCATable[3].QAPEDCATblTXOPLimit);

	return sizeof(EDCA_param_set_t);
}
#endif				//QOS_FEATURE

#ifdef WPA

// Init this sta's RSN IE
void InitThisStaRsnIE(vmacApInfo_t * vmacSta_p)
{
	MIB_RSNCONFIG *mib_RSNConfig_p = vmacSta_p->Mib802dot11->RSNConfig;
	MIB_RSNCONFIG_UNICAST_CIPHERS *mib_RSNConfigUnicastCiphers_p = vmacSta_p->Mib802dot11->UnicastCiphers;
	MIB_RSNCONFIG_AUTH_SUITES *mib_RSNConfigAuthSuites_p = vmacSta_p->Mib802dot11->RSNConfigAuthSuites;
	MIB_RSNCONFIGWPA2 *mib_RSNConfigWPA2_p = vmacSta_p->Mib802dot11->RSNConfigWPA2;
	MIB_RSNCONFIGWPA2_AUTH_SUITES *mib_RSNConfigWPA2AuthSuites_p = vmacSta_p->Mib802dot11->WPA2AuthSuites;
	MIB_RSNCONFIGWPA2_UNICAST_CIPHERS *mib_RSNConfigWPA2UnicastCiphers_p = vmacSta_p->Mib802dot11->WPA2UnicastCiphers;
	MIB_RSNCONFIGWPA2_UNICAST_CIPHERS *mib_RSNConfigWPA2UnicastCiphers2_p = vmacSta_p->Mib802dot11->WPA2UnicastCiphers2;
	IEEEtypes_RSN_IE_t *thisStaRsnIE_p = vmacSta_p->Mib802dot11->thisStaRsnIE;
	IEEEtypes_RSN_IE_WPA2_t *thisStaRsnIEWPA2_p = vmacSta_p->Mib802dot11->thisStaRsnIEWPA2;
	IEEEtypes_RSN_IE_WPA2MixedMode_t *thisStaRsnIEWPA2MixedMode_p = vmacSta_p->Mib802dot11->thisStaRsnIEWPA2MixedMode;

	thisStaRsnIE_p->ElemId = 221;
	thisStaRsnIE_p->Len = 22;
	thisStaRsnIE_p->OuiType[0] = 0x0;
	thisStaRsnIE_p->OuiType[1] = 0x50;
	thisStaRsnIE_p->OuiType[2] = 0xf2;
	thisStaRsnIE_p->OuiType[3] = 0x01;
	thisStaRsnIE_p->Ver[0] = 0x01;
	thisStaRsnIE_p->Ver[1] = 0x0;
	memcpy(thisStaRsnIE_p->GrpKeyCipher, mib_RSNConfig_p->MulticastCipher, 4);
	thisStaRsnIE_p->PwsKeyCnt[0] = 0x01;
	thisStaRsnIE_p->PwsKeyCnt[1] = 0x0;
	memcpy(thisStaRsnIE_p->PwsKeyCipherList, mib_RSNConfigUnicastCiphers_p->UnicastCipher, 4);
	thisStaRsnIE_p->AuthKeyCnt[0] = 0x01;
	thisStaRsnIE_p->AuthKeyCnt[1] = 0x0;
	memcpy(thisStaRsnIE_p->AuthKeyList, mib_RSNConfigAuthSuites_p->AuthSuites, 4);
	//thisStaRsnIE_p->RsnCap[0] = 0x0;
	//thisStaRsnIE_p->RsnCap[1] = 0x0;
#ifdef AP_WPA2
	/* WPA2 Only */
	thisStaRsnIEWPA2_p->ElemId = 48;
	thisStaRsnIEWPA2_p->Len = 20;
	//thisStaRsnIEWPA2_p->OuiType[0] = 0x0;
	//thisStaRsnIEWPA2_p->OuiType[1] = 0x50;
	//thisStaRsnIEWPA2_p->OuiType[2] = 0xf2;
	//thisStaRsnIEWPA2_p->OuiType[3] = 0x01;
	thisStaRsnIEWPA2_p->Ver[0] = 0x01;
	thisStaRsnIEWPA2_p->Ver[1] = 0x0;
	memcpy(thisStaRsnIEWPA2_p->GrpKeyCipher, mib_RSNConfigWPA2_p->MulticastCipher, 4);
	thisStaRsnIEWPA2_p->PwsKeyCnt[0] = 0x01;
	thisStaRsnIEWPA2_p->PwsKeyCnt[1] = 0x0;
	memcpy(thisStaRsnIEWPA2_p->PwsKeyCipherList, mib_RSNConfigWPA2UnicastCiphers_p->UnicastCipher, 4);
	thisStaRsnIEWPA2_p->AuthKeyCnt[0] = 0x01;
	thisStaRsnIEWPA2_p->AuthKeyCnt[1] = 0x0;
	memcpy(thisStaRsnIEWPA2_p->AuthKeyList, mib_RSNConfigWPA2AuthSuites_p->AuthSuites, 4);
	if (mib_RSNConfigWPA2_p->WPA2PreAuthEnabled)
		thisStaRsnIEWPA2_p->RsnCap[0] = 0x01;
	else
		thisStaRsnIEWPA2_p->RsnCap[0] = 0x0;
	thisStaRsnIEWPA2_p->RsnCap[1] = 0x0;

	/* WPA2 Mixed Mode */
	thisStaRsnIEWPA2MixedMode_p->ElemId = 48;
	thisStaRsnIEWPA2MixedMode_p->Len = 24;	//38;
	//thisStaRsnIEWPA2MixedMode_p->OuiType[0] = 0x0;
	//thisStaRsnIEWPA2MixedMode_p->OuiType[1] = 0x50;
	//thisStaRsnIEWPA2MixedMode_p->OuiType[2] = 0xf2;
	//thisStaRsnIEWPA2MixedMode_p->OuiType[3] = 0x01;
	thisStaRsnIEWPA2MixedMode_p->Ver[0] = 0x01;
	thisStaRsnIEWPA2MixedMode_p->Ver[1] = 0x0;
	memcpy(thisStaRsnIEWPA2MixedMode_p->GrpKeyCipher, mib_RSNConfigWPA2_p->MulticastCipher, 4);
	thisStaRsnIEWPA2MixedMode_p->PwsKeyCnt[0] = 0x02;
	thisStaRsnIEWPA2MixedMode_p->PwsKeyCnt[1] = 0x0;
	memcpy(thisStaRsnIEWPA2MixedMode_p->PwsKeyCipherList, mib_RSNConfigWPA2UnicastCiphers_p->UnicastCipher, 4);

	if (mib_RSNConfigWPA2UnicastCiphers_p->UnicastCipher[3] != mib_RSNConfigWPA2UnicastCiphers2_p->UnicastCipher[3]) {
		/*
		   Mix mode 
		   => Use both PwsKeyCipherList[4]; and PwsKeyCipherList2[4]; and PwsKeyCnt[0] set to 2
		 */
		memcpy(thisStaRsnIEWPA2MixedMode_p->PwsKeyCipherList2, mib_RSNConfigWPA2UnicastCiphers2_p->UnicastCipher, 4);
		thisStaRsnIEWPA2MixedMode_p->AuthKeyCnt[0] = 0x01;
		thisStaRsnIEWPA2MixedMode_p->AuthKeyCnt[1] = 0x0;
		memcpy(thisStaRsnIEWPA2MixedMode_p->AuthKeyList, mib_RSNConfigWPA2AuthSuites_p->AuthSuites, 4);
		if (mib_RSNConfigWPA2_p->WPA2PreAuthEnabled)
			thisStaRsnIEWPA2MixedMode_p->RsnCap[0] = 0x01;
		else
			thisStaRsnIEWPA2MixedMode_p->RsnCap[0] = 0x0;
		thisStaRsnIEWPA2MixedMode_p->RsnCap[1] = 0x0;
	} else {
#ifdef SOC_W906X
		/*
		   the cipher is the same, so only need the structure like IEEEtypes_RSN_IE_WPA2_t
		 */
		IEEEtypes_RSN_IE_WPA2MixedMode_singlepwcipher_t *StaMixSingleIE_p =
		    (IEEEtypes_RSN_IE_WPA2MixedMode_singlepwcipher_t *) thisStaRsnIEWPA2MixedMode_p;
		StaMixSingleIE_p->Len = 20;	//38;
		StaMixSingleIE_p->PwsKeyCnt[0] = 0x01;
		StaMixSingleIE_p->AuthKeyCnt[0] = 0x01;	//AuthKeyCnt[0]
		StaMixSingleIE_p->AuthKeyCnt[1] = 0x00;	//AuthKeyCnt[1]
		memcpy(StaMixSingleIE_p->AuthKeyList, mib_RSNConfigWPA2AuthSuites_p->AuthSuites, 4);

		if (mib_RSNConfigWPA2_p->WPA2PreAuthEnabled)
			StaMixSingleIE_p->RsnCap[0] = 0x01;	//RsnCap[0]
		else
			StaMixSingleIE_p->RsnCap[0] = 0x00;	//RsnCap[0]
		StaMixSingleIE_p->RsnCap[1] = 0x0;	//RsnCap[1]
#else
		thisStaRsnIEWPA2MixedMode_p->Len = 20;	//38;
		thisStaRsnIEWPA2MixedMode_p->PwsKeyCnt[0] = 0x01;
		*(thisStaRsnIEWPA2MixedMode_p->PwsKeyCipherList2) = 0x01;	//AuthKeyCnt[0]
		*(thisStaRsnIEWPA2MixedMode_p->PwsKeyCipherList2 + 1) = 0x0;	//AuthKeyCnt[1]
		memcpy(thisStaRsnIEWPA2MixedMode_p->PwsKeyCipherList2 + 2, mib_RSNConfigWPA2AuthSuites_p->AuthSuites, 4);
		if (mib_RSNConfigWPA2_p->WPA2PreAuthEnabled)
			*(thisStaRsnIEWPA2MixedMode_p->AuthKeyCnt) = 0x01;	//RsnCap[0]
		else
			*(thisStaRsnIEWPA2MixedMode_p->AuthKeyCnt) = 0x0;	//RsnCap[0]
		*(thisStaRsnIEWPA2MixedMode_p->AuthKeyCnt + 1) = 0x0;	//RsnCap[1]

#endif
	}

#if defined(CONFIG_IEEE80211W) || defined(CONFIG_HS2)
	if (vmacSta_p->RsnIESetByHost == 1) {
		if (vmacSta_p->RsnIE[0] == RSN_IEWPA2) {
			memcpy(thisStaRsnIEWPA2_p, vmacSta_p->RsnIE, sizeof(IEEEtypes_RSN_IE_WPA2_t));
			memcpy(thisStaRsnIEWPA2MixedMode_p, vmacSta_p->RsnIE, sizeof(IEEEtypes_RSN_IE_WPA2_t));
		}
		if (vmacSta_p->WpaIE[0] == RSN_IE) {
			memcpy(thisStaRsnIE_p, vmacSta_p->WpaIE, sizeof(IEEEtypes_RSN_IE_t));
		}
	} else if (vmacSta_p->RsnIESetByHost == 2) {
		memset((UINT8 *) thisStaRsnIEWPA2_p, 0, sizeof(IEEEtypes_RSN_IE_WPA2_t));
		memset((UINT8 *) thisStaRsnIEWPA2MixedMode_p, 0, sizeof(IEEEtypes_RSN_IE_WPA2MixedMode_t));
		memset((UINT8 *) thisStaRsnIE_p, 0, sizeof(IEEEtypes_RSN_IE_t));
	}
#endif				/* defined(CONFIG_IEEE80211W) || defined(CONFIG_HS2) */

#endif

}

#ifdef UR_WPA
void InitThisStaRsnIEUr(vmacApInfo_t * vmacSta_p)
{
	MIB_RSNCONFIG *mib_RSNConfig_p = vmacSta_p->Mib802dot11->RSNConfig;
	MIB_RSNCONFIG_UNICAST_CIPHERS *mib_RSNConfigUnicastCiphers_p = vmacSta_p->Mib802dot11->UnicastCiphers;
	MIB_RSNCONFIG_AUTH_SUITES *mib_RSNConfigAuthSuites_p = vmacSta_p->Mib802dot11->RSNConfigAuthSuites;
	MIB_RSNCONFIGWPA2 *mib_RSNConfigWPA2_p = vmacSta_p->Mib802dot11->RSNConfigWPA2;
	MIB_RSNCONFIGWPA2_AUTH_SUITES *mib_RSNConfigWPA2AuthSuites_p = vmacSta_p->Mib802dot11->WPA2AuthSuites;
	MIB_RSNCONFIGWPA2_UNICAST_CIPHERS *mib_RSNConfigWPA2UnicastCiphers_p = vmacSta_p->Mib802dot11->WPA2UnicastCiphers;

	thisStaRsnIEUr.ElemId = 221;
	thisStaRsnIEUr.Len = sizeof(IEEEtypes_RSN_IE_t) - 2 - 4;	/* minus Reserved[4] */
	thisStaRsnIEUr.OuiType[0] = 0x0;
	thisStaRsnIEUr.OuiType[1] = 0x50;
	thisStaRsnIEUr.OuiType[2] = 0xf2;
	thisStaRsnIEUr.OuiType[3] = 0x01;
	thisStaRsnIEUr.Ver[0] = 0x01;
	thisStaRsnIEUr.Ver[1] = 0x0;
	memcpy(thisStaRsnIEUr.GrpKeyCipher, mib_RSNConfig_p->MulticastCipher, 4);
	thisStaRsnIEUr.PwsKeyCnt[0] = 0x01;
	thisStaRsnIEUr.PwsKeyCnt[1] = 0x0;
	memcpy(thisStaRsnIEUr.PwsKeyCipherList, mib_RSNConfigUnicastCiphers_p->UnicastCipher, 4);
	thisStaRsnIEUr.AuthKeyCnt[0] = 0x01;
	thisStaRsnIEUr.AuthKeyCnt[1] = 0x0;
	memcpy(thisStaRsnIEUr.AuthKeyList, mib_RSNConfigAuthSuites_p->AuthSuites, 4);
	//thisStaRsnIEUr.RsnCap[0] = 0x0;
	//thisStaRsnIEUr.RsnCap[1] = 0x0;

	/* WPA2 */
	thisStaRsnIEWPA2Ur.ElemId = 48;
	thisStaRsnIEWPA2Ur.Len = 20;
	thisStaRsnIEWPA2Ur.Ver[0] = 0x01;
	thisStaRsnIEWPA2Ur.Ver[1] = 0x0;
	memcpy(thisStaRsnIEWPA2Ur.GrpKeyCipher, mib_RSNConfigWPA2_p->MulticastCipher, 4);
	thisStaRsnIEWPA2Ur.PwsKeyCnt[0] = 0x01;
	thisStaRsnIEWPA2Ur.PwsKeyCnt[1] = 0x0;
	memcpy(thisStaRsnIEWPA2Ur.PwsKeyCipherList, mib_RSNConfigWPA2UnicastCiphers_p->UnicastCipher, 4);
	thisStaRsnIEWPA2Ur.AuthKeyCnt[0] = 0x01;
	thisStaRsnIEWPA2Ur.AuthKeyCnt[1] = 0x0;
	memcpy(thisStaRsnIEWPA2Ur.AuthKeyList, mib_RSNConfigWPA2AuthSuites_p->AuthSuites, 4);
	thisStaRsnIEWPA2Ur.RsnCap[0] = 0x0;
	thisStaRsnIEWPA2Ur.RsnCap[1] = 0x0;
}
#endif

// Add RSN IE to a frame body
UINT16 AddRSN_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_RSN_IE_t * pNextElement)
{
	IEEEtypes_RSN_IE_t *thisStaRsnIE_p = vmacSta_p->Mib802dot11->thisStaRsnIE;

#ifdef UR_WPA
	if ((mib_urMode == 0) && (mib_wbMode == 0))	//Ap
		memcpy(pNextElement, &thisStaRsnIE, sizeof(IEEEtypes_RSN_IE_t));
	else			//WB or UR
		memcpy(pNextElement, &thisStaRsnIEUr, sizeof(IEEEtypes_RSN_IE_t));
#else
	memcpy(pNextElement, thisStaRsnIE_p, sizeof(IEEEtypes_RSN_IE_t));
#endif
	return (thisStaRsnIE_p->Len + 2);
}

UINT16 AddRSN_IE_TO(IEEEtypes_RSN_IE_t * thisStaRsnIE_p, IEEEtypes_RSN_IE_t * pNextElement)
{
	memcpy(pNextElement, thisStaRsnIE_p, sizeof(IEEEtypes_RSN_IE_t));
	return (thisStaRsnIE_p->Len + 2);
}
#endif

#ifdef AP_WPA2
UINT16 AddRSN_IEWPA2(vmacApInfo_t * vmacSta_p, IEEEtypes_RSN_IE_WPA2_t * pNextElement)
{
	IEEEtypes_RSN_IE_WPA2_t *thisStaRsnIEWPA2_p = vmacSta_p->Mib802dot11->thisStaRsnIEWPA2;

#ifdef CONFIG_IEEE80211W
	if (vmacSta_p->RsnIESetByHost == 2)
		return 0;
#endif

	memcpy(pNextElement, thisStaRsnIEWPA2_p, thisStaRsnIEWPA2_p->Len + 2);
	return (thisStaRsnIEWPA2_p->Len + 2);
}

UINT16 AddRSN_IEWPA2_TO(IEEEtypes_RSN_IE_WPA2_t * thisStaRsnIEWPA2_p, IEEEtypes_RSN_IE_WPA2_t * pNextElement)
{
	memcpy(pNextElement, thisStaRsnIEWPA2_p, thisStaRsnIEWPA2_p->Len + 2);
	return (thisStaRsnIEWPA2_p->Len + 2);
}

UINT16 AddRSN_IEWPA2MixedMode(vmacApInfo_t * vmacSta_p, IEEEtypes_RSN_IE_WPA2MixedMode_t * pNextElement)
{
	IEEEtypes_RSN_IE_WPA2MixedMode_t *thisStaRsnIEWPA2MixedMode_p = vmacSta_p->Mib802dot11->thisStaRsnIEWPA2MixedMode;

	memcpy(pNextElement, thisStaRsnIEWPA2MixedMode_p, thisStaRsnIEWPA2MixedMode_p->Len + 2);
	//return ( sizeof(IEEEtypes_RSN_IE_WPA2_t) );
	return (thisStaRsnIEWPA2MixedMode_p->Len + 2);
}
#endif

#ifdef COUNTRY_INFO_SUPPORT

IEEEtypes_COUNTRY_IE_t thisStaCountryIE;

#ifdef COUNTRY_INFO_SUPPORT
void InitThisCountry_IE(vmacApInfo_t * vmacSta_p)
{
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;

	DomainCountryInfo DomainInfo[1];

	domainGetPowerInfo((UINT8 *) DomainInfo);

	thisStaCountryIE.ElemId = COUNTRY;
	thisStaCountryIE.CountryCode[0] = DomainInfo->CountryString[0];
	thisStaCountryIE.CountryCode[1] = DomainInfo->CountryString[1];
	thisStaCountryIE.CountryCode[2] = DomainInfo->CountryString[2];

	if (*(mib->mib_ApMode) == AP_MODE_A_ONLY || *(mib->mib_ApMode) == AP_MODE_AandG) {
		thisStaCountryIE.Len = DomainInfo->AChannelLen + 3;  /** include 3 byte of country code here **/
		memcpy(thisStaCountryIE.DomainEntry, DomainInfo->DomainEntryA, DomainInfo->AChannelLen);
	} else {
		thisStaCountryIE.Len = DomainInfo->GChannelLen + 3;  /** include 3 byte of country code here **/
		memcpy(thisStaCountryIE.DomainEntry, DomainInfo->DomainEntryG, DomainInfo->GChannelLen);
	}

}

/** DUPLICATE OF ABOVE, this is just use for ag mode , g channel **/
void InitThisCountry_IE2(UINT8 mib_ApMode)
{

	DomainCountryInfo DomainInfo[1];

	domainGetPowerInfo((UINT8 *) DomainInfo);

	thisStaCountryIE.ElemId = COUNTRY;
	thisStaCountryIE.CountryCode[0] = DomainInfo->CountryString[0];
	thisStaCountryIE.CountryCode[1] = DomainInfo->CountryString[1];
	thisStaCountryIE.CountryCode[2] = DomainInfo->CountryString[2];

	thisStaCountryIE.Len = DomainInfo->GChannelLen + 3;  /** include 3 byte of country code here **/
	memcpy(thisStaCountryIE.DomainEntry, DomainInfo->DomainEntryG, DomainInfo->GChannelLen);

}
#endif
UINT16 AddCountry_IE(IEEEtypes_COUNTRY_IE_t * pNextElement)
{
	memcpy(pNextElement, &thisStaCountryIE, thisStaCountryIE.Len + 2);   /** 2 for size of length and elementId **/
	return (thisStaCountryIE.Len + 2);
}

#endif

#ifdef IEEE80211H

static IEEEtypes_PowerConstraintElement_t PowerConstraintIE;
IEEEtypes_ChannelSwitchAnnouncementElement_t ChannelSwitchAnnouncementIE;
IEEEtypes_QuietElement_t QuietIE;
#ifdef IEEE80211H_NOTWIFI
static IEEEtypes_TPCRepElement_t TPCRepIE;
#endif

#ifdef SOC_W8964
static void InitPowerConstraint_IE(vmacApInfo_t * vmacSta_p, UINT8 channel)
{
#ifndef IEEE80211_DH
	PowerConstraintIE.value = (SINT8) mib_SpectrumMagament_p->mitigationRequirement;

	PowerConstraintIE.ElementId = PWR_CONSTRAINT;
	PowerConstraintIE.Len = 1;
#endif				//IEEE80211_DH

	return;
}
#endif

static UINT16 AddPowerConstraint_IE(UINT8 * pNextElement)
{
	memcpy(pNextElement, &PowerConstraintIE, PowerConstraintIE.Len + 2);   /** 2 for size of length and elementId **/
	return (PowerConstraintIE.Len + 2);
}

void bcngen_AddChannelSwithcAnnouncement_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_ChannelSwitchAnnouncementElement_t * pChannelSwitchAnnouncementIE)
{
	ChannelSwitchAnnouncementIE.ElementId = CSA;
	ChannelSwitchAnnouncementIE.Mode = pChannelSwitchAnnouncementIE->Mode;
	ChannelSwitchAnnouncementIE.Channel = pChannelSwitchAnnouncementIE->Channel;
	ChannelSwitchAnnouncementIE.Count = pChannelSwitchAnnouncementIE->Count;
	ChannelSwitchAnnouncementIE.Len = 3;

	/* update beacon immediately */
	bcngen_UpdateBeaconBuffer(vmacSta_p, &StartCmd_update);

	ChannelSwitchCtrl.isActivated = TRUE;
	ChannelSwitchCtrl.targetChannel = pChannelSwitchAnnouncementIE->Channel;
	StartCmd_update.PhyParamSet.DsParamSet.CurrentChan = pChannelSwitchAnnouncementIE->Channel;  /** update channel number here **/

	return;
}

void bcngen_RemoveChannelSwithcAnnouncement_IE(vmacApInfo_t * vmacSta_p)
{
	ChannelSwitchCtrl.isActivated = FALSE;
	ChannelSwitchCtrl.targetChannel = 0;

	ChannelSwitchAnnouncementIE.Len = 0;
	memset(&ChannelSwitchAnnouncementIE, 0, sizeof(ChannelSwitchAnnouncementIE));

	/* update beacon immediately */
	bcngen_UpdateBeaconBuffer(vmacSta_p, &StartCmd_update);

	return;
}

static UINT16 AddChannelSwithcAnnouncement_IE(UINT8 * pNextElement)
{
	if (ChannelSwitchAnnouncementIE.Len) {
		memcpy(pNextElement, &ChannelSwitchAnnouncementIE, ChannelSwitchAnnouncementIE.Len + 2);   /** 2 for size of length and elementId **/
		return (ChannelSwitchAnnouncementIE.Len + 2);
	} else
		return (0);
}

void bcngen_AddQuiet_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_QuietElement_t * pQuietIE)
{
	QuietIE.ElementId = QUIET;
	QuietIE.Count = pQuietIE->Count;
	QuietIE.Period = pQuietIE->Period;
	QuietIE.Duration = pQuietIE->Duration;
	QuietIE.Offset = pQuietIE->Offset;
	QuietIE.Len = 6;

	/* update beacon immediately */
	bcngen_UpdateBeaconBuffer(vmacSta_p, &StartCmd_update);

	return;
}

void bcngen_RemoveQuiet_IE(vmacApInfo_t * vmacSta_p)
{
	QuietIE.Len = 0;
	memset(&QuietIE, 0, sizeof(QuietIE));

	/* update beacon immediately */
	bcngen_UpdateBeaconBuffer(vmacSta_p, &StartCmd_update);

	return;
}

UINT16 AddQuiet_IE(UINT8 * pNextElement)
{
	if (QuietIE.Len) {
		memcpy(pNextElement, &QuietIE, QuietIE.Len + 2);   /** 2 for size of length and elementId **/
		return (QuietIE.Len + 2);
	} else
		return (0);
}

#ifdef IEEE80211H_NOTWIFI
static void InitTPCRep_IE(void)
{

	TPCRepIE.ElementId = TPC_REP;
	TPCRepIE.Len = 2;
	TPCRepIE.TxPwr = BcnTxPwr;
	TPCRepIE.LinkMargin = 0;
	return;
}

static UINT16 AddTPCRep_IE(UINT8 * pNextElement)
{
	memcpy(pNextElement, &TPCRepIE, TPCRepIE.Len + 2);   /** 2 for size of length and elementId **/
	return (TPCRepIE.Len + 2);
}
#endif
#ifdef FLEX_TIME
void UpdateBeaconInterval(UINT8 mode)
{
	if (mode == 0) {	//scanning mode
		*ProbeIntervalLocation_p = *BcnIntervalLocation_p = 20;
		*ProbeIntervalLocation_p2 = *BcnIntervalLocation_p2 = 20;

	} else {
		*ProbeIntervalLocation_p = *BcnIntervalLocation_p = 40;
		*ProbeIntervalLocation_p2 = *BcnIntervalLocation_p2 = 40;

	}

}
#endif

#endif				/* IEEE80211H */
/******************************************************************************
 *
 * Name: bcngen_UpdateBeaconBuffer
 *
 * Description:
 *
 *
 * Conditions For Use:
 *    None.
 *
 * Arguments:
 *    None.
 *
 * Return Value:
 *    Status indicating success or failure.
 *
 * Notes:
 *    None.
 *
 * PDL:
 *
 * END PDL
 *
 *****************************************************************************/
void bcngen_UpdateBeaconBuffer(vmacApInfo_t * vmacSta_p, IEEEtypes_StartCmd_t * StartCmd)
{
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_STA_CFG *mib_StaCfg_p = vmacSta_p->Mib802dot11->StationConfig;
	MIB_PRIVACY_TABLE *mib_PrivacyTable_p = vmacSta_p->Mib802dot11->Privacy;
	MIB_RSNCONFIGWPA2 *mib_RSNConfigWPA2_p = vmacSta_p->Mib802dot11->RSNConfigWPA2;
	UINT8 *NextElementPtr;
	IEEEtypes_SsIdElement_t *SsIdPtr;
	IEEEtypes_SuppRatesElement_t *SuppRatesPtr;
	IEEEtypes_PhyParamSet_t *PhyParamSetPtr;
	IEEEtypes_SsParamSet_t *SsParamSetPtr;
	UINT32 RateCnt;
	UINT16 totalLen = 0;
	UINT16 byteCnt;

	IEEEtypes_SuppRatesElement_t *SuppRateSet_p = &(vmacSta_p->SuppRateSet);

#ifdef ERP
	IEEEtypes_ExtSuppRatesElement_t *ExtSuppRateSet_p = &(vmacSta_p->ExtSuppRateSet);
#endif

#ifdef IEEE80211H
	/* snapshot the startcmd */
	StartCmd_update = *StartCmd;
#endif

	BcnBuffer_p->Hdr.Duration = 0;
	BcnBuffer_p->Hdr.FrmCtl.ProtocolVersion = 0;
	BcnBuffer_p->Hdr.FrmCtl.Type = IEEE_TYPE_MANAGEMENT;
	BcnBuffer_p->Hdr.FrmCtl.Subtype = IEEE_MSG_BEACON;
	BcnBuffer_p->Hdr.FrmCtl.ToDs = 0;
	BcnBuffer_p->Hdr.FrmCtl.FromDs = 0;
	BcnBuffer_p->Hdr.FrmCtl.MoreFrag = 0;
	BcnBuffer_p->Hdr.FrmCtl.Retry = 0;
	BcnBuffer_p->Hdr.FrmCtl.PwrMgmt = 0;
	BcnBuffer_p->Hdr.FrmCtl.MoreData = 0;
	BcnBuffer_p->Hdr.FrmCtl.Wep = 0;
	BcnBuffer_p->Hdr.FrmCtl.Order = 0;
	memcpy(&BcnBuffer_p->Hdr.DestAddr, &BcastAddr, sizeof(IEEEtypes_MacAddr_t));
	memcpy(&BcnBuffer_p->Hdr.SrcAddr, &vmacSta_p->macBssId, sizeof(IEEEtypes_MacAddr_t));
	memcpy(&BcnBuffer_p->Hdr.BssId, &vmacSta_p->macBssId, sizeof(IEEEtypes_MacAddr_t));

	if (*(mib->mib_ApMode) == AP_MODE_AandG) {
#ifdef FLEX_TIME
		BcnIntervalLocation_p = (UINT8 *) & BcnBuffer_p->Body.Bcn.BcnInterval;
#endif

		BcnBuffer_p->Body.Bcn.BcnInterval = AGinterval;
	} else {
		BcnBuffer_p->Body.Bcn.BcnInterval = StartCmd->BcnPeriod;
	}

	BcnBuffer_p->Body.Bcn.CapInfo = StartCmd->CapInfo;

	NextElementPtr = (UINT8 *) & BcnBuffer_p->Body.Bcn.SsId;
	SsIdPtr = &BcnBuffer_p->Body.Bcn.SsId;

	if (*(mib->mib_broadcastssid) == TRUE) {
		*SsIdPtr = vmacSta_p->macSsId;
	} else { /** FALSE CASE: NEED TO BLANK OFF SSID **/

		*SsIdPtr = vmacSta_p->macSsId;
		memset(SsIdPtr->SsId, 0, SsIdPtr->Len);
	}

	NextElementPtr = NextElementPtr + 2 + SsIdPtr->Len;
	SuppRatesPtr = (IEEEtypes_SuppRatesElement_t *) NextElementPtr;
	SuppRatesPtr->ElementId = SUPPORTED_RATES;
	RateCnt = 0;

	*SuppRatesPtr = *SuppRateSet_p;
	NextElementPtr = NextElementPtr + 2 + SuppRateSet_p->Len;

	PhyParamSetPtr = (IEEEtypes_PhyParamSet_t *) NextElementPtr;
	if (*(UINT8 *) & StartCmd->PhyParamSet == FH_PARAM_SET) {
		PhyParamSetPtr->FhParamSet = StartCmd->PhyParamSet.FhParamSet;
		NextElementPtr = NextElementPtr + sizeof(IEEEtypes_FhParamSet_t);
	} else if (*(UINT8 *) & StartCmd->PhyParamSet == DS_PARAM_SET) {
		PhyParamSetPtr->DsParamSet = StartCmd->PhyParamSet.DsParamSet;
		Bcnchannel = (UINT8 *) & PhyParamSetPtr->DsParamSet.CurrentChan;
		NextElementPtr = NextElementPtr + sizeof(IEEEtypes_DsParamSet_t);
	}
#ifdef AP_WPA2
	if (mib_PrivacyTable_p->RSNEnabled) {
		// Set capability info.privacy bit for Beacon and probe rsp.
		BcnBuffer_p->Body.Bcn.CapInfo.Privacy = 1;

		InitThisStaRsnIE(vmacSta_p);

		if (!mib_RSNConfigWPA2_p->WPA2OnlyEnabled) {

			// add IE to beacon.
			NextElementPtr += AddRSN_IE(vmacSta_p, (IEEEtypes_RSN_IE_t *) NextElementPtr);
		}
	} else {
		// ReSet capability info.privacy bit for Beacon and probe rsp.
		if ((mib_StaCfg_p->PrivOption && mib_PrivacyTable_p->PrivInvoked))
			BcnBuffer_p->Body.Bcn.CapInfo.Privacy = 1;
		else
			BcnBuffer_p->Body.Bcn.CapInfo.Privacy = 0;
	}

#else
	if (mib_PrivacyTable_p->RSNEnabled) {
		// Set capability info.privacy bit for Beacon and probe rsp.
		BcnBuffer_p->Body.Bcn.CapInfo.Privacy = 1;

		InitThisStaRsnIE(vmacSta_p);

		// add IE to beacon.
		NextElementPtr += AddRSN_IE(vmacSta_p, (IEEEtypes_RSN_IE_t *) NextElementPtr);
	} else {
		// ReSet capability info.privacy bit for Beacon and probe rsp.
		if ((mib_StaCfg_p->PrivOption && mib_PrivacyTable_p->PrivInvoked))
			BcnBuffer_p->Body.Bcn.CapInfo.Privacy = 1;
		else
			BcnBuffer_p->Body.Bcn.CapInfo.Privacy = 0;
	}
#endif

	SsParamSetPtr = (IEEEtypes_SsParamSet_t *) NextElementPtr;
	if (StartCmd->BssType == BSS_INFRASTRUCTURE) {
		SsParamSetPtr->CfParamSet = StartCmd->SsParamSet.CfParamSet;
		NextElementPtr = NextElementPtr + sizeof(IEEEtypes_CfParamSet_t);
	} else if (StartCmd->BssType == BSS_INDEPENDENT) {
		SsParamSetPtr->IbssParamSet = StartCmd->SsParamSet.IbssParamSet;
		NextElementPtr = NextElementPtr + sizeof(IEEEtypes_IbssParamSet_t);
	}

	TimPtr = (IEEEtypes_Tim_t *) NextElementPtr;
	TimPtr->ElementId = TIM;

	if (*(mib->mib_ApMode) == AP_MODE_AandG)       /** Dtim period can only be 0 for A and G mode **/
		TimPtr->DtimPeriod = 1;
	else
		TimPtr->DtimPeriod = StartCmd->DtimPeriod;

	TimPtr->BitmapCtl = 0;
	TimPtr->PartialVirtualBitmap[0] = 0;
	TimPtr->Len = 4;
	// Also, update the local TIM buffer
	Tim.ElementId = TIM;

	if (*(mib->mib_ApMode) == AP_MODE_AandG)       /** Dtim period can only be 0 for A and G mode **/
		Tim.DtimPeriod = 1;
	else
		Tim.DtimPeriod = StartCmd->DtimPeriod;

	Tim.BitmapCtl = 0;
	Tim.PartialVirtualBitmap[0] = 0;
	Tim.Len = 4;
	byteCnt = sizeof(IEEEtypes_InfoElementHdr_t) + TimPtr->Len;
	NextElementPtr += byteCnt;

#ifdef COUNTRY_INFO_SUPPORT
	InitThisCountry_IE(vmacSta_p);
	NextElementPtr += AddCountry_IE((IEEEtypes_COUNTRY_IE_t *) NextElementPtr);

#endif

#ifdef IEEE80211H
	if (mib_StaCfg_p->SpectrumManagementRequired && (*(mib->mib_ApMode) == AP_MODE_A_ONLY || *(mib->mib_ApMode) == AP_MODE_AandG)) {
#ifdef SOC_W8964
		InitPowerConstraint_IE(vmacSta_p, *Bcnchannel);
#endif
		NextElementPtr += AddPowerConstraint_IE(NextElementPtr);
		/* the following 2 IEs MAY BE present */

#ifdef IEEE80211H_NOTWIFI
		InitTPCRep_IE();
		NextElementPtr += AddTPCRep_IE(NextElementPtr);
#endif
		BcnCSACount = &((IEEEtypes_ChannelSwitchAnnouncementElement_t *) NextElementPtr)->Count;
		NextElementPtr += AddChannelSwithcAnnouncement_IE(NextElementPtr);
		NextElementPtr += AddQuiet_IE(NextElementPtr);

	}
#endif				/* IEEE80211H */

	totalLen = NextElementPtr - (UINT8 *) BcnBuffer_p - sizeof(IEEEtypes_MgmtHdr_t);

#ifdef ERP
	if (*(mib->mib_ApMode) != AP_MODE_B_ONLY && *(mib->mib_ApMode) != AP_MODE_A_ONLY && *(mib->mib_ApMode) != AP_MODE_AandG) {
		byteCnt = ErpBufUpdate(NextElementPtr, StartCmd, IEEE_MSG_BEACON, ExtSuppRateSet_p);
		totalLen += byteCnt;
		NextElementPtr += byteCnt;
	}
	BcnBuffer_p->Hdr.FrmBodyLen = totalLen;

#endif

#ifdef AP_WPA2
	if (mib_RSNConfigWPA2_p->WPA2Enabled || mib_RSNConfigWPA2_p->WPA2OnlyEnabled) {
		if (mib_RSNConfigWPA2_p->WPA2Enabled)
			byteCnt = AddRSN_IEWPA2MixedMode(vmacSta_p, (IEEEtypes_RSN_IE_WPA2MixedMode_t *) NextElementPtr);
		else
			byteCnt = AddRSN_IEWPA2(vmacSta_p, (IEEEtypes_RSN_IE_WPA2_t *) NextElementPtr);
		NextElementPtr += byteCnt;
		totalLen += byteCnt;
	}
#endif

	/*Adding the QoS Information of beacon here. */
#ifdef QOS_FEATURE

	//(UINT32)NextElementPtr =  totalLen + (UINT32)BcnBuffer_p +
	//            sizeof(IEEEtypes_MgmtHdr_t);
	if (*(mib->QoSOptImpl)) {
		BcnBuffer_p->Body.Bcn.CapInfo.QoS = 1;
		NextElementPtr += bcngen_UpdateQBSSLoad(vmacSta_p, NextElementPtr);
#ifdef QOS_WSM_FEATURE
		NextElementPtr += Qos_UpdateWSMQosCapElem(vmacSta_p, NextElementPtr);

#else				//QOS_WSM_FEATURE

		//Send EDCA Param or QosCapElem. Not both.
		if (EDCA_Beacon_Counter)
			NextElementPtr += bcngen_AppendEDCAParamSet(vmacSta_p, NextElementPtr);
		else
			NextElementPtr += Qos_UpdateQosCapElem(vmacSta_p, NextElementPtr);
#endif				//QOS_WSM_FEATURE

#ifdef QOS_WSM_FEATURE
		//Always Append the WME Parameter Element.

		{
			BcnWMEParamElemLocation_p = NextElementPtr;
			BcnWMEInfoElemLocation_p = NULL;
			NextElementPtr += QoS_AppendWMEParamElem(vmacSta_p, NextElementPtr);
		}

#endif

		totalLen = NextElementPtr - (UINT8 *) BcnBuffer_p - sizeof(IEEEtypes_MgmtHdr_t);
	}

#endif				//QOS_FEATURE

	BcnBuffer_p->Hdr.FrmBodyLen = totalLen;

	/*--------------------------------------------------------------*/
	/* The following offset to the CF Parameters in the beacon is   */
	/* calculated for the MAC transmit hardware as follows:         */
	/*                                                              */
	/* 1) First, the offset to be calculated is the number of bytes */
	/*    the transmitter will transmit, starting from the frame    */
	/*    control field in the IEEE header, up to the point of the  */
	/*    CF parameter set information in the beacon body.          */
	/*                                                              */
	/* 2) Since the beacon body byte length field is not to be      */
	/*    transmitted, we must subtract out the length of this      */
	/*    field.                                                    */
	/*                                                              */
	/* 3) Since the 4th address in the IEEE header is not to be     */
	/*    transmitted (since there is no 4th address for management */
	/*    messages), the transmitter skips over this field - hence, */
	/*    we must subtract out the length of this field as well.    */
	/*                                                              */
	/* So, taking the difference between pointers to the CF         */
	/* parameter set and the beacon buffer pointer, and subtracting */
	/* out the additional fields mentioned above, yields the        */
	/* number of bytes tranmitted up to the point of the CF         */
	/* paramters.                                                   */
	/*--------------------------------------------------------------*/
}

/******************************************************************************
 *
 * Name:  bcngen_EnableBcnFreeIntr
 *
 * Description:
 * Conditions For Use:
 *    None.
 *
 * Arguments:
 *    None.
 *
 * Return Value:
 *    Status indicating success or failure.
 *
 * Notes:
 *    None.
 *
 * PDL:
 *
 * END PDL
 *
 *****************************************************************************/
void bcngen_EnableTbttFreeIntr(void)
{
	return;
}

void bcngen_EnableBcnFreeIntr(void)
{
	return;
}

/******************************************************************************
 *
 * Name:  bcngen_DisableBcnFreeIntr
 *
 * Description:
 * Conditions For Use:
 *    None.
 *
 * Arguments:
 *    None.
 *
 * Return Value:
 *    Status indicating success or failure.
 *
 * Notes:
 *    None.
 *
 * PDL:
 *
 * END PDL
 *
 *****************************************************************************/
void bcngen_DisableTbttFreeIntr(void)
{
	return;
}

void bcngen_DisableBcnFreeIntr(void)
{
	return;
}

/******************************************************************************
 *
 * Name: bcn_BeaconFreeIsr
 *
 * Description: This ISR updates the TIM in the Beacon buffer. When the
 *    BCN_BUSY interrupt is raised, the HW MAC is just done with using the
 *    beacon buffer and it is safe for the MAC SW to update the TIM fields.
 *    After updating the beacon buffer, the interrupt is disabled.
 *
 * Conditions For Use:
 *    None.
 *
 * Arguments:
 *    None.
 *
 * Return Value:
 *    Status indicating success or failure.
 *
 * Notes:
 *    None.
 *
 * PDL:
 *
 * END PDL
 *
 *****************************************************************************/

void bcngen_BeaconFreeIsr()
{
	/*----------------------------------------------------------------*/
	/* The beacon body length is calculated as the difference between */
	/* the TIM pointer and the beacon buffer pointer, less the size   */
	/* of the header since that is obviously not part of the body and   */
	/* addition of  size of TIM field                                  */
	/*----------------------------------------------------------------*/
}

/******************************************************************************
 *
 * Name:
 *
 * Description:
 *
 *
 * Conditions For Use:
 *    None.
 *
 * Arguments:
 *    None.
 *
 * Return Value:
 *    Status indicating success or failure.
 *
 * Notes:
 *    Refer to Protocol spec for the variables used.Section 7.3.2.6 page 57-58
 *
 * PDL:
 *
 * END PDL
 *
 *****************************************************************************/
void bcngen_UpdateBitInTim(UINT16 Aid, BOOLEAN Set)
{

	static UINT32 LowByte = 0, HighByte = 0;
	UINT32 N1, N2;
	UINT32 ByteNum, BitNum, Len, i, j;

	os_EnterCriticalSection;

	if (Aid == 0) {
		if (Set == TRUE) {
			/* Set bit 0 in the bit map control */
			Tim.BitmapCtl = Tim.BitmapCtl | 0x01;
		} else {
			Tim.BitmapCtl = Tim.BitmapCtl & 0xFE;

		}
		bcngen_EnableBcnFreeIntr();
		os_ExitCriticalSection;
		return;
	}

	/* Set the corresponding bit in the traffic Map */
	ByteNum = Aid / 8;
	BitNum = Aid % 8;
	if (Set) {
		if (HighByte < ByteNum) {
			HighByte = ByteNum;
			//HighByte +=(HighByte%2);
		}
		TrafficMap[ByteNum] = TrafficMap[ByteNum] | (1 << BitNum);
	} else {
		if ((ByteNum < LowByte) || (ByteNum > HighByte)) {
			//                      printk("ByteNum=%d, LowByte=%d, HighByte=%d\n", ByteNum, LowByte, HighByte);
			//os_ExitCriticalSection;
			//return ;
		}
		TrafficMap[ByteNum] = TrafficMap[ByteNum] & ((1 << BitNum) ^ 0xff);
	}
	N1 = 0;
	N2 = 0;
	for (i = 0; i <= HighByte; i += 2) {
		if (TrafficMap[i] == 0 && TrafficMap[i + 1] == 0)
			N1 += 2;
		else
			break;
	}
	for (j = HighByte; j > i; j--) {
		if (TrafficMap[j]) {
			HighByte = j;
			//HighByte -=(HighByte%2);
			break;
		}
	}

	N2 = j;
	if (N2 > N1)
		Len = (N2 - N1) + 4;
	else
		Len = 4;
	/* if the lowest byte did not change, copy only the changed byte,
	 * if the lowest byte changes, copy the entire map */
	/* copy from byte N1 *2 on to partial bit map bytes */
	TimPtr = &Tim2;
	Tim.PartialVirtualBitmap[0] = 0;

	Tim.Len = Len;

	for (i = 0; i <= N2; i++) {
		Tim.PartialVirtualBitmap[i] = TrafficMap[i + N1];
	}
	if ((N2 == N1 || Len == 4) && Tim.PartialVirtualBitmap[0] == 0)
		N1 = 0;
	TimPtr->BitmapCtl = (TimPtr->BitmapCtl & 0x01) | N1;
	/* Safer update, the beacon should be updated only when beacon free interrupt
	 * occurs */
	/* Enable Beacon Free interrupt */
	bcngen_EnableBcnFreeIntr();
	os_ExitCriticalSection;

}

/******************************************************************************
 *
 * Name:
 *
 * Description:
 *
 *
 * Conditions For Use:
 *    None.
 *
 * Arguments:
 *    None.
 *
 * Return Value:
 *    Status indicating success or failure.
 *
 * Notes:
 *    Refer to Protocol spec for the variables used.Section 7.3.2.6 page 57-58
 *
 * PDL:
 *
 * END PDL
 *
 *****************************************************************************/
void bcngen_UpdateBitInTim2(UINT16 Aid, BOOLEAN Set)
{

	static UINT32 LowByte = 0, HighByte = 0;
	CopyMode_e CopyMode;
	static UINT32 N1, N2, prevN2;
	UINT32 ByteNum, HwordNum, BitNum, Len, i;

	if (Aid == 0) {
		if (Set == TRUE) {
			/* Set bit 0 in the bit map control */
			Tim2.BitmapCtl = Tim2.BitmapCtl | 0x01;
		} else {
			//disable for now     Tim2.BitmapCtl = Tim2.BitmapCtl & 0xFE ;
		}
		bcngen_EnableBcnFreeIntr();

		return;
	}

	/* Set the corresponding bit in the traffic Map */
	ByteNum = Aid / 8;
	HwordNum = Aid / 16;
	BitNum = Aid % 8;
	CopyMode = COPY_BYTE;
	if (Set) {
		if (ByteNum < N1 * 2) {
			N1 = Aid / 16;
			CopyMode = COPY_FULL;
		}
		if (ByteNum > N2) {
			prevN2 = N2;
			N2 = Aid / 8;
			CopyMode = COPY_END;
		}
		TrafficMap2[ByteNum] = TrafficMap2[ByteNum] | (1 << BitNum);
	} else {
		if ((ByteNum < LowByte) || (ByteNum > HighByte))
			return;
		TrafficMap2[ByteNum] = TrafficMap2[ByteNum] & ((1 << BitNum) ^ 0xff);
		if (HwordNum == N1 && *((UINT16 *) TrafficMap2 + HwordNum) == 0) {
			CopyMode = COPY_FULL;
			/* Find the next non zero halfword */
			for (i = N1 + 2; i <= HighByte; i += 2) {
				if ((*(UINT16 *) TrafficMap2) + i != 0) {
					N1 = i / 2;
					break;
				}
			}
		} else if (ByteNum == N2 && TrafficMap2[ByteNum] == 0) {
			CopyMode = COPY_END;
			/* find the previous non zero byte */
			for (i = N2 - 1; i >= LowByte; i--) {
				if (TrafficMap2[i] != 0) {
					N2 = i;
				}
			}
		}
	}
	Len = (N2 - N1 * 2) + 4;

	/* if the lowest byte did not change, copy only the changed byte,
	 * if the lowest byte changes, copy the entire map */
	/* copy from byte N1 *2 on to partial bit map bytes */
	TimPtr2->BitmapCtl = TimPtr2->BitmapCtl & (0x80 | N1);
	Tim2.PartialVirtualBitmap[0] = 0;
	Tim2.Len = Len;
	if (CopyMode == COPY_BYTE)
		Tim2.PartialVirtualBitmap[ByteNum] = TrafficMap2[ByteNum];
	else if (CopyMode == COPY_FULL) {
		for (i = N1 * 2; i <= N2; i++) {
			Tim2.PartialVirtualBitmap[i] = TrafficMap2[i];
		}
	} else if (CopyMode == COPY_END) {
		for (i = prevN2 + 1; i <= N2; i++) {
			Tim2.PartialVirtualBitmap[i] = TrafficMap2[i];
		}
	}
	memcpy((UINT8 *) TimPtr2, (UINT8 *) & Tim2, sizeof(IEEEtypes_InfoElementHdr_t) + Tim2.Len);
	/* Enable Beacon Free interrupt */

}

/******************************************************************************
 *
 * Name:
 *
 * Description:
 *
 *
 * Conditions For Use:
 *    None.
 *
 * Arguments:
 *    None.
 *
 * Return Value:
 *    Status indicating success or failure.
 *
 * Notes:
 *    None.
 *
 * PDL:
 *
 * END PDL
 *
 *****************************************************************************/
/**
 * Update the Probe Response buffer
 * Similar to updating beacon buffer
 *
 * @param StartCmd Pointer to start command parameters
 * @return Number of bytes in the probe response
 */
static void InitHT_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_HT_Element_t * elment)
{
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 *mib_guardInterval_p = mib->mib_guardInterval;
	MIB_STA_CFG *mib_StaCfg = mib->StationConfig;
	UINT8 rxAnt = *(vmacSta_p->Mib802dot11->mib_rxAntenna);
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	if (wlpptr->master)
		wlpptr = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);

	memset(elment, 0, sizeof(IEEEtypes_HT_Element_t));
	elment->ElementId = HT;
	elment->Len = 26;	//foo 25; //fixed

	elment->HTCapabilitiesInfo.MIMOPwSave = 0x3;
	if (*mib_guardInterval_p == 2) {
		elment->HTCapabilitiesInfo.SGI20MHz = 0;
		elment->HTCapabilitiesInfo.SGI40MHz = 0;
	} else {
		elment->HTCapabilitiesInfo.SGI20MHz = 1;
		elment->HTCapabilitiesInfo.SGI40MHz = 1;
	}
	if (PhyDSSSTable->Chanflag.ChnlWidth == CH_20_MHz_WIDTH && (wlpptr->auto_bw != 1))
		elment->HTCapabilitiesInfo.SupChanWidth = 0;
	else
		elment->HTCapabilitiesInfo.SupChanWidth = 1;
	if ((*(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_N_ONLY)
	    || (*(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_A_ONLY)
	    || (*(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_AandG)
	    || (*(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_AandN)
	    || (*(vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_11AC)
#ifdef SOC_W906X
	    || (*(vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_11AX)
#endif
	    )
		elment->HTCapabilitiesInfo.DssCck40MHz = 0;	//beacon sent at 6Mbps
	else
		elment->HTCapabilitiesInfo.DssCck40MHz = 1;	//beacon at 1Mbps

	elment->HTCapabilitiesInfo.DelayedBA = 0;
#ifdef DISABLE_AMSDU		/*If AMSDU disabled, set max AMSDU Rx size to 4K, needed for V6FW */
	elment->HTCapabilitiesInfo.MaxAMSDUSize = 0;
#else
	// Per 11n spec, 8K is supported but not for AMSDU + AMPDU which only 4K is supported
	if (((*(vmacSta_p->Mib802dot11->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_8K))
	    && (!(*(vmacSta_p->Mib802dot11->pMib_11nAggrMode) & WL_MODE_AMPDU_TX)))
		elment->HTCapabilitiesInfo.MaxAMSDUSize = 1;
	else
		elment->HTCapabilitiesInfo.MaxAMSDUSize = 0;
#endif
	//elment->MacHTParamInfo = 1;//for now foo 0628 rxampdu factor to 0 0x3;//0x3;//0x04;

	elment->SupportedMCSset[0] = mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_0;

	switch (rxAnt) {
	case 1:
		break;
	case 2:
		elment->SupportedMCSset[1] = mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_1;
		break;
	case 3:
		elment->SupportedMCSset[1] = mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_1;
		elment->SupportedMCSset[2] = mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_2;
		break;
	default:
		/* rxAnt =0 or > 3 */
		elment->SupportedMCSset[1] = mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_1;
		elment->SupportedMCSset[2] = mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_2;
#ifdef SOC_W906X
		elment->SupportedMCSset[3] = mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_3;
#endif
		break;
	}
	/* enable MCS32 support */
	elment->SupportedMCSset[4] = 0x01;

	elment->MacHTParamInfo = *(vmacSta_p->Mib802dot11->mib_ampdu_factor) | ((*(vmacSta_p->Mib802dot11->mib_ampdu_density) << 2));
#if defined ( INTOLERANT40) || defined (COEXIST_20_40_SUPPORT)

	elment->HTCapabilitiesInfo.FortyMIntolerant = *(vmacSta_p->Mib802dot11->mib_FortyMIntolerant);
#endif

	if (*(vmacSta_p->Mib802dot11->mib_HtGreenField))
		elment->HTCapabilitiesInfo.GreenField = 1;
	else
		elment->HTCapabilitiesInfo.GreenField = 0;

	if (*(vmacSta_p->Mib802dot11->mib_HtStbc)) {
		elment->HTCapabilitiesInfo.TxSTBC = 1;
		elment->HTCapabilitiesInfo.RxSTBC = 1;	/* The first spatial stream */
	} else {
		elment->HTCapabilitiesInfo.TxSTBC = 0;
		elment->HTCapabilitiesInfo.RxSTBC = 0;
	}
	elment->HTCapabilitiesInfo.AdvCoding = 1;
#ifdef EXPLICIT_BF
	elment->TxBFCapabilities = txbfcap;
#endif

}

#ifdef INTEROP

/** for I_COMP only, not use anymore  **/
static void Init_Generic_HT_IE2(vmacApInfo_t * vmacSta_p, IEEEtypes_Generic_HT_Element_t2 * elment)
{
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = vmacSta_p->Mib802dot11->PhyDSSSTable;
	UINT8 *mib_guardInterval_p = vmacSta_p->Mib802dot11->mib_guardInterval;

	memset(elment, 0, sizeof(IEEEtypes_Generic_HT_Element_t2));

	elment->ElementId = 221;
	elment->Len = 0x1f;	//fixed for now
	elment->OUI[0] = 0x00;
	elment->OUI[1] = 0x17;
	elment->OUI[2] = 0x35;
	elment->OUIType = 51; /** Temp IE for HT Capabilities Info field **/
	elment->Len2 = 0x1a;

	elment->HTCapabilitiesInfo.MIMOPwSave = 0x3;	//only static supported0x3; /** Mimo enable, no restriction on what may be sent to the STA  **/

	if (*mib_guardInterval_p == 2) {
		elment->HTCapabilitiesInfo.SGI20MHz = 0;
		elment->HTCapabilitiesInfo.SGI40MHz = 0;
	} else {
		elment->HTCapabilitiesInfo.SGI20MHz = 1;
		elment->HTCapabilitiesInfo.SGI40MHz = 1;
	}
	if (PhyDSSSTable->Chanflag.ChnlWidth == CH_20_MHz_WIDTH)
		elment->HTCapabilitiesInfo.SupChanWidth = 0;
	else
		elment->HTCapabilitiesInfo.SupChanWidth = 1;
	if (*(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_N_ONLY)
		elment->HTCapabilitiesInfo.DssCck40MHz = 0;	//beacon sent at 6Mbps
	else
		elment->HTCapabilitiesInfo.DssCck40MHz = 1;	//beacon at 1Mbps
	elment->HTCapabilitiesInfo.DelayedBA = 1;

	// Per 11n spec, 8K is supported but not for AMSDU + AMPDU which only 4K is supported
	if (((*(vmacSta_p->Mib802dot11->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_8K))
	    && (!(*(vmacSta_p->Mib802dot11->pMib_11nAggrMode) & WL_MODE_AMPDU_TX)))
		elment->HTCapabilitiesInfo.MaxAMSDUSize = 1;
	else
		elment->HTCapabilitiesInfo.MaxAMSDUSize = 0;
	//elment->MacHTParamInfo = 0x04;
	elment->SupportedMCSset[0] = 0xff;
	elment->SupportedMCSset[1] = 0xff;
	elment->MacHTParamInfo = *(vmacSta_p->Mib802dot11->mib_ampdu_factor) | (*(vmacSta_p->Mib802dot11->mib_ampdu_density) << 2);
	if (*(vmacSta_p->Mib802dot11->mib_3x3Rate))
		elment->SupportedMCSset[2] = 0xff;
	else
		elment->SupportedMCSset[2] = 0x00;

	if (*(vmacSta_p->Mib802dot11->mib_HtGreenField))
		elment->HTCapabilitiesInfo.GreenField = 1;
	else
		elment->HTCapabilitiesInfo.GreenField = 0;

	if (*(vmacSta_p->Mib802dot11->mib_HtStbc)) {
		elment->HTCapabilitiesInfo.TxSTBC = 1;
		elment->HTCapabilitiesInfo.RxSTBC = 1;	/* The first spatial stream */
	} else {
		elment->HTCapabilitiesInfo.TxSTBC = 0;
		elment->HTCapabilitiesInfo.RxSTBC = 0;
	}

#ifdef EXPLICIT_BF
	elment->TxBFCapabilities = txbfcap;
#endif

}

UINT16 Add_Generic_HT_IE2(vmacApInfo_t * vmacSta_p, IEEEtypes_Generic_HT_Element_t2 * pNextElement)
{
	if ((*(vmacSta_p->Mib802dot11->mib_ApMode) & 0x4) && vmacSta_p->Mib802dot11->StationConfig->WSMQoSOptImpl) {
		Init_Generic_HT_IE2(vmacSta_p, pNextElement);
		return (pNextElement->Len + 2);
	} else
		return 0;
}
#endif
UINT16 AddHT_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_HT_Element_t * pNextElement)
{
	if ((IsHTmode(*(vmacSta_p->Mib802dot11->mib_ApMode))) && vmacSta_p->Mib802dot11->StationConfig->WSMQoSOptImpl) {
		InitHT_IE(vmacSta_p, pNextElement);
		return (pNextElement->Len + 2);
	} else
		return 0;
}

static void InitAddHT_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_Add_HT_Element_t * elment)
{
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = vmacSta_p->Mib802dot11->PhyDSSSTable;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

	memset(elment, 0, sizeof(IEEEtypes_Add_HT_Element_t));
	elment->ElementId = ADD_HT;
	elment->Len = 22;	//>=22
	elment->ControlChan = PhyDSSSTable->CurrChan;

#if defined ( INTOLERANT40) || defined (COEXIST_20_40_SUPPORT)
	/** fktang to check wheter 2.4G **/
	if (*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler) && (*(mib->USER_ChnlWidth) == 0)) {

		elment->AddChan.ExtChanOffset = 0;
		elment->AddChan.STAChannelWidth = 0;

	} else
#endif
	if (PhyDSSSTable->Chanflag.ChnlWidth != CH_20_MHz_WIDTH) {
		elment->AddChan.ExtChanOffset = PhyDSSSTable->Chanflag.ExtChnlOffset;
		elment->AddChan.STAChannelWidth = 1;
	}
	if (*(vmacSta_p->Mib802dot11->mib_rifsQNum))
		elment->AddChan.RIFSMode = 1;	//pWlSysCfg->Mib802dot11->mib_rifsQNum;
	if (*(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_N_ONLY) {
		elment->OpMode.OpMode = 0;
		elment->BscMCSSet[0] = 0xff;
		elment->BscMCSSet[1] = 0xff;
	} else {
		elment->OpMode.OpMode = 0;
	}
	if (*(mib->mib_HtGreenField)) {
		if (vmacSta_p->NonGFSta || wlpptr->wlpd_p->NonGFSta)
			elment->OpMode.NonGFStaPresent = 1;
		else
			elment->OpMode.NonGFStaPresent = 0;
	} else
		elment->OpMode.NonGFStaPresent = 1;
#ifdef SUPPORTED_EXT_NSS_BW
#if defined (TEST_160M_CASE_4_2_58) || defined(TEST_160M_CASE_5_2_65)
	elment->OpMode.center_freq2 = 50;
#else
	elment->OpMode.center_freq2 = 0;
#endif
#endif

#ifdef COEXIST_20_40_SUPPORT
	if (*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler)) {
		if (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_2DOT4GHZ &&
		    (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH || PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH)) {
			if (wlpptr->wlpd_p->BcnAddHtAddChannel == 0) {
				elment->AddChan.STAChannelWidth = 0;
				elment->AddChan.ExtChanOffset = 0;
			} else {
				elment->AddChan.ExtChanOffset = PhyDSSSTable->Chanflag.ExtChnlOffset;
				elment->AddChan.STAChannelWidth = 1;
			}
		}
	}
#endif
	if (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_2DOT4GHZ)
		elment->OpMode.OpMode = (wlpptr->wlpd_p->BcnAddHtOpMode & 0x3);
}

UINT16 AddAddHT_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_Add_HT_Element_t * pNextElement)
{
	if (IsHTmode(*(vmacSta_p->Mib802dot11->mib_ApMode)) && vmacSta_p->Mib802dot11->StationConfig->WSMQoSOptImpl) {
		InitAddHT_IE(vmacSta_p, pNextElement);
		return (pNextElement->Len + 2);
	} else
		return 0;
}

#ifdef INTEROP
#if 0
static void Init_Generic_AddHT_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_Generic_Add_HT_Element_t * elment)
{
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = vmacSta_p->Mib802dot11->PhyDSSSTable;

	memset(elment, 0, sizeof(IEEEtypes_Generic_Add_HT_Element_t));

	elment->ElementId = 221;
	elment->Len = 26;	//fixed for now
	elment->OUI[0] = 0x00;
	elment->OUI[1] = 0x90;
	elment->OUI[2] = 0x4c;
	elment->OUIType = 52; /** Temp IE for HT Capabilities Info field **/

	elment->ControlChan = PhyDSSSTable->CurrChan;
#ifdef INTOLERANT40
	if (*(vmacSta_p->Mib802dot11->mib_FortyMIntolerant)) {
		elment->AddChan.ExtChanOffset = 0;
		elment->AddChan.STAChannelWidth = 0;
	} else
#endif
	if (PhyDSSSTable->Chanflag.ChnlWidth != CH_20_MHz_WIDTH) {
		elment->AddChan.ExtChanOffset = PhyDSSSTable->Chanflag.ExtChnlOffset;
		elment->AddChan.STAChannelWidth = 1;
	}
	if (*(vmacSta_p->Mib802dot11->mib_rifsQNum))
		elment->AddChan.RIFSMode = 1;
	if (*(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_N_ONLY) {
		elment->OpMode.OpMode = 0;
		elment->BscMCSSet[0] = 0xff;
		elment->BscMCSSet[1] = 0xff;
	} else {
		elment->OpMode.OpMode = 0;
	}
}

UINT16 Add_Generic_AddHT_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_Generic_Add_HT_Element_t * pNextElement)
{
	return 0;

}
#endif				//0
static void Init_Generic_AddHT_IE2(vmacApInfo_t * vmacSta_p, IEEEtypes_Generic_Add_HT_Element_t2 * elment)
{
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = vmacSta_p->Mib802dot11->PhyDSSSTable;

	memset(elment, 0, sizeof(IEEEtypes_Generic_Add_HT_Element_t2));

	elment->ElementId = 221;
	elment->Len = 27;	//fixed for now
	elment->OUI[0] = 0x00;
	elment->OUI[1] = 0x17;
	elment->OUI[2] = 0x35;
	elment->OUIType = 52; /** Temp IE for HT Capabilities Info field **/
	elment->Len2 = 27 - 5;

	elment->ControlChan = PhyDSSSTable->CurrChan;

	if (PhyDSSSTable->Chanflag.ChnlWidth != CH_20_MHz_WIDTH) {
		elment->AddChan.ExtChanOffset = PhyDSSSTable->Chanflag.ExtChnlOffset;
		elment->AddChan.STAChannelWidth = 1;
	}
	elment->AddChan.RIFSMode = *(vmacSta_p->Mib802dot11->mib_rifsQNum);
	if ((*(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_N_ONLY)) {
		elment->OpMode.OpMode = 0;
		elment->BscMCSSet[0] = 0xff;
		elment->BscMCSSet[1] = 0xff;
	} else {
		elment->OpMode.OpMode = 0;
	}
}

UINT16 Add_Generic_AddHT_IE2(vmacApInfo_t * vmacSta_p, IEEEtypes_Generic_Add_HT_Element_t2 * pNextElement)
{
	if ((*(vmacSta_p->Mib802dot11->mib_ApMode) & 0x4) && vmacSta_p->Mib802dot11->StationConfig->WSMQoSOptImpl) {
		Init_Generic_AddHT_IE2(vmacSta_p, pNextElement);
		return (pNextElement->Len + 2);
	} else
		return 0;
}
#endif
IEEEtypes_M_Element_t M_COMP_ID_IE = { PROPRIETARY_IE, 6, {0, 0x50, 0x43}
, 3, 0, 0 };

static void InitM_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_M_Element_t * element)
{
	memcpy((UINT8 *) element, (UINT8 *) & M_COMP_ID_IE, sizeof(IEEEtypes_M_Element_t));
}

UINT16 AddM_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_HT_Element_t * pNextElement)
{
	if ((*(vmacSta_p->Mib802dot11->mib_ApMode) & 0x4)) {
		InitM_IE(vmacSta_p, (IEEEtypes_M_Element_t *) pNextElement);
		return (pNextElement->Len + 2);
	} else
		return 0;
}

BOOLEAN isMcIdIE(UINT8 * data_p)
{
	IEEEtypes_M_Element_t *ie;

	ie = (IEEEtypes_M_Element_t *) data_p;
	if (memcmp((UINT8 *) ie, (UINT8 *) & M_COMP_ID_IE, 7))
		return FALSE;
	if (ie->Version > M_COMP_ID_IE.Version) {
		//todo
	}
	return TRUE;
}

IEEEtypes_M_Rptr_Element_t M_COMP_RPTR_ID_IE = { PROPRIETARY_IE, 38, {0, 0x40, 0x96}
, 0x27, 0x00, 0x10, {0}
};

static void InitM_Rptr_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_M_Rptr_Element_t * element)
{
	memcpy(M_COMP_RPTR_ID_IE.RptrDeviceType, vmacSta_p->Mib802dot11->mib_RptrDeviceType, strlen(vmacSta_p->Mib802dot11->mib_RptrDeviceType));
	memcpy((UINT8 *) element, (UINT8 *) & M_COMP_RPTR_ID_IE, sizeof(IEEEtypes_M_Rptr_Element_t));
}

UINT16 AddM_Rptr_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_HT_Element_t * pNextElement)
{
	InitM_Rptr_IE(vmacSta_p, (IEEEtypes_M_Rptr_Element_t *) pNextElement);
	return (pNextElement->Len + 2);
}

IEEEtypes_VendorSpec_VHT_Element_t VendorSpec_VHT_IE;
UINT16 Add_VendorSpec_VHT_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_HT_Element_t * pNextElement)
{
	int len = 0;
	memset(&VendorSpec_VHT_IE, 0, sizeof(IEEEtypes_VendorSpec_VHT_Element_t));

	VendorSpec_VHT_IE.ElementId = PROPRIETARY_IE;
	VendorSpec_VHT_IE.OUI[0] = 0x0;	// Epigram
	VendorSpec_VHT_IE.OUI[1] = 0x90;
	VendorSpec_VHT_IE.OUI[2] = 0x4c;
	VendorSpec_VHT_IE.OUIType = 0x4;	// VENDOR_VHT_TYPE
	VendorSpec_VHT_IE.OUISubType = 0x8;	// VENDOR_VHT_SUBTYPE
	VendorSpec_VHT_IE.Len = 5;	// IE Len: OUI + OUIType + OUISubType

	len = Build_IE_191(vmacSta_p, (UINT8 *) & VendorSpec_VHT_IE.VHTData, FALSE, 0);	// VHTData: VHT cap
	VendorSpec_VHT_IE.Len += len;

	len = Build_IE_192(vmacSta_p, (UINT8 *) & VendorSpec_VHT_IE.VHTData[len]);	// VHTData: VHT info
	VendorSpec_VHT_IE.Len += len;

	memcpy(pNextElement, &VendorSpec_VHT_IE, VendorSpec_VHT_IE.Len + 2);
	return (pNextElement->Len + 2);
}

#ifdef SOC_W906X
void update_nontxd_bssid_profile_ssid(vmacApInfo_t * vmacSta_p, void *pssidIE, UINT8 ssid_len)
{
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	IEEEtypes_SsIdElement_t *ssid_p = &vmacSta_p->NonTxBssidProf.ssid;

	memcpy((void *)ssid_p, (void *)pssidIE, sizeof(IEEEtypes_InfoElementHdr_t) + ssid_len);

}

void update_nontxd_bssid_profile_cap(vmacApInfo_t * vmacSta_p, UINT16 CapInfo)
{
	IEEEtypes_NonTransmitted_BSSID_Cap_t *pCap = &vmacSta_p->NonTxBssidProf.ntBssidCap;

	pCap->ElementId = NONTX_BSSID_CAP;
	pCap->Len = 2;
	*(UINT16 *) & (pCap->CapInfo) = CapInfo;

	//printk("%s: NonTransmitted BSSID Cap:%04x\n",__func__, CapInfo);
}

void update_nontxd_bssid_profile_bssidIdx(vmacApInfo_t * vmacSta_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	IEEEtypes_mbssid_idx_t *pidx = &vmacSta_p->NonTxBssidProf.mbssidIdx;
	u32 primbss;
	u8 *pRefBssid = NULL;
	u8 *pmac = NULL;
	u8 idx = 0;
	u32 mbssidGID;
	struct wlprivate *wlp_primbss = NULL;
	struct wlprivate *wlp_master = NULL;
	u8 mask;

	for (mbssidGID = 0; mbssidGID < MAX_MBSSID_SET; mbssidGID++) {
		mbss_set_t *pset = &wlpptr->wlpd_p->mbssSet[mbssidGID];

		if (pset->mbssid_set & (1 << vmacSta_p->VMacEntry.macId)) {
			//dralee
			//printk("macId:%u in mbssid Group:%u\n",vmacSta_p->VMacEntry.macId, mbssidGID);
			break;
		}
	}

	if (mbssidGID == MAX_MBSSID_SET)
		return;

	primbss = wlpd_p->mbssSet[mbssidGID].primbss;

	pidx->ElementId = MBSSID_INDEX;
	pidx->Len = 3;
	pidx->BssidIdx = 0;

	//printk("primbss:%u\n", primbss);
	if (primbss == bss_num) {	// || primbss == vmacSta_p->VMacEntry.macId)
		return;
	}
	//wlp_primbss = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);
	wlp_master = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);
	wlp_primbss = NETDEV_PRIV_P(struct wlprivate, wlp_master->vdev[primbss]);

	if (wlp_primbss->vmacSta_p->VMacEntry.macId != primbss) {
		printk("Error: MacId inconsistent:%u, %u\n", wlp_primbss->vmacSta_p->VMacEntry.macId, primbss);
	}

	pRefBssid = wlp_primbss->vmacSta_p->VMacEntry.vmacAddr;
	pmac = wlpptr->vmacSta_p->VMacEntry.vmacAddr;

	//printk("Ref BSSID:%02x%02x%02x%02x%02x%02x\n",
	//      pRefBssid[0],pRefBssid[1],pRefBssid[2],pRefBssid[3],pRefBssid[4],pRefBssid[5]);
	//printk("Vap mac:%02x%02x%02x%02x%02x%02x\n",
	//      pmac[0],pmac[1],pmac[2],pmac[3],pmac[4],pmac[5]);

	if (memcmp(pRefBssid, pmac, 5)) {
		printk("Error: Abnormal mac address between ref BSSID:%02x%02x%02x%02x%02x%02x and dev mac:%02x%02x%02x%02x%02x%02x\n",
		       pRefBssid[0], pRefBssid[1], pRefBssid[2], pRefBssid[3], pRefBssid[4], pRefBssid[5],
		       pmac[0], pmac[1], pmac[2], pmac[3], pmac[4], pmac[5]);
	}

	mask = (0xFF >> (8 - Get_MaxBssid_Indicator(SMAC_BSS_NUM)));

	idx = (pmac[5] - pRefBssid[5]) & mask;
	pidx->ElementId = MBSSID_INDEX;
	pidx->Len = 3;
	pidx->BssidIdx = idx;
	//printk("mbssid-idx=%x\n", (u8)idx);
}

void init_NonTx_bssid_cap(vmacApInfo_t * vmacSta_p, void *element)
{
	IEEEtypes_NonTransmitted_BSSID_Cap_t *pCap = &vmacSta_p->NonTxBssidProf.ntBssidCap;

	memcpy((void *)element, (void *)pCap, pCap->Len + 2);
}

void init_nontxd_bssid_ssid(vmacApInfo_t * vmacSta_p, void *pssidIE)
{
	IEEEtypes_SsIdElement_t *ssid_p = &vmacSta_p->NonTxBssidProf.ssid;

	memcpy((void *)pssidIE, (void *)ssid_p, ssid_p->Len + 2);
}

void init_nontxd_bssid_profile_bssidIdx(vmacApInfo_t * vmacSta_p, void *pmbssidIdx)
{
	IEEEtypes_mbssid_idx_t *pidx = &vmacSta_p->NonTxBssidProf.mbssidIdx;

	memcpy((void *)pmbssidIdx, (void *)pidx, pidx->Len + 2);
}

u8 Add_NonTxProfile_IEs(vmacApInfo_t * vmacSta_p, u8 * pnext)
{
	u8 total_len = 0;
	IEEEtypes_NonTransmitted_BSSID_Cap_t *pcap;

	IEEEtypes_SsIdElement_t *pssid;
	IEEEtypes_mbssid_idx_t *pidx;
	IEEEtypes_NonTransmitted_BSSID_Profile_t *pNonTxPf;

	pNonTxPf = (IEEEtypes_NonTransmitted_BSSID_Profile_t *) pnext;
	pNonTxPf->subElementId = NONTRANSMITTED_BSSID_PROFILE_SUBELM_ID;
	total_len += 2;

	init_NonTx_bssid_cap(vmacSta_p, (pnext + total_len));
	pcap = (IEEEtypes_NonTransmitted_BSSID_Cap_t *) (pnext + total_len);
	total_len += (pcap->Len + 2);

	init_nontxd_bssid_ssid(vmacSta_p, (pnext + total_len));
	pssid = (IEEEtypes_SsIdElement_t *) (pnext + total_len);
	total_len += (pssid->Len + 2);

	init_nontxd_bssid_profile_bssidIdx(vmacSta_p, (pnext + total_len));
	pidx = (IEEEtypes_mbssid_idx_t *) (pnext + total_len);
	total_len += (pidx->Len + 2);

	pNonTxPf->Len = total_len - 2;

	return total_len;
}

/*
	Get the max_bssid_indicator from number of bss
	- returned value: n, where 2^n >= bss_num
*/

u8 Get_MaxBssid_Indicator(U32 bss_num)
{
	// Note: 2^0 == 1
	//              bss_num>=1, 1==reference/transmit bss
	u8 idx = 0;
	U32 max_bss_num = 1;	//==2^0
	while (max_bss_num < bss_num) {
		idx++;
		max_bss_num <<= 1;
	}
	return idx;
}

void Init_Mbssid_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_Mbssid_Element_t * element)
{
	u8 ie_len = 0;
	u8 *pnext;

	element->ElementId = MULTI_BSSID;
	element->MaxBssidIndictor = Get_MaxBssid_Indicator(bss_num);
	pnext = (u8 *) ((u8 *) & (element->MaxBssidIndictor) + 1);
	ie_len = Add_NonTxProfile_IEs(vmacSta_p, pnext);

	element->Len = ie_len + 1;	//fixed for now
}

UINT8 Add_Mbssid_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_Mbssid_Element_t * pNextElement)
{
	Init_Mbssid_IE(vmacSta_p, pNextElement);

	return (pNextElement->Len + 2);
}
#endif

BOOLEAN isM_RptrIdIE(UINT8 * data_p)
{
	IEEEtypes_M_Element_t *ie;

	ie = (IEEEtypes_M_Element_t *) data_p;
	if (memcmp((UINT8 *) ie, (UINT8 *) & M_COMP_RPTR_ID_IE, 7))
		return FALSE;
	if (ie->Version > M_COMP_ID_IE.Version) {
		//todo
	}
	return TRUE;
}

#ifdef MULTI_AP_SUPPORT
UINT16 Get_MultiAP_IE_Size(vmacApInfo_t * vmacSta_p)
{
	UINT16 size = MAP_R1_IE_SIZE;

	/* Add Version subelement into Multi-AP IE for R2, Table 3 *
	 * Version subelement omitted by Multi-AP R1 devices.      */
	if (vmacSta_p->Mib802dot11->multi_ap_ver == 2)
		size += sizeof(IEEEtypes_MultiAP_Version_t);

	/* Add Traffic subelement into Multi-AP IE, Table 3 *
	 * Only for Backhaul BSS, Section 5.2               */
	if ((vmacSta_p->Mib802dot11->multi_ap_vid) && (vmacSta_p->Mib802dot11->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS))
		size += sizeof(IEEEtypes_MultiAP_Traffic_t);

	return size;
}

void Init_MultiAP_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_MultiAP_Element_t * element, UINT8 protocol_type)
{
	//IEEEtypes_MultiAP_Element_t   MultiAP_IE;
	IEEEtypes_MultiAP_Element_t *MultiAP_IE = NULL;
	UINT16 version_len = 0;
	UINT8 multi_ap_attr = vmacSta_p->Mib802dot11->multi_ap_attr;
	UINT8 multi_ap_ver = vmacSta_p->Mib802dot11->multi_ap_ver;
	UINT16 multi_ap_vid = vmacSta_p->Mib802dot11->multi_ap_vid;
	UINT16 size = Get_MultiAP_IE_Size(vmacSta_p);

	MultiAP_IE = wl_kmalloc(size, GFP_ATOMIC);
	memset(MultiAP_IE, 0x00, size);
	MultiAP_IE->ElementId = PROPRIETARY_IE;
	MultiAP_IE->Len = (size - 2);
	MultiAP_IE->OUI[0] = 0x50;
	MultiAP_IE->OUI[1] = 0x6F;
	MultiAP_IE->OUI[2] = 0x9A;
	MultiAP_IE->OUIType = MultiAP_OUI_type;
	MultiAP_IE->attributes.Attribute = 0x06;
	MultiAP_IE->attributes.Attribute_Len = 0x01;
	if (protocol_type == WL_WLAN_TYPE_AP) {
		MultiAP_IE->attributes.BackBSS = ((multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS) >> 6);
		MultiAP_IE->attributes.FrontBSS = ((multi_ap_attr & MAP_ATTRIBUTE_FRONTHAUL_BSS) >> 5);
		MultiAP_IE->attributes.TearDown = ((multi_ap_attr & MAP_ATTRIBUTE_TEARDOWN) >> 4);
		//if (MultiAP_IE->attributes.BackBSS) { /* TBD: if check bBSS? need specificatoin clarification */
		/* Encode bit 3 and bit 4 for R2, Table 4. */
		MultiAP_IE->attributes.R1bSTAdisAllowed = ((multi_ap_attr & MAP_ATTRIBUTE_R1BSTA_DISALLOWED) >> 3);
		MultiAP_IE->attributes.R2bSTAdisAllowed = ((multi_ap_attr & MAP_ATTRIBUTE_R2BSTA_DISALLOWED) >> 2);
		//}
	}
	//else {
	//      MultiAP_IE->attributes.BackSTA =
	//              ((multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_STA) >> 7);
	//}

	/* Add Version subelement into Multi-AP IE for R2, Table 3 *
	 * Version subelement omitted by Multi-AP R1 devices.      */
	//MultiAP_IE.version[0] = 0x00; //Subelement ID: TBD
	//MultiAP_IE.version[1] = 0x01; //Subelement Length: 1
	//MultiAP_IE.version[2] = multi_ap_ver; //Subelement Value: Variable
	if (multi_ap_ver == 2) {
		IEEEtypes_MultiAP_Version_t *version = (IEEEtypes_MultiAP_Version_t *) MultiAP_IE->variable;

		version->ElementId = 0x07;
		version->Len = 0x01;
		version->value = multi_ap_ver;
		version_len += (version->Len + 2);
	}

	/* Add Traffic subelement into Multi-AP IE, Table 3 *
	 * Only for Backhaul BSS, Section 5.2               */
	if ((multi_ap_vid) && (multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS)) {
		IEEEtypes_MultiAP_Traffic_t *traffic = (IEEEtypes_MultiAP_Traffic_t *) (MultiAP_IE->variable + version_len);

		traffic->ElementId = 0x08;
		traffic->Len = 0x02;
		traffic->vid = multi_ap_vid;	//(UINT16)SHORT_SWAP(multi_ap_vid);
	}

	memcpy((UINT8 *) element, (UINT8 *) MultiAP_IE, size);
	wl_kfree(MultiAP_IE);
}

UINT16 Add_MultiAP_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_InfoElementHdr_t * pNextElement, UINT8 protocol_type)
{
	Init_MultiAP_IE(vmacSta_p, (IEEEtypes_MultiAP_Element_t *) pNextElement, protocol_type);
	//memcpy((UINT8 *)pNextElement, (UINT8 *)&(vmacSta_p->MultiAP_IE), sizeof(IEEEtypes_MultiAP_Element_t));

	return (pNextElement->Len + 2);
}
#endif				/*MULTI_AP_SUPPORT */

UINT8 getRegulatoryClass(vmacApInfo_t * vmacSta_p)
{
	UINT8 reg_code = DOMAIN_CODE_FCC;
	UINT8 RegulatoryClass = 0;
	UINT8 current_chan = vmacSta_p->Mib802dot11->PhyDSSSTable->CurrChan;
	UINT8 chan_width = vmacSta_p->Mib802dot11->PhyDSSSTable->Chanflag.ChnlWidth;

	/* Mapping Domain Code to Regulatory Code */
	reg_code = domainGetRegulatory(domainGetDomain());

	/* IEEE Std 802.11-2016 Table E-3 */
	if (reg_code == DOMAIN_CODE_FCC) {
		switch (current_chan) {
		case 1:
		case 2:
		case 3:
		case 4:
			switch (chan_width) {
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 32;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 12;
				break;
			}
			break;
		case 5:
		case 6:
		case 7:
			switch (chan_width) {
			case CH_40_MHz_WIDTH:
				if (vmacSta_p->Mib802dot11->PhyDSSSTable->Chanflag.ExtChnlOffset == EXT_CH_BELOW_CTRL_CH)
					RegulatoryClass = 32;
				else
					RegulatoryClass = 33;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 12;
				break;
			}
			break;
		case 8:
		case 9:
		case 10:
		case 11:
			switch (chan_width) {
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 33;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 12;
				break;
			}
			break;
		case 36:
		case 44:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 22;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 1;
				break;
			}
			break;
		case 40:
		case 48:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 27;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 1;
				break;
			}
			break;
		case 52:
		case 60:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 23;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 2;
				break;
			}
			break;
		case 56:
		case 64:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 28;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 2;
				break;
			}
			break;
		case 149:
		case 157:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 25;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 5;
				break;
			}
			break;
		case 100:
		case 108:
		case 116:
		case 124:
		case 132:
		case 140:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 24;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 4;
				break;
			}
			break;
		case 104:
		case 112:
		case 120:
		case 128:
		case 136:
		case 144:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 29;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 4;
				break;
			}
			break;
		case 153:
		case 161:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 30;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 5;
				break;
			}
			break;
		case 165:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				/* no channel set */
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 5;
				break;
			}
			break;
		default:
			break;
		}
	} else if (reg_code == DOMAIN_CODE_ETSI) {
		switch (current_chan) {
		case 1:
		case 2:
		case 3:
		case 4:
			switch (chan_width) {
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 11;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 4;
				break;
			}
			break;
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
			switch (chan_width) {
			case CH_40_MHz_WIDTH:
				if (vmacSta_p->Mib802dot11->PhyDSSSTable->Chanflag.ExtChnlOffset == EXT_CH_BELOW_CTRL_CH)
					RegulatoryClass = 11;
				else
					RegulatoryClass = 12;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 4;
				break;
			}
			break;
		case 10:
		case 11:
		case 12:
		case 13:
			switch (chan_width) {
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 12;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 4;
				break;
			}
			break;
		case 36:
		case 44:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 5;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 1;
				break;
			}
			break;
		case 52:
		case 60:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 6;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 2;
				break;
			}
			break;
		case 40:
		case 48:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 8;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 1;
				break;
			}
			break;
		case 56:
		case 64:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 9;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 2;
				break;
			}
			break;
		case 100:
		case 108:
		case 116:
		case 124:
		case 132:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 7;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 3;
				break;
			}
			break;
		case 104:
		case 112:
		case 120:
		case 128:
		case 136:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 10;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 3;
				break;
			}
			break;
		case 140:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				/* no channel set */
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 3;
				break;
			}
			break;
		case 149:
		case 157:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 126;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 17;
				break;
			}
			break;
		case 153:
		case 161:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 127;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 17;
				break;
			}
			break;
		case 165:
		case 169:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				/* no channel set */
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 17;
				break;
			}
			break;
		default:
			break;
		}
	} else if ((reg_code == DOMAIN_CODE_MKK) || (reg_code == DOMAIN_CODE_MKK_N)) {
		switch (current_chan) {
		case 1:
		case 2:
		case 3:
		case 4:
			switch (chan_width) {
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 56;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 30;
				break;
			}
			break;
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
			switch (chan_width) {
			case CH_40_MHz_WIDTH:
				if (vmacSta_p->Mib802dot11->PhyDSSSTable->Chanflag.ExtChnlOffset == EXT_CH_BELOW_CTRL_CH)
					RegulatoryClass = 56;
				else
					RegulatoryClass = 57;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 30;
				break;
			}
			break;
		case 10:
		case 11:
		case 12:
		case 13:
			switch (chan_width) {
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 57;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 30;
				break;
			}
			break;
		case 14:
			RegulatoryClass = 31;
			break;
		case 36:
		case 44:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 36;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 1;
				break;
			}
			break;

		case 40:
		case 48:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 41;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 1;
				break;
			}
			break;
		case 52:
		case 60:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 37;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 32;
				break;
			}
			break;
		case 56:
		case 64:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 42;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 32;
				break;
			}
			break;
		case 100:
		case 108:
		case 116:
		case 124:
		case 132:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 39;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 34;
				break;
			}
			break;
		case 104:
		case 112:
		case 120:
		case 128:
		case 136:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				RegulatoryClass = 44;
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 34;
				break;
			}
			break;
		case 140:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				/* no channel set */
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 34;
				break;
			}
			break;
		case 144:
			switch (chan_width) {
			case CH_160_MHz_WIDTH:
				RegulatoryClass = 129;
				break;
			case CH_80_MHz_WIDTH:
				RegulatoryClass = 128;
				break;
			case CH_40_MHz_WIDTH:
				/* no channel set */
				break;
			case CH_20_MHz_WIDTH:
				RegulatoryClass = 34;
				break;
			}
			break;
		default:
			break;
		}
	}
	if (!RegulatoryClass) {
		if (current_chan < 36) {
			RegulatoryClass = 81;
		} else {
			RegulatoryClass = 115;
		}
	}

	return RegulatoryClass;
}

//#ifdef INTOLERANT40
static void InitChanReport_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_ChannelReportEL_t * elment)
{
	UINT8 ch_list[IEEEtypes_MAX_CHANNELS];

	memset(elment, 0, sizeof(IEEEtypes_ChannelReportEL_t));
	elment->ElementId = CHAN_REPORT;
	elment->RegClass = getRegulatoryClass(vmacSta_p);
	if (get_ch_report_list_by_reg_code(domainGetRegulatory(domainGetDomain()), elment->RegClass, ch_list)) {
		memcpy(elment->ChanList, &ch_list[0], IEEEtypes_MAX_CHANNELS);
		elment->Len = 1 + strlen(&elment->ChanList[0]);
	} else {
		memset(elment, 0, sizeof(IEEEtypes_ChannelReportEL_t));
	}
}

UINT16 AddChanReport_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_ChannelReportEL_t * pNextElement)
{
	InitChanReport_IE(vmacSta_p, (IEEEtypes_ChannelReportEL_t *) pNextElement);
	if (pNextElement->Len)
		return (pNextElement->Len + 2);
	else
		return 0;
}

//#endif

#ifdef COEXIST_20_40_SUPPORT
static void InitExtended_Cap_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_Extended_Cap_Element_t * elment)
{
	memset(elment, 0, sizeof(IEEEtypes_Extended_Cap_Element_t));
	elment->ElementId = EXT_CAP_IE;
	elment->ExtCap._20_40Coexistence_Support = 1;
#ifdef AP_STEERING_SUPPORT
	elment->ExtCap.BSSTransition = *(vmacSta_p->Mib802dot11->mib_btm_enabled);
#endif

#ifdef SOC_W906X
#ifdef AP_TWT
	//twt
	//per HE-Settings-v1.7.xlsx. AP setting.
	if (*(vmacSta_p->Mib802dot11->he_twt_activated) == 1) {
		if (vmacSta_p->OpMode > WL_OP_MODE_VAP)
			elment->ExtCap.twt_requester_support = 1;	//sta mode
		else
			elment->ExtCap.twt_responder_support = 1;	//ap mode
	}
#endif
	if (*(vmacSta_p->Mib802dot11->mib_mbssid) == 1) {
		elment->ExtCap.MultipleBSSID = 1;
		elment->ExtCap.complete_nontxbss_profile = 1;
	}
#endif

	if ((*(vmacSta_p->Mib802dot11->mib_ApMode) & (AP_MODE_B_ONLY | AP_MODE_G_ONLY)) == 0) {
		elment->ExtCap._20_40Coexistence_Support = 0;
	}
	elment->ExtCap.OpModeNotification = 1;
#ifdef DOT11V_DMS
	elment->ExtCap.DMS = *(vmacSta_p->Mib802dot11->mib_dms);
#endif
#ifdef MBO_SUPPORT
	elment->ExtCap.WNMNotification = vmacSta_p->Mib802dot11->mib_mbo_wnm;
	elment->ExtCap.Interworking = vmacSta_p->Mib802dot11->Interworking;
#endif

#ifdef WLS_FTM_SUPPORT
	if (*(vmacSta_p->Mib802dot11->wls_ftm_enable) == 1) {
		struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
		struct WLS_FTM_CONFIG_st *wls_ftm_config = wlpd_p->wls_ftm_config;

		if (wls_ftm_config->pgConfig_resp_civic_known)
			elment->ExtCap.CivicLocation = 1;	// bit 14: Civic Location
		else
			elment->ExtCap.CivicLocation = 0;

		if (wls_ftm_config->pgConfig_resp_LCI_known)
			elment->ExtCap.GioSpatialLocation = 1;	// bit 15: Geospatial Location
		else
			elment->ExtCap.GioSpatialLocation = 0;

		elment->ExtCap.fine_timing_measurement_responder = 1;	// bit 70: FTM responder supported
		elment->ExtCap.fine_timing_measurement_initiator = 1;	// bit 71: FTM initiator supported
	}
#endif
#ifdef AP_TWT
	elment->Len = sizeof(IEEEtypes_Ext_Cap_t);
#else
	elment->Len = 8;
#endif
}

UINT16 AddExtended_Cap_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_Extended_Cap_Element_t * pNextElement)
{
	InitExtended_Cap_IE(vmacSta_p, (IEEEtypes_Extended_Cap_Element_t *) pNextElement);
	return (pNextElement->Len + 2);
}

static void Init20_40_Coexist_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_20_40_BSS_COEXIST_Element_t * elment)
{

	memset(elment, 0, sizeof(IEEEtypes_20_40_BSS_COEXIST_Element_t));
	elment->ElementId = _20_40_BSSCOEXIST;
	elment->Len = 1;
	elment->Coexist.Inform_Request = 0;	/* is used to indicate that a transmitting STA is requesting the recipient to transmit a 20/40 BSS Coexistence Mangagement frame with
						   transmittign STA as the recipient */
	elment->Coexist.FortyMhz_Intorant = 0;			/** when set to 1, prohitbits an AP that receives this information or reports of this information from operating a 20/40 MHz BSS **/
	elment->Coexist.TwentyMhz_BSS_Width_Request = 0;	/** when set to 1, prohibits a receiving AP from operating its BSS as a 20/40MHz BSS **/
	elment->Coexist.OBSS_Scanning_Exemption_Grant = 0;	/** when set to 1 to indicate that the transmitting non-AP STAis requesting the BSS to allow the STA
	                                                                                                        to be exempt from OBSS Scanning **/
	elment->Coexist.OBSS_Scanning_Exemption_Request = 0;	/** field is  reserved for AP **/

}

UINT16 Add20_40_Coexist_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_20_40_BSS_COEXIST_Element_t * pNextElement)
{
	Init20_40_Coexist_IE(vmacSta_p, (IEEEtypes_20_40_BSS_COEXIST_Element_t *) pNextElement);
	return (pNextElement->Len + 2);
}

static void InitOverlap_BSS_Scan_Parameters_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t * elment)
{
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	memset(elment, 0, sizeof(IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t));
	elment->ElementId = OVERLAPPING_BSS_SCAN_PARAMETERS;
	elment->Len = 14;
	elment->Scan_Passive = 20;									/** contain a value in TUs encoded as an integer, that a receiving STA uses as described in 11.14.5 */
	elment->Scan_Active = 10;
	elment->Channel_Width_Trigger_Scan_Interval = *(mib->mib_Channel_Width_Trigger_Scan_Interval);	//180; //tbd 300; /**  value in second, as describe in 11.14.5 **/
	elment->Scan_Passive_Total_Per_Channel = 200;							/** value in TU, as describe in 11.14.5 **/
	elment->Scan_Active_Total_Per_Channel = 20;							/** value in TU, as describe in 11.14.5 **/
	elment->Width_Channel_Transition_Delay_Factor = *(mib->mib_Channel_Transition_Delay_Factor);	/** integer value describe in 11.14.5 **/
	elment->Scan_Activity_Threshold = 25;								/** contain a value in hundreds of percent encoded as unsigned integer as described in 11.14.5 **/

}

UINT16 AddOverlap_BSS_Scan_Parameters_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t * pNextElement)
{
	InitOverlap_BSS_Scan_Parameters_IE(vmacSta_p, (IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t *) pNextElement);
	return (pNextElement->Len + 2);
}

static void Init20_40Interant_Channel_Report_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_20_40_INTOLERANT_CHANNEL_REPORT_Element_t * elment)
{
	extern int domainGetInfo(UINT8 *);

	memset(elment, 0, sizeof(IEEEtypes_20_40_INTOLERANT_CHANNEL_REPORT_Element_t));
	elment->ElementId = _20_40_BSS_INTOLERANT_CHANNEL_REPORT;
	elment->RegClass = getRegulatoryClass(vmacSta_p);
	domainGetInfo(elment->ChanList);
	elment->Len = 1 + strlen(&elment->ChanList[0]);
}

UINT16 Add20_40Interant_Channel_Report_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_20_40_INTOLERANT_CHANNEL_REPORT_Element_t * pNextElement)
{
	Init20_40Interant_Channel_Report_IE(vmacSta_p, (IEEEtypes_20_40_INTOLERANT_CHANNEL_REPORT_Element_t *) pNextElement);
	return (pNextElement->Len + 2);
}
#endif
#ifdef MRVL_WPS2
UINT16 Build_AssocResp_WSCIE(vmacApInfo_t * vmacSta_p, AssocResp_WSCIE_t * pNextElement)
{
	memset(pNextElement, 0, sizeof(AssocResp_WSCIE_t));
	pNextElement->ElementId = PROPRIETARY_IE;
	pNextElement->Len = sizeof(AssocResp_WSCIE_t) - 2;
	pNextElement->WSC_OUI[0] = 0x00;
	pNextElement->WSC_OUI[1] = 0x50;
	pNextElement->WSC_OUI[2] = 0xF2;
	pNextElement->WSC_OUI[3] = 0x04;

	pNextElement->Version.ID = (UINT16) SHORT_SWAP(WSC_VERSION_ATTRB);
	pNextElement->Version.Len = SHORT_SWAP(0x0001);
	pNextElement->Version.Version = 0x10;

	pNextElement->ResponseType.ID = (UINT16) SHORT_SWAP((UINT16) WSC_RESP_TYPE_ATTRB);
	pNextElement->ResponseType.Len = SHORT_SWAP(0x0001);
	pNextElement->ResponseType.ResponseType = 0x03;

	pNextElement->VendorExtn.ID = (UINT16) SHORT_SWAP((UINT16) WSC_VENDOR_EXTN_ATTRB);
	pNextElement->VendorExtn.Len = SHORT_SWAP(6);
	pNextElement->VendorExtn.VendorID[0] = 0x00;
	pNextElement->VendorExtn.VendorID[1] = 0x37;
	pNextElement->VendorExtn.VendorID[2] = 0x2A;
	pNextElement->Version2.ID = 0x00;
	pNextElement->Version2.Len = 1;
	pNextElement->Version2.Version2 = 0x20;

	return (pNextElement->Len + 2);

}
#endif

#ifdef IEEE80211K
static void InitRRM_Cap_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_RM_Enable_Capabilities_Element_t * elment)
{
	memset(elment, 0, sizeof(IEEEtypes_RM_Enable_Capabilities_Element_t));
	elment->eid = RRM_CAP_IE;
#ifdef WLS_FTM_SUPPORT
	if (*(vmacSta_p->Mib802dot11->wls_ftm_enable) == 1) {
		extern void wlsFTM_AddRMEnabledCap_IE(struct net_device *netdev, IEEEtypes_RM_Enable_Capabilities_Element_t * elment);
		wlsFTM_AddRMEnabledCap_IE(vmacSta_p->dev, elment);
		elment->Len = 5;
	}
#endif
	if (*(vmacSta_p->Mib802dot11->mib_rrm)) {
		/* Enable mib_rrm */
		elment->LinkMeasCap = 1;
		elment->NeighRptCap = 1;
		elment->BcnPasMeasCap = 1;
		elment->BcnActMeasCap = 1;
		elment->BcnTabMeasCap = 1;
		elment->BcnMeasRptCondCap = 1;
		elment->APChnlRptCap = 1;
		elment->RCPIMeasCap = 1;
		elment->RSNIMeasCap = 1;
		elment->Len = 5;
	}
}

UINT16 AddRRM_Cap_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_RM_Enable_Capabilities_Element_t * pNextElement)
{
	if (*(vmacSta_p->ShadowMib802dot11->mib_rrm)
#ifdef WLS_FTM_SUPPORT
	    || *(vmacSta_p->ShadowMib802dot11->wls_ftm_enable) == 1
#endif
	    ) {
		InitRRM_Cap_IE(vmacSta_p, (IEEEtypes_RM_Enable_Capabilities_Element_t *) pNextElement);
		return (pNextElement->Len + 2);
	} else {
		return 0;
	}
}
#endif				/* IEEE80211K */

//for bringup; need to move to mib
UINT32 vht_cap = 0x338b7930;
#ifdef SOC_W906X
UINT32 SupportedRxVhtMcsSet = MAX_RX_VHT_MCS_SET;
#else
UINT32 SupportedRxVhtMcsSet = 0xffea;
#endif
UINT32 ch_width = 1;
UINT32 center_freq0 = 42;
UINT32 center_freq1 = 0;
UINT32 basic_vht_mcs = SC5_VHT_BASIC_MCS_SET;	//In sniffer, 1st byte 0xc0 is decoded first to become c0 ff
UINT32 ie192_version = 2;
UINT32 GetCenterFreq(UINT32 ch, UINT32 bw)
{
	if ((bw == CH_160_MHz_WIDTH) || (bw == CH_AUTO_WIDTH)) {
		switch (ch) {
		case 36:
		case 40:
		case 44:
		case 48:
		case 52:
		case 56:
		case 60:
		case 64:
			return 50;
			break;
		case 68:
		case 72:
		case 76:
		case 80:
		case 84:
		case 88:
		case 92:
		case 96:
			return 82;
			break;
		case 100:
		case 104:
		case 108:
		case 112:
		case 116:
		case 120:
		case 124:
		case 128:
			return 114;
			break;
		case 149:
		case 153:
		case 157:
		case 161:
		case 165:
		case 169:
		case 173:
		case 177:
			return 163;
			break;
		default:	//invalid, return 36/40/44/48/52/56/60/64
			return 50;
		}
	} else if (bw == CH_80_MHz_WIDTH) {
		switch (ch) {
		case 36:
		case 40:
		case 44:
		case 48:
			return (42);
		case 52:
		case 56:
		case 60:
		case 64:
			return (58);
		case 68:
		case 72:
		case 76:
		case 80:
			return (74);
		case 84:
		case 88:
		case 92:
		case 96:
			return (90);
		case 100:
		case 104:
		case 108:
		case 112:
			return (106);
		case 116:
		case 120:
		case 124:
		case 128:
			return (122);
		case 132:
		case 136:
		case 140:
		case 144:
			return (138);
		case 149:
		case 153:
		case 157:
		case 161:
			return (155);
		case 165:
		case 169:
		case 173:
		case 177:
			return (171);
		}
	} else if (bw == CH_40_MHz_WIDTH) {
		switch (ch) {
		case 36:
		case 40:
			return (38);
		case 44:
		case 48:
			return (46);
		case 52:
		case 56:
			return (54);
		case 60:
		case 64:
			return (62);
		case 68:
		case 72:
			return (70);
		case 76:
		case 80:
			return (78);
		case 84:
		case 88:
			return (86);
		case 92:
		case 96:
			return (94);
		case 100:
		case 104:
			return (102);
		case 108:
		case 112:
			return (110);
		case 116:
		case 120:
			return (118);
		case 124:
		case 128:
			return (126);
		case 132:
		case 136:
			return (134);
		case 140:
		case 144:
			return (142);
		case 149:
		case 153:
			return (151);
		case 157:
		case 161:
			return (159);
		case 165:
		case 169:
			return (167);
		case 173:
		case 177:
			return (175);
		case 184:
		case 188:
			return (186);
		case 192:
		case 196:
			return (194);
		}
	}
	return (ch);
}

extern UINT32 countNumOnes(UINT32 bitmap);

#ifdef SOC_W906X
/* Counts the number of ones in the provided bitmap */
static UINT8 count_max_nss_antenna(vmacApInfo_t * vmacSta_p, UINT8 * ant_bitmap, UINT8 * pNumOfAntenna)
{
	UINT8 max_nss;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

	*pNumOfAntenna = countNumOnes(*ant_bitmap & 0xff);

	if (*pNumOfAntenna == 0) {
		if (wlpptr->devid == SC5)
			*pNumOfAntenna = 8;
		else
			*pNumOfAntenna = 4;
	}

	if (wlpptr->devid == SC5) {
		if (*pNumOfAntenna > 8)
			*pNumOfAntenna = 8;

		max_nss = *pNumOfAntenna;
	} else {
		if (*pNumOfAntenna > 4)
			*pNumOfAntenna = 4;

		if ((wlpptr->devid == SC4) && (*pNumOfAntenna > 3))
			max_nss = 3;
		else
			max_nss = *pNumOfAntenna;
	}

	return max_nss;
}
#endif

//TODO: need to reprogram according to mib setting
UINT16 Build_IE_191(vmacApInfo_t * vmacSta_p, UINT8 * IE_p, UINT8 isEffective, UINT8 nss)
{
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_STA_CFG *mib_StaCfg;
#ifdef SOC_W906X
	UINT32 SupportedRxVhtMcsSetMask = 0xffff;
	UINT32 SupportedTxVhtMcsSetMask = 0xffff;
	UINT8 max_nss = 0;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
#else
	UINT32 SupportedRxVhtMcsSetMask = 0xffc0;
	UINT32 SupportedTxVhtMcsSetMask = 0xffc0;
#endif
	IEEEtypes_VhtCap_t *ptr = (IEEEtypes_VhtCap_t *) IE_p;
	UINT8 maxamsdu = 0;
	UINT8 NumOfAntenna;
	UINT8 max_antenna_num = 0x0;

	ptr->id = 191;
	ptr->len = 12;
	mib_StaCfg = mib->StationConfig;

	if ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) ||
	    (mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) || ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) &&
#ifdef SOC_W906X
									 (mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80) &&
#endif				/* SOC_W906X */
									 (mib->PhyDSSSTable->SecChan != 0))) {
		if ((mib->PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_5GHZ)) {
			if ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) &&
#ifdef SOC_W906X
			    (mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80) &&
#endif				/* SOC_W906X */
			    (mib->PhyDSSSTable->SecChan != 0))
				vht_cap |= (1 << 3);	/*set bit3 for 80+80Mhz support */
			else
				vht_cap |= (1 << 2);	/*set bit2 for 160Mhz support */
#ifdef SUPPORTED_EXT_NSS_BW
#ifdef TEST_160M_CASE_5_2_65
			vht_cap &= ~(1 << 2);
			vht_cap |= (1 << 30);	//for test case 5.2.65, ExtendedNssBwSupport is 1
#endif
#endif
			//If LGI
			if (*(mib->mib_guardInterval) == 2)
				vht_cap &= ~(1 << 6);
			else
				vht_cap |= (1 << 6);	//set bit6 for 160 or 80+80MHz SGI support
		} else {	//2.4GHz doesn't have 160MHz support
			vht_cap &= ~(1 << 2);
			vht_cap &= ~(1 << 6);
		}
	} else {
		vht_cap &= ~(1 << 2);	//clear 160Mhz support
		vht_cap &= ~(1 << 3);	/*clear 80+80Mhz support */
		vht_cap &= ~(1 << 6);	//clear 160Mhz SGI support

		if (*(mib->mib_guardInterval) == 2)
			vht_cap &= ~(1 << 5);
		else
			vht_cap |= (1 << 5);	//set bit5 for 80MHz SGI support
	}
#ifdef SOC_W906X
	vht_cap |= (7 << 13);
	if (wlpptr->devid == SC5) {
		UINT8 ss_8_condition = 0;

		max_nss = count_max_nss_antenna(vmacSta_p, vmacSta_p->Mib802dot11->mib_rxAntenna, &NumOfAntenna);

		//8_ss_condition = [(DevBW==80+80) & (NRx==1 or 2)] || [(DevBW<=80) & (NRx<=4)]
		if ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) ||
		    ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) && (mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80))) {
			if ((NumOfAntenna / 2) <= 2) {
				ss_8_condition = 1;
			}
		} else		//BW <= 80
		{
			if (NumOfAntenna <= 4) {
				ss_8_condition = 1;
			}
		}
		if (ss_8_condition == 0) {
			vht_cap &= ~(7 << 13);	//bit[13:15]
			vht_cap |= (3 << 13);
		}
	} else if (wlpptr->devid == SCBT) {
		if (isEffective && nss) {
			WLDBG_INFO(DBG_LEVEL_1, "isEffective vht_cap=0x%x nss=%u\n", vht_cap, nss);
			vht_cap &= ~(7 << 13);	//bit[13:15]
			vht_cap |= ((nss - 1) << 13);
			WLDBG_INFO(DBG_LEVEL_1, "After set bit[13:15] vht_cap=0x%x\n", vht_cap);
		}
	}
#endif
	if (*(mib->mib_bfmee) == 1) {
		vht_cap |= (1 << 12);	//SUBeamformerCapable
	} else {
		vht_cap &= ~(1 << 12);
	}

	if (*(mib->mib_mu_bfmer) == 1) {
		vht_cap |= (1 << 19);	//MUBeamformerCapable
	} else {
		vht_cap &= ~(1 << 19);
	}
#ifdef SOC_W906X
	if (*(mib->mib_mu_bfmee) == 1) {
		vht_cap |= (1 << 20);	//MUBeamformeeCapable
	} else {
		vht_cap &= ~(1 << 20);
	}
#else
	vht_cap &= ~(1 << 20);	//MUBeamformeeCapable
#endif
	memcpy((UINT8 *) & ptr->cap, &vht_cap, sizeof(IEEEtypes_VHT_Cap_Info_t));
#ifdef SOC_W906X
	if (wlpptr->devid == SC5)
		max_antenna_num = 8;
	else
		max_antenna_num = 4;
	max_nss = count_max_nss_antenna(vmacSta_p, vmacSta_p->Mib802dot11->mib_rxAntBitmap, &NumOfAntenna);

	if ((mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80) || (mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH)) {
		max_nss = max_nss / 2;
		//For SC5/11AC/160M(80+80), we only support 3 antennae
		if (max_nss > 3) {
			max_nss = 3;
		}
	} else if ((mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_7x7p1x1) && (max_nss == max_antenna_num))
		max_nss--;

	if (max_nss != 0)
		SupportedRxVhtMcsSetMask = 0xffff << (max_nss * 2) & 0x0000ffff;

	max_nss = count_max_nss_antenna(vmacSta_p, vmacSta_p->Mib802dot11->mib_txAntenna, &NumOfAntenna);
	if ((mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80) || (mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH)) {
		max_nss = max_nss / 2;
		//For SC5/11AC/160M(80+80), we only support 3 antennae
		if (max_nss > 3) {
			max_nss = 3;
		}
	} else if ((mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_7x7p1x1) && (max_nss == max_antenna_num))
		max_nss--;

	if ((mib->PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_5GHZ) && (mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH)) {
		NumOfAntenna = NumOfAntenna / 2;	/* possible values are: 4,3,2,1,0 */
		if ((wlpptr->devid == SC5) || (wlpptr->devid == SCBT)) {	/* 80+80Mhz not continuous 160Mhz */
			if (max_nss > NumOfAntenna)
				max_nss = NumOfAntenna;
		}
	}

	if (max_nss != 0)
		SupportedTxVhtMcsSetMask = 0xffff << (max_nss * 2) & 0x0000ffff;

	if (NumOfAntenna != 0)
		ptr->cap.NumberofSoundingDimensions = NumOfAntenna - 1;
	else
		ptr->cap.NumberofSoundingDimensions = 0;
#else
	NumOfAntenna = countNumOnes((*(vmacSta_p->Mib802dot11->mib_rxAntBitmap) & 0xf));
	if (NumOfAntenna == 1) {	/* Rx only supports one stream 11ac rates */
		SupportedRxVhtMcsSetMask = 0xfffc;
	} else if (NumOfAntenna == 2) {	/* Rx supports up to two stream 11ac rates */
		SupportedRxVhtMcsSetMask = 0xfff0;
	} else if (NumOfAntenna == 3) {
		/* Rx supports up to three stream 11ac rates */
		SupportedRxVhtMcsSetMask = 0xffc0;
	} else {
		/* Rx supports up to four stream 11ac rates */
		SupportedRxVhtMcsSetMask = 0xff00;
	}
	NumOfAntenna = countNumOnes((*(vmacSta_p->Mib802dot11->mib_txAntenna) & 0xf));
	if (NumOfAntenna == 1) {
		/* Tx only supports one stream 11ac rates */
		SupportedTxVhtMcsSetMask = 0xfffc;
		ptr->cap.NumberofSoundingDimensions = 0;
	} else if (NumOfAntenna == 2) {
		/* Tx supports up to two stream 11ac rates */
		SupportedTxVhtMcsSetMask = 0xfff0;
		ptr->cap.NumberofSoundingDimensions = 1;
	} else if (NumOfAntenna == 3) {
		/* Tx supports up to three stream 11ac rates */
		SupportedTxVhtMcsSetMask = 0xffc0;
		ptr->cap.NumberofSoundingDimensions = 2;
	} else {
		/* Tx supports up to four stream 11ac rates */
		SupportedTxVhtMcsSetMask = 0xff00;
		ptr->cap.NumberofSoundingDimensions = 3;
	}
#endif
	if (*(vmacSta_p->Mib802dot11->mib_HtStbc)) {
		ptr->cap.TxSTBC = 1;
	} else {
		ptr->cap.TxSTBC = 0;
	}
	ptr->SupportedRxMcsSet = SupportedRxVhtMcsSet | SupportedRxVhtMcsSetMask;
	ptr->SupportedTxMcsSet = mib_StaCfg->SupportedTxVhtMcsSet | SupportedTxVhtMcsSetMask;
#ifdef NEW_DP

	if ((*(mib->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK) == WL_MODE_AMSDU_TX_8K)
		maxamsdu = 1;
	else if ((*(mib->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK) == WL_MODE_AMSDU_TX_11K)
		maxamsdu = 2;

	ptr->cap.MaximumMPDULength = maxamsdu;
#endif
	/* Beamformee STS Capability */
	ptr->cap.CompressedSteeringNumberofBeamformerAntennaSupported = 0x3;

	return (sizeof(IEEEtypes_VhtCap_t));
}

UINT16 Build_IE_192(vmacApInfo_t * vmacSta_p, UINT8 * IE_p)
{
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	IEEEtypes_VhOpt_t *ptr = (IEEEtypes_VhOpt_t *) IE_p;
	struct wlprivate *priv_p = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

	ptr->id = VHT_OPERATION;
	ptr->len = 5;
	if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) ||
	    (PhyDSSSTable->Chanflag.ChnlWidth == CH_20_MHz_WIDTH) || (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_2DOT4GHZ)) {
		ch_width = 0;
	} else if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) || (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH)) {
		ch_width = 2;	//160MHz
	} else {
#ifdef SOC_W906X
		if ((PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80) && (PhyDSSSTable->SecChan != 0))
			ch_width = 3;	/* 80MHz+80MHz ch_width = 1 for new, ch_width =3 for old */
		else
#endif				/* SOC_W906X */
			ch_width = 1;	/* 80 MHz */
	}
	if (ie192_version == 2)
		ptr->ch_width = ch_width ? 1 : 0;	//new ptr->ch_width = 1 for all 80, 160 and 80+80
	else
		ptr->ch_width = ch_width;
	if (ch_width == 0) {
		/* Channel Center freq seg0 field is reserved in ht20 or ht40 */
		center_freq0 = 0;
		center_freq1 = 0;
	} else {
		if (ie192_version == 2) {
			if (ch_width == 1) {	//80MHz
				center_freq0 = GetCenterFreq(PhyDSSSTable->CurrChan, PhyDSSSTable->Chanflag.ChnlWidth);
				center_freq1 = 0;
			}
			if (ch_width == 2) {	//160MHz
				center_freq0 = GetCenterFreq(PhyDSSSTable->CurrChan, CH_80_MHz_WIDTH);
				center_freq1 = GetCenterFreq(PhyDSSSTable->CurrChan, CH_160_MHz_WIDTH);
			}

			if (ch_width == 3) {	/* 80MHz+80MHz */
				center_freq0 = GetCenterFreq(PhyDSSSTable->CurrChan, CH_80_MHz_WIDTH);
				center_freq1 = GetCenterFreq(PhyDSSSTable->SecChan, CH_80_MHz_WIDTH);
			}

		} else {
			center_freq0 = GetCenterFreq(PhyDSSSTable->CurrChan, PhyDSSSTable->Chanflag.ChnlWidth);

			if (ch_width == 3)
				center_freq1 = GetCenterFreq(PhyDSSSTable->SecChan, CH_80_MHz_WIDTH);
			else
				center_freq1 = 0;
		}
	}

#ifdef SUPPORTED_EXT_NSS_BW
#if defined (TEST_160M_CASE_4_2_58) || defined(TEST_160M_CASE_5_2_65)

	center_freq1 = 0;
#endif
#endif
	ptr->center_freq0 = center_freq0;
	ptr->center_freq1 = center_freq1;
	//printk("ptr->ch_width=%d,ptr->center_freq0=%d,ptr->center_freq1=%d\n", ptr->ch_width, ptr->center_freq0, ptr->center_freq1);

#ifdef SUPPORTED_EXT_NSS_BW
	if (0 == isSupport160MhzByCenterFreq(priv_p, VHT_EXTENDED_NSS_BW_CAPABLE, center_freq0, center_freq1, 0)) {
		WLDBG_INFO(DBG_LEVEL_1, "80MHz or less\n");
	}
#else
	if (center_freq1 == 0) {
		//printk("%s 80MHz or less\n", __FUNCTION__);
	} else {
		UINT8 diff;
		if (center_freq1 > center_freq0) {
			diff = center_freq1 - center_freq0;
		} else {
			diff = center_freq0 - center_freq1;
		}
		if (diff == 8) {
			printk("%s 160Mhz: center frequency of the 80 MHz channel segment that contains the primary channel = %d\n", __FUNCTION__,
			       center_freq0);
			printk("%s 160Mhz: center frequency of the 160 MHz channel = %d\n", __FUNCTION__, center_freq1);
		} else if (diff > 8) {
#ifdef SOC_W906X
			isSupport80plus80Mhz(priv_p);
#else
			WLDBG_ERROR(DBG_LEVEL_1, "80MHz + 80MHz, not support\n");
#endif
		} else
			printk("%s reserved\n", __FUNCTION__);
	}
#endif
	/* VHT basic NSS and MCS set */
	ptr->basic_mcs = basic_vht_mcs;

	return (sizeof(IEEEtypes_VhOpt_t));
}

#ifdef SOC_W906X
/* parameters definition in 9.4.2.222 */
UINT16 Build_IE_Color_Change_Ann_IE(vmacApInfo_t * vmacSta_p, UINT8 * IE_p)
{
	IEEEtypes_Color_Change_Ann_Element_t *ptr = (IEEEtypes_Color_Change_Ann_Element_t *) IE_p;

	ptr->hdr.ElementId = EXT_IE;
	ptr->hdr.Len = sizeof(IEEEtypes_Color_Change_Ann_Element_t)
	    - sizeof(IEEEtypes_ElementId_t)
	    - sizeof(IEEEtypes_Len_t);
	ptr->hdr.ext = BSS_COLOR_CHANGE_ANNOUNCEMENT;
	ptr->ColorSwitchCountDown = 1;	/* get this value from mib ???? */
	ptr->NewBSSColor = 1;	/* get this from mib ??? */
	ptr->Reserved = 0;

	return sizeof(IEEEtypes_Color_Change_Ann_Element_t);
}

/* parameters definition in Draft P802.11ax_D1.4 9.4.2.239 */
UINT16 Build_IE_UoraParamSet_IE(vmacApInfo_t * vmacSta_p, UINT8 * IE_p)
{
	IEEEtypes_RAPS_Element_t *ptr = (IEEEtypes_RAPS_Element_t *) IE_p;

	ptr->hdr.ElementId = EXT_IE;
	ptr->hdr.Len = sizeof(IEEEtypes_RAPS_Element_t)
	    - sizeof(IEEEtypes_ElementId_t)
	    - sizeof(IEEEtypes_Len_t);
	ptr->hdr.ext = UORA_PARAMETERS;
	ptr->EOCWmin = 1;	/* get this value from mib ???? */
	ptr->EOCWmax = 3;	/* get this from mib ??? */
	ptr->Reserved = 0;

	return sizeof(IEEEtypes_RAPS_Element_t);
}

//Base on SCBT Z1. p.31 of PPE_threshold-SCBT-Z1.pdf. Set pe=8 for Nss> 1 & RU= 484/996/2x996. Others: none. 
static u8 ppet16[MAX_NSS][MAX_RU_NUM] = {
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE}
};

static u8 ppet8[MAX_NSS][MAX_RU_NUM] = {
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK, PPE_CONSTELLATION_BPSK}
};

static u8 ppet16_aggressive[MAX_NSS][MAX_RU_NUM] = {
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE}
};

static u8 ppet8_aggressive[MAX_NSS][MAX_RU_NUM] = {
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_256QAM},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_1024QAM, PPE_CONSTELLATION_256QAM},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_256QAM, PPE_CONSTELLATION_256QAM},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_256QAM, PPE_CONSTELLATION_256QAM},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_256QAM, PPE_CONSTELLATION_256QAM},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_256QAM, PPE_CONSTELLATION_256QAM},
	{PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_NONE, PPE_CONSTELLATION_256QAM, PPE_CONSTELLATION_256QAM}
};

//the mask is decides from ppet16 and ppet8 table       RU-242 are all none in the tables.
#define RUID_MASK    0xE

/* parameters definition in 9.4.2.218.1 */
UINT16 Build_IE_HE_CAP(vmacApInfo_t * vmacSta_p, UINT8 * IE_p)
{
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_STA_CFG *mib_StaCfg;
	HE_Capabilities_IE_t *he_cap_p = (HE_Capabilities_IE_t *) IE_p;
	UINT16 len;
	int i, j, k, ru_number_ppe_present = 0, ppe_threshold_number = 0;
	int ppe_thold_oct_number = 0;
	unsigned long index;
	unsigned long ruid_mask = RUID_MASK;
	ppe_threshold_info_t *ppe_thresholds;
	u8 ppet_present[MAX_RU_NUM * MAX_NSS * 2] = { PPE_CONSTELLATION_NONE };
	u8 *ppetp, *tmp_ppet;
	he_mcs_nss_support_t *mcs_nss_setp;
	UINT8 NumOfRxAntenna, NumOfTxAntenna;
	UINT32 SupportedRxHeMcsSetMask = 0xffff;
	UINT32 SupportedTxHeMcsSetMask = 0xffff;
	UINT8 rx_nss, tx_nss, ppe_nss;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	struct wlprivate *wlpptr_parent = GET_PARENT_PRIV(wlpptr);
	UINT8 max_antenna_num = 0x0;

	mib_StaCfg = mib->StationConfig;

	memset(IE_p, 0, sizeof(HE_Capabilities_IE_t));

	he_cap_p->hdr.ElementId = EXT_IE;
	he_cap_p->hdr.ext = HE_CAPABILITIES_IE;
	len = sizeof(HE_Capabilities_IE_t) - sizeof(he_cap_p->hecap_ext);	/* Only count the fixed length part here */

	/* HE MAC capabilities */
	he_cap_p->mac_cap.htc_he_support = 1;
	//twt
#ifdef AP_TWT
	if (*vmacSta_p->Mib802dot11->he_twt_activated == 1) {
		//he_cap_p->mac_cap.twt_request_support = 1;     //enable when STA support twt
		he_cap_p->mac_cap.twt_responder_support = 1;
		he_cap_p->mac_cap.flexible_twt_sched_support = 1;
	}
#endif
	he_cap_p->mac_cap.frammentation_support = 0;
	he_cap_p->mac_cap.max_fragmented_msdus = 0;
	he_cap_p->mac_cap.min_fragment_size = 0;

	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)
		he_cap_p->mac_cap.trigger_frame_mac_duration = 2;
	else
		he_cap_p->mac_cap.trigger_frame_mac_duration = 0;

	he_cap_p->mac_cap.multi_tid_aggregation_support = 0;
	he_cap_p->mac_cap.he_link_adaption = 0;
	he_cap_p->mac_cap.all_ack_support = 0;
	he_cap_p->mac_cap.ul_mu_resp_sched_suport = 0;
	he_cap_p->mac_cap.a_bsr_support = 0;
	//not support broadcast twt in current stage
	he_cap_p->mac_cap.broadcast_twt_support = 0;

	he_cap_p->mac_cap.ba_bitmap_support_32bit = 0;
	he_cap_p->mac_cap.mu_cascade_support = 0;
	he_cap_p->mac_cap.ack_multi_tid_aggr_support = 0;
	he_cap_p->mac_cap.group_addr_multi_sta_ba_dl_mu = 0;
	he_cap_p->mac_cap.omi_a_control_support = 1;
	he_cap_p->mac_cap.ofmda_ra_support = 0;
	he_cap_p->mac_cap.max_ampdu_exponent = 3;	// set to max:8MB
	he_cap_p->mac_cap.amsdu_fragmentation_support = 0;

	he_cap_p->mac_cap.rx_ctrl_frame_to_multibss = 0;
	he_cap_p->mac_cap.bsrp_ampdu_aggregation = 0;
	he_cap_p->mac_cap.qtp_support = 0;
	he_cap_p->mac_cap.a_brq_support = 0;
	he_cap_p->mac_cap.sr_responder = 0;
	he_cap_p->mac_cap.ndp_feedback_report = 0;
	he_cap_p->mac_cap.ops = 0;
	he_cap_p->mac_cap.amsdu_in_ampdu = 0;
	he_cap_p->mac_cap.he_dynamic_sm_power_save = 0;
	he_cap_p->mac_cap.punctured_sounding_support = 0;
	he_cap_p->mac_cap.ht_and_vht_trigger_frame_rx_support = 0;

	/* HE PHY capabilities. */
	he_cap_p->phy_cap.dual_band_support = 0;

	if ((mib->PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_5GHZ)) {
		if ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) ||
		    (mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) ||
		    ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) &&
		     (mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80) && (mib->PhyDSSSTable->SecChan != 0))) {
			he_cap_p->phy_cap.channel_width_set = HE_SUPPORT_40_80MHZ_BW_5G | HE_SUPPORT_80P80MHZ_BW_5G | HE_SUPPORT_160MHZ_BW_5G;
			/* Draft P802.11ax_D2.1
			   B2 indicates support for a 160 MHz channel width in the 5 GHz band.
			   B3 indicates support for a 160/80+80 MHz channel width in the 5 GHz band.
			   B3 is set to 0 if not supported. B3 is set to 1 if supported. If B3 set to 1 then
			   B2 is set to 1. */
		} else if ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) || (mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH)) {
			he_cap_p->phy_cap.channel_width_set = HE_SUPPORT_40_80MHZ_BW_5G | HE_SUPPORT_242TONE_5G;
		} else {
			he_cap_p->phy_cap.channel_width_set = HE_SUPPORT_242TONE_5G;
		}
	} else if ((mib->PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_2DOT4GHZ)) {
		if (mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH)
			he_cap_p->phy_cap.channel_width_set = HE_SUPPORT_40MHZ_BW_24G | HE_SUPPORT_242TONE_24G;
		else
			he_cap_p->phy_cap.channel_width_set = HE_SUPPORT_242TONE_24G;
	}

	he_cap_p->phy_cap.punctured_preamble_rx = 0;

	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)
		he_cap_p->phy_cap.device_class = HE_CLASS_A;

	if (*wlpptr_parent->vmacSta_p->Mib802dot11->mib_heldpc_enable)
		he_cap_p->phy_cap.ldpc_coding_in_payload = 1;
	else
		he_cap_p->phy_cap.ldpc_coding_in_payload = 0;

	he_cap_p->phy_cap.he_ltf_gi_for_he_ppdus = 0;
	he_cap_p->phy_cap.midamble_rx_max_nsts = 0;
	he_cap_p->phy_cap.ndp_with4x_he_ltf_3p2ms_gi = 1;
	he_cap_p->phy_cap.stbc_less_80mhz_tx = 1;
	he_cap_p->phy_cap.stbc_less_80mhz_rx = 1;
	he_cap_p->phy_cap.doppler_tx = 0;
	he_cap_p->phy_cap.doppler_rx = 0;
	he_cap_p->phy_cap.full_bw_ul_mu = 1;
	he_cap_p->phy_cap.partial_bw_ul_mu = 0;
	he_cap_p->phy_cap.dcm_max_constellation_tx = DCM_BPSK;
	he_cap_p->phy_cap.dcm_max_nss_tx = 0;
	he_cap_p->phy_cap.dcm_max_constellation_rx = DCM_BPSK;
	he_cap_p->phy_cap.dcm_max_nss_rx = 0;
	he_cap_p->phy_cap.rx_he_mu_ppdu_from_nonap_sta = 1;

	if (*vmacSta_p->Mib802dot11->he_su_bf == 1) {
		he_cap_p->phy_cap.su_beamformer = 1;
	}

	if (wfa_11ax_pf) {
		he_cap_p->phy_cap.su_beamformee = 0;
	} else {
		if ((*(mib->mib_bfmee) == 1) || (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA))
			he_cap_p->phy_cap.su_beamformee = 1;
		else
			he_cap_p->phy_cap.su_beamformee = 0;
	}
#ifdef SOC_W906X
	if (wlpptr->devid == SC5) {
		he_cap_p->phy_cap.beamformee_sts_gt_80mhz = 3;
	}
#else
	he_cap_p->phy_cap.beamformee_sts_le_80mhz = 0;
	he_cap_p->phy_cap.beamformee_sts_gt_80mhz = 0;
#endif
	he_cap_p->phy_cap.ng_16_for_su_feedback = 0;
	he_cap_p->phy_cap.ng_16_for_mu_feedback = 0;
	he_cap_p->phy_cap.codebook_size_4_2_for_su = 0;
	he_cap_p->phy_cap.codebook_size_7_5_for_mu = 0;
	he_cap_p->phy_cap.triggered_su_beamforming_feedback = 0;

	if (*vmacSta_p->Mib802dot11->he_mu_bf == 1) {
		he_cap_p->phy_cap.mu_beamformer = 1;
		he_cap_p->phy_cap.su_beamformer = 1;
		he_cap_p->phy_cap.triggered_mu_beamforming_feedback = 1;
	}

	he_cap_p->phy_cap.triggered_cqi_feedback = 0;
	he_cap_p->phy_cap.partial_bw_ext_range = 1;
	he_cap_p->phy_cap.partial_bw_dl_mu_mimo = 0;
	he_cap_p->phy_cap.ppe_threshold_present = 1;
	he_cap_p->phy_cap.srp_based_sr_support = 0;
	he_cap_p->phy_cap.power_boost_factor_support = 0;
	he_cap_p->phy_cap.he_su_and_mu_ppdu_4xhe_ltf = 1;

	if ((wlpptr->devid == SCBT) && ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) || (mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) || ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) && (mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80) && (mib->PhyDSSSTable->SecChan != 0))))	// TODO: exclude 80M 7+1 and 3+1 mode*/
		he_cap_p->phy_cap.max_nc = 0;
	else
		he_cap_p->phy_cap.max_nc = 3;

	he_cap_p->phy_cap.stbc_greater_80m_tx = 0;
	he_cap_p->phy_cap.stbc_greater_80m_rx = 0;
	he_cap_p->phy_cap.he_er_su_ppdu_4xhe_ltf = 1;
	he_cap_p->phy_cap.he_20m_in_40m_ppdu_24g_band = 0;
	he_cap_p->phy_cap.he_20mhz_in_160mhz_ppdu = 0;
	he_cap_p->phy_cap.he_80mhz_in_160mhz_ppdu = 0;
	he_cap_p->phy_cap.he_er_su_ppdu_1xhe_ltf = 0;
	he_cap_p->phy_cap.midamble_rx_2x_1x_he_ltf = 0;
	he_cap_p->phy_cap.dcm_max_bw = DCM_MAX_BW_20M;
	he_cap_p->phy_cap.rx_full_su_using_he_mu_with_non_comp_sigb = 1;
	he_cap_p->phy_cap.nominal_packet_padding = 0;

	/* Tx Rx HE NSS/MCS Support field */
	rx_nss = count_max_nss_antenna(vmacSta_p, vmacSta_p->Mib802dot11->mib_rxAntBitmap, &NumOfRxAntenna);
	tx_nss = count_max_nss_antenna(vmacSta_p, vmacSta_p->Mib802dot11->mib_txAntenna, &NumOfTxAntenna);

	if (wlpptr->devid == SC5)
		max_antenna_num = 8;
	else
		max_antenna_num = 4;

	if (mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80) {
		rx_nss = rx_nss / 2;
		tx_nss = tx_nss / 2;
	} else if (mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_7x7p1x1) {
		if (rx_nss == max_antenna_num)
			rx_nss--;
		if (tx_nss == max_antenna_num)
			tx_nss--;
	}

	ppe_nss = tx_nss;

	if ((NumOfTxAntenna == 0) || (*vmacSta_p->Mib802dot11->he_mu_bf == 0))
		he_cap_p->phy_cap.sounding_dimension_le_80mhz = 0;
	else
		he_cap_p->phy_cap.sounding_dimension_le_80mhz = NumOfTxAntenna - 1;

	/*Rx HE-MCS Map <= 80 MHz */
	SupportedRxHeMcsSetMask = SupportedRxHeMcsSetMask << (rx_nss * 2);
	he_cap_p->rx_he_mcs_80m.max_mcs_set = mib_StaCfg->supoorted_rx_he_80m_mcs_set | SupportedRxHeMcsSetMask;
	/*Tx HE-MCS Map <= 80MHz */
	SupportedTxHeMcsSetMask = SupportedTxHeMcsSetMask << (tx_nss * 2);
	he_cap_p->tx_he_mcs_80m.max_mcs_set = mib_StaCfg->supoorted_tx_he_80m_mcs_set | SupportedTxHeMcsSetMask;

	/*Rx/TX HE-MCS Map 160MHz */
	NumOfRxAntenna = NumOfRxAntenna / 2;	/* possible values are: 4,3,2,1,0 */
	NumOfTxAntenna = NumOfTxAntenna / 2;	/* possible values are: 4,3,2,1,0 */

	if ((wlpptr->devid == SC5) || (wlpptr->devid == SCBT)) {	/* 80+80Mhz not continuous 160Mhz */
		if (rx_nss > NumOfRxAntenna)
			rx_nss = NumOfRxAntenna;

		if (tx_nss > NumOfTxAntenna)
			tx_nss = NumOfTxAntenna;
	}

	SupportedRxHeMcsSetMask = 0xffff;
	SupportedTxHeMcsSetMask = 0xffff;
	SupportedRxHeMcsSetMask = SupportedRxHeMcsSetMask << (rx_nss * 2);
	SupportedTxHeMcsSetMask = SupportedTxHeMcsSetMask << (tx_nss * 2);

	if ((NumOfTxAntenna == 0) || (*vmacSta_p->Mib802dot11->he_mu_bf == 0))
		he_cap_p->phy_cap.sounding_dimension_gt_80mhz = 0;
	else
		he_cap_p->phy_cap.sounding_dimension_gt_80mhz = NumOfTxAntenna - 1;

	/* SC5/SCBT doesn't support continuous 160Mhz */
	if (he_cap_p->phy_cap.channel_width_set & HE_SUPPORT_160MHZ_BW_5G) {
		mcs_nss_setp = (he_mcs_nss_support_t *) ((u8 *) he_cap_p + len);
		/* Rx */
		mcs_nss_setp->max_mcs_set = mib_StaCfg->supoorted_rx_he_160m_mcs_set | SupportedRxHeMcsSetMask;	/* RX MCS NSS set */
		mcs_nss_setp += 1;
		/* Tx */
		mcs_nss_setp->max_mcs_set = mib_StaCfg->supoorted_tx_he_160m_mcs_set | SupportedTxHeMcsSetMask;	/* TX MCS NSS set */
		len += 2 * sizeof(he_mcs_nss_support_t);
	}

	/*Rx/TX HE-MCS Map 80+80MHz */
	if (he_cap_p->phy_cap.channel_width_set & HE_SUPPORT_80P80MHZ_BW_5G) {
		mcs_nss_setp = (he_mcs_nss_support_t *) ((u8 *) he_cap_p + len);
		/* Rx */
		mcs_nss_setp->max_mcs_set = mib_StaCfg->supoorted_rx_he_80p80m_mcs_set | SupportedRxHeMcsSetMask;	/* RX MCS NSS set */
		mcs_nss_setp += 1;
		/* Tx */
		mcs_nss_setp->max_mcs_set = mib_StaCfg->supoorted_tx_he_80p80m_mcs_set | SupportedTxHeMcsSetMask;	/* TX MCS NSS set */
		len += 2 * sizeof(he_mcs_nss_support_t);
	}

	if (he_cap_p->phy_cap.ppe_threshold_present == 1) {

		/*PPE Thresholds field */
		ppe_thresholds = (ppe_threshold_info_t *) ((u8 *) he_cap_p + len);
		ppe_thresholds->nss_m1 = ppe_nss - 1;	//MAX_NSS - 1;
		ppe_thresholds->ru_idx_mask = ruid_mask & 0xf;

		for_each_set_bit(index, (unsigned long *)&ruid_mask, MAX_RU_NUM) {
			ru_number_ppe_present++;
		}

		for (i = 0, k = 0; i < ppe_nss; i++) {
			for (j = 0; j < MAX_RU_NUM; j++) {
				if (ruid_mask & (1 << j)) {
					if (vmacSta_p->Mib802dot11->HEConfig->pe_type == MIB_PE_TYPE_DEFAULT) {
						ppet_present[k++] = ppet16[i][j];
						ppet_present[k++] = ppet8[i][j];
					} else {
						ppet_present[k++] = ppet16_aggressive[i][j];
						ppet_present[k++] = ppet8_aggressive[i][j];
					}
				}
			}
		}

		ppe_threshold_number = k;

		//NSS:3, RU index bitmask:4
		ppe_thold_oct_number = (7 + ppe_threshold_number * 3 + 7) / 8;
		len += ppe_thold_oct_number;

		if (ppe_threshold_number > 0) {
			ppe_thresholds->ppet0 = ppet_present[0] & 0x7;
			ppe_thresholds->ppet1 = ppet_present[1] & 0x7;
			ppe_threshold_number -= 2;
			if (ppe_threshold_number > 0) {
				ppe_thresholds->ppet2 = ppet_present[2] & 0x7;
				ppe_threshold_number--;
			}
		}

		ppetp = (u8 *) ppe_thresholds + sizeof(ppe_threshold_info_t);
		tmp_ppet = &ppet_present[3];

		for (i = 0; i < ppe_threshold_number; i += 8) {

			ppet8_ppe16_t *ppe8_16 = (ppet8_ppe16_t *) ppetp;
			UINT32 n = 0;

			while (n < 8 && (i + n) < ppe_threshold_number) {
				switch (n) {
				case 0:
					ppe8_16->ppet0 = tmp_ppet[i + n] & 0x7;
					break;
				case 1:
					ppe8_16->ppet1 = tmp_ppet[i + n] & 0x7;
					break;
				case 2:
					ppe8_16->ppet2 = tmp_ppet[i + n] & 0x7;
					break;
				case 3:
					ppe8_16->ppet3 = tmp_ppet[i + n] & 0x7;
					break;
				case 4:
					ppe8_16->ppet4 = tmp_ppet[i + n] & 0x7;
					break;
				case 5:
					ppe8_16->ppet5 = tmp_ppet[i + n] & 0x7;
					break;
				case 6:
					ppe8_16->ppet6 = tmp_ppet[i + n] & 0x7;
					break;
				case 7:
					ppe8_16->ppet7 = tmp_ppet[i + n] & 0x7;
					break;
				}

				n++;
			}

			if (n == 8) {
				ppetp += sizeof(ppet8_ppe16_t);
				continue;
			}
			//the last ppe8_ppe16
			if ((i + n) == ppe_threshold_number)
				break;

		}

	}

	if (wlpptr->is_wfa_testbed == true) {
		he_cap_p->phy_cap.beamformee_sts_gt_80mhz = 0;
		he_cap_p->phy_cap.beamformee_sts_le_80mhz = 0;
		he_cap_p->phy_cap.dcm_max_constellation_tx = 0;
		he_cap_p->phy_cap.dcm_max_constellation_rx = 0;
		he_cap_p->mac_cap.flexible_twt_sched_support = 0;
		he_cap_p->phy_cap.he_su_and_mu_ppdu_4xhe_ltf = 0;
		he_cap_p->phy_cap.he_er_su_ppdu_4xhe_ltf = 0;
		he_cap_p->phy_cap.max_nc = 0;
		he_cap_p->phy_cap.ndp_with4x_he_ltf_3p2ms_gi = 0;
		he_cap_p->phy_cap.partial_bw_ext_range = 0;
		he_cap_p->phy_cap.rx_full_su_using_he_mu_with_non_comp_sigb = 0;
		he_cap_p->phy_cap.rx_he_mu_ppdu_from_nonap_sta = 0;
		he_cap_p->phy_cap.stbc_less_80mhz_rx = 0;
		he_cap_p->phy_cap.stbc_less_80mhz_tx = 0;
	} else {
		he_cap_p->phy_cap.beamformee_sts_le_80mhz = 7;
		he_cap_p->phy_cap.beamformee_sts_gt_80mhz = 7;
		if (wlpptr->devid == SC5) {
			rx_nss = count_max_nss_antenna(vmacSta_p, vmacSta_p->Mib802dot11->mib_rxAntBitmap, &NumOfRxAntenna);
			if ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) || ((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) && (mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80)))	//BW 160 and 80+80
			{
				if ((NumOfRxAntenna / 2) > 2) {
					he_cap_p->phy_cap.beamformee_sts_gt_80mhz = 3;
				}
			} else	//BW <= 80
			{
				if (NumOfRxAntenna > 4) {
					he_cap_p->phy_cap.beamformee_sts_le_80mhz = 3;
				}
			}
		}
	}

	he_cap_p->hdr.Len = len - sizeof(IEEEtypes_ElementId_t) - sizeof(IEEEtypes_Len_t);

	memset((void *)&vmacSta_p->he_cap, 0, sizeof(vmacSta_p->he_cap));
	memcpy((void *)&vmacSta_p->he_cap, (void *)he_cap_p, len);
	if (len > MAX_HE_CAP_IE_LENGTH)
		printk("MAX_HE_CAP_IE_LENGTH is only %d but the length of the HE CAP IE is %d\n", MAX_HE_CAP_IE_LENGTH, len);

	return len;
}

UINT8 isMbssidConfigured(struct net_device * netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT8 mbssidGID;

	for (mbssidGID = 0; mbssidGID < MAX_MBSSID_SET; mbssidGID++) {
		mbss_set_t *pset = &wlpptr->wlpd_p->mbssSet[mbssidGID];

		if (pset->mbssid_set)
			return TRUE;
	}

	return FALSE;
}

#ifndef AP_TWT
static int he_twt_required = 0;	// TODO: move to MIB
#endif
static int he_default_pe_duration = 7;

/* parameters definition in 9.4.2.219 */
UINT16 Build_IE_HE_OP(vmacApInfo_t * vmacSta_p, UINT8 * IE_p, UINT8 vhtopie_present)
{
	HE_Operation_IE_t *heop_iep = (HE_Operation_IE_t *) IE_p;
	vht_operation_info_t *vht_opp;
	IEEEtypes_VhOpt_t temp_vht_op_ie;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_STA_CFG *mib_StaCfg;

	heop_iep->hdr.ElementId = EXT_IE;
	heop_iep->hdr.ext = HE_OPERATION_IE;
	heop_iep->hdr.Len = sizeof(HE_Operation_IE_t) - sizeof(IEEEtypes_ElementId_t) - sizeof(IEEEtypes_Len_t) - sizeof(heop_iep->heop_ext);

	heop_iep->he_op_param.default_pe_duration = he_default_pe_duration & 0x7;	/* unit 4us  5-7 reserved. */
#ifdef AP_TWT
	if (*vmacSta_p->Mib802dot11->he_twt_activated == 0)
#endif
		heop_iep->he_op_param.twt_required = 0;
	else
		heop_iep->he_op_param.twt_required = 1;

	heop_iep->he_op_param.txop_duration_rts_threshold = mib->he_rts_threshold & 0x3FF;	/* unit 32us, 0 (RTS/CTS always enable), 1023 mean disable */
	//printk("%s(), set txop_duration_rts_threshold: %x\n", __func__, heop_iep->he_op_param.txop_duration_rts_threshold);
	heop_iep->he_op_param.co_located_bss = 0;
	heop_iep->he_op_param.er_su_disable = 1;

	if (vhtopie_present)
		heop_iep->he_op_param.vht_op_info_present = 0;
	else
		heop_iep->he_op_param.vht_op_info_present = 1;

	heop_iep->he_op_param.six_g_op_info_present = 0;

	if (vmacSta_p->master)
		mib = vmacSta_p->master->Mib802dot11;

	mib_StaCfg = mib->StationConfig;

	if (mib_StaCfg->bss_color)
		heop_iep->bss_color_info.bss_color = mib_StaCfg->bss_color;
	else
		heop_iep->bss_color_info.bss_color = (vmacSta_p->master) ? vmacSta_p->master->bss_color : vmacSta_p->bss_color;

	heop_iep->bss_color_info.partial_bss_color = 0;	/* 4 least significant bits of bss color are used in AID assignment */
	heop_iep->bss_color_info.bss_color_disabled = 0;	/* if not detect bss_color_overlap */

	heop_iep->basic_mcs_nss_set.max_mcs_set = SC5_HE_BASIC_MCS_SET;

	if (heop_iep->he_op_param.vht_op_info_present) {
		memset(&temp_vht_op_ie, 0x00, sizeof(IEEEtypes_VhOpt_t));
		Build_IE_192(vmacSta_p, (UINT8 *) & temp_vht_op_ie);
		vht_opp = (vht_operation_info_t *) ((u8 *) & heop_iep->basic_mcs_nss_set + sizeof(heop_iep->basic_mcs_nss_set));
		vht_opp->channel_width = temp_vht_op_ie.ch_width;
		vht_opp->channel_center_freq_0 = temp_vht_op_ie.center_freq0;
		vht_opp->channel_center_freq_1 = temp_vht_op_ie.center_freq1;
		heop_iep->hdr.Len += sizeof(vht_operation_info_t);
	}

	/* if(heop_iep->he_op_param.multi_bssid_ap) */
	// TODO: add MaxBSSID Indicator.
	return (heop_iep->hdr.Len + sizeof(IEEEtypes_ElementId_t)
		+ sizeof(IEEEtypes_Len_t));
}

inline UINT16 Build_IE_MU_EDCA(vmacApInfo_t * vmacSta_p, UINT8 * pBcnBuf)
{
	MIB_STA_CFG *mib_StaCfg_p = vmacSta_p->Mib802dot11->StationConfig;
	MU_EDCA_param_set_t *pIe = (MU_EDCA_param_set_t *) pBcnBuf;

	pIe->hdr.ElementId = EXT_IE;
	pIe->hdr.ext = MU_EDCA_PARAMETERS;
	pIe->hdr.Len = sizeof(MU_EDCA_param_set_t) - 2;

#ifdef WMM_PS_SUPPORT
	pIe->QoS_info.EDCA_param_set_update_cnt = vmacSta_p->VMacEntry.edca_param_set_update_cnt;
	pIe->QoS_info.U_APSD = 1;
	pIe->QoS_info.Reserved = 0;
#else
	pIe->QoS_info.EDCA_param_set_update_cnt = vmacSta_p->VMacEntry.edca_param_set_update_cnt;
	pIe->QoS_info.Q_ack = mib_StaCfg_p->QAckOptImpl;
	pIe->QoS_info.TXOP_req = PROCESS_TXOP_REQ;	//We can process TxOp Request.
	pIe->QoS_info.Q_req = PROCESS_QUEUE_REQ;	//We can process non-zero Queue Size.
#endif

	memcpy((void *)pIe->ac, (void *)vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table, sizeof(pIe->ac));

	return sizeof(MU_EDCA_param_set_t);
}

inline UINT16 Build_IE_SRP(vmacApInfo_t * vmacSta_p, UINT8 * pBcnBuf)
{
	SRP_param_set_t *pIe = (SRP_param_set_t *) pBcnBuf;

	pIe->hdr.ElementId = EXT_IE;
	pIe->hdr.ext = SPATIAL_REUSE_PARAMETERS;
	pIe->hdr.Len = sizeof(SRP_param_set_t) - 2;

	pIe->srpc.srp_disallowed = 0;
	pIe->srpc.non_srg_obss_pd_sr_disallowed = 0;
	pIe->srpc.non_srg_offset_present = 0;
	pIe->srpc.srg_info_present = 0;
	pIe->srpc.hesiga_spatial_reuse_val15_allowed = 0;

	return sizeof(SRP_param_set_t);
}

#ifdef CB_SUPPORT
UINT16 Build_IE_cb(vmacApInfo_t * vmacSta_p, UINT8 * pBcnBuf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

	if ((0 < wlpptr->custie_len) && (wlpptr->custie_len <= sizeof(wlpptr->cust_ie))) {
		memcpy(pBcnBuf, wlpptr->cust_ie, wlpptr->custie_len);
	}

	return wlpptr->custie_len;
}
#endif				//CB_SUPPORT

#endif
