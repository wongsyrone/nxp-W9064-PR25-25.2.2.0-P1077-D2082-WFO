/** @file AssocSta_srv.c
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
/*******************************************************************************************
*
* File: AssocSta_srv.c
*
*        Client Association Service Function Calls
* Description:  Implementation of the Client MLME Association Services
*
*******************************************************************************************/
#include "wltypes.h"
#include "IEEE_types.h"
#ifdef STA_QOS
#include "qos.h"
#endif
#include "mlmeSta.h"
#include "mlmeApi.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "wlvmac.h"
#include "StaDb.h"
#include "linkmgt.h"
#include "domain.h"
#include "wldebug.h"
#ifdef CFG80211
#include "cfg80211.h"
#endif

//=============================================================================
//                         IMPORTED PUBLIC VARIABLES
//=============================================================================
extern SINT32 mlmeApiInitKeyMgmt(vmacStaInfo_t * vStaInfo_p);
#ifdef MULTI_AP_SUPPORT
extern UINT16 Get_MultiAP_IE_Size(vmacApInfo_t * vmacSta_p);
#endif

/*************************************************************************
* Function: assocSrv_SndAssocCnfm
*
* Description: Send Association Confirmation to SME
*
* Input:
*
* Output:
*
**************************************************************************/
UINT8 gDebug_sendSmeMsgFail[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

extern UINT32 vht_cap;

static void assocSrv_SndAssocCnfm(vmacStaInfo_t * vStaInfo_p, UINT16 assocResult)
{
	IEEEtypes_AssocCfrm_t AssocCfrm;

	AssocCfrm.Result = assocResult;
	if (mlmeApiSndNotification(vStaInfo_p, (UINT8 *) & AssocCfrm, MlmeAssoc_Cnfm) == MLME_FAILURE) {
		gDebug_sendSmeMsgFail[assocResult]++;
	}
}

/*************************************************************************
* Function: assocSrv_SndReAssocCnfm
*
* Description: Send ReAssociation Confirmation to SME
*
* Input:
*
* Output:
*
**************************************************************************/
static void assocSrv_SndReAssocCnfm(vmacStaInfo_t * vStaInfo_p, UINT16 reAssocResult)
{
	IEEEtypes_ReassocCfrm_t ReAssocCfrm;

	ReAssocCfrm.Result = reAssocResult;
	mlmeApiSndNotification(vStaInfo_p, (UINT8 *) & ReAssocCfrm, MlmeReAssoc_Cnfm);
}

/*************************************************************************
* Function: assocSrv_SndDisAssocCnfm
*
* Description: Send DisAssociation Confirmation to SME
*
* Input:
*
* Output:
*
**************************************************************************/
static void assocSrv_SndDisAssocCnfm(vmacStaInfo_t * vStaInfo_p, UINT16 disAssocResult)
{
	IEEEtypes_DisassocCfrm_t DisAssocCfrm;

	DisAssocCfrm.Result = disAssocResult;
	mlmeApiSndNotification(vStaInfo_p, (UINT8 *) & DisAssocCfrm, MlmeDisAssoc_Cnfm);
}

/*************************************************************************
* Function: assocSrv_SndDisAssocInd
*
* Description: Send DisAssociation Indication to SME
*
* Input:
*
* Output:
*
**************************************************************************/
static void assocSrv_SndDisAssocInd(vmacStaInfo_t * vStaInfo_p, UINT16 disAssocResult, UINT8 * disAssocPeerAddr)
{
	IEEEtypes_DisassocInd_t DisAssocInd;

	DisAssocInd.Reason = disAssocResult;
	memcpy(&DisAssocInd.PeerStaAddr, disAssocPeerAddr, sizeof(IEEEtypes_MacAddr_t));
	mlmeApiSndNotification(vStaInfo_p, (UINT8 *) & DisAssocInd, MlmeDisAssoc_Ind);
}

/*************************************************************************
* Function: assocSrv_AssocActTimeOut
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT32 assocSrv_AssocActTimeOut(UINT8 * data)
{
	vmacStaInfo_t *vStaInfo_p = (vmacStaInfo_t *) data;

#ifdef ETH_DEBUG
	eprintf("assocSrv_AssocActTimeOut:: ****** Association Time Out \n");
#endif				/* ETH_DEBUG */

	/* Notify SME of Time Out */
	assocSrv_SndAssocCnfm(vStaInfo_p, ASSOC_RESULT_TIMEOUT);
	if (vStaInfo_p->macMgmtMain_State == STATE_ASSOCIATING) {
		vStaInfo_p->macMgmtMain_State = STATE_AUTHENTICATED_WITH_AP;

	}
	/* L2 Event Notification */
	mlmeApiEventNotification(vStaInfo_p, MlmeAssoc_Cnfm, (UINT8 *) & vStaInfo_p->macMgmtMlme_ThisStaData.BssId, ETH_EVT_JOIN_TIMEOUT);
	return 0;
}

/*************************************************************************
* Function: assocSrv_DisAssocActTimeOut
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT32 assocSrv_DisAssocActTimeOut(vmacStaInfo_t * vStaInfo_p, UINT8 * peerAddr)
{
	/* Notify SME of Time Out */
	assocSrv_SndDisAssocCnfm(vStaInfo_p, DISASSOC_RESULT_TIMEOUT);
	vStaInfo_p->macMgmtMain_State = STATE_AUTHENTICATED_WITH_AP;
	return 0;
}

/*************************************************************************
* Function: assocSrv_ReAssocActTimeOut
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT32 assocSrv_ReAssocActTimeOut(vmacStaInfo_t * vStaInfo_p, IEEEtypes_MacAddr_t * peerAddr)
{
	/* Notify SME of Time Out */
	assocSrv_SndReAssocCnfm(vStaInfo_p, REASSOC_RESULT_TIMEOUT);
	if (vStaInfo_p->macMgmtMain_State == STATE_REASSOCIATING) {
		vStaInfo_p->macMgmtMain_State = STATE_ASSOCIATED;
	}
	return 0;
}

/*************************************************************************
* Function: assocSrv_ClearAssocInfo
*
* Description: Clear informations related to the current association
*
* Input:
*
* Output:
*
**************************************************************************/
static void assocSrv_ClearAssocInfo(vmacStaInfo_t * vStaInfo_p)
{
	mlmeApiSetAIdToMac(vStaInfo_p, 0);
}

extern UINT32 SupportedRxVhtMcsSet;
//extern UINT32 SupportedTxVhtMcsSet;
extern UINT16 Build_IE_191(vmacApInfo_t * vmacSta_p, UINT8 * IE_p, UINT8 isEffective, UINT8 nss);
extern UINT16 Build_IE_HE_CAP(vmacApInfo_t * vmacSta_p, UINT8 * IE_p);
extern UINT16 Build_IE_HE_OP(vmacApInfo_t * vmacSta_p, UINT8 * IE_p);
extern UINT16 AddExtended_Cap_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_Extended_Cap_Element_t * pNextElement);
/*************************************************************************
* Function: assocSrv_AssocCmd
*
* Description: Perform an Association Process with AP
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT32 assocSrv_AssocCmd(vmacStaInfo_t * vStaInfo_p, IEEEtypes_AssocCmd_t * AssocCmd_p)
{
	dot11MgtFrame_t *mgtFrame_p;
	UINT8 ssidLen = 0;
	UINT8 extendedRateLen = 0;
	vmacEntry_t *vmacEntry_p;
	UINT8 i;
	IEEEtypes_InfoElementHdr_t *ieHdr_p;
	UINT32 addedVendorLen;
	struct net_device *clientDev_p, *pStaDev;
	struct wlprivate *priv_p, *wlpptrSta;
	vmacApInfo_t *vmacSta_p;
	MIB_802DOT11 *mib, *mibSta;
	BOOLEAN isSpectrumMgmt = FALSE;
	UINT8 j;
	int maxPwr = 0;
	UINT8 *ChannelList = NULL;
	IEEEtypes_PowerCapabilityElement_t *pwrcap = NULL;
	DomainCountryInfo *pInfo = NULL;
	IEEEtypes_SupportedChannelElement_t *supp_chan = NULL;
	UINT8 *supp = NULL;
#ifdef SOC_W8964
	UINT8 use160M = 0;
	UINT8 maxamsdu = 0;
#endif
	UINT8 extendedCap_needAdd = 0;
	UINT8(*attribData)[] = NULL;

#ifdef ETH_DEBUG
	eprintf("assocSrv_AssocCmd:: Entered\n");
#endif				/* ETH_DEBUG */

	//Parent interface pointers
	vmacEntry_p = (vmacEntry_t *) vStaInfo_p->vMacEntry_p;
	clientDev_p = mainNetdev_p[vmacEntry_p->phyHwMacIndx];
	priv_p = NETDEV_PRIV_P(struct wlprivate, clientDev_p);
	mib = priv_p->vmacSta_p->Mib802dot11;

	//Child interface pointers, wdev0sta0
	pStaDev = (struct net_device *)vmacEntry_p->privInfo_p;
	wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);
	vmacSta_p = wlpptrSta->vmacSta_p;
	mibSta = vmacSta_p->Mib802dot11;

	if (vStaInfo_p->macMgmtMain_State != STATE_AUTHENTICATED_WITH_AP) {
		assocSrv_SndAssocCnfm(vStaInfo_p, ASSOC_RESULT_REFUSED);
		return MLME_FAILURE;
	}
	/* Build mgt frame */
	if ((mgtFrame_p = mlmeApiAllocMgtMsg(vmacEntry_p->phyHwMacIndx)) == NULL) {
		/* Notify SME of Assoc failure */
		assocSrv_SndAssocCnfm(vStaInfo_p, ASSOC_RESULT_INVALID_PARAMETERS);
		return MLME_FAILURE;
	}
	mlmePrepDefaultMgtMsg_Sta(vStaInfo_p,
				  mgtFrame_p, &AssocCmd_p->PeerStaAddr, IEEE_MSG_ASSOCIATE_RQST, &(vStaInfo_p->macMgmtMlme_ThisStaData.BssId));
	/* Fill out the MAC body */
	mgtFrame_p->Hdr.FrmBodyLen = 0;
	/* Add Capability Info */
	mgtFrame_p->Body.AssocRqst.CapInfo = AssocCmd_p->CapInfo;
	if (vStaInfo_p->macMgt_StaMode == CLIENT_MODE_B) {
		mgtFrame_p->Body.AssocRqst.CapInfo.ShortSlotTime = 0;
	}
	mgtFrame_p->Hdr.FrmBodyLen += sizeof(IEEEtypes_CapInfo_t);
	/* Add Listen Interval */
	mgtFrame_p->Body.AssocRqst.ListenInterval = AssocCmd_p->ListenInterval;
	mgtFrame_p->Hdr.FrmBodyLen += sizeof(IEEEtypes_ListenInterval_t);
	/* Add SSID Attrib */
	ssidLen = util_ListLen(&AssocCmd_p->SsId[0], IEEEtypes_SSID_SIZE);
	syncSrv_AddAttrib(mgtFrame_p, SSID, &AssocCmd_p->SsId[0], ssidLen);

	if (*(mib->mib_STAMode) == CLIENT_MODE_B) {
		syncSrv_AddAttrib(mgtFrame_p, SUPPORTED_RATES, &vStaInfo_p->bOpRateSet[0], MAX_B_DATA_RATES);
	} else {
		UINT8 supportedRateLen = 0;

		supportedRateLen = util_ListLen(&vStaInfo_p->bssDescProfile_p->DataRates[0], IEEEtypes_MAX_DATA_RATES_G);
		if (supportedRateLen > MLME_SUPPORT_RATE_IE_MAX) {
			extendedRateLen = supportedRateLen - MLME_SUPPORT_RATE_IE_MAX;
			supportedRateLen = MLME_SUPPORT_RATE_IE_MAX;
		}
		/* Supported Rate IE */
		if (supportedRateLen) {
			syncSrv_AddAttrib(mgtFrame_p, SUPPORTED_RATES, &vStaInfo_p->bssDescProfile_p->DataRates[0], supportedRateLen);
		}
	}
	/* If in 5 GHz channel and spectrum management bit is set 
	 * in the capabilities field, make sure to include the power 
	 * capability and supported channel IEs in the association requrest
	 */
	if (domainChannelValid(vStaInfo_p->JoinChannel, FREQ_BAND_5GHZ)) {
		isSpectrumMgmt = (mgtFrame_p->Body.AssocRqst.CapInfo.SpectrumMgmt) ? TRUE : FALSE;
		if (isSpectrumMgmt) {
			ChannelList = wl_kmalloc(IEEE_80211_MAX_NUMBER_OF_CHANNELS, GFP_ATOMIC);
			if (ChannelList == NULL) {
				return MLME_FAILURE;
			}
			pwrcap = wl_kmalloc(sizeof(IEEEtypes_PowerCapabilityElement_t), GFP_ATOMIC);
			if (pwrcap == NULL) {
				wl_kfree(ChannelList);
				return MLME_FAILURE;
			}
			pInfo = wl_kmalloc(sizeof(DomainCountryInfo), GFP_ATOMIC);
			if (pInfo == NULL) {
				wl_kfree(pwrcap);
				wl_kfree(ChannelList);
				return MLME_FAILURE;
			}
			memset(pInfo, 0, sizeof(DomainCountryInfo));
			domainGetPowerInfo((UINT8 *) pInfo);
			for (i = 0; i < pInfo->AChannelLen; i++) {
				if (vStaInfo_p->JoinChannel >= pInfo->DomainEntryA[i].FirstChannelNo &&
				    vStaInfo_p->JoinChannel < pInfo->DomainEntryA[i].FirstChannelNo + pInfo->DomainEntryA[i].NoofChannel) {
					maxPwr = pInfo->DomainEntryA[i].MaxTransmitPw;
					break;
				}
			}
			wl_kfree(pInfo);
			pwrcap->ElementId = PWR_CAP;
			pwrcap->Len = 2;
			pwrcap->MaxTxPwr = maxPwr ? maxPwr : 18;
			pwrcap->MinTxPwr = 5;
			attribData = (UINT8(*)[]) & pwrcap->MaxTxPwr;
			syncSrv_AddAttrib(mgtFrame_p, PWR_CAP, (UINT8 *) attribData, 2);
			wl_kfree(pwrcap);
			if (domainGetInfo(ChannelList)) {
				supp_chan = wl_kmalloc(sizeof(IEEEtypes_SupportedChannelElement_t), GFP_ATOMIC);
				if (supp_chan == NULL) {
					wl_kfree(ChannelList);
					return MLME_FAILURE;
				}
				supp_chan->ElementId = SUPPORTED_CHANNEL;
				supp = (UINT8 *) & supp_chan->SupportedChannel[0];
				for (i = 0, j = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
					if (ChannelList[i] != 0 && domainChannelValid(ChannelList[i], FREQ_BAND_5GHZ)) {
						*supp = ChannelList[i];
						supp++;
						*supp = 1;
						supp++;
						j += 2;
					}
				}
				supp_chan->Len = j;
				syncSrv_AddAttrib(mgtFrame_p, SUPPORTED_CHANNEL, (UINT8 *) & supp_chan->SupportedChannel[0], j);
				wl_kfree(supp_chan);
			}
			wl_kfree(ChannelList);
		}
	}

	/* HT IE */
	if (IsHTmode(*(mib->mib_ApMode))) {
		if (vStaInfo_p->bssDescProfile_p->HTElement.Len) {
			IEEEtypes_Add_HT_Element_t add_ht;
				/** Set ldpc coding to 1 for 8864 and newer chips **/
			vStaInfo_p->bssDescProfile_p->HTElement.HTCapabilitiesInfo.AdvCoding = 1;

			if ((*(mibSta->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_8K))
				vStaInfo_p->bssDescProfile_p->HTElement.HTCapabilitiesInfo.MaxAMSDUSize = 1;
			else
				vStaInfo_p->bssDescProfile_p->HTElement.HTCapabilitiesInfo.MaxAMSDUSize = 0;

			switch (*(mib->mib_rxAntenna)) {
			case 1:
				vStaInfo_p->bssDescProfile_p->HTElement.SupportedMCSset[3] = 0;
				vStaInfo_p->bssDescProfile_p->HTElement.SupportedMCSset[2] = 0;
				vStaInfo_p->bssDescProfile_p->HTElement.SupportedMCSset[1] = 0;
				break;
			case 2:
				vStaInfo_p->bssDescProfile_p->HTElement.SupportedMCSset[3] = 0;
				vStaInfo_p->bssDescProfile_p->HTElement.SupportedMCSset[2] = 0;
				break;
			case 3:
				vStaInfo_p->bssDescProfile_p->HTElement.SupportedMCSset[3] = 0;
				break;
			default:
				break;
			}

			syncSrv_AddAttrib(mgtFrame_p,
					  vStaInfo_p->bssDescProfile_p->HTElement.ElementId,
					  (UINT8 *) & vStaInfo_p->bssDescProfile_p->HTElement.HTCapabilitiesInfo,
					  vStaInfo_p->bssDescProfile_p->HTElement.Len);
			{
				extern UINT16 AddAddHT_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_Add_HT_Element_t * pNextElement);
				UINT16 length = AddAddHT_IE(priv_p->vmacSta_p, &add_ht);
				attribData = (UINT8(*)[]) & add_ht.ControlChan;
				if (length != 0)
					syncSrv_AddAttrib(mgtFrame_p, ADD_HT, (UINT8 *) attribData, length - 2);
			}
		}
	}
#if defined(CONFIG_IEEE80211W) || defined(CONFIG_HS2)
	/* RSN IE (WPA2) */
	if (vmacSta_p->RsnIESetByHost) {
		IEEEtypes_RSN_IE_WPA2_t *pRsn = (IEEEtypes_RSN_IE_WPA2_t *) vmacSta_p->RsnIE;

		syncSrv_AddAttrib(mgtFrame_p, pRsn->ElemId, &pRsn->Ver[0], pRsn->Len);
	} else
#endif
	if (vStaInfo_p->bssDescProfile_p->Wpa2Element.Len) {
		syncSrv_AddAttrib(mgtFrame_p,
				  vStaInfo_p->bssDescProfile_p->Wpa2Element.ElemId,
				  (UINT8 *) & vStaInfo_p->bssDescProfile_p->Wpa2Element.Ver[0], vStaInfo_p->bssDescProfile_p->Wpa2Element.Len);
	}
	/* Extended Supported Rate IE */
	if (extendedRateLen) {
		syncSrv_AddAttrib(mgtFrame_p,
				  EXT_SUPPORTED_RATES, &vStaInfo_p->bssDescProfile_p->DataRates[MLME_SUPPORT_RATE_IE_MAX], extendedRateLen);
	}
#ifdef WPA_STA
	if (vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->RSNEnabled) {
		// For WPA/WPA2, Privacy bit in association request frame should be set to
		// zero
		mgtFrame_p->Body.AssocRqst.CapInfo.Privacy = 0;
		mlmeApiInitKeyMgmt(vStaInfo_p);
	}
#endif				/* WPA_STA */
	/* Add in Vendor Specific IEs */
	if (vStaInfo_p->bssDescProfile_p->vendorIENum && vStaInfo_p->bssDescProfile_p->vendorTotalLen) {
		addedVendorLen = 0;
		for (i = 0; i < vStaInfo_p->bssDescProfile_p->vendorIENum; i++) {
			ieHdr_p = (IEEEtypes_InfoElementHdr_t *) & vStaInfo_p->bssDescProfile_p->vendorBuf[addedVendorLen];
			if (ieHdr_p->Len) {
				/*when opmode configured legacy non-HT capable mode, assoc-req shall not contain this HT-PROP IE either, otherwise, AP might reject the association request */
				if (!
				    (*(mib->mib_ApMode) == AP_MODE_B_ONLY || *(mib->mib_ApMode) == AP_MODE_G_ONLY
				     || *(mib->mib_ApMode) == AP_MODE_A_ONLY || *(mib->mib_ApMode) == AP_MODE_AandG)
|| (memcmp(&((IEEEtypes_Generic_HT_Element_t *) & vStaInfo_p->bssDescProfile_p->vendorBuf[addedVendorLen])->OUI, B_COMP_OUI, 3)
    && ((IEEEtypes_Generic_HT_Element_t *) & vStaInfo_p->bssDescProfile_p->vendorBuf[addedVendorLen])->OUIType != 51)
				    ) {

					/*Exclude any vendor specific IE with OUI 00-90-4C to avoid AP misinterpret any HT-PROP values. 
					 * In STA mode, no need other vendor IE in assoc req packet
					 */
					if (memcmp
					    (&((IEEEtypes_Generic_HT_Element_t *) & vStaInfo_p->bssDescProfile_p->vendorBuf[addedVendorLen])->OUI,
					     B_COMP_OUI, 3)) {
						syncSrv_AddAttrib(mgtFrame_p, ieHdr_p->ElementId,
								  (&vStaInfo_p->bssDescProfile_p->vendorBuf[addedVendorLen] +
								   sizeof(IEEEtypes_InfoElementHdr_t)), ieHdr_p->Len);
					}
				}
			}
			addedVendorLen += ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
		}
	}
	if (*(mib->mib_ApMode) & AP_MODE_11AC) {	/* add IE191  && IE192 to Assoc REQ */
		IEEEtypes_VhtCap_t ptr;
		IEEEtypes_VhOpt_t vhtOpt_ptr;
		UINT8 HZ160_support = 0;

		if (vStaInfo_p->bssDescProfile_p->VHTOp.len) {
			if (vStaInfo_p->bssDescProfile_p->VHTOp.ch_width == 2) {
				HZ160_support = 1;
			} else if (vStaInfo_p->bssDescProfile_p->VHTOp.ch_width == 1) {
#ifdef SUPPORTED_EXT_NSS_BW
				int ret = 0;
				printk("%s ", __FUNCTION__);

				if (1 == (ret = isSupport160MhzByCenterFreq(priv_p, VHT_EXTENDED_NSS_BW_CAPABLE,
									    vStaInfo_p->bssDescProfile_p->VHTOp.center_freq0,
									    vStaInfo_p->bssDescProfile_p->VHTOp.center_freq1,
									    vStaInfo_p->bssDescProfile_p->ADDHTElement.OpMode.center_freq2))) {

					HZ160_support = 1;

				} else if (0 == ret) {

					printk("80MHz or less\n");
				}
#else
				if (vStaInfo_p->bssDescProfile_p->VHTOp.center_freq1 == 0) {
					printk("%s 80MHz or less\n", __FUNCTION__);
				} else {
					UINT8 diff;
					if (vStaInfo_p->bssDescProfile_p->VHTOp.center_freq1 > vStaInfo_p->bssDescProfile_p->VHTOp.center_freq0) {
						diff =
						    vStaInfo_p->bssDescProfile_p->VHTOp.center_freq1 -
						    vStaInfo_p->bssDescProfile_p->VHTOp.center_freq0;
					} else {
						diff =
						    vStaInfo_p->bssDescProfile_p->VHTOp.center_freq0 -
						    vStaInfo_p->bssDescProfile_p->VHTOp.center_freq1;
					}
					if (diff == 8) {
						printk
						    ("%s 160Mhz: center frequency of the 80 MHz channel segment that contains the primary channel = %d\n",
						     __FUNCTION__, vStaInfo_p->bssDescProfile_p->VHTOp.center_freq0);
						printk("%s 160Mhz: center frequency of the 160 MHz channel = %d\n", __FUNCTION__,
						       vStaInfo_p->bssDescProfile_p->VHTOp.center_freq1);
						HZ160_support = 1;
					} else if (diff > 8) {
#ifdef SOC_W906X
						isSupport80plus80Mhz(priv_p);
#else
						WLDBG_ERROR(DBG_LEVEL_1, "80MHz + 80MHz, not support\n");
#endif
					} else {
						printk("%s reserved\n", __FUNCTION__);
					}
				}
#endif
			}
#ifdef SOC_W906X
			Build_IE_191(vmacSta_p, (UINT8 *) & ptr, FALSE, 0);
#else
			/*Check against own configured bw */
			if ((vStaInfo_p->bssDescProfile_p->VHTCap.cap.SupportedChannelWidthSet == 1)
			    || (vStaInfo_p->bssDescProfile_p->VHTCap.cap.SupportedChannelWidthSet == 2)
			    || (HZ160_support)) {

				if ((mib->PhyDSSSTable->Chanflag.ChnlWidth > CH_AUTO_WIDTH) &&
				    (mib->PhyDSSSTable->Chanflag.ChnlWidth < CH_160_MHz_WIDTH))
					use160M = 0;
				else
					use160M = 1;
			}

			if (use160M) {
				vht_cap |= (1 << 2);	//set bit2 for 160Mhz support
#ifdef SUPPORTED_EXT_NSS_BW
#ifdef TEST_160M_CASE_4_2_58
				vht_cap &= ~(1 << 2);
				vht_cap |= (1 << 30);	//for test case 4.2.58, ExtendedNssBwSupport is 1
#endif
#endif
				//If LGI
				if (*(mib->mib_guardInterval) == 2)
					vht_cap &= ~(1 << 6);
				else
					vht_cap |= (1 << 6);	//set bit6 for 160 or 80+80MHz SGI support

			} else {
				vht_cap &= ~(1 << 2);

				if (*(mib->mib_guardInterval) == 2)
					vht_cap &= ~(1 << 5);
				else
					vht_cap |= (1 << 5);	//set bit5 for 80MHz SGI support
			}

			vht_cap &= ~(1 << 19);	//MUBeamformerCapable
			vht_cap |= (1 << 20);	//MUBeamformeeCapable                            
			memcpy((UINT8 *) & ptr.cap, &vht_cap, sizeof(IEEEtypes_VHT_Cap_Info_t));
			//ptr.SupportedRxMcsSet = 0xffea;
			//ptr.SupportedTxMcsSet = 0xffea;
			ptr.SupportedRxMcsSet = SupportedRxVhtMcsSet;
#ifdef SUPPORTED_EXT_NSS_BW
			ptr.SupportedTxMcsSet = mib->StationConfig->SupportedTxVhtMcsSet | VHT_EXTENDED_NSS_BW_CAPABLE_BIT;	//will move to mib
#else
			ptr.SupportedTxMcsSet = mib->StationConfig->SupportedTxVhtMcsSet;
#endif
			if ((*(mibSta->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK) == WL_MODE_AMSDU_TX_8K)
				maxamsdu = 1;
			else if ((*(mibSta->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK) == WL_MODE_AMSDU_TX_11K)
				maxamsdu = 2;

			ptr.cap.MaximumMPDULength = maxamsdu;
#endif				/* SOC_W906X */

			attribData = (UINT8(*)[]) & ptr.cap;
			syncSrv_AddAttrib(mgtFrame_p, 191, (UINT8 *) attribData, 12);
			{
				UINT16 Build_IE_192(vmacApInfo_t * vmacSta_p, UINT8 * IE_p);
				attribData = (UINT8(*)[]) & vhtOpt_ptr.ch_width;
				vhtOpt_ptr.ch_width = 0;
				Build_IE_192(priv_p->vmacSta_p, (UINT8 *) & vhtOpt_ptr);
				syncSrv_AddAttrib(mgtFrame_p, 192, (UINT8 *) attribData, 5);

			}
		}
	}
#ifdef MULTI_AP_SUPPORT
	if (mibSta->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_STA) {
		IEEEtypes_MultiAP_Element_t *multi_ap = NULL;
		UINT16 size = Get_MultiAP_IE_Size(vmacSta_p);

		multi_ap = wl_kmalloc(size, GFP_ATOMIC);
		if (multi_ap == NULL) {
			return MLME_FAILURE;
		}

		memset(multi_ap, 0x00, size);
		multi_ap->OUI[0] = 0x50;
		multi_ap->OUI[1] = 0x6F;
		multi_ap->OUI[2] = 0x9A;
		multi_ap->OUIType = MultiAP_OUI_type;
		multi_ap->attributes.Attribute = 0x06;
		multi_ap->attributes.Attribute_Len = 0x01;
		multi_ap->attributes.BackSTA = 1;
		/* Add Version subelement for R2, Table 3.            *
		 * Version subelement omitted by Multi-AP R1 devices. */
		//multi_ap->version[0] = 0x07; //Subelement ID: 0x07
		//multi_ap->version[1] = 0x01; //Subelement Length: 1
		//multi_ap->version[2] = mibSta->multi_ap_ver; //Subelement Value: Variable
		if (mibSta->multi_ap_ver == 2) {
			IEEEtypes_MultiAP_Version_t *version = (IEEEtypes_MultiAP_Version_t *) multi_ap->variable;

			version->ElementId = 0x07;
			version->Len = 0x01;
			version->value = mibSta->multi_ap_ver;
		}
		attribData = (UINT8(*)[]) & multi_ap->OUI[0];
		syncSrv_AddAttrib(mgtFrame_p, PROPRIETARY_IE, (UINT8 *) attribData, (size - 2));
		wl_kfree(multi_ap);
	}
#endif				/* MULTI_AP_SUPPORT */

#ifdef MBO_SUPPORT
	if (wlpptrSta->mboAssocRequestIeLen > 0) {
		UINT8 *pos = (UINT8 *) & mgtFrame_p->Body + mgtFrame_p->Hdr.FrmBodyLen;
		memcpy(pos, wlpptrSta->mboAssocRequestIe, wlpptrSta->mboAssocRequestIeLen);
		mgtFrame_p->Hdr.FrmBodyLen += wlpptrSta->mboAssocRequestIeLen;
	}

	if ((mibSta->mib_mbo_wnm) || (mibSta->Interworking))
		extendedCap_needAdd = 1;
#endif				/* MBO_SUPPORT */

#ifdef AP_STEERING_SUPPORT
	if (*(mibSta->mib_btm_enabled))
		extendedCap_needAdd = 1;
#endif				/* AP_STEERING_SUPPORT */

	if (extendedCap_needAdd) {
		IEEEtypes_Extended_Cap_Element_t *pExtCap = NULL;

		pExtCap = wl_kmalloc(sizeof(IEEEtypes_Extended_Cap_Element_t), GFP_ATOMIC);
		if (pExtCap) {
			AddExtended_Cap_IE(vmacSta_p, pExtCap);
			syncSrv_AddAttrib(mgtFrame_p, EXT_CAP_IE, (UINT8 *) & pExtCap->ExtCap, sizeof(IEEEtypes_Extended_Cap_Element_t) - 2);
			wl_kfree(pExtCap);
		}
	}
#ifdef SOC_W906X
	if (*(mib->mib_ApMode) & AP_MODE_11AX) {
		/* add HE CAP IE  && HE OP IE to Assoc REQ */
		mgtFrame_p->Hdr.FrmBodyLen += Build_IE_HE_CAP(vmacSta_p, (UINT8 *) & mgtFrame_p->Body + mgtFrame_p->Hdr.FrmBodyLen);
	}
#endif				/* SOC_W906X */
	/* Send mgt frame */
	if (mlmeApiSendMgtMsg_Sta(vStaInfo_p, mgtFrame_p, NULL) == MLME_FAILURE) {
		/* Notify SME of Assoc failure */
		assocSrv_SndAssocCnfm(vStaInfo_p, ASSOC_RESULT_REFUSED);
		return MLME_FAILURE;
	}
	/* Start Assoc Timer */
	mlmeApiStartTimer(vStaInfo_p, (UINT8 *) & vStaInfo_p->assocTimer, &assocSrv_AssocActTimeOut, ASSOC_TIME);
	vStaInfo_p->macMgmtMain_State = STATE_ASSOCIATING;
	return MLME_SUCCESS;
}

/*************************************************************************
* Function: assocSrv_ReAssocCmd
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT32 assocSrv_ReAssocCmd(vmacStaInfo_t * vStaInfo_p, IEEEtypes_ReassocCmd_t * ReassocCmd_p)
{
	dot11MgtFrame_t *mgtFrame_p;
	vmacEntry_t *vmacEntry_p;
	UINT8 ssidLen = 0;
	UINT8 supportedRateLen = 0;
	UINT8 extendedRateLen = 0;
	BOOLEAN isSpectrumMgmt = FALSE;
	UINT8 i, j;
	int maxPwr = 0;
	UINT8 *ChannelList = NULL;
	IEEEtypes_PowerCapabilityElement_t *pwrcap = NULL;
	DomainCountryInfo *pInfo = NULL;
	IEEEtypes_SupportedChannelElement_t *supp_chan = NULL;
	UINT8 *supp = NULL;

#if defined(AP_STEERING_SUPPORT) || defined(MULTI_AP_SUPPORT) || defined(MBO_SUPPORT)
	struct net_device *pStaDev = NULL;
	struct wlprivate *wlpptrSta = NULL;
	vmacApInfo_t *vmacSta_p = NULL;
	MIB_802DOT11 *mibSta = NULL;
#endif				/* AP_STEERING_SUPPORT || MULTI_AP_SUPPORT || MBO_SUPPORT */
	UINT8(*attribData)[] = NULL;
	UINT8 extendedCap_needAdd = 0;

	vmacEntry_p = (vmacEntry_t *) vStaInfo_p->vMacEntry_p;

#if defined(AP_STEERING_SUPPORT) || defined(MULTI_AP_SUPPORT) || defined(MBO_SUPPORT)
	//Child interface pointers, wdev0sta0
	pStaDev = (struct net_device *)vmacEntry_p->privInfo_p;
	wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);
	vmacSta_p = wlpptrSta->vmacSta_p;
	mibSta = vmacSta_p->Mib802dot11;
#endif				/* AP_STEERING_SUPPORT || MULTI_AP_SUPPORT || MBO_SUPPORT */

	if (vStaInfo_p->macMgmtMain_State != STATE_ASSOCIATED) {
		assocSrv_SndReAssocCnfm(vStaInfo_p, REASSOC_RESULT_REFUSED);
		return MLME_FAILURE;
	}

	/* Build mgt frame */
	if ((mgtFrame_p = mlmeApiAllocMgtMsg(vmacEntry_p->phyHwMacIndx)) == NULL) {
		return MLME_FAILURE;
	}

	mlmePrepDefaultMgtMsg_Sta(vStaInfo_p,
				  mgtFrame_p, &ReassocCmd_p->NewApAddr, IEEE_MSG_REASSOCIATE_RQST, &(vStaInfo_p->macMgmtMlme_ThisStaData.BssId));
	memset(&(mgtFrame_p->Body), 0, sizeof(mgtFrame_p->Body));
	mgtFrame_p->Hdr.FrmBodyLen = 0;
	/* Add Capability Info */
	mgtFrame_p->Body.ReassocRqst.CapInfo = ReassocCmd_p->CapInfo;
	mgtFrame_p->Hdr.FrmBodyLen += sizeof(IEEEtypes_CapInfo_t);
	/* Add Listen Interval */
	mgtFrame_p->Body.ReassocRqst.ListenInterval = ReassocCmd_p->ListenInterval;
	mgtFrame_p->Hdr.FrmBodyLen += sizeof(IEEEtypes_ListenInterval_t);
	/* Add AP Address */
	memcpy(&mgtFrame_p->Body.ReassocRqst.CurrentApAddr, vStaInfo_p->macMgmtMlme_ThisStaData.BssId, sizeof(IEEEtypes_MacAddr_t));
	mgtFrame_p->Hdr.FrmBodyLen += sizeof(IEEEtypes_MacAddr_t);
	/* Add SSID Attrib */
	ssidLen = util_ListLen(&ReassocCmd_p->SsId[0], IEEEtypes_SSID_SIZE);
	syncSrv_AddAttrib(mgtFrame_p, SSID, &ReassocCmd_p->SsId[0], ssidLen);
	/* Add Support Rates Attrib */
	supportedRateLen = util_ListLen(&vStaInfo_p->bssDescProfile_p->DataRates[0], IEEEtypes_MAX_DATA_RATES_G);

	if (supportedRateLen > MLME_SUPPORT_RATE_IE_MAX) {
		extendedRateLen = supportedRateLen - MLME_SUPPORT_RATE_IE_MAX;
		supportedRateLen = MLME_SUPPORT_RATE_IE_MAX;
	}
	if (supportedRateLen) {
		syncSrv_AddAttrib(mgtFrame_p, SUPPORTED_RATES, &vStaInfo_p->bssDescProfile_p->DataRates[0], supportedRateLen);
	}
	/* If in 5 GHz channel and spectrum management bit is set 
	 * in the capabilities field, make sure to include the power 
	 * capability and supported channel IEs in the association requrest
	 */
	if (domainChannelValid(vStaInfo_p->JoinChannel, FREQ_BAND_5GHZ)) {
		isSpectrumMgmt = (mgtFrame_p->Body.AssocRqst.CapInfo.SpectrumMgmt) ? TRUE : FALSE;
		if (isSpectrumMgmt) {
			ChannelList = wl_kmalloc(IEEE_80211_MAX_NUMBER_OF_CHANNELS, GFP_ATOMIC);
			if (ChannelList == NULL) {
				return MLME_FAILURE;
			}
			pwrcap = wl_kmalloc(sizeof(IEEEtypes_PowerCapabilityElement_t), GFP_ATOMIC);
			if (pwrcap == NULL) {
				wl_kfree(ChannelList);
				return MLME_FAILURE;
			}
			pInfo = wl_kmalloc(sizeof(DomainCountryInfo), GFP_ATOMIC);
			if (pInfo == NULL) {
				wl_kfree(pwrcap);
				wl_kfree(ChannelList);
				return MLME_FAILURE;
			}
			memset(pInfo, 0, sizeof(DomainCountryInfo));
			domainGetPowerInfo((UINT8 *) pInfo);
			for (i = 0; i < pInfo->AChannelLen; i++) {
				if (vStaInfo_p->JoinChannel >= pInfo->DomainEntryA[i].FirstChannelNo &&
				    vStaInfo_p->JoinChannel < pInfo->DomainEntryA[i].FirstChannelNo + pInfo->DomainEntryA[i].NoofChannel) {
					maxPwr = pInfo->DomainEntryA[i].MaxTransmitPw;
					break;
				}
			}
			wl_kfree(pInfo);
			pwrcap->ElementId = PWR_CAP;
			pwrcap->Len = 2;
			pwrcap->MaxTxPwr = maxPwr ? maxPwr : 18;
			pwrcap->MinTxPwr = 5;
			attribData = (UINT8(*)[]) & pwrcap->MaxTxPwr;
			syncSrv_AddAttrib(mgtFrame_p, PWR_CAP, (UINT8 *) attribData, 2);
			wl_kfree(pwrcap);
			if (domainGetInfo(ChannelList)) {
				supp_chan = wl_kmalloc(sizeof(IEEEtypes_SupportedChannelElement_t), GFP_ATOMIC);
				if (supp_chan == NULL) {
					wl_kfree(ChannelList);
					return MLME_FAILURE;
				}
				supp_chan->ElementId = SUPPORTED_CHANNEL;
				supp = (UINT8 *) & supp_chan->SupportedChannel[0];
				for (i = 0, j = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
					if (ChannelList[i] != 0 && domainChannelValid(ChannelList[i], FREQ_BAND_5GHZ)) {
						*supp = ChannelList[i];
						supp++;
						*supp = 1;
						supp++;
						j += 2;
					}
				}
				supp_chan->Len = j;
				syncSrv_AddAttrib(mgtFrame_p, SUPPORTED_CHANNEL, (UINT8 *) & supp_chan->SupportedChannel[0], j);
				wl_kfree(supp_chan);
			}
			wl_kfree(ChannelList);
		}
	}
	if (extendedRateLen) {
		syncSrv_AddAttrib(mgtFrame_p,
				  EXT_SUPPORTED_RATES, &vStaInfo_p->bssDescProfile_p->DataRates[MLME_SUPPORT_RATE_IE_MAX], extendedRateLen);
	}
#ifdef WPA_STA
	if (vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->RSNEnabled) {
		((KeyData_t *) vStaInfo_p->keyMgmtInfoSta_p->pKeyData)->RSNDataTrafficEnabled = 0;
		syncSrv_AddAttrib(mgtFrame_p, RSN_IE, "\x00\x10\x18\x01\x00", 3);	/*add dummy params for interop issues */
		syncSrv_AddAttrib(mgtFrame_p, RSN_IE, &vStaInfo_p->thisStaRsnIE_p->OuiType[0], vStaInfo_p->thisStaRsnIE_p->Len);
	}
#endif				/* WPA_STA */
#ifdef STA_QOS
	if (vStaInfo_p->staSystemMibs.mib_StaCfg_p->QoSOptImpl) {

		syncSrv_AddAttrib(mgtFrame_p, QOS_CAPABILITY, &vStaInfo_p->thisStaQoSCapElem_p->QoS_info[0], vStaInfo_p->thisStaQoSCapElem_p->Len);
#ifdef QOS_WSM_FEATURE
		if (vStaInfo_p->staSystemMibs.mib_StaCfg_p->WSMQoSOptImpl) {
			syncSrv_AddAttrib(mgtFrame_p, PROPRIETARY_IE, &gThisStaWSMQoSCapElem.OUI[0], gThisStaWSMQoSCapElem.Len);
			//Add a WME Info Elem here as well.
			syncSrv_AddAttrib(mgtFrame_p, PROPRIETARY_IE, &gThisStaWMEQoSCapElem.OUI[0], gThisStaWMEQoSCapElem.Len);
		}
#endif				/* QOS_WSM_FEATURE */
	}
#endif				/* STA_QOS */

#ifdef MULTI_AP_SUPPORT
	if (mibSta->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_STA) {
		IEEEtypes_MultiAP_Element_t *multi_ap = NULL;
		UINT16 size = Get_MultiAP_IE_Size(vmacSta_p);

		multi_ap = wl_kmalloc(size, GFP_ATOMIC);
		if (multi_ap == NULL) {
			return MLME_FAILURE;
		}

		memset(multi_ap, 0x00, size);
		multi_ap->OUI[0] = 0x50;
		multi_ap->OUI[1] = 0x6F;
		multi_ap->OUI[2] = 0x9A;
		multi_ap->OUIType = MultiAP_OUI_type;
		multi_ap->attributes.Attribute = 0x06;
		multi_ap->attributes.Attribute_Len = 0x01;
		multi_ap->attributes.BackSTA = 1;
		/* Add Version subelement for R2, Table 3.            *
		 * Version subelement omitted by Multi-AP R1 devices. */
		//multi_ap->version[0] = 0x07; //Subelement ID: 0x07
		//multi_ap->version[1] = 0x01; //Subelement Length: 1
		//multi_ap->version[2] = mibSta->multi_ap_ver; //Subelement Value: Variable
		if (mibSta->multi_ap_ver == 2) {
			IEEEtypes_MultiAP_Version_t *version = (IEEEtypes_MultiAP_Version_t *) multi_ap->variable;

			version->ElementId = 0x07;
			version->Len = 0x01;
			version->value = mibSta->multi_ap_ver;
		}
		attribData = (UINT8(*)[]) & multi_ap->OUI[0];
		syncSrv_AddAttrib(mgtFrame_p, PROPRIETARY_IE, (UINT8 *) attribData, (size - 2));
		wl_kfree(multi_ap);
	}
#endif				/* MULTI_AP_SUPPORT */

#ifdef MBO_SUPPORT
	if (wlpptrSta->mboAssocRequestIeLen > 0) {
		UINT8 *pos = (UINT8 *) & mgtFrame_p->Body + mgtFrame_p->Hdr.FrmBodyLen;
		memcpy(pos, wlpptrSta->mboAssocRequestIe, wlpptrSta->mboAssocRequestIeLen);
		mgtFrame_p->Hdr.FrmBodyLen += wlpptrSta->mboAssocRequestIeLen;
	}

	if ((mibSta->mib_mbo_wnm) || (mibSta->Interworking))
		extendedCap_needAdd = 1;
#endif				/* MBO_SUPPORT */

#ifdef AP_STEERING_SUPPORT
	if (*(mibSta->mib_btm_enabled))
		extendedCap_needAdd = 1;
#endif				/* AP_STEERING_SUPPORT */

	if (extendedCap_needAdd) {
		IEEEtypes_Extended_Cap_Element_t *pExtCap = NULL;

		pExtCap = wl_kmalloc(sizeof(IEEEtypes_Extended_Cap_Element_t), GFP_ATOMIC);
		if (pExtCap) {
			AddExtended_Cap_IE(vmacSta_p, pExtCap);
			syncSrv_AddAttrib(mgtFrame_p, EXT_CAP_IE, (UINT8 *) & pExtCap->ExtCap, sizeof(IEEEtypes_Extended_Cap_Element_t) - 2);
			wl_kfree(pExtCap);
		}
	}

	/* Transmit Mgt Frame */
	if (mlmeApiSendMgtMsg_Sta(vStaInfo_p, mgtFrame_p, NULL) == MLME_FAILURE) {
		/* Notify SME of Failure */
		assocSrv_SndReAssocCnfm(vStaInfo_p, REASSOC_RESULT_REFUSED);
		return MLME_FAILURE;
	}
	vStaInfo_p->macMgmtMain_State = STATE_REASSOCIATING;
	return MLME_SUCCESS;
}

/*************************************************************************
* Function: assocSrv_DisAssocCmd
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT32 assocSrv_DisAssocCmd(vmacStaInfo_t * vStaInfo_p, IEEEtypes_DisassocCmd_t * DisassocCmd_p)
{
	dot11MgtFrame_t *mgtFrame_p;
	vmacEntry_t *vmacEntry_p;

	vmacEntry_p = (vmacEntry_t *) vStaInfo_p->vMacEntry_p;
	/* Are we Associated first of all? */
	if (vStaInfo_p->macMgmtMain_State != STATE_ASSOCIATED) {
		assocSrv_SndDisAssocCnfm(vStaInfo_p, DISASSOC_RESULT_REFUSED);
		return MLME_FAILURE;
	}

	/* Build mgt frame */
	if ((mgtFrame_p = mlmeApiAllocMgtMsg(vmacEntry_p->phyHwMacIndx)) == NULL) {
		return MLME_FAILURE;
	}

	mlmePrepDefaultMgtMsg_Sta(vStaInfo_p,
				  mgtFrame_p, &DisassocCmd_p->PeerStaAddr, IEEE_MSG_DISASSOCIATE, &(vStaInfo_p->macMgmtMlme_ThisStaData.BssId));
	mgtFrame_p->Hdr.FrmBodyLen = 0;
	/* Add Reason Code */
	mgtFrame_p->Body.DisAssoc.ReasonCode = DisassocCmd_p->Reason;
	mgtFrame_p->Hdr.FrmBodyLen += sizeof(IEEEtypes_DisAssoc_t);
	/* Transmit Mgt Frame */
	if (mlmeApiSendMgtMsg_Sta(vStaInfo_p, mgtFrame_p, NULL) == MLME_FAILURE) {
		/* Notify SME of Failure */
		assocSrv_SndDisAssocCnfm(vStaInfo_p, DISASSOC_RESULT_REFUSED);
	}
	/* L2 Event Notification */
	mlmeApiEventNotification(vStaInfo_p, MlmeDisAssoc_Req, &DisassocCmd_p->PeerStaAddr[0], DisassocCmd_p->Reason);
	vStaInfo_p->macMgmtMain_State = STATE_AUTHENTICATED_WITH_AP;
	/* Clear out data related to association with this AP */
	assocSrv_ClearAssocInfo(vStaInfo_p);
	/* Notify SME of Success */
	assocSrv_SndDisAssocCnfm(vStaInfo_p, DISASSOC_RESULT_SUCCESS);
	/*Milind. 09/29/05 */
	/*Free the AssocTable data structure that has been currently assigned to this */
	/*peer station to which the WB was associated/joined */
	mlmeApiFreePeerStationStaInfoAndAid(&(DisassocCmd_p->PeerStaAddr), vmacEntry_p);
	return MLME_SUCCESS;
}

#ifdef SOC_W8964
//5.2.48++
extern void *syncSrv_ParseAttrib(macmgmtQ_MgmtMsg_t * mgtFrame_p, UINT8 attrib, UINT16 len);
extern void SendScanCmd(vmacApInfo_t * vmacSta_p, UINT8 * channels);
extern SINT32 linkMgtStop(UINT8 phyIndex);
UINT32 smePendingCmd(UINT8 * info_p);
extern UINT32 smeClearCmdHistory(UINT8 * info_p);

extern linkMgtEntry_t linkMgtEntry[NUM_OF_WLMACS];
extern SINT32 scan_obss(UINT8 * data)
{
	vmacStaInfo_t *vStaInfo_p = (vmacStaInfo_t *) data;
	vmacEntry_t *vmacEntry_p = (vmacEntry_t *) vStaInfo_p->vMacEntry_p;

	struct net_device *staDev = (struct net_device *)vmacEntry_p->privInfo_p;
	struct wlprivate *stapriv = NETDEV_PRIV_P(struct wlprivate, staDev);
	UINT8 bcAddr1[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };	/* BROADCAST BSSID */
	UINT8 ieBuf[2 + IEEE_80211_MAX_NUMBER_OF_CHANNELS];
	UINT16 ieBufLen = 0;
	IEEEtypes_InfoElementHdr_t *IE_p;

	vmacApInfo_t *vmacSta_p = vmacSta_p = stapriv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	UINT8 mlmeAssociatedFlag;
	UINT8 mlmeBssid[6];
	UINT8 currChnlIndex = 0;
	UINT8 chnlListLen = 0;
	UINT8 chnlScanList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	UINT8 i = 0, idx_current;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;
	UINT8 mainChnlList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	int clientDisable = 0;

	UINT8 bgn_chnl_id, end_chnl_id;
	SINT32 rc = 0;

	{
		BOOLEAN tx_empty = TRUE;
		for (i = 0; i < NUM_OF_DESCRIPTOR_DATA; i++) {
			if (skb_queue_empty(&stapriv->wlpd_p->txQ[i]) == FALSE) {
				// Queue is not empty
				printk("%s(), Queue[%d] is not empty\n", __func__, i);
				tx_empty = FALSE;
				break;
			}
		}
		if ((tx_empty == FALSE) || (stapriv->bgscan_period == 0)) {
			//printk("%s(), TX queue is not empty or bgscan_period=%d, skip this scan (%d)\n", __func__, 
			//      stapriv->bgscan_period,
			//      vStaInfo_p->obss_scan_interval);
			TimerInit(&vStaInfo_p->obss_Timer_retry);
			TimerFireIn(&vStaInfo_p->obss_Timer_retry, 1, &scan_obss, (unsigned char *)vStaInfo_p, vStaInfo_p->obss_scan_interval);
			return 0;
		}
	}

	// For the last connection 
	{
		linkMgtEntry_t *aLink_p;
		aLink_p = &linkMgtEntry[vmacEntry_p->phyHwMacIndx];
		// searchBitMap , change to 0
		aLink_p->searchBitMap = 0;
	}

	//when this command issued on AP mode, system would crash because of no STA interface
	//so the following checking is necessary.
#ifdef AP_SCAN_SUPPORT
	if (*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) {
		*(mib->mib_STAMode) = CLIENT_MODE_AUTO;
		clientDisable = 1;
	}
#else
	if (*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) {
		rc = -EOPNOTSUPP;
		return rc;
	}
#endif

	memset(&mainChnlList[0], 0, (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));
	memset(&chnlScanList[0], 0, (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));

	PhyDSSSTable = mib->PhyDSSSTable;

	/* Stop Autochannel on AP first */
	if (stapriv->master) {
		struct wlprivate *wlMPrvPtr = NETDEV_PRIV_P(struct wlprivate, stapriv->master);
		StopAutoChannel(wlMPrvPtr->vmacSta_p);
	}
	/* get range to scan */
	domainGetInfo(mainChnlList);

	// Get the channel to scan
	// Find the working channel
	if ((*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_AUTO) || (*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_N)) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
			if ((mainChnlList[i] > 0) && (mainChnlList[i] == vStaInfo_p->JoinChannel)) {
				// Find the working channel
				idx_current = i;
				break;
			}
		}
		if (i < IEEEtypes_MAX_CHANNELS) {
			// Found the channel
			bgn_chnl_id = (i >= 2) ? (i - 2) : 0;
			end_chnl_id = (i <= IEEEtypes_MAX_CHANNELS - 1 - 2) ? (i + 2) : (IEEEtypes_MAX_CHANNELS - 1);

			//for (i=bgn_chnl_id ; i<=end_chnl_id ; i++) {
			for (i = bgn_chnl_id; i <= end_chnl_id; i += 2) {
				if (i == idx_current) {	// Skip current channel
					continue;
				}
				if (mainChnlList[i] > 0) {
					chnlScanList[currChnlIndex] = mainChnlList[i];
					currChnlIndex++;
				}
			}

		}

		for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
			if ((mainChnlList[i + IEEEtypes_MAX_CHANNELS] > 0) && (mainChnlList[i + IEEEtypes_MAX_CHANNELS] == vStaInfo_p->JoinChannel)) {
				idx_current = i;
				break;
				chnlScanList[currChnlIndex] = mainChnlList[i + IEEEtypes_MAX_CHANNELS];
				currChnlIndex++;
			}
		}
		if (i < IEEEtypes_MAX_CHANNELS_A) {
			// Found the channel
			bgn_chnl_id = (i >= 2) ? (i + IEEEtypes_MAX_CHANNELS - 2) : IEEEtypes_MAX_CHANNELS;
			end_chnl_id = (i <= IEEEtypes_MAX_CHANNELS_A - 1 - 2) ?
			    (i + IEEEtypes_MAX_CHANNELS + 2) : ((IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A) - 1);
			//for (i=bgn_chnl_id ; i<=end_chnl_id ; i++) {
			for (i = bgn_chnl_id; i <= end_chnl_id; i += 2) {
				if (i == idx_current) {	// Skip current channel
					continue;
				}
				if (mainChnlList[i] > 0) {
					chnlScanList[currChnlIndex] = mainChnlList[i];
					currChnlIndex++;
				}
			}
		}

		chnlListLen = currChnlIndex;
	} else if (*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_N_24) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
			if ((mainChnlList[i] > 0) && (mainChnlList[i] == vStaInfo_p->JoinChannel)) {
				// Find the working channel
				idx_current = i;
				break;
			}
		}
		if (i < IEEEtypes_MAX_CHANNELS) {
			// Found the channel
			bgn_chnl_id = (i >= 2) ? (i - 2) : 0;
			end_chnl_id = (i <= IEEEtypes_MAX_CHANNELS - 1 - 2) ? (i + 2) : (IEEEtypes_MAX_CHANNELS - 1);
			//for (i=bgn_chnl_id ; i<=end_chnl_id ; i++) {
			for (i = bgn_chnl_id; i <= end_chnl_id; i += 2) {
				if (i == idx_current) {	// Skip current channel
					continue;
				}
				if (mainChnlList[i] > 0) {
					chnlScanList[currChnlIndex] = mainChnlList[i];
					currChnlIndex++;
				}
			}
		}

		chnlScanList[i] = 0;
		chnlListLen = currChnlIndex;
	} else if (*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_N_5) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
			//chnlScanList[i] = mainChnlList[i+IEEEtypes_MAX_CHANNELS];
			if ((mainChnlList[i + IEEEtypes_MAX_CHANNELS] > 0) && (mainChnlList[i + IEEEtypes_MAX_CHANNELS] == vStaInfo_p->JoinChannel)) {
				// Find the working channel
				idx_current = i;
				break;
			}
		}
		if (i < IEEEtypes_MAX_CHANNELS_A) {
			// Found the channel
			bgn_chnl_id = (i >= 2) ? (i + IEEEtypes_MAX_CHANNELS - 2) : IEEEtypes_MAX_CHANNELS;
			end_chnl_id = (i <= IEEEtypes_MAX_CHANNELS_A - 1 - 2) ?
			    (i + IEEEtypes_MAX_CHANNELS + 2) : ((IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A) - 1);
			//for (i=bgn_chnl_id ; i<=end_chnl_id ; i++) {
			for (i = bgn_chnl_id; i <= end_chnl_id; i += 2) {
				if (i == idx_current) {	// Skip current channel
					continue;
				}
				if (mainChnlList[i] > 0) {
					chnlScanList[currChnlIndex] = mainChnlList[i];
					currChnlIndex++;
				}
			}
		}

		chnlScanList[i] = 0;
		chnlListLen = currChnlIndex;
	}
#ifdef AP_SCAN_SUPPORT
	if (clientDisable)
		*(mib->mib_STAMode) = CLIENT_MODE_DISABLE;
#endif
	ieBufLen = 0;
	/* Build IE Buf */
	IE_p = (IEEEtypes_InfoElementHdr_t *) & ieBuf[ieBufLen];

	/* SSID element */
	/* For scan all SSIDs to be scanned */

	/* DS_PARAM_SET element */
	IE_p->ElementId = DS_PARAM_SET;
	IE_p->Len = chnlListLen;
	ieBufLen += sizeof(IEEEtypes_InfoElementHdr_t);
	memcpy((char *)&ieBuf[ieBufLen], &chnlScanList[0], chnlListLen);

	ieBufLen += IE_p->Len;
	IE_p = (IEEEtypes_InfoElementHdr_t *) & ieBuf[ieBufLen];

	if ((vmacEntry_p = sme_GetParentVMacEntry(((vmacApInfo_t *) stapriv->vmacSta_p)->VMacEntry.phyHwMacIndx)) == NULL) {
		rc = -EFAULT;
		return rc;
	}

	if (!smeGetStaLinkInfo(vmacEntry_p->id, &mlmeAssociatedFlag, &mlmeBssid[0])) {
		rc = -EFAULT;
		return rc;
	}
	if (mlmeAssociatedFlag == true) {
		vStaInfo_p->in_obss_scan = TRUE;
		vStaInfo_p->intolerant_chnl_size = 0;
	} else {
		// Already disconnected => leave now
		vStaInfo_p->in_obss_scan = FALSE;
		return rc;
	}

	/* Set a flag indicating usr initiated scan */
	if (smeSendScanRequest(vmacEntry_p->phyHwMacIndx, 0, 3, 200, &bcAddr1[0], &ieBuf[0], ieBufLen) == MLME_SUCCESS) {
		/*set the busy scanning flag */
		vmacSta_p->busyScanning = 1;
		return rc;
	} else {
		/* Reset a flag indicating usr initiated scan */
		vmacSta_p->gUserInitScan = FALSE;
		rc = -EALREADY;
		return rc;
	}
	return rc;
}
#endif				/* SOC_W8964 */

/*************************************************************************
* Function: assocSrv_RecvAssocRsp
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT32 assocSrv_RecvAssocRsp(vmacStaInfo_t * vStaInfo_p, dot11MgtFrame_t * MgmtMsg_p)
{
#ifdef MULTI_AP_SUPPORT
	struct net_device *pStaDev;
	struct wlprivate *wlpptrSta;
	vmacApInfo_t *vmacSta_p;
	MIB_802DOT11 *mibSta;
	UINT8 MultiAp_OUI[3] = { 0x50, 0x6F, 0x9A };
	UINT8 *attrib_p = NULL;
	UINT16 primary_vid = 0;
	unsigned char buf[IW_CUSTOM_MAX] = { 0 };
	union iwreq_data wreq;
	static const char *tag = "1905Q";
	IEEEtypes_MultiAP_Traffic_t *traffic = NULL;
	IEEEtypes_MultiAP_Element_t *MultiAp_elem_p = NULL;
#endif				/* MULTI_AP_SUPPORT */
#ifdef STA_QOS
#ifdef QOS_WSM_FEATURE
	MhsmEvent_t TsMsg;
	WME_param_elem_t *WME_param_elem = NULL;;
#endif				/* QOS_WSM_FEATURE */
#endif				/* STA_QOS */
#ifdef SOC_W8964
	extern void PciWriteMacReg(struct net_device *netdev, UINT32 offset, UINT32 val);
#endif
	vmacEntry_t *vmacEntry_p;
	vmacEntry_p = (vmacEntry_t *) vStaInfo_p->vMacEntry_p;

#ifdef MULTI_AP_SUPPORT
	//Child interface pointers, wdev0sta0
	pStaDev = (struct net_device *)vmacEntry_p->privInfo_p;
	wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);
	vmacSta_p = wlpptrSta->vmacSta_p;
	mibSta = vmacSta_p->Mib802dot11;
#endif				/* MULTI_AP_SUPPORT */

#ifdef ETH_DEBUG
	eprintf("assocSrv_RecvMsgRsp:: Entered\n");
#endif				/* ETH_DEBUG */
	mlmeApiStopTimer(vStaInfo_p, (UINT8 *) & vStaInfo_p->assocTimer);
	vStaInfo_p->aId = ENDIAN_SWAP16(MgmtMsg_p->Body.AssocRsp.AId);
	/* L2 Event Notification */
	mlmeApiEventNotification(vStaInfo_p, MlmeAssoc_Cnfm, (UINT8 *) & MgmtMsg_p->Hdr.SrcAddr[0], MgmtMsg_p->Body.AssocRsp.StatusCode);
	if (MgmtMsg_p->Body.AssocRsp.StatusCode != IEEEtypes_STATUS_SUCCESS) {
		/* Handle ASSOCIATION Failure */
		if (vStaInfo_p->macMgmtMain_State == STATE_ASSOCIATING) {
			/* Set back to Authenticated state */
			vStaInfo_p->macMgmtMain_State = STATE_AUTHENTICATED_WITH_AP;
			/* Notify SME of association failure */
			assocSrv_SndAssocCnfm(vStaInfo_p, ASSOC_RESULT_REFUSED);
		}
		return MLME_FAILURE;
	}
	/* Record the information given by the association. */
	mlmeApiSetAIdToMac(vStaInfo_p, MgmtMsg_p->Body.AssocRsp.AId);
#ifdef SOC_W8964
	//printk("AID: %x\n", MgmtMsg_p->Body.AssocRsp.AId);
	PciWriteMacReg(mainNetdev_p[vmacEntry_p->phyHwMacIndx], 0x11a0, MgmtMsg_p->Body.AssocRsp.AId & 0x3f);
#endif

#ifdef SOC_W906X
	{
		struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, mainNetdev_p[vmacEntry_p->phyHwMacIndx]);

		*(u32 *) (&((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.staAid) = MgmtMsg_p->Body.AssocRsp.AId & 0x7ff;
	}
#endif

#ifdef STA_QOS
	if (vStaInfo_p->staSystemMibs.mib_StaCfg_p->QoSOptImpl) {	//search for QOS Action Element ID
		Qos_InitTCLASTable();	//Initialize the QoS database
#ifdef QOS_WSM_FEATURE
		//Also initialise the the EDCA parameters here.
		attrib_p = &MgmtMsg_p->Body.AssocRsp.AId;
		attrib_p += sizeof(IEEEtypes_AId_t);
		staInfo_p->macMgmtMlme_ThisStaData.IsStaQosSTA = 0;
		while ((attrib_p = syncSrv_ParseAttribWithinFrame(MgmtMsg_p, attrib_p, PROPRIETARY_IE)) != NULL) {
			//if(WME_param_elem = (WME_param_elem_t*)syncSrv_ParseAttrib(MgmtMsg_p, PROPRIETARY_IE))
			//check if it is a WME/WSM Info Element.
			WME_param_elem = attrib_p;
			if (!memcmp(WME_param_elem->OUI.OUI, WiFiOUI, 3)) {
				//Check if it is a WME element
				if (WME_param_elem->OUI.Type == 2) {
					//check if it is a WME Param Element
					if (WME_param_elem->OUI.Subtype == 1) {
						QoS_UpdateStnEDCAParameters(WME_param_elem);
						//Update the QoS Info Parameters.
						memcpy(&(Qos_Stn_Data[0].QoS_Info), &(WME_param_elem->QoS_info), sizeof(QoS_Info_t));
						vStaInfo_p->macMgmtMlme_ThisStaData.IsStaQosSTA = 1;
						break;
					}
				}
			}
			//Now process to teh next element pointer.
			attrib_p += (2 + *((UINT8 *) (attrib_p + 1)));
		}
#endif				/* QOS_WSM_FEATURE */
	}
#endif				/* STA_QOS */

#ifdef MULTI_AP_SUPPORT
	if (mibSta->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_STA) {
		UINT16 MultiAp_elem_size = MAP_R1_IE_SIZE;
		attrib_p = (UINT8 *) & MgmtMsg_p->Body.AssocRsp.AId;
		attrib_p += sizeof(IEEEtypes_AId_t);
		vStaInfo_p->isConnectbBSS = FALSE;
		while ((attrib_p = syncSrv_ParseAttribWithinFrame(MgmtMsg_p, attrib_p, PROPRIETARY_IE)) != NULL) {
			MultiAp_elem_p = (IEEEtypes_MultiAP_Element_t *) attrib_p;
			if ((MultiAp_elem_p != NULL) && (!memcmp(MultiAp_elem_p->OUI, MultiAp_OUI, 3)) &&
			    (MultiAp_elem_p->OUIType == MultiAP_OUI_type) && (MultiAp_elem_p->attributes.Attribute == 0x06)) {
				vStaInfo_p->isConnectbBSS = (MultiAp_elem_p->attributes.BackBSS == 1) ? TRUE : FALSE;

				if (MultiAp_elem_p->Len >= MAP_R1_IE_LEN + sizeof(IEEEtypes_MultiAP_Version_t)) {
					UINT16 version_len = 0;
					IEEEtypes_MultiAP_Version_t *version = (IEEEtypes_MultiAP_Version_t *) MultiAp_elem_p->variable;

					if ((version->ElementId == 0x07) && (version->Len == 0x01)) {
						version_len += version->Len + 2;
						MultiAp_elem_size += sizeof(IEEEtypes_MultiAP_Version_t);
					}

					if ((version_len && (MultiAp_elem_p->Len >=
							     (MAP_R1_IE_LEN +
							      sizeof(IEEEtypes_MultiAP_Version_t) +
							      sizeof(IEEEtypes_MultiAP_Traffic_t)))) ||
					    (MultiAp_elem_p->Len >= (MAP_R1_IE_LEN + sizeof(IEEEtypes_MultiAP_Traffic_t)))) {
						traffic = (IEEEtypes_MultiAP_Traffic_t *) (MultiAp_elem_p->variable + version_len);

						if ((traffic->ElementId == 0x08) && (traffic->Len == 0x02)) {
							primary_vid = (UINT16) SHORT_SWAP(traffic->vid);
							MultiAp_elem_size += sizeof(IEEEtypes_MultiAP_Traffic_t);
						}
					}
				}

				if ((primary_vid > 0) && (traffic != NULL)) {
					snprintf(buf, sizeof(buf), "%s", tag);
					memcpy(&buf[strlen(tag)], traffic, sizeof(IEEEtypes_MultiAP_Traffic_t));

					memset(&wreq, 0, sizeof(wreq));
					wreq.data.length = strlen(tag) + sizeof(IEEEtypes_MultiAP_Traffic_t);
					if (vmacSta_p->dev->flags & IFF_RUNNING)
						wireless_send_event(vmacSta_p->dev, IWEVCUSTOM, &wreq, buf);
				}
#if defined(SOC_W906X) && defined(CFG80211)
				mwl_send_vendor_multiapIE_event(vmacSta_p->dev,
								(uint8_t *) & MgmtMsg_p->Hdr.SrcAddr, MultiAp_elem_p, MultiAp_elem_size);
#endif				/* SOC_W906X */

				break;
			}

			attrib_p += (2 + *((UINT8 *) (attrib_p + 1)));
		}
	}
#endif				/* MULTI_AP_SUPPORT */

	if (vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->RSNEnabled) {
		KeyMgmtResetCounter(vStaInfo_p->keyMgmtInfoSta_p);
		CounterMeasureInit_Sta(&vStaInfo_p->keyMgmtInfoSta_p->sta_MIC_Error, TRUE);
	} else {
		CounterMeasureInit_Sta(&vStaInfo_p->keyMgmtInfoSta_p->sta_MIC_Error, FALSE);
	}
	vStaInfo_p->macMgmtMain_State = STATE_ASSOCIATED;
	vStaInfo_p->AssociatedFlag = 1;
	vStaInfo_p->Station_p->ChipCtrl.GreenFieldSet = 0;
#ifdef SOC_W8964
	/* Remove AP from station database, somtimes added by AP state machine. */
	mlmeApiDelStaDbEntry(vStaInfo_p, (UINT8 *) & vStaInfo_p->macMgmtMlme_ThisStaData.BssId);
#endif
	/* Add Sta Db Entry */
	mlmeApiAddStaDbEntry(vStaInfo_p, MgmtMsg_p);

	/* Notify SME */
	assocSrv_SndAssocCnfm(vStaInfo_p, ASSOC_RESULT_SUCCESS);
	memcpy(vStaInfo_p->macMgmtMlme_ThisStaData.BssId, MgmtMsg_p->Hdr.SrcAddr, sizeof(IEEEtypes_MacAddr_t));
#ifdef MRVL_WPS_CLIENT
	if (vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->RSNEnabled && vStaInfo_p->staSystemMibs.mib_StaCfg_p->wpawpa2Mode < 4)
#else
	if (vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->RSNEnabled)
#endif
	{
		// Start RSN key handshake session
		mlmeApiStartKeyMgmt(vStaInfo_p);
	}
#ifdef SOC_W8964
	//5.2.48++

	{
		IEEEtypes_DsParamSet_t *p_ds_param_elm = NULL;
		IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t *p_obss_param_elm = NULL;
		IEEEtypes_20_40_BSS_COEXIST_Element_t *p_2040_coex_elm = NULL;
		struct net_device *staDev = (struct net_device *)vmacEntry_p->privInfo_p;
		struct wlprivate *stapriv = NETDEV_PRIV_P(struct wlprivate, staDev);

		p_ds_param_elm = (IEEEtypes_DsParamSet_t *) syncSrv_ParseAttribWithinFrame(MgmtMsg_p, (UINT8 *) & MgmtMsg_p->Body, DS_PARAM_SET);
		p_obss_param_elm =
		    (IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t *) syncSrv_ParseAttribWithinFrame(MgmtMsg_p, (UINT8 *) & MgmtMsg_p->Body,
												       OVERLAPPING_BSS_SCAN_PARAMETERS);
		p_2040_coex_elm =
		    (IEEEtypes_20_40_BSS_COEXIST_Element_t *) syncSrv_ParseAttribWithinFrame(MgmtMsg_p, (UINT8 *) & MgmtMsg_p->Body,
											     _20_40_BSSCOEXIST);
		if (p_obss_param_elm != NULL) {
			if (stapriv->bgscan_period != 0) {
				vStaInfo_p->obss_scan_interval = stapriv->bgscan_period;
			} else {
				vStaInfo_p->obss_scan_interval = DEF_OBSS_SCAN_PERIOD;
			}
			printk("=>%s(), File scan_obss(), %d, %d, %p\n", __func__, vStaInfo_p->obss_scan_interval, stapriv->bgscan_period, stapriv);

			TimerInit(&vStaInfo_p->obss_Timer);
			TimerFireIn(&vStaInfo_p->obss_Timer, 1, &scan_obss, (unsigned char *)vStaInfo_p, vStaInfo_p->obss_scan_interval);

		}
	}
	//5.2.48--
#endif				/* SOC_W8964 */
	return MLME_SUCCESS;
}

/*************************************************************************
* Function: assocSrv_RecvReAssocRsp
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT32 assocSrv_RecvReAssocRsp(vmacStaInfo_t * vStaInfo_p, dot11MgtFrame_t * MgmtMsg_p)
{
#ifdef STA_QOS
	MhsmEvent_t TsMsg;
#endif
	vmacEntry_t *vmacEntry_p;
	extStaDb_StaInfo_t *wbStaInfo_p = NULL;
	UINT32 local_urAid;
	UINT8 *attrib_p;
	IEEEtypes_SuppRatesElement_t *PeerSupportedRates_p;
	IEEEtypes_ExtSuppRatesElement_t *PeerExtSupportedRates_p;
	struct net_device *pStaDev;
	struct wlprivate *wlpptrSta, *wlpptr;

	vmacEntry_p = (vmacEntry_t *) vStaInfo_p->vMacEntry_p;
	pStaDev = (struct net_device *)vmacEntry_p->privInfo_p;
	wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);
	wlpptr = NETDEV_PRIV_P(struct wlprivate, wlpptrSta->master);

	/* Since we are not doing ReAssoc, just silently discard */
	if (vStaInfo_p->macMgmtMain_State != STATE_REASSOCIATING) {
		return MLME_FAILURE;
	}
	if (MgmtMsg_p->Body.ReassocRsp.StatusCode != IEEEtypes_STATUS_SUCCESS) {
		/* Failure handler */
		/* Notify SME of ReAssoc Refused */
		assocSrv_SndReAssocCnfm(vStaInfo_p, REASSOC_RESULT_REFUSED);
		return MLME_FAILURE;
	}
	if (vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->RSNEnabled) {
		KeyMgmtResetCounter(vStaInfo_p->keyMgmtInfoSta_p);
		CounterMeasureInit_Sta(&vStaInfo_p->keyMgmtInfoSta_p->sta_MIC_Error, TRUE);
	} else {
		CounterMeasureInit_Sta(&vStaInfo_p->keyMgmtInfoSta_p->sta_MIC_Error, FALSE);
	}
	vStaInfo_p->macMgmtMain_State = STATE_ASSOCIATED;
	vStaInfo_p->AssociatedFlag = 1;
	vStaInfo_p->Station_p->ChipCtrl.GreenFieldSet = 0;
	/* Remove AP from station database, somtimes added by AP state machine. */
	mlmeApiDelStaDbEntry(vStaInfo_p, (UINT8 *) & vStaInfo_p->macMgmtMlme_ThisStaData.BssId);

	/* Notify SME of ReAssoc Success */
	assocSrv_SndReAssocCnfm(vStaInfo_p, REASSOC_RESULT_SUCCESS);

	if (vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->RSNEnabled) {
		// Start RSN key handshake session
		mlmeApiStartKeyMgmt(vStaInfo_p);
	}

	if (mlmeApiGetPeerStationStaInfoAndAid(&(MgmtMsg_p->Hdr.SrcAddr), &wbStaInfo_p, &local_urAid) == FALSE) {
		/*there is no entry in the station database for the peer station with this */
		/*mac address. So first create one */
		/*first get the set of supported rates of the peer station */

		/*get a pointer to the starting IE for this Mgt frame */
		attrib_p = (UINT8 *) & MgmtMsg_p->Body.AssocRsp.AId;
		attrib_p += sizeof(IEEEtypes_AId_t);
		/*now get a pointer to the set of Supported Rates and Ext Supported Rates */
		PeerSupportedRates_p = syncSrv_ParseAttribWithinFrame(MgmtMsg_p, attrib_p, SUPPORTED_RATES);

		PeerExtSupportedRates_p = syncSrv_ParseAttribWithinFrame(MgmtMsg_p, attrib_p, EXT_SUPPORTED_RATES);

		if (mlmeApiCreatePeerStationInfoForWBMode(&(MgmtMsg_p->Hdr.SrcAddr),
							  PeerSupportedRates_p, PeerExtSupportedRates_p, vmacEntry_p->phyHwMacIndx) == TRUE) {

			mlmeApiGetPeerStationStaInfoAndAid(&(MgmtMsg_p->Hdr.SrcAddr), &wbStaInfo_p, &local_urAid);
		} else {
			/*Could not create an entry for this station */
			return MLME_FAILURE;
		}
	}
	/*Set the state of the Sta Info to WB_ASSOCIATED */
	if (wbStaInfo_p == NULL) {
		return MLME_FAILURE;
	} else {
		/* Drop all frames in the fragment cache. */
		if (wbStaInfo_p && (wbStaInfo_p->pDefragSkBuff)) {
			struct except_cnt *wlexcept_p = &wlpptr->wlpd_p->except_cnt;

			wl_free_skb(wbStaInfo_p->pDefragSkBuff);
			wbStaInfo_p->pDefragSkBuff = NULL;
			wlexcept_p->cnt_defrag_drop++;
			wlexcept_p->cnt_defrag_drop_x[9]++;
		}
		mlmeApiSetPeerStationStateForWB(wbStaInfo_p, WB_ASSOCIATED);
	}
	return MLME_SUCCESS;
}

/*************************************************************************
* Function: assocSrv_RecvDisAssocMsg
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT32 assocSrv_RecvDisAssocMsg(vmacStaInfo_t * vStaInfo_p, dot11MgtFrame_t * MgmtMsg_p)
{
	vmacEntry_t *vmacEntry_p;
	vmacEntry_p = (vmacEntry_t *) vStaInfo_p->vMacEntry_p;
	/* Check BSSID */
	if (memcmp(vStaInfo_p->macMgmtMlme_ThisStaData.BssId, MgmtMsg_p->Hdr.SrcAddr, sizeof(IEEEtypes_MacAddr_t))) {
		/* BSSID don't match so silently discard packet */
		return MLME_FAILURE;
	}

	/* L2 Event Notification */
	mlmeApiEventNotification(vStaInfo_p, MlmeDisAssoc_Ind, &MgmtMsg_p->Hdr.SrcAddr[0], MgmtMsg_p->Body.DisAssoc.ReasonCode);

	/* Clear out data related to association with this AP */
	assocSrv_ClearAssocInfo(vStaInfo_p);
	/* Notify SME of DisAssoc */
	assocSrv_SndDisAssocInd(vStaInfo_p, MgmtMsg_p->Body.DisAssoc.ReasonCode, MgmtMsg_p->Hdr.SrcAddr);
	/*Milind. 09/29/05 */
	/*Free the AssocTable data structure that has been currently assigned to this */
	/*peer station to which the WB was associated/joined */
	mlmeApiFreePeerStationStaInfoAndAid(&(MgmtMsg_p->Hdr.SrcAddr), vmacEntry_p);
	//macMgtMlme_Free_AssocTblInfo(macMgtMlme_geturAid(vmacEntry_p->phyHwMacIndx));

	return MLME_SUCCESS;
}

/*************************************************************************
* Function: assocSrv_Reset
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT32 assocSrv_Reset(vmacStaInfo_t * vStaInfo_p)
{
	mlmeApiStopTimer(vStaInfo_p, (UINT8 *) & vStaInfo_p->assocTimer);
	/* Init the Association state machines */
	AssocSrvStaCtor(&vStaInfo_p->assocsrv);
	mhsm_initialize(&vStaInfo_p->assocsrv.super, &vStaInfo_p->assocsrv.sTop);
	return MLME_SUCCESS;
}
