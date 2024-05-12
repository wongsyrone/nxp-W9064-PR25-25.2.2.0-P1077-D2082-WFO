/** @file linkmgt.c
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
/*******************************************************************************************
*
* File: linkmgt.c
*        Link Mgt Module
* Description:  Implementation of the Link Mgt Module Services
*
*******************************************************************************************/
#include "mlmeSta.h"
#include "wlvmac.h"
#include "timer.h"
#include "mlmeParent.h"
#include "linkmgt.h"
#include "ap8xLnxIntf.h"
#include "qos.h"
#include "mlmeApi.h"
#include "ap8xLnxFwcmd.h"
typedef struct Wps_Header_t {
	UINT16 ElementId;
	UINT16 Len;
} PACK_END Wps_Header_t;

const static UINT8 wps_oui[] = { 0x00, 0x50, 0xF2, 0x04 };

#ifdef WPA_STA			//pick one below
#define DO_WPA_TKIP 1
#define DO_WPA_AES  1
extern IEEEtypes_RSN_IE_t *staMib_thisStaRsnIE_p[NUM_OF_WLMACS];
#ifdef AP_WPA2
extern IEEEtypes_RSN_IE_WPA2_t *staMib_thisStaRsnIEWPA2_p[NUM_OF_WLMACS];
extern MIB_RSNCONFIGWPA2 *staMib_RSNConfigWPA2_p[NUM_OF_WLMACS];
#endif
#endif				/* WPA_STA */
extern UINT8 WiFiOUI[3];
//#define LNK_DEBUG   1
#ifdef LNK_DEBUG
#define eprintf printk
#endif				/* LNK_DEBUG */
extern void keyMgmtUpdateRsnIE(UINT8 phymacIndex, UINT8 rsn_modeId, UINT32 mCipherId, UINT32 uCipherId, UINT32 aCipherId);

extern IEEEtypes_InfoElementHdr_t *smeParseIeType(UINT8 ieType, UINT8 * ieBuf_p, UINT16 ieBufLen);
extern BOOLEAN isMcIdIE(UINT8 * data_p);
extern BOOLEAN isM_RptrIdIE(UINT8 * data_p);
static const UINT8 rptr_oui_type_subtype_ver[6] = { 0x00, 0x40, 0x96, 0x27, 0x00, 0x10 };

/* Global Declaration */
linkMgtEntry_t linkMgtEntry[NUM_OF_WLMACS];
UINT8 linkMgtSelectedBss[LNK_MGT_BSS_PROFILE_BUF_LEN];

/*************************************************************************
 * Function: linkMgtInit
 *
 * Description: Inital Auto Link Services for a particular MAC entity.
 *
 * Input:
 *
 * Output:
 **************************************************************************/
extern void linkMgtInit(UINT8 phyIndex)
{
	if (phyIndex >= NUM_OF_WLMACS) {
		return;
	}
	memset((void *)&linkMgtEntry[phyIndex], 0, sizeof(linkMgtEntry_t));
}

/*************************************************************************
 * Function: linkMgtActTimeOut
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
extern SINT32 linkMgtActTimeOut(UINT8 * data)
{
	linkMgtEntry_t *aLink_p = (linkMgtEntry_t *) data;

#ifdef LNK_DEBUG
	eprintf("**** linkMgtActTimeOut\n");
#endif				/* LNK_DEBUG */
	if (aLink_p == NULL) {
		return -1;
	}
	if (!aLink_p->active) {
		return 0;
	}
	smeSendScanRequest(aLink_p->phyHwMacIndx, 0, 3, 200, &aLink_p->bssid[0], &aLink_p->scanIeBuf[0], aLink_p->scanIeBufLen);
	return 0;
}

/*************************************************************************
 * Function: smeParseIeType
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
extern IEEEtypes_RSN_IE_t *linkMgtParseWpaIe(UINT8 * ieBuf_p, UINT16 ieBufLen)
{
	UINT8 *ieBufEnd_p;
	UINT8 *ieCurrent_p;
	IEEEtypes_RSN_IE_t *IE_p;

	ieCurrent_p = ieBuf_p;
	ieBufEnd_p = ieBuf_p + ieBufLen;

	while (ieCurrent_p < ieBufEnd_p) {
		IE_p = (IEEEtypes_RSN_IE_t *) ieCurrent_p;
		if (IE_p->ElemId == PROPRIETARY_IE) {
			if ((IE_p->OuiType[0] == 0x00) && (IE_p->OuiType[1] == 0x50) && (IE_p->OuiType[2] == 0xf2) && (IE_p->OuiType[3] == 0x01)) {
				return IE_p;
			}
		}
		ieCurrent_p += (IE_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
	}
	return NULL;
}

/*************************************************************************
 * Function: smeParseIeType
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
extern IEEEtypes_RSN_IE_t *linkMgtParseWpsIe(UINT8 * ieBuf_p, UINT16 ieBufLen)
{
	UINT8 *ieBufEnd_p;
	UINT8 *ieCurrent_p;
	IEEEtypes_RSN_IE_t *IE_p;

	ieCurrent_p = ieBuf_p;
	ieBufEnd_p = ieBuf_p + ieBufLen;

	while (ieCurrent_p < ieBufEnd_p) {
		IE_p = (IEEEtypes_RSN_IE_t *) ieCurrent_p;
		if (IE_p->ElemId == PROPRIETARY_IE) {
			//if (!memcmp(wps_oui, IE_p->OuiType, 4))
			if ((IE_p->OuiType[0] == 0x00) && (IE_p->OuiType[1] == 0x50) && (IE_p->OuiType[2] == 0xf2) && (IE_p->OuiType[3] == 0x04)) {
				return IE_p;
			}
		}
		ieCurrent_p += (IE_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
	}
	return NULL;
}

#ifdef MULTI_AP_SUPPORT
/*************************************************************************
* Function: linkMgtParseMultiAPIe
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern IEEEtypes_MultiAP_Element_t *linkMgtParseMultiAPIe(UINT8 * ieBuf_p, UINT16 ieBufLen)
{
	UINT8 *ieBufEnd_p;
	UINT8 *ieCurrent_p;
	IEEEtypes_MultiAP_Element_t *IE_p;

	ieCurrent_p = ieBuf_p;
	ieBufEnd_p = ieBuf_p + ieBufLen;

	while (ieCurrent_p < ieBufEnd_p) {
		if (*(IEEEtypes_ElementId_t *) ieCurrent_p == PROPRIETARY_IE) {
			IE_p = (IEEEtypes_MultiAP_Element_t *) ieCurrent_p;
			if ((IE_p->OUI[0] == 0x50) &&
			    (IE_p->OUI[1] == 0x6F) &&
			    (IE_p->OUI[2] == 0x9A) && (IE_p->OUIType == MultiAP_OUI_type) && (IE_p->attributes.Attribute == 0x06)) {
				return IE_p;
			}
		}

		ieCurrent_p += (2 + *((UINT8 *) (ieCurrent_p + 1)));
	}

	return NULL;
}
#endif				/* MULTI_AP_SUPPORT */

#ifdef MBO_SUPPORT
/*************************************************************************
* Function: linkMgtParseMBOIe
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern struct IEEEtypes_MBO_Element_t *linkMgtParseMBOIe(UINT8 * ieBuf_p, UINT16 ieBufLen)
{
	UINT8 *ieBufEnd_p;
	UINT8 *ieCurrent_p;
	struct IEEEtypes_MBO_Element_t *IE_p;

	ieCurrent_p = ieBuf_p;
	ieBufEnd_p = ieBuf_p + ieBufLen;

	while (ieCurrent_p < ieBufEnd_p) {
		if (*(IEEEtypes_ElementId_t *) ieCurrent_p == PROPRIETARY_IE) {
			IE_p = (struct IEEEtypes_MBO_Element_t *)ieCurrent_p;
			if ((IE_p->OUI[0] == 0x50) && (IE_p->OUI[1] == 0x6F) && (IE_p->OUI[2] == 0x9A) && (IE_p->OUIType == MBO_OUI_type)) {
				return IE_p;
			}
		}

		ieCurrent_p += (2 + *((UINT8 *) (ieCurrent_p + 1)));
	}

	return NULL;
}
#endif				/* MBO_SUPPORT */

/*************************************************************************
 * Function: smeParseIeType
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
extern WSC_HeaderIE_t *linkMgtParseWpsInfo(UINT16 wpsInfoID, UINT8 * ieBuf_p, UINT16 ieBufLen)
{
	UINT8 *ieBufEnd_p;
	UINT8 *ieCurrent_p;
	/* Use to identify Wps info element. */
	WSC_ProbeRespIE_t *IE_p = (WSC_ProbeRespIE_t *) ieBuf_p;
	WSC_HeaderIE_t *IE_Wps_p = NULL;

	if ((IE_p->ElementId != PROPRIETARY_IE) && memcmp(wps_oui, IE_p->OUI, 4)) {
		return NULL;
	}
	/* Start where data field begins for wps information. */
	ieCurrent_p = (UINT8 *) & IE_p->WSCData[0];
	ieBufEnd_p = ieBuf_p + ieBufLen;

	while (ieCurrent_p < ieBufEnd_p) {
		IE_Wps_p = (WSC_HeaderIE_t *) ieCurrent_p;
		if (IE_Wps_p->ElementId == wpsInfoID) {
			return IE_Wps_p;
		}
		ieCurrent_p += (IE_Wps_p->Len + sizeof(WSC_HeaderIE_t));
	}
	return NULL;
}

/*************************************************************************
 * Function: smeParseIeType
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
extern IEEEtypes_Generic_HT_Element_t *linkMgtParseHTGenIe(UINT8 * ieBuf_p, UINT16 ieBufLen)
{
	UINT8 *ieBufEnd_p;
	UINT8 *ieCurrent_p;
	IEEEtypes_Generic_HT_Element_t *pHTGen;

	ieCurrent_p = ieBuf_p;
	ieBufEnd_p = ieBuf_p + ieBufLen;

	while (ieCurrent_p < ieBufEnd_p) {
		pHTGen = (IEEEtypes_Generic_HT_Element_t *) ieCurrent_p;
		if (pHTGen->ElementId == PROPRIETARY_IE) {
			if (!memcmp(&pHTGen->OUI, B_COMP_OUI, 3) && (pHTGen->OUIType == HT_PROP))
				return pHTGen;
		}
		ieCurrent_p += (pHTGen->Len + sizeof(IEEEtypes_InfoElementHdr_t));
	}
	return NULL;
}

/*************************************************************************
 * Function: linkMgtSetBssProfile
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
extern SINT32 linkMgtSetBssProfile(UINT8 phyIndex, scanDescptHdr_t * selectedDescpt_p)
{
	linkMgtEntry_t *aLink_p;
	UINT16 ieBufLen;
	IEEEtypes_InfoElementHdr_t *ieHdr_p;
	UINT8 *curData_p, *attrib_p;
	UINT16 parseLen;
	struct net_device *pStaDev;
	struct wlprivate *wlpptrSta;
	WME_param_elem_t *WME_param_elem = NULL;
	IEEEtypes_Generic_HT_Element_t *pHTGen;
	IEEEtypes_Generic_Add_HT_Element_t *pHTAddGen;
	IEEEtypes_RSN_IE_t *wpaIE_p;
	IEEEtypes_RSN_IE_WPAMixedMode_t *wpaMixedIE_p;
	IEEEtypes_RSN_IE_WPA2_t *wpa2IE_p;
	IEEEtypes_RSN_IE_WPA2MixedMode_t *wpa2MixedIE_p;
	IEEEtypes_InfoElementHdr_t *pMcIdIE;
	BOOLEAN isApMrvl = FALSE;
	UINT32 mCipherId;
	UINT32 uCipherId;
	UINT32 aCipherId;
	UINT8 rsn_modeId;
	BOOLEAN isApRptr = FALSE;
	UINT8 PrIE[] = "\x00\x50\x43\x03\x00\0x00";
#ifdef SOC_W906X
	struct wlprivate *priv_p;
	MIB_802DOT11 *mib;
#endif

#ifdef LNK_DEBUG
	eprintf("******* linkMgtSetBssProfile:: entered\n");
#endif				/* LNK_DEBUG */
	aLink_p = &linkMgtEntry[phyIndex];
	if (aLink_p->vMac_p == NULL) {
		return -1;
	}

	pStaDev = (struct net_device *)aLink_p->vMac_p->privInfo_p;
	wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);

#ifdef SOC_W906X
	priv_p = GET_PARENT_PRIV(wlpptrSta);
	mib = priv_p->vmacSta_p->Mib802dot11;
#endif

	memset((void *)&linkMgtSelectedBss[0], 0, LNK_MGT_BSS_PROFILE_BUF_LEN);
	ieBufLen = 0;
	parseLen = selectedDescpt_p->length + sizeof(selectedDescpt_p->length) - sizeof(scanDescptHdr_t);
	curData_p = (((UINT8 *) selectedDescpt_p) + sizeof(scanDescptHdr_t));
	ieHdr_p = (IEEEtypes_InfoElementHdr_t *) curData_p;

	/* Check if selected BSS is operating in ad hoc, if it is do not associate.
	   Currently Client does not support ad hoc mode.                          */
	if (selectedDescpt_p->CapInfo.Ibss) {
		return -1;
	}
	/* Pack in SSID */
	if ((ieHdr_p = smeParseIeType(SSID, curData_p, parseLen)) != NULL) {
		memcpy((void *)&linkMgtSelectedBss[ieBufLen], (const void *)ieHdr_p, ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
		ieBufLen += ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
	}
	/* Pack in Supported Rates */
	if ((ieHdr_p = smeParseIeType(SUPPORTED_RATES, curData_p, parseLen)) != NULL) {
		memcpy((void *)&linkMgtSelectedBss[ieBufLen], (const void *)ieHdr_p, ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
		ieBufLen += ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
	}
	/* Pack in Supported Rates */
	if ((ieHdr_p = smeParseIeType(EXT_SUPPORTED_RATES, curData_p, parseLen)) != NULL) {
		memcpy((void *)&linkMgtSelectedBss[ieBufLen], (const void *)ieHdr_p, ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
		ieBufLen += ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
	}
	/* Pack in DS Param */
	if ((ieHdr_p = smeParseIeType(DS_PARAM_SET, curData_p, parseLen)) != NULL) {
		memcpy((void *)&linkMgtSelectedBss[ieBufLen], (const void *)ieHdr_p, ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
		ieBufLen += ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
	}
	/* Pack in HT */
	if ((ieHdr_p = smeParseIeType(HT, curData_p, parseLen)) != NULL) {
		memcpy((void *)&linkMgtSelectedBss[ieBufLen], (const void *)ieHdr_p, ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
		ieBufLen += ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
	}

	if ((ieHdr_p = smeParseIeType(ADD_HT, curData_p, parseLen)) != NULL) {

		memcpy((void *)&linkMgtSelectedBss[ieBufLen], (const void *)ieHdr_p, ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
		ieBufLen += ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
	}

	/*Pack in VHT */
	if ((ieHdr_p = smeParseIeType(VHT_CAP, curData_p, parseLen)) != NULL) {
		memcpy((void *)&linkMgtSelectedBss[ieBufLen], (const void *)ieHdr_p, ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
		ieBufLen += ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
	}

	if ((ieHdr_p = smeParseIeType(VHT_OPERATION, curData_p, parseLen)) != NULL) {
		memcpy((void *)&linkMgtSelectedBss[ieBufLen], (const void *)ieHdr_p, ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
		ieBufLen += ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
	}
#ifdef SOC_W906X
	/*Pack in HE */
	if ((ieHdr_p = smeParseExtIeType(HE_CAPABILITIES_IE, curData_p, parseLen)) != NULL) {
		if ((ieBufLen + ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t)) < LNK_MGT_BSS_PROFILE_BUF_LEN) {
			memcpy((void *)&linkMgtSelectedBss[ieBufLen], (const void *)ieHdr_p, ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
			ieBufLen += ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
		}
	} else if ((*(mib->mib_ApMode) == AP_MODE_5GHZ_11AX_ONLY)) {
		return -1;
	}

	if ((ieHdr_p = smeParseExtIeType(HE_OPERATION_IE, curData_p, parseLen)) != NULL) {
		if ((ieBufLen + ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t)) < LNK_MGT_BSS_PROFILE_BUF_LEN) {
			memcpy((void *)&linkMgtSelectedBss[ieBufLen], (const void *)ieHdr_p, ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
			ieBufLen += ieHdr_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
		}
	} else if ((*(mib->mib_ApMode) == AP_MODE_5GHZ_11AX_ONLY)) {
		return -1;
	}
#endif

	/* Finally Pack in any PROPRIETARY IEs */
	{
		attrib_p = curData_p;
		while ((attrib_p = (UINT8 *) smeParseIeType(PROPRIETARY_IE, attrib_p, parseLen)) != NULL) {
			//check if it is a WME/WSM Info Element.
			WME_param_elem = (WME_param_elem_t *) attrib_p;
			pHTGen = (IEEEtypes_Generic_HT_Element_t *) attrib_p;
			pHTAddGen = (IEEEtypes_Generic_Add_HT_Element_t *) attrib_p;
			pMcIdIE = (IEEEtypes_InfoElementHdr_t *) attrib_p;
			if (!memcmp(WME_param_elem->OUI.OUI, WiFiOUI, 3)) {
				//Check if it is a WME element
				if (WME_param_elem->OUI.Type == 2) {
					/* Add QoS IE here. */
					if (*(wlpptrSta->vmacSta_p->Mib802dot11->QoSOptImpl)) {
						//check if it is a WME Param Element
						if (WME_param_elem->OUI.Subtype == 1) {
							UINT8 MvPIE[] = "\x00\x50\xf2\x02\x00\x01\x00";

							/* Add in WME */
							ieHdr_p = (IEEEtypes_InfoElementHdr_t *) & linkMgtSelectedBss[ieBufLen];
							ieHdr_p->ElementId = PROPRIETARY_IE;
							ieHdr_p->Len = 7;
							ieBufLen += sizeof(IEEEtypes_InfoElementHdr_t);
							memcpy((void *)&linkMgtSelectedBss[ieBufLen], &MvPIE[0], ieHdr_p->Len);
							ieBufLen += ieHdr_p->Len;
						}
					}
				}
			} /* If regular HT element not found then look for Proprietary HT element - support for Broadcom. */
			else if (!memcmp(&pHTGen->OUI, B_COMP_OUI, 3)) {
				if (pHTGen->OUIType == HT_PROP) {

					{
						vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) wlpptrSta->vmacSta_p;

						if (*(vmacSta_p->Mib802dot11->mib_HtGreenField) == 0)
							pHTGen->HTCapabilitiesInfo.GreenField = 0;
						if (*(vmacSta_p->Mib802dot11->mib_HtStbc) == 0) {
							pHTGen->HTCapabilitiesInfo.RxSTBC = 0;
							pHTGen->HTCapabilitiesInfo.TxSTBC = 0;
						}
						pHTGen->ExtHTCapabilitiesInfo = 0x00;

						if (*(vmacSta_p->Mib802dot11->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_8K)
							pHTGen->HTCapabilitiesInfo.MaxAMSDUSize = 1;
						else
							pHTGen->HTCapabilitiesInfo.MaxAMSDUSize = 0;
					}
					memcpy((void *)&linkMgtSelectedBss[ieBufLen], pHTGen, pHTGen->Len + sizeof(IEEEtypes_InfoElementHdr_t));
					ieBufLen += (pHTGen->Len + sizeof(IEEEtypes_InfoElementHdr_t));
				}
			} else if (isMcIdIE((UINT8 *) pMcIdIE) == TRUE) {
				isApMrvl = TRUE;
			} else if (isM_RptrIdIE((UINT8 *) pMcIdIE) == TRUE) {
				isApRptr = TRUE;
			}
			//Now process to the next element pointer.
			attrib_p += (2 + *((UINT8 *) (attrib_p + 1)));
		}

	}
	/* Pack in NXP IE. */
	ieHdr_p = (IEEEtypes_InfoElementHdr_t *) & linkMgtSelectedBss[ieBufLen];
	ieHdr_p->ElementId = PROPRIETARY_IE;
	ieHdr_p->Len = 6;
	ieBufLen += sizeof(IEEEtypes_InfoElementHdr_t);
	memcpy((void *)&linkMgtSelectedBss[ieBufLen], &PrIE[0], ieHdr_p->Len);
	ieBufLen += ieHdr_p->Len;

	{			/* Pack in NXP Rptr IE. */
		vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) wlpptrSta->vmacSta_p;
		if ((*(vmacSta_p->Mib802dot11->mib_STAMacCloneEnable) == 2) && isApRptr) {
			/* Pack in NXP IE. */
			ieHdr_p = (IEEEtypes_InfoElementHdr_t *) & linkMgtSelectedBss[ieBufLen];
			ieHdr_p->ElementId = PROPRIETARY_IE;
			ieHdr_p->Len = 6;
			ieBufLen += sizeof(IEEEtypes_InfoElementHdr_t);
			memcpy((void *)&linkMgtSelectedBss[ieBufLen], &rptr_oui_type_subtype_ver[0], ieHdr_p->Len);
			ieHdr_p->Len += MAXRPTRDEVTYPESTR;	/* Append Rptr Device type: 32 bytes */
			memcpy((void *)&linkMgtSelectedBss[ieBufLen + 6], vmacSta_p->Mib802dot11->mib_RptrDeviceType,
			       strlen(vmacSta_p->Mib802dot11->mib_RptrDeviceType));

			ieBufLen += ieHdr_p->Len;
		}
	}

#ifdef WPA_STA
#ifdef DO_WPA_TKIP		//wpa_only_test
	{
#ifdef DO_WPA_AES		//WPA_test_only
		/* Pack in RSN (WPA2) */
		wpa2IE_p = (IEEEtypes_RSN_IE_WPA2_t *) smeParseIeType(RSN_IEWPA2, curData_p, parseLen);
#ifdef CLIENT_SUPPORT
		if (wlpptrSta->vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
			if (wpa2IE_p && (wlpptrSta->vmacSta_p->RsnIESetByHost == 1) && (wlpptrSta->vmacSta_p->RsnIE)) {
				if ((ieBufLen + wpa2IE_p->Len + sizeof(IEEEtypes_InfoElementHdr_t)) < LNK_MGT_BSS_PROFILE_BUF_LEN) {
					memcpy((void *)&linkMgtSelectedBss[ieBufLen],
					       (const void *)wpa2IE_p, wpa2IE_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
					ieBufLen += wpa2IE_p->Len + sizeof(IEEEtypes_InfoElementHdr_t);
				}
			}
		}
#endif
#endif				//DO_WPA_AES
		wpaIE_p = linkMgtParseWpaIe(curData_p, parseLen);
		if (wpa2IE_p || wpaIE_p) {
			if (!wlpptrSta->vmacSta_p->Mib802dot11->Privacy->RSNEnabled) {
#ifdef MRVL_WPS_CLIENT
				vmacEntry_t *vmacEntry_p = NULL;
				STA_SYSTEM_MIBS *pStaSystemMibs = NULL;
				UINT8 wpawpa2Mode = 0;

				vmacEntry_p = sme_GetParentVMacEntry(phyIndex);
				if (vmacEntry_p)
					pStaSystemMibs = sme_GetStaSystemMibsPtr(vmacEntry_p);
				if (pStaSystemMibs)
					wpawpa2Mode = pStaSystemMibs->mib_StaCfg_p->wpawpa2Mode;
				/* If WPS is enabled, allow open mode Association with AP that requires
				 * WPA/WPA2
				 */
#endif				//MRVL_WPS_CLIENT

				/* AP requires WPA/WPA2 - station WPA/WPA2 not enabled. */
#ifdef MRVL_WPS_CLIENT
				/* If the Station is intended to intiate WPS, the association
				 * request may not contain the WPA/WPA2 IEs.
				 * Allowing association for WPS */
				if (wpawpa2Mode != 16)
#endif				//MRVL_WPS_CLIENT
					return -1;
			} else if ((wlpptrSta->vmacSta_p->Mib802dot11->RSNConfigWPA2->WPA2Enabled) &&
				   (wlpptrSta->vmacSta_p->Mib802dot11->RSNConfigWPA2->WPA2OnlyEnabled) && wpa2IE_p) {
				/* WPA2 only mode */
				mCipherId = wpa2IE_p->GrpKeyCipher[3];
				if (wpa2IE_p->PwsKeyCnt[0] == 1)
					uCipherId = wlpptrSta->vmacSta_p->Mib802dot11->WPA2UnicastCiphers->UnicastCipher[3];
				else {
					/* AP supports mixed mode */
					wpa2MixedIE_p = (IEEEtypes_RSN_IE_WPA2MixedMode_t *) wpa2IE_p;
					if (wpa2MixedIE_p->PwsKeyCipherList[3] == RSN_TKIP_ID) {
						if (wpa2MixedIE_p->PwsKeyCipherList2[3] == RSN_TKIP_ID)
							uCipherId = RSN_TKIP_ID;
						else
							uCipherId = RSN_AES_ID;
					} else
						uCipherId = RSN_AES_ID;
				}
				aCipherId = wlpptrSta->vmacSta_p->Mib802dot11->WPA2AuthSuites->AuthSuites[3];
				keyMgmtUpdateRsnIE(phyIndex, RSN_WPA2_ID, mCipherId, uCipherId, aCipherId);
				if (staMib_thisStaRsnIEWPA2_p[phyIndex]->Len) {
					memcpy((void *)&linkMgtSelectedBss[ieBufLen], staMib_thisStaRsnIEWPA2_p[phyIndex],
					       staMib_thisStaRsnIEWPA2_p[phyIndex]->Len + 2);
					ieBufLen += staMib_thisStaRsnIEWPA2_p[phyIndex]->Len + 2;
				}
			} else if (wlpptrSta->vmacSta_p->Mib802dot11->RSNConfigWPA2->WPA2Enabled) {
				/* supports station WPA WPA2 mixed mode */
				if (wpa2IE_p) {
					/*If the AP supports both WPA and WPA2, select WPA2 as the authentication method */
					mCipherId = wpa2IE_p->GrpKeyCipher[3];
					if (wpa2IE_p->PwsKeyCnt[0] == 1)
						uCipherId = wlpptrSta->vmacSta_p->Mib802dot11->WPA2UnicastCiphers->UnicastCipher[3];
					else {
						/* AP supports mixed mode */
						wpa2MixedIE_p = (IEEEtypes_RSN_IE_WPA2MixedMode_t *) wpa2IE_p;
						if (wpa2MixedIE_p->PwsKeyCipherList[3] == RSN_TKIP_ID) {
							if (wpa2MixedIE_p->PwsKeyCipherList2[3] == RSN_TKIP_ID)
								uCipherId = RSN_TKIP_ID;
							else
								uCipherId = RSN_AES_ID;
						} else
							uCipherId = RSN_AES_ID;
					}
					aCipherId = wlpptrSta->vmacSta_p->Mib802dot11->WPA2AuthSuites->AuthSuites[3];
					memset(staMib_thisStaRsnIEWPA2_p[phyIndex], 0, sizeof(IEEEtypes_RSN_IE_WPA2_t));
					keyMgmtUpdateRsnIE(phyIndex, RSN_WPA2_ID, mCipherId, uCipherId, aCipherId);
					if (staMib_thisStaRsnIEWPA2_p[phyIndex]->Len) {
						memcpy((void *)&linkMgtSelectedBss[ieBufLen], staMib_thisStaRsnIEWPA2_p[phyIndex],
						       staMib_thisStaRsnIEWPA2_p[phyIndex]->Len + 2);
						ieBufLen += staMib_thisStaRsnIEWPA2_p[phyIndex]->Len + 2;
					}

				} else {
					mCipherId = wpaIE_p->GrpKeyCipher[3];
					if (wpaIE_p->PwsKeyCnt[0] == 1)
						uCipherId = wpaIE_p->PwsKeyCipherList[3];
					else {
						/* AP supports mixed mode */
						wpaMixedIE_p = (IEEEtypes_RSN_IE_WPAMixedMode_t *) wpaIE_p;
						if (wpaMixedIE_p->PwsKeyCipherList[3] == RSN_TKIP_ID) {
							if (wpaMixedIE_p->PwsKeyCipherList2[3] == RSN_TKIP_ID)
								uCipherId = RSN_TKIP_ID;
							else
								uCipherId = RSN_AES_ID;
						} else
							uCipherId = RSN_AES_ID;
					}
					aCipherId = wlpptrSta->vmacSta_p->Mib802dot11->RSNConfigAuthSuites->AuthSuites[3];
					rsn_modeId = RSN_WPA_ID;
					memset(staMib_thisStaRsnIE_p[phyIndex], 0, sizeof(IEEEtypes_RSN_IE_t));
					keyMgmtUpdateRsnIE(phyIndex, RSN_WPA_ID, mCipherId, uCipherId, aCipherId);
					if (staMib_thisStaRsnIE_p[phyIndex]->Len) {
						memcpy((void *)&linkMgtSelectedBss[ieBufLen], staMib_thisStaRsnIE_p[phyIndex],
						       staMib_thisStaRsnIE_p[phyIndex]->Len + 2);
						ieBufLen += staMib_thisStaRsnIE_p[phyIndex]->Len + 2;
					}

				}

			} else {
				if (!wpaIE_p) {
					/* AP requires WPA2 - station WPA2 not enabled - station WPA enabled. */
					return -1;
				}
				mCipherId = wpaIE_p->GrpKeyCipher[3];
				if (wpaIE_p->PwsKeyCnt[0] == 1)
					uCipherId = wpaIE_p->PwsKeyCipherList[3];
				else {
					/* AP supports mixed mode */
					wpaMixedIE_p = (IEEEtypes_RSN_IE_WPAMixedMode_t *) wpaIE_p;
					if (wpaMixedIE_p->PwsKeyCipherList[3] == RSN_TKIP_ID) {
						if (wpaMixedIE_p->PwsKeyCipherList2[3] == RSN_TKIP_ID)
							uCipherId = RSN_TKIP_ID;
						else
							uCipherId = RSN_AES_ID;
					} else
						uCipherId = RSN_AES_ID;
				}
				aCipherId = wlpptrSta->vmacSta_p->Mib802dot11->RSNConfigAuthSuites->AuthSuites[3];
				rsn_modeId = RSN_WPA_ID;
				keyMgmtUpdateRsnIE(phyIndex, RSN_WPA_ID, mCipherId, uCipherId, aCipherId);
				if (staMib_thisStaRsnIE_p[phyIndex]->Len) {
					memcpy((void *)&linkMgtSelectedBss[ieBufLen], staMib_thisStaRsnIE_p[phyIndex],
					       staMib_thisStaRsnIE_p[phyIndex]->Len + 2);
					ieBufLen += staMib_thisStaRsnIE_p[phyIndex]->Len + 2;
				}
			}
		} else {
			/* Return failure if station WPA/WPA2 enabled but WPA/WPA2 elements not found. */
			if (wlpptrSta->vmacSta_p->Mib802dot11->Privacy->RSNEnabled)
				return -1;
			/* Return failure if station WEP enabled and capability Privacy bit mismatch. */
			if ((wlpptrSta->vmacSta_p->Mib802dot11->Privacy->PrivInvoked ^ selectedDescpt_p->CapInfo.Privacy))
				return -1;
		}
	}
#endif				//DO_WPA_TKIP
#endif				/* WPA_STA */
	if (smeSetBssProfile(phyIndex,
			     &selectedDescpt_p->bssId[0], &selectedDescpt_p->CapInfo, &linkMgtSelectedBss[0], ieBufLen, isApMrvl) != MLME_SUCCESS) {
		return -1;
	}
	wlFwSetTxPower(pStaDev, HostCmd_ACT_GEN_SET_LIST, 0);
	return 0;
}

/*************************************************************************
 * Function: linkMgtParseScanResult
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
#ifdef SOC_W8964
extern SINT32 scan_obss(UINT8 * data);
extern void Send2040CoexSta(vmacStaInfo_t * vStaInfo_p);
#endif
extern SINT32 linkMgtParseScanResult(UINT8 phyIndex)
{
	linkMgtEntry_t *aLink_p;
	UINT8 numDescpt = 0;
	BOOLEAN bssFound = FALSE;
	UINT32 bestSignal = 100;
	scanDescptHdr_t *curDescpt_p = NULL;
	scanDescptHdr_t *bestDescpt_p = NULL;
	UINT16 parsedLen = 0;
	UINT8 i;
	BOOLEAN prefBssidFound = FALSE;
	UINT8 *buf_p;
	UINT16 bufSize = MAX_SCAN_BUF_SIZE;
#ifdef SOC_W8964
	vmacEntry_t *vmacEntry_p = sme_GetParentVMacEntry(phyIndex);
	vmacStaInfo_t *vStaInfo_p = (vmacStaInfo_t *) vmacEntry_p->info_p;
#endif
#ifdef LNK_DEBUG
	eprintf("******* linkMgtParseScanResult:: entered\n");
#endif				/* LNK_DEBUG */
	aLink_p = &linkMgtEntry[phyIndex];
	if (!aLink_p->active) {
		return -1;
	}
	TimerRemove(&aLink_p->linkTimer);
	smeGetScanResults(phyIndex, &numDescpt, &bufSize, &buf_p);
#ifdef LNK_DEBUG
	eprintf("**** Num of scan descpt = %d\n", numDescpt);
#endif				/* LNK_DEBUG */
	for (i = 0; i < numDescpt; i++) {
		curDescpt_p = (scanDescptHdr_t *) (buf_p + parsedLen);

#ifdef LNK_DEBUG
		eprintf("Scan Descrpt index %d: BSSID %x-%x-%x-%x-%x-%x\n",
			i,
			curDescpt_p->bssId[0],
			curDescpt_p->bssId[1], curDescpt_p->bssId[2], curDescpt_p->bssId[3], curDescpt_p->bssId[4], curDescpt_p->bssId[5]);
		eprintf("Scan Descrpt Length= %d\n", curDescpt_p->length);
		eprintf("Scan Descrpt RSSI= %d\n", curDescpt_p->rssi);
#endif				/* LNK_DEBUG */
		/* Checked for Matching Preferred BSSID */

		if (aLink_p->searchBitMap & SELECT_FOR_SSID) {	/* Else check for Matching SSID */
			IEEEtypes_SsIdElement_t *ssidIE_p;

			if ((ssidIE_p = (IEEEtypes_SsIdElement_t *) smeParseIeType(SSID,
										   (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
										   curDescpt_p->length + sizeof(curDescpt_p->length) -
										   sizeof(scanDescptHdr_t))) != NULL) {
				if ((ssidIE_p->Len == aLink_p->ssidIE.Len)
				    && !memcmp(&ssidIE_p->SsId[0], &aLink_p->ssidIE.SsId[0], aLink_p->ssidIE.Len)) {
#ifdef LNK_DEBUG
					eprintf("** Bingo SSID \n");
#endif				/* LNK_DEBUG */
					if (aLink_p->searchBitMap & SELECT_FOR_BSSID) {
						if (!memcmp(&curDescpt_p->bssId[0], &aLink_p->bssid[0], IEEEtypes_ADDRESS_SIZE)) {
#ifdef LNK_DEBUG
							eprintf("** Bingo BSSID \n");
#endif				/* LNK_DEBUG */
							prefBssidFound = TRUE;
							bssFound = TRUE;
							bestDescpt_p = curDescpt_p;
							bestSignal = curDescpt_p->rssi;
						}
					}
					if (!prefBssidFound && (curDescpt_p->rssi <= bestSignal)) {
						bssFound = TRUE;
						bestDescpt_p = curDescpt_p;
						bestSignal = curDescpt_p->rssi;
					}
				}
			}
		} else if (aLink_p->searchBitMap & SELECT_FOR_BSSID) {
			if (!memcmp(&curDescpt_p->bssId[0], &aLink_p->bssid[0], IEEEtypes_ADDRESS_SIZE)) {
#ifdef LNK_DEBUG
				eprintf("** Bingo BSSID \n");
#endif				/* LNK_DEBUG */
				prefBssidFound = TRUE;
				bssFound = TRUE;
				bestDescpt_p = curDescpt_p;
				bestSignal = curDescpt_p->rssi;
			}
		} else {	/* Else check for RSSI */
			if (curDescpt_p->rssi < bestSignal) {
#ifdef LNK_DEBUG
				eprintf("** Bingo RSSI of %d \n", curDescpt_p->rssi);
#endif				/* LNK_DEBUG */
				bssFound = TRUE;
				bestDescpt_p = curDescpt_p;
				bestSignal = curDescpt_p->rssi;
			}
		}
		parsedLen += curDescpt_p->length + sizeof(curDescpt_p->length);
	}
	/* Any Available BSS */
	if (bssFound && (bestDescpt_p != NULL)) {
#ifdef LNK_DEBUG
		eprintf("** BSS Found\n");
#endif				/* LNK_DEBUG */
		/* Set Client BSS Profile */
#ifdef SOC_W8964
		if (vStaInfo_p->AssociatedFlag == FALSE) {	// No connected OBSS_Scan => connect
#endif
			if (!linkMgtSetBssProfile(phyIndex, bestDescpt_p)) {
				if (smeStartBss(phyIndex) == MLME_SUCCESS) {
					return 0;
				}
			}
		}
#ifdef SOC_W8964
	}
#endif
	/* Else Try again to join later */
#ifdef LNK_DEBUG
	eprintf("** BSS NOT Found => Start timer\n");
#endif				/* LNK_DEBUG */

#ifdef SOC_W8964
	if (vStaInfo_p->in_obss_scan == FALSE) {
#endif
		/* Start a timer to try again later */
		TimerInit(&aLink_p->linkTimer);
		TimerFireIn(&aLink_p->linkTimer, 1, &linkMgtActTimeOut, (UINT8 *) aLink_p, LNK_MGT_POLL_TICK);
#ifdef SOC_W8964
	} else {
		if (vStaInfo_p->intolerant_chnl_size > 0) {
			extern int wlFwSet11N_20_40_Switch(struct net_device *netdev, UINT8 mode);
			struct net_device *staDev = (struct net_device *)vmacEntry_p->privInfo_p;

			// Need to report OBSS Mgmt
			printk("%s Send out Send2040CoexSta\n", __func__);
			Send2040CoexSta(vStaInfo_p);

			// Reduce to 20MHz
			wlFwSet11N_20_40_Switch(staDev, 0);

			// Already down to 20MHz => Not need to scan obss
		} else {
			// Fire Another OBSS Scan
			TimerInit(&vStaInfo_p->obss_Timer);
			TimerFireIn(&vStaInfo_p->obss_Timer, 1, &scan_obss, (unsigned char *)vStaInfo_p, vStaInfo_p->obss_scan_interval);
		}
	}
#endif
	return 0;
}

/*************************************************************************
 * Function: linkMgtStop
 *
 * Description:
 *
 * Input:
 *
 * Output:
 **************************************************************************/
extern SINT32 linkMgtStop(UINT8 phyIndex)
{
	linkMgtEntry_t *aLink_p;

	if (phyIndex >= NUM_OF_WLMACS) {
		return -1;
	}
	aLink_p = &linkMgtEntry[phyIndex];
	aLink_p->active = 0;
	smeStopBss(phyIndex);
	TimerRemove(&aLink_p->linkTimer);
	aLink_p->phyHwMacIndx = 0;
	aLink_p->vMac_p = NULL;
	return 0;
}

/*************************************************************************
 * Function: linkMgtStart
 *
 * Description:
 *
 * Input:
 *
 * Output:
 **************************************************************************/
extern SINT32 linkMgtStart(UINT8 phyIndex, UINT8 * prefBSSID_p, UINT8 * ieBuf_p, UINT8 ieBufLen)
{
	linkMgtEntry_t *aLink_p;

#ifdef LNK_DEBUG
	eprintf("linkMgtStart ieBuf len %d\n", ieBufLen);
#endif				/* LNK_DEBUG */

	if ((phyIndex >= NUM_OF_WLMACS)
#if LNK_MGT_SCAN_IE_BUF_LEN < 256
	    || (ieBufLen > LNK_MGT_SCAN_IE_BUF_LEN)
#endif
	    ) {
		return -1;
	}
	aLink_p = &linkMgtEntry[phyIndex];
	TimerRemove(&aLink_p->linkTimer);
	/* Clean Slate */
	memset((void *)aLink_p, 0, sizeof(linkMgtEntry_t));
	aLink_p->active = 1;
	aLink_p->phyHwMacIndx = phyIndex;
	aLink_p->vMac_p = vmacGetVMacEntryById(parentGetVMacId(phyIndex));
	aLink_p->searchBitMap = 0;
	if (prefBSSID_p != NULL) {
		memcpy(&aLink_p->bssid[0], prefBSSID_p, IEEEtypes_ADDRESS_SIZE);
		if (aLink_p->bssid[0] != 0xff) {
			aLink_p->searchBitMap |= SELECT_FOR_BSSID;
		}
	}
	if (ieBuf_p && ieBufLen) {
		IEEEtypes_SsIdElement_t *ssidIE_p;
		memcpy(&aLink_p->scanIeBuf[0], ieBuf_p, ieBufLen);
		aLink_p->scanIeBufLen = ieBufLen;
		/* Save SSID IE for faster searching later */
		if ((ssidIE_p = (IEEEtypes_SsIdElement_t *) smeParseIeType(SSID, ieBuf_p, ieBufLen)) != NULL) {
			if (ssidIE_p->Len && (ssidIE_p->Len <= IEEEtypes_SSID_SIZE)) {
				memcpy((void *)&aLink_p->ssidIE, (const void *)ssidIE_p, ssidIE_p->Len + sizeof(IEEEtypes_InfoElementHdr_t));
				aLink_p->searchBitMap |= SELECT_FOR_SSID;
			}
		}
	}
	smeSendScanRequest(aLink_p->phyHwMacIndx, 0, 3, 200, &aLink_p->bssid[0], &aLink_p->scanIeBuf[0], aLink_p->scanIeBufLen);
	return 0;
}

/*************************************************************************
 * Function: linkMgtReStart
 *
 * Description:
 *
 * Input:
 *
 * Output:
 **************************************************************************/
extern SINT32 linkMgtReStart(UINT8 phyIndex, vmacEntry_t * vmacEntry_p)
{
	linkMgtEntry_t *aLink_p;
	UINT32 clientSrvId;
	vmacStaInfo_t *vStaInfo_p = (vmacStaInfo_t *) vmacEntry_p->info_p;

#ifdef LNK_DEBUG
	eprintf("linkMgtReStart\n");
#endif				/* LNK_DEBUG */

	if ((phyIndex >= NUM_OF_WLMACS)) {
		return -1;
	}
	aLink_p = &linkMgtEntry[phyIndex];
	if (!aLink_p->active) {
		return -1;
	}
	memset(vStaInfo_p->macMgmtMlme_ThisStaData.BssId, 0, sizeof(IEEEtypes_MacAddr_t));
	vStaInfo_p->JoinRetryCount = 0;
	vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->RSNLinkStatus = 0;
	vStaInfo_p->AssociatedFlag = 0;
	vStaInfo_p->in_obss_scan = FALSE;
	vStaInfo_p->AssocRetryCount = 0;
	vStaInfo_p->AuthRetryCount = 0;
	vStaInfo_p->g_rcvdProbeRsp = 1;
	memset(&vStaInfo_p->linkInfo, 0, sizeof(iw_linkInfo_t));
	clientSrvId = vmacGetClientSrvId(phyIndex);
	vmacDeActiveSrvId(phyIndex, clientSrvId);
	TimerRemove(&aLink_p->linkTimer);
	TimerInit(&aLink_p->linkTimer);
	TimerFireIn(&aLink_p->linkTimer, 1, &linkMgtActTimeOut, (UINT8 *) aLink_p, LNK_MGT_RESTART_WAIT_TICK);
	return 0;
}
