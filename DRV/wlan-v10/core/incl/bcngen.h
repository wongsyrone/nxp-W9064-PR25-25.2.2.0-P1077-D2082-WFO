/** @file bcngen.h
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

#ifndef _BCNGEN_H_
#define _BCNGEN_H_

#include "wlmac.h"
#include "macmgmtap.h"

#define SETBIT    1
#define RESETBIT  0
#define SET_ERP_PROTECTION 1
#define RESET_ERP_PROTECTION 0

extern macmgmtQ_MgmtMsg_t *BcnBuffer_p;
extern void bcngen_UpdateBeaconBuffer(vmacApInfo_t * vmacSta_p,
				      IEEEtypes_StartCmd_t * StartCmd_p);
extern void bcngen_UpdateBitInTim(UINT16 Aid, BOOLEAN Set);
extern void bcngen_BeaconFreeIsr(void);
extern void bcngen_UpdateBeaconErpInfo(vmacApInfo_t * vmacSta_p,
				       BOOLEAN SetFlag);
extern void bcngen_EnableBcnFreeIntr(void);

extern UINT16 AddRSN_IEWPA2_TO(IEEEtypes_RSN_IE_WPA2_t * thisStaRsnIEWPA2_p,
			       IEEEtypes_RSN_IE_WPA2_t * pNextElement);

#ifdef WPA
// Add RSN IE to a frame body
UINT16 AddRSN_IE(vmacApInfo_t * vmacSta_p, IEEEtypes_RSN_IE_t * pNextElement);
#endif

#ifdef IEEE80211H
void bcngen_AddChannelSwithcAnnouncement_IE(vmacApInfo_t * vmacSta_p,
					    IEEEtypes_ChannelSwitchAnnouncementElement_t
					    * pChannelSwitchAnnouncementIE);
void bcngen_RemoveChannelSwithcAnnouncement_IE(vmacApInfo_t * vmacSta_p);
void bcngen_AddQuiet_IE(vmacApInfo_t * vmacSta_p,
			IEEEtypes_QuietElement_t * pQuietIE);
void bcngen_RemoveQuiet_IE(vmacApInfo_t * vmacSta_p);
UINT16 AddQuiet_IE(UINT8 * pNextElement);
#endif /* IEEE80211H */

#ifdef UR_WPA
void InitThisStaRsnIEUr(vmacApInfo_t * vmacSta_p);
#endif

UINT16 AddHT_IE(vmacApInfo_t * vmacSta_p,
		IEEEtypes_HT_Element_t * pNextElement);
UINT16 AddRSN_IE_TO(IEEEtypes_RSN_IE_t * thisStaRsnIE_p,
		    IEEEtypes_RSN_IE_t * pNextElement);
extern UINT16 AddM_IE(vmacApInfo_t * vmacSta_p,
		      IEEEtypes_HT_Element_t * pNextElement);
extern UINT16 Add_Generic_AddHT_IE(vmacApInfo_t * vmacSta_p,
				   IEEEtypes_Generic_Add_HT_Element_t *
				   pNextElement);
extern UINT16 Add_Generic_HT_IE(vmacApInfo_t * vmacSta_p,
				IEEEtypes_Generic_HT_Element_t * pNextElement);
extern UINT16 AddAddHT_IE(vmacApInfo_t * vmacSta_p,
			  IEEEtypes_Add_HT_Element_t * pNextElement);
extern void InitThisStaRsnIE(vmacApInfo_t * vmacSta_p);
extern UINT16 AddM_Rptr_IE(vmacApInfo_t * vmacSta_p,
			   IEEEtypes_HT_Element_t * pNextElement);
UINT16 AddChanReport_IE(vmacApInfo_t * vmacSta_p,
			IEEEtypes_ChannelReportEL_t * pNextElement);
UINT16 AddOverlap_BSS_Scan_Parameters_IE(vmacApInfo_t * vmacSta_p,
					 IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t
					 * pNextElement);
UINT16 AddExtended_Cap_IE(vmacApInfo_t * vmacSta_p,
			  IEEEtypes_Extended_Cap_Element_t * pNextElement);
UINT16 AddExtended_Cap_IE(vmacApInfo_t * vmacSta_p,
			  IEEEtypes_Extended_Cap_Element_t * pNextElement);
#ifdef SOC_W906X
extern UINT8 Add_Mbssid_IE(vmacApInfo_t * vmacSta_p,
			   IEEEtypes_Mbssid_Element_t * pNextElement);
#endif
UINT16 Add_VendorSpec_VHT_IE(vmacApInfo_t * vmacSta_p,
			     IEEEtypes_HT_Element_t * pNextElement);

#ifdef IEEE80211K
UINT16 AddRRM_Cap_IE(vmacApInfo_t * vmacSta_p,
		     IEEEtypes_RM_Enable_Capabilities_Element_t * pNextElement);
#endif /* IEEE80211K */

#ifdef MULTI_AP_SUPPORT
extern UINT16 Get_MultiAP_IE_Size(vmacApInfo_t * vmacSta_p);
extern UINT16 Add_MultiAP_IE(vmacApInfo_t * vmacSta_p,
			     IEEEtypes_InfoElementHdr_t * pNextElement,
			     UINT8 protocol_type);
#endif /*MULTI_AP_SUPPORT */
#ifdef IEEE80211H
extern UINT8 bcn_reg_domain;
#endif /* IEEE80211H */
extern UINT16 AddRSN_IEWPA2MixedMode(vmacApInfo_t * vmacSta_p,
				     IEEEtypes_RSN_IE_WPA2MixedMode_t *
				     pNextElement);
UINT16 AddRSN_IEWPA2(vmacApInfo_t * vmacSta_p,
		     IEEEtypes_RSN_IE_WPA2_t * pNextElement);
#ifdef MRVL_WPS2
UINT16 Build_AssocResp_WSCIE(vmacApInfo_t * vmacSta_p,
			     AssocResp_WSCIE_t * pNextElement);
#endif
UINT16 Build_IE_191(vmacApInfo_t * vmacSta_p, UINT8 * IE_p, UINT8 isEffective,
		    UINT8 nss);
UINT16 Build_IE_192(vmacApInfo_t * vmacSta_p, UINT8 * IE_p);

extern UINT16 Build_IE_HE_CAP(vmacApInfo_t * vmacSta_p, UINT8 * IE_p);
extern UINT16 Build_IE_HE_OP(vmacApInfo_t * vmacSta_p, UINT8 * IE_p,
			     UINT8 vhtopie_present);
extern UINT16 Build_IE_MU_EDCA(vmacApInfo_t * vmacSta_p, UINT8 * IE_p);
extern UINT16 Build_IE_SRP(vmacApInfo_t * vmacSta_p, UINT8 * IE_p);
extern u8 Get_MaxBssid_Indicator(U32 bss_num);

#endif /* _BCNGEN_H_ */
